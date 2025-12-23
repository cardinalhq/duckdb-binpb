// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! OpenTelemetry metrics processing for DuckDB.

use duckdb::{
    core::{DataChunkHandle, Inserter, LogicalTypeHandle, LogicalTypeId},
    vtab::{BindInfo, InitInfo, TableFunctionInfo, VTab},
    Connection, Result,
};
use prost::Message;
use std::{
    error::Error,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::common::{any_value_to_string, read_binpb_file};
use crate::normalize::normalize_attribute_name;
use crate::opentelemetry::proto::{
    collector::metrics::v1::ExportMetricsServiceRequest,
    common::v1::KeyValue,
    metrics::v1::{metric, AggregationTemporality, Metric},
};
use crate::sketch::{
    exponential_histogram_to_sketch, histogram_to_sketch, summary_to_sketch, DDSketch,
    ExponentialHistogramBuckets, HistogramBucket, RollupStats, SummaryQuantile,
};
use crate::tid::{compute_tid_from_otel, metric_type_to_string, should_keep_resource_key};

// ============================================================================
// Constants
// ============================================================================

/// Timestamp truncation interval (10 seconds in milliseconds)
const TIMESTAMP_TRUNCATION_MS: i64 = 10_000;

// ============================================================================
// Flattened metric row representation
// ============================================================================

/// A single flattened metric data point row with CHQ schema
#[derive(Debug, Clone)]
pub struct MetricRow {
    // CHQ system fields
    pub chq_customer_id: String,
    pub chq_telemetry_type: String, // Always "metrics"
    pub chq_tid: i64,
    pub chq_timestamp: i64, // Milliseconds, truncated to 10s
    pub chq_tsns: i64,      // Original nanoseconds

    // Metric metadata (chq_ prefixed)
    pub metric_name: String, // Normalized name
    pub chq_description: String,
    pub chq_unit: String,
    pub chq_metric_type: String, // "gauge", "count", or "histogram"

    // Scope
    pub chq_scope_name: String,
    pub chq_scope_url: String, // scope version

    // Aggregation properties (Sum, Histogram, ExponentialHistogram only)
    pub metric_is_monotonic: Option<bool>,   // true/false for Sum, None for others
    pub metric_temporality: Option<String>,  // "delta", "cumulative", or None

    // Sketch and rollups
    pub chq_sketch: Vec<u8>,
    pub chq_rollup_avg: f64,
    pub chq_rollup_count: f64,
    pub chq_rollup_min: f64,
    pub chq_rollup_max: f64,
    pub chq_rollup_sum: f64,
    pub chq_rollup_p25: f64,
    pub chq_rollup_p50: f64,
    pub chq_rollup_p75: f64,
    pub chq_rollup_p90: f64,
    pub chq_rollup_p95: f64,
    pub chq_rollup_p99: f64,

    // Dynamic attributes
    pub resource_attrs: Arc<Vec<(String, String)>>, // Filtered to allowed keys (shared across rows)
    pub datapoint_attrs: Vec<(String, String)>, // Filtered (no underscore-prefix, no empty)
}

// ============================================================================
// Parsing helpers
// ============================================================================

/// Extract attributes as (normalized_key, value_string) pairs
fn extract_filtered_resource_attrs(attrs: &[KeyValue]) -> Vec<(String, String)> {
    attrs
        .iter()
        .filter_map(|kv| {
            let normalized_key = normalize_attribute_name(&kv.key);
            if should_keep_resource_key(&normalized_key) {
                let value = any_value_to_string(&kv.value);
                if !value.is_empty() {
                    Some((format!("resource_{}", normalized_key), value))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

/// Extract datapoint attributes, filtering out underscore-prefixed and empty values.
/// Returns (prefixed_attrs_for_output, raw_attrs_for_tid)
fn extract_datapoint_attrs_both(attrs: &[KeyValue]) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut prefixed = Vec::with_capacity(attrs.len());
    let mut raw = Vec::with_capacity(attrs.len());

    for kv in attrs {
        // Skip underscore-prefixed keys
        if kv.key.starts_with('_') {
            continue;
        }
        let value = any_value_to_string(&kv.value);
        if value.is_empty() {
            continue;
        }
        let normalized_key = normalize_attribute_name(&kv.key);
        prefixed.push((format!("attr_{}", normalized_key), value.clone()));
        raw.push((kv.key.clone(), value));
    }

    (prefixed, raw)
}

/// Convert KeyValue slice to owned tuples for TID computation.
/// Returns raw keys (not normalized/prefixed) since compute_tid_from_otel handles that.
fn keyvalues_to_owned(attrs: &[KeyValue]) -> Vec<(String, String)> {
    attrs
        .iter()
        .filter_map(|kv| {
            let value = any_value_to_string(&kv.value);
            if value.is_empty() {
                None
            } else {
                Some((kv.key.clone(), value))
            }
        })
        .collect()
}

/// Convert nanoseconds to milliseconds with 10s truncation
fn truncate_timestamp(time_unix_nano: u64) -> i64 {
    let ms = (time_unix_nano / 1_000_000) as i64;
    (ms / TIMESTAMP_TRUNCATION_MS) * TIMESTAMP_TRUNCATION_MS
}

/// Get OTEL metric type string
fn otel_metric_type(metric: &Metric) -> &'static str {
    match &metric.data {
        Some(metric::Data::Gauge(_)) => "gauge",
        Some(metric::Data::Sum(_)) => "sum",
        Some(metric::Data::Histogram(_)) => "histogram",
        Some(metric::Data::ExponentialHistogram(_)) => "exponential_histogram",
        Some(metric::Data::Summary(_)) => "summary",
        None => "unknown",
    }
}

/// Convert aggregation temporality enum value to string
fn temporality_to_string(temporality: i32) -> Option<String> {
    match temporality {
        x if x == AggregationTemporality::Delta as i32 => Some("delta".to_string()),
        x if x == AggregationTemporality::Cumulative as i32 => Some("cumulative".to_string()),
        _ => None, // Unspecified or unknown
    }
}

/// Check if a histogram datapoint has any non-zero bucket counts.
/// Returns false if all bucket counts are zero (empty histogram).
fn histogram_has_counts(
    dp: &crate::opentelemetry::proto::metrics::v1::HistogramDataPoint,
) -> bool {
    dp.bucket_counts.iter().any(|&count| count > 0)
}

/// Check if an exponential histogram datapoint has any non-zero bucket counts.
/// Returns false if all bucket counts are zero (empty histogram).
fn exp_histogram_has_counts(
    dp: &crate::opentelemetry::proto::metrics::v1::ExponentialHistogramDataPoint,
) -> bool {
    // Check positive buckets
    if let Some(pos) = &dp.positive {
        if pos.bucket_counts.iter().any(|&count| count > 0) {
            return true;
        }
    }
    // Check negative buckets
    if let Some(neg) = &dp.negative {
        if neg.bucket_counts.iter().any(|&count| count > 0) {
            return true;
        }
    }
    // Check zero count
    dp.zero_count > 0
}

/// Create row from a gauge/sum data point
fn create_row_from_number_datapoint(
    customer_id: &str,
    metric: &Metric,
    resource_attrs: &Arc<Vec<(String, String)>>,
    raw_resource_for_tid: &[(&str, &str)], // Pre-computed raw resource attrs for TID
    scope_name: &str,
    scope_version: &str,
    dp_attrs: &[KeyValue],
    time_unix_nano: u64,
    value: f64,
    is_monotonic: Option<bool>,
    temporality: Option<String>,
) -> MetricRow {
    let otel_type = otel_metric_type(metric);
    let chq_type = metric_type_to_string(otel_type);
    let normalized_name = normalize_attribute_name(&metric.name);

    // Process datapoint attrs once for both output and TID
    let (filtered_dp_attrs, dp_owned) = extract_datapoint_attrs_both(dp_attrs);
    let dp_for_tid: Vec<(&str, &str)> = dp_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let tid = compute_tid_from_otel(&metric.name, otel_type, raw_resource_for_tid, &dp_for_tid);

    // Create sketch from single value
    let mut sketch = DDSketch::default();
    sketch.add(value);
    let sketch_bytes = sketch.encode().unwrap_or_default();
    let stats = RollupStats::from_sketch(&sketch);

    MetricRow {
        chq_customer_id: customer_id.to_string(),
        chq_telemetry_type: "metrics".to_string(),
        chq_tid: tid,
        chq_timestamp: truncate_timestamp(time_unix_nano),
        chq_tsns: time_unix_nano as i64,
        metric_name: normalized_name,
        chq_description: metric.description.clone(),
        chq_unit: metric.unit.clone(),
        chq_metric_type: chq_type.to_string(),
        chq_scope_name: scope_name.to_string(),
        chq_scope_url: scope_version.to_string(),
        metric_is_monotonic: is_monotonic,
        metric_temporality: temporality,
        chq_sketch: sketch_bytes,
        chq_rollup_avg: stats.avg,
        chq_rollup_count: stats.count,
        chq_rollup_min: stats.min,
        chq_rollup_max: stats.max,
        chq_rollup_sum: stats.sum,
        chq_rollup_p25: stats.p25,
        chq_rollup_p50: stats.p50,
        chq_rollup_p75: stats.p75,
        chq_rollup_p90: stats.p90,
        chq_rollup_p95: stats.p95,
        chq_rollup_p99: stats.p99,
        resource_attrs: Arc::clone(resource_attrs),
        datapoint_attrs: filtered_dp_attrs,
    }
}

/// Create row from histogram data point
fn create_row_from_histogram(
    customer_id: &str,
    metric: &Metric,
    resource_attrs: &Arc<Vec<(String, String)>>,
    raw_resource_for_tid: &[(&str, &str)], // Pre-computed raw resource attrs for TID
    scope_name: &str,
    scope_version: &str,
    dp: &crate::opentelemetry::proto::metrics::v1::HistogramDataPoint,
    temporality: Option<String>,
) -> MetricRow {
    let normalized_name = normalize_attribute_name(&metric.name);

    // Process datapoint attrs once for both output and TID
    let (filtered_dp_attrs, dp_owned) = extract_datapoint_attrs_both(&dp.attributes);
    let dp_for_tid: Vec<(&str, &str)> = dp_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let tid = compute_tid_from_otel(&metric.name, "histogram", raw_resource_for_tid, &dp_for_tid);

    // Convert histogram buckets to sketch
    let buckets: Vec<HistogramBucket> = dp
        .explicit_bounds
        .iter()
        .zip(dp.bucket_counts.iter())
        .scan(0u64, |cumulative, (bound, &count)| {
            *cumulative += count;
            Some(HistogramBucket {
                upper_bound: *bound,
                count: *cumulative,
            })
        })
        .collect();

    let sketch = histogram_to_sketch(&buckets, dp.sum, dp.count);
    let sketch_bytes = sketch.encode().unwrap_or_default();
    let stats = RollupStats::from_sketch(&sketch);

    MetricRow {
        chq_customer_id: customer_id.to_string(),
        chq_telemetry_type: "metrics".to_string(),
        chq_tid: tid,
        chq_timestamp: truncate_timestamp(dp.time_unix_nano),
        chq_tsns: dp.time_unix_nano as i64,
        metric_name: normalized_name,
        chq_description: metric.description.clone(),
        chq_unit: metric.unit.clone(),
        chq_metric_type: "histogram".to_string(),
        chq_scope_name: scope_name.to_string(),
        chq_scope_url: scope_version.to_string(),
        metric_is_monotonic: None, // Histograms don't have is_monotonic
        metric_temporality: temporality,
        chq_sketch: sketch_bytes,
        chq_rollup_avg: stats.avg,
        chq_rollup_count: stats.count,
        chq_rollup_min: dp.min.unwrap_or(stats.min),
        chq_rollup_max: dp.max.unwrap_or(stats.max),
        chq_rollup_sum: stats.sum,
        chq_rollup_p25: stats.p25,
        chq_rollup_p50: stats.p50,
        chq_rollup_p75: stats.p75,
        chq_rollup_p90: stats.p90,
        chq_rollup_p95: stats.p95,
        chq_rollup_p99: stats.p99,
        resource_attrs: Arc::clone(resource_attrs),
        datapoint_attrs: filtered_dp_attrs,
    }
}

/// Create row from exponential histogram data point
fn create_row_from_exp_histogram(
    customer_id: &str,
    metric: &Metric,
    resource_attrs: &Arc<Vec<(String, String)>>,
    raw_resource_for_tid: &[(&str, &str)], // Pre-computed raw resource attrs for TID
    scope_name: &str,
    scope_version: &str,
    dp: &crate::opentelemetry::proto::metrics::v1::ExponentialHistogramDataPoint,
    temporality: Option<String>,
) -> MetricRow {
    let normalized_name = normalize_attribute_name(&metric.name);

    // Process datapoint attrs once for both output and TID
    let (filtered_dp_attrs, dp_owned) = extract_datapoint_attrs_both(&dp.attributes);
    let dp_for_tid: Vec<(&str, &str)> = dp_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let tid = compute_tid_from_otel(
        &metric.name,
        "exponential_histogram",
        raw_resource_for_tid,
        &dp_for_tid,
    );

    let positive = dp.positive.as_ref().map(|b| ExponentialHistogramBuckets {
        offset: b.offset,
        bucket_counts: b.bucket_counts.clone(),
    });

    let negative = dp.negative.as_ref().map(|b| ExponentialHistogramBuckets {
        offset: b.offset,
        bucket_counts: b.bucket_counts.clone(),
    });

    let sketch = exponential_histogram_to_sketch(
        dp.scale,
        positive.as_ref(),
        negative.as_ref(),
        dp.zero_count,
        dp.sum,
        dp.min,
        dp.max,
    );
    let sketch_bytes = sketch.encode().unwrap_or_default();
    let stats = RollupStats::from_sketch(&sketch);

    MetricRow {
        chq_customer_id: customer_id.to_string(),
        chq_telemetry_type: "metrics".to_string(),
        chq_tid: tid,
        chq_timestamp: truncate_timestamp(dp.time_unix_nano),
        chq_tsns: dp.time_unix_nano as i64,
        metric_name: normalized_name,
        chq_description: metric.description.clone(),
        chq_unit: metric.unit.clone(),
        chq_metric_type: "histogram".to_string(),
        chq_scope_name: scope_name.to_string(),
        chq_scope_url: scope_version.to_string(),
        metric_is_monotonic: None, // Exponential histograms don't have is_monotonic
        metric_temporality: temporality,
        chq_sketch: sketch_bytes,
        chq_rollup_avg: stats.avg,
        chq_rollup_count: stats.count,
        chq_rollup_min: dp.min.unwrap_or(stats.min),
        chq_rollup_max: dp.max.unwrap_or(stats.max),
        chq_rollup_sum: stats.sum,
        chq_rollup_p25: stats.p25,
        chq_rollup_p50: stats.p50,
        chq_rollup_p75: stats.p75,
        chq_rollup_p90: stats.p90,
        chq_rollup_p95: stats.p95,
        chq_rollup_p99: stats.p99,
        resource_attrs: Arc::clone(resource_attrs),
        datapoint_attrs: filtered_dp_attrs,
    }
}

/// Create row from summary data point
/// Note: Summary metrics don't have aggregation temporality or is_monotonic
fn create_row_from_summary(
    customer_id: &str,
    metric: &Metric,
    resource_attrs: &Arc<Vec<(String, String)>>,
    raw_resource_for_tid: &[(&str, &str)], // Pre-computed raw resource attrs for TID
    scope_name: &str,
    scope_version: &str,
    dp: &crate::opentelemetry::proto::metrics::v1::SummaryDataPoint,
) -> MetricRow {
    let normalized_name = normalize_attribute_name(&metric.name);

    // Process datapoint attrs once for both output and TID
    let (filtered_dp_attrs, dp_owned) = extract_datapoint_attrs_both(&dp.attributes);
    let dp_for_tid: Vec<(&str, &str)> = dp_owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let tid = compute_tid_from_otel(&metric.name, "summary", raw_resource_for_tid, &dp_for_tid);

    let quantiles: Vec<SummaryQuantile> = dp
        .quantile_values
        .iter()
        .map(|qv| SummaryQuantile {
            quantile: qv.quantile,
            value: qv.value,
        })
        .collect();

    let sketch = summary_to_sketch(&quantiles, dp.count, dp.sum);
    let sketch_bytes = sketch.encode().unwrap_or_default();
    let stats = RollupStats::from_sketch(&sketch);

    MetricRow {
        chq_customer_id: customer_id.to_string(),
        chq_telemetry_type: "metrics".to_string(),
        chq_tid: tid,
        chq_timestamp: truncate_timestamp(dp.time_unix_nano),
        chq_tsns: dp.time_unix_nano as i64,
        metric_name: normalized_name,
        chq_description: metric.description.clone(),
        chq_unit: metric.unit.clone(),
        chq_metric_type: "histogram".to_string(),
        chq_scope_name: scope_name.to_string(),
        chq_scope_url: scope_version.to_string(),
        metric_is_monotonic: None, // Summaries don't have is_monotonic
        metric_temporality: None,  // Summaries don't have aggregation_temporality
        chq_sketch: sketch_bytes,
        chq_rollup_avg: stats.avg,
        chq_rollup_count: stats.count,
        chq_rollup_min: stats.min,
        chq_rollup_max: stats.max,
        chq_rollup_sum: stats.sum,
        chq_rollup_p25: stats.p25,
        chq_rollup_p50: stats.p50,
        chq_rollup_p75: stats.p75,
        chq_rollup_p90: stats.p90,
        chq_rollup_p95: stats.p95,
        chq_rollup_p99: stats.p99,
        resource_attrs: Arc::clone(resource_attrs),
        datapoint_attrs: filtered_dp_attrs,
    }
}

// ============================================================================
// Main parsing function
// ============================================================================

/// Parse metrics from binary protobuf data
pub fn parse_metrics(data: &[u8], customer_id: &str) -> Result<Vec<MetricRow>, Box<dyn Error>> {
    let request = ExportMetricsServiceRequest::decode(data)?;
    let mut rows = Vec::new();

    for rm in &request.resource_metrics {
        // Get filtered/prefixed resource attributes for output columns (wrapped in Arc for sharing)
        let resource_attrs = Arc::new(rm
            .resource
            .as_ref()
            .map(|r| extract_filtered_resource_attrs(&r.attributes))
            .unwrap_or_default());

        // Pre-compute raw resource attributes for TID computation (once per ResourceMetrics)
        let raw_resource_owned: Vec<(String, String)> = rm
            .resource
            .as_ref()
            .map(|r| keyvalues_to_owned(&r.attributes))
            .unwrap_or_default();
        let raw_resource_for_tid: Vec<(&str, &str)> = raw_resource_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        for sm in &rm.scope_metrics {
            let (scope_name, scope_version) = sm
                .scope
                .as_ref()
                .map(|s| (s.name.clone(), s.version.clone()))
                .unwrap_or_default();

            for metric in &sm.metrics {
                match &metric.data {
                    Some(metric::Data::Gauge(gauge)) => {
                        // Gauges don't have is_monotonic or aggregation_temporality
                        for dp in &gauge.data_points {
                            let value = match &dp.value {
                                Some(
                                    crate::opentelemetry::proto::metrics::v1::number_data_point::Value::AsDouble(d),
                                ) => *d,
                                Some(
                                    crate::opentelemetry::proto::metrics::v1::number_data_point::Value::AsInt(i),
                                ) => *i as f64,
                                None => 0.0,
                            };
                            rows.push(create_row_from_number_datapoint(
                                customer_id,
                                metric,
                                &resource_attrs,
                                &raw_resource_for_tid,
                                &scope_name,
                                &scope_version,
                                &dp.attributes,
                                dp.time_unix_nano,
                                value,
                                None, // is_monotonic
                                None, // temporality
                            ));
                        }
                    }
                    Some(metric::Data::Sum(sum)) => {
                        let temporality = temporality_to_string(sum.aggregation_temporality);
                        for dp in &sum.data_points {
                            let value = match &dp.value {
                                Some(
                                    crate::opentelemetry::proto::metrics::v1::number_data_point::Value::AsDouble(d),
                                ) => *d,
                                Some(
                                    crate::opentelemetry::proto::metrics::v1::number_data_point::Value::AsInt(i),
                                ) => *i as f64,
                                None => 0.0,
                            };
                            rows.push(create_row_from_number_datapoint(
                                customer_id,
                                metric,
                                &resource_attrs,
                                &raw_resource_for_tid,
                                &scope_name,
                                &scope_version,
                                &dp.attributes,
                                dp.time_unix_nano,
                                value,
                                Some(sum.is_monotonic),
                                temporality.clone(),
                            ));
                        }
                    }
                    Some(metric::Data::Histogram(hist)) => {
                        let temporality = temporality_to_string(hist.aggregation_temporality);
                        for dp in &hist.data_points {
                            // Skip histograms with all-zero bucket counts (matches Go behavior)
                            if !histogram_has_counts(dp) {
                                continue;
                            }
                            rows.push(create_row_from_histogram(
                                customer_id,
                                metric,
                                &resource_attrs,
                                &raw_resource_for_tid,
                                &scope_name,
                                &scope_version,
                                dp,
                                temporality.clone(),
                            ));
                        }
                    }
                    Some(metric::Data::ExponentialHistogram(exp_hist)) => {
                        let temporality = temporality_to_string(exp_hist.aggregation_temporality);
                        for dp in &exp_hist.data_points {
                            // Skip exponential histograms with no counts (matches Go behavior)
                            if !exp_histogram_has_counts(dp) {
                                continue;
                            }
                            rows.push(create_row_from_exp_histogram(
                                customer_id,
                                metric,
                                &resource_attrs,
                                &raw_resource_for_tid,
                                &scope_name,
                                &scope_version,
                                dp,
                                temporality.clone(),
                            ));
                        }
                    }
                    Some(metric::Data::Summary(summary)) => {
                        for dp in &summary.data_points {
                            rows.push(create_row_from_summary(
                                customer_id,
                                metric,
                                &resource_attrs,
                                &raw_resource_for_tid,
                                &scope_name,
                                &scope_version,
                                dp,
                            ));
                        }
                    }
                    None => {}
                }
            }
        }
    }

    Ok(rows)
}

// ============================================================================
// DuckDB Table Function
// ============================================================================

/// Expand a file path that may contain glob patterns into a list of matching files.
/// Also handles list syntax like `['file1.binpb', 'file2.binpb']`.
fn expand_file_input(input: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let input = input.trim();

    // Check for list syntax: [file1, file2, ...]
    if input.starts_with('[') && input.ends_with(']') {
        let inner = &input[1..input.len() - 1];
        let mut paths = Vec::new();
        for part in inner.split(',') {
            let path = part.trim().trim_matches(|c| c == '\'' || c == '"');
            if !path.is_empty() {
                // Each element can also be a glob
                let expanded = expand_single_path(path)?;
                paths.extend(expanded);
            }
        }
        if paths.is_empty() {
            return Err("Empty file list".into());
        }
        return Ok(paths);
    }

    // Single path or glob
    expand_single_path(input)
}

/// Expand a single file path that may be a glob pattern
fn expand_single_path(pattern: &str) -> Result<Vec<String>, Box<dyn Error>> {
    // Check if this looks like a glob pattern
    if pattern.contains('*') || pattern.contains('?') {
        let paths: Vec<String> = glob::glob(pattern)?
            .filter_map(|entry| entry.ok())
            .map(|path| path.to_string_lossy().to_string())
            .collect();

        if paths.is_empty() {
            return Err(format!("No files matched pattern: {}", pattern).into());
        }
        Ok(paths)
    } else {
        // Single file path
        Ok(vec![pattern.to_string()])
    }
}

#[repr(C)]
pub struct MetricsBindData {
    rows: Vec<MetricRow>,
    // Store the superset of attribute column names for consistent schema
    resource_attr_names: Vec<String>,
    datapoint_attr_names: Vec<String>,
}

#[repr(C)]
pub struct MetricsInitData {
    current_row: AtomicUsize,
}

pub struct ReadMetricsVTab;

impl VTab for ReadMetricsVTab {
    type InitData = MetricsInitData;
    type BindData = MetricsBindData;

    fn bind(bind: &BindInfo) -> Result<Self::BindData, Box<dyn Error>> {
        let param_count = bind.get_parameter_count();
        if param_count < 1 {
            return Err(
                "Usage: otel_metrics_read('file.binpb', customer_id='xxx') or otel_metrics_read(['file1.binpb', 'file2.binpb'], customer_id='xxx')"
                    .into(),
            );
        }

        // Get customer_id from named parameter (required)
        let customer_id = bind
            .get_named_parameter("customer_id")
            .ok_or("Missing required named parameter: customer_id")?
            .to_string();

        // Get file path(s) from first positional parameter
        // Supports: single path, glob pattern, or list ['file1', 'file2']
        let file_input = bind.get_parameter(0).to_string();
        let file_paths = expand_file_input(&file_input)?;

        // Parse all files and collect rows
        let mut all_rows = Vec::new();
        for file_path in &file_paths {
            let data = read_binpb_file(file_path)?;
            let rows = parse_metrics(&data, &customer_id)?;
            all_rows.extend(rows);
        }

        // Compute superset of attribute columns from all rows
        let (resource_attr_names, datapoint_attr_names) = collect_attr_names(&all_rows);

        // Fixed columns - CHQ schema
        bind.add_result_column("chq_customer_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_telemetry_type", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_tid", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("chq_timestamp", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("chq_tsns", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("metric_name", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_description", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_unit", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_metric_type", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_scope_name", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_scope_url", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("metric_is_monotonic", LogicalTypeHandle::from(LogicalTypeId::Boolean));
        bind.add_result_column("metric_temporality", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_sketch", LogicalTypeHandle::from(LogicalTypeId::Blob));
        bind.add_result_column("chq_rollup_avg", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_count", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_min", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_max", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_sum", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_p25", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_p50", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_p75", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_p90", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_p95", LogicalTypeHandle::from(LogicalTypeId::Double));
        bind.add_result_column("chq_rollup_p99", LogicalTypeHandle::from(LogicalTypeId::Double));

        // Dynamic columns - use the superset computed above
        for name in &resource_attr_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }
        for name in &datapoint_attr_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }

        Ok(MetricsBindData {
            rows: all_rows,
            resource_attr_names,
            datapoint_attr_names,
        })
    }

    fn init(_: &InitInfo) -> Result<Self::InitData, Box<dyn Error>> {
        Ok(MetricsInitData {
            current_row: AtomicUsize::new(0),
        })
    }

    fn func(
        func: &TableFunctionInfo<Self>,
        output: &mut DataChunkHandle,
    ) -> Result<(), Box<dyn Error>> {
        let init_data = func.get_init_data();
        let bind_data = func.get_bind_data();

        let batch_size = 2048;
        let start_row = init_data.current_row.fetch_add(batch_size, Ordering::Relaxed);

        if start_row >= bind_data.rows.len() {
            output.set_len(0);
            return Ok(());
        }

        let end_row = std::cmp::min(start_row + batch_size, bind_data.rows.len());
        let rows_to_output = end_row - start_row;

        // Use the superset of column names stored during bind
        let resource_attr_names = &bind_data.resource_attr_names;
        let datapoint_attr_names = &bind_data.datapoint_attr_names;

        for (i, row) in bind_data.rows[start_row..end_row].iter().enumerate() {
            let mut col = 0;

            // Fixed columns
            output.flat_vector(col).insert(i, row.chq_customer_id.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_telemetry_type.as_bytes());
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.chq_tid;
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.chq_timestamp;
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.chq_tsns;
            col += 1;

            output.flat_vector(col).insert(i, row.metric_name.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_description.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_unit.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_metric_type.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_scope_name.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_scope_url.as_bytes());
            col += 1;

            // metric_is_monotonic (nullable boolean)
            match row.metric_is_monotonic {
                Some(v) => output.flat_vector(col).as_mut_slice::<bool>()[i] = v,
                None => output.flat_vector(col).set_null(i),
            }
            col += 1;

            // metric_temporality (nullable varchar)
            match &row.metric_temporality {
                Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                None => output.flat_vector(col).set_null(i),
            }
            col += 1;

            output.flat_vector(col).insert(i, &row.chq_sketch);
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_avg;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_count;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_min;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_max;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_sum;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_p25;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_p50;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_p75;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_p90;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_p95;
            col += 1;

            output.flat_vector(col).as_mut_slice::<f64>()[i] = row.chq_rollup_p99;
            col += 1;

            // Dynamic attribute columns
            for name in resource_attr_names {
                let value = row.resource_attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v);
                let vec = output.flat_vector(col);
                match value {
                    Some(v) => vec.insert(i, v.as_bytes()),
                    None => {
                        let mut vec = output.flat_vector(col);
                        vec.set_null(i);
                    }
                }
                col += 1;
            }

            for name in datapoint_attr_names {
                let value = row.datapoint_attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v);
                let vec = output.flat_vector(col);
                match value {
                    Some(v) => vec.insert(i, v.as_bytes()),
                    None => {
                        let mut vec = output.flat_vector(col);
                        vec.set_null(i);
                    }
                }
                col += 1;
            }
        }

        output.set_len(rows_to_output);
        Ok(())
    }

    fn parameters() -> Option<Vec<LogicalTypeHandle>> {
        // Single VARCHAR parameter: can be a path, glob, or list like ['file1', 'file2']
        Some(vec![LogicalTypeHandle::from(LogicalTypeId::Varchar)])
    }

    fn named_parameters() -> Option<Vec<(String, LogicalTypeHandle)>> {
        Some(vec![(
            "customer_id".to_string(),
            LogicalTypeHandle::from(LogicalTypeId::Varchar),
        )])
    }
}

/// Collect all unique attribute names from rows
fn collect_attr_names(rows: &[MetricRow]) -> (Vec<String>, Vec<String>) {
    use std::collections::HashSet;

    let mut resource_attr_set: HashSet<String> = HashSet::new();
    let mut datapoint_attr_set: HashSet<String> = HashSet::new();

    for row in rows {
        for (key, _) in row.resource_attrs.iter() {
            resource_attr_set.insert(key.clone());
        }
        for (key, _) in &row.datapoint_attrs {
            datapoint_attr_set.insert(key.clone());
        }
    }

    let mut resource_attr_names: Vec<String> = resource_attr_set.into_iter().collect();
    let mut datapoint_attr_names: Vec<String> = datapoint_attr_set.into_iter().collect();

    resource_attr_names.sort();
    datapoint_attr_names.sort();

    (resource_attr_names, datapoint_attr_names)
}

/// Register metrics table functions with DuckDB
pub fn register(con: &Connection) -> Result<(), Box<dyn Error>> {
    con.register_table_function::<ReadMetricsVTab>("otel_metrics_read")
        .map_err(|e| format!("Failed to register otel_metrics_read: {}", e))?;
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opentelemetry::proto::{
        common::v1::{any_value, AnyValue, InstrumentationScope, KeyValue},
        metrics::v1::{
            AggregationTemporality, Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics,
            Sum, Histogram, HistogramDataPoint, Summary, SummaryDataPoint,
            summary_data_point::ValueAtQuantile,
        },
        resource::v1::Resource,
    };
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn create_sample_request() -> ExportMetricsServiceRequest {
        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![
                        KeyValue {
                            key: "service.name".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "test-service".to_string(),
                                )),
                            }),
                        },
                        KeyValue {
                            key: "host.name".to_string(), // Not in KEEP_RESOURCE_KEYS
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("test-host".to_string())),
                            }),
                        },
                        KeyValue {
                            key: "k8s.pod.name".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("pod-123".to_string())),
                            }),
                        },
                    ],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(InstrumentationScope {
                        name: "test-scope".to_string(),
                        version: "1.0.0".to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    }),
                    metrics: vec![
                        Metric {
                            name: "test.gauge".to_string(),
                            description: "A test gauge metric".to_string(),
                            unit: "1".to_string(),
                            data: Some(metric::Data::Gauge(Gauge {
                                data_points: vec![NumberDataPoint {
                                    attributes: vec![
                                        KeyValue {
                                            key: "env".to_string(),
                                            value: Some(AnyValue {
                                                value: Some(any_value::Value::StringValue(
                                                    "prod".to_string(),
                                                )),
                                            }),
                                        },
                                        KeyValue {
                                            key: "_internal".to_string(), // Should be filtered
                                            value: Some(AnyValue {
                                                value: Some(any_value::Value::StringValue(
                                                    "hidden".to_string(),
                                                )),
                                            }),
                                        },
                                    ],
                                    start_time_unix_nano: 1000000000,
                                    time_unix_nano: 1700000000_000_000_000, // 2023-11-14 ~
                                    value: Some(crate::opentelemetry::proto::metrics::v1::number_data_point::Value::AsDouble(42.5)),
                                    exemplars: vec![],
                                    flags: 0,
                                }],
                            })),
                            metadata: vec![],
                        },
                        Metric {
                            name: "test.counter".to_string(),
                            description: "A test counter metric".to_string(),
                            unit: "bytes".to_string(),
                            data: Some(metric::Data::Sum(Sum {
                                data_points: vec![NumberDataPoint {
                                    attributes: vec![KeyValue {
                                        key: "region".to_string(),
                                        value: Some(AnyValue {
                                            value: Some(any_value::Value::StringValue(
                                                "us-west-2".to_string(),
                                            )),
                                        }),
                                    }],
                                    start_time_unix_nano: 1000000000,
                                    time_unix_nano: 1700000000_000_000_000,
                                    value: Some(crate::opentelemetry::proto::metrics::v1::number_data_point::Value::AsInt(12345)),
                                    exemplars: vec![],
                                    flags: 0,
                                }],
                                aggregation_temporality: AggregationTemporality::Cumulative as i32,
                                is_monotonic: true,
                            })),
                            metadata: vec![],
                        },
                    ],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        }
    }

    #[test]
    fn test_parse_metrics() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        assert_eq!(rows.len(), 2, "Should have 2 data points");

        let gauge_row = &rows[0];
        assert_eq!(gauge_row.metric_name, "test_gauge"); // Normalized
        assert_eq!(gauge_row.chq_metric_type, "gauge");
        assert_eq!(gauge_row.chq_customer_id, "test-customer");
        assert_eq!(gauge_row.chq_telemetry_type, "metrics");
        assert!(gauge_row.chq_rollup_count == 1.0);
        assert!(gauge_row.chq_rollup_sum == 42.5);

        let counter_row = &rows[1];
        assert_eq!(counter_row.metric_name, "test_counter");
        assert_eq!(counter_row.chq_metric_type, "count"); // "sum" -> "count"
        assert!(counter_row.chq_rollup_sum == 12345.0);
    }

    #[test]
    fn test_aggregation_temporality_fields() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        // Gauge should have None for both fields
        let gauge_row = &rows[0];
        assert_eq!(gauge_row.metric_is_monotonic, None, "Gauge should not have is_monotonic");
        assert_eq!(gauge_row.metric_temporality, None, "Gauge should not have temporality");

        // Sum (counter) should have both fields populated
        let counter_row = &rows[1];
        assert_eq!(counter_row.metric_is_monotonic, Some(true), "Counter should have is_monotonic=true");
        assert_eq!(counter_row.metric_temporality, Some("cumulative".to_string()), "Counter should have temporality=cumulative");
    }

    #[test]
    fn test_aggregation_temporality_delta() {
        // Create a metric with delta temporality
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("test-service".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: None,
                    metrics: vec![Metric {
                        name: "delta.counter".to_string(),
                        description: "A delta counter".to_string(),
                        unit: "1".to_string(),
                        data: Some(metric::Data::Sum(Sum {
                            data_points: vec![NumberDataPoint {
                                attributes: vec![],
                                start_time_unix_nano: 1000000000,
                                time_unix_nano: 1700000000_000_000_000,
                                value: Some(crate::opentelemetry::proto::metrics::v1::number_data_point::Value::AsInt(100)),
                                exemplars: vec![],
                                flags: 0,
                            }],
                            aggregation_temporality: AggregationTemporality::Delta as i32,
                            is_monotonic: false,
                        })),
                        metadata: vec![],
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].metric_is_monotonic, Some(false), "Delta counter should have is_monotonic=false");
        assert_eq!(rows[0].metric_temporality, Some("delta".to_string()), "Should have temporality=delta");
    }

    #[test]
    fn test_histogram_temporality() {
        // Histogram should have temporality but not is_monotonic
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("test-service".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: None,
                    metrics: vec![Metric {
                        name: "request.duration".to_string(),
                        description: "Request duration".to_string(),
                        unit: "ms".to_string(),
                        data: Some(metric::Data::Histogram(Histogram {
                            data_points: vec![HistogramDataPoint {
                                attributes: vec![],
                                start_time_unix_nano: 0,
                                time_unix_nano: 1700000000_000_000_000,
                                count: 100,
                                sum: Some(5000.0),
                                bucket_counts: vec![10, 30, 40, 15, 5],
                                explicit_bounds: vec![10.0, 50.0, 100.0, 500.0],
                                exemplars: vec![],
                                flags: 0,
                                min: Some(1.0),
                                max: Some(1000.0),
                            }],
                            aggregation_temporality: AggregationTemporality::Delta as i32,
                        })),
                        metadata: vec![],
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].metric_is_monotonic, None, "Histogram should not have is_monotonic");
        assert_eq!(rows[0].metric_temporality, Some("delta".to_string()), "Histogram should have temporality=delta");
    }

    #[test]
    fn test_resource_attribute_filtering() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        let row = &rows[0];
        let resource_keys: Vec<_> = row.resource_attrs.iter().map(|(k, _)| k.as_str()).collect();

        // service.name and k8s.pod.name are in KEEP_RESOURCE_KEYS
        assert!(resource_keys.contains(&"resource_service_name"));
        assert!(resource_keys.contains(&"resource_k8s_pod_name"));
        // host.name is NOT in KEEP_RESOURCE_KEYS
        assert!(!resource_keys.contains(&"resource_host_name"));
    }

    #[test]
    fn test_datapoint_attribute_filtering() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        let row = &rows[0];
        let dp_keys: Vec<_> = row.datapoint_attrs.iter().map(|(k, _)| k.as_str()).collect();

        // "env" should be included
        assert!(dp_keys.contains(&"attr_env"));
        // "_internal" should be filtered out (underscore-prefixed)
        assert!(!dp_keys.iter().any(|k| k.contains("internal")));
    }

    #[test]
    fn test_timestamp_truncation() {
        let ns = 1700000000_123_456_789u64; // Some nanoseconds
        let truncated = truncate_timestamp(ns);

        // Should be truncated to 10s intervals
        assert_eq!(truncated % TIMESTAMP_TRUNCATION_MS, 0);
        // Should be in milliseconds (1700000000123 ms -> truncated to 1700000000000)
        assert_eq!(truncated, 1700000000_000);

        // Another test with different value
        let ns2 = 1700000015_000_000_000u64; // 15 seconds later
        let truncated2 = truncate_timestamp(ns2);
        assert_eq!(truncated2, 1700000010_000); // Truncated to 10s boundary
    }

    #[test]
    fn test_tid_calculation() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        // TID should be non-zero
        assert_ne!(rows[0].chq_tid, 0);
        assert_ne!(rows[1].chq_tid, 0);

        // Different metrics should have different TIDs
        assert_ne!(rows[0].chq_tid, rows[1].chq_tid);
    }

    #[test]
    fn test_sketch_encoding() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        // Sketch should be non-empty
        assert!(!rows[0].chq_sketch.is_empty());

        // Should be decodable
        let sketch = DDSketch::decode(&rows[0].chq_sketch).expect("Failed to decode sketch");
        assert_eq!(sketch.count, 1.0);
    }

    #[test]
    fn test_write_and_read_binpb() {
        use crate::common::read_binpb_file;

        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_metrics_new.binpb");
        let mut file = std::fs::File::create(&temp_file).expect("Failed to create temp file");
        file.write_all(&encoded).expect("Failed to write binpb");
        drop(file);

        let data = read_binpb_file(temp_file.to_str().unwrap()).expect("Failed to read binpb");
        let rows = parse_metrics(&data, "test-customer").expect("Failed to parse metrics");

        assert_eq!(rows.len(), 2);

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_write_and_read_binpb_gz() {
        use crate::common::read_binpb_file;

        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let temp_dir = std::env::temp_dir();
        let temp_file = temp_dir.join("test_metrics_new.binpb.gz");
        let file = std::fs::File::create(&temp_file).expect("Failed to create temp file");
        let mut encoder = GzEncoder::new(file, Compression::default());
        encoder
            .write_all(&encoded)
            .expect("Failed to write gzipped binpb");
        encoder.finish().expect("Failed to finish gzip");

        let data =
            read_binpb_file(temp_file.to_str().unwrap()).expect("Failed to read gzipped binpb");
        let rows = parse_metrics(&data, "test-customer").expect("Failed to parse metrics");

        assert_eq!(rows.len(), 2);

        std::fs::remove_file(&temp_file).ok();
    }

    #[test]
    fn test_histogram_parsing() {
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("test-service".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: None,
                    metrics: vec![Metric {
                        name: "request.duration".to_string(),
                        description: "Request duration histogram".to_string(),
                        unit: "ms".to_string(),
                        data: Some(metric::Data::Histogram(Histogram {
                            data_points: vec![HistogramDataPoint {
                                attributes: vec![],
                                start_time_unix_nano: 0,
                                time_unix_nano: 1700000000_000_000_000,
                                count: 100,
                                sum: Some(5000.0),
                                bucket_counts: vec![10, 30, 40, 15, 5],
                                explicit_bounds: vec![10.0, 50.0, 100.0, 500.0],
                                exemplars: vec![],
                                flags: 0,
                                min: Some(1.0),
                                max: Some(1000.0),
                            }],
                            aggregation_temporality: AggregationTemporality::Cumulative as i32,
                        })),
                        metadata: vec![],
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].chq_metric_type, "histogram");
        assert_eq!(rows[0].chq_rollup_min, 1.0);
        assert_eq!(rows[0].chq_rollup_max, 1000.0);
    }

    #[test]
    fn test_summary_parsing() {
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("test-service".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: None,
                    metrics: vec![Metric {
                        name: "request.latency".to_string(),
                        description: "Request latency summary".to_string(),
                        unit: "ms".to_string(),
                        data: Some(metric::Data::Summary(Summary {
                            data_points: vec![SummaryDataPoint {
                                attributes: vec![],
                                start_time_unix_nano: 0,
                                time_unix_nano: 1700000000_000_000_000,
                                count: 1000,
                                sum: 50000.0,
                                quantile_values: vec![
                                    ValueAtQuantile { quantile: 0.5, value: 45.0 },
                                    ValueAtQuantile { quantile: 0.9, value: 90.0 },
                                    ValueAtQuantile { quantile: 0.99, value: 150.0 },
                                ],
                                flags: 0,
                            }],
                        })),
                        metadata: vec![],
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].chq_metric_type, "histogram"); // Summary -> histogram
        assert_eq!(rows[0].chq_rollup_sum, 50000.0);
    }

    #[test]
    fn test_empty_histogram_filtered() {
        // Empty histograms (all bucket counts = 0) should be dropped to match Go behavior
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("test-service".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: None,
                    metrics: vec![Metric {
                        name: "http.server.duration".to_string(),
                        description: "HTTP server request duration".to_string(),
                        unit: "ms".to_string(),
                        data: Some(metric::Data::Histogram(Histogram {
                            aggregation_temporality: 2, // Cumulative
                            data_points: vec![
                                // This datapoint has counts - should be kept
                                HistogramDataPoint {
                                    attributes: vec![KeyValue {
                                        key: "http.status_code".to_string(),
                                        value: Some(AnyValue {
                                            value: Some(any_value::Value::IntValue(200)),
                                        }),
                                    }],
                                    start_time_unix_nano: 0,
                                    time_unix_nano: 1700000000_000_000_000,
                                    count: 100,
                                    sum: Some(5000.0),
                                    bucket_counts: vec![10, 30, 40, 15, 5],
                                    explicit_bounds: vec![10.0, 50.0, 100.0, 500.0],
                                    exemplars: vec![],
                                    flags: 0,
                                    min: Some(1.0),
                                    max: Some(1000.0),
                                },
                                // This datapoint has all-zero counts - should be dropped
                                HistogramDataPoint {
                                    attributes: vec![KeyValue {
                                        key: "http.status_code".to_string(),
                                        value: Some(AnyValue {
                                            value: Some(any_value::Value::IntValue(500)),
                                        }),
                                    }],
                                    start_time_unix_nano: 0,
                                    time_unix_nano: 1700000000_000_000_000,
                                    count: 0,
                                    sum: Some(0.0),
                                    bucket_counts: vec![0, 0, 0, 0, 0], // All zeros
                                    explicit_bounds: vec![10.0, 50.0, 100.0, 500.0],
                                    exemplars: vec![],
                                    flags: 0,
                                    min: None,
                                    max: None,
                                },
                            ],
                        })),
                        metadata: vec![],
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        // Should only have 1 row (the one with counts), not 2
        assert_eq!(rows.len(), 1, "Empty histogram should be filtered out");
        assert_eq!(rows[0].metric_name, "http_server_duration");
        // rollup_count is computed from DDSketch, not the original count
        assert!(rows[0].chq_rollup_count > 0.0, "rollup_count should be positive");
    }

    #[test]
    fn test_empty_exp_histogram_filtered() {
        use crate::opentelemetry::proto::metrics::v1::{
            ExponentialHistogram, ExponentialHistogramDataPoint,
        };

        // Empty exponential histograms should also be dropped
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "service.name".to_string(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("test-service".to_string())),
                        }),
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: None,
                    metrics: vec![Metric {
                        name: "request.latency".to_string(),
                        description: "Request latency".to_string(),
                        unit: "ms".to_string(),
                        data: Some(metric::Data::ExponentialHistogram(ExponentialHistogram {
                            aggregation_temporality: 2,
                            data_points: vec![
                                // This datapoint has positive bucket counts - should be kept
                                ExponentialHistogramDataPoint {
                                    attributes: vec![],
                                    start_time_unix_nano: 0,
                                    time_unix_nano: 1700000000_000_000_000,
                                    count: 50,
                                    sum: Some(2500.0),
                                    scale: 3,
                                    zero_count: 0,
                                    positive: Some(
                                        crate::opentelemetry::proto::metrics::v1::exponential_histogram_data_point::Buckets {
                                            offset: 0,
                                            bucket_counts: vec![10, 20, 15, 5],
                                        },
                                    ),
                                    negative: None,
                                    flags: 0,
                                    exemplars: vec![],
                                    min: Some(10.0),
                                    max: Some(200.0),
                                    zero_threshold: 0.0,
                                },
                                // This datapoint has no counts at all - should be dropped
                                ExponentialHistogramDataPoint {
                                    attributes: vec![],
                                    start_time_unix_nano: 0,
                                    time_unix_nano: 1700000000_000_000_000,
                                    count: 0,
                                    sum: Some(0.0),
                                    scale: 3,
                                    zero_count: 0, // No zero count
                                    positive: Some(
                                        crate::opentelemetry::proto::metrics::v1::exponential_histogram_data_point::Buckets {
                                            offset: 0,
                                            bucket_counts: vec![0, 0, 0, 0], // All zeros
                                        },
                                    ),
                                    negative: None,
                                    flags: 0,
                                    exemplars: vec![],
                                    min: None,
                                    max: None,
                                    zero_threshold: 0.0,
                                },
                            ],
                        })),
                        metadata: vec![],
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_metrics(&encoded, "test-customer").expect("Failed to parse metrics");

        // Should only have 1 row (the one with counts), not 2
        assert_eq!(rows.len(), 1, "Empty exponential histogram should be filtered out");
        assert_eq!(rows[0].metric_name, "request_latency");
        assert_eq!(rows[0].chq_rollup_count, 50.0);
    }
}
