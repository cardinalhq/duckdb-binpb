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

//! TID (Time-series ID) calculation for metrics.
//!
//! The TID is a hash that identifies a unique time series. It is computed from:
//! - metric_name (normalized)
//! - chq_metric_type
//! - resource_* attributes (only allowed keys)
//! - attr_* attributes (excluding underscore-prefixed)
//!
//! The format is: `key=value|key=value|...` with keys sorted alphabetically.

use fnv::FnvHasher;
use std::hash::Hasher;

use crate::normalize::normalize_attribute_name;

/// Resource attribute keys that are included in TID computation.
/// Keys are stored WITHOUT the "resource_" prefix.
pub const KEEP_RESOURCE_KEYS: &[&str] = &[
    "app",
    "container_image_name",
    "container_image_tag",
    "k8s_cluster_name",
    "k8s_daemonset_name",
    "k8s_deployment_name",
    "k8s_namespace_name",
    "k8s_pod_ip",
    "k8s_pod_name",
    "k8s_statefulset_name",
    "service_name",
    "service_version",
];

/// Check if a normalized resource key should be kept for TID computation.
pub fn should_keep_resource_key(normalized_key: &str) -> bool {
    KEEP_RESOURCE_KEYS.contains(&normalized_key)
}

/// Convert OTEL metric type to canonical string representation.
pub fn metric_type_to_string(metric_type: &str) -> &'static str {
    match metric_type {
        "gauge" => "gauge",
        "sum" => "count",
        "histogram" | "exponential_histogram" | "summary" => "histogram",
        _ => "gauge",
    }
}

/// Key-value pair for TID computation
struct TidKV {
    key: String,
    value: String,
}

/// Compute TID from a set of key-value pairs.
///
/// The tags map should contain:
/// - "metric_name" -> normalized metric name
/// - "chq_metric_type" -> metric type string
/// - "resource_*" -> resource attributes (already prefixed)
/// - "attr_*" -> datapoint attributes (already prefixed)
///
/// Only string values are considered. Empty values are filtered out.
pub fn compute_tid(tags: &[(&str, &str)]) -> i64 {
    let mut kvs: Vec<TidKV> = Vec::with_capacity(tags.len());

    for (key, value) in tags {
        // Skip empty values
        if value.is_empty() {
            continue;
        }

        // Only include specific key patterns
        if *key == "metric_name"
            || *key == "chq_metric_type"
            || key.starts_with("resource_")
            || key.starts_with("attr_")
        {
            kvs.push(TidKV {
                key: key.to_string(),
                value: value.to_string(),
            });
        }
    }

    // Sort by key for deterministic hashing
    kvs.sort_by(|a, b| a.key.cmp(&b.key));

    // Build hash input: key=value|key=value|...
    let mut hasher = FnvHasher::default();
    for kv in &kvs {
        hasher.write(kv.key.as_bytes());
        hasher.write(b"=");
        hasher.write(kv.value.as_bytes());
        hasher.write(b"|");
    }

    hasher.finish() as i64
}

/// Compute TID directly from OTEL-style attributes.
///
/// This is the primary entry point for computing TID from parsed OTEL data.
///
/// # Arguments
/// * `metric_name` - The original OTEL metric name (will be normalized)
/// * `metric_type` - The OTEL metric type ("gauge", "sum", "histogram", etc.)
/// * `resource_attrs` - Resource attributes as (key, value) pairs (keys will be normalized and filtered)
/// * `datapoint_attrs` - Datapoint attributes as (key, value) pairs (keys will be normalized)
pub fn compute_tid_from_otel(
    metric_name: &str,
    metric_type: &str,
    resource_attrs: &[(&str, &str)],
    datapoint_attrs: &[(&str, &str)],
) -> i64 {
    let mut kvs: Vec<TidKV> = Vec::with_capacity(2 + resource_attrs.len() + datapoint_attrs.len());

    // Add normalized metric name
    let normalized_metric_name = normalize_attribute_name(metric_name);
    if !normalized_metric_name.is_empty() {
        kvs.push(TidKV {
            key: "metric_name".to_string(),
            value: normalized_metric_name,
        });
    }

    // Add metric type
    kvs.push(TidKV {
        key: "chq_metric_type".to_string(),
        value: metric_type_to_string(metric_type).to_string(),
    });

    // Add filtered resource attributes (prefixed with "resource_")
    for (key, value) in resource_attrs {
        if value.is_empty() {
            continue;
        }
        let normalized_key = normalize_attribute_name(key);
        if should_keep_resource_key(&normalized_key) {
            kvs.push(TidKV {
                key: format!("resource_{}", normalized_key),
                value: value.to_string(),
            });
        }
    }

    // Add datapoint attributes (prefixed with "attr_")
    // Skip underscore-prefixed attributes
    for (key, value) in datapoint_attrs {
        if value.is_empty() {
            continue;
        }
        // Skip underscore-prefixed attributes (internal/special attributes)
        if key.starts_with('_') {
            continue;
        }
        let normalized_key = normalize_attribute_name(key);
        kvs.push(TidKV {
            key: format!("attr_{}", normalized_key),
            value: value.to_string(),
        });
    }

    // Sort by key for deterministic hashing
    kvs.sort_by(|a, b| a.key.cmp(&b.key));

    // Build hash input: key=value|key=value|...
    let mut hasher = FnvHasher::default();
    for kv in &kvs {
        hasher.write(kv.key.as_bytes());
        hasher.write(b"=");
        hasher.write(kv.value.as_bytes());
        hasher.write(b"|");
    }

    hasher.finish() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Tests: TID changes when specific fields change
    // =========================================================================

    #[test]
    fn test_tid_changes_with_metric_name() {
        let tid1 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "metric2"),
            ("resource_service_name", "server1"),
        ]);
        assert_ne!(tid1, tid2, "TID should change when metric_name changes");
    }

    #[test]
    fn test_tid_changes_with_chq_metric_type() {
        let tid1 = compute_tid(&[
            ("metric_name", "metric1"),
            ("chq_metric_type", "gauge"),
            ("resource_service_name", "server1"),
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "metric1"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "server1"),
        ]);
        assert_ne!(tid1, tid2, "TID should change when chq_metric_type changes");
    }

    #[test]
    fn test_tid_changes_with_resource_fields() {
        // Test adding a resource field
        let tid1 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
            ("resource_k8s_pod_name", "pod-123"),
        ]);
        assert_ne!(tid1, tid2, "TID should change when resource field is added");

        // Test changing a resource field value
        let tid3 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server2"),
        ]);
        assert_ne!(tid1, tid3, "TID should change when resource field value changes");

        // Test removing a resource field
        let tid4 = compute_tid(&[("metric_name", "metric1")]);
        assert_ne!(tid1, tid4, "TID should change when resource field is removed");
    }

    #[test]
    fn test_tid_changes_with_attr_fields() {
        // Test adding an attr field
        let tid1 = compute_tid(&[("metric_name", "metric1"), ("attr_label1", "value1")]);
        let tid2 = compute_tid(&[
            ("metric_name", "metric1"),
            ("attr_label1", "value1"),
            ("attr_label2", "value2"),
        ]);
        assert_ne!(tid1, tid2, "TID should change when attr field is added");

        // Test changing an attr field value
        let tid3 = compute_tid(&[("metric_name", "metric1"), ("attr_label1", "value3")]);
        assert_ne!(tid1, tid3, "TID should change when attr field value changes");
    }

    // =========================================================================
    // Tests: TID does NOT change for certain fields
    // =========================================================================

    #[test]
    fn test_tid_does_not_change_with_scope_fields() {
        let tid1 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
            ("scope_name", "my-scope"),
            ("scope_version", "1.0.0"),
        ]);
        assert_eq!(tid1, tid2, "TID should not change when scope fields are added");
    }

    #[test]
    fn test_tid_does_not_change_with_arbitrary_fields() {
        let tid1 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
            ("alice", "value"),
            ("bob", "another"),
            ("random_field", "ignored"),
        ]);
        assert_eq!(
            tid1, tid2,
            "TID should not change when arbitrary fields are added"
        );
    }

    #[test]
    fn test_tid_ignores_other_chq_fields() {
        let tid1 = compute_tid(&[
            ("metric_name", "metric1"),
            ("chq_metric_type", "gauge"),
            ("resource_service_name", "server1"),
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "metric1"),
            ("chq_metric_type", "gauge"),
            ("resource_service_name", "server1"),
            ("chq_timestamp", "123456789"),
            ("chq_description", "some description"),
            ("chq_unit", "bytes"),
        ]);
        assert_eq!(
            tid1, tid2,
            "TID should not change when other chq_* fields are added"
        );
    }

    // =========================================================================
    // Tests: Edge cases
    // =========================================================================

    #[test]
    fn test_tid_is_deterministic() {
        let tags = [
            ("metric_name", "metric1"),
            ("chq_metric_type", "gauge"),
            ("resource_service_name", "server1"),
            ("resource_k8s_pod_name", "pod-123"),
            ("attr_label1", "value1"),
            ("attr_label2", "value2"),
        ];
        let tid1 = compute_tid(&tags);
        let tid2 = compute_tid(&tags);
        let tid3 = compute_tid(&tags);
        assert_eq!(tid1, tid2, "TID should be deterministic");
        assert_eq!(tid1, tid3, "TID should be deterministic");
    }

    #[test]
    fn test_tid_empty_values_are_filtered() {
        let tid1 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
            ("resource_k8s_pod_name", ""), // empty string should be filtered
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "metric1"),
            ("resource_service_name", "server1"),
        ]);
        assert_eq!(tid1, tid2, "Empty string values should be filtered out");
    }

    // =========================================================================
    // Tests: compute_tid_from_otel
    // =========================================================================

    #[test]
    fn test_compute_tid_from_otel_basic() {
        let tid = compute_tid_from_otel(
            "http.server.requests",
            "gauge",
            &[("service.name", "my-service")],
            &[("http.method", "GET")],
        );

        // Verify it matches compute_tid with normalized values
        let expected_tid = compute_tid(&[
            ("metric_name", "http_server_requests"),
            ("chq_metric_type", "gauge"),
            ("resource_service_name", "my-service"),
            ("attr_http_method", "GET"),
        ]);

        assert_eq!(tid, expected_tid, "compute_tid_from_otel should match compute_tid");
    }

    #[test]
    fn test_compute_tid_from_otel_filters_resource_keys() {
        // host.name is NOT in KEEP_RESOURCE_KEYS, should be filtered
        let tid1 = compute_tid_from_otel(
            "test_metric",
            "gauge",
            &[("service.name", "my-service"), ("host.name", "server01")],
            &[],
        );
        let tid2 = compute_tid_from_otel(
            "test_metric",
            "gauge",
            &[("service.name", "my-service")],
            &[],
        );
        assert_eq!(
            tid1, tid2,
            "Non-kept resource keys should be filtered"
        );
    }

    #[test]
    fn test_compute_tid_from_otel_skips_underscore_prefixed() {
        let tid1 = compute_tid_from_otel(
            "test_metric",
            "gauge",
            &[("service.name", "my-service")],
            &[("_cardinalhq.collector_id", "chq-123"), ("normal.attr", "value")],
        );
        let tid2 = compute_tid_from_otel(
            "test_metric",
            "gauge",
            &[("service.name", "my-service")],
            &[("normal.attr", "value")],
        );
        assert_eq!(
            tid1, tid2,
            "Underscore-prefixed attributes should be skipped"
        );
    }

    #[test]
    fn test_compute_tid_from_otel_metric_type_conversion() {
        // "sum" should become "count"
        let tid_sum = compute_tid_from_otel("metric", "sum", &[], &[]);
        let tid_count = compute_tid(&[
            ("metric_name", "metric"),
            ("chq_metric_type", "count"),
        ]);
        assert_eq!(tid_sum, tid_count, "sum should be converted to count");

        // "histogram" stays "histogram"
        let tid_hist = compute_tid_from_otel("metric", "histogram", &[], &[]);
        let tid_hist_expected = compute_tid(&[
            ("metric_name", "metric"),
            ("chq_metric_type", "histogram"),
        ]);
        assert_eq!(tid_hist, tid_hist_expected);

        // "exponential_histogram" becomes "histogram"
        let tid_exp_hist = compute_tid_from_otel("metric", "exponential_histogram", &[], &[]);
        assert_eq!(tid_exp_hist, tid_hist_expected, "exponential_histogram should become histogram");

        // "summary" becomes "histogram"
        let tid_summary = compute_tid_from_otel("metric", "summary", &[], &[]);
        assert_eq!(tid_summary, tid_hist_expected, "summary should become histogram");
    }

    // =========================================================================
    // Tests: Cross-validation with Go implementation
    // These tests use known TID values from the Go implementation to ensure
    // our Rust implementation produces identical results.
    // =========================================================================

    #[test]
    fn test_tid_cross_validation_simple() {
        // This test requires running the Go code to get the expected value.
        // For now, we verify the format is correct by checking determinism.
        let tid = compute_tid(&[
            ("metric_name", "test_metric"),
            ("chq_metric_type", "gauge"),
            ("resource_service_name", "my-service"),
        ]);

        // The TID should be non-zero and consistent
        assert_ne!(tid, 0);

        // Re-compute to verify determinism
        let tid2 = compute_tid(&[
            ("metric_name", "test_metric"),
            ("chq_metric_type", "gauge"),
            ("resource_service_name", "my-service"),
        ]);
        assert_eq!(tid, tid2);
    }

    #[test]
    fn test_tid_cross_validation_with_otel() {
        // Test that matches Go's TestComputeTIDFromOTEL_MatchesComputeTID
        // gauge with all KeepResourceKeys
        let tid = compute_tid_from_otel(
            "test_metric",
            "gauge",
            &[
                ("service.name", "my-service"),
                ("service.version", "1.0.0"),
                ("k8s.pod.name", "pod-123"),
            ],
            &[("http.method", "GET"), ("http.status", "200")],
        );

        // Verify against equivalent compute_tid call
        let expected = compute_tid(&[
            ("metric_name", "test_metric"),
            ("chq_metric_type", "gauge"),
            ("resource_service_name", "my-service"),
            ("resource_service_version", "1.0.0"),
            ("resource_k8s_pod_name", "pod-123"),
            ("attr_http_method", "GET"),
            ("attr_http_status", "200"),
        ]);

        assert_eq!(tid, expected);
    }

    /// Cross-validation with Go implementation.
    /// These test cases match TestTID_CrossValidation_WithRust in Go.
    #[test]
    fn test_tid_cross_validation_with_go() {
        // Test 1: simple gauge metric
        // Go hash input: "chq_metric_type=gauge|metric_name=test_metric|resource_service_name=my-service|"
        // Go TID: 4261145125547256768 (0x3b22a0ea48a1abc0)
        let tid1 = compute_tid(&[
            ("chq_metric_type", "gauge"),
            ("metric_name", "test_metric"),
            ("resource_service_name", "my-service"),
        ]);
        println!("Test 1 (simple gauge): TID={} (0x{:x})", tid1, tid1 as u64);
        assert_eq!(
            tid1, 4261145125547256768,
            "simple gauge metric TID must match Go"
        );

        // Test 2: count metric with attributes
        // Go hash input: "attr_http_method=GET|attr_http_status=200|chq_metric_type=count|metric_name=http_server_requests|resource_k8s_pod_name=pod-123|resource_service_name=my-service|resource_service_version=1.0.0|"
        // Go TID: -7350676297560190200 (0x99fd26da590a9308)
        let tid2 = compute_tid(&[
            ("attr_http_method", "GET"),
            ("attr_http_status", "200"),
            ("chq_metric_type", "count"),
            ("metric_name", "http_server_requests"),
            ("resource_k8s_pod_name", "pod-123"),
            ("resource_service_name", "my-service"),
            ("resource_service_version", "1.0.0"),
        ]);
        println!("Test 2 (count with attrs): TID={} (0x{:x})", tid2, tid2 as u64);
        assert_eq!(
            tid2, -7350676297560190200_i64,
            "count metric with attributes TID must match Go"
        );
    }

    #[test]
    fn test_keep_resource_keys() {
        // Verify all expected keys are in the list
        assert!(should_keep_resource_key("app"));
        assert!(should_keep_resource_key("container_image_name"));
        assert!(should_keep_resource_key("container_image_tag"));
        assert!(should_keep_resource_key("k8s_cluster_name"));
        assert!(should_keep_resource_key("k8s_daemonset_name"));
        assert!(should_keep_resource_key("k8s_deployment_name"));
        assert!(should_keep_resource_key("k8s_namespace_name"));
        assert!(should_keep_resource_key("k8s_pod_ip"));
        assert!(should_keep_resource_key("k8s_pod_name"));
        assert!(should_keep_resource_key("k8s_statefulset_name"));
        assert!(should_keep_resource_key("service_name"));
        assert!(should_keep_resource_key("service_version"));

        // Verify non-kept keys are rejected
        assert!(!should_keep_resource_key("host_name"));
        assert!(!should_keep_resource_key("process_pid"));
        assert!(!should_keep_resource_key("custom_label"));
    }

    // =========================================================================
    // Tests: metric_is_monotonic and metric_temporality are NOT in TID
    // =========================================================================

    #[test]
    fn test_tid_does_not_change_with_metric_is_monotonic() {
        // metric_is_monotonic should NOT affect TID calculation
        // Even if it were passed, it would be ignored since it doesn't match
        // the allowed key patterns (metric_name, chq_metric_type, resource_*, attr_*)
        let tid1 = compute_tid(&[
            ("metric_name", "test_counter"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "server1"),
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "test_counter"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "server1"),
            ("metric_is_monotonic", "true"),
        ]);
        let tid3 = compute_tid(&[
            ("metric_name", "test_counter"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "server1"),
            ("metric_is_monotonic", "false"),
        ]);
        assert_eq!(tid1, tid2, "TID should not change when metric_is_monotonic is added");
        assert_eq!(tid1, tid3, "TID should not change with different metric_is_monotonic values");
    }

    #[test]
    fn test_tid_does_not_change_with_metric_temporality() {
        // metric_temporality should NOT affect TID calculation
        // Even if it were passed, it would be ignored since it doesn't match
        // the allowed key patterns (metric_name, chq_metric_type, resource_*, attr_*)
        let tid1 = compute_tid(&[
            ("metric_name", "test_counter"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "server1"),
        ]);
        let tid2 = compute_tid(&[
            ("metric_name", "test_counter"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "server1"),
            ("metric_temporality", "delta"),
        ]);
        let tid3 = compute_tid(&[
            ("metric_name", "test_counter"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "server1"),
            ("metric_temporality", "cumulative"),
        ]);
        assert_eq!(tid1, tid2, "TID should not change when metric_temporality is added");
        assert_eq!(tid1, tid3, "TID should not change with different metric_temporality values");
    }

    #[test]
    fn test_tid_excludes_aggregation_fields_comprehensive() {
        // Comprehensive test: TID should be identical regardless of is_monotonic
        // and temporality combinations
        let base_tid = compute_tid(&[
            ("metric_name", "http_requests_total"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "api-server"),
            ("resource_k8s_pod_name", "pod-abc123"),
            ("attr_http_method", "GET"),
            ("attr_http_status", "200"),
        ]);

        // All these should produce the same TID
        let with_monotonic = compute_tid(&[
            ("metric_name", "http_requests_total"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "api-server"),
            ("resource_k8s_pod_name", "pod-abc123"),
            ("attr_http_method", "GET"),
            ("attr_http_status", "200"),
            ("metric_is_monotonic", "true"),
        ]);

        let with_temporality = compute_tid(&[
            ("metric_name", "http_requests_total"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "api-server"),
            ("resource_k8s_pod_name", "pod-abc123"),
            ("attr_http_method", "GET"),
            ("attr_http_status", "200"),
            ("metric_temporality", "cumulative"),
        ]);

        let with_both = compute_tid(&[
            ("metric_name", "http_requests_total"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "api-server"),
            ("resource_k8s_pod_name", "pod-abc123"),
            ("attr_http_method", "GET"),
            ("attr_http_status", "200"),
            ("metric_is_monotonic", "true"),
            ("metric_temporality", "cumulative"),
        ]);

        let with_delta = compute_tid(&[
            ("metric_name", "http_requests_total"),
            ("chq_metric_type", "count"),
            ("resource_service_name", "api-server"),
            ("resource_k8s_pod_name", "pod-abc123"),
            ("attr_http_method", "GET"),
            ("attr_http_status", "200"),
            ("metric_is_monotonic", "false"),
            ("metric_temporality", "delta"),
        ]);

        assert_eq!(base_tid, with_monotonic, "metric_is_monotonic should be excluded from TID");
        assert_eq!(base_tid, with_temporality, "metric_temporality should be excluded from TID");
        assert_eq!(base_tid, with_both, "Both aggregation fields should be excluded from TID");
        assert_eq!(base_tid, with_delta, "Different aggregation values should produce same TID");
    }
}
