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

//! OpenTelemetry traces processing for DuckDB.

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
use crate::fingerprint::generate_span_fingerprints;
use crate::normalize::normalize_attribute_name;
use crate::opentelemetry::proto::{
    collector::trace::v1::ExportTraceServiceRequest,
    common::v1::KeyValue,
    trace::v1::span::SpanKind,
    trace::v1::status::StatusCode,
};

// ============================================================================
// Flattened span row representation
// ============================================================================

/// A single flattened span row with CHQ schema
#[derive(Debug, Clone)]
pub struct SpanRow {
    // CHQ system fields
    pub chq_customer_id: String,
    pub chq_telemetry_type: String, // Always "traces"
    pub chq_timestamp: i64,         // Start time in milliseconds
    pub chq_tsns: i64,              // Start time in nanoseconds
    pub chq_fingerprint: String,    // JSON array of fingerprint i64 values

    // Span identification
    pub span_trace_id: String,
    pub span_id: String,
    pub span_parent_span_id: String,

    // Span metadata
    pub span_name: String,
    pub span_kind: String,
    pub span_status_code: String,
    pub span_status_message: Option<String>,

    // Timing
    pub span_end_timestamp: i64, // End time in milliseconds
    pub span_duration: i64,      // Duration in milliseconds

    // Scope
    pub scope_name: String,
    pub scope_version: String,

    // Dynamic attributes
    pub resource_attrs: Arc<Vec<(String, String)>>,
    pub scope_attrs: Vec<(String, String)>,
    pub span_attrs: Vec<(String, String)>,
}

// ============================================================================
// Parsing helpers
// ============================================================================

/// Extract attributes as (normalized_key, value_string) pairs with prefix
fn extract_attrs_with_prefix(attrs: &[KeyValue], prefix: &str) -> Vec<(String, String)> {
    attrs
        .iter()
        .filter_map(|kv| {
            let value = any_value_to_string(&kv.value);
            if value.is_empty() {
                None
            } else {
                let normalized_key = normalize_attribute_name(&kv.key);
                Some((format!("{}_{}", prefix, normalized_key), value))
            }
        })
        .collect()
}

/// Convert bytes to hex string for trace/span IDs
fn bytes_to_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
        String::new()
    } else {
        hex::encode(bytes)
    }
}

/// Convert SpanKind enum to string
fn span_kind_to_string(kind: i32) -> String {
    match SpanKind::try_from(kind) {
        Ok(SpanKind::Unspecified) => "SPAN_KIND_UNSPECIFIED".to_string(),
        Ok(SpanKind::Internal) => "SPAN_KIND_INTERNAL".to_string(),
        Ok(SpanKind::Server) => "SPAN_KIND_SERVER".to_string(),
        Ok(SpanKind::Client) => "SPAN_KIND_CLIENT".to_string(),
        Ok(SpanKind::Producer) => "SPAN_KIND_PRODUCER".to_string(),
        Ok(SpanKind::Consumer) => "SPAN_KIND_CONSUMER".to_string(),
        Err(_) => "SPAN_KIND_UNSPECIFIED".to_string(),
    }
}

/// Convert StatusCode enum to string
fn status_code_to_string(code: i32) -> String {
    match StatusCode::try_from(code) {
        Ok(StatusCode::Unset) => "STATUS_CODE_UNSET".to_string(),
        Ok(StatusCode::Ok) => "STATUS_CODE_OK".to_string(),
        Ok(StatusCode::Error) => "STATUS_CODE_ERROR".to_string(),
        Err(_) => "STATUS_CODE_UNSET".to_string(),
    }
}

/// Get timestamp in milliseconds with fallback to current time
fn get_timestamp_ms(time_unix_nano: u64) -> i64 {
    if time_unix_nano > 0 {
        (time_unix_nano / 1_000_000) as i64
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// Get timestamp in nanoseconds
fn get_timestamp_ns(time_unix_nano: u64) -> i64 {
    if time_unix_nano > 0 {
        time_unix_nano as i64
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0)
    }
}

// ============================================================================
// Main parsing function
// ============================================================================

/// Parse traces from binary protobuf data
pub fn parse_traces(
    data: &[u8],
    customer_id: &str,
) -> Result<Vec<SpanRow>, Box<dyn Error>> {
    let request = ExportTraceServiceRequest::decode(data)?;
    let mut rows = Vec::new();

    for rs in &request.resource_spans {
        // Get resource attributes (wrapped in Arc for sharing)
        let resource_attrs = Arc::new(
            rs.resource
                .as_ref()
                .map(|r| extract_attrs_with_prefix(&r.attributes, "resource"))
                .unwrap_or_default(),
        );

        for ss in &rs.scope_spans {
            let (scope_name, scope_version, scope_attrs) = ss
                .scope
                .as_ref()
                .map(|s| {
                    (
                        s.name.clone(),
                        s.version.clone(),
                        extract_attrs_with_prefix(&s.attributes, "scope"),
                    )
                })
                .unwrap_or_default();

            for span in &ss.spans {
                let start_ms = get_timestamp_ms(span.start_time_unix_nano);
                let end_ms = get_timestamp_ms(span.end_time_unix_nano);

                // Calculate duration - set to 0 if either timestamp required fallback
                let duration = if span.start_time_unix_nano > 0 && span.end_time_unix_nano > 0 {
                    end_ms - start_ms
                } else {
                    0
                };

                let status_code = span
                    .status
                    .as_ref()
                    .map(|s| status_code_to_string(s.code))
                    .unwrap_or_else(|| "STATUS_CODE_UNSET".to_string());

                let status_message = span
                    .status
                    .as_ref()
                    .and_then(|s| {
                        if s.message.is_empty() {
                            None
                        } else {
                            Some(s.message.clone())
                        }
                    });

                let span_attrs = extract_attrs_with_prefix(&span.attributes, "attr");
                let trace_id = bytes_to_hex(&span.trace_id);

                // Compute fingerprints for this span
                let fingerprints = generate_span_fingerprints(
                    &resource_attrs,
                    &scope_attrs,
                    &span_attrs,
                    "traces",
                    &trace_id,
                );
                // Format fingerprints as JSON array
                let chq_fingerprint = format!(
                    "[{}]",
                    fingerprints
                        .iter()
                        .map(|f| f.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                );

                rows.push(SpanRow {
                    chq_customer_id: customer_id.to_string(),
                    chq_telemetry_type: "traces".to_string(),
                    chq_timestamp: start_ms,
                    chq_tsns: get_timestamp_ns(span.start_time_unix_nano),
                    chq_fingerprint,
                    span_trace_id: trace_id,
                    span_id: bytes_to_hex(&span.span_id),
                    span_parent_span_id: bytes_to_hex(&span.parent_span_id),
                    span_name: span.name.clone(),
                    span_kind: span_kind_to_string(span.kind),
                    span_status_code: status_code,
                    span_status_message: status_message,
                    span_end_timestamp: end_ms,
                    span_duration: duration,
                    scope_name: scope_name.clone(),
                    scope_version: scope_version.clone(),
                    resource_attrs: Arc::clone(&resource_attrs),
                    scope_attrs: scope_attrs.clone(),
                    span_attrs,
                });
            }
        }
    }

    Ok(rows)
}

// ============================================================================
// File input helpers (shared with logs)
// ============================================================================

/// Expand a file path that may contain glob patterns into a list of matching files.
fn expand_file_input(input: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let input = input.trim();

    // Check for list syntax: [file1, file2, ...]
    if input.starts_with('[') && input.ends_with(']') {
        let inner = &input[1..input.len() - 1];
        let mut paths = Vec::new();
        for part in inner.split(',') {
            let path = part.trim().trim_matches(|c| c == '\'' || c == '"');
            if !path.is_empty() {
                let expanded = expand_single_path(path)?;
                paths.extend(expanded);
            }
        }
        if paths.is_empty() {
            return Err("Empty file list".into());
        }
        return Ok(paths);
    }

    expand_single_path(input)
}

/// Expand a single file path that may be a glob pattern
fn expand_single_path(pattern: &str) -> Result<Vec<String>, Box<dyn Error>> {
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
        Ok(vec![pattern.to_string()])
    }
}

// ============================================================================
// DuckDB Table Function
// ============================================================================

#[repr(C)]
pub struct TracesBindData {
    rows: Vec<SpanRow>,
    resource_attr_names: Vec<String>,
    scope_attr_names: Vec<String>,
    span_attr_names: Vec<String>,
}

#[repr(C)]
pub struct TracesInitData {
    current_row: AtomicUsize,
}

pub struct ReadTracesVTab;

impl VTab for ReadTracesVTab {
    type InitData = TracesInitData;
    type BindData = TracesBindData;

    fn bind(bind: &BindInfo) -> Result<Self::BindData, Box<dyn Error>> {
        let param_count = bind.get_parameter_count();
        if param_count < 1 {
            return Err(
                "Usage: otel_traces_read('file.binpb', customer_id='xxx')"
                    .into(),
            );
        }

        // Get customer_id from named parameter (required)
        let customer_id = bind
            .get_named_parameter("customer_id")
            .ok_or("Missing required named parameter: customer_id")?
            .to_string();

        // Get file path(s) from first positional parameter
        let file_input = bind.get_parameter(0).to_string();
        let file_paths = expand_file_input(&file_input)?;

        // Parse all files and collect rows
        let mut all_rows = Vec::new();
        for file_path in &file_paths {
            let data = read_binpb_file(file_path)?;
            let rows = parse_traces(&data, &customer_id)?;
            all_rows.extend(rows);
        }

        // Compute superset of attribute columns from all rows
        let (resource_attr_names, scope_attr_names, span_attr_names) =
            collect_attr_names(&all_rows);

        // Fixed columns - CHQ schema for traces
        bind.add_result_column("chq_customer_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_telemetry_type", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_timestamp", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("chq_tsns", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("chq_fingerprint", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_trace_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_parent_span_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_name", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_kind", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_status_code", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_status_message", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_end_timestamp", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("span_duration", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("scope_name", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("scope_version", LogicalTypeHandle::from(LogicalTypeId::Varchar));

        // Dynamic columns
        for name in &resource_attr_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }
        for name in &scope_attr_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }
        for name in &span_attr_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }

        Ok(TracesBindData {
            rows: all_rows,
            resource_attr_names,
            scope_attr_names,
            span_attr_names,
        })
    }

    fn init(_: &InitInfo) -> Result<Self::InitData, Box<dyn Error>> {
        Ok(TracesInitData {
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

        for (i, row) in bind_data.rows[start_row..end_row].iter().enumerate() {
            let mut col = 0;

            // Fixed columns
            output.flat_vector(col).insert(i, row.chq_customer_id.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_telemetry_type.as_bytes());
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.chq_timestamp;
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.chq_tsns;
            col += 1;

            output.flat_vector(col).insert(i, row.chq_fingerprint.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.span_trace_id.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.span_id.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.span_parent_span_id.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.span_name.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.span_kind.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.span_status_code.as_bytes());
            col += 1;

            // span_status_message (nullable)
            match &row.span_status_message {
                Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                None => output.flat_vector(col).set_null(i),
            }
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.span_end_timestamp;
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.span_duration;
            col += 1;

            output.flat_vector(col).insert(i, row.scope_name.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.scope_version.as_bytes());
            col += 1;

            // Dynamic resource attributes
            for name in &bind_data.resource_attr_names {
                let value = row.resource_attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v);
                match value {
                    Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                    None => output.flat_vector(col).set_null(i),
                }
                col += 1;
            }

            // Dynamic scope attributes
            for name in &bind_data.scope_attr_names {
                let value = row.scope_attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v);
                match value {
                    Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                    None => output.flat_vector(col).set_null(i),
                }
                col += 1;
            }

            // Dynamic span attributes
            for name in &bind_data.span_attr_names {
                let value = row.span_attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v);
                match value {
                    Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                    None => output.flat_vector(col).set_null(i),
                }
                col += 1;
            }
        }

        output.set_len(rows_to_output);
        Ok(())
    }

    fn parameters() -> Option<Vec<LogicalTypeHandle>> {
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
fn collect_attr_names(rows: &[SpanRow]) -> (Vec<String>, Vec<String>, Vec<String>) {
    use std::collections::HashSet;

    let mut resource_set: HashSet<String> = HashSet::new();
    let mut scope_set: HashSet<String> = HashSet::new();
    let mut span_set: HashSet<String> = HashSet::new();

    for row in rows {
        for (key, _) in row.resource_attrs.iter() {
            resource_set.insert(key.clone());
        }
        for (key, _) in &row.scope_attrs {
            scope_set.insert(key.clone());
        }
        for (key, _) in &row.span_attrs {
            span_set.insert(key.clone());
        }
    }

    let mut resource_names: Vec<String> = resource_set.into_iter().collect();
    let mut scope_names: Vec<String> = scope_set.into_iter().collect();
    let mut span_names: Vec<String> = span_set.into_iter().collect();

    resource_names.sort();
    scope_names.sort();
    span_names.sort();

    (resource_names, scope_names, span_names)
}

/// Register traces table functions with DuckDB
pub fn register(con: &Connection) -> Result<(), Box<dyn Error>> {
    con.register_table_function::<ReadTracesVTab>("otel_traces_read")
        .map_err(|e| format!("Failed to register otel_traces_read: {}", e))?;
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
        trace::v1::{ResourceSpans, ScopeSpans, Span, Status},
        resource::v1::Resource,
    };
    use prost::Message;

    fn create_sample_request() -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
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
                            key: "k8s.namespace.name".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "production".to_string(),
                                )),
                            }),
                        },
                    ],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "opentelemetry-go".to_string(),
                        version: "1.21.0".to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    }),
                    spans: vec![
                        Span {
                            trace_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                            span_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
                            trace_state: "".to_string(),
                            parent_span_id: vec![],
                            flags: 0,
                            name: "GET /api/users".to_string(),
                            kind: SpanKind::Server as i32,
                            start_time_unix_nano: 1700000000_000_000_000,
                            end_time_unix_nano: 1700000000_050_000_000, // 50ms later
                            attributes: vec![
                                KeyValue {
                                    key: "http.request.method".to_string(),
                                    value: Some(AnyValue {
                                        value: Some(any_value::Value::StringValue("GET".to_string())),
                                    }),
                                },
                                KeyValue {
                                    key: "http.response.status_code".to_string(),
                                    value: Some(AnyValue {
                                        value: Some(any_value::Value::IntValue(200)),
                                    }),
                                },
                            ],
                            dropped_attributes_count: 0,
                            events: vec![],
                            dropped_events_count: 0,
                            links: vec![],
                            dropped_links_count: 0,
                            status: Some(Status {
                                message: "".to_string(),
                                code: StatusCode::Ok as i32,
                            }),
                        },
                        Span {
                            trace_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                            span_id: vec![2, 3, 4, 5, 6, 7, 8, 9],
                            trace_state: "".to_string(),
                            parent_span_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
                            flags: 0,
                            name: "SELECT users".to_string(),
                            kind: SpanKind::Client as i32,
                            start_time_unix_nano: 1700000000_010_000_000,
                            end_time_unix_nano: 1700000000_025_000_000, // 15ms
                            attributes: vec![
                                KeyValue {
                                    key: "db.system.name".to_string(),
                                    value: Some(AnyValue {
                                        value: Some(any_value::Value::StringValue(
                                            "postgresql".to_string(),
                                        )),
                                    }),
                                },
                                KeyValue {
                                    key: "db.operation.name".to_string(),
                                    value: Some(AnyValue {
                                        value: Some(any_value::Value::StringValue(
                                            "SELECT".to_string(),
                                        )),
                                    }),
                                },
                            ],
                            dropped_attributes_count: 0,
                            events: vec![],
                            dropped_events_count: 0,
                            links: vec![],
                            dropped_links_count: 0,
                            status: Some(Status {
                                message: "".to_string(),
                                code: StatusCode::Ok as i32,
                            }),
                        },
                    ],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        }
    }

    #[test]
    fn test_parse_traces() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_traces(&encoded, "test-customer").expect("Failed to parse traces");

        assert_eq!(rows.len(), 2, "Should have 2 spans");

        let row1 = &rows[0];
        assert_eq!(row1.chq_customer_id, "test-customer");
        assert_eq!(row1.chq_telemetry_type, "traces");
        assert_eq!(row1.span_name, "GET /api/users");
        assert_eq!(row1.span_kind, "SPAN_KIND_SERVER");
        assert_eq!(row1.span_status_code, "STATUS_CODE_OK");
        assert_eq!(row1.span_duration, 50); // 50ms
        assert!(row1.span_parent_span_id.is_empty()); // Root span
        // Verify fingerprint is a JSON array with at least one value
        assert!(row1.chq_fingerprint.starts_with('['), "Fingerprint should be JSON array");
        assert!(row1.chq_fingerprint.ends_with(']'), "Fingerprint should be JSON array");
        assert!(row1.chq_fingerprint.len() > 2, "Fingerprint array should not be empty");

        let row2 = &rows[1];
        assert_eq!(row2.span_name, "SELECT users");
        assert_eq!(row2.span_kind, "SPAN_KIND_CLIENT");
        assert_eq!(row2.span_duration, 15); // 15ms
        assert!(!row2.span_parent_span_id.is_empty()); // Has parent
    }

    #[test]
    fn test_span_kind_conversion() {
        assert_eq!(span_kind_to_string(0), "SPAN_KIND_UNSPECIFIED");
        assert_eq!(span_kind_to_string(1), "SPAN_KIND_INTERNAL");
        assert_eq!(span_kind_to_string(2), "SPAN_KIND_SERVER");
        assert_eq!(span_kind_to_string(3), "SPAN_KIND_CLIENT");
        assert_eq!(span_kind_to_string(4), "SPAN_KIND_PRODUCER");
        assert_eq!(span_kind_to_string(5), "SPAN_KIND_CONSUMER");
        assert_eq!(span_kind_to_string(99), "SPAN_KIND_UNSPECIFIED");
    }

    #[test]
    fn test_status_code_conversion() {
        assert_eq!(status_code_to_string(0), "STATUS_CODE_UNSET");
        assert_eq!(status_code_to_string(1), "STATUS_CODE_OK");
        assert_eq!(status_code_to_string(2), "STATUS_CODE_ERROR");
        assert_eq!(status_code_to_string(99), "STATUS_CODE_UNSET");
    }

    #[test]
    fn test_duration_calculation() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_traces(&encoded, "test").expect("Failed to parse");

        // First span: 50ms duration
        assert_eq!(rows[0].span_duration, 50);

        // Second span: 15ms duration
        assert_eq!(rows[1].span_duration, 15);
    }

    #[test]
    fn test_zero_timestamp_fallback() {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![Span {
                        trace_id: vec![1; 16],
                        span_id: vec![1; 8],
                        trace_state: "".to_string(),
                        parent_span_id: vec![],
                        flags: 0,
                        name: "test".to_string(),
                        kind: SpanKind::Internal as i32,
                        start_time_unix_nano: 0, // Zero - should fallback
                        end_time_unix_nano: 0,   // Zero - should fallback
                        attributes: vec![],
                        dropped_attributes_count: 0,
                        events: vec![],
                        dropped_events_count: 0,
                        links: vec![],
                        dropped_links_count: 0,
                        status: None,
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_traces(&encoded, "test").expect("Failed to parse");

        assert_eq!(rows.len(), 1);
        // Duration should be 0 when timestamps required fallback
        assert_eq!(rows[0].span_duration, 0);
        // Timestamps should be non-zero (current time)
        assert!(rows[0].chq_timestamp > 0);
    }
}
