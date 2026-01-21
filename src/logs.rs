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

//! OpenTelemetry logs processing for DuckDB.

use duckdb::{
    core::{DataChunkHandle, Inserter, LogicalTypeHandle, LogicalTypeId},
    vtab::{BindInfo, InitInfo, TableFunctionInfo, VTab},
    Connection, Result,
};
use prost::Message;
use std::{
    collections::HashMap,
    error::Error,
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::common::{any_value_to_string, read_binpb_file};
use crate::log_fingerprint::cluster::TENANT_MANAGER;
use crate::log_fingerprint::Fingerprinter;
use crate::normalize::normalize_attribute_name;
use crate::opentelemetry::proto::{
    collector::logs::v1::ExportLogsServiceRequest,
    common::v1::KeyValue,
};

// ============================================================================
// ID Generation
// ============================================================================

/// Generate a unique ULID for record identification.
fn generate_ulid() -> String {
    ulid::Ulid::new().to_string().to_lowercase()
}

// ============================================================================
// Flattened log row representation
// ============================================================================

/// A single flattened log record row with CHQ schema
#[derive(Debug, Clone)]
pub struct LogRow {
    // CHQ system fields
    pub chq_id: String,             // Unique record ID (ULID)
    pub chq_customer_id: String,
    pub chq_telemetry_type: String, // Always "logs"
    pub chq_timestamp: i64,         // Milliseconds
    pub chq_tsns: i64,              // Original nanoseconds
    pub chq_fingerprint: i64,       // Log fingerprint for grouping

    // Log-specific fields
    pub log_level: Option<String>,   // Severity text (uppercase)
    pub log_message: Option<String>, // Body as string
    pub metric_name: String,         // Always "log_events"

    // Scope
    pub scope_name: String,
    pub scope_version: String,

    // Trace correlation (optional)
    pub trace_id: Option<String>,
    pub span_id: Option<String>,

    // Dynamic attributes
    pub resource_attrs: Arc<Vec<(String, String)>>,
    pub scope_attrs: Vec<(String, String)>,
    pub log_attrs: Vec<(String, String)>,

    // Per-file metadata (injected from file_metadata parameter)
    pub file_metadata: Vec<(String, String)>,
}

// ============================================================================
// Parsing helpers
// ============================================================================

/// Extract attributes as (normalized_key, value_string) pairs with prefix
/// Filters out underscore-prefixed keys and empty values
fn extract_attrs_with_prefix(attrs: &[KeyValue], prefix: &str) -> Vec<(String, String)> {
    attrs
        .iter()
        .filter_map(|kv| {
            // Skip underscore-prefixed keys (internal/private attributes)
            if kv.key.starts_with('_') {
                return None;
            }
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
fn bytes_to_hex(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
        None
    } else {
        Some(hex::encode(bytes))
    }
}

/// Get timestamp in milliseconds, with fallback logic
fn get_timestamp_ms(time_unix_nano: u64, observed_time_unix_nano: u64) -> i64 {
    let ns = if time_unix_nano > 0 {
        time_unix_nano
    } else if observed_time_unix_nano > 0 {
        observed_time_unix_nano
    } else {
        // Fallback to current time
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    };
    (ns / 1_000_000) as i64
}

/// Get timestamp in nanoseconds
fn get_timestamp_ns(time_unix_nano: u64, observed_time_unix_nano: u64) -> i64 {
    let ns = if time_unix_nano > 0 {
        time_unix_nano
    } else if observed_time_unix_nano > 0 {
        observed_time_unix_nano
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    };
    ns as i64
}

// ============================================================================
// Main parsing function
// ============================================================================

/// Parse logs from binary protobuf data
pub fn parse_logs(
    data: &[u8],
    customer_id: &str,
    file_metadata: &[(String, String)],
) -> Result<Vec<LogRow>, Box<dyn Error>> {
    let request = ExportLogsServiceRequest::decode(data)?;
    let mut rows = Vec::new();

    // Get the tenant's cluster manager for fingerprinting
    let cluster_manager = TENANT_MANAGER.get_or_create(customer_id);
    let fingerprinter = Fingerprinter::new();

    for rl in &request.resource_logs {
        // Get resource attributes (wrapped in Arc for sharing)
        let resource_attrs = Arc::new(
            rl.resource
                .as_ref()
                .map(|r| extract_attrs_with_prefix(&r.attributes, "resource"))
                .unwrap_or_default(),
        );

        for sl in &rl.scope_logs {
            let (scope_name, scope_version, scope_attrs) = sl
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

            for log in &sl.log_records {
                // Extract body as string
                let log_message = log.body.as_ref().map(|b| any_value_to_string(&Some(b.clone())));
                let log_message = if log_message.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                    None
                } else {
                    log_message
                };

                // Extract severity text
                let log_level = if log.severity_text.is_empty() {
                    None
                } else {
                    Some(log.severity_text.clone())
                };

                // Generate fingerprint from log message.
                // A fingerprint of 0 indicates either no message or tokenization failure.
                // We don't log errors here since this is a library - callers can check for 0.
                let chq_fingerprint = if let Some(ref msg) = log_message {
                    match fingerprinter.tokenize_input(msg) {
                        Ok((tokens, _level, json_keys)) => {
                            let json_keys = json_keys.unwrap_or_default();
                            cluster_manager.cluster(&tokens, &json_keys)
                        }
                        Err(_) => 0,
                    }
                } else {
                    0
                };

                // Extract log attributes
                let log_attrs = extract_attrs_with_prefix(&log.attributes, "attr");

                rows.push(LogRow {
                    chq_id: generate_ulid(),
                    chq_customer_id: customer_id.to_string(),
                    chq_telemetry_type: "logs".to_string(),
                    chq_timestamp: get_timestamp_ms(log.time_unix_nano, log.observed_time_unix_nano),
                    chq_tsns: get_timestamp_ns(log.time_unix_nano, log.observed_time_unix_nano),
                    chq_fingerprint,
                    log_level,
                    log_message,
                    metric_name: "log_events".to_string(),
                    scope_name: scope_name.clone(),
                    scope_version: scope_version.clone(),
                    trace_id: bytes_to_hex(&log.trace_id),
                    span_id: bytes_to_hex(&log.span_id),
                    resource_attrs: Arc::clone(&resource_attrs),
                    scope_attrs: scope_attrs.clone(),
                    log_attrs,
                    file_metadata: file_metadata.to_vec(),
                });
            }
        }
    }

    Ok(rows)
}

// ============================================================================
// File metadata parsing
// ============================================================================

/// Represents a file input with optional metadata
#[derive(Debug, Clone)]
pub struct FileInput {
    pub path: String,
    pub metadata: Vec<(String, String)>,
}

/// Parse file input which can be:
/// - A single path: 'file.binpb'
/// - A glob pattern: '*.binpb'
/// - A list with optional metadata: [{'path': 'file.binpb', 'bucket': 'my-bucket'}, ...]
/// - A simple list: ['file1.binpb', 'file2.binpb']
fn parse_file_input(input: &str, file_metadata_json: Option<&str>) -> Result<Vec<FileInput>, Box<dyn Error>> {
    let input = input.trim();

    // Parse file_metadata JSON if provided (maps file paths to metadata)
    let metadata_map: HashMap<String, HashMap<String, String>> = if let Some(json) = file_metadata_json {
        serde_json::from_str(json).unwrap_or_default()
    } else {
        HashMap::new()
    };

    // Check for JSON array syntax: [...]
    if input.starts_with('[') && input.ends_with(']') {
        // Try to parse as JSON array
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(input) {
            if let Some(arr) = parsed.as_array() {
                let mut inputs = Vec::new();
                for item in arr {
                    if let Some(path) = item.as_str() {
                        // Simple string path
                        let metadata = get_metadata_for_path(path, &metadata_map);
                        for expanded in expand_single_path(path)? {
                            inputs.push(FileInput {
                                path: expanded,
                                metadata: metadata.clone(),
                            });
                        }
                    } else if let Some(obj) = item.as_object() {
                        // Object with path and metadata
                        if let Some(path) = obj.get("path").and_then(|v| v.as_str()) {
                            let mut metadata: Vec<(String, String)> = obj
                                .iter()
                                .filter(|(k, _)| *k != "path")
                                .filter_map(|(k, v)| {
                                    v.as_str().map(|s| (k.clone(), s.to_string()))
                                })
                                .collect();
                            // Also add from file_metadata_json if present
                            metadata.extend(get_metadata_for_path(path, &metadata_map));
                            for expanded in expand_single_path(path)? {
                                inputs.push(FileInput {
                                    path: expanded,
                                    metadata: metadata.clone(),
                                });
                            }
                        }
                    }
                }
                if inputs.is_empty() {
                    return Err("Empty file list".into());
                }
                return Ok(inputs);
            }
        }

        // Fallback: parse as simple list ['file1', 'file2']
        let inner = &input[1..input.len() - 1];
        let mut inputs = Vec::new();
        for part in inner.split(',') {
            let path = part.trim().trim_matches(|c| c == '\'' || c == '"');
            if !path.is_empty() {
                let metadata = get_metadata_for_path(path, &metadata_map);
                for expanded in expand_single_path(path)? {
                    inputs.push(FileInput {
                        path: expanded,
                        metadata: metadata.clone(),
                    });
                }
            }
        }
        if inputs.is_empty() {
            return Err("Empty file list".into());
        }
        return Ok(inputs);
    }

    // Single path or glob
    let metadata = get_metadata_for_path(input, &metadata_map);
    let mut inputs = Vec::new();
    for expanded in expand_single_path(input)? {
        inputs.push(FileInput {
            path: expanded,
            metadata: metadata.clone(),
        });
    }
    Ok(inputs)
}

fn get_metadata_for_path(path: &str, metadata_map: &HashMap<String, HashMap<String, String>>) -> Vec<(String, String)> {
    metadata_map
        .get(path)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
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
pub struct LogsBindData {
    rows: Vec<LogRow>,
    resource_attr_names: Vec<String>,
    scope_attr_names: Vec<String>,
    log_attr_names: Vec<String>,
    file_metadata_names: Vec<String>,
}

#[repr(C)]
pub struct LogsInitData {
    current_row: AtomicUsize,
}

pub struct ReadLogsVTab;

impl VTab for ReadLogsVTab {
    type InitData = LogsInitData;
    type BindData = LogsBindData;

    fn bind(bind: &BindInfo) -> Result<Self::BindData, Box<dyn Error>> {
        let param_count = bind.get_parameter_count();
        if param_count < 1 {
            return Err(
                "Usage: otel_logs_read('file.binpb', customer_id='xxx') or otel_logs_read([{path: 'file.binpb', resource_bucket_name: 'bucket'}], customer_id='xxx')"
                    .into(),
            );
        }

        // Get customer_id from named parameter (required)
        let customer_id = bind
            .get_named_parameter("customer_id")
            .ok_or("Missing required named parameter: customer_id")?
            .to_string();

        // Get optional file_metadata JSON parameter
        let file_metadata_json = bind
            .get_named_parameter("file_metadata")
            .map(|v| v.to_string());

        // Get file path(s) from first positional parameter
        let file_input = bind.get_parameter(0).to_string();
        let file_inputs = parse_file_input(&file_input, file_metadata_json.as_deref())?;

        // Parse all files and collect rows
        let mut all_rows = Vec::new();
        for fi in &file_inputs {
            let data = read_binpb_file(&fi.path)?;
            let rows = parse_logs(&data, &customer_id, &fi.metadata)?;
            all_rows.extend(rows);
        }

        // Compute superset of attribute columns from all rows
        let (resource_attr_names, scope_attr_names, log_attr_names, file_metadata_names) =
            collect_attr_names(&all_rows);

        // Fixed columns - CHQ schema for logs
        bind.add_result_column("chq_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_customer_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_telemetry_type", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("chq_timestamp", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("chq_tsns", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("chq_fingerprint", LogicalTypeHandle::from(LogicalTypeId::Bigint));
        bind.add_result_column("log_level", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("log_message", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("metric_name", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("scope_name", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("scope_version", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("trace_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));
        bind.add_result_column("span_id", LogicalTypeHandle::from(LogicalTypeId::Varchar));

        // Dynamic columns
        for name in &resource_attr_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }
        for name in &scope_attr_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }
        for name in &log_attr_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }
        for name in &file_metadata_names {
            bind.add_result_column(name, LogicalTypeHandle::from(LogicalTypeId::Varchar));
        }

        Ok(LogsBindData {
            rows: all_rows,
            resource_attr_names,
            scope_attr_names,
            log_attr_names,
            file_metadata_names,
        })
    }

    fn init(_: &InitInfo) -> Result<Self::InitData, Box<dyn Error>> {
        Ok(LogsInitData {
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
            output.flat_vector(col).insert(i, row.chq_id.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_customer_id.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.chq_telemetry_type.as_bytes());
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.chq_timestamp;
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.chq_tsns;
            col += 1;

            output.flat_vector(col).as_mut_slice::<i64>()[i] = row.chq_fingerprint;
            col += 1;

            // log_level (nullable)
            match &row.log_level {
                Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                None => output.flat_vector(col).set_null(i),
            }
            col += 1;

            // log_message (nullable)
            match &row.log_message {
                Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                None => output.flat_vector(col).set_null(i),
            }
            col += 1;

            output.flat_vector(col).insert(i, row.metric_name.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.scope_name.as_bytes());
            col += 1;

            output.flat_vector(col).insert(i, row.scope_version.as_bytes());
            col += 1;

            // trace_id (nullable)
            match &row.trace_id {
                Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                None => output.flat_vector(col).set_null(i),
            }
            col += 1;

            // span_id (nullable)
            match &row.span_id {
                Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                None => output.flat_vector(col).set_null(i),
            }
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

            // Dynamic log attributes
            for name in &bind_data.log_attr_names {
                let value = row.log_attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v);
                match value {
                    Some(v) => output.flat_vector(col).insert(i, v.as_bytes()),
                    None => output.flat_vector(col).set_null(i),
                }
                col += 1;
            }

            // File metadata
            for name in &bind_data.file_metadata_names {
                let value = row.file_metadata.iter().find(|(k, _)| k == name).map(|(_, v)| v);
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
        Some(vec![
            (
                "customer_id".to_string(),
                LogicalTypeHandle::from(LogicalTypeId::Varchar),
            ),
            (
                "file_metadata".to_string(),
                LogicalTypeHandle::from(LogicalTypeId::Varchar),
            ),
        ])
    }
}

/// Collect all unique attribute names from rows
fn collect_attr_names(rows: &[LogRow]) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    use std::collections::HashSet;

    let mut resource_set: HashSet<String> = HashSet::new();
    let mut scope_set: HashSet<String> = HashSet::new();
    let mut log_set: HashSet<String> = HashSet::new();
    let mut file_metadata_set: HashSet<String> = HashSet::new();

    for row in rows {
        for (key, _) in row.resource_attrs.iter() {
            resource_set.insert(key.clone());
        }
        for (key, _) in &row.scope_attrs {
            scope_set.insert(key.clone());
        }
        for (key, _) in &row.log_attrs {
            log_set.insert(key.clone());
        }
        for (key, _) in &row.file_metadata {
            file_metadata_set.insert(key.clone());
        }
    }

    let mut resource_names: Vec<String> = resource_set.into_iter().collect();
    let mut scope_names: Vec<String> = scope_set.into_iter().collect();
    let mut log_names: Vec<String> = log_set.into_iter().collect();
    let mut file_metadata_names: Vec<String> = file_metadata_set.into_iter().collect();

    resource_names.sort();
    scope_names.sort();
    log_names.sort();
    file_metadata_names.sort();

    (resource_names, scope_names, log_names, file_metadata_names)
}

/// Register logs table functions with DuckDB
pub fn register(con: &Connection) -> Result<(), Box<dyn Error>> {
    con.register_table_function::<ReadLogsVTab>("otel_logs_read")
        .map_err(|e| format!("Failed to register otel_logs_read: {}", e))?;
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
        logs::v1::{LogRecord, ResourceLogs, ScopeLogs},
        resource::v1::Resource,
    };
    use prost::Message;

    fn create_sample_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
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
                            key: "host.name".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("test-host".to_string())),
                            }),
                        },
                    ],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: "test-logger".to_string(),
                        version: "1.0.0".to_string(),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                    }),
                    log_records: vec![
                        LogRecord {
                            time_unix_nano: 1700000000_000_000_000,
                            observed_time_unix_nano: 1700000000_000_000_000,
                            severity_number: 9, // INFO
                            severity_text: "INFO".to_string(),
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "Test log message".to_string(),
                                )),
                            }),
                            attributes: vec![KeyValue {
                                key: "request.id".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue("abc123".to_string())),
                                }),
                            }],
                            dropped_attributes_count: 0,
                            flags: 0,
                            trace_id: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                            span_id: vec![1, 2, 3, 4, 5, 6, 7, 8],
                            event_name: String::new(),
                        },
                        LogRecord {
                            time_unix_nano: 1700000001_000_000_000,
                            observed_time_unix_nano: 1700000001_000_000_000,
                            severity_number: 17, // ERROR
                            severity_text: "ERROR".to_string(),
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "Something went wrong".to_string(),
                                )),
                            }),
                            attributes: vec![KeyValue {
                                key: "error.type".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue(
                                        "RuntimeError".to_string(),
                                    )),
                                }),
                            }],
                            dropped_attributes_count: 0,
                            flags: 0,
                            trace_id: vec![],
                            span_id: vec![],
                            event_name: String::new(),
                        },
                    ],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        }
    }

    #[test]
    fn test_parse_logs() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_logs(&encoded, "test-customer", &[]).expect("Failed to parse logs");

        assert_eq!(rows.len(), 2, "Should have 2 log records");

        let row1 = &rows[0];
        assert_eq!(row1.chq_customer_id, "test-customer");
        assert_eq!(row1.chq_telemetry_type, "logs");
        assert_eq!(row1.log_level, Some("INFO".to_string()));
        assert_eq!(row1.log_message, Some("Test log message".to_string()));
        assert_eq!(row1.metric_name, "log_events");
        assert!(row1.trace_id.is_some());
        assert!(row1.span_id.is_some());

        let row2 = &rows[1];
        assert_eq!(row2.log_level, Some("ERROR".to_string()));
        assert_eq!(row2.log_message, Some("Something went wrong".to_string()));
        assert!(row2.trace_id.is_none()); // Empty trace_id
        assert!(row2.span_id.is_none()); // Empty span_id
    }

    #[test]
    fn test_parse_logs_with_file_metadata() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let file_metadata = vec![
            ("resource_bucket_name".to_string(), "my-bucket".to_string()),
            ("resource_file_name".to_string(), "./logs/app.binpb".to_string()),
        ];

        let rows = parse_logs(&encoded, "test-customer", &file_metadata).expect("Failed to parse logs");

        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_eq!(row.file_metadata.len(), 2);
            assert!(row.file_metadata.iter().any(|(k, v)| k == "resource_bucket_name" && v == "my-bucket"));
            assert!(row.file_metadata.iter().any(|(k, v)| k == "resource_file_name" && v == "./logs/app.binpb"));
        }
    }

    #[test]
    fn test_timestamp_fallback() {
        // Test with zero timestamp - should use observed_time
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano: 0, // Zero
                        observed_time_unix_nano: 1700000000_000_000_000,
                        severity_number: 0,
                        severity_text: "".to_string(),
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("Test".to_string())),
                        }),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                        flags: 0,
                        trace_id: vec![],
                        span_id: vec![],
                        event_name: String::new(),
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_logs(&encoded, "test", &[]).expect("Failed to parse");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].chq_timestamp, 1700000000_000); // Observed time in ms
    }

    #[test]
    fn test_file_input_parsing() {
        // Test simple path
        let inputs = parse_file_input("test.binpb", None).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, "test.binpb");

        // Test list syntax
        let inputs = parse_file_input("['file1.binpb', 'file2.binpb']", None).unwrap();
        assert_eq!(inputs.len(), 2);

        // Test JSON with metadata
        let json_input = r#"[{"path": "file1.binpb", "resource_bucket_name": "bucket1"}]"#;
        let inputs = parse_file_input(json_input, None).unwrap();
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].path, "file1.binpb");
        assert!(inputs[0].metadata.iter().any(|(k, _)| k == "resource_bucket_name"));
    }

    #[test]
    fn test_parse_logs_with_fingerprint() {
        let request = create_sample_request();
        let encoded = request.encode_to_vec();

        let rows = parse_logs(&encoded, "test-customer", &[]).expect("Failed to parse logs");

        assert_eq!(rows.len(), 2);

        // Verify fingerprints are generated (non-zero for non-empty messages)
        assert_ne!(rows[0].chq_fingerprint, 0, "Fingerprint should be generated for non-empty message");
        assert_ne!(rows[1].chq_fingerprint, 0, "Fingerprint should be generated for non-empty message");

        // Verify chq_id is generated (ULID format - 26 chars lowercase)
        assert_eq!(rows[0].chq_id.len(), 26, "chq_id should be 26 characters (ULID)");
        assert_eq!(rows[1].chq_id.len(), 26, "chq_id should be 26 characters (ULID)");
        assert_ne!(rows[0].chq_id, rows[1].chq_id, "Each row should have unique chq_id");
    }

    #[test]
    fn test_similar_logs_get_same_fingerprint() {
        // Two similar log messages should get the same fingerprint (Jaccard clustering)
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![
                        LogRecord {
                            time_unix_nano: 1700000000_000_000_000,
                            observed_time_unix_nano: 1700000000_000_000_000,
                            severity_number: 9,
                            severity_text: "INFO".to_string(),
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "User logged in from 192.168.1.100".to_string(),
                                )),
                            }),
                            attributes: vec![],
                            dropped_attributes_count: 0,
                            flags: 0,
                            trace_id: vec![],
                            span_id: vec![],
                            event_name: String::new(),
                        },
                        LogRecord {
                            time_unix_nano: 1700000001_000_000_000,
                            observed_time_unix_nano: 1700000001_000_000_000,
                            severity_number: 9,
                            severity_text: "INFO".to_string(),
                            body: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "User logged in from 10.0.0.50".to_string(),
                                )),
                            }),
                            attributes: vec![],
                            dropped_attributes_count: 0,
                            flags: 0,
                            trace_id: vec![],
                            span_id: vec![],
                            event_name: String::new(),
                        },
                    ],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_logs(&encoded, "test-customer", &[]).expect("Failed to parse");

        assert_eq!(rows.len(), 2);
        // Similar messages with only IP address difference should cluster together
        assert_eq!(
            rows[0].chq_fingerprint, rows[1].chq_fingerprint,
            "Similar log messages should have the same fingerprint"
        );
    }

    #[test]
    fn test_tenant_isolation() {
        // Different tenants should have separate cluster managers
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: None,
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![LogRecord {
                        time_unix_nano: 1700000000_000_000_000,
                        observed_time_unix_nano: 1700000000_000_000_000,
                        severity_number: 9,
                        severity_text: "INFO".to_string(),
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue(
                                "Test log message".to_string(),
                            )),
                        }),
                        attributes: vec![],
                        dropped_attributes_count: 0,
                        flags: 0,
                        trace_id: vec![],
                        span_id: vec![],
                        event_name: String::new(),
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();

        // Parse for two different tenants
        let rows_tenant1 = parse_logs(&encoded, "tenant-1", &[]).expect("Failed to parse");
        let rows_tenant2 = parse_logs(&encoded, "tenant-2", &[]).expect("Failed to parse");

        // Both should generate valid fingerprints
        assert_ne!(rows_tenant1[0].chq_fingerprint, 0);
        assert_ne!(rows_tenant2[0].chq_fingerprint, 0);

        // Verify TenantManager has both tenants
        use crate::log_fingerprint::cluster::TENANT_MANAGER;
        let tenant_ids = TENANT_MANAGER.tenant_ids();
        assert!(tenant_ids.contains(&"tenant-1".to_string()));
        assert!(tenant_ids.contains(&"tenant-2".to_string()));
    }

    #[test]
    fn test_underscore_prefixed_attributes_filtered() {
        // Attributes starting with underscore should be filtered out
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![
                        KeyValue {
                            key: "service.name".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("test".to_string())),
                            }),
                        },
                        KeyValue {
                            key: "_cardinalhq.internal".to_string(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("should-be-filtered".to_string())),
                            }),
                        },
                    ],
                    dropped_attributes_count: 0,
                    entity_refs: vec![],
                }),
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        name: "test".to_string(),
                        version: "1.0".to_string(),
                        attributes: vec![
                            KeyValue {
                                key: "_internal.scope".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue("filtered".to_string())),
                                }),
                            },
                        ],
                        dropped_attributes_count: 0,
                    }),
                    log_records: vec![LogRecord {
                        time_unix_nano: 1700000000_000_000_000,
                        observed_time_unix_nano: 1700000000_000_000_000,
                        severity_number: 9,
                        severity_text: "INFO".to_string(),
                        body: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("Test".to_string())),
                        }),
                        attributes: vec![
                            KeyValue {
                                key: "normal.attr".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue("kept".to_string())),
                                }),
                            },
                            KeyValue {
                                key: "_hidden.attr".to_string(),
                                value: Some(AnyValue {
                                    value: Some(any_value::Value::StringValue("filtered".to_string())),
                                }),
                            },
                        ],
                        dropped_attributes_count: 0,
                        flags: 0,
                        trace_id: vec![],
                        span_id: vec![],
                        event_name: String::new(),
                    }],
                    schema_url: "".to_string(),
                }],
                schema_url: "".to_string(),
            }],
        };

        let encoded = request.encode_to_vec();
        let rows = parse_logs(&encoded, "test", &[]).expect("Failed to parse");

        assert_eq!(rows.len(), 1);
        let row = &rows[0];

        // Check resource attributes - _cardinalhq.internal should be filtered
        let resource_keys: Vec<_> = row.resource_attrs.iter().map(|(k, _)| k.as_str()).collect();
        assert!(resource_keys.contains(&"resource_service_name"));
        assert!(!resource_keys.iter().any(|k| k.contains("cardinalhq")));

        // Check scope attributes - _internal.scope should be filtered
        let scope_keys: Vec<_> = row.scope_attrs.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!scope_keys.iter().any(|k| k.contains("internal")));

        // Check log attributes - _hidden.attr should be filtered
        let log_keys: Vec<_> = row.log_attrs.iter().map(|(k, _)| k.as_str()).collect();
        assert!(log_keys.contains(&"attr_normal_attr"));
        assert!(!log_keys.iter().any(|k| k.contains("hidden")));
    }
}
