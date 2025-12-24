# DuckDB OpenTelemetry Extension

A DuckDB extension for reading OpenTelemetry binary protobuf (binpb) files directly into queryable tables with CardinalHQ schema. Supports metrics, logs, and traces.

## Features

- **Metrics**: Read `ExportMetricsServiceRequest` with all metric types (Gauge, Sum, Histogram, ExponentialHistogram, Summary)
- **Logs**: Read `ExportLogsServiceRequest` with severity levels and trace correlation
- **Traces**: Read `ExportTraceServiceRequest` with span hierarchy and duration calculation
- Automatic gzip decompression for `.binpb.gz` files
- Multiple file support: glob patterns or explicit list `[file1, file2]` with schema unioning
- Per-file metadata injection for logs (bucket name, file source tracking)
- DDSketch integration for histogram quantile computation
- TID (Telemetry ID) calculation for time series identification
- Flattens telemetry into rows with normalized column names

## Installation

```sql
LOAD 'otel_binpb.duckdb_extension';
```

## Usage

```sql
-- Read metrics from a single file
SELECT * FROM otel_metrics_read('path/to/metrics.binpb', customer_id='my-customer');

-- Read from gzipped file
SELECT * FROM otel_metrics_read('path/to/metrics.binpb.gz', customer_id='my-customer');

-- Read multiple files with glob pattern (schema unioning)
SELECT * FROM otel_metrics_read('testdata/metrics_*.binpb.gz', customer_id='my-customer');

-- Read specific files using list syntax
SELECT * FROM otel_metrics_read('[file1.binpb.gz, file2.binpb.gz]', customer_id='my-customer');

-- Query specific metrics
SELECT
    metric_name,
    chq_metric_type,
    chq_rollup_sum,
    chq_rollup_count
FROM otel_metrics_read('metrics.binpb.gz', customer_id='test')
WHERE chq_metric_type = 'gauge';

-- Export to parquet sorted by time series
COPY (
    SELECT * FROM otel_metrics_read('testdata/*.binpb.gz', customer_id='prod')
    ORDER BY metric_name, chq_tid, chq_timestamp
) TO 'output.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);

-- Aggregate metrics by time series
SELECT
    metric_name,
    chq_tid,
    count(*) as point_count,
    sum(chq_rollup_sum) as total_sum
FROM otel_metrics_read('metrics.binpb.gz', customer_id='test')
GROUP BY metric_name, chq_tid;
```

### Reading Logs

```sql
-- Read logs from files
SELECT * FROM otel_logs_read('path/to/logs.binpb.gz', customer_id='my-customer');

-- Read multiple files with glob pattern (schema unioning)
SELECT * FROM otel_logs_read('logs/*.binpb.gz', customer_id='my-customer');

-- Read specific files using list syntax
SELECT * FROM otel_logs_read('["file1.binpb.gz", "file2.binpb.gz"]', customer_id='my-customer');

-- Query logs by severity
SELECT
    log_level,
    count(*) as count
FROM otel_logs_read('logs/*.binpb.gz', customer_id='test')
GROUP BY log_level
ORDER BY count DESC;

-- Logs with trace correlation
SELECT
    log_message,
    log_level,
    trace_id,
    span_id
FROM otel_logs_read('logs.binpb.gz', customer_id='test')
WHERE trace_id IS NOT NULL;

-- Per-file metadata injection (for tracking file sources)
SELECT * FROM otel_logs_read(
    '[{"path": "bucket1/logs.binpb.gz", "resource_bucket_name": "bucket1"},
      {"path": "bucket2/logs.binpb.gz", "resource_bucket_name": "bucket2"}]',
    customer_id='test'
);

-- Alternative: Use file_metadata parameter for glob patterns
SELECT * FROM otel_logs_read(
    'logs/*.binpb.gz',
    customer_id='test',
    file_metadata='{"logs/app.binpb.gz": {"resource_bucket_name": "prod"}}'
);
```

### Reading Traces

```sql
-- Read traces from files
SELECT * FROM otel_traces_read('path/to/traces.binpb.gz', customer_id='my-customer');

-- Read multiple files with glob pattern (schema unioning)
SELECT * FROM otel_traces_read('traces/*.binpb.gz', customer_id='my-customer');

-- Read specific files using list syntax
SELECT * FROM otel_traces_read('["file1.binpb.gz", "file2.binpb.gz"]', customer_id='my-customer');

-- Query spans by kind
SELECT
    span_kind,
    count(*) as count,
    avg(span_duration) as avg_duration_ms
FROM otel_traces_read('traces/*.binpb.gz', customer_id='test')
GROUP BY span_kind;

-- Find slow spans
SELECT
    span_name,
    span_duration,
    span_trace_id,
    span_id
FROM otel_traces_read('traces.binpb.gz', customer_id='test')
WHERE span_duration > 1000
ORDER BY span_duration DESC;

-- Trace hierarchy analysis
SELECT
    CASE WHEN span_parent_span_id = '' THEN 'root' ELSE 'child' END as span_type,
    count(*) as count
FROM otel_traces_read('traces.binpb.gz', customer_id='test')
GROUP BY span_type;

-- Export traces to parquet
COPY (
    SELECT * FROM otel_traces_read('traces/*.binpb.gz', customer_id='prod')
    ORDER BY span_trace_id, chq_timestamp
) TO 'traces.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
```

## Parameters

### otel_metrics_read

| Parameter | Type | Required | Description |
| ----------- | ------ | ---------- | ------------- |
| File path | VARCHAR | Yes | File path, glob pattern (`*.binpb.gz`), or list (`[file1, file2]`) |
| `customer_id` | VARCHAR | Yes | Customer identifier for `chq_customer_id` field |

### otel_logs_read

| Parameter | Type | Required | Description |
| ----------- | ------ | ---------- | ------------- |
| File path | VARCHAR | Yes | File path, glob pattern, list, or JSON array with metadata |
| `customer_id` | VARCHAR | Yes | Customer identifier for `chq_customer_id` field |
| `file_metadata` | VARCHAR | No | JSON object mapping file paths to metadata fields |

### otel_traces_read

| Parameter | Type | Required | Description |
| ----------- | ------ | ---------- | ------------- |
| File path | VARCHAR | Yes | File path, glob pattern (`*.binpb.gz`), or list (`[file1, file2]`) |
| `customer_id` | VARCHAR | Yes | Customer identifier for `chq_customer_id` field |

## Output Columns

### Metrics Output (otel_metrics_read)

#### CHQ System Fields

| Column | Type | Description |
| -------- | ------ | ------------- |
| `chq_customer_id` | VARCHAR | Customer identifier (from parameter) |
| `chq_telemetry_type` | VARCHAR | Always "metrics" |
| `chq_tid` | BIGINT | Telemetry ID (FNV-1a hash for time series identification) |
| `chq_timestamp` | BIGINT | Timestamp in milliseconds, truncated to 10s intervals |
| `chq_tsns` | BIGINT | Original timestamp in nanoseconds |

#### Metric Metadata

| Column | Type | Description |
| -------- | ------ | ------------- |
| `metric_name` | VARCHAR | Normalized metric name (lowercase, underscores) |
| `chq_description` | VARCHAR | Metric description |
| `chq_unit` | VARCHAR | Metric unit (e.g., `%`, `bytes`) |
| `chq_metric_type` | VARCHAR | Type: `gauge`, `count`, or `histogram` |
| `chq_scope_name` | VARCHAR | Instrumentation scope name |
| `chq_scope_url` | VARCHAR | Instrumentation scope version |

#### Sketch and Rollup Fields

| Column | Type | Description |
| -------- | ------ | ------------- |
| `chq_sketch` | BLOB | DDSketch binary (DataDog wire format) |
| `chq_rollup_avg` | DOUBLE | Average value |
| `chq_rollup_count` | DOUBLE | Count of values |
| `chq_rollup_min` | DOUBLE | Minimum value |
| `chq_rollup_max` | DOUBLE | Maximum value |
| `chq_rollup_sum` | DOUBLE | Sum of values |
| `chq_rollup_p25` | DOUBLE | 25th percentile |
| `chq_rollup_p50` | DOUBLE | 50th percentile (median) |
| `chq_rollup_p75` | DOUBLE | 75th percentile |
| `chq_rollup_p90` | DOUBLE | 90th percentile |
| `chq_rollup_p95` | DOUBLE | 95th percentile |
| `chq_rollup_p99` | DOUBLE | 99th percentile |

#### Dynamic Attribute Columns

Attributes are flattened into columns with normalized names:

- **Resource attributes**: `resource_<normalized_name>`
  - Filtered to allowed keys: `service_name`, `service_version`, `k8s_*`, `container_image_*`, `app`
  - Example: `service.name` → `resource_service_name`
- **Datapoint attributes**: `attr_<normalized_name>`
  - Underscore-prefixed keys are excluded (e.g., `_internal`)
  - Empty values are excluded
  - Example: `http.method` → `attr_http_method`

### Logs Output (otel_logs_read)

| Column | Type | Description |
| -------- | ------ | ------------- |
| `chq_customer_id` | VARCHAR | Customer identifier (from parameter) |
| `chq_telemetry_type` | VARCHAR | Always "logs" |
| `chq_timestamp` | BIGINT | Timestamp in milliseconds |
| `chq_tsns` | BIGINT | Original timestamp in nanoseconds |
| `log_level` | VARCHAR | Severity text (e.g., INFO, ERROR) |
| `log_message` | VARCHAR | Log body as string |
| `metric_name` | VARCHAR | Always "log_events" |
| `scope_name` | VARCHAR | Instrumentation scope name |
| `scope_version` | VARCHAR | Instrumentation scope version |
| `trace_id` | VARCHAR | Trace ID (hex, if present) |
| `span_id` | VARCHAR | Span ID (hex, if present) |
| `resource_*` | VARCHAR | Resource attributes (dynamic) |
| `scope_*` | VARCHAR | Scope attributes (dynamic) |
| `attr_*` | VARCHAR | Log record attributes (dynamic) |
| File metadata | VARCHAR | Per-file injected metadata (dynamic) |

### Traces Output (otel_traces_read)

| Column | Type | Description |
| -------- | ------ | ------------- |
| `chq_customer_id` | VARCHAR | Customer identifier (from parameter) |
| `chq_telemetry_type` | VARCHAR | Always "traces" |
| `chq_timestamp` | BIGINT | Span start time in milliseconds |
| `chq_tsns` | BIGINT | Span start time in nanoseconds |
| `span_trace_id` | VARCHAR | Trace ID (hex) |
| `span_id` | VARCHAR | Span ID (hex) |
| `span_parent_span_id` | VARCHAR | Parent span ID (hex, empty for root spans) |
| `span_name` | VARCHAR | Span operation name |
| `span_kind` | VARCHAR | Span kind (SPAN_KIND_SERVER, SPAN_KIND_CLIENT, etc.) |
| `span_status_code` | VARCHAR | Status (STATUS_CODE_OK, STATUS_CODE_ERROR, etc.) |
| `span_status_message` | VARCHAR | Status message (if error) |
| `span_end_timestamp` | BIGINT | Span end time in milliseconds |
| `span_duration` | BIGINT | Span duration in milliseconds |
| `scope_name` | VARCHAR | Instrumentation scope name |
| `scope_version` | VARCHAR | Instrumentation scope version |
| `resource_*` | VARCHAR | Resource attributes (dynamic) |
| `scope_*` | VARCHAR | Scope attributes (dynamic) |
| `attr_*` | VARCHAR | Span attributes (dynamic) |

### Attribute Normalization

- Converted to lowercase
- Dots, hyphens, and slashes become underscores
- Special characters removed
- Consecutive underscores collapsed

## Metric Type Mapping

| OTEL Type | CHQ Type |
| ----------- | ---------- |
| Gauge | `gauge` |
| Sum | `count` |
| Histogram | `histogram` |
| ExponentialHistogram | `histogram` |
| Summary | `histogram` |

## TID Calculation

The `chq_tid` field is a 64-bit FNV-1a hash computed from:

- `metric_name`
- `chq_metric_type`
- `resource_*` attributes (filtered to allowed keys)
- `attr_*` attributes (excluding underscore-prefixed)

This provides a stable identifier for each unique time series.

## Building

### Prerequisites

- Rust 1.70+
- protobuf compiler (`protoc`)
- DuckDB 1.4.x

### Build Commands

```bash
# Build release version
make release

# Run tests
cargo test

# Test in DuckDB
duckdb -unsigned -c "LOAD 'build/release/otel_metrics.duckdb_extension';"
```

## License

GNU Affero General Public License v3.0 (AGPL-3.0)

Copyright 2025 CardinalHQ, Inc.
