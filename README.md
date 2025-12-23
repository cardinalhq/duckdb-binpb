# DuckDB OpenTelemetry Metrics Extension

A DuckDB extension for reading OpenTelemetry binary protobuf (binpb) metric files directly into queryable tables with CardinalHQ schema.

## Features

- Read OpenTelemetry `ExportMetricsServiceRequest` from `.binpb` files
- Automatic gzip decompression for `.binpb.gz` files
- Glob pattern support for reading multiple files with schema unioning
- Supports all OTEL metric types: Gauge, Sum, Histogram, ExponentialHistogram, Summary
- DDSketch integration for histogram quantile computation
- TID (Telemetry ID) calculation for time series identification
- Flattens metrics into rows with normalized column names

## Installation

```sql
LOAD 'otel_metrics.duckdb_extension';
```

## Usage

```sql
-- Read metrics from a single file
SELECT * FROM otel_metrics_read('path/to/metrics.binpb', customer_id='my-customer');

-- Read from gzipped file
SELECT * FROM otel_metrics_read('path/to/metrics.binpb.gz', customer_id='my-customer');

-- Read multiple files with glob pattern (schema unioning)
SELECT * FROM otel_metrics_read('testdata/metrics_*.binpb.gz', customer_id='my-customer');

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

## Parameters

| Parameter | Type | Required | Description |
| ----------- | ------ | ---------- | ------------- |
| File path | VARCHAR | Yes | File path or glob pattern (e.g., `*.binpb.gz`) |
| `customer_id` | VARCHAR | Yes | Customer identifier for `chq_customer_id` field |

## Output Columns

### CHQ System Fields

| Column | Type | Description |
| -------- | ------ | ------------- |
| `chq_customer_id` | VARCHAR | Customer identifier (from parameter) |
| `chq_telemetry_type` | VARCHAR | Always "metrics" |
| `chq_tid` | BIGINT | Telemetry ID (FNV-1a hash for time series identification) |
| `chq_timestamp` | BIGINT | Timestamp in milliseconds, truncated to 10s intervals |
| `chq_tsns` | BIGINT | Original timestamp in nanoseconds |

### Metric Metadata

| Column | Type | Description |
| -------- | ------ | ------------- |
| `metric_name` | VARCHAR | Normalized metric name (lowercase, underscores) |
| `chq_description` | VARCHAR | Metric description |
| `chq_unit` | VARCHAR | Metric unit (e.g., `%`, `bytes`) |
| `chq_metric_type` | VARCHAR | Type: `gauge`, `count`, or `histogram` |
| `chq_scope_name` | VARCHAR | Instrumentation scope name |
| `chq_scope_url` | VARCHAR | Instrumentation scope version |

### Sketch and Rollup Fields

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

### Dynamic Attribute Columns

Attributes are flattened into columns with normalized names:

- **Resource attributes**: `resource_<normalized_name>`
  - Filtered to allowed keys: `service_name`, `service_version`, `k8s_*`, `container_image_*`, `app`
  - Example: `service.name` → `resource_service_name`
- **Datapoint attributes**: `attr_<normalized_name>`
  - Underscore-prefixed keys are excluded (e.g., `_internal`)
  - Empty values are excluded
  - Example: `http.method` → `attr_http_method`

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
