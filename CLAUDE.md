# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build and package extension (recommended)
make release

# Extension output: build/release/otel_metrics.duckdb_extension

# Run tests
cargo test

# Test extension in DuckDB
duckdb -unsigned -c "LOAD 'build/release/otel_metrics.duckdb_extension';"
```

## Critical: DuckDB API Version

**DuckDB v1.4.x uses C API version v1.2.0, NOT v1.4.3.**

The Makefile `TARGET_DUCKDB_VERSION` must be set to `v1.2.0`. If you get errors like:
- "Built for DuckDB C API version 'vX.X.X', but we can only load extensions built for DuckDB C API 'v1.2.0'"

Check that `TARGET_DUCKDB_VERSION=v1.2.0` in the Makefile.

## Architecture

This is a Rust DuckDB extension for reading OpenTelemetry binary protobuf (binpb) metric files.

### Source Files

- **`src/lib.rs`** - DuckDB extension entry point, registers table function
- **`src/otel.rs`** - Generated protobuf code (via build.rs from proto/*.proto)
- **`src/normalize.rs`** - Attribute name normalization logic
- **`build.rs`** - Protobuf compilation script using prost

### Key Implementation Details

- Reads OpenTelemetry ExportMetricsServiceRequest from binpb files
- Supports gzip-compressed (.binpb.gz) files via flate2
- Flattens metrics into rows with normalized column names:
  - `resource_<attr>` - Resource attributes
  - `scope_<attr>` - Scope attributes
  - `metric_name`, `metric_type`, `metric_unit` - Metric metadata
  - `attr_<attr>` - Datapoint attributes
  - Value columns based on metric type (counter, gauge)
- Uses `prost` for protobuf parsing (compatible with OpenTelemetry proto v1.x)

### Column Naming Convention

Attribute names are normalized:
- Lowercase
- Dots and hyphens converted to underscores
- Special characters removed

Example: `service.name` becomes `resource_service_name`

### Supported Metric Types (Initial)

- **Gauge**: Instantaneous values (int64/double)
- **Sum** (Counter): Cumulative or delta counters (int64/double)

Future: Histogram, ExponentialHistogram, Summary
