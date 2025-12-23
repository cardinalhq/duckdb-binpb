#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "=== Running OTel Metrics Extension Integration Tests ==="

# First generate test data using Rust
echo "Generating test data..."
cargo run --example generate_test_data 2>/dev/null || true

# Run DuckDB tests
echo "Running DuckDB integration tests..."
duckdb -unsigned < "$SCRIPT_DIR/integration_test.sql"

echo "=== All tests passed! ==="
