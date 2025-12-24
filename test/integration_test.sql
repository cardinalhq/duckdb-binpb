-- OTel Binpb Extension Integration Tests
-- Run with: duckdb -unsigned < test/integration_test.sql

.bail on

-- Load the extension
LOAD 'build/release/otel_binpb.duckdb_extension';

-- Test 1: Read uncompressed binpb file
SELECT '=== Test 1: Read uncompressed binpb ===' as test;
SELECT count(*) as row_count FROM otel_metrics_read('test/data/test_metrics.binpb', customer_id='test');

-- Test 2: Read gzipped binpb file
SELECT '=== Test 2: Read gzipped binpb ===' as test;
SELECT count(*) as row_count FROM otel_metrics_read('test/data/test_metrics.binpb.gz', customer_id='test');

-- Test 3: Verify CHQ schema columns exist
SELECT '=== Test 3: Verify CHQ schema ===' as test;
SELECT
    chq_customer_id,
    chq_telemetry_type,
    chq_tid,
    chq_timestamp,
    chq_tsns,
    metric_name,
    chq_metric_type
FROM otel_metrics_read('test/data/test_metrics.binpb', customer_id='integration-test')
LIMIT 1;

-- Test 4: Verify rollup fields
SELECT '=== Test 4: Verify rollup fields ===' as test;
SELECT
    metric_name,
    chq_rollup_count,
    chq_rollup_sum,
    chq_rollup_min,
    chq_rollup_max,
    chq_rollup_avg
FROM otel_metrics_read('test/data/test_metrics.binpb', customer_id='test')
LIMIT 2;

-- Test 5: Verify sketch is populated
SELECT '=== Test 5: Verify sketch ===' as test;
SELECT
    metric_name,
    octet_length(chq_sketch) as sketch_bytes
FROM otel_metrics_read('test/data/test_metrics.binpb', customer_id='test')
LIMIT 2;

-- Test 6: Read glob pattern (testdata files)
SELECT '=== Test 6: Read glob pattern ===' as test;
SELECT count(*) as total_rows FROM otel_metrics_read('testdata/metrics_*.binpb.gz', customer_id='glob-test');

-- Test 7: Write to parquet with ZSTD compression
SELECT '=== Test 7: Write parquet with ZSTD ===' as test;
COPY (
    SELECT * FROM otel_metrics_read('testdata/metrics_*.binpb.gz', customer_id='parquet-test')
    ORDER BY metric_name, chq_tid, chq_timestamp
) TO '/tmp/integration_test_output.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);

-- Verify parquet was written correctly
SELECT count(*) as parquet_rows FROM '/tmp/integration_test_output.parquet';

-- Test 8: Aggregate by metric type
SELECT '=== Test 8: Aggregate by metric type ===' as test;
SELECT
    chq_metric_type,
    count(*) as count
FROM otel_metrics_read('testdata/metrics_*.binpb.gz', customer_id='test')
GROUP BY chq_metric_type
ORDER BY chq_metric_type;

-- Test 9: Verify TID is consistent for same time series
SELECT '=== Test 9: TID consistency ===' as test;
SELECT
    metric_name,
    chq_tid,
    count(*) as points
FROM otel_metrics_read('testdata/metrics_*.binpb.gz', customer_id='test')
GROUP BY metric_name, chq_tid
ORDER BY points DESC
LIMIT 5;

-- ============================================================================
-- LOGS TESTS
-- ============================================================================

-- Test 10: Read logs files
SELECT '=== Test 10: Read logs files ===' as test;
SELECT count(*) as logs_row_count FROM otel_logs_read('testdata/logs_*.binpb.gz', customer_id='test');

-- Test 11: Verify logs schema columns
SELECT '=== Test 11: Verify logs schema ===' as test;
SELECT
    chq_customer_id,
    chq_telemetry_type,
    chq_timestamp,
    chq_tsns,
    log_level,
    log_message,
    metric_name,
    scope_name
FROM otel_logs_read('testdata/logs_*.binpb.gz', customer_id='logs-test')
LIMIT 3;

-- Test 12: Aggregate logs by severity level
SELECT '=== Test 12: Logs by severity ===' as test;
SELECT
    log_level,
    count(*) as count
FROM otel_logs_read('testdata/logs_*.binpb.gz', customer_id='test')
GROUP BY log_level
ORDER BY count DESC;

-- Test 13: Logs with trace correlation
SELECT '=== Test 13: Logs with trace correlation ===' as test;
SELECT
    count(*) as total_logs,
    count(trace_id) as with_trace_id,
    count(span_id) as with_span_id
FROM otel_logs_read('testdata/logs_*.binpb.gz', customer_id='test');

-- Test 14: Write logs to parquet
SELECT '=== Test 14: Write logs to parquet ===' as test;
COPY (
    SELECT * FROM otel_logs_read('testdata/logs_*.binpb.gz', customer_id='parquet-test')
    ORDER BY chq_timestamp
) TO '/tmp/integration_test_logs.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
SELECT count(*) as logs_parquet_rows FROM '/tmp/integration_test_logs.parquet';

-- ============================================================================
-- TRACES TESTS
-- ============================================================================

-- Test 15: Read traces files
SELECT '=== Test 15: Read traces files ===' as test;
SELECT count(*) as traces_row_count FROM otel_traces_read('testdata/traces_*.binpb.gz', customer_id='test');

-- Test 16: Verify traces schema columns
SELECT '=== Test 16: Verify traces schema ===' as test;
SELECT
    chq_customer_id,
    chq_telemetry_type,
    chq_timestamp,
    span_trace_id,
    span_id,
    span_parent_span_id,
    span_name,
    span_kind,
    span_status_code,
    span_duration
FROM otel_traces_read('testdata/traces_*.binpb.gz', customer_id='traces-test')
LIMIT 3;

-- Test 17: Aggregate traces by span kind
SELECT '=== Test 17: Traces by span kind ===' as test;
SELECT
    span_kind,
    count(*) as count
FROM otel_traces_read('testdata/traces_*.binpb.gz', customer_id='test')
GROUP BY span_kind
ORDER BY count DESC;

-- Test 18: Traces duration statistics
SELECT '=== Test 18: Traces duration stats ===' as test;
SELECT
    span_kind,
    count(*) as span_count,
    min(span_duration) as min_duration_ms,
    max(span_duration) as max_duration_ms,
    avg(span_duration)::INTEGER as avg_duration_ms
FROM otel_traces_read('testdata/traces_*.binpb.gz', customer_id='test')
GROUP BY span_kind
ORDER BY span_kind;

-- Test 19: Root vs child spans
SELECT '=== Test 19: Root vs child spans ===' as test;
SELECT
    CASE WHEN span_parent_span_id = '' THEN 'root' ELSE 'child' END as span_type,
    count(*) as count
FROM otel_traces_read('testdata/traces_*.binpb.gz', customer_id='test')
GROUP BY span_type;

-- Test 20: Write traces to parquet
SELECT '=== Test 20: Write traces to parquet ===' as test;
COPY (
    SELECT * FROM otel_traces_read('testdata/traces_*.binpb.gz', customer_id='parquet-test')
    ORDER BY span_trace_id, chq_timestamp
) TO '/tmp/integration_test_traces.parquet' (FORMAT PARQUET, COMPRESSION ZSTD);
SELECT count(*) as traces_parquet_rows FROM '/tmp/integration_test_traces.parquet';

SELECT '=== All tests passed! ===' as result;
