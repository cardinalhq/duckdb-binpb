-- OTel Metrics Extension Integration Tests
-- Run with: duckdb -unsigned < test/integration_test.sql

.bail on

-- Load the extension
LOAD 'build/release/otel_metrics.duckdb_extension';

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

SELECT '=== All tests passed! ===' as result;
