-- OTel Metrics Extension Integration Tests
-- Run with: duckdb -unsigned < test/integration_test.sql

.bail on

-- Load the extension
LOAD 'build/release/otel_metrics.duckdb_extension';

-- Test 1: Read uncompressed binpb file
SELECT '=== Test 1: Read uncompressed binpb ===' as test;
SELECT * FROM otel_metrics_read('test/data/test_metrics.binpb');

-- Test 2: Read gzipped binpb file
SELECT '=== Test 2: Read gzipped binpb ===' as test;
SELECT * FROM otel_metrics_read('test/data/test_metrics.binpb.gz');

-- Test 3: Verify row count
SELECT '=== Test 3: Verify row count ===' as test;
SELECT count(*) as row_count FROM otel_metrics_read('test/data/test_metrics.binpb');

-- Test 4: Query specific columns
SELECT '=== Test 4: Query specific columns ===' as test;
SELECT
    metric_name,
    metric_type,
    value_int,
    value_double
FROM otel_metrics_read('test/data/test_metrics.binpb');

-- Test 5: Verify resource attributes are normalized
SELECT '=== Test 5: Verify resource attributes ===' as test;
SELECT
    metric_name,
    resource_service_name,
    resource_host_name,
    resource_k8s_pod_name
FROM otel_metrics_read('test/data/test_metrics.binpb')
LIMIT 1;

-- Test 6: Filter by metric type
SELECT '=== Test 6: Filter by metric type ===' as test;
SELECT
    metric_name,
    metric_type,
    is_monotonic,
    aggregation_temporality
FROM otel_metrics_read('test/data/test_metrics.binpb')
WHERE metric_type = 'sum';

-- Test 7: Aggregate query
SELECT '=== Test 7: Aggregate query ===' as test;
SELECT
    metric_name,
    count(*) as point_count,
    sum(value_int) as total_int,
    avg(value_double) as avg_double
FROM otel_metrics_read('test/data/test_metrics.binpb')
GROUP BY metric_name
ORDER BY metric_name;

SELECT '=== All tests passed! ===' as result;
