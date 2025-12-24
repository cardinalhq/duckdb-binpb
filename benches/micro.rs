// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Micro-benchmarks for identifying specific bottlenecks

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use otel_binpb::common::read_binpb_file;
use otel_binpb::normalize::normalize_attribute_name;
use otel_binpb::sketch::{DDSketch, RollupStats};
use otel_binpb::tid::compute_tid_from_otel;
use otel_binpb::opentelemetry::proto::collector::metrics::v1::ExportMetricsServiceRequest;
use prost::Message;

fn get_test_file_data() -> Vec<u8> {
    let files: Vec<String> = glob::glob("testdata/*.binpb.gz")
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|path| path.to_string_lossy().to_string())
        .collect();

    if files.is_empty() {
        panic!("No test files found");
    }

    read_binpb_file(&files[0]).unwrap()
}

/// Benchmark TID computation (includes normalization + hashing)
fn bench_tid_computation(c: &mut Criterion) {
    let resource_attrs = vec![
        ("service.name", "my-service"),
        ("k8s.pod.name", "pod-123"),
        ("k8s.namespace.name", "default"),
        ("host.name", "server01"), // Not kept
    ];
    let dp_attrs = vec![
        ("http.method", "GET"),
        ("http.status_code", "200"),
        ("http.route", "/api/users"),
    ];

    c.bench_function("tid_computation", |b| {
        b.iter(|| {
            compute_tid_from_otel(
                black_box("http.server.request.duration"),
                black_box("gauge"),
                black_box(&resource_attrs),
                black_box(&dp_attrs),
            )
        })
    });
}

/// Benchmark DDSketch creation for single value (gauge/sum)
fn bench_sketch_single_value(c: &mut Criterion) {
    c.bench_function("sketch_single_value", |b| {
        b.iter(|| {
            let mut sketch = DDSketch::default();
            sketch.add(black_box(42.5));
            black_box(sketch)
        })
    });
}

/// Benchmark DDSketch encoding
fn bench_sketch_encode(c: &mut Criterion) {
    let mut sketch = DDSketch::default();
    sketch.add(42.5);

    c.bench_function("sketch_encode", |b| {
        b.iter(|| {
            black_box(sketch.encode().unwrap())
        })
    });
}

/// Benchmark RollupStats extraction (6 quantile calls)
fn bench_rollup_stats(c: &mut Criterion) {
    let mut sketch = DDSketch::default();
    for i in 1..=100 {
        sketch.add(i as f64);
    }

    c.bench_function("rollup_stats_from_sketch", |b| {
        b.iter(|| {
            black_box(RollupStats::from_sketch(black_box(&sketch)))
        })
    });
}

/// Benchmark attribute normalization
fn bench_normalize_typical(c: &mut Criterion) {
    let attrs = [
        "service.name",
        "k8s.pod.name",
        "http.request.method",
        "http.response.status_code",
        "_internal.collector_id",
    ];

    c.bench_function("normalize_5_attrs", |b| {
        b.iter(|| {
            for attr in &attrs {
                black_box(normalize_attribute_name(black_box(attr)));
            }
        })
    });
}

/// Benchmark string cloning (simulating per-row allocations)
fn bench_string_cloning(c: &mut Criterion) {
    let customer_id = "customer-12345";
    let metric_name = "http_server_request_duration";
    let description = "Measures the duration of HTTP server requests";
    let unit = "ms";
    let scope_name = "opentelemetry.instrumentation.http";

    c.bench_function("string_clones_per_row", |b| {
        b.iter(|| {
            black_box(customer_id.to_string());
            black_box("metrics".to_string());
            black_box(metric_name.to_string());
            black_box(description.to_string());
            black_box(unit.to_string());
            black_box("gauge".to_string());
            black_box(scope_name.to_string());
            black_box("1.0.0".to_string());
        })
    });
}

/// Benchmark format! calls for attribute prefixing
fn bench_format_prefix(c: &mut Criterion) {
    let keys = ["service_name", "k8s_pod_name", "k8s_namespace_name"];

    c.bench_function("format_resource_prefix", |b| {
        b.iter(|| {
            for key in &keys {
                black_box(format!("resource_{}", key));
            }
        })
    });
}

/// Benchmark Vec::contains vs HashSet::contains
fn bench_contains_check(c: &mut Criterion) {
    let vec_names: Vec<String> = (0..50).map(|i| format!("attr_{}", i)).collect();
    let set_names: std::collections::HashSet<String> = vec_names.iter().cloned().collect();
    let search_key = "attr_25";

    let mut group = c.benchmark_group("contains_check");

    group.bench_function("vec_contains", |b| {
        b.iter(|| {
            black_box(vec_names.contains(&search_key.to_string()))
        })
    });

    group.bench_function("hashset_contains", |b| {
        b.iter(|| {
            black_box(set_names.contains(search_key))
        })
    });

    group.finish();
}

/// Count data points in test file to understand scale
fn count_datapoints(c: &mut Criterion) {
    let data = get_test_file_data();
    let request = ExportMetricsServiceRequest::decode(data.as_slice()).unwrap();

    let mut total_datapoints = 0;
    let mut gauge_count = 0;
    let mut sum_count = 0;
    let mut histogram_count = 0;

    for rm in &request.resource_metrics {
        for sm in &rm.scope_metrics {
            for metric in &sm.metrics {
                use otel_binpb::opentelemetry::proto::metrics::v1::metric::Data;
                match &metric.data {
                    Some(Data::Gauge(g)) => {
                        gauge_count += g.data_points.len();
                        total_datapoints += g.data_points.len();
                    }
                    Some(Data::Sum(s)) => {
                        sum_count += s.data_points.len();
                        total_datapoints += s.data_points.len();
                    }
                    Some(Data::Histogram(h)) => {
                        histogram_count += h.data_points.len();
                        total_datapoints += h.data_points.len();
                    }
                    Some(Data::ExponentialHistogram(eh)) => {
                        histogram_count += eh.data_points.len();
                        total_datapoints += eh.data_points.len();
                    }
                    Some(Data::Summary(s)) => {
                        histogram_count += s.data_points.len();
                        total_datapoints += s.data_points.len();
                    }
                    None => {}
                }
            }
        }
    }

    eprintln!("Test file stats:");
    eprintln!("  Total data points: {}", total_datapoints);
    eprintln!("  Gauges: {}", gauge_count);
    eprintln!("  Sums: {}", sum_count);
    eprintln!("  Histograms: {}", histogram_count);
    eprintln!("  Processing time per datapoint: ~{:.2}us",
        200_000.0 / total_datapoints as f64);

    // Dummy benchmark just to output stats
    c.bench_function("_stats_only", |b| {
        b.iter(|| black_box(total_datapoints))
    });
}

criterion_group!(
    benches,
    count_datapoints,
    bench_tid_computation,
    bench_sketch_single_value,
    bench_sketch_encode,
    bench_rollup_stats,
    bench_normalize_typical,
    bench_string_cloning,
    bench_format_prefix,
    bench_contains_check,
);
criterion_main!(benches);
