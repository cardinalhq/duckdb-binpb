// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Integration tests using real-world metric files

use otel_metrics::common::read_binpb_file;
use otel_metrics::metrics::parse_metrics;
use otel_metrics::opentelemetry::proto::collector::metrics::v1::ExportMetricsServiceRequest;
use otel_metrics::opentelemetry::proto::metrics::v1::metric;
use prost::Message;
use std::collections::HashMap;
use std::time::Instant;

fn get_testdata_files() -> Vec<String> {
    let testdata_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata");
    std::fs::read_dir(testdata_dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            // Match .binpb or .binpb.gz files
            if name.ends_with(".binpb") || name.ends_with(".binpb.gz") {
                Some(path.to_string_lossy().to_string())
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn analyze_testdata_files() {
    let files = get_testdata_files();
    assert!(!files.is_empty(), "No testdata files found");

    let mut total_stats = MetricStats::default();

    for file_path in &files {
        println!("\n=== Analyzing: {} ===", file_path);

        let data = read_binpb_file(file_path).expect("Failed to read file");
        println!("  Compressed size: {} bytes", std::fs::metadata(file_path).unwrap().len());
        println!("  Uncompressed size: {} bytes", data.len());

        let request = ExportMetricsServiceRequest::decode(&data[..]).expect("Failed to decode");

        let stats = analyze_request(&request);
        println!("  Resource metrics: {}", stats.resource_metrics);
        println!("  Scope metrics: {}", stats.scope_metrics);
        println!("  Metrics: {}", stats.metrics);
        println!("  Data points by type:");
        println!("    Gauge: {}", stats.gauge_points);
        println!("    Sum: {}", stats.sum_points);
        println!("    Histogram: {}", stats.histogram_points);
        println!("    ExponentialHistogram: {}", stats.exp_histogram_points);
        println!("    Summary: {}", stats.summary_points);
        println!("  Unique metric names: {}", stats.unique_metrics.len());

        total_stats.merge(&stats);
    }

    println!("\n=== TOTAL ACROSS ALL FILES ===");
    println!("Files processed: {}", files.len());
    println!("Resource metrics: {}", total_stats.resource_metrics);
    println!("Scope metrics: {}", total_stats.scope_metrics);
    println!("Metrics: {}", total_stats.metrics);
    println!("Data points by type:");
    println!("  Gauge: {}", total_stats.gauge_points);
    println!("  Sum: {}", total_stats.sum_points);
    println!("  Histogram: {}", total_stats.histogram_points);
    println!("  ExponentialHistogram: {}", total_stats.exp_histogram_points);
    println!("  Summary: {}", total_stats.summary_points);
    println!("Unique metric names: {}", total_stats.unique_metrics.len());

    // Print some sample metric names
    let mut names: Vec<_> = total_stats.unique_metrics.keys().collect();
    names.sort();
    println!("\nSample metric names (first 20):");
    for name in names.iter().take(20) {
        println!("  - {}", name);
    }
}

#[test]
fn test_parse_all_testdata_files() {
    let files = get_testdata_files();
    assert!(!files.is_empty(), "No testdata files found");

    for file_path in &files {
        println!("\nParsing: {}", file_path);

        let data = read_binpb_file(file_path).expect("Failed to read file");
        let rows = parse_metrics(&data, "test-customer").expect("Failed to parse metrics");

        println!("  Rows generated: {}", rows.len());

        // Verify all rows have required fields
        for row in &rows {
            assert!(!row.chq_customer_id.is_empty());
            assert_eq!(row.chq_telemetry_type, "metrics");
            assert_ne!(row.chq_tid, 0);
            assert!(row.chq_timestamp > 0);
            assert!(row.chq_tsns > 0);
            assert!(!row.metric_name.is_empty());
            assert!(!row.chq_sketch.is_empty());
        }

        // Count metric types
        let mut type_counts: HashMap<&str, usize> = HashMap::new();
        for row in &rows {
            *type_counts.entry(&row.chq_metric_type).or_insert(0) += 1;
        }
        println!("  Metric types: {:?}", type_counts);
    }
}

#[test]
fn benchmark_parsing_speed() {
    let files = get_testdata_files();
    if files.is_empty() {
        println!("No testdata files found, skipping benchmark");
        return;
    }

    // Use first file for benchmark
    let file_path = &files[0];
    let data = read_binpb_file(file_path).expect("Failed to read file");

    // Warm up
    let _ = parse_metrics(&data, "bench");

    // Benchmark
    let iterations = 10;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = parse_metrics(&data, "bench");
    }
    let elapsed = start.elapsed();

    let per_iteration = elapsed / iterations;
    let data_size_mb = data.len() as f64 / 1_000_000.0;
    let throughput_mb_s = data_size_mb / per_iteration.as_secs_f64();

    println!("\n=== Parsing Benchmark ===");
    println!("File: {}", file_path);
    println!("Data size: {:.2} MB", data_size_mb);
    println!("Iterations: {}", iterations);
    println!("Total time: {:?}", elapsed);
    println!("Per iteration: {:?}", per_iteration);
    println!("Throughput: {:.2} MB/s", throughput_mb_s);
}

#[derive(Default)]
struct MetricStats {
    resource_metrics: usize,
    scope_metrics: usize,
    metrics: usize,
    gauge_points: usize,
    sum_points: usize,
    histogram_points: usize,
    exp_histogram_points: usize,
    summary_points: usize,
    unique_metrics: HashMap<String, usize>,
}

impl MetricStats {
    fn merge(&mut self, other: &MetricStats) {
        self.resource_metrics += other.resource_metrics;
        self.scope_metrics += other.scope_metrics;
        self.metrics += other.metrics;
        self.gauge_points += other.gauge_points;
        self.sum_points += other.sum_points;
        self.histogram_points += other.histogram_points;
        self.exp_histogram_points += other.exp_histogram_points;
        self.summary_points += other.summary_points;
        for (name, count) in &other.unique_metrics {
            *self.unique_metrics.entry(name.clone()).or_insert(0) += count;
        }
    }
}

fn analyze_request(request: &ExportMetricsServiceRequest) -> MetricStats {
    let mut stats = MetricStats::default();

    for rm in &request.resource_metrics {
        stats.resource_metrics += 1;

        for sm in &rm.scope_metrics {
            stats.scope_metrics += 1;

            for m in &sm.metrics {
                stats.metrics += 1;
                *stats.unique_metrics.entry(m.name.clone()).or_insert(0) += 1;

                match &m.data {
                    Some(metric::Data::Gauge(g)) => {
                        stats.gauge_points += g.data_points.len();
                    }
                    Some(metric::Data::Sum(s)) => {
                        stats.sum_points += s.data_points.len();
                    }
                    Some(metric::Data::Histogram(h)) => {
                        stats.histogram_points += h.data_points.len();
                    }
                    Some(metric::Data::ExponentialHistogram(eh)) => {
                        stats.exp_histogram_points += eh.data_points.len();
                    }
                    Some(metric::Data::Summary(s)) => {
                        stats.summary_points += s.data_points.len();
                    }
                    None => {}
                }
            }
        }
    }

    stats
}
