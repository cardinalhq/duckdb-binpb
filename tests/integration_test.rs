// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Integration tests using real-world metric, log, and trace files

use otel_binpb::common::read_binpb_file;
use otel_binpb::logs::parse_logs;
use otel_binpb::metrics::parse_metrics;
use otel_binpb::traces::parse_traces;
use otel_binpb::opentelemetry::proto::collector::logs::v1::ExportLogsServiceRequest;
use otel_binpb::opentelemetry::proto::collector::metrics::v1::ExportMetricsServiceRequest;
use otel_binpb::opentelemetry::proto::collector::trace::v1::ExportTraceServiceRequest;
use otel_binpb::opentelemetry::proto::metrics::v1::metric;
use prost::Message;
use std::collections::HashMap;
use std::time::Instant;

fn get_testdata_files() -> Vec<String> {
    get_testdata_files_by_prefix("metrics_")
}

fn get_logs_testdata_files() -> Vec<String> {
    get_testdata_files_by_prefix("logs_")
}

fn get_traces_testdata_files() -> Vec<String> {
    get_testdata_files_by_prefix("traces_")
}

fn get_testdata_files_by_prefix(prefix: &str) -> Vec<String> {
    let testdata_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata");
    std::fs::read_dir(testdata_dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            // Match .binpb or .binpb.gz files with the given prefix
            if name.starts_with(prefix) && (name.ends_with(".binpb") || name.ends_with(".binpb.gz")) {
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

// ============================================================================
// Logs Tests
// ============================================================================

#[test]
fn analyze_logs_testdata_files() {
    let files = get_logs_testdata_files();
    if files.is_empty() {
        println!("No logs testdata files found, skipping");
        return;
    }

    let mut total_resource_logs = 0usize;
    let mut total_scope_logs = 0usize;
    let mut total_log_records = 0usize;
    let mut severity_counts: HashMap<String, usize> = HashMap::new();

    for file_path in &files {
        println!("\n=== Analyzing Logs: {} ===", file_path);

        let data = read_binpb_file(file_path).expect("Failed to read file");
        println!("  Compressed size: {} bytes", std::fs::metadata(file_path).unwrap().len());
        println!("  Uncompressed size: {} bytes", data.len());

        let request = ExportLogsServiceRequest::decode(&data[..]).expect("Failed to decode");

        for rl in &request.resource_logs {
            total_resource_logs += 1;
            for sl in &rl.scope_logs {
                total_scope_logs += 1;
                for log in &sl.log_records {
                    total_log_records += 1;
                    let severity = if log.severity_text.is_empty() {
                        format!("severity_{}", log.severity_number)
                    } else {
                        log.severity_text.clone()
                    };
                    *severity_counts.entry(severity).or_insert(0) += 1;
                }
            }
        }

        println!("  Resource logs: {}", request.resource_logs.len());
    }

    println!("\n=== LOGS TOTAL ACROSS ALL FILES ===");
    println!("Files processed: {}", files.len());
    println!("Resource logs: {}", total_resource_logs);
    println!("Scope logs: {}", total_scope_logs);
    println!("Log records: {}", total_log_records);
    println!("Severity counts: {:?}", severity_counts);
}

#[test]
fn test_parse_all_logs_testdata_files() {
    let files = get_logs_testdata_files();
    if files.is_empty() {
        println!("No logs testdata files found, skipping");
        return;
    }

    for file_path in &files {
        println!("\nParsing logs: {}", file_path);

        let data = read_binpb_file(file_path).expect("Failed to read file");
        let rows = parse_logs(&data, "test-customer", &[]).expect("Failed to parse logs");

        println!("  Rows generated: {}", rows.len());

        // Verify all rows have required fields
        for row in &rows {
            assert!(!row.chq_customer_id.is_empty());
            assert_eq!(row.chq_telemetry_type, "logs");
            assert!(row.chq_timestamp > 0);
            assert!(row.chq_tsns > 0);
            assert_eq!(row.metric_name, "log_events");
        }

        // Count severity levels
        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for row in &rows {
            let level = row.log_level.clone().unwrap_or_else(|| "UNKNOWN".to_string());
            *severity_counts.entry(level).or_insert(0) += 1;
        }
        println!("  Severity levels: {:?}", severity_counts);

        // Count trace correlation
        let with_trace = rows.iter().filter(|r| r.trace_id.is_some()).count();
        println!("  Logs with trace correlation: {}/{}", with_trace, rows.len());
    }
}

#[test]
fn test_logs_with_file_metadata() {
    let files = get_logs_testdata_files();
    if files.is_empty() {
        println!("No logs testdata files found, skipping");
        return;
    }

    let file_path = &files[0];
    let data = read_binpb_file(file_path).expect("Failed to read file");

    // Parse with file metadata
    let metadata = vec![
        ("resource_bucket_name".to_string(), "test-bucket".to_string()),
        ("resource_file_name".to_string(), file_path.clone()),
    ];

    let rows = parse_logs(&data, "test-customer", &metadata).expect("Failed to parse logs");

    assert!(!rows.is_empty(), "Should have at least one log row");

    // Verify file metadata is propagated to all rows
    for row in &rows {
        assert_eq!(row.file_metadata.len(), 2);
        assert!(row.file_metadata.iter().any(|(k, v)| k == "resource_bucket_name" && v == "test-bucket"));
        assert!(row.file_metadata.iter().any(|(k, v)| k == "resource_file_name" && v == file_path));
    }

    println!("File metadata propagation test passed with {} rows", rows.len());
}

// ============================================================================
// Traces Tests
// ============================================================================

#[test]
fn analyze_traces_testdata_files() {
    let files = get_traces_testdata_files();
    if files.is_empty() {
        println!("No traces testdata files found, skipping");
        return;
    }

    let mut total_resource_spans = 0usize;
    let mut total_scope_spans = 0usize;
    let mut total_spans = 0usize;
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    let mut status_counts: HashMap<String, usize> = HashMap::new();

    for file_path in &files {
        println!("\n=== Analyzing Traces: {} ===", file_path);

        let data = read_binpb_file(file_path).expect("Failed to read file");
        println!("  Compressed size: {} bytes", std::fs::metadata(file_path).unwrap().len());
        println!("  Uncompressed size: {} bytes", data.len());

        let request = ExportTraceServiceRequest::decode(&data[..]).expect("Failed to decode");

        for rs in &request.resource_spans {
            total_resource_spans += 1;
            for ss in &rs.scope_spans {
                total_scope_spans += 1;
                for span in &ss.spans {
                    total_spans += 1;
                    *kind_counts.entry(format!("kind_{}", span.kind)).or_insert(0) += 1;
                    if let Some(status) = &span.status {
                        *status_counts.entry(format!("status_{}", status.code)).or_insert(0) += 1;
                    }
                }
            }
        }

        println!("  Resource spans: {}", request.resource_spans.len());
    }

    println!("\n=== TRACES TOTAL ACROSS ALL FILES ===");
    println!("Files processed: {}", files.len());
    println!("Resource spans: {}", total_resource_spans);
    println!("Scope spans: {}", total_scope_spans);
    println!("Spans: {}", total_spans);
    println!("Span kinds: {:?}", kind_counts);
    println!("Status codes: {:?}", status_counts);
}

#[test]
fn test_parse_all_traces_testdata_files() {
    let files = get_traces_testdata_files();
    if files.is_empty() {
        println!("No traces testdata files found, skipping");
        return;
    }

    for file_path in &files {
        println!("\nParsing traces: {}", file_path);

        let data = read_binpb_file(file_path).expect("Failed to read file");
        let rows = parse_traces(&data, "test-customer").expect("Failed to parse traces");

        println!("  Rows generated: {}", rows.len());

        // Verify all rows have required fields
        for row in &rows {
            assert!(!row.chq_customer_id.is_empty());
            assert_eq!(row.chq_telemetry_type, "traces");
            assert!(row.chq_timestamp > 0);
            assert!(row.chq_tsns > 0);
            assert!(!row.span_trace_id.is_empty(), "trace_id should not be empty");
            assert!(!row.span_id.is_empty(), "span_id should not be empty");
            assert!(!row.span_name.is_empty(), "span_name should not be empty");
            assert!(!row.span_kind.is_empty());
            assert!(!row.span_status_code.is_empty());
        }

        // Count span kinds
        let mut kind_counts: HashMap<&str, usize> = HashMap::new();
        for row in &rows {
            *kind_counts.entry(&row.span_kind).or_insert(0) += 1;
        }
        println!("  Span kinds: {:?}", kind_counts);

        // Count root vs child spans
        let root_spans = rows.iter().filter(|r| r.span_parent_span_id.is_empty()).count();
        println!("  Root spans: {}/{}", root_spans, rows.len());

        // Duration statistics
        let durations: Vec<i64> = rows.iter().map(|r| r.span_duration).collect();
        if !durations.is_empty() {
            let min_duration = durations.iter().min().unwrap();
            let max_duration = durations.iter().max().unwrap();
            let avg_duration: f64 = durations.iter().sum::<i64>() as f64 / durations.len() as f64;
            println!("  Duration (ms): min={}, max={}, avg={:.2}", min_duration, max_duration, avg_duration);
        }
    }
}

#[test]
fn benchmark_logs_parsing_speed() {
    let files = get_logs_testdata_files();
    if files.is_empty() {
        println!("No logs testdata files found, skipping benchmark");
        return;
    }

    let file_path = &files[0];
    let data = read_binpb_file(file_path).expect("Failed to read file");

    // Warm up
    let _ = parse_logs(&data, "bench", &[]);

    // Benchmark
    let iterations = 10;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = parse_logs(&data, "bench", &[]);
    }
    let elapsed = start.elapsed();

    let per_iteration = elapsed / iterations;
    let data_size_mb = data.len() as f64 / 1_000_000.0;
    let throughput_mb_s = data_size_mb / per_iteration.as_secs_f64();

    println!("\n=== Logs Parsing Benchmark ===");
    println!("File: {}", file_path);
    println!("Data size: {:.2} MB", data_size_mb);
    println!("Iterations: {}", iterations);
    println!("Total time: {:?}", elapsed);
    println!("Per iteration: {:?}", per_iteration);
    println!("Throughput: {:.2} MB/s", throughput_mb_s);
}

#[test]
fn benchmark_traces_parsing_speed() {
    let files = get_traces_testdata_files();
    if files.is_empty() {
        println!("No traces testdata files found, skipping benchmark");
        return;
    }

    let file_path = &files[0];
    let data = read_binpb_file(file_path).expect("Failed to read file");

    // Warm up
    let _ = parse_traces(&data, "bench");

    // Benchmark
    let iterations = 10;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = parse_traces(&data, "bench");
    }
    let elapsed = start.elapsed();

    let per_iteration = elapsed / iterations;
    let data_size_mb = data.len() as f64 / 1_000_000.0;
    let throughput_mb_s = data_size_mb / per_iteration.as_secs_f64();

    println!("\n=== Traces Parsing Benchmark ===");
    println!("File: {}", file_path);
    println!("Data size: {:.2} MB", data_size_mb);
    println!("Iterations: {}", iterations);
    println!("Total time: {:?}", elapsed);
    println!("Per iteration: {:?}", per_iteration);
    println!("Throughput: {:.2} MB/s", throughput_mb_s);
}
