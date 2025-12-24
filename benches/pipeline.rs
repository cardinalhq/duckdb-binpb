// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Pipeline benchmark - measures each step of processing binpb files

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use otel_binpb::common::read_binpb_file;
use otel_binpb::metrics::parse_metrics;
use otel_binpb::opentelemetry::proto::collector::metrics::v1::ExportMetricsServiceRequest;
use prost::Message;

fn get_test_files() -> Vec<String> {
    glob::glob("testdata/*.binpb.gz")
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|path| path.to_string_lossy().to_string())
        .collect()
}

/// Benchmark: File reading + gzip decompression
fn bench_read_file(c: &mut Criterion) {
    let files = get_test_files();
    if files.is_empty() {
        eprintln!("No test files found in testdata/");
        return;
    }

    let mut group = c.benchmark_group("1_read_file");
    for file in &files {
        let name = std::path::Path::new(file)
            .file_stem()
            .unwrap()
            .to_str()
            .unwrap();
        group.bench_with_input(BenchmarkId::from_parameter(name), file, |b, file| {
            b.iter(|| read_binpb_file(black_box(file)).unwrap())
        });
    }
    group.finish();
}

/// Benchmark: Protobuf decoding only
fn bench_protobuf_decode(c: &mut Criterion) {
    let files = get_test_files();
    if files.is_empty() {
        return;
    }

    // Pre-read all files into memory
    let file_data: Vec<(String, Vec<u8>)> = files
        .iter()
        .filter_map(|f| {
            let data = read_binpb_file(f).ok()?;
            let name = std::path::Path::new(f)
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            Some((name, data))
        })
        .collect();

    let mut group = c.benchmark_group("2_protobuf_decode");
    for (name, data) in &file_data {
        group.bench_with_input(BenchmarkId::from_parameter(name), data, |b, data| {
            b.iter(|| ExportMetricsServiceRequest::decode(black_box(data.as_slice())).unwrap())
        });
    }
    group.finish();
}

/// Benchmark: Full parse_metrics (includes row creation, TID, sketch)
fn bench_parse_metrics(c: &mut Criterion) {
    let files = get_test_files();
    if files.is_empty() {
        return;
    }

    let file_data: Vec<(String, Vec<u8>)> = files
        .iter()
        .filter_map(|f| {
            let data = read_binpb_file(f).ok()?;
            let name = std::path::Path::new(f)
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            Some((name, data))
        })
        .collect();

    let mut group = c.benchmark_group("3_parse_metrics");
    for (name, data) in &file_data {
        group.bench_with_input(BenchmarkId::from_parameter(name), data, |b, data| {
            b.iter(|| parse_metrics(black_box(data), black_box("test-customer")).unwrap())
        });
    }
    group.finish();
}

/// Detailed timing breakdown - not a criterion bench, but prints detailed stats
fn detailed_breakdown(c: &mut Criterion) {
    let files = get_test_files();
    if files.is_empty() {
        return;
    }

    // Just measure one file in detail
    let file = &files[0];

    c.bench_function("full_pipeline_single", |b| {
        b.iter(|| {
            let data = read_binpb_file(black_box(file)).unwrap();
            let rows = parse_metrics(black_box(&data), black_box("test-customer")).unwrap();
            black_box(rows.len())
        })
    });
}

/// Benchmark collect_attr_names using HashSet (current impl)
fn bench_collect_attr_names(c: &mut Criterion) {
    use std::collections::HashSet;

    let files = get_test_files();
    if files.is_empty() {
        return;
    }

    // Parse one file to get rows
    let data = read_binpb_file(&files[0]).unwrap();
    let rows = parse_metrics(&data, "test-customer").unwrap();

    c.bench_function("4_collect_attr_names_hashset", |b| {
        b.iter(|| {
            let mut resource_attr_set: HashSet<String> = HashSet::new();
            let mut datapoint_attr_set: HashSet<String> = HashSet::new();

            for row in black_box(&rows) {
                for (key, _) in row.resource_attrs.iter() {
                    resource_attr_set.insert(key.clone());
                }
                for (key, _) in &row.datapoint_attrs {
                    datapoint_attr_set.insert(key.clone());
                }
            }

            let mut resource_attr_names: Vec<String> = resource_attr_set.into_iter().collect();
            let mut datapoint_attr_names: Vec<String> = datapoint_attr_set.into_iter().collect();

            resource_attr_names.sort();
            datapoint_attr_names.sort();

            black_box((resource_attr_names, datapoint_attr_names))
        })
    });
}

criterion_group!(
    benches,
    bench_read_file,
    bench_protobuf_decode,
    bench_parse_metrics,
    bench_collect_attr_names,
    detailed_breakdown
);
criterion_main!(benches);
