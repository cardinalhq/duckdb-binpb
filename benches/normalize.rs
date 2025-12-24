// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use otel_binpb::normalize::normalize_attribute_name;

fn bench_normalize(c: &mut Criterion) {
    let test_cases = [
        ("short", "cpu"),
        ("dotted", "service.name"),
        ("k8s", "k8s.pod.name"),
        ("mixed", "HTTP.Status-Code"),
        ("long", "opentelemetry.instrumentation.library.name.with.many.dots"),
    ];

    let mut group = c.benchmark_group("normalize");

    for (name, input) in test_cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), input, |b, input| {
            b.iter(|| normalize_attribute_name(black_box(input)))
        });
    }

    group.finish();
}

fn bench_normalize_batch(c: &mut Criterion) {
    let attributes = vec![
        "service.name",
        "service.namespace",
        "host.name",
        "host.id",
        "k8s.pod.name",
        "k8s.namespace.name",
        "k8s.deployment.name",
        "http.method",
        "http.status_code",
        "http.route",
    ];

    c.bench_function("batch_10", |b| {
        b.iter(|| {
            for attr in &attributes {
                black_box(normalize_attribute_name(black_box(attr)));
            }
        })
    });
}

criterion_group!(benches, bench_normalize, bench_normalize_batch);
criterion_main!(benches);
