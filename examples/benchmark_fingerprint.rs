//! Benchmark for log fingerprinting

use otel_binpb::log_fingerprint::Fingerprinter;
use std::time::Instant;

const TEST_MESSAGES: &[&str] = &[
    "2024-06-16T18:37:46.053Z\tinfo\tchqs3exporter@v0.31.0/exporter.go:142\tWrote buffer",
    "2024-04-17 00:37:23.147 ERROR 1 --- [lt-dispatcher-5] c.g.d.TelemetryEmitter : Received error code 400, endpoint = /api/v10/endpoint",
    "2024-12-14T00:46:28.852Z pid=9 tid=12msap class=SearchSyncWorker jid=96322f73c635d6812fd60163 INFO: start",
    "INFO Received request for /api/v1/endpoint from userId=65431",
    r#"{"msg": "alice bob", "key": "value"}"#,
    r#"{"msg": "alice john", "user": {"id": 123, "name": "John Doe"}, "action": "login", "timestamp": "2024-06-16T18:41:32.309Z"}"#,
    "alice@example.com sent email to bob@company.org",
    "Connection from 10.42.255.254:8080 to 192.168.1.1:443",
    "Request dddddddd-dddd-dddd-dddd-dddddddddddd completed in 150ms",
    "GET /api/v1/users?page=1&limit=10 HTTP/1.1 200 OK",
];

fn main() {
    let fp = Fingerprinter::new();
    let iterations = 100_000;

    // Warmup
    for _ in 0..1000 {
        for msg in TEST_MESSAGES {
            let _ = fp.tokenize_input(msg);
        }
    }

    // Benchmark
    let start = Instant::now();
    for _ in 0..iterations {
        for msg in TEST_MESSAGES {
            let _ = fp.tokenize_input(msg);
        }
    }
    let elapsed = start.elapsed();

    let total_ops = iterations * TEST_MESSAGES.len();
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();
    let ns_per_op = elapsed.as_nanos() as f64 / total_ops as f64;

    println!("Rust Fingerprinter Benchmark");
    println!("============================");
    println!("Total operations: {}", total_ops);
    println!("Total time: {:?}", elapsed);
    println!("Ops/sec: {:.0}", ops_per_sec);
    println!("ns/op: {:.2}", ns_per_op);
}
