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

//! Comprehensive tests matching the Go implementation in oteltools/pkg/fingerprinter.
//!
//! These tests verify that our Rust implementation produces the same token sequences
//! and fingerprints as the Go implementation.

#[cfg(test)]
mod go_compatibility_tests {
    use crate::log_fingerprint::{Fingerprinter, fingerprint};

    /// Test cases from Go fingerprinter_test.go TestFingerprinter
    #[test]
    fn test_empty() {
        let fp = Fingerprinter::new();
        let (tokens, level, json_keys) = fp.tokenize_input("").unwrap();
        assert_eq!(tokens.join(" "), "");
        assert_eq!(level, "");
        assert!(json_keys.is_none());
    }

    #[test]
    fn test_simple() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input("hello world").unwrap();
        assert_eq!(tokens.join(" "), "hello world");
        assert_eq!(level, "");
    }

    #[test]
    fn test_date_yyyy_mm_dd() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("2024-01-02").unwrap();
        assert_eq!(tokens.join(" "), "<Date>");
    }

    #[test]
    fn test_date_yyyy_slash_mm_slash_dd() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("2024/01/02").unwrap();
        assert_eq!(tokens.join(" "), "<Date>");
    }

    #[test]
    fn test_date_dd_mm_yy() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("02/01/24").unwrap();
        assert_eq!(tokens.join(" "), "<Date>");
    }

    #[test]
    fn test_time() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("14:54:12").unwrap();
        assert_eq!(tokens.join(" "), "<Time>");
    }

    #[test]
    fn test_iso8601() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("2024-01-02T14:54:12").unwrap();
        assert_eq!(tokens.join(" "), "<ISO8601>");
    }

    #[test]
    fn test_iso8601_with_z() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("2024-01-02T14:54:12Z").unwrap();
        assert_eq!(tokens.join(" "), "<ISO8601>");
    }

    #[test]
    fn test_iso8601_with_timezone() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("2024-01-02T14:54:12+01:00").unwrap();
        assert_eq!(tokens.join(" "), "<ISO8601>");
    }

    #[test]
    fn test_uuid() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap();
        assert_eq!(tokens.join(" "), "<UUID>");
    }

    #[test]
    fn test_ipv4() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("10.42.255.254").unwrap();
        assert_eq!(tokens.join(" "), "<IPv4>");
    }

    #[test]
    fn test_email_simple() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("alice@example.com").unwrap();
        assert_eq!(tokens.join(" "), "<Email>");
    }

    #[test]
    fn test_email_with_underscore() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("alice_smith@example.com").unwrap();
        assert_eq!(tokens.join(" "), "<Email>");
    }

    #[test]
    fn test_email_with_dash() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("alice-smith@example.com").unwrap();
        assert_eq!(tokens.join(" "), "<Email>");
    }

    #[test]
    fn test_email_with_plus() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("alice+smith@example.com").unwrap();
        assert_eq!(tokens.join(" "), "<Email>");
    }

    #[test]
    fn test_email_with_dot() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("alice.smith@example.com").unwrap();
        assert_eq!(tokens.join(" "), "<Email>");
    }

    #[test]
    fn test_fqdn() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("example.com").unwrap();
        assert_eq!(tokens.join(" "), "<FQDN>");
    }

    #[test]
    fn test_path_alone() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input(" /api/v10/endpoint").unwrap();
        assert_eq!(tokens.join(" "), "<Path>");
    }

    #[test]
    fn test_path_with_version() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("bob /api/v10/endpoint").unwrap();
        assert_eq!(tokens.join(" "), "bob <Path>");
    }

    #[test]
    fn test_case_1() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input(
            "2024-12-14T00:46:28.852Z pid=9 tid=12msap class=SearchSyncWorker jid=96322f73c635d6812fd60163 INFO: start"
        ).unwrap();
        assert_eq!(tokens.join(" "), "<ISO8601> <Number> tid <Identifier> <Loglevel> start");
        assert_eq!(level, "info");
    }

    #[test]
    fn test_case_2() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input(
            "2024-12-14T00:46:28.852Z pid=9 tid=12xsap class=SearchSyncWorker jid=96322f73c635d6812fd60163 INFO: start"
        ).unwrap();
        assert_eq!(tokens.join(" "), "<ISO8601> <Number> tid <Identifier> <Loglevel> start");
        assert_eq!(level, "info");
    }

    #[test]
    fn test_sample_log_1() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input(
            "2024-04-17 00:37:23.147 ERROR 1 --- [lt-dispatcher-5] c.g.d.TelemetryEmitter : Received error code 400, endpoint = /api/v10/endpoint"
        ).unwrap();
        assert_eq!(tokens.join(" "), "<Date> <Time> <Loglevel> <Number> <Identifier> received error code <Number> endpoint <Path>");
        assert_eq!(level, "error");
    }

    #[test]
    fn test_go_module() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("chqs3exporter@v0.31.0/exporter.go:142").unwrap();
        assert_eq!(tokens.join(" "), "<ModuleName>");
    }

    #[test]
    fn test_truncates_at_newline() {
        let fp = Fingerprinter::new();
        let input = "2024-06-16T18:37:46.053Z\tinfo\tchqs3exporter@v0.31.0/exporter.go:142\tWrote buffer\n15 lines written to file foo.bar";
        let (tokens, level, _) = fp.tokenize_input(input).unwrap();
        // Debug: print actual tokens
        eprintln!("Input: {:?}", input);
        eprintln!("Tokens: {:?}", tokens);
        eprintln!("Level: {:?}", level);
        assert_eq!(tokens.join(" "), "<ISO8601> <Loglevel> <ModuleName> wrote buffer");
        assert_eq!(level, "info");
    }

    #[test]
    fn test_path_with_query_params() {
        let fp = Fingerprinter::new();
        let (tokens, _, _) = fp.tokenize_input("/api/v1/endpoint?query=foo&bar=baz").unwrap();
        assert_eq!(tokens.join(" "), "<Path>");
    }

    // Tests with max token limit
    #[test]
    fn test_with_line_limit_simple() {
        let fp = Fingerprinter::with_max_tokens(5);
        let (tokens, _, _) = fp.tokenize_input("hello world").unwrap();
        assert_eq!(tokens.join(" "), "hello world");
    }

    #[test]
    fn test_with_line_limit_long() {
        let fp = Fingerprinter::with_max_tokens(5);
        let input = format!("hello 12345{}", " foo bar".repeat(10));
        let (tokens, _, _) = fp.tokenize_input(&input).unwrap();
        assert_eq!(tokens.join(" "), "hello <Number> foo bar foo");
    }

    // JSON fingerprint tests
    #[test]
    fn test_json_fingerprint_simple() {
        let result = fingerprint(r#"{"msg": "alice bob", "key": "value"}"#).unwrap();
        assert_eq!(result.fingerprint, -4799080351441142732_i64);
    }

    #[test]
    fn test_json_fingerprint_complex_alice_john() {
        let result = fingerprint(
            r#"{"msg": "alice john", "user": {"id": 123, "name": "John Doe"}, "action": "login", "timestamp": "2024-06-16T18:41:32.309Z"}"#
        ).unwrap();
        assert_eq!(result.fingerprint, -1298215320945995457_i64);
    }

    #[test]
    fn test_json_fingerprint_complex_alice_nancy() {
        let result = fingerprint(
            r#"{"msg": "alice nancy", "user": {"id": 123, "name": "John Doe"}, "action": "login", "timestamp": "2024-06-16T18:41:32.309Z"}"#
        ).unwrap();
        assert_eq!(result.fingerprint, -4204312781059083134_i64);
    }

    // Fingerprint identicality tests (same fingerprint for similar logs)
    #[test]
    fn test_identical_fingerprints_simple() {
        let inputs = vec![
            "INFO Received request for /api/v1/endpoint from userId=65431",
            "INFO Received request for /api/v1/endpoint from userId=12345",
        ];

        let fp = Fingerprinter::new();
        let fp1 = fp.fingerprint(inputs[0]).unwrap().fingerprint;
        let fp2 = fp.fingerprint(inputs[1]).unwrap().fingerprint;
        assert_eq!(fp1, fp2);
    }
}

/// Additional tests for edge cases and internal functions
#[cfg(test)]
mod internal_tests {
    use crate::log_fingerprint::wordlist::{split_words, is_word};

    #[test]
    fn test_split_words_this_is_a_test() {
        assert_eq!(
            split_words("THISIsATest"),
            vec!["t", "h", "i", "s", "is", "a", "test"]
        );
    }

    #[test]
    fn test_is_word_with_space() {
        // "hello baz" contains space so isn't a single word
        assert!(!is_word("hello baz"));
    }
}
