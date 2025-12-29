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

//! Fingerprinting for telemetry data indexing.
//!
//! This module implements fingerprinting that is compatible with the Go implementation
//! in lakerunner/internal/fingerprint. The fingerprints are used for efficient query
//! filtering on indexed dimensions.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// ExistsRegex is the wildcard pattern used for "field exists" fingerprints.
pub const EXISTS_REGEX: &str = ".*";

/// IndexFlags defines which fingerprinting strategies to use for a dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexFlags(u8);

impl IndexFlags {
    /// IndexExact generates a fingerprint for the exact full value.
    pub const EXACT: IndexFlags = IndexFlags(1 << 0);

    /// IndexTrigramExact generates both trigram fingerprints AND the exact value fingerprint.
    pub const TRIGRAM_EXACT: IndexFlags = IndexFlags((1 << 1) | (1 << 0));

    /// Returns true if the flags include exact value fingerprinting.
    pub fn has_exact(self) -> bool {
        self.0 & Self::EXACT.0 != 0
    }

    /// Returns true if the flags include trigram fingerprinting.
    pub fn has_trigram(self) -> bool {
        self.0 & Self::TRIGRAM_EXACT.0 == Self::TRIGRAM_EXACT.0
    }
}

/// IndexedDimensions maps dimension names to their indexing strategy.
/// Fields not in this map only get "exists" fingerprints.
/// Initialized once via LazyLock to avoid repeated allocations.
static INDEXED_DIMENSIONS: LazyLock<HashMap<&'static str, IndexFlags>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert("chq_telemetry_type", IndexFlags::TRIGRAM_EXACT);
    m.insert("log_level", IndexFlags::EXACT);
    m.insert("metric_name", IndexFlags::EXACT);
    m.insert("resource_customer_domain", IndexFlags::TRIGRAM_EXACT);
    m.insert("resource_file", IndexFlags::EXACT);
    m.insert("resource_k8s_cluster_name", IndexFlags::TRIGRAM_EXACT);
    m.insert("resource_k8s_namespace_name", IndexFlags::TRIGRAM_EXACT);
    m.insert("resource_service_name", IndexFlags::TRIGRAM_EXACT);
    m.insert("span_trace_id", IndexFlags::TRIGRAM_EXACT);
    m
});

/// Compute the hash of a string using the same algorithm as Go's ComputeHash.
///
/// This is a variant of Java's String.hashCode() but returning i64.
/// It processes 4 bytes at a time for efficiency.
pub fn compute_hash(s: &str) -> i64 {
    let bytes = s.as_bytes();
    let length = bytes.len();
    let mut h: i64 = 0;
    let mut i = 0;

    // Process 4 bytes at a time
    while i + 3 < length {
        // h = 31*31*31*31*h + 31*31*31*b[i] + 31*31*b[i+1] + 31*b[i+2] + b[i+3]
        // Using wrapping operations to match Go's overflow behavior
        h = h
            .wrapping_mul(31 * 31 * 31 * 31)
            .wrapping_add((bytes[i] as i64).wrapping_mul(31 * 31 * 31))
            .wrapping_add((bytes[i + 1] as i64).wrapping_mul(31 * 31))
            .wrapping_add((bytes[i + 2] as i64).wrapping_mul(31))
            .wrapping_add(bytes[i + 3] as i64);
        i += 4;
    }

    // Process remaining bytes
    while i < length {
        h = h.wrapping_mul(31).wrapping_add(bytes[i] as i64);
        i += 1;
    }

    h
}

/// Compute a fingerprint for a field name and value.
///
/// The fingerprint is the hash of "fieldName:value".
pub fn compute_fingerprint(field_name: &str, value: &str) -> i64 {
    let s = format!("{}:{}", field_name, value);
    compute_hash(&s)
}

/// Generate trigrams (3-character substrings) from a UTF-8 string.
///
/// Returns an empty set if the string has fewer than 3 characters.
pub fn to_trigrams(s: &str) -> HashSet<String> {
    let mut trigrams = HashSet::new();
    let chars: Vec<char> = s.chars().collect();

    if chars.len() < 3 {
        return trigrams;
    }

    for i in 0..=chars.len() - 3 {
        let trigram: String = chars[i..i + 3].iter().collect();
        trigrams.insert(trigram);
    }

    trigrams
}

/// Convert a map of tag names to values into a set of fingerprints.
///
/// This matches the Go ToFingerprints function.
pub fn to_fingerprints(tag_values_by_name: &HashMap<String, HashSet<String>>) -> HashSet<i64> {
    let mut fingerprints = HashSet::new();
    let indexed = &*INDEXED_DIMENSIONS;

    for (tag_name, values) in tag_values_by_name {
        // Always add "exists" fingerprint for every field
        fingerprints.insert(compute_fingerprint(tag_name, EXISTS_REGEX));

        // Check if this field is indexed
        let flags = match indexed.get(tag_name.as_str()) {
            Some(f) => *f,
            None => continue,
        };

        for value in values {
            // Add exact value fingerprint if configured
            if flags.has_exact() {
                fingerprints.insert(compute_fingerprint(tag_name, value));
            }

            // Add trigram fingerprints if configured
            if flags.has_trigram() {
                for trigram in to_trigrams(value) {
                    fingerprints.insert(compute_fingerprint(tag_name, &trigram));
                }
            }
        }
    }

    fingerprints
}

/// Generate fingerprints for a span row's fields.
///
/// This is the main entry point for trace fingerprinting.
pub fn generate_span_fingerprints(
    resource_attrs: &[(String, String)],
    scope_attrs: &[(String, String)],
    span_attrs: &[(String, String)],
    chq_telemetry_type: &str,
    span_trace_id: &str,
) -> Vec<i64> {
    let mut tag_values_by_name: HashMap<String, HashSet<String>> = HashMap::new();

    // Add chq_telemetry_type
    tag_values_by_name
        .entry("chq_telemetry_type".to_string())
        .or_default()
        .insert(chq_telemetry_type.to_string());

    // Add span_trace_id
    if !span_trace_id.is_empty() {
        tag_values_by_name
            .entry("span_trace_id".to_string())
            .or_default()
            .insert(span_trace_id.to_string());
    }

    // Process resource attributes
    for (key, value) in resource_attrs {
        if !value.is_empty() {
            tag_values_by_name
                .entry(key.clone())
                .or_default()
                .insert(value.clone());
        }
    }

    // Process scope attributes
    for (key, value) in scope_attrs {
        if !value.is_empty() {
            tag_values_by_name
                .entry(key.clone())
                .or_default()
                .insert(value.clone());
        }
    }

    // Process span attributes
    for (key, value) in span_attrs {
        if !value.is_empty() {
            tag_values_by_name
                .entry(key.clone())
                .or_default()
                .insert(value.clone());
        }
    }

    let fps = to_fingerprints(&tag_values_by_name);
    let mut result: Vec<i64> = fps.into_iter().collect();
    result.sort();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from Go implementation
    #[test]
    fn test_compute_hash_known_values() {
        // These values must match the Go implementation exactly
        assert_eq!(compute_hash(""), 0);
        assert_eq!(compute_hash("a"), 97);
        assert_eq!(compute_hash("ab"), 3105);
        assert_eq!(compute_hash("abc"), 96354);
        assert_eq!(compute_hash("abcd"), 2987074);
        assert_eq!(compute_hash("hello"), 99162322);
        assert_eq!(compute_hash("hello world"), 88006926820958916);
    }

    #[test]
    fn test_compute_fingerprint_known_values() {
        // These values must match the Go implementation exactly
        assert_eq!(
            compute_fingerprint("resource_service_name", ".*"),
            -7421396210046370992
        );
        assert_eq!(
            compute_fingerprint("resource_service_name", "test-service"),
            921231586932607246
        );
        assert_eq!(
            compute_fingerprint("chq_telemetry_type", "traces"),
            5341645454625328437
        );
        assert_eq!(
            compute_fingerprint("span_trace_id", ".*"),
            5450394539053759372
        );
        assert_eq!(
            compute_fingerprint("chq_telemetry_type", ".*"),
            5113163176687986339
        );
    }

    #[test]
    fn test_to_trigrams() {
        // Empty and short strings
        assert!(to_trigrams("").is_empty());
        assert!(to_trigrams("a").is_empty());
        assert!(to_trigrams("ab").is_empty());

        // Exactly 3 chars
        let tri3 = to_trigrams("abc");
        assert_eq!(tri3.len(), 1);
        assert!(tri3.contains("abc"));

        // 4 chars
        let tri4 = to_trigrams("abcd");
        assert_eq!(tri4.len(), 2);
        assert!(tri4.contains("abc"));
        assert!(tri4.contains("bcd"));

        // 5 chars
        let tri5 = to_trigrams("hello");
        assert_eq!(tri5.len(), 3);
        assert!(tri5.contains("hel"));
        assert!(tri5.contains("ell"));
        assert!(tri5.contains("llo"));

        // More complex string
        let tri_svc = to_trigrams("test-service");
        assert_eq!(tri_svc.len(), 10);
        assert!(tri_svc.contains("tes"));
        assert!(tri_svc.contains("est"));
        assert!(tri_svc.contains("st-"));
        assert!(tri_svc.contains("t-s"));
        assert!(tri_svc.contains("-se"));
        assert!(tri_svc.contains("ser"));
        assert!(tri_svc.contains("erv"));
        assert!(tri_svc.contains("rvi"));
        assert!(tri_svc.contains("vic"));
        assert!(tri_svc.contains("ice"));
    }

    #[test]
    fn test_to_fingerprints_trace_data() {
        // Replicate the Go test case
        let mut tag_values_by_name: HashMap<String, HashSet<String>> = HashMap::new();

        // Indexed fields
        let mut service_names = HashSet::new();
        service_names.insert("test-service".to_string());
        service_names.insert("api-gateway".to_string());
        tag_values_by_name.insert("resource_service_name".to_string(), service_names);

        let mut namespace_names = HashSet::new();
        namespace_names.insert("production".to_string());
        tag_values_by_name.insert("resource_k8s_namespace_name".to_string(), namespace_names);

        let mut telemetry_types = HashSet::new();
        telemetry_types.insert("traces".to_string());
        tag_values_by_name.insert("chq_telemetry_type".to_string(), telemetry_types);

        let mut trace_ids = HashSet::new();
        trace_ids.insert("abc123".to_string());
        tag_values_by_name.insert("span_trace_id".to_string(), trace_ids);

        // Non-indexed fields (only get exists fingerprints)
        let mut span_names = HashSet::new();
        span_names.insert("GET /api/users".to_string());
        tag_values_by_name.insert("span_name".to_string(), span_names);

        let mut span_durations = HashSet::new();
        span_durations.insert("50".to_string());
        tag_values_by_name.insert("span_duration".to_string(), span_durations);

        let fingerprints = to_fingerprints(&tag_values_by_name);

        // Should have 46 fingerprints (matching Go output)
        assert_eq!(fingerprints.len(), 46, "Expected 46 fingerprints");

        // Verify specific exists fingerprints
        assert!(fingerprints.contains(&compute_fingerprint("resource_service_name", ".*")));
        assert!(fingerprints.contains(&compute_fingerprint(
            "resource_k8s_namespace_name",
            ".*"
        )));
        assert!(fingerprints.contains(&compute_fingerprint("chq_telemetry_type", ".*")));
        assert!(fingerprints.contains(&compute_fingerprint("span_trace_id", ".*")));
        assert!(fingerprints.contains(&compute_fingerprint("span_name", ".*")));
        assert!(fingerprints.contains(&compute_fingerprint("span_duration", ".*")));

        // Verify specific value fingerprints
        assert!(fingerprints.contains(&compute_fingerprint(
            "resource_service_name",
            "test-service"
        )));
        assert!(fingerprints.contains(&compute_fingerprint(
            "resource_service_name",
            "api-gateway"
        )));
        assert!(fingerprints.contains(&compute_fingerprint("chq_telemetry_type", "traces")));

        // Convert to sorted vec and compare with Go output
        let mut fps_vec: Vec<i64> = fingerprints.into_iter().collect();
        fps_vec.sort();

        // Expected values from Go test
        let expected: Vec<i64> = vec![
            -9003346288533732963,
            -8702353626922880333,
            -8702353626922879957,
            -8702353626922830074,
            -8702353626922829954,
            -8702353626922826155,
            -8702353626922826126,
            -8702353626922826021,
            -8702353626922824762,
            -8702353626922824465,
            -8702353626922822793,
            -8702353626922815936,
            -8702353626922813882,
            -8702353626922813551,
            -8702353626922813108,
            -8702353626922812712,
            -8702353626922812146,
            -8702353626922812142,
            -8702353626922810116,
            -8702353626922809381,
            -7512638186058337156,
            -7512638186058335158,
            -7512638186058320883,
            -7512638186058318436,
            -7421396210046370992,
            -3489059281346167910,
            -2402573838902394281,
            -2402573838902393295,
            -2402573838902388665,
            -2402573838902383233,
            -2402573838902381844,
            -2402573838902380026,
            -2402573838902378279,
            -2402573838902377499,
            921231586932607246,
            2941534047280579170,
            2941534047280626834,
            2941534047280627188,
            2941534047280627776,
            2989705917235296893,
            3016434386796611862,
            5113163176687986339,
            5341645454625328437,
            5437374263055642605,
            5450394539053759372,
            9206452416783884384,
        ];

        assert_eq!(fps_vec, expected, "Fingerprints should match Go output exactly");
    }

    #[test]
    fn test_index_flags() {
        assert!(IndexFlags::EXACT.has_exact());
        assert!(!IndexFlags::EXACT.has_trigram());

        assert!(IndexFlags::TRIGRAM_EXACT.has_exact());
        assert!(IndexFlags::TRIGRAM_EXACT.has_trigram());
    }
}
