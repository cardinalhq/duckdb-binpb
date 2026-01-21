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

//! JSON extraction utilities for log fingerprinting.
//!
//! This module handles extraction of JSON content from log messages,
//! matching the Go implementation in fingerprinter.go.

use serde_json::Value;

/// Result of finding JSON content in a string.
#[derive(Debug, Default)]
pub struct JsonContent {
    pub prefix: String,
    pub json: String,
    pub suffix: String,
}

/// Find JSON content in a string using balanced brace counting.
///
/// Returns the prefix before JSON, the JSON content, and the suffix after.
/// If no valid JSON object is found, returns empty strings.
/// Handles nested braces and braces within string literals correctly.
pub fn find_json_content(input: &str) -> JsonContent {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut idx = 0;

    while idx < len {
        // Look for the next potential JSON object start
        if bytes[idx] != b'{' {
            idx += 1;
            continue;
        }

        let start = idx;
        let mut brace_depth: i32 = 0;
        let mut in_string = false;
        let mut escape = false;
        let mut end: Option<usize> = None;

        let mut j = start;
        while j < len {
            let c = bytes[j];

            if in_string {
                if escape {
                    escape = false;
                } else if c == b'\\' {
                    escape = true;
                } else if c == b'"' {
                    in_string = false;
                }
            } else {
                match c {
                    b'"' => in_string = true,
                    b'{' => brace_depth += 1,
                    b'}' => {
                        brace_depth -= 1;
                        if brace_depth == 0 {
                            end = Some(j);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            j += 1;
        }

        if let Some(end_idx) = end {
            // Verify it's valid JSON by attempting to parse
            let candidate = &input[start..=end_idx];
            if serde_json::from_str::<Value>(candidate).is_ok() {
                return JsonContent {
                    prefix: input[..start].to_string(),
                    json: candidate.to_string(),
                    suffix: input[end_idx + 1..].to_string(),
                };
            }
        }

        // Move past this '{' and look for the next candidate
        idx = start + 1;
    }

    JsonContent::default()
}

/// Look up a key in a nested JSON object, searching recursively.
fn lookup_key<'a>(obj: &'a Value, key: &str) -> Option<&'a str> {
    match obj {
        Value::Object(map) => {
            // Check direct key first
            if let Some(val) = map.get(key) {
                if let Some(s) = val.as_str() {
                    return Some(s);
                }
            }
            // Search nested objects
            for (_, v) in map {
                if let Some(result) = lookup_key(v, key) {
                    return Some(result);
                }
            }
            None
        }
        _ => None,
    }
}

/// Get a string value from JSON, trying multiple possible keys.
pub fn get_string_key(obj: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(val) = lookup_key(obj, key) {
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Extract all keys from a JSON object recursively, with dot-separated paths.
pub fn deep_keys(obj: &Value) -> Vec<String> {
    let mut keys = Vec::new();
    collect_keys(obj, "", &mut keys);
    keys.sort();
    keys
}

fn collect_keys(obj: &Value, prefix: &str, keys: &mut Vec<String>) {
    if let Value::Object(map) = obj {
        for (k, v) in map {
            let full_key = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{}.{}", prefix, k)
            };

            match v {
                Value::Object(_) => {
                    // Recurse into nested objects
                    collect_keys(v, &full_key, keys);
                }
                _ => {
                    keys.push(full_key);
                }
            }
        }
    }
}

/// Parse JSON, also trying Ruby hash syntax (=> instead of :).
pub fn parse_json(input: &str) -> Option<Value> {
    // Try standard JSON first
    if let Ok(val) = serde_json::from_str(input) {
        return Some(val);
    }

    // Try Ruby hash syntax (replace => with :)
    let ruby_fixed = input.replace("=>", ":");
    serde_json::from_str(&ruby_fixed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_json_content_no_json() {
        let result = find_json_content("Hello, world!");
        assert!(result.json.is_empty());
    }

    #[test]
    fn test_find_json_content_with_prefix_and_suffix() {
        let result = find_json_content(r#"Message: {"key": "value"} Extra"#);
        assert_eq!(result.prefix, "Message: ");
        assert_eq!(result.json, r#"{"key": "value"}"#);
        assert_eq!(result.suffix, " Extra");
    }

    #[test]
    fn test_find_json_content_json_only() {
        let result = find_json_content(r#"{"key": "value"}"#);
        assert!(result.prefix.is_empty());
        assert_eq!(result.json, r#"{"key": "value"}"#);
        assert!(result.suffix.is_empty());
    }

    #[test]
    fn test_find_json_content_nested() {
        let result = find_json_content(r#"Message: {"key": {"nested": "value"}} Extra"#);
        assert_eq!(result.prefix, "Message: ");
        assert_eq!(result.json, r#"{"key": {"nested": "value"}}"#);
        assert_eq!(result.suffix, " Extra");
    }

    #[test]
    fn test_get_string_key() {
        let json: Value = serde_json::from_str(r#"{"message": "Hello", "level": "INFO"}"#).unwrap();
        assert_eq!(get_string_key(&json, &["message"]), Some("Hello".to_string()));
        assert_eq!(get_string_key(&json, &["level"]), Some("INFO".to_string()));
        assert_eq!(get_string_key(&json, &["nonexistent"]), None);
    }

    #[test]
    fn test_get_string_key_multiple_keys() {
        let json: Value = serde_json::from_str(r#"{"msg": "Hello"}"#).unwrap();
        assert_eq!(get_string_key(&json, &["message", "msg"]), Some("Hello".to_string()));
    }

    #[test]
    fn test_deep_keys() {
        let json: Value = serde_json::from_str(r#"{"a": 1, "b": {"c": 2, "d": {"e": 3}}}"#).unwrap();
        let keys = deep_keys(&json);
        assert_eq!(keys, vec!["a", "b.c", "b.d.e"]);
    }

    #[test]
    fn test_parse_json_standard() {
        let result = parse_json(r#"{"key": "value"}"#);
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_json_ruby() {
        let result = parse_json(r#"{"key" => "value"}"#);
        assert!(result.is_some());
    }
}
