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

//! Log fingerprinting for semantic log grouping.
//!
//! This module implements log fingerprinting compatible with the Go implementation
//! in lakerunner/internal/oteltools/pkg/fingerprinter.
//!
//! The fingerprinter:
//! 1. Tokenizes log messages into semantic tokens
//! 2. Replaces variable parts with placeholders
//! 3. Generates a hash fingerprint from the token sequence
//!
//! Similar log messages (with different variable values) produce the same fingerprint.

pub mod cluster;
pub mod json;
pub mod tokenizer;
pub mod wordlist;

#[cfg(test)]
mod compatibility_tests;

#[cfg(test)]
mod cluster_tests;

use once_cell::sync::Lazy;
use regex::Regex;
use xxhash_rust::xxh64::xxh64;

use crate::log_fingerprint::json::{deep_keys, find_json_content, get_string_key, parse_json};
use crate::log_fingerprint::tokenizer::{tokenize, TokenType, LOG_LEVEL_NAMES};
use crate::log_fingerprint::wordlist::is_word;

/// Placeholder for log level in fingerprint.
pub const LOG_LEVEL_PLACEHOLDER: &str = "<Loglevel>";
/// Placeholder for identifiers in fingerprint.
pub const IDENTIFIER_PLACEHOLDER: &str = "<Identifier>";

/// Result of fingerprinting a log message.
#[derive(Debug, Clone)]
pub struct FingerprintResult {
    /// The fingerprint value (xxhash of token sequence).
    pub fingerprint: i64,
    /// Detected log level (lowercase), if any.
    pub level: String,
    /// JSON keys found in the message, if JSON was detected.
    pub json_keys: Option<Vec<String>>,
}

/// Log fingerprinter with configurable max tokens.
pub struct Fingerprinter {
    max_tokens: usize,
}

impl Default for Fingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

impl Fingerprinter {
    /// Create a new fingerprinter with default settings (15 max tokens).
    pub fn new() -> Self {
        Self { max_tokens: 15 }
    }

    /// Create a fingerprinter with custom max tokens.
    pub fn with_max_tokens(max_tokens: usize) -> Self {
        Self { max_tokens }
    }

    /// Fingerprint a log message.
    ///
    /// Returns the fingerprint, detected log level, and any JSON keys found.
    pub fn fingerprint(&self, input: &str) -> Result<FingerprintResult, String> {
        let (token_seq, level, json_keys) = self.tokenize_input(input)?;

        let fingerprint = if json_keys.is_some() {
            self.fingerprint_items_and_json_keys(&token_seq, json_keys.as_ref().unwrap())
        } else {
            self.fingerprint_items(&token_seq)
        };

        Ok(FingerprintResult {
            fingerprint,
            level,
            json_keys,
        })
    }

    /// Tokenize input into a sequence of normalized tokens.
    ///
    /// Returns (token_sequence, log_level, json_keys).
    /// This is exposed for testing purposes.
    pub fn tokenize_input(&self, input: &str) -> Result<(Vec<String>, String, Option<Vec<String>>), String> {
        // Pre-process: trim and remove ANSI codes
        let input = input.trim();
        let input = remove_ansi_codes(input);

        // Try to extract JSON content
        let json_content = find_json_content(&input);
        if !json_content.json.is_empty() {
            if let Some(data) = parse_json(&json_content.json) {
                // Extract message and level from JSON
                let message = get_string_key(&data, &["message", "msg"]).unwrap_or_default();
                let mut level = get_string_key(&data, &["level", "loglevel"]).unwrap_or_default().to_lowercase();

                // Validate level
                if !LOG_LEVEL_NAMES.contains(&level.as_str()) {
                    level = String::new();
                }

                // Combine prefix + level + message + suffix for tokenization
                let combined = format!("{} {} {} {}", json_content.prefix, level, message, json_content.suffix);
                let (tokens, detected_level) = self.tokenize_string(&combined)?;

                // Use JSON level if we found one, otherwise use detected level
                let final_level = if level.is_empty() { detected_level } else { level };

                // Get JSON keys
                let json_keys = deep_keys(&data);

                return Ok((tokens, final_level, Some(json_keys)));
            }
        }

        // Truncate at first newline
        let input = if let Some(pos) = input.find(|c| c == '\n' || c == '\r') {
            &input[..pos]
        } else {
            &input
        };

        let (tokens, level) = self.tokenize_string(input)?;
        Ok((tokens, level, None))
    }

    /// Tokenize a string into normalized token items.
    fn tokenize_string(&self, input: &str) -> Result<(Vec<String>, String), String> {
        // Split quoted strings first
        let (processed, quoted_strings) = split_quoted_strings(input);

        let raw_tokens = tokenize(&processed);

        let mut items = Vec::new();
        let mut level = String::new();
        let mut quoted_idx = 0;

        for token in raw_tokens {
            if items.len() >= self.max_tokens {
                break;
            }

            match token.token_type {
                TokenType::QuotedString => {
                    if quoted_idx < quoted_strings.len() {
                        items.push("<QuotedString>".to_string());
                        quoted_idx += 1;
                    }
                }
                TokenType::List => {
                    let placeholder_count = token.literal.matches("quotedstringplaceholder").count();
                    if quoted_idx + placeholder_count <= quoted_strings.len() {
                        items.push("<List>".to_string());
                        quoted_idx += placeholder_count;
                    }
                }
                TokenType::Loglevel => {
                    if level.is_empty() {
                        level = token.literal.to_lowercase();
                        items.push(LOG_LEVEL_PLACEHOLDER.to_string());
                    } else {
                        items.push(token.literal.to_lowercase());
                    }
                }
                TokenType::Identifier => {
                    let lower = token.literal.to_lowercase();
                    // Check if it's actually a log level
                    if level.is_empty() && LOG_LEVEL_NAMES.contains(&lower.as_str()) {
                        level = lower;
                        items.push(LOG_LEVEL_PLACEHOLDER.to_string());
                        continue;
                    }
                    // Check if it's an English word
                    if is_word(&token.literal) {
                        items.push(lower);
                        continue;
                    }
                    // Collapse consecutive identifiers
                    if items.last().map(|s| s.as_str()) != Some(IDENTIFIER_PLACEHOLDER) {
                        items.push(IDENTIFIER_PLACEHOLDER.to_string());
                    }
                }
                TokenType::String => {
                    // Only keep if it's a word
                    if is_word(&token.literal) {
                        items.push(token.literal.to_lowercase());
                    }
                }
                _ => {
                    // Use the placeholder for this token type
                    items.push(token.token_type.placeholder().to_string());
                }
            }
        }

        Ok((items, level.to_lowercase()))
    }

    /// Compute fingerprint from token items.
    fn fingerprint_items(&self, items: &[String]) -> i64 {
        let combined = items.join(":");
        xxh64(combined.as_bytes(), 0) as i64
    }

    /// Compute fingerprint from token items and JSON keys.
    fn fingerprint_items_and_json_keys(&self, items: &[String], json_keys: &[String]) -> i64 {
        let mut combined = items.join(":");
        for key in json_keys {
            combined.push(':');
            combined.push_str(key);
        }
        xxh64(combined.as_bytes(), 0) as i64
    }
}

/// Remove ANSI escape codes from a string.
static ANSI_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\x1b\[[0-9;]*m").unwrap()
});

fn remove_ansi_codes(input: &str) -> String {
    ANSI_REGEX.replace_all(input, "").to_string()
}

/// Split a string into literal and quoted parts.
///
/// Returns the string with quoted parts replaced by "quotedstringplaceholder"
/// and a vector of the original quoted strings.
fn split_quoted_strings(input: &str) -> (String, Vec<String>) {
    let mut result = String::new();
    let mut quoted_strings = Vec::new();
    let mut chars = input.chars().peekable();
    let mut in_quote = false;
    let mut quote_char = '"';
    let mut current_quoted = String::new();

    while let Some(c) = chars.next() {
        if !in_quote {
            if c == '"' || c == '\'' {
                in_quote = true;
                quote_char = c;
                current_quoted.clear();
            } else {
                result.push(c);
            }
        } else {
            if c == quote_char {
                // End of quoted string
                in_quote = false;
                quoted_strings.push(current_quoted.clone());
                result.push_str("quotedstringplaceholder");
            } else if c == '\\' {
                // Escape sequence
                current_quoted.push(c);
                if let Some(&next) = chars.peek() {
                    current_quoted.push(next);
                    chars.next();
                }
            } else {
                current_quoted.push(c);
            }
        }
    }

    // Handle unclosed quote
    if in_quote {
        result.push(quote_char);
        result.push_str(&current_quoted);
    }

    (result, quoted_strings)
}

/// Convenience function to fingerprint a log message with default settings.
pub fn fingerprint(input: &str) -> Result<FingerprintResult, String> {
    Fingerprinter::new().fingerprint(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_empty() {
        let result = fingerprint("").unwrap();
        assert_eq!(result.level, "");
    }

    #[test]
    fn test_fingerprint_simple() {
        let fp = Fingerprinter::new();
        let result = fp.fingerprint("hello world").unwrap();
        assert_eq!(result.level, "");
    }

    #[test]
    fn test_remove_ansi_codes() {
        let input = "\x1b[1m\x1b[36mHello\x1b[0m World";
        assert_eq!(remove_ansi_codes(input), "Hello World");
    }

    #[test]
    fn test_split_quoted_strings() {
        let (result, quoted) = split_quoted_strings(r#"Hello "world" test"#);
        assert_eq!(result, "Hello quotedstringplaceholder test");
        assert_eq!(quoted, vec!["world"]);
    }

    #[test]
    fn test_split_quoted_strings_multiple() {
        let (result, quoted) = split_quoted_strings(r#""a" and "b""#);
        assert_eq!(result, "quotedstringplaceholder and quotedstringplaceholder");
        assert_eq!(quoted, vec!["a", "b"]);
    }

    // Test cases matching Go implementation
    #[test]
    fn test_tokenize_date() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input("2024-01-02").unwrap();
        assert_eq!(tokens, vec!["<Date>"]);
        assert_eq!(level, "");
    }

    #[test]
    fn test_tokenize_time() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input("14:54:12").unwrap();
        assert_eq!(tokens, vec!["<Time>"]);
        assert_eq!(level, "");
    }

    #[test]
    fn test_tokenize_iso8601() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input("2024-01-02T14:54:12").unwrap();
        assert_eq!(tokens, vec!["<ISO8601>"]);
        assert_eq!(level, "");
    }

    #[test]
    fn test_tokenize_uuid() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input("dddddddd-dddd-dddd-dddd-dddddddddddd").unwrap();
        assert_eq!(tokens, vec!["<UUID>"]);
        assert_eq!(level, "");
    }

    #[test]
    fn test_tokenize_ipv4() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input("10.42.255.254").unwrap();
        assert_eq!(tokens, vec!["<IPv4>"]);
        assert_eq!(level, "");
    }

    #[test]
    fn test_tokenize_email() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input("alice@example.com").unwrap();
        assert_eq!(tokens, vec!["<Email>"]);
        assert_eq!(level, "");
    }

    #[test]
    fn test_tokenize_fqdn() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input("example.com").unwrap();
        assert_eq!(tokens, vec!["<FQDN>"]);
        assert_eq!(level, "");
    }

    #[test]
    fn test_tokenize_path() {
        let fp = Fingerprinter::new();
        let (tokens, level, _) = fp.tokenize_input(" /api/v10/endpoint").unwrap();
        assert_eq!(tokens, vec!["<Path>"]);
        assert_eq!(level, "");
    }
}
