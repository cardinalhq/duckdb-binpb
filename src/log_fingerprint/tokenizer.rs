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

//! Log tokenizer for fingerprinting.
//!
//! This module implements tokenization compatible with the Go implementation
//! in oteltools/pkg/fingerprinter/tokenizer.

use once_cell::sync::Lazy;
use regex::Regex;

/// Token types matching the Go implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    Identifier,
    String,
    Url,
    Duration,
    Date,
    Time,
    Number,
    Bool,
    Loglevel,
    IPv4,
    HttpMethod,
    Uuid,
    Email,
    Path,
    Fqdn,
    Iso8601,
    ModuleName,
    QuotedString,
    List,
}

impl TokenType {
    /// Get the placeholder string for this token type.
    pub fn placeholder(&self) -> &'static str {
        match self {
            TokenType::Identifier => "<Identifier>",
            TokenType::String => "", // Strings are kept as-is (lowercased)
            TokenType::Url => "<Url>",
            TokenType::Duration => "<Duration>",
            TokenType::Date => "<Date>",
            TokenType::Time => "<Time>",
            TokenType::Number => "<Number>",
            TokenType::Bool => "<Bool>",
            TokenType::Loglevel => "<Loglevel>",
            TokenType::IPv4 => "<IPv4>",
            TokenType::HttpMethod => "<HTTPMethod>",
            TokenType::Uuid => "<UUID>",
            TokenType::Email => "<Email>",
            TokenType::Path => "<Path>",
            TokenType::Fqdn => "<FQDN>",
            TokenType::Iso8601 => "<ISO8601>",
            TokenType::ModuleName => "<ModuleName>",
            TokenType::QuotedString => "<QuotedString>",
            TokenType::List => "<List>",
        }
    }
}

/// A parsed token with its type and literal value.
#[derive(Debug, Clone)]
pub struct Token {
    pub token_type: TokenType,
    pub literal: String,
}

/// Log level names (lowercase).
pub const LOG_LEVEL_NAMES: &[&str] = &["trace", "debug", "info", "warn", "error", "fatal", "panic"];

// Regex patterns for complex token matching
// These are compiled once and reused

static ISO8601_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z| ?[+-]\d{2}:?\d{2})?").unwrap()
});

static UUID_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[{(\[]?[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}[})\]]?").unwrap()
});

static IPV4_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d{1,5})?").unwrap()
});

static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_][a-zA-Z0-9_.+\-]*@[a-zA-Z0-9][a-zA-Z0-9_\-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9_\-]*)+").unwrap()
});

static URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]*://(?:[a-zA-Z0-9_]*:[a-zA-Z0-9_]*@)?(?:[a-zA-Z][a-zA-Z0-9_\-]*(?:\.[a-zA-Z][a-zA-Z0-9_\-]*)*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?(?::\d{1,5})?(?:/[a-zA-Z0-9_]*)*").unwrap()
});

static FQDN_REGEX: Lazy<Regex> = Lazy::new(|| {
    // FQDN: each label must be at least 2 chars (letter + alphanumeric+)
    // This prevents "c.g.d.Something" from matching as FQDN
    Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]+(?:[-_][a-zA-Z0-9_]+)*(?:\.[a-zA-Z_][a-zA-Z0-9_]+(?:[-_][a-zA-Z0-9_]+)*)+").unwrap()
});

static PATH_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:/[a-zA-Z0-9_.@:~+=&?!*\[\]{}<>;$|\-]+(?:%[0-9a-fA-F]{2})*)+/?").unwrap()
});

static DATE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:\d{4}|\d{2})[-/](?:\d{2}|jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[-/]\d{2}").unwrap()
});

static TIME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\d{2}[:.]\d{2}[:.]\d{2}(?:[.,]\d{1,9})?").unwrap()
});

static DURATION_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Duration must be followed by non-alphanumeric (word boundary)
    // This prevents matching "12ms" in "12msap"
    Regex::new(r"^[\d.]+\s*(?:ns|nano|nanos|nanosecond|us|micro|microsecond|ms|mil|mils|milli|millis|millisecond|milliseconds|s|sec|secs|second|seconds|min|mins|minute|minutes|hour|hours|day|days|week|weeks|mon|month|months|year|years)(?:s|\(s\))?(?:[^a-zA-Z0-9]|$)").unwrap()
});

static NUMBER_REGEX: Lazy<Regex> = Lazy::new(|| {
    // All alternatives must be anchored - wrap in group so ^ applies to all
    Regex::new(r"^(?:\d+(?:\.\d+)?|\.\d+|\d+\.)").unwrap()
});

static GO_MODULE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*@[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9_.@:~+=&?!*\[\]{}<>;$|\-]+)+:\d+").unwrap()
});

static HTTP_METHOD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?i:GET|POST|PUT|DELETE|HEAD|PATCH)").unwrap()
});

static LOG_LEVEL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?i:TRACE|DEBUG|INFO|WARN|ERROR|FATAL|PANIC):?").unwrap()
});

static IDENTIFIER_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9_.@:\-]{4,}:?").unwrap()
});

static BASE64_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9+/=]{20,}").unwrap()
});

static WORD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*").unwrap()
});

static LIST_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[\[({]\s*quotedstringplaceholder(?:\s*,\s*quotedstringplaceholder)*\s*[\])}]").unwrap()
});

static QUOTED_PLACEHOLDER_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^quotedstringplaceholder").unwrap()
});

/// Tokenize a log message string.
///
/// Returns a vector of tokens. This matches the Go tokenizer behavior.
pub fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut pos = 0;

    while pos < input.len() {
        // Skip whitespace and punctuation
        if let Some(skip_len) = skip_chars(&input[pos..]) {
            pos += skip_len;
            continue;
        }

        // Try to match tokens in priority order (matching Go's ragel order)
        if let Some((token, len)) = try_match_token(&input[pos..]) {
            tokens.push(token);
            pos += len;
        } else {
            // Skip single character if no match
            pos += 1;
        }
    }

    tokens
}

/// Skip whitespace, control characters, and punctuation.
fn skip_chars(input: &str) -> Option<usize> {
    let mut len = 0;
    for c in input.chars() {
        if c.is_whitespace() || c.is_control() || is_skip_punct(c) {
            len += c.len_utf8();
        } else {
            break;
        }
    }
    if len > 0 { Some(len) } else { None }
}

fn is_skip_punct(c: char) -> bool {
    matches!(c, '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' |
             '.' | ',' | ';' | ':' | '!' | '?' | '"' | '\'' | '*' |
             '-' | '_' | '@' | '#' | '$' | '%' | '&' | '^' | '|' |
             '~' | '`' | '+' | '=' | '\\')
}

/// Try to match a token at the current position.
/// Returns the token and the number of bytes consumed.
fn try_match_token(input: &str) -> Option<(Token, usize)> {
    // Order matters - try most specific patterns first

    // Quoted string placeholder (must be before identifier)
    if let Some(m) = QUOTED_PLACEHOLDER_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::QuotedString,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // List (must be early)
    if let Some(m) = LIST_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::List,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // ISO8601 (before date/time)
    if let Some(m) = ISO8601_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::Iso8601,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // Go module (before path)
    if let Some(m) = GO_MODULE_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::ModuleName,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // UUID (before identifier)
    if let Some(m) = UUID_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::Uuid,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // URL (before fqdn)
    if let Some(m) = URL_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::Url,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // Email (before fqdn)
    if let Some(m) = EMAIL_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::Email,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // Path (before fqdn)
    if input.starts_with('/') {
        if let Some(m) = PATH_REGEX.find(input) {
            return Some((Token {
                token_type: TokenType::Path,
                literal: m.as_str().to_string(),
            }, m.end()));
        }
    }

    // IPv4 (before time/date/number - important because IP looks like time)
    if let Some(m) = IPV4_REGEX.find(input) {
        // Validate it's a real IP (not just numbers with dots)
        let s = m.as_str();
        // Split only on dots for validation (port comes after colon)
        let ip_part = s.split(':').next().unwrap_or(s);
        let parts: Vec<&str> = ip_part.split('.').collect();
        if parts.len() == 4 {
            let valid = parts.iter().all(|p| {
                p.parse::<u32>().map(|n| n <= 255).unwrap_or(false)
            });
            if valid {
                return Some((Token {
                    token_type: TokenType::IPv4,
                    literal: s.to_string(),
                }, m.end()));
            }
        }
    }

    // Time (before number, but after iso8601 and ipv4)
    if let Some(m) = TIME_REGEX.find(input) {
        // Only match if it looks like a time (starts with digits and colon pattern)
        let s = m.as_str();
        if s.len() >= 8 && (s.as_bytes()[2] == b':' || s.as_bytes()[2] == b'.') {
            return Some((Token {
                token_type: TokenType::Time,
                literal: s.to_string(),
            }, m.end()));
        }
    }

    // Date (before number)
    if let Some(m) = DATE_REGEX.find(&input.to_lowercase()) {
        return Some((Token {
            token_type: TokenType::Date,
            literal: input[..m.end()].to_string(),
        }, m.end()));
    }

    // Duration (before number)
    if let Some(m) = DURATION_REGEX.find(&input.to_lowercase()) {
        // The regex includes a trailing boundary check, so we need to exclude it from the match
        let matched = m.as_str();
        let actual_len = if matched.ends_with(|c: char| !c.is_alphanumeric()) {
            m.end() - 1
        } else {
            m.end()
        };
        if actual_len > 0 {
            return Some((Token {
                token_type: TokenType::Duration,
                literal: input[..actual_len].to_string(),
            }, actual_len));
        }
    }

    // FQDN (before identifier)
    if let Some(m) = FQDN_REGEX.find(input) {
        let s = m.as_str();
        // Must have at least one dot and valid TLD pattern
        if s.contains('.') && !s.ends_with('.') {
            return Some((Token {
                token_type: TokenType::Fqdn,
                literal: s.to_string(),
            }, m.end()));
        }
    }

    // Number - but check if there's a longer identifier match first
    // (ragel uses longest-match semantics)
    if let Some(num_match) = NUMBER_REGEX.find(input) {
        // Check if identifier would match longer
        if let Some(id_match) = IDENTIFIER_REGEX.find(input) {
            if id_match.end() > num_match.end() {
                // Identifier is longer, skip number matching here
                // (will be handled by identifier case below)
            } else {
                return Some((Token {
                    token_type: TokenType::Number,
                    literal: num_match.as_str().to_string(),
                }, num_match.end()));
            }
        } else {
            return Some((Token {
                token_type: TokenType::Number,
                literal: num_match.as_str().to_string(),
            }, num_match.end()));
        }
    }

    // Log level
    if let Some(m) = LOG_LEVEL_REGEX.find(input) {
        let mut s = m.as_str();
        // Remove trailing colon if present
        if s.ends_with(':') {
            s = &s[..s.len()-1];
        }
        return Some((Token {
            token_type: TokenType::Loglevel,
            literal: s.to_string(),
        }, m.end()));
    }

    // HTTP method
    if let Some(m) = HTTP_METHOD_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::HttpMethod,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // Base64 (long alphanumeric sequences)
    if let Some(m) = BASE64_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::Identifier,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    // Identifier (4+ chars with special chars)
    if let Some(m) = IDENTIFIER_REGEX.find(input) {
        let mut s = m.as_str();
        // Remove trailing colon if present
        if s.ends_with(':') {
            s = &s[..s.len()-1];
        }
        return Some((Token {
            token_type: TokenType::Identifier,
            literal: s.to_string(),
        }, m.end()));
    }

    // Word/String (alphanumeric)
    if let Some(m) = WORD_REGEX.find(input) {
        return Some((Token {
            token_type: TokenType::String,
            literal: m.as_str().to_string(),
        }, m.end()));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso8601() {
        let tokens = tokenize("2024-01-02T14:54:12");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Iso8601);
    }

    #[test]
    fn test_iso8601_with_z() {
        let tokens = tokenize("2024-01-02T14:54:12Z");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Iso8601);
    }

    #[test]
    fn test_uuid() {
        let tokens = tokenize("dddddddd-dddd-dddd-dddd-dddddddddddd");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Uuid);
    }

    #[test]
    fn test_ipv4() {
        let tokens = tokenize("10.42.255.254");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::IPv4);
    }

    #[test]
    fn test_email() {
        let tokens = tokenize("alice@example.com");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Email);
    }

    #[test]
    fn test_path() {
        let tokens = tokenize(" /api/v10/endpoint");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Path);
    }

    #[test]
    fn test_date() {
        let tokens = tokenize("2024-01-02");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Date);
    }

    #[test]
    fn test_time() {
        let tokens = tokenize("14:54:12");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Time);
    }

    #[test]
    fn test_fqdn() {
        let tokens = tokenize("example.com");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_type, TokenType::Fqdn);
    }

    #[test]
    fn test_simple_words() {
        let tokens = tokenize("hello world");
        assert_eq!(tokens.len(), 2);
        // Note: "hello" (5 chars) matches identifier pattern (4+ chars)
        // The fingerprinter will check IsWord() and handle it appropriately
        assert_eq!(tokens[0].literal, "hello");
        assert_eq!(tokens[1].literal, "world");
    }
}
