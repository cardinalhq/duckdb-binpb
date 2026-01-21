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

//! English word list for log fingerprinting.
//!
//! Words are used to distinguish meaningful tokens from identifiers.

use once_cell::sync::Lazy;
use std::collections::HashSet;

/// The raw word list embedded at compile time.
static WORDS_DATA: &str = include_str!("english_words.txt");

/// Set of English words for O(1) lookup.
pub static ENGLISH_WORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    WORDS_DATA.lines().collect()
});

/// Check if a word is in the English dictionary.
pub fn is_english_word(word: &str) -> bool {
    ENGLISH_WORDS.contains(word.to_lowercase().as_str())
}

/// Check if a string is a valid "word" according to the fingerprinter rules.
///
/// This matches the Go IsWord implementation:
/// - If the word exists in the dictionary, return true
/// - If the word is mixed case (camelCase or PascalCase), split and check each part
/// - If all parts are words, return true
pub fn is_word(word: &str) -> bool {
    let lower = word.to_lowercase();

    // Direct dictionary lookup
    if ENGLISH_WORDS.contains(lower.as_str()) {
        return true;
    }

    // If entirely uppercase or lowercase, it must fully match
    if word == word.to_uppercase() || word == word.to_lowercase() {
        return false;
    }

    // Try splitting camelCase/PascalCase
    let parts = split_words(word);
    if parts.is_empty() {
        return false;
    }

    parts.iter().all(|part| is_word(part))
}

/// Split a word by camelCase and snake_case boundaries.
///
/// This matches the Go splitWords implementation.
pub fn split_words(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = input.chars().collect();

    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            // Start of a new word if not first char and previous wasn't underscore
            if i != 0 && (i == 0 || chars.get(i - 1) != Some(&'_')) {
                if !current.is_empty() {
                    result.push(current);
                    current = String::new();
                }
            }
            current.push(c.to_lowercase().next().unwrap());
        } else if c == '_' {
            // Underscore is a word boundary
            if !current.is_empty() {
                result.push(current);
                current = String::new();
            }
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        result.push(current);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_english_word() {
        assert!(is_english_word("hello"));
        assert!(is_english_word("HELLO"));
        assert!(is_english_word("Hello"));
        assert!(is_english_word("world"));
        assert!(!is_english_word("xyznonexistent"));
    }

    #[test]
    fn test_split_words_empty() {
        assert!(split_words("").is_empty());
    }

    #[test]
    fn test_split_words_snake_case() {
        assert_eq!(split_words("hello_world"), vec!["hello", "world"]);
    }

    #[test]
    fn test_split_words_camel_case() {
        assert_eq!(split_words("helloWorld"), vec!["hello", "world"]);
    }

    #[test]
    fn test_split_words_pascal_case() {
        assert_eq!(split_words("HelloWorld"), vec!["hello", "world"]);
    }

    #[test]
    fn test_split_words_longer() {
        assert_eq!(
            split_words("hello_world_this_is_a_test"),
            vec!["hello", "world", "this", "is", "a", "test"]
        );
    }

    #[test]
    fn test_split_words_longer_camel() {
        assert_eq!(
            split_words("helloWorldThisIsATest"),
            vec!["hello", "world", "this", "is", "a", "test"]
        );
    }

    #[test]
    fn test_is_word_simple() {
        assert!(is_word("hello"));
    }

    #[test]
    fn test_is_word_nonexistent() {
        assert!(!is_word("xyznonexistent"));
    }

    #[test]
    fn test_is_word_uppercase() {
        assert!(is_word("WORLD"));
    }

    #[test]
    fn test_is_word_camel_case() {
        assert!(is_word("HelloWorld"));
        assert!(is_word("helloWorld"));
    }
}
