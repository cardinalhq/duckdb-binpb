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

/// Normalize an attribute name for use as a DuckDB column name.
///
/// Rules (matching Go implementation):
/// - Lowercase letters and digits preserved as-is
/// - Uppercase letters converted to lowercase
/// - Everything else becomes underscore
///
/// Examples:
/// - "service.name" -> "service_name"
/// - "http.method" -> "http_method"
/// - "k8s.pod.name" -> "k8s_pod_name"
/// - "My-Custom-Attr" -> "my_custom_attr"
pub fn normalize_attribute_name(name: &str) -> String {
    name.bytes()
        .map(|c| match c {
            b'a'..=b'z' | b'0'..=b'9' => c,
            b'A'..=b'Z' => c + 32, // lowercase
            _ => b'_',
        })
        .map(|c| c as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_simple() {
        assert_eq!(normalize_attribute_name("service.name"), "service_name");
        assert_eq!(normalize_attribute_name("http.method"), "http_method");
    }

    #[test]
    fn test_normalize_k8s() {
        assert_eq!(normalize_attribute_name("k8s.pod.name"), "k8s_pod_name");
        assert_eq!(normalize_attribute_name("k8s.namespace.name"), "k8s_namespace_name");
    }

    #[test]
    fn test_normalize_case() {
        assert_eq!(normalize_attribute_name("My-Custom-Attr"), "my_custom_attr");
        assert_eq!(normalize_attribute_name("HTTP_STATUS_CODE"), "http_status_code");
    }

    #[test]
    fn test_normalize_special_chars() {
        assert_eq!(normalize_attribute_name("foo/bar/baz"), "foo_bar_baz");
        // Note: consecutive underscores are NOT collapsed (matching Go)
        assert_eq!(normalize_attribute_name("foo  bar"), "foo__bar");
    }

    #[test]
    fn test_normalize_numeric_prefix() {
        // Note: numeric prefix is kept as-is (matching Go)
        assert_eq!(normalize_attribute_name("123abc"), "123abc");
    }

    #[test]
    fn test_normalize_empty() {
        assert_eq!(normalize_attribute_name(""), "");
        // Dots become underscores, not collapsed
        assert_eq!(normalize_attribute_name("..."), "___");
    }
}
