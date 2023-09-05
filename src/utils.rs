/// Splits the given line into segments separated by spaces. Substrings defined by
/// double-quotes are kept as a single segment, with double-quotes removed.
/// Unterminated substrings are tolerated and the remaining of the line is returned
/// as the last segment.
pub fn split_line(line: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current_segment = String::new();
    let mut inside_quoted_substring = false;

    let mut iter = line.chars();
    while let Some(char) = iter.next() {
        match char {
            ' ' if !inside_quoted_substring => {
                if !current_segment.is_empty() {
                    segments.push(current_segment);
                    current_segment = String::new();
                }
            }
            '"' => inside_quoted_substring = !inside_quoted_substring,
            '\\' => {
                // Escaping character
                if let Some(escaped_char) = iter.next() {
                    current_segment.push(escaped_char);
                } else {
                    // The line ends with a backslash : ignore it
                    break;
                }
            }
            c => current_segment.push(c),
        }
    }
    if !current_segment.is_empty() {
        segments.push(current_segment);
    }

    segments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_line() {
        // Empty line
        assert_eq!(split_line(""), vec![] as Vec<String>);

        // Single word
        assert_eq!(split_line("hello"), vec!["hello"]);

        // Simple line split
        assert_eq!(split_line("hello world"), vec!["hello", "world"]);

        // Trim
        assert_eq!(split_line("   hello   world     "), vec!["hello", "world"]);

        // Escaped backslashes
        assert_eq!(split_line(r"\\hello\\world"), vec![r"\hello\world"]);

        // Invalid escaped characters
        assert_eq!(split_line(r"\\ \a \b"), vec!["\\", "a", "b"]);

        // Simple quoted substring
        assert_eq!(
            split_line(r#"hi, "hello   world" !"#),
            vec!["hi,", "hello   world", "!"]
        );

        // Nested quotes
        assert_eq!(split_line(r#""hello \"world\"""#), vec![r#"hello "world""#]);

        // Evil quoted substrings
        assert_eq!(split_line(r#"hello" "world"#), vec![r#"hello world"#]);
        assert_eq!(split_line(r#"\"\\\"\""#), vec![r#""\"""#]);
        assert_eq!(split_line(r#" \" \\ \" \" "#), vec!["\"", "\\", "\"", "\""]);

        // Real-world examples
        assert_eq!(
            split_line(r#"sh -c "echo \"hello world\" > test.txt""#),
            vec!["sh", "-c", r#"echo "hello world" > test.txt"#]
        );
    }
}
