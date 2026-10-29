//! Primitives for the Go-compatible fixed-wire serializer (ADR-004).
//!
//! Hash rows use `encoding/json.Encoder.SetEscapeHTML(false)`, while cache
//! and query comparisons use `json.Marshal`. The caller controls row newlines.
//! Full record, timestamp and verdict serialization will build on this module.

/// The two encodings used by the Go reference client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Records hashing: keep `<`, `>` and `&` literal.
    Hash,
    /// Cache and query JSON: escape `<`, `>` and `&` as Go `json.Marshal` does.
    Marshal,
}

/// Append one quoted JSON string in the selected Go encoding.
///
/// Rust strings are valid UTF-8. The future wire parser must reject invalid
/// UTF-8 before this point, as required by ADR-004's fail-closed differences.
pub fn write_string(output: &mut String, value: &str, mode: Mode) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{2028}' => output.push_str("\\u2028"),
            '\u{2029}' => output.push_str("\\u2029"),
            '<' if mode == Mode::Marshal => output.push_str("\\u003c"),
            '>' if mode == Mode::Marshal => output.push_str("\\u003e"),
            '&' if mode == Mode::Marshal => output.push_str("\\u0026"),
            '\u{0000}'..='\u{001f}' => {
                let byte = character as usize;
                output.push_str("\\u00");
                output.push(char::from(HEX[byte >> 4]));
                output.push(char::from(HEX[byte & 0xf]));
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}
