//! Lexical master-file entries. Tokens retain presentation escapes for the
//! name and RDATA parsers; parentheses only suppress physical line endings.
#![cfg_attr(not(test), warn(clippy::too_many_lines, clippy::cognitive_complexity))]

use super::MasterError;

pub(super) struct Entry<'a> {
    pub(super) inherited: bool,
    pub(super) first_group: Option<usize>,
    pub(super) fields: Vec<&'a str>,
}

pub(super) fn entries(input: &str) -> Result<Vec<Entry<'_>>, MasterError> {
    let bytes = input.as_bytes();
    let mut output = Vec::new();
    let mut fields = Vec::new();
    let mut index = 0;
    let mut groups = Vec::new();
    let mut first_group = None;
    let mut inherited = false;
    let mut line_start = true;
    let mut separated = true;
    while let Some(&byte) = bytes.get(index) {
        if line_start {
            inherited = matches!(byte, b' ' | b'\t');
            line_start = false;
        }
        match byte {
            b' ' | b'\t' => {
                index += 1;
                separated = true;
            }
            b'\r' | b'\n' => {
                index += 1;
                if byte == b'\r' && bytes.get(index) == Some(&b'\n') {
                    index += 1;
                }
                if groups.is_empty() {
                    if !fields.is_empty() {
                        output.push(Entry {
                            inherited,
                            first_group: first_group.take(),
                            fields: std::mem::take(&mut fields),
                        });
                    }
                    line_start = true;
                }
                separated = true;
            }
            b';' => {
                while bytes
                    .get(index)
                    .is_some_and(|b| !matches!(b, b'\r' | b'\n'))
                {
                    index += 1;
                }
            }
            b'(' => {
                if !separated {
                    return Err(error(input, index, "missing delimiter before group"));
                }
                first_group.get_or_insert(fields.len());
                groups.push(fields.len());
                index += 1;
                separated = true;
            }
            b')' => {
                if groups.is_empty() {
                    return Err(error(input, index, "unmatched closing parenthesis"));
                }
                if groups.pop() == Some(fields.len()) {
                    return Err(error(input, index, "empty parenthesized group"));
                }
                index += 1;
                separated = false;
            }
            _ => {
                if !separated {
                    return Err(error(input, index, "missing token delimiter"));
                }
                let start = index;
                token_end(input, &mut index)?;
                fields.push(&input[start..index]);
                separated = false;
            }
        }
    }
    if !groups.is_empty() {
        return Err(error(input, input.len(), "unclosed parenthesis"));
    }
    if !fields.is_empty() {
        output.push(Entry {
            inherited,
            first_group,
            fields,
        });
    }
    Ok(output)
}

const DECIMAL_ESCAPE_DIGITS: usize = 3;

fn token_end(input: &str, index: &mut usize) -> Result<(), MasterError> {
    let bytes = input.as_bytes();
    let start = *index;
    let mut quoted = false;
    let mut label_start = true;
    while let Some(&next) = bytes.get(*index) {
        match next {
            b'\\' => {
                label_start = false;
                *index += 1;
                let escaped = *bytes
                    .get(*index)
                    .ok_or_else(|| error(input, *index, "dangling escape"))?;
                if escaped.is_ascii_digit() {
                    let digits = bytes
                        .get(*index..*index + DECIMAL_ESCAPE_DIGITS)
                        .filter(|s| s.iter().all(u8::is_ascii_digit))
                        .ok_or_else(|| {
                            error(input, *index, "decimal escape requires three digits")
                        })?;
                    let value = u16::from(digits[0] - b'0') * 100
                        + u16::from(digits[1] - b'0') * 10
                        + u16::from(digits[2] - b'0');
                    if value > u16::from(u8::MAX) {
                        return Err(error(input, *index, "decimal escape exceeds 255"));
                    }
                    *index += DECIMAL_ESCAPE_DIGITS;
                } else {
                    // Advance a whole UTF-8 scalar so all borrowed slices remain valid.
                    *index += input[*index..]
                        .chars()
                        .next()
                        .expect("escaped character")
                        .len_utf8();
                }
            }
            b'"' => {
                if !quoted && !label_start {
                    return Err(error(input, *index, "quote must start a label or string"));
                }
                quoted = !quoted;
                label_start = false;
                *index += 1;
                if !quoted
                    && bytes.get(*index).is_some_and(|b| {
                        !matches!(b, b'.' | b' ' | b'\t' | b'\r' | b'\n' | b';' | b'(' | b')')
                    })
                {
                    return Err(error(input, *index, "missing delimiter after quote"));
                }
            }
            b' ' | b'\t' | b'\r' | b'\n' | b';' | b'(' | b')' if !quoted => break,
            _ => {
                label_start = next == b'.' && !quoted;
                *index += 1;
            }
        }
    }
    if quoted {
        return Err(error(input, start, "unterminated quoted token"));
    }
    Ok(())
}

fn error(input: &str, index: usize, message: &str) -> MasterError {
    let mut line = 1;
    let mut column = 1;
    let mut cr = false;
    for ch in input[..index].chars() {
        match ch {
            '\r' => {
                line += 1;
                column = 1;
                cr = true;
            }
            '\n' => {
                if !cr {
                    line += 1;
                }
                column = 1;
                cr = false;
            }
            _ => {
                column += 1;
                cr = false;
            }
        }
    }
    MasterError::new(format!(
        "master-file line {line}, column {column}: {message}"
    ))
}

pub(super) fn character_string(value: &str) -> Result<(), MasterError> {
    let mut escaped = false;
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' && index != 0 && index != value.len() - 1 {
            return Err(MasterError::new(
                "quotes must enclose a complete character string",
            ));
        }
    }
    Ok(())
}
