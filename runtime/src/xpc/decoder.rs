//! Zero-copy, defensive XPC binary decoder.

use super::types::*;

pub struct XpcDecoder;

impl XpcDecoder {
    #[inline]
    pub fn word(bytes: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }

    #[inline]
    pub fn padded(size: usize) -> Option<usize> {
        Some(size.checked_add(3)? & !3)
    }

    pub fn key<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
        let remaining = bytes.get(*cursor..)?;
        let length = remaining.iter().position(|byte| *byte == 0)?;
        let result = &remaining[..length];
        *cursor = cursor.checked_add(Self::padded(length + 1)?)?;
        bytes.get(..*cursor)?;
        Some(result)
    }

    pub fn parse_value<'a>(
        bytes: &'a [u8],
        cursor: &mut usize,
        depth: u32,
        budget: &mut u32,
    ) -> Option<Value<'a>> {
        if depth > 8 || *budget == 0 {
            return None;
        }
        *budget -= 1;
        let kind = Self::word(bytes, *cursor)?;
        *cursor += 4;
        let mut count = 0;
        let start = *cursor;
        let body = match kind {
            XPC_TYPE_NULL => &bytes[start..start],
            XPC_TYPE_BOOL => {
                if Self::word(bytes, start)? > 1 {
                    return None;
                }
                *cursor += 4;
                bytes.get(start..*cursor)?
            }
            XPC_TYPE_INT64 | XPC_TYPE_UINT64 => {
                *cursor += 8;
                bytes.get(start..*cursor)?
            }
            XPC_TYPE_MACH_SEND => {
                *cursor += 4;
                bytes.get(start..*cursor)?
            }
            XPC_TYPE_UUID => {
                // Fixed 16-byte body without length prefix
                *cursor += 16;
                bytes.get(start..*cursor)?
            }
            XPC_TYPE_STRING => {
                let size = Self::word(bytes, start)? as usize;
                let content = start.checked_add(4)?;
                let end = content.checked_add(size)?;
                let text = bytes.get(content..end)?;
                if text.last() != Some(&0) || text[..text.len() - 1].contains(&0) {
                    return None;
                }
                *cursor = content.checked_add(Self::padded(size)?)?;
                bytes.get(end..*cursor)?;
                text
            }
            XPC_TYPE_ARRAY | XPC_TYPE_DICTIONARY => {
                let size = Self::word(bytes, start)? as usize;
                let end = start.checked_add(4)?.checked_add(size)?;
                count = Self::word(bytes, start + 4)?;
                let content = start + 8;
                let body = bytes.get(content..end)?;
                let mut inner = 0;
                for _ in 0..count {
                    if kind == XPC_TYPE_DICTIONARY {
                        Self::key(body, &mut inner)?;
                    }
                    Self::parse_value(body, &mut inner, depth + 1, budget)?;
                }
                if inner != body.len() {
                    return None;
                }
                *cursor = end;
                body
            }
            _ => return None,
        };
        Some(Value { kind, body, count })
    }

    pub fn parse_root<'a>(bytes: &'a [u8]) -> Option<Value<'a>> {
        if Self::word(bytes, 0)? != XPC_MAGIC || Self::word(bytes, 4)? != XPC_VERSION {
            return None;
        }
        let mut cursor = 8;
        let mut budget = 256;
        let root = Self::parse_value(bytes, &mut cursor, 0, &mut budget)?;
        if cursor != bytes.len() || root.kind != XPC_TYPE_DICTIONARY {
            return None;
        }
        Some(root)
    }

    pub fn dictionary_get<'a>(dictionary: Value<'a>, name: &[u8]) -> Option<Value<'a>> {
        if dictionary.kind != XPC_TYPE_DICTIONARY {
            return None;
        }
        let mut cursor = 0;
        let mut found = None;
        let mut budget = 256;
        for _ in 0..dictionary.count {
            let field = Self::key(dictionary.body, &mut cursor)?;
            let entry = Self::parse_value(dictionary.body, &mut cursor, 0, &mut budget)?;
            if field == name {
                if found.is_some() {
                    return None;
                }
                found = Some(entry);
            }
        }
        found
    }

    pub fn integer(value: Value<'_>) -> Option<u64> {
        if !matches!(value.kind, XPC_TYPE_INT64 | XPC_TYPE_UINT64) {
            return None;
        }
        Some(u64::from_le_bytes(value.body.try_into().ok()?))
    }

    pub fn bootstrap_lookup_name(bytes: &[u8]) -> Option<&[u8]> {
        let root = Self::parse_root(bytes)?;
        let name = Self::dictionary_get(root, b"name")?;
        if name.kind != XPC_TYPE_STRING || name.body.len() < 2 {
            return None;
        }
        Some(name.body)
    }
}
