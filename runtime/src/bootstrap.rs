//! Construct Darwin's initial kernel argument stack without host pointer aliases.
use std::ffi::{c_char, CStr};

#[derive(Debug)]
pub struct StackLayout {
    pub stack_pointer: u64,
    pub argument_pointer: u64,
    pub apple_pointer: u64,
}

pub fn build_stack(
    bytes: &mut [u8],
    base: u64,
    header: u64,
    executable: &str,
) -> Result<StackLayout, String> {
    if bytes.len() < 4096
        || header == 0
        || executable.is_empty()
        || executable.as_bytes().contains(&0)
    {
        return Err("invalid bootstrap stack configuration".into());
    }
    let end = base
        .checked_add(bytes.len() as u64)
        .ok_or("stack address overflow")?;
    let mut token = 0xcbf29ce484222325u64;
    for byte in base
        .to_le_bytes()
        .into_iter()
        .chain(header.to_le_bytes())
        .chain(executable.bytes())
    {
        token ^= u64::from(byte);
        token = token.wrapping_mul(0x100000001b3);
    }
    if token == 0 {
        token = 1;
    }
    let apple_entries = [
        format!("executable_path={executable}"),
        format!("ptr_munge=0x{token:016x}"),
    ];
    let apple_size = apple_entries
        .iter()
        .map(String::len)
        .sum::<usize>()
        .checked_add(apple_entries.len())
        .ok_or("stack string overflow")?;
    let strings = executable
        .len()
        .checked_add(apple_size)
        .and_then(|v| v.checked_add(1))
        .ok_or("stack string overflow")?;
    if strings + 128 > bytes.len() {
        return Err("bootstrap strings exceed stack space".into());
    }
    let argv_offset = bytes.len() - executable.len() - 1;
    let apple_offset = argv_offset - apple_size;
    let sp = (base + apple_offset as u64 - 8 * 8) & !15;
    if sp < base + 1024 || sp >= end {
        return Err("insufficient guest stack space".into());
    }
    bytes.fill(0);
    bytes[argv_offset..argv_offset + executable.len()].copy_from_slice(executable.as_bytes());
    let mut apple_at = apple_offset;
    for entry in &apple_entries {
        bytes[apple_at..apple_at + entry.len()].copy_from_slice(entry.as_bytes());
        apple_at += entry.len() + 1;
    }
    let words = [
        header,
        1,
        base + argv_offset as u64,
        0,
        0,
        base + apple_offset as u64,
        base + apple_offset as u64 + apple_entries[0].len() as u64 + 1,
        0,
    ];
    let offset = (sp - base) as usize;
    for (i, word) in words.iter().enumerate() {
        bytes[offset + i * 8..offset + i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    Ok(StackLayout {
        stack_pointer: sp,
        argument_pointer: base + argv_offset as u64,
        apple_pointer: base + apple_offset as u64,
    })
}

/// # Safety
/// `stack` points to `len` exclusively writable bytes, `executable` to a valid
/// NUL-terminated UTF-8 string, `out` to a writable u64. No pointers escape this allocation.
#[no_mangle]
pub unsafe extern "C" fn hm_build_boot_stack(
    stack: *mut u8,
    len: usize,
    header: u64,
    executable: *const c_char,
    out: *mut u64,
) -> i32 {
    if stack.is_null() || executable.is_null() || out.is_null() || len > 64 * 1024 * 1024 {
        return -1;
    }
    let Ok(path) = CStr::from_ptr(executable).to_str() else {
        return -2;
    };
    let bytes = std::slice::from_raw_parts_mut(stack, len);
    match build_stack(bytes, stack as u64, header, path) {
        Ok(layout) => {
            *out = layout.stack_pointer;
            0
        }
        Err(_) => -3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_args_use_pointers_into_the_guest_stack_and_align_sp() {
        let mut bytes = vec![0u8; 8192];
        let base = 0x1000_0007;
        let layout = build_stack(&mut bytes, base, 0x2000_0000, "/apps/Hello.app/Hello").unwrap();
        assert_eq!(layout.stack_pointer & 15, 0);
        let offset = (layout.stack_pointer - base) as usize;
        let word = |i: usize| {
            u64::from_le_bytes(
                bytes[offset + i * 8..offset + i * 8 + 8]
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(word(0), 0x2000_0000);
        assert_eq!(word(1), 1);
        assert_eq!(word(2), layout.argument_pointer);
        assert_eq!(word(3), 0);
        assert_eq!(word(4), 0); // envp terminator
        assert_eq!(word(5), layout.apple_pointer);
        assert!(word(6) > word(5));
        assert_eq!(word(7), 0);
        let argv = (layout.argument_pointer - base) as usize;
        assert!(bytes[argv..].starts_with(b"/apps/Hello.app/Hello\0"));
        let apple = (layout.apple_pointer - base) as usize;
        assert!(bytes[apple..].starts_with(b"executable_path=/apps/Hello.app/Hello\0"));
        let second = (word(6) - base) as usize;
        let entry = bytes[second..].split(|byte| *byte == 0).next().unwrap();
        let token = entry.strip_prefix(b"ptr_munge=").unwrap();
        assert_eq!(token.len(), 18);
        assert!(token.starts_with(b"0x"));
        assert_ne!(token, b"0x0000000000000000");
    }

    #[test]
    fn invalid_or_overflowing_inputs_do_not_mutate_stack() {
        let mut bytes = vec![0xa5; 4096];
        for (base, header, path) in [(u64::MAX, 1, "/app"), (0, 0, "/app"), (0, 1, "bad\0path")] {
            assert!(build_stack(&mut bytes, base, header, path).is_err());
            assert!(bytes.iter().all(|b| *b == 0xa5));
        }
    }
}
