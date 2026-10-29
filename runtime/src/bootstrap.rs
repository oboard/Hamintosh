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
    let env_entries = [
        "MallocAllowInternalSecurity=1",
        "MallocSecureAllocator=0",
        "MallocNanoZone=0",
        // Diagnostic: make Apple dyld narrate every initializer so the log
        // pinpoints the framework whose static init does not complete.
        "DYLD_PRINT_INITIALIZERS=1",
        "DYLD_PRINT_STATISTICS=1",
    ];
    let apple_entries = [
        format!("executable_path={executable}"),
        format!("ptr_munge=0x{token:016x}"),
        "ptrauth_disabled=1".to_string(),
    ];
    let apple_size = apple_entries
        .iter()
        .map(|entry| entry.len())
        .sum::<usize>()
        .checked_add(apple_entries.len())
        .ok_or("stack string overflow")?;
    let env_size = env_entries
        .iter()
        .map(|entry| entry.len())
        .sum::<usize>()
        .checked_add(env_entries.len())
        .ok_or("stack string overflow")?;
    let strings = executable
        .len()
        .checked_add(apple_size)
        .and_then(|v| v.checked_add(env_size))
        .and_then(|v| v.checked_add(1))
        .ok_or("stack string overflow")?;
    if strings + 128 > bytes.len() {
        return Err("bootstrap strings exceed stack space".into());
    }
    let argv_offset = bytes.len() - executable.len() - 1;
    let env_offset = argv_offset - env_size;
    let apple_offset = env_offset - apple_size;
    let sp_slots = 4 + env_entries.len() as u64 + 1 + apple_entries.len() as u64 + 1;
    let sp = (base + apple_offset as u64 - sp_slots * 8) & !15;
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
    let mut env_at = env_offset;
    for entry in env_entries {
        bytes[env_at..env_at + entry.len()].copy_from_slice(entry.as_bytes());
        env_at += entry.len() + 1;
    }
    let apple_ptr = |index: usize| -> u64 {
        base + apple_offset as u64
            + apple_entries[..index].iter().map(|entry| entry.len() as u64 + 1).sum::<u64>()
    };
    let env_ptr = |index: usize| -> u64 {
        base + env_offset as u64
            + env_entries[..index].iter().map(|entry| entry.len() as u64 + 1).sum::<u64>()
    };
    let mut words = vec![header, 1, base + argv_offset as u64, 0];
    words.extend((0..env_entries.len()).map(env_ptr));
    words.push(0);
    words.extend((0..apple_entries.len()).map(apple_ptr));
    words.push(0);
    if (sp - base) < (words.len() * 8) as u64 {
        return Err("insufficient guest stack space".into());
    }
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
        const ENVS: usize = 5;
        for i in 0..ENVS {
            assert!(i == 0 || word(4 + i) > word(4 + i - 1), "env pointers ascend");
        }
        assert_eq!(word(4 + ENVS), 0);
        let apple_index = 4 + ENVS + 1;
        assert_eq!(word(apple_index), layout.apple_pointer);
        assert!(word(apple_index + 1) > word(apple_index));
        assert!(word(apple_index + 2) > word(apple_index + 1));
        assert_eq!(word(apple_index + 3), 0);
        let argv = (layout.argument_pointer - base) as usize;
        assert!(bytes[argv..].starts_with(b"/apps/Hello.app/Hello\0"));
        let apple = (layout.apple_pointer - base) as usize;
        assert!(bytes[apple..].starts_with(b"executable_path=/apps/Hello.app/Hello\0"));
        let second = (word(apple_index + 1) - base) as usize;
        let entry = bytes[second..].split(|byte| *byte == 0).next().unwrap();
        let token = entry.strip_prefix(b"ptr_munge=").unwrap();
        assert_eq!(token.len(), 18);
        assert!(token.starts_with(b"0x"));
        assert_ne!(token, b"0x0000000000000000");
        let third = (word(apple_index + 2) - base) as usize;
        assert!(bytes[third..].starts_with(b"ptrauth_disabled=1\0"));
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
