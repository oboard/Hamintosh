pub mod bootstrap;
pub mod cache;
pub mod darwin;
pub mod mach;
pub mod macho;
pub mod mig;
pub mod relocation;
pub mod report;
pub mod services;
pub mod vfs;

use std::ffi::{c_char, CStr, CString};

#[repr(C)]
#[derive(Default)]
pub struct ProbePlan {
    pub slice_offset: u64,
    pub slice_size: u64,
    pub entry_offset: u64,
}

/// # Safety
/// `data` points to `len` readable bytes and `out` to a writable ProbePlan.
#[no_mangle]
pub unsafe extern "C" fn hm_probe_plan(data: *const u8, len: usize, out: *mut ProbePlan) -> i32 {
    if data.is_null() || out.is_null() || len > 1024 * 1024 {
        return -1;
    }
    let bytes = std::slice::from_raw_parts(data, len);
    let Ok(image) = macho::parse(bytes) else {
        return -2;
    };
    if image.file_type != 2
        || image.cpu_subtype & 0x00ff_ffff != 0
        || image.encrypted
        || image.chained_fixups
        || image.legacy_dyld_info
        || image.interpreter.is_some()
        || !image.dependencies.is_empty()
        || image.segments.len() != 1
    {
        return -3;
    }
    let Some(entry) = image.entry_file_offset else {
        return -4;
    };
    // Only our audited mov w0,#42; ret fixture may pass this execution boundary.
    let begin = image.slice_offset + entry as usize;
    if bytes.get(begin..begin + 8) != Some(&[0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]) {
        return -5;
    }
    *out = ProbePlan {
        slice_offset: image.slice_offset as u64,
        slice_size: image.slice_size as u64,
        entry_offset: entry,
    };
    0
}

#[no_mangle]
pub extern "C" fn hm_runtime_greeting() -> *const c_char {
    c"Hello from Rust".as_ptr()
}

/// Check that the ELF linker preserved every original segment byte and address delta.
/// This intentionally does not bind or call the iOS executable.
///
/// # Safety
/// `original` points to `len` readable bytes; each mapped segment is readable
/// within `mapped..mapped+span`. `entry_offset` points to a writable u64.
#[no_mangle]
pub unsafe extern "C" fn hm_validate_aot_image(
    original: *const u8,
    len: usize,
    mapped: *const u8,
    span: usize,
    entry_offset: *mut u64,
) -> i32 {
    if original.is_null() || mapped.is_null() || entry_offset.is_null() || len > 512 * 1024 * 1024 {
        return -1;
    }
    let bytes = std::slice::from_raw_parts(original, len);
    let Ok(image) = macho::parse(bytes) else {
        return -2;
    };
    let Some(text) = image.segments.iter().find(|s| s.name == "__TEXT") else {
        return -3;
    };
    for segment in image
        .segments
        .iter()
        .filter(|s| s.protection != 0 && s.vm_size != 0)
    {
        let Some(offset) = segment.vm_address.checked_sub(text.vm_address) else {
            return -4;
        };
        if offset
            .checked_add(segment.vm_size)
            .filter(|end| *end <= span as u64)
            .is_none()
        {
            return -4;
        }
        let contents =
            std::slice::from_raw_parts(mapped.add(offset as usize), segment.file_size as usize);
        let file = image.slice_offset + segment.file_offset as usize;
        if contents != &bytes[file..file + segment.file_size as usize] {
            return -5;
        }
    }
    let Some(entry) = image.entry_vm_address else {
        return -6;
    };
    *entry_offset = entry - text.vm_address;
    0
}

/// # Safety
/// Both arguments are valid, NUL-terminated UTF-8 strings for this call.
/// Free the returned allocation exactly once with hm_string_free.
#[no_mangle]
pub unsafe extern "C" fn hm_inspect_json(
    path: *const c_char,
    sysroot: *const c_char,
) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        if path.is_null() || sysroot.is_null() {
            return Err("null path".to_string());
        }
        let path = CStr::from_ptr(path).to_str().map_err(|e| e.to_string())?;
        let sysroot = CStr::from_ptr(sysroot)
            .to_str()
            .map_err(|e| e.to_string())?;
        Ok(report::inspect(
            std::path::Path::new(path),
            std::path::Path::new(sysroot),
        ))
    });
    let value = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => serde_json::json!({"status":"invalid-input", "error":e, "appExecuted":false}),
        Err(_) => {
            serde_json::json!({"status":"runtime-error", "error":"Rust inspection panicked", "appExecuted":false})
        }
    };
    CString::new(value.to_string()).unwrap().into_raw()
}

/// # Safety
/// `value` is null or an unfreed pointer returned by hm_inspect_json.
#[no_mangle]
pub unsafe extern "C" fn hm_string_free(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}
