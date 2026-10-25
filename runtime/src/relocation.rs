//! Apply only self-contained bootstrap dyld rebases, leaving App linking to Apple dyld.
use crate::macho::{self, fixups::Target};

pub type SignPointer = unsafe extern "C" fn(u64, u64, u16, u8, u8) -> u64;

/// # Safety
/// The original bytes are readable; mapped segments have their Mach-O protections
/// and fit in `span`. No guest thread may access this image during mutation.
/// A supplied signer must use the active host process PAC keys and cannot unwind.
#[no_mangle]
pub unsafe extern "C" fn hm_apply_bootstrap_rebases(
    original: *const u8,
    len: usize,
    mapped: *mut u8,
    span: usize,
    sign: Option<SignPointer>,
    count: *mut u64,
) -> i32 {
    if original.is_null() || mapped.is_null() || count.is_null() || len > 512 * 1024 * 1024 {
        return -1;
    }
    *count = 0;
    let bytes = std::slice::from_raw_parts(original, len);
    let Ok(image) = macho::parse(bytes) else {
        return -2;
    };
    if image.file_type != 7
        || image.encrypted
        || !image.dependencies.is_empty()
        || image.legacy_dyld_info
    {
        return -3;
    }
    let Ok(plan) = macho::fixups::parse(bytes, &image) else {
        return -2;
    };
    if !plan.imports.is_empty()
        || plan
            .fixups
            .iter()
            .any(|f| matches!(f.target, Target::Bind { .. }))
    {
        return -3;
    }
    let mut entry = 0;
    if crate::hm_validate_aot_image(original, len, mapped, span, &mut entry) != 0 {
        return -4;
    }
    let writes = plan.resolve(mapped as u64, &[], |target, storage, auth| {
        let Some(sign) = sign else {
            return Err("PAC signer is required".into());
        };
        Ok(sign(
            target,
            storage,
            auth.diversity,
            auth.key,
            auth.address_diversity as u8,
        ))
    });
    let Ok(writes) = writes else {
        return -5;
    };
    for (offset, value) in &writes {
        std::ptr::write_unaligned(mapped.add(*offset as usize).cast::<u64>(), *value);
    }
    *count = writes.len() as u64;
    0
}

/// Restore writable segments between isolated bootstrap attempts.
///
/// # Safety
/// All original bytes are readable and each writable segment is writable in the
/// supplied mapped span. No guest thread may be running or retain this image's data.
#[no_mangle]
pub unsafe extern "C" fn hm_reset_bootstrap_data(
    original: *const u8,
    len: usize,
    mapped: *mut u8,
    span: usize,
) -> i32 {
    if original.is_null() || mapped.is_null() || len > 512 * 1024 * 1024 {
        return -1;
    }
    let bytes = std::slice::from_raw_parts(original, len);
    let Ok(image) = macho::parse(bytes) else {
        return -2;
    };
    if image.file_type != 7 {
        return -3;
    }
    let Some(text) = image.segments.iter().find(|s| s.name == "__TEXT") else {
        return -3;
    };
    for segment in &image.segments {
        if segment.protection & 2 == 0 {
            continue;
        }
        if segment
            .vm_address
            .checked_sub(text.vm_address)
            .and_then(|offset| offset.checked_add(segment.vm_size))
            .filter(|end| *end <= span as u64)
            .is_none()
        {
            return -4;
        }
    }
    for segment in &image.segments {
        if segment.protection & 2 == 0 {
            continue;
        }
        let offset = (segment.vm_address - text.vm_address) as usize;
        let file = image.slice_offset + segment.file_offset as usize;
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr().add(file),
            mapped.add(offset),
            segment.file_size as usize,
        );
        std::ptr::write_bytes(
            mapped.add(offset + segment.file_size as usize),
            0,
            (segment.vm_size - segment.file_size) as usize,
        );
    }
    0
}
