//! BSD VM operations use the same owned mappings as the Mach VM callbacks.
//! Error/protection translation follows XNU bsd/kern/kern_mman.c:mprotect.
use super::{Process, TrapFrame};

const PAGE_MASK: u64 = 0x3fff; // Current iOS ARM64 guest uses 16 KiB pages.

pub(super) fn protect(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let address = frame.arguments[0];
    let length = frame.arguments[1];
    if address & PAGE_MASK != 0 {
        return Some(22); // EINVAL: mprotect requires an aligned start.
    }
    let Some(length) = length.checked_add(PAGE_MASK).map(|n| n & !PAGE_MASK) else {
        return Some(12); // ENOMEM: address range overflows.
    };
    if address.checked_add(length).is_none() {
        return Some(12);
    }
    // XNU masks other bits away. TRUSTED and STRIP_READ have distinct code
    // signing / execute-only semantics; keep them explicit unsupported calls
    // until this compatibility kernel can implement those semantics.
    let mut protection = frame.arguments[2] as u32 & 0xa7;
    if protection & 0xa0 != 0 {
        return None;
    }
    // The BSD interface adds read permission for write or execute requests.
    if protection & 6 != 0 {
        protection |= 1;
    }
    if length == 0 {
        return Some(0);
    }
    let callback = process.vm_protect?;
    let result = unsafe { callback(process.host_context, address, length, 0, protection) };
    Some(match result {
        0 => 0,
        1 => 12, // KERN_INVALID_ADDRESS -> ENOMEM
        2 => 13, // KERN_PROTECTION_FAILURE -> EACCES
        _ => 22, // Other Mach failures -> EINVAL
    })
}

const MAP_SHARED: u32 = 0x0001;
const MAP_PRIVATE: u32 = 0x0002;
const MAP_FIXED: u32 = 0x0010;
const MAP_ANON: u32 = 0x1000;
const MAP_UNIX03: u32 = 0x40000;
const VM_FLAGS_ANYWHERE: u32 = 1;
const MAX_MAPPING: u64 = 1 << 30;

fn mach_map_error(result: u32) -> u32 {
    match result {
        0 => 0,
        1 | 3 => 12, // KERN_INVALID_ADDRESS / KERN_NO_SPACE
        2 => 13,     // KERN_PROTECTION_FAILURE
        4 => 22,     // KERN_INVALID_ARGUMENT
        46 => 45,    // KERN_NOT_SUPPORTED
        _ => 5,      // EIO: preserve failure instead of inventing success
    }
}

/// Darwin arm64 `mmap(addr, len, prot, flags, fd, offset)`.
///
/// Executable memory remains reserved for signed AOT images. Anonymous
/// mappings use the existing VM callback; file-backed mappings resolve only a
/// guest-owned descriptor and ask the native layer to create a private host
/// mapping. Fixed mappings, shared writable files and JIT requests stay
/// explicit unsupported calls.
pub(super) fn mmap(process: &Process, frame: &TrapFrame) -> Option<Result<u64, u32>> {
    let a = frame.arguments;
    let size = a[1];
    let protection = a[2] as u32;
    let flags = a[3] as u32;
    let descriptor = a[4] as u32;
    let offset = a[5];
    if size == 0 {
        return Some(Err(22));
    }
    if size > MAX_MAPPING {
        return Some(Err(12));
    }
    if protection & !7 != 0 {
        return Some(Err(22));
    }
    if protection & 4 != 0 || flags & MAP_FIXED != 0 {
        // No executable mmap is performed here. The native callback may only
        // identify an existing immutable mapping from the signed HAP.
        let allowed = MAP_PRIVATE | MAP_FIXED | MAP_UNIX03;
        if flags & !allowed != 0 || flags & 3 != MAP_PRIVATE || protection & 6 == 6 {
            return Some(Err(45));
        }
        let Some(host_fd) = process.files.host(descriptor) else {
            return Some(Err(9));
        };
        let Some(map) = process.aot_map_file else {
            return Some(Err(45));
        };
        let mut address = a[0];
        let error = unsafe {
            map(
                process.host_context,
                &mut address,
                size,
                protection,
                flags,
                host_fd,
                offset,
            )
        };
        return Some(if error == 0 { Ok(address) } else { Err(error) });
    }
    if flags & MAP_SHARED != 0 || flags & 3 != MAP_PRIVATE {
        return Some(Err(22)); // This runtime supports private mappings only.
    }
    let allowed = MAP_PRIVATE | MAP_ANON | MAP_UNIX03;
    if flags & !allowed != 0 {
        return Some(Err(45));
    }

    let mut address = a[0];
    if flags & MAP_ANON != 0 {
        let Some(map) = process.vm_map else {
            return Some(Err(45));
        };
        let result = unsafe {
            map(
                process.host_context,
                &mut address,
                size,
                PAGE_MASK,
                VM_FLAGS_ANYWHERE,
                protection,
            )
        };
        let error = mach_map_error(result);
        return Some(if error == 0 { Ok(address) } else { Err(error) });
    }

    // A file-backed call must reference a descriptor already known to the VFS.
    // A raw host fd supplied by the guest is never accepted.
    let Some(host_fd) = process.files.host(descriptor) else {
        return Some(Err(9)); // EBADF
    };
    let Some(map_file) = process.map_file else {
        return Some(Err(45));
    };
    let error = unsafe {
        map_file(
            process.host_context,
            &mut address,
            size,
            protection,
            host_fd,
            offset,
        )
    };
    Some(if error == 0 { Ok(address) } else { Err(error) })
}

pub(super) fn unmap(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let address = frame.arguments[0];
    let length = frame.arguments[1];
    if address & PAGE_MASK != 0 || length == 0 {
        return Some(22); // EINVAL: Darwin requires a non-empty page-aligned range.
    }
    let Some(length) = length.checked_add(PAGE_MASK).map(|n| n & !PAGE_MASK) else {
        return Some(12); // ENOMEM: address range overflows.
    };
    if address.checked_add(length).is_none() {
        return Some(12);
    }
    let callback = process.vm_deallocate?;
    let result = unsafe { callback(process.host_context, address, length) };
    Some(match result {
        0 => 0,
        1 => 12, // KERN_INVALID_ADDRESS -> ENOMEM
        2 => 13, // KERN_PROTECTION_FAILURE -> EACCES
        _ => 22, // Other Mach failures -> EINVAL
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    #[derive(Default)]
    struct Host {
        calls: u32,
        address: u64,
        size: u64,
        protection: u32,
        result: u32,
    }

    unsafe extern "C" fn protect(
        context: *const c_void,
        address: u64,
        size: u64,
        set_maximum: u32,
        protection: u32,
    ) -> u32 {
        let host = &mut *(context as *mut Host);
        assert_eq!(set_maximum, 0);
        host.calls += 1;
        host.address = address;
        host.size = size;
        host.protection = protection;
        host.result
    }

    fn process(host: &mut Host) -> Process {
        let mut process = Process::new(1, 0, 2);
        process.host_context = (host as *mut Host).cast();
        process.vm_protect = Some(protect);
        process
    }

    fn frame(address: u64, length: u64, protection: u64) -> TrapFrame {
        TrapFrame {
            number: 74,
            arguments: [address, length, protection, 0, 0, 0, 0, 0],
            nzcv: 0xf000_0000,
            ..Default::default()
        }
    }

    #[test]
    fn bsd_protection_rounds_length_and_routes_owned_mapping_transitions() {
        let mut host = Host::default();
        let process = process(&mut host);
        let mut frame = frame(0x1_0000_0000, 0x4001, 2);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0, 0]);
        assert_eq!(frame.nzcv, 0xd000_0000);
        assert_eq!(host.address, 0x1_0000_0000);
        assert_eq!(host.size, 0x8000);
        assert_eq!(host.protection, 3); // write implies read
        frame.arguments[2] = 1;
        assert!(process.dispatch(&mut frame));
        assert_eq!(host.protection, 1);
        frame.arguments[2] = 0;
        assert!(process.dispatch(&mut frame));
        assert_eq!(host.protection, 0);
        assert_eq!(host.calls, 3);
    }

    #[test]
    fn malformed_ranges_do_not_reach_the_host_callback() {
        let mut host = Host::default();
        let process = process(&mut host);
        for (address, length, error) in [
            (1, 0x4000, 22),
            (1, 0, 22),
            (0x4000, u64::MAX, 12),
            (!PAGE_MASK, 0x4000, 12),
        ] {
            let mut frame = frame(address, length, 1);
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result, [error, 0]);
            assert_eq!(frame.nzcv, 0xf000_0000);
        }
        assert_eq!(host.calls, 0);
        assert_eq!(super::protect(&process, &frame(0, 0, 0)), Some(0));
        assert_eq!(host.calls, 0);
    }

    #[test]
    fn mach_failures_become_bsd_errno_and_maximum_permissions_are_not_bypassed() {
        for (result, error) in [(1, 12), (2, 13), (4, 22), (46, 22)] {
            let mut host = Host {
                result,
                ..Default::default()
            };
            let process = process(&mut host);
            let mut frame = frame(0x4000, 0x4000, 4);
            assert!(process.dispatch(&mut frame));
            assert_eq!(host.protection, 5); // execute implies read
            assert_eq!(frame.result, [error, 0]);
            assert_ne!(frame.nzcv & super::super::CARRY, 0);
        }
    }

    #[test]
    fn code_signing_and_execute_only_requests_remain_explicitly_unsupported() {
        let mut host = Host::default();
        let process = process(&mut host);
        for protection in [0x20, 0x25, 0x84] {
            let mut frame = frame(0x4000, 0x4000, protection);
            assert!(!process.dispatch(&mut frame));
            assert_eq!(frame.result, [78, 0]);
        }
        assert_eq!(host.calls, 0);
        let mut frame = frame(0x4000, 0x4000, 0x41);
        assert!(process.dispatch(&mut frame));
        assert_eq!(host.protection, 1); // unknown flag stripped as in XNU
    }

    #[derive(Default)]
    struct MappingHost {
        map_calls: u32,
        file_calls: u32,
        size: u64,
        mask: u64,
        flags: u32,
        protection: u32,
        host_fd: i32,
        offset: u64,
        map_error: u32,
        file_error: u32,
    }

    unsafe extern "C" fn vm_map(
        context: *const c_void,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: u32,
        protection: u32,
    ) -> u32 {
        let host = &mut *(context as *mut MappingHost);
        host.map_calls += 1;
        host.size = size;
        host.mask = mask;
        host.flags = flags;
        host.protection = protection;
        if host.map_error == 0 {
            *address = 0x7000_0000;
        }
        host.map_error
    }

    unsafe extern "C" fn map_file(
        context: *const c_void,
        address: *mut u64,
        size: u64,
        protection: u32,
        host_fd: i32,
        offset: u64,
    ) -> u32 {
        let host = &mut *(context as *mut MappingHost);
        host.file_calls += 1;
        host.size = size;
        host.protection = protection;
        host.host_fd = host_fd;
        host.offset = offset;
        if host.file_error == 0 {
            *address = 0x7100_0000;
        }
        host.file_error
    }

    fn mmap_frame(
        address: u64,
        size: u64,
        protection: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    ) -> TrapFrame {
        TrapFrame {
            number: 197,
            arguments: [address, size, protection, flags, fd, offset, 0, 0],
            nzcv: 0xf000_0000,
            ..Default::default()
        }
    }

    #[test]
    fn file_mmap_resolves_only_guest_owned_descriptors_and_preserves_offset() {
        let mut host = MappingHost::default();
        let mut process = Process::new(1, 0, 2);
        process.host_context = (&mut host as *mut MappingHost).cast();
        process.map_file = Some(map_file);
        let guest = process.files.insert(91).unwrap();
        assert_eq!(guest, 3);
        let mut frame = mmap_frame(0, 0x92000, 1, 0x40002, guest as u64, 0x8000);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0x7100_0000, 0]);
        assert_eq!(frame.nzcv & super::super::CARRY, 0);
        assert_eq!((host.map_calls, host.file_calls), (0, 1));
        assert_eq!(
            (host.size, host.protection, host.host_fd, host.offset),
            (0x92000, 1, 91, 0x8000)
        );
    }

    unsafe extern "C" fn aot_map_file(
        context: *const c_void,
        address: *mut u64,
        size: u64,
        protection: u32,
        flags: u32,
        host_fd: i32,
        offset: u64,
    ) -> u32 {
        let host = &mut *(context as *mut MappingHost);
        host.flags = flags;
        map_file(context, address, size, protection, host_fd, offset)
    }

    #[test]
    fn signed_aot_mapping_requires_owned_file_and_preserves_validation_errors() {
        let mut host = MappingHost::default();
        let mut process = Process::new(1, 0, 2);
        process.host_context = (&mut host as *mut MappingHost).cast();
        process.aot_map_file = Some(aot_map_file);
        let guest = process.files.insert(91).unwrap();
        let mut frame = mmap_frame(0x71000000, 0xc000, 5, 0x12, guest as u64, 0);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0x71000000, 0]);
        assert_eq!((host.flags, host.protection, host.host_fd), (0x12, 5, 91));
        host.file_error = 45;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [45, 0]);
        assert_ne!(frame.nzcv & super::super::CARRY, 0);
        let calls = host.file_calls;
        for (protection, flags, fd, error) in [
            (7, 0x12, guest as u64, 45),
            (5, 0x11, guest as u64, 45),
            (5, 0x1012, guest as u64, 45),
            (5, 0x12, 91, 9),
        ] {
            let mut rejected = mmap_frame(0x71000000, 0xc000, protection, flags, fd, 0);
            assert!(process.dispatch(&mut rejected));
            assert_eq!(rejected.result, [error, 0]);
        }
        assert_eq!(host.file_calls, calls);
    }

    #[test]
    fn anonymous_mmap_routes_through_the_existing_guest_vm_allocator() {
        let mut host = MappingHost::default();
        let mut process = Process::new(1, 0, 2);
        process.host_context = (&mut host as *mut MappingHost).cast();
        process.vm_map = Some(vm_map);
        let mut frame = mmap_frame(0, 0x4001, 3, 0x1002, 0, 0);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0x7000_0000, 0]);
        assert_eq!((host.map_calls, host.file_calls), (1, 0));
        assert_eq!(
            (host.size, host.mask, host.flags, host.protection),
            (0x4001, PAGE_MASK, VM_FLAGS_ANYWHERE, 3)
        );
    }

    #[test]
    fn mmap_rejects_executable_shared_fixed_and_unknown_guest_descriptors() {
        let mut host = MappingHost::default();
        let mut process = Process::new(1, 0, 2);
        process.host_context = (&mut host as *mut MappingHost).cast();
        process.map_file = Some(map_file);
        process.vm_map = Some(vm_map);
        for (protection, flags, fd, error) in [
            (5, 0x1002, 0, 45),
            (1, 0x1001, 0, 22),
            (1, 0x1012, 0, 45),
            (1, 0x40002, 99, 9),
            (1, 0x20000002, 3, 45),
        ] {
            let mut frame = mmap_frame(0, 0x4000, protection, flags, fd, 0);
            assert!(
                process.dispatch(&mut frame),
                "mmap case prot={protection:#x} flags={flags:#x} fd={fd} returned no result"
            );
            assert_eq!(frame.result, [error, 0]);
            assert_ne!(frame.nzcv & super::super::CARRY, 0);
        }
        let mut frame = mmap_frame(0, 0x4000, 1, 0x1002, 0, 0);
        frame.arguments[1] = (1 << 30) + 1;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [12, 0]);
        assert_eq!((host.map_calls, host.file_calls), (0, 0));
    }

    #[test]
    fn mmap_propagates_kernel_and_host_mapping_failures() {
        let mut host = MappingHost {
            map_error: 2,
            file_error: 45,
            ..Default::default()
        };
        let mut process = Process::new(1, 0, 2);
        process.host_context = (&mut host as *mut MappingHost).cast();
        process.vm_map = Some(vm_map);
        let mut frame = mmap_frame(0, 0x4000, 1, 0x1002, 0, 0);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [13, 0]);
        assert_ne!(frame.nzcv & super::super::CARRY, 0);

        process.map_file = Some(map_file);
        let guest = process.files.insert(91).unwrap();
        let mut frame = mmap_frame(0, 0x4000, 1, 0x40002, guest as u64, 0);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [45, 0]);
        assert_ne!(frame.nzcv & super::super::CARRY, 0);
    }

    #[derive(Default)]
    struct DeallocationHost {
        calls: u32,
        address: u64,
        size: u64,
        result: u32,
    }

    unsafe extern "C" fn deallocate(context: *const c_void, address: u64, size: u64) -> u32 {
        let host = &mut *(context as *mut DeallocationHost);
        host.calls += 1;
        host.address = address;
        host.size = size;
        host.result
    }

    fn deallocation_frame(address: u64, length: u64) -> TrapFrame {
        TrapFrame {
            number: 73,
            arguments: [address, length, 0, 0, 0, 0, 0, 0],
            nzcv: 0xf000_0000,
            ..Default::default()
        }
    }

    #[test]
    fn munmap_rounds_the_range_and_delegates_only_to_owned_vm() {
        let mut host = DeallocationHost::default();
        let mut process = Process::new(1, 0, 2);
        process.host_context = (&mut host as *mut DeallocationHost).cast();
        process.vm_deallocate = Some(deallocate);
        let mut frame = deallocation_frame(0x1_0000, 0x4001);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0, 0]);
        assert_eq!(frame.nzcv, 0xd000_0000);
        assert_eq!((host.calls, host.address, host.size), (1, 0x1_0000, 0x8000));
    }

    #[test]
    fn munmap_rejects_invalid_ranges_without_touching_the_callback() {
        let mut host = DeallocationHost::default();
        let mut process = Process::new(1, 0, 2);
        process.host_context = (&mut host as *mut DeallocationHost).cast();
        process.vm_deallocate = Some(deallocate);
        for (address, length, error) in [
            (1, 0x4000, 22),
            (0x4000, 0, 22),
            (0x4000, u64::MAX, 12),
            (!PAGE_MASK, 0x4000, 12),
        ] {
            let mut frame = deallocation_frame(address, length);
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result, [error, 0]);
            assert_ne!(frame.nzcv & super::super::CARRY, 0);
        }
        assert_eq!(host.calls, 0);
    }

    #[test]
    fn munmap_preserves_kernel_failures_and_never_reclaims_signed_code() {
        for (result, error) in [(1, 12), (2, 13), (3, 22), (4, 22), (46, 22)] {
            let mut host = DeallocationHost {
                result,
                ..Default::default()
            };
            let mut process = Process::new(1, 0, 2);
            process.host_context = (&mut host as *mut DeallocationHost).cast();
            process.vm_deallocate = Some(deallocate);
            let mut frame = deallocation_frame(0x4000, 0x4000);
            assert!(process.dispatch(&mut frame));
            assert_eq!(host.calls, 1);
            assert_eq!(frame.result, [error, 0]);
            assert_ne!(frame.nzcv & super::super::CARRY, 0);
        }
    }
}
