//! Minimal sysctl namespace, extended from observed dyld requests.
use super::{Process, TrapFrame};

// Private sysctls use kernel-assigned OIDs. This namespace owns its number;
// callers discover it through NAME2OID rather than relying on an Apple number.
const BOOTARGS: [u8; 8] = [1, 0, 0, 0, 1, 0, 77, 72];

fn emit(process: &Process, frame: &TrapFrame, data: &[u8]) -> Option<u32> {
    let read = process.copy_in?;
    let write = process.copy_out?;
    let mut capacity = [0u8; 8];
    if frame.arguments[3] != 0
        && unsafe {
            read(
                process.host_context,
                frame.arguments[3],
                capacity.as_mut_ptr(),
                8,
            )
        } != 0
    {
        return Some(14);
    }
    let capacity = u64::from_le_bytes(capacity).min(usize::MAX as u64) as usize;
    let copied = if frame.arguments[2] == 0 {
        data.len()
    } else {
        capacity.min(data.len())
    };
    if frame.arguments[2] != 0
        && copied != 0
        && unsafe {
            write(
                process.host_context,
                frame.arguments[2],
                data.as_ptr(),
                copied,
            )
        } != 0
    {
        return Some(14);
    }
    if frame.arguments[3] != 0 {
        let length = (copied as u64).to_le_bytes();
        if unsafe { write(process.host_context, frame.arguments[3], length.as_ptr(), 8) } != 0 {
            return Some(14);
        }
    }
    Some(if frame.arguments[2] != 0 && capacity < data.len() {
        12
    } else {
        0
    })
}

pub(super) fn query(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let read = process.copy_in?;
    if frame.arguments[1] != 2 {
        return None;
    }
    let mut mib = [0u8; 8];
    if unsafe {
        read(
            process.host_context,
            frame.arguments[0],
            mib.as_mut_ptr(),
            mib.len(),
        )
    } != 0
    {
        return Some(14);
    }
    if mib == BOOTARGS {
        if frame.arguments[4] != 0 || frame.arguments[5] != 0 {
            return Some(1);
        }
        // This userspace guest has no XNU boot loader arguments or overrides.
        return emit(process, frame, b"\0");
    }
    // CTL_SYSCTL / CTL_SYSCTL_NAME2OID resolves the name in newp to an integer MIB.
    if mib != [0, 0, 0, 0, 3, 0, 0, 0] {
        return None;
    }
    let length = frame.arguments[5];
    if length == 0 || length > 1024 {
        return Some(22);
    }
    let mut name = [0u8; 1024];
    if unsafe {
        read(
            process.host_context,
            frame.arguments[4],
            name.as_mut_ptr(),
            length as usize,
        )
    } != 0
    {
        return Some(14);
    }
    // There is no MAC framework in this compatibility kernel. As on an XNU
    // build without that module, its security.mac sysctl subtree is absent.
    // Return ENOENT, leaving optional-policy fallback decisions to Apple dyld.
    if name[..length as usize].starts_with(b"security.mac.") {
        return Some(2);
    }
    let name = &name[..length as usize];
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    if name == b"kern.bootargs" {
        return emit(process, frame, &BOOTARGS);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    unsafe extern "C" fn read(
        context: *const std::ffi::c_void,
        address: u64,
        out: *mut u8,
        size: usize,
    ) -> u32 {
        let memory = &*(context as *const [u8; 2048]);
        let Some(end) = (address as usize).checked_add(size) else {
            return 14;
        };
        let Some(bytes) = memory.get(address as usize..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, size);
        0
    }
    unsafe extern "C" fn write(
        context: *const std::ffi::c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        let memory = &mut *(context as *mut [u8; 2048]);
        let Some(end) = (address as usize).checked_add(size) else {
            return 14;
        };
        let Some(bytes) = memory.get_mut(address as usize..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), size);
        0
    }
    #[test]
    fn bootargs_name_resolution_and_size_queries_use_guest_lengths() {
        let mut memory = [0xaau8; 2048];
        memory[..8].copy_from_slice(&[0, 0, 0, 0, 3, 0, 0, 0]);
        memory[64..78].copy_from_slice(b"kern.bootargs\0");
        memory[520..528].copy_from_slice(&32u64.to_le_bytes());
        let mut process = Process::new(1, 0, 2);
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        process.host_context = (&mut memory as *mut [u8; 2048]).cast();
        let mut frame = TrapFrame {
            number: 202,
            arguments: [0, 2, 512, 520, 64, 14, 0, 0],
            ..Default::default()
        };
        assert_eq!(query(&process, &frame), Some(0));
        assert_eq!(&memory[512..520], &BOOTARGS);
        assert_eq!(u64::from_le_bytes(memory[520..528].try_into().unwrap()), 8);
        memory[..8].copy_from_slice(&BOOTARGS);
        frame.arguments[4] = 0;
        frame.arguments[5] = 0;
        assert_eq!(query(&process, &frame), Some(0));
        assert_eq!(memory[512], 0);
        assert_eq!(u64::from_le_bytes(memory[520..528].try_into().unwrap()), 1);
        frame.arguments[2] = 0;
        assert_eq!(query(&process, &frame), Some(0));
        assert_eq!(u64::from_le_bytes(memory[520..528].try_into().unwrap()), 1);
        frame.arguments[2] = 512;
        memory[520..528].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(query(&process, &frame), Some(12));
        frame.arguments[4] = 64;
        frame.arguments[5] = 1;
        assert_eq!(query(&process, &frame), Some(1));
    }
    #[test]
    fn absent_mac_namespace_returns_errno_without_inventing_policy_values() {
        let mut memory = [0u8; 2048];
        memory[..8].copy_from_slice(&[0, 0, 0, 0, 3, 0, 0, 0]);
        let name = b"security.mac.lockdown_mode_state";
        memory[64..64 + name.len()].copy_from_slice(name);
        let mut process = Process::new(1, 0, 2);
        process.copy_in = Some(read);
        process.host_context = (&memory as *const [u8; 2048]).cast();
        let mut frame = TrapFrame {
            number: 202,
            arguments: [0, 2, 512, 520, 64, name.len() as u64, 0, 0],
            ..Default::default()
        };
        assert_eq!(query(&process, &frame), Some(2));
        frame.arguments[5] = 1025;
        assert_eq!(query(&process, &frame), Some(22));
        frame.arguments[0] = 2048;
        assert_eq!(query(&process, &frame), Some(14));
        assert_eq!(&memory[512..528], &[0; 16]);
    }
}
