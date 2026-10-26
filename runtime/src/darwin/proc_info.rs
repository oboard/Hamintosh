//! Darwin proc_info(2) queries that can be answered by the compatibility
//! process model. XNU returns fixed ABI structures; unsupported flavors remain
//! explicit errors instead of returning partial success.
use super::{Process, TrapFrame};

const PROC_INFO_CALL_PIDINFO: u64 = 2;
const PROC_PIDPATHINFO: u64 = 2;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
const MAXPATHLEN: usize = 1024;
const PROC_PIDUNIQIDENTIFIERINFO: u64 = 17;
const PROC_PIDUNIQIDENTIFIERINFO_SIZE: usize = 56;
const ESRCH: u32 = 3;
const ENOMEM: u32 = 12;
const EFAULT: u32 = 14;
const EINVAL: u32 = 22;

fn unique_identity(pid: u32, generation: u32) -> u64 {
    (u64::from(pid) << 32) | u64::from(generation)
}

fn write_struct(process: &Process) -> [u8; PROC_PIDUNIQIDENTIFIERINFO_SIZE] {
    let mut bytes = [0u8; PROC_PIDUNIQIDENTIFIERINFO_SIZE];
    // p_uuid remains zero until the native App header supplies LC_UUID. It is
    // deliberately not replaced with a random or path-derived fake UUID.
    bytes[16..24]
        .copy_from_slice(&unique_identity(process.pid, process.thread_id as u32).to_le_bytes());
    bytes[24..32].copy_from_slice(&unique_identity(process.parent_pid, 1).to_le_bytes());
    bytes[32..36].copy_from_slice(&1u32.to_le_bytes()); // p_idversion
    bytes[36..40].copy_from_slice(&1u32.to_le_bytes()); // p_orig_ppidversion
    bytes
}

pub(super) fn query(process: &Process, frame: &TrapFrame) -> Option<(u32, u64)> {
    let call = frame.arguments[0];
    let pid = frame.arguments[1] as u32;
    let flavor = frame.arguments[2];
    if call != PROC_INFO_CALL_PIDINFO {
        return Some((EINVAL, 0));
    }
    if pid != process.pid {
        return Some((ESRCH, 0));
    }
    let buffer = frame.arguments[4];
    let size = frame.arguments[5];
    let Some(copy_out) = process.copy_out else {
        return Some((EFAULT, 0));
    };
    if flavor == PROC_PIDPATHINFO {
        if !(MAXPATHLEN as u64..=PROC_PIDPATHINFO_MAXSIZE as u64).contains(&size) {
            return Some((ENOMEM, 0));
        }
        if buffer == 0 || process.executable.is_null() || process.executable_len >= MAXPATHLEN {
            return Some((ENOMEM, 0));
        }
        let mut path = [0u8; MAXPATHLEN];
        let source = unsafe {
            std::slice::from_raw_parts(process.executable.cast::<u8>(), process.executable_len)
        };
        path[..source.len()].copy_from_slice(source);
        let error = unsafe { copy_out(process.host_context, buffer, path.as_ptr(), path.len()) };
        return Some(if error == 0 { (0, 0) } else { (EFAULT, 0) });
    }
    if flavor != PROC_PIDUNIQIDENTIFIERINFO {
        return Some((EINVAL, 0));
    }
    if buffer == 0 || size < PROC_PIDUNIQIDENTIFIERINFO_SIZE as u64 {
        return Some((ENOMEM, 0));
    }
    let bytes = write_struct(process);
    let error = unsafe { copy_out(process.host_context, buffer, bytes.as_ptr(), bytes.len()) };
    if error != 0 {
        Some((EFAULT, 0))
    } else {
        Some((0, PROC_PIDUNIQIDENTIFIERINFO_SIZE as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    unsafe extern "C" fn write(
        context: *const c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        if address != 0x100 || size > MAXPATHLEN {
            return EFAULT;
        }
        let bytes = &mut *(context as *mut [u8; MAXPATHLEN]);
        std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), size);
        0
    }

    fn frame(pid: u32, flavor: u64, size: u64) -> TrapFrame {
        TrapFrame {
            number: 336,
            arguments: [
                PROC_INFO_CALL_PIDINFO,
                u64::from(pid),
                flavor,
                0,
                0x100,
                size,
                0,
                0,
            ],
            nzcv: 0xf000_0000,
            ..Default::default()
        }
    }

    #[test]
    fn unique_identifier_flavor_writes_the_exact_darwin_abi() {
        let mut process = Process::new(1234, 5678, 0x99aa_bbcc);
        let mut output = [0u8; MAXPATHLEN];
        process.host_context = output.as_mut_ptr().cast();
        process.copy_out = Some(write);
        let mut frame = frame(1234, PROC_PIDUNIQIDENTIFIERINFO, 56);
        assert_eq!(
            query(&process, &frame),
            Some((0, PROC_PIDUNIQIDENTIFIERINFO_SIZE as u64))
        );
        assert_eq!(&output[..16], &[0; 16]);
        assert_eq!(
            u64::from_le_bytes(output[16..24].try_into().unwrap()),
            unique_identity(1234, 0x99aa_bbcc)
        );
        assert_eq!(
            u64::from_le_bytes(output[24..32].try_into().unwrap()),
            unique_identity(5678, 1)
        );
        assert_eq!(u32::from_le_bytes(output[32..36].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(output[36..40].try_into().unwrap()), 1);
        assert!(output[40..].iter().all(|byte| *byte == 0));
        frame.arguments[1] = 1235;
        assert_eq!(query(&process, &frame), Some((ESRCH, 0)));
        frame.arguments[1] = 1234;
        frame.arguments[2] = 4;
        assert_eq!(query(&process, &frame), Some((EINVAL, 0)));
        frame.arguments[2] = PROC_PIDUNIQIDENTIFIERINFO;
        frame.arguments[5] = 55;
        assert_eq!(query(&process, &frame), Some((ENOMEM, 0)));
        frame.arguments[5] = 56;
        frame.arguments[4] = 0;
        assert_eq!(query(&process, &frame), Some((ENOMEM, 0)));
        frame.arguments[4] = 0x200;
        assert_eq!(query(&process, &frame), Some((EFAULT, 0)));
        frame.arguments[0] = 7;
        frame.arguments[4] = 0x100;
        assert_eq!(query(&process, &frame), Some((EINVAL, 0)));
    }

    #[test]
    fn process_path_flavor_copies_the_real_app_executable() {
        let path = b"/data/apps/SwiftUIHelloWorld.app/SwiftUIHelloWorld";
        let mut process = Process::new(1234, 1, 2);
        process.executable = path.as_ptr().cast();
        process.executable_len = path.len();
        let mut output = [0xAAu8; MAXPATHLEN];
        process.host_context = output.as_mut_ptr().cast();
        process.copy_out = Some(write);
        let mut frame = frame(1234, PROC_PIDPATHINFO, MAXPATHLEN as u64);
        assert_eq!(query(&process, &frame), Some((0, 0)));
        assert_eq!(&output[..path.len()], path);
        assert_eq!(output[path.len()], 0);
        assert!(output[path.len() + 1..].iter().all(|byte| *byte == 0));
        frame.arguments[5] = (MAXPATHLEN - 1) as u64;
        assert_eq!(query(&process, &frame), Some((ENOMEM, 0)));
        frame.arguments[5] = (PROC_PIDPATHINFO_MAXSIZE + 1) as u64;
        assert_eq!(query(&process, &frame), Some((ENOMEM, 0)));
    }
}
