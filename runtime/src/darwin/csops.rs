//! Darwin `csops(2)` status translation for the single guest process.
//!
//! The observed libSystem call is `CS_OPS_STATUS` with a four-byte result.
//! Code-signature mutation, path, blob and entitlement queries need separate
//! kernel semantics and remain unsupported until they are actually observed.

use super::{Process, TrapFrame};
use std::mem::size_of;

const ESRCH: u32 = 3;
const EFAULT: u32 = 14;
const EINVAL: u32 = 22;

const CS_OPS_STATUS: u64 = 0;
const CS_VALID: u32 = 0x0000_0001;
const CS_SIGNED: u32 = 0x2000_0000;

/// Handle the status query justified by the packaged, signed App executable.
///
/// `pid == 0` addresses the caller in XNU. This process model has exactly one
/// guest process, so either zero or its recorded PID is accepted. Returning
/// `None` leaves an unobserved operation on the explicit unsupported path.
pub(super) fn csops(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let [pid, operation, address, size, ..] = frame.arguments;
    let Ok(pid) = u32::try_from(pid) else {
        return Some(ESRCH);
    };
    if pid != 0 && pid != process.pid {
        return Some(ESRCH);
    }
    if operation != CS_OPS_STATUS {
        return None;
    }
    if size < size_of::<u32>() as u64 {
        return Some(EINVAL);
    }
    let write = process.copy_out?;
    let status = (CS_VALID | CS_SIGNED).to_le_bytes();
    let error = unsafe { write(process.host_context, address, status.as_ptr(), status.len()) };
    Some(if error == 0 { 0 } else { EFAULT })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    struct Host {
        bytes: [u8; 8],
        calls: u32,
    }

    impl Default for Host {
        fn default() -> Self {
            Self {
                bytes: [0xaa; 8],
                calls: 0,
            }
        }
    }

    unsafe extern "C" fn write(
        context: *const c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        if address != 0x100 || size != 4 {
            return EFAULT;
        }
        let host = &mut *(context as *mut Host);
        host.calls += 1;
        std::ptr::copy_nonoverlapping(data, host.bytes.as_mut_ptr(), size);
        0
    }

    fn process(host: &mut Host) -> Process {
        let mut process = Process::new(41_134, 1, 2);
        process.host_context = (host as *mut Host).cast();
        process.copy_out = Some(write);
        process
    }

    fn frame(pid: u64, operation: u64, size: u64) -> TrapFrame {
        TrapFrame {
            number: 169,
            arguments: [pid, operation, 0x100, size, 0, 0, 0, 0],
            ..Default::default()
        }
    }

    #[test]
    fn status_accepts_zero_or_the_current_pid_and_reports_signed_valid_code() {
        let mut host = Host::default();
        let process = process(&mut host);
        for pid in [0, u64::from(process.pid)] {
            host.bytes = [0xaa; 8];
            let mut call = frame(pid, CS_OPS_STATUS, 4);
            assert_eq!(csops(&process, &call), Some(0));
            assert_eq!(
                u32::from_le_bytes(host.bytes[..4].try_into().unwrap()),
                CS_VALID | CS_SIGNED
            );
            assert_eq!(&host.bytes[4..], &[0xaa; 4]);
            call.arguments[3] = 8;
            assert_eq!(csops(&process, &call), Some(0));
        }
        assert_eq!(host.calls, 4); // only the requested four-byte prefix is copied
    }

    #[test]
    fn unknown_pid_operation_and_short_output_do_not_touch_guest_memory() {
        let mut host = Host::default();
        let process = process(&mut host);
        assert_eq!(csops(&process, &frame(1, CS_OPS_STATUS, 4)), Some(ESRCH));
        assert_eq!(
            csops(&process, &frame(u64::MAX, CS_OPS_STATUS, 4)),
            Some(ESRCH)
        );
        assert_eq!(csops(&process, &frame(0, 1, 4)), None);
        assert_eq!(csops(&process, &frame(0, CS_OPS_STATUS, 3)), Some(EINVAL));
        assert_eq!(host.calls, 0);
        assert_eq!(host.bytes, [0xaa; 8]);
    }

    #[test]
    fn guest_copy_failure_is_efault() {
        let mut host = Host::default();
        let process = process(&mut host);
        let mut call = frame(0, CS_OPS_STATUS, 4);
        call.arguments[2] = 0x200;
        assert_eq!(csops(&process, &call), Some(EFAULT));
        assert_eq!(host.bytes, [0xaa; 8]);
    }
}
