//! Calendar time at the Darwin syscall boundary, without host structure casts.
//!
//! ABI: apple-oss-distributions/xnu, bsd/kern/kern_time.c:gettimeofday and
//! bsd/kern/syscalls.master:116. The third, private output is mach absolute time.
use super::{Process, TrapFrame};

pub(super) fn gettimeofday(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let [time, timezone, absolute, ..] = frame.arguments;
    if time == 0 && timezone == 0 && absolute == 0 {
        return Some(0);
    }
    let write = process.copy_out?;
    let mut calendar_ns = 0;
    let mut absolute_ns = 0;
    if time != 0 {
        let clock = process.clock?;
        if unsafe { clock(process.host_context, 2, &mut calendar_ns) } != 0 {
            return Some(5); // Darwin EIO: no calendar sample was obtained.
        }
    }
    if absolute != 0 {
        let clock = process.clock?;
        if unsafe { clock(process.host_context, 0, &mut absolute_ns) } != 0 {
            return Some(5);
        }
    }
    if time != 0 {
        // XNU deliberately truncates calendar seconds to uint32_t even for
        // user64_timeval, matching the arm64 commpage. tv_usec is int32_t;
        // its trailing 32-bit alignment padding is cleared by the kernel.
        let seconds = (calendar_ns / 1_000_000_000) as u32 as u64;
        let micros = ((calendar_ns % 1_000_000_000) / 1_000) as u32;
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&seconds.to_le_bytes());
        bytes[8..12].copy_from_slice(&micros.to_le_bytes());
        if unsafe { write(process.host_context, time, bytes.as_ptr(), bytes.len()) } != 0 {
            return Some(14);
        }
    }
    if timezone != 0 {
        // This compatibility kernel has no settimeofday timezone state. Its
        // timezone remains the XNU initial value: zero minutes west, no DST.
        let bytes = [0u8; 8];
        if unsafe { write(process.host_context, timezone, bytes.as_ptr(), bytes.len()) } != 0 {
            return Some(14);
        }
    }
    if absolute != 0 {
        let bytes = absolute_ns.to_le_bytes();
        if unsafe { write(process.host_context, absolute, bytes.as_ptr(), bytes.len()) } != 0 {
            return Some(14);
        }
    }
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    struct Host {
        memory: [u8; 128],
        calendar_ns: u64,
        absolute_ns: u64,
        clock_error: u32,
        calls: [u32; 3],
    }

    impl Default for Host {
        fn default() -> Self {
            Self {
                memory: [0xaa; 128],
                calendar_ns: 1_792_923_456_987_654_321,
                absolute_ns: 0x1_2345_6789,
                clock_error: 0,
                calls: [0; 3],
            }
        }
    }

    unsafe extern "C" fn clock(context: *const c_void, kind: u32, value: *mut u64) -> u32 {
        let host = &mut *(context as *mut Host);
        let Some(calls) = host.calls.get_mut(kind as usize) else {
            return 46;
        };
        *calls += 1;
        *value = if kind == 2 {
            host.calendar_ns
        } else {
            host.absolute_ns
        };
        host.clock_error
    }

    unsafe extern "C" fn write(
        context: *const c_void,
        address: u64,
        bytes: *const u8,
        size: usize,
    ) -> u32 {
        let host = &mut *(context as *mut Host);
        let Ok(start) = usize::try_from(address) else {
            return 14;
        };
        let Some(end) = start.checked_add(size) else {
            return 14;
        };
        let Some(destination) = host.memory.get_mut(start..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(bytes, destination.as_mut_ptr(), size);
        0
    }

    fn process(host: &mut Host) -> Process {
        let mut process = Process::new(1, 0, 2);
        process.host_context = (host as *mut Host).cast();
        process.copy_out = Some(write);
        process.clock = Some(clock);
        process
    }

    fn frame(arguments: [u64; 3]) -> TrapFrame {
        TrapFrame {
            number: 116,
            arguments: [arguments[0], arguments[1], arguments[2], 0, 0, 0, 0, 0],
            nzcv: 0xf000_0000,
            ..Default::default()
        }
    }

    #[test]
    fn calendar_layout_uses_microseconds_and_the_guest_absolute_timebase() {
        let mut host = Host::default();
        let process = process(&mut host);
        let mut frame = frame([16, 48, 72]);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [0, 0]);
        assert_eq!(frame.nzcv, 0xd000_0000);
        assert_eq!(frame.arguments[..3], [16, 48, 72]);
        assert_eq!(host.calls, [1, 0, 1]);
        assert_eq!(
            u64::from_le_bytes(host.memory[16..24].try_into().unwrap()),
            1_792_923_456
        );
        assert_eq!(
            u32::from_le_bytes(host.memory[24..28].try_into().unwrap()),
            987_654
        );
        assert_eq!(&host.memory[28..32], &[0; 4]);
        assert_eq!(&host.memory[48..56], &[0; 8]);
        assert_eq!(&host.memory[72..80], &host.absolute_ns.to_le_bytes());
        for range in [0..16, 32..48, 56..72, 80..128] {
            assert!(host.memory[range].iter().all(|&byte| byte == 0xaa));
        }
    }

    #[test]
    fn null_outputs_and_timezone_only_do_not_require_a_clock() {
        let process_without_callbacks = Process::new(1, 0, 2);
        assert_eq!(
            gettimeofday(&process_without_callbacks, &frame([0, 0, 0])),
            Some(0)
        );
        assert_eq!(
            gettimeofday(&process_without_callbacks, &frame([16, 0, 0])),
            None
        );
        let mut host = Host::default();
        let mut process = process(&mut host);
        process.clock = None;
        assert_eq!(gettimeofday(&process, &frame([0, 48, 0])), Some(0));
        assert_eq!(host.calls, [0; 3]);
        assert_eq!(&host.memory[48..56], &[0; 8]);
    }

    #[test]
    fn clock_failure_and_invalid_guest_memory_return_bsd_errors() {
        let mut host = Host {
            clock_error: 46,
            ..Default::default()
        };
        let process = process(&mut host);
        let mut frame = frame([16, 48, 72]);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result, [5, 0]);
        assert_eq!(frame.nzcv, 0xf000_0000);
        assert!(host.memory.iter().all(|&byte| byte == 0xaa));
        let mut host = Host::default();
        let process = self::process(&mut host);
        for arguments in [[120, 48, 72], [0, 124, 72], [0, 0, u64::MAX]] {
            frame.arguments[..3].copy_from_slice(&arguments);
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result, [14, 0]);
            assert_ne!(frame.nzcv & super::super::CARRY, 0);
        }
    }

    #[test]
    fn seconds_truncation_matches_the_arm64_commpage_contract() {
        let mut host = Host {
            calendar_ns: (u32::MAX as u64 + 3) * 1_000_000_000 + 999,
            ..Default::default()
        };
        let process = process(&mut host);
        assert_eq!(gettimeofday(&process, &frame([16, 0, 0])), Some(0));
        assert_eq!(&host.memory[16..24], &2u64.to_le_bytes());
        assert_eq!(&host.memory[24..32], &[0; 8]);
    }
}
