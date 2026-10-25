//! The sandbox kernel extension is not present on the HarmonyOS host.
//!
//! Apple's libsystem uses `sandbox_ms` for a few process-container queries
//! while initializing libdispatch. Only the two audited queries needed by that
//! path are emulated here. All other operations retain the previous ENOSYS
//! failure, so this does not claim MAC policy enforcement or sandbox access.

use super::{Process, TrapFrame};

const EFAULT: u32 = 14;
const ERANGE: u32 = 34;
const GET_CONTAINER_PATH: u64 = 4;
const GET_CONTAINER_EXPECTED: u64 = 67;
const GUEST_ROOT: &[u8] = b"/\0";

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    read_u64(bytes, offset) as i64
}

fn write_u64(process: &Process, copy_out: super::CopyOut, address: u64, value: u64) -> Option<u32> {
    let bytes = value.to_le_bytes();
    let error = unsafe { copy_out(process.host_context, address, bytes.as_ptr(), bytes.len()) };
    (error != 0).then_some(EFAULT)
}

fn get_container_expected(process: &Process, arguments: u64) -> u32 {
    let (Some(copy_in), Some(copy_out)) = (process.copy_in, process.copy_out) else {
        return super::DARWIN_ENOSYS as u32;
    };
    let mut values = [0u8; 16];
    if unsafe {
        copy_in(
            process.host_context,
            arguments,
            values.as_mut_ptr(),
            values.len(),
        )
    } != 0
    {
        return EFAULT;
    }
    let first = read_u64(&values, 0);
    let second = read_u64(&values, 8);
    if first == 0 || second == 0 {
        return EFAULT;
    }
    if let Some(error) = write_u64(process, copy_out, first, 1) {
        return error;
    }
    if let Some(error) = write_u64(process, copy_out, second, 1) {
        return error;
    }
    0
}

fn get_container_path(process: &Process, arguments: u64) -> u32 {
    let (Some(copy_in), Some(copy_out)) = (process.copy_in, process.copy_out) else {
        return super::DARWIN_ENOSYS as u32;
    };
    let mut values = [0u8; 40];
    if unsafe {
        copy_in(
            process.host_context,
            arguments,
            values.as_mut_ptr(),
            values.len(),
        )
    } != 0
    {
        return EFAULT;
    }
    let pid = read_i64(&values, 0);
    let storage_class = read_u64(&values, 8);
    let output = read_u64(&values, 16);
    let output_size = read_u64(&values, 24);
    if pid != i64::from(process.pid) || storage_class != 0 {
        return 22;
    }
    if output == 0 || output_size < GUEST_ROOT.len() as u64 {
        return ERANGE;
    }
    let error = unsafe {
        copy_out(
            process.host_context,
            output,
            GUEST_ROOT.as_ptr(),
            GUEST_ROOT.len(),
        )
    };
    if error != 0 {
        return EFAULT;
    }
    0
}

/// Dispatch the audited `sandbox_ms` operations. `None` identifies an
/// unsupported operation; the caller maps that to Darwin ENOSYS.
pub(super) fn sandbox_ms(process: &Process, frame: &TrapFrame) -> Option<u32> {
    match frame.arguments[1] {
        GET_CONTAINER_PATH => Some(get_container_path(process, frame.arguments[2])),
        GET_CONTAINER_EXPECTED => Some(get_container_expected(process, frame.arguments[2])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    const BASE: u64 = 0x1000;

    struct Memory(Vec<u8>);

    unsafe extern "C" fn copy_in(
        context: *const c_void,
        address: u64,
        output: *mut u8,
        size: usize,
    ) -> u32 {
        let memory = &*(context as *const Memory);
        let Ok(offset) = usize::try_from(address.wrapping_sub(BASE)) else {
            return EFAULT;
        };
        let Some(bytes) = memory.0.get(offset..offset.saturating_add(size)) else {
            return EFAULT;
        };
        if output.is_null() {
            return EFAULT;
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, size);
        0
    }

    unsafe extern "C" fn copy_out(
        context: *const c_void,
        address: u64,
        input: *const u8,
        size: usize,
    ) -> u32 {
        let memory = &mut *(context as *mut Memory);
        let Ok(offset) = usize::try_from(address.wrapping_sub(BASE)) else {
            return EFAULT;
        };
        let Some(bytes) = memory.0.get_mut(offset..offset.saturating_add(size)) else {
            return EFAULT;
        };
        if input.is_null() {
            return EFAULT;
        }
        std::ptr::copy_nonoverlapping(input, bytes.as_mut_ptr(), size);
        0
    }

    fn process(memory: &mut Memory) -> Process {
        let mut process = Process::new(123, 1, 2);
        process.host_context = memory as *mut Memory as *const c_void;
        process.copy_in = Some(copy_in);
        process.copy_out = Some(copy_out);
        process
    }

    fn frame(operation: u64, arguments: u64) -> TrapFrame {
        TrapFrame {
            number: 381,
            arguments: [0, operation, arguments, 0, 0, 0, 0, 0],
            ..Default::default()
        }
    }

    fn store_u64(memory: &mut Memory, offset: usize, value: u64) {
        memory.0[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn container_expectation_sets_both_outputs_and_clears_carry() {
        let mut memory = Memory(vec![0u8; 0x200]);
        store_u64(&mut memory, 0, BASE + 0x100);
        store_u64(&mut memory, 8, BASE + 0x108);
        let process = process(&mut memory);
        let mut trap = frame(GET_CONTAINER_EXPECTED, BASE);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [0, 0]);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        assert_eq!(read_u64(&memory.0, 0x100), 1);
        assert_eq!(read_u64(&memory.0, 0x108), 1);
    }

    #[test]
    fn container_path_uses_the_guest_root_and_validates_the_query() {
        let mut memory = Memory(vec![0u8; 0x200]);
        store_u64(&mut memory, 0, 123);
        store_u64(&mut memory, 8, 0);
        store_u64(&mut memory, 16, BASE + 0x100);
        store_u64(&mut memory, 24, 32);
        store_u64(&mut memory, 32, 0);
        let process = process(&mut memory);
        let mut trap = frame(GET_CONTAINER_PATH, BASE);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [0, 0]);
        assert_eq!(&memory.0[0x100..0x102], b"/\0");

        store_u64(&mut memory, 0, 124);
        let mut trap = frame(GET_CONTAINER_PATH, BASE);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [22, 0]);
        assert_ne!(trap.nzcv & super::super::CARRY, 0);

        store_u64(&mut memory, 0, 123);
        store_u64(&mut memory, 24, 1);
        let mut trap = frame(GET_CONTAINER_PATH, BASE);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [ERANGE as u64, 0]);
    }

    #[test]
    fn malformed_arguments_fault_and_unknown_operations_remain_unsupported() {
        let mut memory = Memory(vec![0u8; 0x200]);
        store_u64(&mut memory, 0, 1);
        store_u64(&mut memory, 8, 0);
        let process = process(&mut memory);
        let mut trap = frame(GET_CONTAINER_EXPECTED, BASE);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [EFAULT as u64, 0]);

        let mut trap = frame(99, BASE);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [super::super::DARWIN_ENOSYS, 0]);
        assert_eq!(
            process
                .unsupported
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn operation_structure_reads_do_not_escape_the_copy_callback() {
        let mut memory = Memory(vec![0u8; 0x40]);
        let process = process(&mut memory);
        let mut trap = frame(GET_CONTAINER_PATH, BASE + 0x20);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [EFAULT as u64, 0]);
    }
}
