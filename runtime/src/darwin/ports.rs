//! Bounded Mach port fast paths. ABI and error conventions follow XNU
//! osfmk/ipc/mach_kernelrpc.c, mach_port.c and bsd/libkern/copyio.h.
//! Transfers between different names and EXC_GUARD delivery remain explicit
//! unsupported boundaries; successful calls update actual process-owned rights.
use super::{Process, TrapFrame};

fn copy_word(process: &Process, address: u64, value: u32) -> u32 {
    let Some(write) = process.copy_out else {
        return 10;
    };
    if unsafe {
        write(
            process.host_context,
            address,
            value.to_le_bytes().as_ptr(),
            4,
        )
    } == 0
    {
        0
    } else {
        10 // KERN_MEMORY_ERROR, as mach_copyout (not BSD EFAULT).
    }
}

pub(super) fn dispatch(process: &Process, frame: &TrapFrame) -> Option<u32> {
    if frame.arguments[0] as u32 != 0x103 {
        return None;
    }
    let name = frame.arguments[1] as u32;
    match frame.number as i32 {
        -76 => Some(match process.ports.port_type(name) {
            Ok(rights) => copy_word(process, frame.arguments[2], rights),
            Err(error) => error,
        }),
        -16 if frame.arguments[1] as u32 == 1 => {
            // MACH_PORT_RIGHT_RECEIVE. Port sets/dead-name allocations need
            // their own rights model and are not silently allocated as ports.
            let name = match process.ports.construct(0) {
                Ok(name) => name,
                Err(error) => return Some(error),
            };
            let error = copy_word(process, frame.arguments[2], name);
            if error != 0 {
                process.ports.discard_unpublished(name);
            }
            Some(error)
        }
        -21 if name == frame.arguments[2] as u32
            && matches!(frame.arguments[3] as u32, 19 | 20)
            && name != u32::MAX =>
        {
            Some(
                process
                    .ports
                    .insert_send(name, frame.arguments[3] as u32 == 20),
            )
        }
        -41 | -42 => {
            // Invalid calls can raise EXC_GUARD in XNU. Stop explicitly until
            // guest exception delivery exists, leaving the guard untouched.
            if !process.ports.has_receive(name) {
                return None;
            }
            let error = if frame.number as i32 == -41 {
                process
                    .ports
                    .apply_guard(name, frame.arguments[2], frame.arguments[3] as u32 != 0)
            } else {
                process.ports.remove_guard(name, frame.arguments[2])
            };
            (error == 0).then_some(0)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::CARRY;
    use std::ffi::c_void;

    unsafe extern "C" fn write(
        context: *const c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        if address != 32 || size != 4 {
            return 14;
        }
        std::ptr::copy_nonoverlapping(data, (context as *mut u8).add(32), size);
        0
    }

    #[test]
    fn rights_lifecycle_is_visible_through_traps_and_copyout_is_bounded() {
        let mut memory = [0u8; 40];
        let mut process = Process::new(1, 0, 2);
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_out = Some(write);
        let mut frame = TrapFrame {
            number: -16,
            arguments: [0x103, 1, 999, 0, 0, 0, 0, 0],
            nzcv: CARRY,
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 10);
        assert_eq!(frame.nzcv & CARRY, 0);
        frame.arguments[2] = 32;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        let name = u32::from_le_bytes(memory[32..36].try_into().unwrap());
        assert_eq!(name, 0x403); // unpublished failed allocation was rolled back
        frame.number = -76;
        frame.arguments[1] = name as u64;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert_eq!(
            u32::from_le_bytes(memory[32..36].try_into().unwrap()),
            1 << 17
        );
        frame.number = -21;
        frame.arguments[2] = name as u64;
        frame.arguments[3] = 19; // COPY_SEND cannot manufacture a first send right
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 17);
        frame.arguments[3] = 20; // MAKE_SEND uses the owned receive right
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        frame.arguments[3] = 19;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert_eq!(process.ports.port_type(name), Ok((1 << 17) | (1 << 16)));
        assert_eq!(process.ports.modify_send_refs(name, -2), 0);
        assert_eq!(process.ports.port_type(name), Ok(1 << 17));
    }

    #[test]
    fn null_dead_stale_names_and_copyout_failures_are_distinct() {
        let process = Process::new(1, 0, 2);
        let name = process.ports.construct(0).unwrap();
        for (name, expected) in [(0, 15), (name ^ 1, 15), (name, 10), (u32::MAX, 10)] {
            let mut frame = TrapFrame {
                number: -76,
                arguments: [0x103, name as u64, 999, 0, 0, 0, 0, 0],
                ..Default::default()
            };
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], expected);
        }
        assert_eq!(process.ports.port_type(u32::MAX), Ok(1 << 20));
        let mut frame = TrapFrame {
            number: -76,
            arguments: [0x203, name as u64, 32, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(!process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 46);
    }

    #[test]
    fn guard_operations_preserve_state_when_exception_delivery_is_needed() {
        let process = Process::new(1, 0, 2);
        let name = process.ports.construct(0).unwrap();
        let mut frame = TrapFrame {
            number: -41,
            arguments: [0x103, name as u64, 0x1234, 1, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), Some(0x1234));
        assert!(!process.dispatch(&mut frame));
        frame.number = -42;
        frame.arguments[2] = 0x9999;
        assert!(!process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), Some(0x1234));
        frame.arguments[2] = 0x1234;
        assert!(process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), None);
        frame.number = -41;
        frame.arguments[2] = 0; // A zero guard is valid and still guarded.
        assert!(process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), Some(0));
        assert!(process.dispatch(&mut frame)); // XNU permits reapplying a zero context
        frame.number = -42;
        assert!(process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), None);
    }

    #[test]
    fn unmodeled_rights_and_transfers_do_not_mutate_the_space() {
        let process = Process::new(1, 0, 2);
        for right in [0, 2, 3, 4, u32::MAX] {
            let mut frame = TrapFrame {
                number: -16,
                arguments: [0x103, right as u64, 32, 0, 0, 0, 0, 0],
                ..Default::default()
            };
            assert!(!process.dispatch(&mut frame));
        }
        let name = process.ports.construct(0).unwrap();
        assert_eq!(name, 0x403);
        let mut frame = TrapFrame {
            number: -21,
            arguments: [0x103, name as u64, name as u64 + 256, 20, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(!process.dispatch(&mut frame));
        assert_eq!(process.ports.port_type(name), Ok(1 << 17));
    }
}
