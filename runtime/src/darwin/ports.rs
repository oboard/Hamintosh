//! Bounded Mach port fast paths. ABI and error conventions follow XNU
//! osfmk/ipc/mach_kernelrpc.c, mach_port.c and bsd/libkern/copyio.h.
//! Transfers between different names and EXC_GUARD delivery remain explicit
//! unsupported boundaries; successful calls update actual process-owned rights.
use super::{Process, TrapFrame};
use std::mem::size_of;

const SELF_TASK_PORT: u32 = 0x103;
const MACH_PORT_NULL: u32 = 0;
const MACH_PORT_DEAD: u32 = u32::MAX;
const NO_PORT_OPTIONS: u32 = 0;
#[cfg(test)]
const MACH_PORT_TYPE_SEND: u32 = 1 << 16;
#[cfg(test)]
const MACH_PORT_TYPE_RECEIVE: u32 = 1 << 17;
#[cfg(test)]
const MACH_PORT_TYPE_PORT_SET: u32 = 1 << 19;
#[cfg(test)]
const MACH_PORT_TYPE_DEAD_NAME: u32 = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
enum MachTrap {
    PortType = -76,
    PortGetAttributes = -40,
    PortDestruct = -25,
    PortAllocate = -16,
    PortInsertRight = -21,
    PortInsertMember = -22,
    PortExtractMember = -23,
    PortGuard = -41,
    PortUnguard = -42,
    TimerCreate = -91,
    TimerDestroy = -92,
    TimerArm = -93,
    TimerCancel = -94,
    TimerArmLeeway = -95,
}

impl MachTrap {
    fn from_raw(value: i64) -> Option<Self> {
        Some(match value {
            -76 => Self::PortType,
            -40 => Self::PortGetAttributes,
            -25 => Self::PortDestruct,
            -16 => Self::PortAllocate,
            -21 => Self::PortInsertRight,
            -22 => Self::PortInsertMember,
            -23 => Self::PortExtractMember,
            -41 => Self::PortGuard,
            -42 => Self::PortUnguard,
            -91 => Self::TimerCreate,
            -92 => Self::TimerDestroy,
            -93 => Self::TimerArm,
            -94 => Self::TimerCancel,
            -95 => Self::TimerArmLeeway,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum PortRight {
    Receive = 1,
    PortSet = 3,
}

impl PortRight {
    fn from_raw(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::Receive,
            3 => Self::PortSet,
            _ => return None,
        })
    }

    #[cfg(test)]
    const fn raw(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum PortDisposition {
    CopySend = 19,
    MakeSend = 20,
}

impl PortDisposition {
    fn from_raw(value: u32) -> Option<Self> {
        Some(match value {
            19 => Self::CopySend,
            20 => Self::MakeSend,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
enum KernReturn {
    Success = 0,
    Failure = 1,
    NoSpace = 6,
    MemoryError = 10,
    #[cfg(test)]
    AlreadyInSet = 11,
    #[cfg(test)]
    NotInSet = 12,
    #[cfg(test)]
    InvalidName = 15,
    #[cfg(test)]
    InvalidRight = 17,
    #[cfg(test)]
    NotSupported = 46,
}

impl KernReturn {
    const fn code(self) -> u32 {
        self as u32
    }
}

fn copy_word(process: &Process, address: u64, value: u32) -> u32 {
    let Some(write) = process.copy_out else {
        return KernReturn::MemoryError.code();
    };
    if unsafe {
        write(
            process.host_context,
            address,
            value.to_le_bytes().as_ptr(),
            size_of::<u32>(),
        )
    } == 0
    {
        KernReturn::Success.code()
    } else {
        // mach_copyout reports KERN_MEMORY_ERROR rather than BSD EFAULT.
        KernReturn::MemoryError.code()
    }
}

pub(super) fn dispatch(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let trap = MachTrap::from_raw(frame.number)?;

    match trap {
        MachTrap::TimerCreate => {
            return Some(process.ports.construct_timer().unwrap_or(MACH_PORT_NULL));
        }
        MachTrap::TimerDestroy => return Some(process.ports.destroy(frame.arguments[0] as u32)),
        MachTrap::TimerArm | MachTrap::TimerArmLeeway => {
            return Some(
                process
                    .ports
                    .arm_timer(frame.arguments[0] as u32, frame.arguments[1]),
            );
        }
        MachTrap::TimerCancel => {
            let result = match process.ports.cancel_timer(frame.arguments[0] as u32) {
                Ok(_deadline) if frame.arguments[1] == 0 => KernReturn::Success.code(),
                Ok(deadline) => match process.copy_out {
                    Some(write) => unsafe {
                        write(
                            process.host_context,
                            frame.arguments[1],
                            deadline.to_le_bytes().as_ptr(),
                            size_of::<u64>(),
                        )
                    },
                    None => KernReturn::Failure.code(),
                },
                Err(error) => error,
            };
            return Some(result);
        }
        _ => {}
    }

    if frame.arguments[0] as u32 != SELF_TASK_PORT {
        return None;
    }
    let name = frame.arguments[1] as u32;
    match trap {
        MachTrap::PortDestruct => {
            let error =
                process
                    .ports
                    .destruct(name, frame.arguments[2] as u32 as i32, frame.arguments[3]);
            // Guard violations require EXC_GUARD delivery. Keep the attempt
            // terminal while that exception transport remains unavailable.
            match error {
                4 | 46 => None,
                error => Some(error),
            }
        }
        MachTrap::PortGetAttributes => {
            let (Some(read), Some(write)) = (process.copy_in, process.copy_out) else {
                return Some(10);
            };
            let mut count = [0u8; 4];
            if unsafe {
                read(
                    process.host_context,
                    frame.arguments[4],
                    count.as_mut_ptr(),
                    4,
                )
            } != 0
            {
                return Some(10);
            }
            if frame.arguments[2] != 1 {
                return Some(4);
            }
            if u32::from_le_bytes(count) < 1 {
                return Some(5);
            }
            if name == 0 || name == u32::MAX {
                return Some(copy_word(process, frame.arguments[4], 0));
            }
            let limit = match process.ports.queue_limit(name) {
                Ok(value) => value,
                Err(error) => return Some(error),
            };
            if copy_word(process, frame.arguments[4], 1) != 0 {
                return Some(10);
            }
            Some(
                if unsafe {
                    write(
                        process.host_context,
                        frame.arguments[3],
                        limit.to_le_bytes().as_ptr(),
                        4,
                    )
                } == 0
                {
                    0
                } else {
                    10
                },
            )
        }
        MachTrap::PortType => Some(match process.ports.port_type(name) {
            Ok(rights) => copy_word(process, frame.arguments[2], rights),
            Err(error) => error,
        }),
        MachTrap::PortAllocate => {
            let right = PortRight::from_raw(frame.arguments[1] as u32)?;
            let allocated = match right {
                PortRight::Receive => process.ports.construct(NO_PORT_OPTIONS),
                PortRight::PortSet => process
                    .ports
                    .allocate_port_set()
                    .ok_or(KernReturn::NoSpace.code()),
            };
            let name = match allocated {
                Ok(name) => name,
                Err(error) => return Some(error),
            };
            let error = copy_word(process, frame.arguments[2], name);
            if error != KernReturn::Success.code() {
                process.ports.discard_unpublished(name);
            }
            Some(error)
        }
        MachTrap::PortInsertMember => {
            Some(process.ports.insert_member(name, frame.arguments[2] as u32))
        }
        MachTrap::PortExtractMember => Some(
            process
                .ports
                .extract_member(name, frame.arguments[2] as u32),
        ),
        MachTrap::PortInsertRight => {
            let disposition = PortDisposition::from_raw(frame.arguments[3] as u32)?;
            if name != frame.arguments[2] as u32 || name == MACH_PORT_DEAD {
                return None;
            }
            Some(
                process
                    .ports
                    .insert_send(name, disposition == PortDisposition::MakeSend),
            )
        }
        MachTrap::PortGuard | MachTrap::PortUnguard => {
            // Invalid calls can raise EXC_GUARD in XNU. Stop explicitly until
            // guest exception delivery exists, leaving the guard untouched.
            if !process.ports.has_receive(name) {
                return None;
            }
            let error = if trap == MachTrap::PortGuard {
                process
                    .ports
                    .apply_guard(name, frame.arguments[2], frame.arguments[3] as u32 != 0)
            } else {
                process.ports.remove_guard(name, frame.arguments[2])
            };
            (error == KernReturn::Success.code()).then_some(KernReturn::Success.code())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::darwin::CARRY;
    use std::ffi::c_void;

    #[test]
    fn port_limits_query_uses_owned_receive_right_and_preserves_errors() {
        unsafe extern "C" fn read(ctx: *const c_void, addr: u64, out: *mut u8, len: usize) -> u32 {
            if addr > 128 || len > 128 - addr as usize {
                return 10;
            }
            std::ptr::copy_nonoverlapping((ctx as *const u8).add(addr as usize), out, len);
            0
        }
        unsafe extern "C" fn copy(
            ctx: *const c_void,
            addr: u64,
            data: *const u8,
            len: usize,
        ) -> u32 {
            if addr > 128 || len > 128 - addr as usize {
                return 10;
            }
            std::ptr::copy_nonoverlapping(data, (ctx as *mut u8).add(addr as usize), len);
            0
        }
        let mut memory = [0xa5u8; 128];
        memory[64..68].copy_from_slice(&2u32.to_le_bytes());
        let mut process = Process::new(1, 0, 2);
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(copy);
        let name = process.ports.construct(0x10).unwrap();
        let mut trap = trap_frame(
            MachTrap::PortGetAttributes,
            [0x103, name.into(), 1, 32, 64, 0, 0, 0],
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0], 0);
        assert_eq!(u32::from_le_bytes(memory[32..36].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(memory[64..68].try_into().unwrap()), 1);
        process.ports.set_queue_limit(name, 1024).unwrap();
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0], 0);
        assert_eq!(u32::from_le_bytes(memory[32..36].try_into().unwrap()), 1024);
        assert_eq!(process.ports.set_queue_limit(name, 1025), Err(18));
        assert!(process.ports.acquire_send(0x103));
        for (port, flavor, count, error) in [
            (name, 1, 0u32, 5),
            (name, 99, 1, 4),
            (0xbeef, 1, 1, 15),
            (0x103, 1, 1, 17),
        ] {
            memory[64..68].copy_from_slice(&count.to_le_bytes());
            let before = memory;
            trap.arguments[1] = port.into();
            trap.arguments[2] = flavor;
            assert!(process.dispatch(&mut trap));
            assert_eq!(trap.result[0], error);
            assert_eq!(memory, before);
        }
        for port in [0u32, u32::MAX] {
            memory[64..68].copy_from_slice(&1u32.to_le_bytes());
            trap.arguments[1] = port.into();
            trap.arguments[2] = 1;
            let before = memory[32..36].to_vec();
            assert!(process.dispatch(&mut trap));
            assert_eq!(trap.result[0], 0);
            assert_eq!(&memory[32..36], before.as_slice());
            assert_eq!(u32::from_le_bytes(memory[64..68].try_into().unwrap()), 0);
        }
        trap.arguments[1] = name.into();
        trap.arguments[2] = 1;
        trap.arguments[4] = 126;
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0], 10);
    }

    const OUTPUT_ADDRESS: u64 = 32;
    const GUARD_CONTEXT: u64 = 0x1234;
    const OTHER_GUARD_CONTEXT: u64 = 0x9999;
    const TIMER_DEADLINE: u64 = 0x1234;
    const INVALID_ADDRESS: u64 = 999;

    unsafe extern "C" fn write(
        context: *const c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        if address != OUTPUT_ADDRESS || (size != size_of::<u32>() && size != size_of::<u64>()) {
            return KernReturn::MemoryError.code();
        }
        std::ptr::copy_nonoverlapping(data, (context as *mut u8).add(address as usize), size);
        KernReturn::Success.code()
    }

    fn trap_frame(number: MachTrap, arguments: [u64; 8]) -> TrapFrame {
        TrapFrame {
            number: number as i64,
            arguments,
            ..Default::default()
        }
    }

    fn code(error: KernReturn) -> u64 {
        error.code() as u64
    }

    fn task_arguments(name: u32, address: u64) -> [u64; 8] {
        [SELF_TASK_PORT as u64, name as u64, address, 0, 0, 0, 0, 0]
    }

    #[test]
    fn destruct_trap_changes_receive_rights_without_returning_fake_guard_success() {
        let process = Process::new(1, 0, 2);
        let name = process.ports.construct(0).unwrap();
        let mut frame = trap_frame(
            MachTrap::PortDestruct,
            [0x103, name.into(), 0, 0, 0, 0, 0, 0],
        );
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert!(!process.ports.has_receive(name));
        let guarded = process.ports.construct(0x10).unwrap();
        process.ports.apply_guard(guarded, 42, true);
        frame.arguments[1] = guarded.into();
        assert!(!process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 46);
        assert!(process.ports.has_receive(guarded));
        frame.arguments[2] = (-1i64) as u64;
        frame.arguments[3] = 42;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert_eq!(process.ports.port_type(guarded), Err(15));
    }

    #[test]
    fn rights_lifecycle_is_visible_through_traps_and_copyout_is_bounded() {
        let mut memory = [0u8; 40];
        let mut process = Process::new(1, 0, 2);
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_out = Some(write);
        let mut frame = trap_frame(
            MachTrap::PortAllocate,
            [
                SELF_TASK_PORT as u64,
                PortRight::Receive.raw() as u64,
                INVALID_ADDRESS,
                0,
                0,
                0,
                0,
                0,
            ],
        );
        frame.nzcv = CARRY;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::MemoryError));
        assert_eq!(frame.nzcv & CARRY, 0);
        frame.arguments[2] = OUTPUT_ADDRESS;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        let name = u32::from_le_bytes(
            memory[OUTPUT_ADDRESS as usize..OUTPUT_ADDRESS as usize + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(name >> 8, 4); // slot rolled back; generation still advances
        frame = trap_frame(MachTrap::PortType, task_arguments(name, OUTPUT_ADDRESS));
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        assert_eq!(
            u32::from_le_bytes(
                memory[OUTPUT_ADDRESS as usize..OUTPUT_ADDRESS as usize + 4]
                    .try_into()
                    .unwrap()
            ),
            MACH_PORT_TYPE_RECEIVE
        );
        frame = trap_frame(
            MachTrap::PortInsertRight,
            [
                SELF_TASK_PORT as u64,
                name as u64,
                name as u64,
                PortDisposition::CopySend as u64,
                0,
                0,
                0,
                0,
            ],
        );
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::InvalidRight));
        frame.arguments[3] = PortDisposition::MakeSend as u64;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        frame.arguments[3] = PortDisposition::CopySend as u64;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        assert_eq!(
            process.ports.port_type(name),
            Ok(MACH_PORT_TYPE_RECEIVE | MACH_PORT_TYPE_SEND)
        );
        assert_eq!(process.ports.modify_send_refs(name, -2), 0);
        assert_eq!(process.ports.port_type(name), Ok(MACH_PORT_TYPE_RECEIVE));
    }

    #[test]
    fn timer_traps_create_arm_cancel_and_destroy_a_receive_port() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 72];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_out = Some(write);
        let mut frame = trap_frame(MachTrap::TimerCreate, [0; 8]);
        assert!(process.dispatch(&mut frame));
        let timer = frame.result[0] as u32;
        assert_ne!(timer, MACH_PORT_NULL);
        assert!(process.ports.is_timer(timer));
        assert!(process.ports.has_receive(timer));
        assert!(process.ports.has_send(timer));

        frame = trap_frame(
            MachTrap::TimerArm,
            [timer as u64, TIMER_DEADLINE, 0, 0, 0, 0, 0, 0],
        );
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        assert_eq!(process.ports.timer_deadline(timer), Some(TIMER_DEADLINE));

        frame = trap_frame(
            MachTrap::TimerCancel,
            [timer as u64, OUTPUT_ADDRESS, 0, 0, 0, 0, 0, 0],
        );
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        assert_eq!(
            u64::from_le_bytes(
                memory[OUTPUT_ADDRESS as usize..OUTPUT_ADDRESS as usize + 8]
                    .try_into()
                    .unwrap()
            ),
            TIMER_DEADLINE
        );
        assert_eq!(process.ports.timer_deadline(timer), None);

        frame = trap_frame(MachTrap::TimerDestroy, [timer as u64, 0, 0, 0, 0, 0, 0, 0]);
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        assert!(!process.ports.has_receive(timer));
    }

    #[test]
    fn port_sets_allocate_and_track_receive_membership() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 40];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_out = Some(write);
        let mut frame = trap_frame(
            MachTrap::PortAllocate,
            [
                SELF_TASK_PORT as u64,
                PortRight::PortSet.raw() as u64,
                OUTPUT_ADDRESS,
                0,
                0,
                0,
                0,
                0,
            ],
        );
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        let port_set = u32::from_le_bytes(
            memory[OUTPUT_ADDRESS as usize..OUTPUT_ADDRESS as usize + 4]
                .try_into()
                .unwrap(),
        );
        assert!(process.ports.has_port_set(port_set));
        assert_eq!(
            process.ports.port_type(port_set),
            Ok(MACH_PORT_TYPE_PORT_SET)
        );

        let member = process.ports.construct(NO_PORT_OPTIONS).unwrap();
        frame = trap_frame(
            MachTrap::PortInsertMember,
            [
                SELF_TASK_PORT as u64,
                member as u64,
                port_set as u64,
                0,
                0,
                0,
                0,
                0,
            ],
        );
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        assert!(process.ports.port_set_contains(port_set, member));
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::AlreadyInSet));
        frame.number = MachTrap::PortExtractMember as i64;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::Success));
        assert!(!process.ports.port_set_contains(port_set, member));
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::NotInSet));
    }

    #[test]
    fn null_dead_stale_names_and_copyout_failures_are_distinct() {
        let process = Process::new(1, 0, 2);
        let name = process.ports.construct(NO_PORT_OPTIONS).unwrap();
        for (name, expected) in [
            (MACH_PORT_NULL, code(KernReturn::InvalidName)),
            (name ^ 1, code(KernReturn::InvalidName)),
            (name, code(KernReturn::MemoryError)),
            (MACH_PORT_DEAD, code(KernReturn::MemoryError)),
        ] {
            let mut frame = trap_frame(MachTrap::PortType, task_arguments(name, INVALID_ADDRESS));
            assert!(process.dispatch(&mut frame));
            assert_eq!(frame.result[0], expected);
        }
        assert_eq!(
            process.ports.port_type(MACH_PORT_DEAD),
            Ok(MACH_PORT_TYPE_DEAD_NAME)
        );
        let mut frame = trap_frame(MachTrap::PortType, [0x203, name as u64, 32, 0, 0, 0, 0, 0]);
        assert!(!process.dispatch(&mut frame));
        assert_eq!(frame.result[0], code(KernReturn::NotSupported));
    }

    #[test]
    fn guard_operations_preserve_state_when_exception_delivery_is_needed() {
        let process = Process::new(1, 0, 2);
        let name = process.ports.construct(NO_PORT_OPTIONS).unwrap();
        let mut frame = trap_frame(
            MachTrap::PortGuard,
            [
                SELF_TASK_PORT as u64,
                name as u64,
                GUARD_CONTEXT,
                1,
                0,
                0,
                0,
                0,
            ],
        );
        assert!(process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), Some(GUARD_CONTEXT));
        assert!(!process.dispatch(&mut frame));
        frame.number = MachTrap::PortUnguard as i64;
        frame.arguments[2] = OTHER_GUARD_CONTEXT;
        assert!(!process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), Some(GUARD_CONTEXT));
        frame.arguments[2] = GUARD_CONTEXT;
        assert!(process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), None);
        frame.number = MachTrap::PortGuard as i64;
        frame.arguments[2] = 0; // A zero guard is valid and still guarded.
        assert!(process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), Some(0));
        assert!(process.dispatch(&mut frame)); // XNU permits reapplying a zero context
        frame.number = MachTrap::PortUnguard as i64;
        assert!(process.dispatch(&mut frame));
        assert_eq!(process.ports.guard(name), None);
    }

    #[test]
    fn unmodeled_rights_and_transfers_do_not_mutate_the_space() {
        let process = Process::new(1, 0, 2);
        for right in [0, 2, 4, u32::MAX] {
            let mut frame = trap_frame(
                MachTrap::PortAllocate,
                [SELF_TASK_PORT as u64, right as u64, 32, 0, 0, 0, 0, 0],
            );
            assert!(!process.dispatch(&mut frame));
        }
        let name = process.ports.construct(NO_PORT_OPTIONS).unwrap();
        assert_eq!(name, 0x403);
        let mut frame = trap_frame(
            MachTrap::PortInsertRight,
            [
                SELF_TASK_PORT as u64,
                name as u64,
                name as u64 + 256,
                PortDisposition::MakeSend as u64,
                0,
                0,
                0,
                0,
            ],
        );
        assert!(!process.dispatch(&mut frame));
        assert_eq!(process.ports.port_type(name), Ok(MACH_PORT_TYPE_RECEIVE));
    }
}
