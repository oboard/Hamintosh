//! Synchronous messages to compatibility-kernel objects. This is not a daemon
//! registry: unknown RPCs remain unsupported until their object semantics exist.
use super::{Process, TrapFrame};

const NDR: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];
// Darwin priority scale exposed by this kernel. HOST_PRIORITY_INFO describes
// the scale, not a measurement of the host scheduler or a QoS guarantee.
const PRIORITIES: [u32; 8] = [80, 80, 64, 31, 0, 0, 0, 79];

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn quad(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn service_port(process: &Process, port: &std::sync::atomic::AtomicU32) -> Option<u32> {
    let existing = port.load(std::sync::atomic::Ordering::Acquire);
    if existing != 0 && process.ports.has_receive(existing) {
        return Some(existing);
    }
    let candidate = process.ports.construct(0x10).ok()?;
    match port.compare_exchange(
        0,
        candidate,
        std::sync::atomic::Ordering::AcqRel,
        std::sync::atomic::Ordering::Acquire,
    ) {
        Ok(_) => Some(candidate),
        Err(existing) => {
            process.ports.discard_unpublished(candidate);
            Some(existing)
        }
    }
}

fn clock_service(process: &Process) -> Option<u32> {
    service_port(process, &process.clock_port)
}

fn semaphore_service(process: &Process) -> Option<u32> {
    service_port(process, &process.semaphore_port)
}

fn write_value(reply: &mut [u8; 72], at: usize, value: u32) {
    reply[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn message2(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    let request_size = (a[2] >> 32) as usize;
    // Scalar send-and-receive, kernel-object call, no voucher, descriptors,
    // timeout or receive priority. Other modes need their own state machine.
    let id = (a[4] >> 32) as u32;
    let restartable = a[3] as u32 == 0x103 && id == 8000;
    if !(matches!(request_size, 24 | 36 | 40 | 100)
        || (restartable && (36..=1060).contains(&request_size)))
        || a[1] != 0x2_0000_0003
        || a[2] as u32 & 0x7fff_ffff != 0x1513
        || a[4] as u32 != 0
        || a[5] as u32 > 1
        || a[6] >> 32 != 0
        || a[7] != 0
    {
        return None;
    }
    let remote = a[3] as u32;
    let local = (a[3] >> 32) as u32;
    let known_clock = process
        .clock_port
        .load(std::sync::atomic::Ordering::Acquire);
    let deferred_reclamation = remote == 0x103 && id == 90;
    let valid_destination = matches!(
        (remote, id),
        (0x303, 200 | 206) | (0x103, 3418 | 4811 | 8000 | 8001)
    ) || (id == 1000 && known_clock != 0 && remote == known_clock)
        || deferred_reclamation;
    if !valid_destination {
        return None;
    }
    let (read, write) = (process.copy_in?, process.copy_out?);
    if !process.ports.has_send(remote) {
        return Some(0x10000003);
    }
    if local != (a[5] >> 32) as u32 || !process.ports.is_reply(local) {
        return Some(0x10004002);
    }
    let mut request = [0u8; 1064];
    if unsafe {
        read(
            process.host_context,
            a[0],
            request.as_mut_ptr(),
            request_size,
        )
    } != 0
    {
        return Some(0x10000002);
    }
    if word(&request, 0) & 0x7fff_ffff != a[2] as u32 & 0x7fff_ffff
        || word(&request, 4) != request_size as u32
        || word(&request, 8) != remote
        || word(&request, 12) != local
        || word(&request, 16) != 0
        || word(&request, 20) != id
    {
        return Some(0x10000010);
    }

    if deferred_reclamation {
        // Deferred reclamation is optional. Apple clients handle a real
        // KERN_NOT_SUPPORTED without creating a reply message.
        return Some(46);
    }

    let mut reply = [0u8; 72];
    let reply_size = match (remote, id) {
        (0x103, 8000) => {
            if request_size < 36 || request[24..32] != NDR || word(&request, 0) & 0x8000_0000 != 0 {
                return None;
            }
            let count = word(&request, 32) as usize;
            if count > 64 || request_size != 36 + count * 16 {
                return None;
            }
            if (a[6] as u32) < 36 {
                return Some(0x10004004);
            }
            reply[24..32].copy_from_slice(&NDR);
            write_value(
                &mut reply,
                32,
                process.restartable.register(&request[36..request_size]),
            );
            36
        }
        (0x103, 8001) => {
            if request_size != 24 || word(&request, 0) & 0x8000_0000 != 0 {
                return None;
            }
            if (a[6] as u32) < 36 {
                return Some(0x10004004);
            }
            // Only one guest thread exists. The requesting thread cannot be
            // executing an ObjC cache-reader region while making this RPC,
            // so there are no other guest PCs to interrupt or wait for.
            reply[24..32].copy_from_slice(&NDR);
            write_value(&mut reply, 32, 0);
            36
        }
        (0x303, 200) => {
            if request_size != 40 || request[24..32] != NDR || word(&request, 32) != 5 {
                return None;
            }
            let count = word(&request, 36);
            let size = if count >= 8 { 72 } else { 36 };
            if (a[6] as u32) < size {
                return Some(0x10004004);
            }
            reply[24..32].copy_from_slice(&NDR);
            if count < 8 {
                write_value(&mut reply, 32, 5); // KERN_FAILURE
            } else {
                write_value(&mut reply, 32, 0);
                write_value(&mut reply, 36, 8);
                for (i, priority) in PRIORITIES.iter().enumerate() {
                    write_value(&mut reply, 40 + i * 4, *priority);
                }
            }
            size
        }
        (0x303, 206) => {
            if request_size != 36 || request[24..32] != NDR || word(&request, 32) > 1 {
                return None;
            }
            let Some(service) = clock_service(process) else {
                return Some(0x10000003);
            };
            let size = 40;
            if (a[6] as u32) < size {
                return Some(0x10004004);
            }
            write_value(&mut reply, 24, 1); // one port descriptor
            write_value(&mut reply, 28, service);
            write_value(&mut reply, 32, 0);
            write_value(&mut reply, 36, 17 << 16); // MOVE_SEND port
            size
        }
        (0x103, 3418) => {
            if request_size != 40 || request[24..32] != NDR {
                return None;
            }
            let Some(service) = semaphore_service(process) else {
                return Some(0x10000003);
            };
            let size = 40;
            if (a[6] as u32) < size {
                return Some(0x10004004);
            }
            write_value(&mut reply, 24, 1);
            write_value(&mut reply, 28, service);
            write_value(&mut reply, 32, 0);
            write_value(&mut reply, 36, 17 << 16);
            size
        }
        (0x103, 4811) => {
            if request_size != 100
                || word(&request, 0) & 0x8000_0000 == 0
                || word(&request, 24) != 1
                || word(&request, 28) != 0
            {
                return None;
            }
            let Some(map) = process.vm_map else {
                return Some(0x10000003);
            };
            let mut address = quad(&request, 48);
            let size = quad(&request, 56);
            let mask = quad(&request, 64);
            let flags = word(&request, 72);
            let current_protection = word(&request, 88);
            let maximum_protection = word(&request, 92);
            if current_protection & !maximum_protection != 0 {
                return None;
            }
            let error = unsafe {
                map(
                    process.host_context,
                    &mut address,
                    size,
                    mask,
                    flags,
                    current_protection,
                )
            };
            reply[24..32].copy_from_slice(&NDR);
            write_value(&mut reply, 32, error);
            if error == 0 {
                reply[36..44].copy_from_slice(&address.to_le_bytes());
                44
            } else {
                36
            }
        }
        (_, 1000) => {
            if request_size != 24 {
                return None;
            }
            let size = 44;
            if (a[6] as u32) < size {
                return Some(0x10004004);
            }
            let mut value = 0;
            let Some(read_clock) = process.clock else {
                return Some(0x10000003);
            };
            let error = unsafe { read_clock(process.host_context, 0, &mut value) };
            reply[24..32].copy_from_slice(&NDR);
            write_value(&mut reply, 32, error);
            if error == 0 {
                write_value(&mut reply, 36, (value / 1_000_000_000) as u32);
                write_value(&mut reply, 40, (value % 1_000_000_000) as u32);
            }
            size
        }
        _ => return None,
    };
    // Received header: the destination becomes the local reply-port name.
    let reply_bits = if matches!(id, 206 | 3418) {
        0x8000_1200
    } else {
        0x1200
    };
    for (i, value) in [reply_bits, reply_size, 0, local, 0, id + 100]
        .into_iter()
        .enumerate()
    {
        write_value(&mut reply, i * 4, value);
    }
    // COPY_SEND preserves the host send reference. MAKE_SEND_ONCE supplies a
    // single kernel reply and is consumed by this synchronous delivery; it does
    // not create a lasting user send right on the reply port.
    if unsafe {
        write(
            process.host_context,
            a[0],
            reply.as_ptr(),
            reply_size as usize,
        )
    } != 0
    {
        Some(0x10004008)
    } else {
        Some(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    unsafe extern "C" fn read(
        context: *const c_void,
        address: u64,
        out: *mut u8,
        size: usize,
    ) -> u32 {
        let memory = &*(context as *const [u8; 128]);
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
        context: *const c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        let memory = &mut *(context as *mut [u8; 128]);
        let Some(end) = (address as usize).checked_add(size) else {
            return 14;
        };
        let Some(bytes) = memory.get_mut(address as usize..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), size);
        0
    }
    fn request(memory: &mut [u8; 128], local: u32, count: u32) -> TrapFrame {
        memory.fill(0);
        for (i, value) in [0x1513, 40, 0x303, local, 0, 200, 0, 1, 5, count]
            .into_iter()
            .enumerate()
        {
            memory[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (40 << 32) | 0x1513,
                ((local as u64) << 32) | 0x303,
                200 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        }
    }
    #[test]
    fn host_priority_rpc_returns_a_real_kernel_reply_without_leaking_rights() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x303));
        let local = process.ports.construct(0x1000).unwrap();
        let frame = request(&mut memory, local, 8);
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 4), 72);
        assert_eq!(word(&memory, 12), local);
        assert_eq!(word(&memory, 20), 300);
        assert_eq!(word(&memory, 32), 0);
        assert_eq!(word(&memory, 36), 8);
        assert_eq!((word(&memory, 52), word(&memory, 68)), (31, 79));
        assert!(process.ports.is_reply(local));
        assert_eq!(process.ports.modify_send_refs(local, -1), 17);
        assert_eq!(process.ports.modify_send_refs(0x303, -1), 0);
        assert!(!process.ports.has_send(0x303));
    }

    #[test]
    fn restartable_range_rpc_registers_regions_and_replies_with_kernel_errors() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        let mut frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (52 << 32) | 0x1513,
                ((local as u64) << 32) | 0x103,
                8000 << 32,
                (local as u64) << 32,
                44,
                0,
            ],
            ..Default::default()
        };
        fn encode(memory: &mut [u8; 128], local: u32, count: u32) {
            memory.fill(0);
            for (i, value) in [0x1513, 52, 0x103, local, 0, 8000, 0, 1, count]
                .into_iter()
                .enumerate()
            {
                memory[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
            }
            memory[36..44].copy_from_slice(&0x1000u64.to_le_bytes());
            memory[44..52].copy_from_slice(&((8u64 << 16) | 8).to_le_bytes());
        }
        encode(&mut memory, local, 2);
        assert_eq!(message2(&process, &frame), None); // Count doesn't fit message.
        assert_eq!(process.restartable.resume_pc(0x1004), 0x1004);
        encode(&mut memory, local, 1);
        frame.arguments[6] = 32;
        assert_eq!(message2(&process, &frame), Some(0x10004004));
        assert_eq!(process.restartable.resume_pc(0x1004), 0x1004);
        frame.arguments[6] = 44;
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(
            (word(&memory, 4), word(&memory, 20), word(&memory, 32)),
            (36, 8100, 0)
        );
        assert_eq!(process.restartable.resume_pc(0x1004), 0x1008);
        encode(&mut memory, local, 1);
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 32), 46);
        encode(&mut memory, local, 1);
        memory[4..8].copy_from_slice(&24u32.to_le_bytes());
        memory[20..24].copy_from_slice(&8001u32.to_le_bytes());
        frame.arguments[2] = (24 << 32) | 0x1513;
        frame.arguments[4] = 8001 << 32;
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 20), word(&memory, 32)), (8101, 0));
    }
    unsafe extern "C" fn test_clock(_: *const c_void, _: u32, value: *mut u64) -> u32 {
        *value = 3_000_000_017;
        0
    }

    #[test]
    fn host_clock_service_and_clock_time_round_trip_as_mach_messages() {
        let mut process = Process::new(1, 0, 2);
        process.clock = Some(test_clock);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x303));
        let reply_port = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (i, value) in [0x1513, 36, 0x303, reply_port, 0, 206, 0, 1, 0]
            .into_iter()
            .enumerate()
        {
            memory[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (36 << 32) | 0x1513,
                ((reply_port as u64) << 32) | 0x303,
                206 << 32,
                (reply_port as u64) << 32,
                64,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 4), word(&memory, 20)), (40, 306));
        assert_eq!(word(&memory, 0), 0x8000_1200);
        assert_eq!(word(&memory, 24), 1);
        assert_eq!(word(&memory, 36), 17 << 16);
        let service = word(&memory, 28);
        assert!(process.ports.has_send(service));

        let clock_reply = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (i, value) in [0x1513, 24, service, clock_reply, 0, 1000]
            .into_iter()
            .enumerate()
        {
            memory[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (24 << 32) | 0x1513,
                ((clock_reply as u64) << 32) | service as u64,
                1000 << 32,
                (clock_reply as u64) << 32,
                64,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 4), word(&memory, 20)), (44, 1100));
        assert_eq!(word(&memory, 32), 0);
        assert_eq!((word(&memory, 36), word(&memory, 40)), (3, 17));
    }

    #[test]
    fn task_semaphore_create_returns_a_complex_port_reply() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        for (i, value) in [0x1513, 40, 0x103, local, 0, 3418, 0, 1, 0, 0]
            .into_iter()
            .enumerate()
        {
            memory[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (40 << 32) | 0x1513,
                ((local as u64) << 32) | 0x103,
                3418 << 32,
                (local as u64) << 32,
                64,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 4), word(&memory, 20)), (40, 3518));
        assert_eq!(word(&memory, 0), 0x8000_1200);
        assert_eq!(word(&memory, 24), 1);
        assert_eq!(word(&memory, 36), 17 << 16);
        assert!(process.ports.has_send(word(&memory, 28)));
    }

    unsafe extern "C" fn vm_map(
        _: *const c_void,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: u32,
        protection: u32,
    ) -> u32 {
        if size != 0x41c000 || mask != 0 || flags != 0x0100_0001 || protection != 0 {
            return 4;
        }
        *address = 0x7000_0000;
        0
    }

    #[test]
    fn kernelrpc_mach_vm_map_returns_the_allocated_address() {
        let mut process = Process::new(1, 0, 2);
        process.vm_map = Some(vm_map);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (i, value) in [0x8000_1513, 100, 0x103, local, 0, 4811]
            .into_iter()
            .enumerate()
        {
            memory[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        memory[24..28].copy_from_slice(&1u32.to_le_bytes());
        memory[28..32].copy_from_slice(&0u32.to_le_bytes());
        memory[32..36].copy_from_slice(&(19u32 << 16).to_le_bytes());
        memory[40..48].copy_from_slice(&NDR);
        memory[56..64].copy_from_slice(&0x41c000u64.to_le_bytes());
        memory[72..76].copy_from_slice(&0x0100_0001u32.to_le_bytes());
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (100 << 32) | 0x8000_1513,
                ((local as u64) << 32) | 0x103,
                4811 << 32,
                ((local as u64) << 32) | 1,
                64,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 4), 44);
        assert_eq!(word(&memory, 20), 4911);
        assert_eq!(word(&memory, 32), 0);
        assert_eq!(quad(&memory, 36), 0x7000_0000);
    }

    #[test]
    fn optional_deferred_reclamation_failure_is_delivered() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        let request_size = 40u64;
        for (i, value) in [0x1513, 40, 0x103, local, 0, 90].into_iter().enumerate() {
            memory[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (request_size << 32) | 0x1513,
                ((local as u64) << 32) | 0x103,
                90 << 32,
                (local as u64) << 32,
                64,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(46));
    }

    #[test]
    fn malformed_requests_short_buffers_and_unsupported_queries_do_not_succeed() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        process.ports.acquire_send(0x303);
        let local = process.ports.construct(0x1000).unwrap();
        let mut frame = request(&mut memory, local, 8);
        frame.arguments[6] = 32;
        assert_eq!(message2(&process, &frame), Some(0x10004004));
        frame.arguments[6] = 128;
        frame.arguments[0] = 120;
        assert_eq!(message2(&process, &frame), Some(0x10000002));
        frame.arguments[0] = 0;
        memory[20..24].copy_from_slice(&201u32.to_le_bytes());
        assert_eq!(message2(&process, &frame), Some(0x10000010));
        frame = request(&mut memory, local, 7);
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 4), 36);
        assert_eq!(word(&memory, 32), 5);
        frame = request(&mut memory, local, 8);
        memory[32..36].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(message2(&process, &frame), None);
    }
}
