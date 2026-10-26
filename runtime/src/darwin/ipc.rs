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
    // A local service keeps one send reference for its own dispatch while the
    // MOVE_SEND descriptor gives the guest a separate user reference. Without
    // the service-owned ref, a normal guest deallocation would make later
    // synchronous calls appear to target a dead service.
    if !process.ports.acquire_send(candidate) {
        process.ports.discard_unpublished(candidate);
        return None;
    }
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

fn bootstrap_service(process: &Process) -> Option<u32> {
    service_port(process, &process.bootstrap_port)
}

fn clock_service(process: &Process) -> Option<u32> {
    service_port(process, &process.clock_port)
}

fn io_main_service(process: &Process) -> Option<u32> {
    service_port(process, &process.io_main_port)
}

fn io_registry_service(process: &Process) -> Option<u32> {
    service_port(process, &process.io_registry_port)
}

fn io_display_service(process: &Process) -> Option<u32> {
    service_port(process, &process.io_display_service_port)
}

fn semaphore_service(process: &Process) -> Option<u32> {
    service_port(process, &process.semaphore_port)
}

fn write_value(reply: &mut [u8; 72], at: usize, value: u32) {
    reply[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

const MACH64_MSG_VECTOR: u64 = 0x1_0000_0000;
const MACH64_SEND_MQ_CALL: u64 = 0x4_0000_0000;
const MACH_SEND_MSG: u64 = 0x1;
const MACH_RCV_MSG: u64 = 0x2;

fn send_vector(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    if a[1] & MACH64_MSG_VECTOR == 0
        || a[1] & MACH64_SEND_MQ_CALL == 0
        || a[1] & MACH_SEND_MSG == 0
        || a[1] & MACH_RCV_MSG != 0
        || a[2] >> 32 != 2
    {
        return None;
    }
    let read = process.copy_in?;
    let mut vectors = [0u8; 48];
    if unsafe {
        read(
            process.host_context,
            a[0],
            vectors.as_mut_ptr(),
            vectors.len(),
        )
    } != 0
    {
        return Some(0x10000002); // MACH_SEND_INVALID_DATA
    }
    let mut message = [0u8; 24];
    for index in 0..2 {
        let at = index * 24;
        let data = quad(&vectors, at);
        let send_size = word(&vectors, at + 16) as usize;
        if send_size > 4096 || (send_size != 0 && data == 0) {
            return Some(0x10000002);
        }
        if index == 1 && send_size != 0 {
            // libdispatch starts attaching tracing activity after the first
            // activity-ID allocation. This is an independent opaque auxiliary
            // vector, not part of the XPC dictionary or a port descriptor.
            // Bound it to libsyscall's 128-byte auxiliary limit and validate
            // its header without placing a large buffer on the trap stack.
            let mut auxiliary = [0u8; 128];
            if !(8..=auxiliary.len()).contains(&send_size)
                || unsafe {
                    read(
                        process.host_context,
                        data,
                        auxiliary.as_mut_ptr(),
                        send_size,
                    )
                } != 0
                || word(&auxiliary, 0) as usize != send_size
                || word(&auxiliary, 4) != 0
            {
                return Some(0x10000002);
            }
        }
        if index == 0
            && (send_size < message.len()
                || unsafe {
                    read(
                        process.host_context,
                        data,
                        message.as_mut_ptr(),
                        message.len(),
                    )
                } != 0)
        {
            return Some(0x10000002);
        }
    }
    let message_size = word(&message, 4);
    let remote = word(&message, 8);
    let local = word(&message, 12);
    let voucher = word(&message, 16);
    let id = word(&message, 20);
    if message_size < 24
        || u64::from(message_size) > word(&vectors, 16) as u64
        || message_size != word(&vectors, 16)
        || remote != a[3] as u32
        || local != (a[3] >> 32) as u32
        || voucher != a[4] as u32
        || id != (a[4] >> 32) as u32
        || !process.ports.has_send(remote)
        || !process.ports.has_receive(remote)
        || (voucher != 0 && !process.ports.has_send(voucher))
    {
        return Some(0x10000003); // MACH_SEND_INVALID_DEST
    }
    super::xpc::send(process, frame, quad(&vectors, 0), message_size as usize)
}

pub(super) fn message2(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    if let Some(result) = super::xpc::receive(process, frame) {
        return Some(result);
    }
    if let Some(result) = super::display::message2(process, frame) {
        return Some(result);
    }
    if let Some(result) = send_vector(process, frame) {
        return Some(result);
    }
    let request_size = (a[2] >> 32) as usize;
    // Scalar send-and-receive, kernel-object call, no voucher, descriptors,
    // timeout or receive priority. Other modes need their own state machine.
    // Receive-only operations cannot block the host signal/trap thread. Known
    // process ports currently have no queued reply, so report Darwin's real
    // MACH_RCV_TIMED_OUT and let the guest event loop continue.
    if a[1] & 0x0000_0002 != 0 && a[1] & 0x0000_0001 == 0 && a[2] == 0 {
        let receive = (a[5] >> 32) as u32;
        if receive != 0 && process.ports.has_receive(receive) {
            return Some(0x10004003);
        }
    }
    let id = (a[4] >> 32) as u32;
    let restartable = a[3] as u32 == 0x103 && id == 8000;
    // Receive-only operations cannot block the host signal/trap thread. Known
    // process ports currently have no queued reply, so report Darwin's real
    // MACH_RCV_TIMED_OUT and let the guest event loop continue.
    if a[1] & 0x0000_0002 != 0 && a[1] & 0x0000_0001 == 0 && a[2] == 0 {
        let receive = (a[5] >> 32) as u32;
        if receive != 0 && process.ports.has_receive(receive) {
            return Some(0x10004003);
        }
    }
    let id = (a[4] >> 32) as u32;
    // The host bootstrap port is process-owned, but this compatibility kernel
    // does not yet register launchd services. XPC service lookup uses ids with
    // the 0x40000000 flag and an attached voucher. Report the destination as
    // unavailable so libxpc can take its normal optional-service fallback
    // instead of treating the Darwin trap itself as an implementation failure.
    let bootstrap = process
        .bootstrap_port
        .load(std::sync::atomic::Ordering::Acquire);
    if bootstrap != 0 && a[3] as u32 == bootstrap && id & 0x4000_0000 != 0 {
        return Some(0x10000003); // MACH_SEND_INVALID_DEST
    }
    if !(matches!(request_size, 24 | 36 | 40 | 52 | 68 | 80 | 84 | 88 | 100)
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
    let known_io_main = process
        .io_main_port
        .load(std::sync::atomic::Ordering::Acquire);
    let known_io_registry = process
        .io_registry_port
        .load(std::sync::atomic::Ordering::Acquire);
    let known_io_display = process
        .io_display_service_port
        .load(std::sync::atomic::Ordering::Acquire);
    let deferred_reclamation = remote == 0x103 && id == 90;
    let valid_destination = matches!(
        (remote, id),
        (0x303, 200 | 205 | 206 | 412) | (0x103, 3405 | 3409 | 3410 | 3418 | 4811 | 8000 | 8001)
    ) || (id == 1000 && known_clock != 0 && remote == known_clock)
        || (id == 2877 && known_io_main != 0 && remote == known_io_main)
        || (id == 2809 && known_io_main != 0 && remote == known_io_main)
        || (id == 2810 && known_io_registry != 0 && remote == known_io_registry)
        || (id == 2889
            && ((known_io_registry != 0 && remote == known_io_registry)
                || (known_io_display != 0 && remote == known_io_display)))
        || (id == 2880 && known_io_main != 0 && remote == known_io_main)
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
        (0x103, 3409) => {
            // task.defs: task_get_special_port. Early libxpc asks for the
            // bootstrap port, while iOS 27 libsystem_kernel also uses a
            // compact kernel-RPC body to retrieve the installed debug-control
            // right.
            if word(&request, 0) & 0x8000_0000 != 0 {
                return None;
            }
            let which_port = if request_size == 36 && request[24..32] == NDR {
                word(&request, 32)
            } else if request_size == 36 && word(&request, 24) == 1 && word(&request, 32) == 0 {
                word(&request, 28)
            } else {
                return None;
            };
            let service = match which_port {
                4 => bootstrap_service(process),
                10 => {
                    let port = process
                        .debug_control_port
                        .load(std::sync::atomic::Ordering::Acquire);
                    (port != 0 && process.ports.has_send(port)).then_some(port)
                }
                _ => return None,
            };
            if (a[6] as u32) < 40 {
                return Some(0x10004004);
            }
            let Some(service) = service else {
                return Some(0x10000003);
            };
            write_value(&mut reply, 24, 1);
            write_value(&mut reply, 28, service);
            write_value(&mut reply, 32, 0);
            write_value(&mut reply, 36, 17 << 16); // MOVE_SEND port descriptor
            40
        }
        (0x103, 3410) => {
            // task.defs: task_set_special_port. The observed request installs
            // a COPY_SEND debug-control right (which_port 10).
            if request_size != 52
                || word(&request, 24) != 1
                || word(&request, 28) & 0x0fff_ffff == 0
                || (word(&request, 36) >> 16) & 0xff != 19 // COPY_SEND
                || word(&request, 36) >> 24 != 0 // MACH_MSG_PORT_DESCRIPTOR
                || request[40..48] != NDR
                || word(&request, 48) != 10
            {
                return None;
            }
            let port = word(&request, 28) & 0x0fff_ffff;
            if !process.ports.has_send(port) {
                return Some(0x10000003);
            }
            if (a[6] as u32) < 36 {
                return Some(0x10004004);
            }
            process
                .debug_control_port
                .store(port, std::sync::atomic::Ordering::Release);
            reply[24..32].copy_from_slice(&NDR);
            write_value(&mut reply, 32, 0);
            36
        }
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
        (_, 2880) => {
            // device.defs: io_service_get_matching_service_bin. MobileGestalt
            // looks up the AppleCLCD display provider by its IORegistry match
            // dictionary. Return a local display-service port for that match.
            if request_size != 80
                || !request
                    .windows(15)
                    .any(|window| window == b"IOProviderClass")
                || !request.windows(9).any(|window| window == b"AppleCLCD")
            {
                return None;
            }
            if (a[6] as u32) < 40 {
                return Some(0x10004004);
            }
            let Some(service) = io_display_service(process) else {
                return Some(0x10000003);
            };
            write_value(&mut reply, 24, 1);
            write_value(&mut reply, 28, service);
            write_value(&mut reply, 32, 0);
            write_value(&mut reply, 36, 17 << 16); // MOVE_SEND port descriptor
            40
        }
        (_, 2889) => {
            // device.defs: io_registry_entry_get_property_bin_buf. The registry
            // backend exposes only the two validated display capability keys.
            if !matches!(request_size, 84 | 88) {
                return None;
            }
            let name_size = word(&request, 48) as usize;
            let name_end = 52usize.checked_add(name_size)?;
            if !(2..=128).contains(&name_size)
                || name_end > request_size
                || request[name_end - 1] != 0
                || request[52..name_end - 1].contains(&0)
            {
                return None;
            }
            let property = &request[52..name_end - 1];
            if property != b"APTDevice" && property != b"supports-apt" {
                if (a[6] as u32) < 36 {
                    return Some(0x10004004);
                }
                reply[24..32].copy_from_slice(&NDR);
                write_value(&mut reply, 32, 0xe000_02bc); // kIOReturnNotFound
                36
            } else {
                let value_size = if property == b"supports-apt" { 8 } else { 16 };
                let output_offset = ((name_end + 3) & !3) + 4;
                let capacity_offset = output_offset.checked_add(8)?;
                if capacity_offset + 8 > request_size {
                    return None;
                }
                let output = quad(&request, output_offset);
                let capacity = quad(&request, capacity_offset);
                if output == 0 || capacity < value_size as u64 {
                    return None;
                }
                if (a[6] as u32) < 64 {
                    return Some(0x10004004);
                }
                let Some(write) = process.copy_out else {
                    return Some(0x10004008);
                };
                let mut value = [0u8; 16];
                value[..4].copy_from_slice(&[0xd3, 0, 0, 0]); // binary signature; root values end the collection
                if property == b"supports-apt" {
                    value[4..8].copy_from_slice(&0x8b00_0001u32.to_le_bytes());
                } else {
                    value[4..8].copy_from_slice(&0x8400_0040u32.to_le_bytes());
                    value[8..].copy_from_slice(&1u64.to_le_bytes());
                }
                if unsafe { write(process.host_context, output, value.as_ptr(), value_size) } != 0 {
                    return Some(0x10004008);
                }
                reply.fill(0);
                write_value(&mut reply, 24, 1); // one OOL descriptor
                write_value(&mut reply, 36, 1 << 24); // MACH_MSG_OOL_DESCRIPTOR
                write_value(&mut reply, 40, 0); // direct output, propertiesCnt
                reply[52..60].copy_from_slice(&(value_size as u64).to_le_bytes());
                write_value(&mut reply, 60, 0);
                64
            }
        }
        (_, 2809) => {
            // device.defs: io_registry_entry_from_path. Preserve the observed
            // bounded IORegistry path and return a local registry-entry port.
            if request_size != 68
                || word(&request, 36) != 27
                || request[40..67] != *b"IODeviceTree:/arm-io/disp0\0"
                || request[67] != 0
            {
                return None;
            }
            if (a[6] as u32) < 40 {
                return Some(0x10004004);
            }
            let Some(service) = io_registry_service(process) else {
                return Some(0x10000003);
            };
            write_value(&mut reply, 24, 1);
            write_value(&mut reply, 28, service);
            write_value(&mut reply, 32, 0);
            write_value(&mut reply, 36, 17 << 16); // MOVE_SEND port descriptor
            40
        }
        (_, 2877) => {
            // device.defs: io_server_version. The returned MIG value is the
            // public IOKit server version used by libMobileGestalt.
            if request_size != 24 {
                return None;
            }
            let size = 44;
            if (a[6] as u32) < size {
                return Some(0x10004004);
            }
            reply[24..32].copy_from_slice(&NDR);
            write_value(&mut reply, 32, 0);
            reply[36..44].copy_from_slice(&20_210_810u64.to_le_bytes());
            size
        }
        (0x303, 205) => {
            // host.defs: host_get_io_main. The observed request is an empty
            // 24-byte MIG message; return a process-owned IOKit main port.
            if request_size != 24 || word(&request, 0) & 0x8000_0000 != 0 {
                return None;
            }
            if (a[6] as u32) < 40 {
                return Some(0x10004004);
            }
            let Some(service) = io_main_service(process) else {
                return Some(0x10000003);
            };
            write_value(&mut reply, 24, 1);
            write_value(&mut reply, 28, service);
            write_value(&mut reply, 32, 0);
            write_value(&mut reply, 36, 17 << 16); // MOVE_SEND port descriptor
            40
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
        (0x303, 412) => {
            // host_priv.defs: host_get_special_port. The observed local node
            // query asks for HOST_PORT (1); return the process's existing host
            // identity as a COPY_SEND descriptor.
            if request_size != 40
                || request[24..32] != NDR
                || word(&request, 32) != u32::MAX
                || word(&request, 36) != 1
            {
                return None;
            }
            if (a[6] as u32) < 40 {
                return Some(0x10004004);
            }
            write_value(&mut reply, 24, 1);
            write_value(&mut reply, 28, 0x303);
            write_value(&mut reply, 32, 0);
            write_value(&mut reply, 36, 19 << 16); // COPY_SEND
            40
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
        (0x103, 3405) => {
            // task_info(TASK_AUDIT_TOKEN): return the fixed eight-word
            // Darwin identity token used by audit-aware frameworks.
            if request_size != 40
                || request[24..32] != NDR
                || word(&request, 32) != 15
                || word(&request, 36) < 8
            {
                return None;
            }
            const TOKEN_WORDS: u32 = 8;
            const REPLY_SIZE: u32 = 40 + TOKEN_WORDS * 4;
            if (a[6] as u32) < REPLY_SIZE {
                return Some(0x10004004);
            }
            reply[24..32].copy_from_slice(&NDR);
            write_value(&mut reply, 32, 0);
            write_value(&mut reply, 36, TOKEN_WORDS);
            let token = [
                u32::MAX,    // unset audit id
                501,         // effective uid
                501,         // effective gid
                501,         // real uid
                501,         // real gid
                process.pid, // process id
                100,         // default audit session id
                process.thread_id as u32,
            ];
            for (index, value) in token.into_iter().enumerate() {
                write_value(&mut reply, 40 + index * 4, value);
            }
            REPLY_SIZE
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
    let reply_bits =
        if reply_size == 64 || matches!(id, 205 | 206 | 412 | 2809 | 2880 | 3409 | 3418) {
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

    // Validate the actual MIG output with Apple's parser when running on macOS.
    // Checking only its tag bytes missed the mandatory root end marker.
    #[cfg(target_os = "macos")]
    fn assert_native_iokit_property(data: &[u8], number: bool) {
        #[link(name = "IOKit", kind = "framework")]
        unsafe extern "C" {
            fn IOCFUnserializeWithSize(
                bytes: *const u8,
                size: usize,
                allocator: *const c_void,
                options: usize,
                error: *mut *const c_void,
            ) -> *const c_void;
        }
        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            fn CFGetTypeID(value: *const c_void) -> usize;
            fn CFBooleanGetTypeID() -> usize;
            fn CFNumberGetTypeID() -> usize;
            fn CFBooleanGetValue(value: *const c_void) -> u8;
            fn CFNumberGetValue(value: *const c_void, kind: isize, output: *mut i64) -> u8;
            fn CFRelease(value: *const c_void);
        }
        unsafe {
            let value = IOCFUnserializeWithSize(
                data.as_ptr(),
                data.len(),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            );
            assert!(
                !value.is_null(),
                "IOKit rejected the serialized root property"
            );
            if number {
                assert_eq!(CFGetTypeID(value), CFNumberGetTypeID());
                let mut decoded = 0i64;
                assert_ne!(CFNumberGetValue(value, 4, &mut decoded), 0); // SInt64
                assert_eq!(decoded, 1);
            } else {
                assert_eq!(CFGetTypeID(value), CFBooleanGetTypeID());
                assert_ne!(CFBooleanGetValue(value), 0);
            }
            CFRelease(value);
        }
    }

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
    fn host_privileged_rpc_returns_the_existing_host_port() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x303));
        let local = process.ports.construct(0x1000).unwrap();
        for (offset, value) in [
            (0, 0x1513u32),
            (4, 40),
            (8, 0x303),
            (12, local),
            (20, 412),
            (28, 1),
            (32, u32::MAX),
            (36, 1),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (40 << 32) | 0x1513,
                ((local as u64) << 32) | 0x303,
                412 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 40));
        assert_eq!((word(&memory, 24), word(&memory, 28)), (1, 0x303));
        assert_eq!(word(&memory, 36), 19 << 16);
    }

    #[test]
    fn host_io_main_query_returns_a_process_owned_send_right() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x303));
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (offset, value) in [(0, 0x1513u32), (4, 24), (8, 0x303), (12, local), (20, 205)] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (24 << 32) | 0x1513,
                ((local as u64) << 32) | 0x303,
                205 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 40));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 305));
        assert_eq!((word(&memory, 24), word(&memory, 32)), (1, 0));
        let service = word(&memory, 28);
        assert!(process.ports.has_receive(service));
        assert!(process.ports.has_send(service));
        assert_eq!(word(&memory, 36), 17 << 16);
        // The guest's MOVE_SEND user reference can be released without
        // destroying the service-owned dispatch reference.
        assert_eq!(process.ports.modify_send_refs(service, -1), 0);
        assert!(process.ports.has_send(service));
    }

    #[test]
    fn iokit_server_version_uses_the_local_main_port() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let io_main = process.ports.construct(0x10).unwrap();
        process
            .io_main_port
            .store(io_main, std::sync::atomic::Ordering::Release);
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (offset, value) in [
            (0, 0x1513u32),
            (4, 24),
            (8, io_main),
            (12, local),
            (20, 2877),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (24 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(io_main),
                2877 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x1200, 44));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2977));
        assert_eq!(&memory[24..32], &NDR);
        assert_eq!(word(&memory, 32), 0);
        assert_eq!(
            u64::from_le_bytes(memory[36..44].try_into().unwrap()),
            20_210_810
        );
    }

    #[test]
    fn iokit_apt_device_property_returns_a_serialized_number() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let display = process.ports.construct(0x10).unwrap();
        process
            .io_display_service_port
            .store(display, std::sync::atomic::Ordering::Release);
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (offset, value) in [
            (0, 0x1513u32),
            (4, 84),
            (8, display),
            (12, local),
            (20, 2889),
            (48, 10),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        memory[52..62].copy_from_slice(b"APTDevice\0");
        memory[68..76].copy_from_slice(&96u64.to_le_bytes());
        memory[76..84].copy_from_slice(&16u64.to_le_bytes());
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (84 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(display),
                2889 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 64));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2989));
        assert_eq!((word(&memory, 24), word(&memory, 40)), (1, 0));
        assert_eq!(word(&memory, 36), 1 << 24);
        assert_eq!(u64::from_le_bytes(memory[52..60].try_into().unwrap()), 16);
        assert_eq!(&memory[96..100], &[0xd3, 0, 0, 0]);
        assert_eq!(
            u32::from_le_bytes(memory[100..104].try_into().unwrap()),
            0x8400_0040
        );
        assert_eq!(u64::from_le_bytes(memory[104..112].try_into().unwrap()), 1);
        #[cfg(target_os = "macos")]
        assert_native_iokit_property(&memory[96..112], true);
    }

    #[test]
    fn iokit_supports_apt_returns_serialized_true() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let registry = process.ports.construct(0x10).unwrap();
        process
            .io_registry_port
            .store(registry, std::sync::atomic::Ordering::Release);
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (offset, value) in [
            (0, 0x1513u32),
            (4, 88),
            (8, registry),
            (12, local),
            (20, 2889),
            (48, 13),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        memory[52..65].copy_from_slice(b"supports-apt\0");
        memory[72..80].copy_from_slice(&96u64.to_le_bytes());
        memory[80..88].copy_from_slice(&8u64.to_le_bytes());
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (88 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(registry),
                2889 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 64));
        assert_eq!(&memory[96..104], &[0xd3, 0, 0, 0, 1, 0, 0, 0x8b]);
        #[cfg(target_os = "macos")]
        assert_native_iokit_property(&memory[96..104], false);
    }

    #[test]
    fn iokit_registry_path_returns_a_local_entry_port() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let io_main = process.ports.construct(0x10).unwrap();
        process
            .io_main_port
            .store(io_main, std::sync::atomic::Ordering::Release);
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (offset, value) in [
            (0, 0x1513u32),
            (4, 68),
            (8, io_main),
            (12, local),
            (20, 2809),
            (36, 27),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        memory[40..67].copy_from_slice(b"IODeviceTree:/arm-io/disp0\0");
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (68 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(io_main),
                2809 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 40));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2909));
        assert_eq!((word(&memory, 24), word(&memory, 32)), (1, 0));
        let service = word(&memory, 28);
        assert!(process.ports.has_receive(service));
        assert!(process.ports.has_send(service));
        assert_eq!(word(&memory, 36), 17 << 16);
    }

    #[test]
    fn iokit_display_match_returns_a_local_service_port() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let io_main = process.ports.construct(0x10).unwrap();
        process
            .io_main_port
            .store(io_main, std::sync::atomic::Ordering::Release);
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (offset, value) in [
            (0, 0x1513u32),
            (4, 80),
            (8, io_main),
            (12, local),
            (20, 2880),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        memory[48..63].copy_from_slice(b"IOProviderClass");
        memory[68..77].copy_from_slice(b"AppleCLCD");
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (80 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(io_main),
                2880 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 40));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2980));
        assert_eq!((word(&memory, 24), word(&memory, 32)), (1, 0));
        let service = word(&memory, 28);
        assert!(process.ports.has_receive(service));
        assert!(process.ports.has_send(service));
        assert_eq!(word(&memory, 36), 17 << 16);
    }

    #[test]
    fn iokit_registry_property_returns_not_found_for_an_absent_value() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let registry = process.ports.construct(0x10).unwrap();
        process
            .io_registry_port
            .store(registry, std::sync::atomic::Ordering::Release);
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        for (offset, value) in [
            (0, 0x1513u32),
            (4, 88),
            (8, registry),
            (12, local),
            (20, 2889),
            (48, 14),
            (68, 0x1000),
            (76, 2048),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        memory[52..66].copy_from_slice(b"missing-value\0");
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (88 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(registry),
                2889 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x1200, 36));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2989));
        assert_eq!(&memory[24..32], &NDR);
        assert_eq!(word(&memory, 32), 0xe000_02bc);
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

    fn set_special_port_request(memory: &mut [u8; 128], local: u32, port: u32) -> TrapFrame {
        memory.fill(0);
        for (offset, value) in [
            (0, 0x8000_1513u32),
            (4, 52),
            (8, 0x103),
            (12, local),
            (20, 3410),
            (24, 1),
            (28, port),
            (36, 19 << 16),
            (44, 1),
            (48, 10),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (52 << 32) | 0x1513,
                ((local as u64) << 32) | 0x103,
                3410 << 32,
                ((local as u64) << 32) | 1,
                128,
                0,
            ],
            ..Default::default()
        }
    }

    fn bootstrap_request(memory: &mut [u8; 128], local: u32) -> TrapFrame {
        let mut frame = request(memory, local, 8);
        for (offset, value) in [(4, 36u32), (8, 0x103), (20, 3409), (32, 4)] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        frame.arguments[2] = (36 << 32) | 0x1513;
        frame.arguments[3] = ((local as u64) << 32) | 0x103;
        frame.arguments[4] = 3409 << 32;
        frame
    }

    #[test]
    fn task_bootstrap_port_query_returns_a_process_owned_send_right() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        for _ in 0..2 {
            let frame = bootstrap_request(&mut memory, local);
            assert_eq!(message2(&process, &frame), Some(0));
            assert_eq!(word(&memory, 0), 0x8000_1200);
            assert_eq!(
                (word(&memory, 4), word(&memory, 12), word(&memory, 20)),
                (40, local, 3509)
            );
            let service = word(&memory, 28);
            assert_eq!(word(&memory, 24), 1);
            assert_ne!(service, 0);
            assert!(process.ports.has_receive(service));
            assert!(process.ports.has_send(service));
            assert_eq!((word(&memory, 32), word(&memory, 36)), (0, 17 << 16));
        }
        assert_eq!(process.ports.modify_send_refs(0x103, -1), 0);
        assert!(!process.ports.has_send(0x103));
        assert_eq!(process.ports.modify_send_refs(local, -1), 17);
    }

    #[test]
    fn compact_debug_control_query_returns_the_installed_send_right() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        let debug = process.ports.construct(0x10).unwrap();
        process
            .debug_control_port
            .store(debug, std::sync::atomic::Ordering::Release);
        for (offset, value) in [
            (0, 0x1513u32),
            (4, 36),
            (8, 0x103),
            (12, local),
            (20, 3409),
            (24, 1),
            (28, 10),
            (32, 0),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (36 << 32) | 0x1513,
                ((local as u64) << 32) | 0x103,
                3409 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 0), 0x8000_1200);
        assert_eq!((word(&memory, 4), word(&memory, 20)), (40, 3509));
        assert_eq!((word(&memory, 24), word(&memory, 28)), (1, debug));
        assert_eq!(word(&memory, 36), 17 << 16);
        assert!(process.ports.has_send(debug));
    }

    #[test]
    fn task_set_special_port_accepts_a_copy_send_debug_control_right() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        let debug = process.ports.construct(0x10).unwrap();
        let frame = set_special_port_request(&mut memory, local, debug);
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 0), 0x1200);
        assert_eq!(
            (word(&memory, 4), word(&memory, 12), word(&memory, 20)),
            (36, local, 3510)
        );
        assert_eq!((word(&memory, 24), word(&memory, 28)), (0, 1));
        assert_eq!(
            process
                .debug_control_port
                .load(std::sync::atomic::Ordering::Acquire),
            debug
        );
        let mut bad = set_special_port_request(&mut memory, local, debug);
        bad.arguments[6] = 35;
        assert_eq!(message2(&process, &bad), Some(0x10004004));
        assert_eq!(process.ports.modify_send_refs(debug, -1), 0);
    }

    #[test]
    fn task_bootstrap_query_rejects_malformed_or_unimplemented_special_ports() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        let mut frame = bootstrap_request(&mut memory, local);
        frame.arguments[6] = 39;
        let before = memory;
        assert_eq!(message2(&process, &frame), Some(0x10004004));
        assert_eq!(memory, before);
        frame = bootstrap_request(&mut memory, local);
        memory[28] = 2; // Only the native little-endian NDR is accepted.
        assert_eq!(message2(&process, &frame), None);
        frame = bootstrap_request(&mut memory, local);
        memory[0..4].copy_from_slice(&0x8000_1513u32.to_le_bytes());
        frame.arguments[2] |= 0x8000_0000;
        assert_eq!(message2(&process, &frame), None);
        frame = bootstrap_request(&mut memory, local);
        memory[32..36].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(message2(&process, &frame), None);
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
