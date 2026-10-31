//! Synchronous messages to compatibility-kernel objects. This is not a daemon
//! registry: unknown RPCs remain unsupported until their object semantics exist.
use super::{Process, TrapFrame};

#[cfg(test)]
const NDR: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn quad(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

fn service_port(process: &Process, port: &std::sync::atomic::AtomicU32) -> Option<u32> {
    let existing = port.load(std::sync::atomic::Ordering::Acquire);
    if existing != 0 && process.ports.has_receive(existing) {
        if process.ports.has_send(existing) || process.ports.acquire_send(existing) {
            return Some(existing);
        }
        return None;
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

pub(crate) fn bootstrap_service(process: &Process) -> Option<u32> {
    service_port(process, &process.bootstrap_port)
}

pub(crate) fn clock_service(process: &Process) -> Option<u32> {
    service_port(process, &process.clock_port)
}

pub(crate) fn io_main_service(process: &Process) -> Option<u32> {
    service_port(process, &process.io_main_port)
}

pub(crate) fn io_registry_service(process: &Process) -> Option<u32> {
    service_port(process, &process.io_registry_port)
}

pub(crate) fn io_display_service(process: &Process) -> Option<u32> {
    service_port(process, &process.io_display_service_port)
}

pub(crate) fn semaphore_service(process: &Process) -> Option<u32> {
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
    if let Some(result) = super::iokit::message2(process, frame) {
        return Some(result);
    }
    if let Some(result) = send_vector(process, frame) {
        return Some(result);
    }
    let request_size = (a[2] >> 32) as usize;
    // libdispatch uses the mach_msg2 message-queue fast path for local
    // send-only notifications. There is no reply buffer to populate and no
    // host daemon to contact; once the destination send right is valid,
    // accepting the queue send is equivalent to kernel delivery.
    const MACH64_SEND_MQ_CALL: u64 = 0x0000_0004_0000_0000;
    const MACH_SEND_MSG: u64 = 0x1;
    const MACH_RCV_MSG: u64 = 0x2;
    if a[1] & MACH64_SEND_MQ_CALL != 0 {
        if a[1] & MACH_SEND_MSG == 0 {
            if a[1] & MACH_RCV_MSG == 0 {
                return None;
            }
            // Scalar and vector receive-only calls both use a5's high half as
            // the receive name. No service can enqueue into this local right,
            // so the Darwin-correct result is a receive timeout.
            let receive = (a[5] >> 32) as u32;
            return Some(if receive != 0 {
                0x1000_4003 // MACH_RCV_TIMED_OUT
            } else {
                0x1000_4002 // MACH_RCV_INVALID_NAME
            });
        }
        if request_size < 24 {
            return None;
        }
        let remote = a[3] as u32;
        if !process.ports.has_send(remote) {
            return Some(0x1000_0003); // MACH_SEND_INVALID_DEST
        }
        if a[1] & MACH_RCV_MSG != 0 {
            let sent = super::xpc::send(process, frame, a[0], request_size).unwrap_or(0x1000_0003);
            if sent != 0 {
                return Some(sent);
            }
            // A successful combined trap must copy out its reply now. Merely
            // queueing it leaves a stale reply on the thread's reusable port.
            let mut receive = TrapFrame {
                number: frame.number,
                arguments: frame.arguments,
                ..Default::default()
            };
            receive.arguments[1] &= !MACH_SEND_MSG;
            receive.arguments[2] = 0;
            return super::xpc::receive(process, &receive).or(Some(
                if process.ports.has_receive((a[5] >> 32) as u32) {
                    0x1000_4003
                } else {
                    0x1000_4002
                },
            ));
        }
        return Some(0);
    }
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
    let registry_path =
        id == 2809 && (44..=552).contains(&request_size) && request_size.is_multiple_of(4);
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
        return None;
    }
    let port_limits_rpc = a[3] as u32 == 0x103
        && id == 3218
        && (44..=112).contains(&request_size)
        && request_size.is_multiple_of(4);
    if !(matches!(
        request_size,
        24 | 36 | 40 | 48 | 52 | 68 | 80 | 84 | 88 | 92 | 96 | 100 | 104
    ) || (restartable && (36..=1060).contains(&request_size))
        || registry_path
        || port_limits_rpc)
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
        (0x303, 200 | 205 | 206 | 412)
            | (
                0x103,
                3218 | 3405 | 3409 | 3410 | 3418 | 4811 | 4813 | 8000 | 8001
            )
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
    if id == 3418 && !process.ports.has_send(remote) {
        if !process.ports.acquire_send(remote) {
            return Some(0x10000003);
        }
    }
    if id == 2809
        && known_io_main != 0
        && remote == known_io_main
        && process.ports.has_receive(remote)
        && !process.ports.has_send(remote)
        && !process.ports.acquire_send(remote)
    {
        return Some(0x10000003);
    }
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

    let msg = crate::mig::MachMessage::parse(&request[..request_size])?;
    let (mut reply, reply_size, is_complex) = match process.mig.dispatch(process, frame, &msg) {
        Some(crate::mig::MigReply::Status(err)) => return Some(err),
        Some(crate::mig::MigReply::Buffer {
            bytes,
            size,
            complex,
        }) => (bytes, size as u32, complex),
        None => return None,
    };
    let reply_bits = if is_complex { 0x8000_1200 } else { 0x1200 };
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

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&s[at..at + 2], 16).unwrap())
            .collect()
    }

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

    #[cfg(target_os = "macos")]
    fn assert_native_iokit_string(data: &[u8], expected: &str) {
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
            fn CFStringGetTypeID() -> usize;
            fn CFStringGetCString(
                value: *const c_void,
                buffer: *mut i8,
                size: isize,
                encoding: u32,
            ) -> u8;
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
            assert!(!value.is_null(), "IOKit rejected the serialized string");
            assert_eq!(CFGetTypeID(value), CFStringGetTypeID());
            let mut decoded = [0i8; 16];
            assert_ne!(
                CFStringGetCString(
                    value,
                    decoded.as_mut_ptr(),
                    decoded.len() as isize,
                    0x0800_0100, // kCFStringEncodingUTF8
                ),
                0
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(decoded.as_ptr()).to_str().unwrap(),
                expected
            );
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
    unsafe extern "C" fn read_send_memory(
        context: *const c_void,
        address: u64,
        out: *mut u8,
        size: usize,
    ) -> u32 {
        let memory = &*(context as *const [u8; 4096]);
        let Some(end) = (address as usize).checked_add(size) else {
            return 14;
        };
        let Some(bytes) = memory.get(address as usize..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, size);
        0
    }
    unsafe extern "C" fn write_send_memory(
        context: *const c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        let memory = &mut *(context as *mut [u8; 4096]);
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
    fn set_port_limits_rpc_updates_state_and_reports_kernel_errors() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        let port = process.ports.construct(0x10).unwrap();
        for (name, flavor, count, limit, expected) in [
            (port, 1, 1, 16, 0),
            (port, 1, 1, 1024, 0),
            (port, 1, 1, 1025, 18),
            (port, 2, 1, 5, 4),
            (port, 1, 0, 5, 5),
            (0xbeef, 1, 1, 5, 15),
            (0x103, 1, 1, 5, 17),
        ] {
            memory.fill(0);
            for (offset, value) in [
                (0, 0x1513u32),
                (4, 48),
                (8, 0x103),
                (12, local),
                (20, 3218),
                (32, name),
                (36, flavor),
                (40, count),
                (44, limit),
            ] {
                memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            let send_size = 44 + count * 4;
            memory[4..8].copy_from_slice(&send_size.to_le_bytes());
            memory[24..32].copy_from_slice(&NDR);
            let frame = TrapFrame {
                number: -47,
                arguments: [
                    0,
                    0x2_0000_0003,
                    u64::from(send_size) << 32 | 0x1513,
                    (u64::from(local) << 32) | 0x103,
                    3218 << 32,
                    u64::from(local) << 32,
                    128,
                    0,
                ],
                ..Default::default()
            };
            let old_limit = process.ports.queue_limit(port).unwrap();
            assert_eq!(message2(&process, &frame), Some(0));
            assert_eq!(word(&memory, 20), 3318);
            assert_eq!(word(&memory, 32), expected);
            assert_eq!(word(&memory, 4), 36);
            assert_eq!(word(&memory, 12), local);
            assert_eq!(
                process.ports.queue_limit(port).unwrap(),
                if expected == 0 { limit } else { old_limit }
            );
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
    fn message_queue_send_accepts_a_valid_send_right_without_a_reply() {
        let process = Process::new(1, 0, 2);
        let port = process.ports.construct(0x10).unwrap();
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0x1000,
                0x4_0000_0011,
                24 << 32 | 0x13,
                u64::from(port),
                78 << 32,
                0,
                0,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        let receive_half = TrapFrame {
            arguments: [
                0x1000,
                0x4_0000_0013,
                24 << 32 | 0x13,
                u64::from(port),
                78 << 32,
                0,
                0,
                0,
            ],
            ..frame
        };
        assert_eq!(message2(&process, &receive_half), Some(0x1000_0003));
        let receive_only = TrapFrame {
            arguments: [
                0x1000,
                0x4_0000_0102,
                0,
                0,
                0,
                u64::from(port) << 32,
                108,
                0,
            ],
            ..frame
        };
        assert_eq!(message2(&process, &receive_only), Some(0x1000_4003));
        let vector_receive = TrapFrame {
            arguments: [
                0x1000,
                0x5_0700_0906,
                2 << 32,
                0,
                0,
                u64::from(port) << 32,
                2,
                0,
            ],
            ..frame
        };
        assert_eq!(message2(&process, &vector_receive), Some(0x1000_4003));
        let no_receive_name = TrapFrame {
            arguments: [0x1000, 0x5_0700_0906, 2 << 32, 0, 0, 0, 2, 0],
            ..frame
        };
        assert_eq!(message2(&process, &no_receive_name), Some(0x1000_4002));
        let invalid = TrapFrame {
            arguments: [
                0x1000,
                0x4_0000_0011,
                24 << 32 | 0x13,
                0x2204,
                78 << 32,
                0,
                0,
                0,
            ],
            ..frame
        };
        assert_eq!(message2(&process, &invalid), Some(0x1000_0003));
    }

    #[test]
    fn notification_center_send_receive_message_queue_uses_local_xpc_reply() {
        let mut process = Process::new(77, 1, 2);
        let mut memory = Box::new([0u8; 4096]);
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read_send_memory);
        process.copy_out = Some(write_send_memory);
        let bootstrap = bootstrap_service(&process).unwrap();
        let reply = process.ports.construct(0x1000).unwrap();

        let request = hex(concat!(
            "13151300d8000000030b0000030d0000030e0000cf000040",
            "435058400500000000f00000b000000006000000",
            "68616e646c650000004000000000000000000000",
            "696e7374616e63650000000000a0000000000000000000000000000000000000",
            "666c616773000000004000000800000000000000",
            "6e616d65000000000090000025000000636f6d2e6170706c652e73797374656d2e",
            "6e6f74696669636174696f6e5f63656e74657200000000",
            "7479706500000000004000000700000000000000",
            "746172676574706964000000003000000000000000000000"
        ));
        assert_eq!(request.len(), 216);
        let mut request = request;
        request[8..12].copy_from_slice(&bootstrap.to_le_bytes());
        request[12..16].copy_from_slice(&reply.to_le_bytes());
        request[16..20].fill(0);
        let message_address = 64usize;
        memory[message_address..message_address + request.len()].copy_from_slice(&request);

        let frame = TrapFrame {
            number: -47,
            arguments: [
                message_address as u64,
                0x4_0311_4207,
                (request.len() as u64) << 32 | 0x13_1513,
                u64::from(reply) << 32 | u64::from(bootstrap),
                0x4000_00cf << 32,
                u64::from(reply) << 32,
                216,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(
            super::super::xpc::bootstrap_lookup_name(&request[24..]),
            Some(b"com.apple.system.notification_center\0".as_slice())
        );
        let mut copied = [0u8; 216];
        assert_eq!(
            unsafe {
                process.copy_in.unwrap()(
                    process.host_context,
                    message_address as u64,
                    copied.as_mut_ptr(),
                    copied.len(),
                )
            },
            0
        );
        assert_eq!(copied.as_slice(), request.as_slice());
        assert_eq!(word(&copied, 8), bootstrap);
        assert_eq!(word(&copied, 12), reply);
        // A missing service must leave launchd's shared pipe usable for the
        // next lookup. Keep the wire envelope identical to the captured call.
        let service_at = request.windows(6).position(|v| v == b"system").unwrap();
        memory[message_address + service_at..message_address + service_at + 6]
            .copy_from_slice(b"absent");
        assert_eq!(message2(&process, &frame), Some(0));
        let failed = &memory[message_address..];
        assert_eq!(word(failed, 0), 0x1200);
        assert_eq!(&failed[44..50], b"error\0");
        assert_eq!(word(failed, 52), 0x3000); // signed int64 ESRCH
        assert_eq!(quad(failed, 56), 3);
        let failed_size = word(failed, 4) as usize;
        assert_eq!(word(failed, failed_size + 40), 1); // bootstrap audit pid
        memory[message_address..message_address + request.len()].copy_from_slice(&request);
        assert_eq!(message2(&process, &frame), Some(0));
        let result = &memory[message_address..];
        let size = word(result, 4) as usize;
        assert_eq!(word(result, 12), reply);
        assert_eq!(word(result, 20), 0x2000_0000);
        assert_eq!(word(result, 24), 1); // complex Mach body, one descriptor
        assert!(process.ports.has_send(word(result, 28)));
        assert_eq!(word(result, 36), 17 << 16);
        assert_eq!(word(result, 40), 0x4058_5043);
        assert_eq!(word(result, size + 4), 52); // requested audit trailer
        assert_eq!(word(result, size + 24), 0); // bootstrap effective uid
        assert_eq!(word(result, size + 40), 1); // bootstrap sender, not client pid 77
        let receive = TrapFrame {
            number: -47,
            arguments: [
                message_address as u64,
                0x4_0700_420e,
                0,
                0,
                0,
                u64::from(reply) << 32,
                512,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(
            message2(&process, &receive),
            Some(0x10004003),
            "combined call must not leave a stale reply"
        );
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
        memory[24..32].copy_from_slice(&NDR);
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
        memory[24..32].copy_from_slice(&NDR);
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
        memory[24..32].copy_from_slice(&NDR);
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
    fn iokit_absent_registry_paths_return_null_without_creating_hardware() {
        for malformed in [false, true] {
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
            for (offset, value) in [
                (0, 0x1513u32),
                (4, 64),
                (8, io_main),
                (12, local),
                (20, 2809),
                (36, 22),
            ] {
                memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            memory[24..32].copy_from_slice(&NDR);
            memory[40..62].copy_from_slice(b"IODeviceTree:/buttons\0");
            if malformed {
                memory[61] = b'x';
            }
            let original = memory;
            let frame = TrapFrame {
                number: -47,
                arguments: [
                    0,
                    0x2_0000_0003,
                    (64 << 32) | 0x1513,
                    ((local as u64) << 32) | u64::from(io_main),
                    2809 << 32,
                    (local as u64) << 32,
                    48,
                    0,
                ],
                ..Default::default()
            };
            if malformed {
                assert_eq!(message2(&process, &frame), None);
                assert_eq!(memory, original);
            } else {
                assert_eq!(message2(&process, &frame), Some(0));
                assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 40));
                assert_eq!((word(&memory, 24), word(&memory, 28)), (1, 0));
                assert_eq!(word(&memory, 36), 17 << 16);
            }
            assert_eq!(
                process
                    .io_registry_port
                    .load(std::sync::atomic::Ordering::Acquire),
                0
            );
        }
    }

    #[test]
    fn iokit_product_path_acquires_receive_only_master_and_returns_local_service() {
        let mut process = Process::new(1, 0, 2);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let io_main = process.ports.construct(0x10).unwrap();
        assert_eq!(process.ports.deallocate(io_main), 0);
        assert!(process.ports.has_receive(io_main));
        assert!(!process.ports.has_send(io_main));
        process
            .io_main_port
            .store(io_main, std::sync::atomic::Ordering::Release);
        let local = process.ports.construct(0x1000).unwrap();
        memory.fill(0);
        let captured = hex("1315000040000000032200000308000000000000f90a000000000000010000000000000016000000494f446576696365547265653a2f70726f64756374000000");
        assert_eq!(captured.len(), 64);
        memory[..64].copy_from_slice(&captured);
        for (offset, value) in [(8, io_main), (12, local)] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (64 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(io_main),
                2809 << 32,
                (local as u64) << 32,
                48,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 40));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2909));
        assert_eq!((word(&memory, 24), word(&memory, 32)), (1, 0));
        let service = word(&memory, 28);
        assert_ne!(service, 0);
        assert_ne!(service, io_main);
        assert!(process.ports.has_receive(service));
        assert!(process.ports.has_send(service));
        assert_eq!(word(&memory, 36), 17 << 16);
        assert!(process.ports.has_send(io_main));
        assert_eq!(
            process
                .io_registry_port
                .load(std::sync::atomic::Ordering::Acquire),
            service
        );
        assert_eq!(
            process
                .io_display_service_port
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );

        // Releasing the descriptor's user reference must leave the
        // service-owned dispatch reference usable by the property RPC.
        assert_eq!(process.ports.modify_send_refs(service, -1), 0);
        assert!(process.ports.has_send(service));

        memory.fill(0);
        let captured = hex("1315000060000000032300000308000000000000490b000000000000010000000000000001000000000000000000000016000000617274776f726b2d646973706c61792d67616d757400000000000000a8c067135f0000000008000000000000");
        assert_eq!(captured.len(), 96);
        memory[..96].copy_from_slice(&captured);
        for (offset, value) in [(8, service), (12, local)] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        // Redirect only the captured guest pointer into this test's memory.
        memory[80..88].copy_from_slice(&96u64.to_le_bytes());
        let property = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (96 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(service),
                2889 << 32,
                (local as u64) << 32,
                72,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &property), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x8000_1200, 64));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2989));
        assert_eq!(word(&memory, 24), 1);
        assert_eq!(quad(&memory, 28), 0); // properties == NULL
        assert_eq!(word(&memory, 36), 1 << 24);
        assert_eq!(word(&memory, 40), 0);
        assert_eq!(&memory[44..52], &NDR);
        assert_eq!(u64::from_le_bytes(memory[52..60].try_into().unwrap()), 12);
        assert_eq!(word(&memory, 60), 0); // propertiesCnt == 0
        let serialized = &[0xd3, 0, 0, 0, 2, 0, 0, 0x89, b'P', b'3', 0, 0];
        assert_eq!(&memory[96..108], serialized);
        assert!(process.ports.has_send(service));
        #[cfg(target_os = "macos")]
        assert_native_iokit_string(&memory[96..108], "P3");
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
            (72, 0x1000),
            (80, 2048),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        memory[24..32].copy_from_slice(&NDR);
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
        assert_eq!(word(&memory, 32), 0xe000_02f0);
    }

    #[test]
    fn iokit_property_bin_buf_accepts_the_full_captured_layout() {
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
        let captured = hex("1315000068000000033500000308000000000000490b0000000000000100000000000000010000000000000000000000200000004261736541646472657373416c69676e6d656e74526571756972656d656e74000000000048c30f3b5a0000000008000000000000");
        assert_eq!(captured.len(), 104);
        memory[..104].copy_from_slice(&captured);
        for (offset, value) in [(8, registry), (12, local)] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (104 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(registry),
                2889 << 32,
                (local as u64) << 32,
                72,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x1200, 36));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2989));
        assert_eq!(&memory[24..32], &NDR);
        assert_eq!(word(&memory, 32), 0xe000_02f0);
    }

    #[test]
    fn iokit_property_bin_buf_accepts_a_96_byte_request() {
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
            (4, 96),
            (8, registry),
            (12, local),
            (20, 2889),
            (36, 1),
            (48, 23),
        ] {
            memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        memory[24..32].copy_from_slice(&NDR);
        memory[52..75].copy_from_slice(b"IOPlatformSerialNumber\0");
        memory[80..88].copy_from_slice(&96u64.to_le_bytes());
        memory[88..96].copy_from_slice(&2048u64.to_le_bytes());
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (96 << 32) | 0x1513,
                ((local as u64) << 32) | u64::from(registry),
                2889 << 32,
                (local as u64) << 32,
                72,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 0), word(&memory, 4)), (0x1200, 36));
        assert_eq!((word(&memory, 12), word(&memory, 20)), (local, 2989));
        assert_eq!(word(&memory, 32), 0xe000_02f0);
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
        assert_eq!(process.ports.deallocate(0x103), 0);
        assert!(!process.ports.has_send(0x103));
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

    unsafe extern "C" fn signed_aot_remap(
        _: *const c_void,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: u32,
        source: u64,
        copy: u32,
        current: *mut u32,
        maximum: *mut u32,
        inheritance: u32,
    ) -> u32 {
        if *address != 0x70004000
            || size != 0xc000
            || mask != 0
            || flags != 0x4000
            || source != 0x78000000
            || copy != 1
            || inheritance != 0
        {
            return 4;
        }
        *current = 5;
        *maximum = 5;
        0
    }

    #[test]
    fn mach_vm_remap_validates_task_descriptor_and_returns_address_and_protections() {
        fn put(bytes: &mut [u8], at: usize, value: u32) {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut process = Process::new(1, 0, 2);
        process.vm_remap = Some(signed_aot_remap);
        let mut memory = [0u8; 128];
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        assert!(process.ports.acquire_send(0x103));
        let local = process.ports.construct(0x1000).unwrap();
        let mut request = [0u8; 92];
        for (i, value) in [0x80001513, 92, 0x103, local, 0, 4813]
            .into_iter()
            .enumerate()
        {
            put(&mut request, i * 4, value);
        }
        put(&mut request, 24, 1);
        put(&mut request, 28, 0x103);
        put(&mut request, 36, 19 << 16);
        request[40..48].copy_from_slice(&NDR);
        request[48..56].copy_from_slice(&0x70004000u64.to_le_bytes());
        request[56..64].copy_from_slice(&0xc000u64.to_le_bytes());
        put(&mut request, 72, 0x4000);
        request[76..84].copy_from_slice(&0x78000000u64.to_le_bytes());
        put(&mut request, 84, 1);
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x200000003,
                (92 << 32) | 0x80001513,
                ((local as u64) << 32) | 0x103,
                4813 << 32,
                ((local as u64) << 32) | 1,
                60,
                0,
            ],
            ..Default::default()
        };
        memory[..92].copy_from_slice(&request);
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(
            (word(&memory, 4), word(&memory, 20), word(&memory, 32)),
            (52, 4913, 0)
        );
        assert_eq!(
            (quad(&memory, 36), word(&memory, 44), word(&memory, 48)),
            (0x70004000, 5, 5)
        );
        memory[..92].copy_from_slice(&request);
        put(&mut memory, 28, 0x303);
        assert_eq!(message2(&process, &frame), None);
        memory[..92].copy_from_slice(&request);
        put(&mut memory, 84, 0);
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!((word(&memory, 4), word(&memory, 32)), (36, 4));
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
