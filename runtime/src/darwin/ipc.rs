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

pub(super) fn message2(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    // Scalar send-and-receive, kernel-object call, no voucher, descriptors,
    // timeout or receive priority. Other modes need their own state machine.
    if a[1] != 0x2_0000_0003
        || a[2] >> 32 != 40
        || a[2] as u32 != 0x1513
        || a[4] as u32 != 0
        || a[5] as u32 != 0
        || a[6] >> 32 != 0
        || a[7] != 0
    {
        return None;
    }
    let remote = a[3] as u32;
    let local = (a[3] >> 32) as u32;
    if remote != 0x303 || a[4] >> 32 != 200 {
        return None;
    }
    let (read, write) = (process.copy_in?, process.copy_out?);
    if !process.ports.has_send(remote) {
        return Some(0x10000003);
    }
    if local != (a[5] >> 32) as u32 || !process.ports.is_reply(local) {
        return Some(0x10004002);
    }
    let mut request = [0u8; 40];
    if unsafe {
        read(
            process.host_context,
            a[0],
            request.as_mut_ptr(),
            request.len(),
        )
    } != 0
    {
        return Some(0x10000002);
    }
    if word(&request, 0) != a[2] as u32
        || word(&request, 4) != 40
        || word(&request, 8) != remote
        || word(&request, 12) != local
        || word(&request, 16) != 0
        || word(&request, 20) != 200
    {
        return Some(0x10000010);
    }
    if request[24..32] != NDR || word(&request, 32) != 5 {
        return None;
    }
    let count = word(&request, 36);
    let size = if count >= 8 { 72 } else { 36 };
    if (a[6] as u32) < size {
        return Some(0x10004004);
    }
    let mut reply = [0u8; 72];
    // Received header: the destination becomes the local reply-port name.
    for (i, value) in [0x1200, size, 0, local, 0, 300].into_iter().enumerate() {
        reply[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    reply[24..32].copy_from_slice(&NDR);
    if count < 8 {
        reply[32..36].copy_from_slice(&5u32.to_le_bytes()); // KERN_FAILURE
    } else {
        reply[36..40].copy_from_slice(&8u32.to_le_bytes());
        for (i, priority) in PRIORITIES.iter().enumerate() {
            reply[40 + i * 4..44 + i * 4].copy_from_slice(&priority.to_le_bytes());
        }
    }
    // COPY_SEND preserves the host send reference. MAKE_SEND_ONCE supplies a
    // single kernel reply and is consumed by this synchronous delivery; it does
    // not create a lasting user send right on the reply port.
    if unsafe { write(process.host_context, a[0], reply.as_ptr(), size as usize) } != 0 {
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
