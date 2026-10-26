//! Local replies for the private display service queried by BackBoardServices.
//!
//! The observed `BKSDisplayGetMainScreenInfo` request is a 24-byte scalar Mach
//! message with no body. Its reply is a 60-byte message whose status and screen
//! geometry are read directly by the original BackBoardServices code. The
//! service is local because backboardd is absent from the guest process.
use super::{Process, TrapFrame};

const REQUEST_ID: u32 = 0x005b_9175;
const REPLY_ID: u32 = REQUEST_ID + 100;
const SEND_AND_RECEIVE: u64 = 0x4_0030_4003;
const REQUEST_BITS: u32 = 0x0013_1513;
const REPLY_BITS: u32 = 0x1113;
const MESSAGE_SIZE: usize = 60;
const TRAILER_SIZE: usize = 8;

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_float(bytes: &mut [u8], at: usize, value: f32) {
    put(bytes, at, value.to_bits());
}

fn reject(process: &Process, message: &[u8]) -> Option<u32> {
    if let Some(console) = process.console {
        unsafe {
            console(process.host_context, 2, message.as_ptr(), message.len());
        }
    }
    None
}

/// Handle the observed BackBoardServices main-screen query as one synchronous
/// send-and-receive trap. The guest receives a real local reply in the same
/// buffer used for its request; no external daemon identity is fabricated.
pub(super) fn message2(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    let request_size = (a[2] >> 32) as usize;
    let reply_port = (a[3] >> 32) as u32;
    let receive_port = (a[5] >> 32) as u32;
    let voucher = a[4] as u32;
    if (a[4] >> 32) as u32 != REQUEST_ID {
        return None;
    }
    if a[1] != SEND_AND_RECEIVE {
        return reject(process, b"local display: unexpected send mode\n");
    }
    if request_size != 24 {
        return reject(process, b"local display: unexpected request size\n");
    }
    if a[2] as u32 != REQUEST_BITS {
        return reject(process, b"local display: unexpected trap flags\n");
    }
    if a[3] as u32 != 0 {
        return reject(process, b"local display: unexpected remote port\n");
    }
    if reply_port == 0 || reply_port != receive_port {
        return reject(process, b"local display: invalid reply port\n");
    }
    if voucher == 0 {
        return reject(process, b"local display: missing voucher port\n");
    }
    if a[5] as u32 != 0 {
        return reject(process, b"local display: unexpected receive flags\n");
    }
    if a[6] != 68 || a[7] != 0 {
        return reject(process, b"local display: invalid receive size\n");
    }
    if !process.ports.has_receive(reply_port) {
        return reject(process, b"local display: reply port lacks receive right\n");
    }

    let read = process.copy_in?;
    let write = process.copy_out?;
    let mut request = [0u8; 24];
    if unsafe {
        read(
            process.host_context,
            a[0],
            request.as_mut_ptr(),
            request.len(),
        )
    } != 0
    {
        return Some(0x10000002); // MACH_SEND_INVALID_DATA
    }
    // libsystem leaves msgh_size zero for this preconstructed scalar request.
    if word(&request, 0) != REQUEST_BITS
        || word(&request, 4) != 0
        || word(&request, 8) != 0
        || word(&request, 12) != reply_port
        || word(&request, 16) != voucher
        || word(&request, 20) != REQUEST_ID
    {
        return reject(process, b"local display: request header mismatch\n");
    }

    let mut reply = [0u8; MESSAGE_SIZE + TRAILER_SIZE];
    put(&mut reply, 0, REPLY_BITS);
    put(&mut reply, 4, MESSAGE_SIZE as u32);
    put(&mut reply, 8, 0);
    put(&mut reply, 12, reply_port);
    put(&mut reply, 16, 0);
    put(&mut reply, 20, REPLY_ID);
    // The original client reads a signed status at message offset 32, then
    // four floats, followed by two byte-valued display flags.
    put(&mut reply, 32, 0);
    put_float(&mut reply, 36, process.display_width as f32);
    put_float(&mut reply, 40, process.display_height as f32);
    put_float(&mut reply, 44, process.display_scale);
    put_float(&mut reply, 48, process.display_native_scale);
    reply[52] = 1; // main display
    reply[56] = 1; // built-in display
    put(&mut reply, MESSAGE_SIZE, 0); // format-0 trailer
    put(&mut reply, MESSAGE_SIZE + 4, TRAILER_SIZE as u32);

    if unsafe { write(process.host_context, a[0], reply.as_ptr(), reply.len()) } != 0 {
        return Some(0x10004008); // MACH_RCV_INVALID_DATA
    }
    Some(0)
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
        let memory = &*(context as *const [u8; 256]);
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
        let memory = &mut *(context as *mut [u8; 256]);
        let Some(end) = (address as usize).checked_add(size) else {
            return 14;
        };
        let Some(bytes) = memory.get_mut(address as usize..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(data, bytes.as_mut_ptr(), size);
        0
    }

    fn request(memory: &mut [u8; 256], port: u32, voucher: u32) -> TrapFrame {
        for (index, value) in [REQUEST_BITS, 0, 0, port, voucher, REQUEST_ID]
            .into_iter()
            .enumerate()
        {
            put(memory, index * 4, value);
        }
        TrapFrame {
            number: -47,
            arguments: [
                0,
                SEND_AND_RECEIVE,
                (24 << 32) | u64::from(REQUEST_BITS),
                u64::from(port) << 32,
                u64::from(REQUEST_ID) << 32 | u64::from(voucher),
                u64::from(port) << 32,
                68,
                0,
            ],
            ..Default::default()
        }
    }

    #[test]
    fn screen_query_returns_geometry_and_a_format_zero_trailer() {
        let mut process = Process::new(42, 1, 99);
        let mut memory = [0u8; 256];
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        process.host_context = memory.as_mut_ptr().cast();
        process.display_width = 1272;
        process.display_height = 2860;
        process.display_scale = 3.5;
        process.display_native_scale = 3.5;
        let reply = process.ports.construct(0x10).unwrap();
        let voucher = process.ports.construct(0x10).unwrap();
        let frame = request(&mut memory, reply, voucher);

        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 0), REPLY_BITS);
        assert_eq!(word(&memory, 4), MESSAGE_SIZE as u32);
        assert_eq!(word(&memory, 8), 0);
        assert_eq!(word(&memory, 12), reply);
        assert_eq!(word(&memory, 20), REPLY_ID);
        assert_eq!(word(&memory, 32), 0);
        assert_eq!(f32::from_bits(word(&memory, 36)), 1272.0);
        assert_eq!(f32::from_bits(word(&memory, 40)), 2860.0);
        assert_eq!(f32::from_bits(word(&memory, 44)), 3.5);
        assert_eq!(f32::from_bits(word(&memory, 48)), 3.5);
        assert_eq!((memory[52], memory[56]), (1, 1));
        assert_eq!((word(&memory, 60), word(&memory, 64)), (0, 8));
    }

    #[test]
    fn unrelated_or_unknown_port_requests_stay_unsupported() {
        let mut process = Process::new(42, 1, 99);
        let mut memory = [0u8; 256];
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        process.host_context = memory.as_mut_ptr().cast();
        let reply = process.ports.construct(0x10).unwrap();
        let voucher = process.ports.construct(0x10).unwrap();
        let mut frame = request(&mut memory, reply, voucher);
        frame.arguments[1] = 0x2_0000_0003;
        assert_eq!(message2(&process, &frame), None);

        frame = request(&mut memory, reply, voucher);
        frame.arguments[4] = 0x005b_9174_0000_0000 | u64::from(voucher);
        assert_eq!(message2(&process, &frame), None);
    }
}
