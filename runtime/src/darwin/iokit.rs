//! Matching notifications for the local IOKit registry's HID inventory.
//! No IOHIDDevice backend is registered yet: matching iterators are empty.
//! Preserve the subscription and callback references without fabricating an
//! input device or dispatching synthetic hardware callbacks.
use super::ipc::io_registry_service;
use super::{Process, TrapFrame};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};

const NDR: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];
const INVALID_DATA: u32 = 0x10000002;
const INVALID_DEST: u32 = 0x10000003;
const TOO_LARGE: u32 = 0x10004004;

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn quad(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}
fn align(size: usize) -> Option<usize> {
    Some(size.checked_add(3)? & !3)
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Matching {
    page: Option<u32>,
    usage: Option<u32>,
}

// The observed IOCFSerialize binary dictionary, with bounded symbol/string
// keys and 32/64-bit numeric properties. Unsupported registry matching syntax
// remains an explicit boundary rather than an unconditional no-match answer.
fn matching(bytes: &[u8]) -> Option<Matching> {
    if word(bytes, 0)? != 0xd3 {
        return None;
    }
    let header = word(bytes, 4)?;
    let count = (header & 0xffffff) as usize;
    if header & 0xff000000 != 0x81000000 || !(1..=3).contains(&count) {
        return None;
    }
    let mut at = 8;
    let mut result = Matching::default();
    let mut seen = 0;
    for index in 0..count {
        let tag = word(bytes, at)?;
        let size = (tag & 0xffffff) as usize;
        if tag & 0xff000000 != 0x08000000 || !(1..=64).contains(&size) {
            return None;
        }
        let key = bytes.get(at + 4..at + 4 + size)?;
        if key.last() != Some(&0) {
            return None;
        }
        at += 4 + align(size)?;
        let value = word(bytes, at)?;
        if (value & 0x80000000 != 0) != (index + 1 == count) {
            return None;
        }
        let bit = match key {
            b"IOProviderClass\0" | b"IONameMatch\0" => {
                if value & 0x7f000000 != 0x09000000 {
                    return None;
                }
                let size = (value & 0xffffff) as usize;
                let provider = bytes.get(at + 4..at + 4 + size)?;
                if !matches!(
                    provider,
                    b"IOHIDDevice"
                        | b"IOHIDDevice\0"
                        | b"IOAcceleratorES"
                        | b"IOAcceleratorES\0"
                        | b"AGXAccelerator"
                        | b"AGXAccelerator\0"
                        | b"IOPlatformExpertDevice"
                        | b"IOPlatformExpertDevice\0"
                        | b"IOCoreSurfaceRoot"
                        | b"IOCoreSurfaceRoot\0"
                ) {
                    return None;
                }
                at += 4 + align(size)?;
                1
            }
            b"DeviceUsagePage\0" | b"DeviceUsage\0" => {
                if value & 0x7f000000 != 0x04000000 || !matches!(value & 0xffffff, 32 | 64) {
                    return None;
                }
                let number = u32::try_from(quad(bytes, at + 4)?).ok()?;
                at += 12;
                if key == b"DeviceUsagePage\0" {
                    result.page = Some(number);
                    2
                } else {
                    result.usage = Some(number);
                    4
                }
            }
            _ => return None,
        };
        if seen & bit != 0 {
            return None;
        }
        seen |= bit;
    }
    (at == bytes.len() && seen & 1 != 0).then_some(result)
}

#[derive(Clone, Copy, Default)]
// Retain the client's notification/callback metadata even while the registry
// has no HID service to match. No callback can be delivered in that inventory.
#[allow(dead_code)]
struct Subscription {
    iterator: u32,
    wake: u32,
    kind: u32,
    matching: Matching,
    references: [u64; 8],
    reference_count: usize,
    armed: bool,
}

pub(crate) struct State {
    busy: AtomicBool,
    slots: UnsafeCell<[Subscription; 32]>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            busy: AtomicBool::new(false),
            slots: UnsafeCell::new([Subscription::default(); 32]),
        }
    }
}
// Access is protected by a nonblocking claim, including nested signal paths.
unsafe impl Sync for State {}
struct Claim<'a>(&'a AtomicBool);
impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl State {
    fn with<T>(&self, operation: impl FnOnce(&mut [Subscription; 32]) -> T) -> Option<T> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let _claim = Claim(&self.busy);
        Some(operation(unsafe { &mut *self.slots.get() }))
    }
    pub(super) fn reap(&self, process: &Process) {
        self.with(|slots| reap(slots, process));
    }
}
fn reap(slots: &mut [Subscription; 32], process: &Process) {
    for slot in slots {
        if slot.iterator != 0 && !process.ports.has_send(slot.iterator) {
            process.ports.deallocate(slot.wake);
            *slot = Subscription::default();
        }
    }
}

fn reply(id: u32, local: u32, object: u32) -> [u8; 48] {
    let mut bytes = [0; 48];
    for (index, value) in [
        0x80001200u32,
        40,
        0,
        local,
        0,
        id + 100,
        1,
        object,
        0,
        17 << 16,
    ]
    .into_iter()
    .enumerate()
    {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[44..48].copy_from_slice(&8u32.to_le_bytes()); // format-0 trailer
    bytes
}

fn status_reply(id: u32, local: u32, status: u32) -> [u8; 44] {
    let mut bytes = [0; 44];
    for (index, value) in [0x1200u32, 36, 0, local, 0, id + 100]
        .into_iter()
        .enumerate()
    {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[24..32].copy_from_slice(&NDR);
    bytes[32..36].copy_from_slice(&status.to_le_bytes());
    bytes[40..44].copy_from_slice(&8u32.to_le_bytes()); // format-0 trailer
    bytes
}

fn empty_reply(id: u32, local: u32) -> [u8; 44] {
    // XNU's is_io_iterator_next returns kIOReturnNoDevice on exhaustion;
    // MIG encodes that as a simple error reply, without an object descriptor.
    status_reply(id, local, 0xe00002c0)
}

pub(super) fn message2(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    let id = (a[4] >> 32) as u32;
    if !matches!(id, 2862 | 2865 | 2880 | 2881 | 2884 | 2816 | 2802) {
        return None;
    }
    let remote = a[3] as u32;
    if id == 2884 && (remote == 0 || remote != process.io_main_port.load(Ordering::Acquire)) {
        return None;
    }
    if matches!(id, 2880 | 2881) && remote == 0 {
        return None;
    }
    let size = (a[2] >> 32) as usize;
    if a[1] != 0x2_0000_0003
        || a[4] as u32 != 0
        || (id != 2862 && a[5] as u32 > 1)
        || (id == 2862 && a[5] as u32 > 2)
        || a[6] >> 32 != 0
        || a[7] != 0
        || !(24..=512).contains(&size)
    {
        return None;
    }
    if matches!(id, 2880 | 2881)
        && !process.ports.has_send(remote)
        && process.ports.has_receive(remote)
    {
        if !process.ports.acquire_send(remote) {
            return Some(INVALID_DEST);
        }
    }
    if matches!(id, 2862 | 2865) && !process.ports.has_send(remote) {
        if !process.ports.acquire_send(remote) {
            return Some(INVALID_DEST);
        }
    }
    if !process.ports.has_send(remote) {
        return Some(INVALID_DEST);
    }
    let local = (a[3] >> 32) as u32;
    if local != (a[5] >> 32) as u32 || !process.ports.is_reply(local) {
        return Some(0x10004002);
    }
    let (read, write) = (process.copy_in?, process.copy_out?);
    let mut request = [0; 512];
    if unsafe { read(process.host_context, a[0], request.as_mut_ptr(), size) } != 0 {
        return Some(INVALID_DATA);
    }
    let request = &request[..size];
    if word(request, 0)? != a[2] as u32
        || word(request, 4)? as usize != size
        || word(request, 8)? != remote
        || word(request, 12)? != local
        || word(request, 16)? != 0
        || word(request, 20)? != id
    {
        return Some(INVALID_DATA);
    }
    if (a[6] as u32) < if id == 2802 { 44 } else { 48 } {
        return Some(TOO_LARGE);
    }
    process
        .iokit
        .with(|slots| {
            reap(slots, process);
            if id == 2865 {
                let selector = word(request, 32).unwrap_or(0xffff);
                process
                    .iokit_open_count
                    .store(((size as u32) << 16) | selector, Ordering::Relaxed);
                if selector != 13 {
                    return None;
                }
                // IOSurface's limits query has no inputs or OOL output. In the
                // packed io_connect_method request, inband_outputCnt follows
                // the 64-bit ool_input_size at offset 52, so it is at 60 (not
                // 56, which is the upper half of ool_input_size).
                let output_count = word(request, 60).unwrap_or(0) as usize;
                if size != 84
                    || word(request, 0)? != 0x1513
                    || request.get(24..32)? != NDR
                    || a[5] as u32 != 0
                    || word(request, 36)? != 0 // scalar_inputCnt
                    || word(request, 40)? != 0 // inband_inputCnt
                    || quad(request, 44)? != 0 // ool_input
                    || quad(request, 52)? != 0 // ool_input_size
                    || !(24..=64).contains(&output_count)
                    || word(request, 64)? != 0 // scalar_outputCnt
                    || quad(request, 68)? != 0 // ool_output
                    || quad(request, 76)? != 0
                {
                    return None;
                }
                let mut bytes = vec![0u8; 52 + output_count];
                let reply_size = bytes.len() as u32;
                bytes[0..4].copy_from_slice(&0x1113u32.to_le_bytes());
                bytes[4..8].copy_from_slice(&reply_size.to_le_bytes());
                bytes[12..16].copy_from_slice(&local.to_le_bytes());
                bytes[20..24].copy_from_slice(&(id + 100).to_le_bytes());
                bytes[24..32].copy_from_slice(&NDR);
                bytes[36..40].copy_from_slice(&(output_count as u32).to_le_bytes());
                for (offset, value) in [
                    (40usize, 0x0fffu32),
                    (44, 0x003f),
                    (48, 0x0fff),
                    (52, 0x0fff),
                    (56, 0x4000),
                    (60, 0x4000),
                ] {
                    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
                if output_count >= 36 {
                    bytes[74..76].copy_from_slice(&1u16.to_le_bytes());
                }
                if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) } != 0 {
                    return Some(0x10004008);
                }
                process.iokit_open_count.store(0x200, Ordering::Relaxed);
                return Some(0);
            }
            if id == 2862 {
                process.iokit_open_count.fetch_add(1, Ordering::Relaxed);
                if size != 80 || word(request, 0)? & 0x7fff_ffff != 0x1513 {
                    return None;
                }
                let Some(client) = process.ports.construct_send() else {
                    return Some(0x10000004);
                };
                let mut bytes = [0u8; 52];
                bytes[0..4].copy_from_slice(&0x8000_1200u32.to_le_bytes());
                bytes[4..8].copy_from_slice(&52u32.to_le_bytes());
                bytes[12..16].copy_from_slice(&local.to_le_bytes());
                bytes[20..24].copy_from_slice(&(id + 100).to_le_bytes());
                bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
                bytes[28..32].copy_from_slice(&client.to_le_bytes());
                bytes[36..40].copy_from_slice(&(17u32 << 16).to_le_bytes());
                bytes[40..48].copy_from_slice(&NDR);
                bytes[48..52].copy_from_slice(&0u32.to_le_bytes());
                if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) } != 0 {
                    process.ports.deallocate(client);
                    return Some(0x10004008);
                }
                process.iokit_open_count.store(0x100, Ordering::Relaxed);
                return Some(0);
            }
            if id == 2880 {
                // io_service_get_matching_services carries an inband binary
                // dictionary: NDR, matchingCnt, then exactly matchingCnt bytes.
                // Keep this layout check independent of the 2881 routine.
                if word(request, 0)? != 0x1513 || request.get(24..32)? != NDR || a[5] as u32 != 0 {
                    return None;
                }
                let count = word(request, 32)? as usize;
                if count == 0 || count > 256 || size != 36 + count {
                    return None;
                }
                let dictionary = request.get(36..36 + count)?;
                matching(dictionary)?;
                if dictionary
                    .windows(b"IOPlatformExpertDevice".len())
                    .any(|window| window == b"IOPlatformExpertDevice")
                {
                    // The singular platform-expert query resolves to the real
                    // /product registry service, not to a GPU or a null object.
                    let Some(service) = io_registry_service(process) else {
                        return Some(INVALID_DEST);
                    };
                    let bytes = reply(id, local, service);
                    if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) }
                        != 0
                    {
                        return Some(0x10004008);
                    }
                    return Some(0);
                }
                if !dictionary
                    .windows(b"AGXAccelerator".len())
                    .any(|window| window == b"AGXAccelerator")
                {
                    return None;
                }
                // This is the singular io_service_get_matching_service_bin.
                // XNU returns kIOReturnNotFound when copyMatchingService is
                // null; never return an iterator or another service here.
                let bytes = status_reply(id, local, 0xe000_02f0);
                if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) } != 0 {
                    return Some(0x10004008);
                }
                return Some(0);
            }
            if id == 2881 {
                if word(request, 0)? != 0x1513 || request.get(24..32)? != NDR || a[5] as u32 != 0 {
                    return None;
                }
                let count = word(request, 32)? as usize;
                if count == 0 || count > 256 || size != 36 + count {
                    return None;
                }
                let rule = matching(request.get(36..36 + count)?)?;
                let core_surface = request[36..36 + count]
                    .windows(b"IOCoreSurfaceRoot".len())
                    .any(|window| window == b"IOCoreSurfaceRoot");
                let Some(iterator) = process.ports.construct_send() else {
                    return Some(0x10000004);
                };
                if core_surface {
                    let Some(slot) = slots.iter_mut().find(|slot| slot.iterator == 0) else {
                        process.ports.deallocate(iterator);
                        return Some(0x10000004);
                    };
                    let Some(service) = process.ports.construct_send() else {
                        process.ports.deallocate(iterator);
                        return Some(0x10000004);
                    };
                    let mut references = [0; 8];
                    references[0] = u64::from(service);
                    *slot = Subscription {
                        iterator,
                        wake: 0,
                        kind: 3,
                        matching: rule,
                        references,
                        reference_count: 1,
                        armed: false,
                    };
                }
                let bytes = reply(id, local, iterator);
                if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) } != 0 {
                    process.ports.deallocate(iterator);
                    return Some(0x10004008);
                }
                return Some(0);
            }
            if id == 2816 {
                // io_service_close is a MIG routine, not an IOConnectMethod
                // selector. Its complete request is only mach_msg_header_t;
                // the reply carries NDR and the IOReturn status. The user
                // library destroys the connect handle after this RPC, so do
                // not consume the caller's send right here.
                if size != 24 || word(request, 0)? != 0x1513 || a[5] as u32 != 0 {
                    return None;
                }
                let bytes = status_reply(id, local, 0);
                if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) } != 0 {
                    return Some(0x10004008);
                }
                return Some(0);
            }
            if id == 2802 {
                if size != 24 || word(request, 0)? != 0x1513 || a[5] as u32 != 0 {
                    return None;
                }
                let slot = slots.iter_mut().find(|slot| slot.iterator == remote);
                let bytes = if let Some(slot) = slot {
                    slot.armed = true;
                    if slot.kind == 3 {
                        let service = slot.references[0] as u32;
                        slot.kind = 4;
                        reply(id, local, service).to_vec()
                    } else {
                        empty_reply(id, local).to_vec()
                    }
                } else {
                    empty_reply(id, local).to_vec()
                };
                if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) } != 0 {
                    return Some(0x10004008);
                }
                return Some(0);
            }
            if a[5] as u32 != 1
                || word(request, 0)? != 0x80001513
                || word(request, 24)? != 1
                || word(request, 32)? != 0
                || word(request, 36)? != 20 << 16
                || request.get(40..48)? != NDR
                || word(request, 48)? != 0
            {
                return None;
            }
            let type_len = word(request, 52)? as usize;
            if !(1..=128).contains(&type_len) {
                return None;
            }
            let kind = match request.get(56..56 + type_len)? {
                b"IOServiceFirstMatch\0" => 1,
                b"IOServiceTerminate\0" => 2,
                _ => return None,
            };
            let count_offset = 56 + align(type_len)?;
            let count = word(request, count_offset)? as usize;
            if count > 256 {
                return None;
            }
            let rule = matching(request.get(count_offset + 4..count_offset + 4 + count)?)?;
            let references_offset = count_offset + 4 + align(count)?;
            let reference_count = word(request, references_offset)? as usize;
            if reference_count > 8 || size != references_offset + 4 + reference_count * 8 {
                return None;
            }
            let wake = word(request, 28)?;
            if !process.ports.has_receive(wake) {
                return Some(0x1000000a);
            }
            let Some(slot) = slots.iter_mut().find(|slot| slot.iterator == 0) else {
                return Some(0x10000004);
            };
            let mut references = [0; 8];
            for (index, value) in references.iter_mut().enumerate().take(reference_count) {
                *value = quad(request, references_offset + 4 + index * 8)?;
            }
            let Some(iterator) = process.ports.construct_send() else {
                return Some(0x10000004);
            };
            if !process.ports.acquire_send(wake) {
                process.ports.deallocate(iterator);
                return Some(0x1000000a);
            }
            let bytes = reply(id, local, iterator);
            if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) } != 0 {
                process.ports.deallocate(iterator);
                process.ports.deallocate(wake);
                return Some(0x10004008);
            }
            *slot = Subscription {
                iterator,
                wake,
                kind,
                matching: rule,
                references,
                reference_count,
                armed: false,
            };
            Some(0)
        })
        .unwrap_or(Some(0x10000004))
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
        let memory = &*(context as *const [u8; 1024]);
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
        input: *const u8,
        size: usize,
    ) -> u32 {
        let memory = &mut *(context as *mut [u8; 1024]);
        let Some(end) = (address as usize).checked_add(size) else {
            return 14;
        };
        let Some(bytes) = memory.get_mut(address as usize..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(input, bytes.as_mut_ptr(), size);
        0
    }
    unsafe extern "C" fn fail_write(_: *const c_void, _: u64, _: *const u8, _: usize) -> u32 {
        14
    }

    fn put(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn push_word(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend(value.to_le_bytes());
    }
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&s[at..at + 2], 16).unwrap())
            .collect()
    }
    fn text(bytes: &mut Vec<u8>, tag: u32, value: &[u8]) {
        push_word(bytes, tag | value.len() as u32);
        bytes.extend(value);
        bytes.resize(align(bytes.len()).unwrap(), 0);
    }
    fn dictionary() -> Vec<u8> {
        let mut bytes = Vec::new();
        push_word(&mut bytes, 0xd3);
        push_word(&mut bytes, 0x81000003);
        text(&mut bytes, 0x08000000, b"IOProviderClass\0");
        text(&mut bytes, 0x09000000, b"IOHIDDevice\0");
        text(&mut bytes, 0x08000000, b"DeviceUsagePage\0");
        push_word(&mut bytes, 0x04000020);
        bytes.extend(1u64.to_le_bytes());
        text(&mut bytes, 0x08000000, b"DeviceUsage\0");
        push_word(&mut bytes, 0x84000020);
        bytes.extend(5u64.to_le_bytes());
        bytes
    }
    fn accelerator_dictionary() -> Vec<u8> {
        let mut bytes = Vec::new();
        push_word(&mut bytes, 0xd3);
        push_word(&mut bytes, 0x81000001);
        text(&mut bytes, 0x08000000, b"IOProviderClass\0");
        text(&mut bytes, 0x89000000, b"IOAcceleratorES");
        bytes
    }

    fn setup(memory: &mut [u8; 1024]) -> (Process, u32, u32, u32) {
        let mut process = Process::new(1, 0, 2);
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        let main = process.ports.construct(0x10).unwrap();
        let local = process.ports.construct(0x1000).unwrap();
        let wake = process.ports.construct(0).unwrap();
        process.io_main_port.store(main, Ordering::Release);
        (process, main, local, wake)
    }
    fn request(memory: &mut [u8; 1024], main: u32, local: u32, wake: u32) -> TrapFrame {
        memory.fill(0);
        for (at, value) in [
            (0, 0x80001513),
            (4, 212),
            (8, main),
            (12, local),
            (20, 2884),
            (24, 1),
            (28, wake),
            (36, 20 << 16),
            (52, 20),
            (76, 104),
            (184, 3),
        ] {
            put(memory, at, value);
        }
        memory[40..48].copy_from_slice(&NDR);
        memory[56..76].copy_from_slice(b"IOServiceFirstMatch\0");
        memory[80..184].copy_from_slice(&dictionary());
        // The callback is an opaque guest pointer: preserve every PAC bit.
        memory[196..204].copy_from_slice(&0x8c09005f0d8d9d4cu64.to_le_bytes());
        memory[204..212].copy_from_slice(&0x607ecfc000u64.to_le_bytes());
        TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (212 << 32) | 0x80001513,
                ((local as u64) << 32) | main as u64,
                2884 << 32,
                ((local as u64) << 32) | 1,
                48,
                0,
            ],
            ..Default::default()
        }
    }
    fn used(process: &Process) -> usize {
        process
            .iokit
            .with(|slots| slots.iter().filter(|s| s.iterator != 0).count())
            .unwrap()
    }

    #[test]
    fn agx_accelerator_captured_matching_returns_not_found() {
        let mut memory = [0; 1024];
        let (process, main, local, _) = setup(&mut memory);
        process.io_main_port.store(0, Ordering::Release);
        assert_eq!(process.ports.deallocate(main), 0);
        assert!(process.ports.has_receive(main));
        assert!(!process.ports.has_send(main));
        memory.fill(0);
        // physical-ca-close-limits/incomplete-system.log:1662. The complete
        // 84-byte inband request contains a 48-byte IOCFSerialize dictionary.
        let mut captured = hex(concat!(
            "1315000054000000032200000308000000000000400b0000",
            "000000000100000030000000d30000000100008110000008",
            "494f50726f7669646572436c617373000e00008941475841",
            "6363656c657261746f720000"
        ));
        assert_eq!(captured.len(), 84);
        assert_eq!(word(&captured, 32), Some(48));
        assert_eq!(&captured[68..82], b"AGXAccelerator");
        assert_eq!(matching(&captured[36..]), Some(Matching::default()));
        captured[8..12].copy_from_slice(&main.to_le_bytes());
        captured[12..16].copy_from_slice(&local.to_le_bytes());
        memory[..84].copy_from_slice(&captured);
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (84 << 32) | 0x1513,
                ((local as u64) << 32) | main as u64,
                2880 << 32,
                (local as u64) << 32,
                48,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 0), Some(0x1200));
        assert_eq!(word(&memory, 4), Some(36));
        assert_eq!(word(&memory, 12), Some(local));
        assert_eq!(word(&memory, 20), Some(2980));
        assert_eq!(&memory[24..32], &NDR);
        assert_eq!(word(&memory, 32), Some(0xe000_02f0));
        assert_eq!(word(&memory, 40), Some(8));
        assert!(process.ports.has_send(main));
        assert_eq!(used(&process), 0);
    }

    #[test]
    fn platform_expert_captured_matching_returns_the_product_service() {
        let mut memory = [0; 1024];
        let (process, main, local, _) = setup(&mut memory);
        process.io_main_port.store(0, Ordering::Release);
        assert_eq!(process.ports.deallocate(main), 0);
        assert!(process.ports.has_receive(main));
        assert!(!process.ports.has_send(main));
        memory.fill(0);
        let mut captured = hex("131500005c000000032200000308000000000000400b0000000000000100000038000000d30000000100008110000008494f50726f7669646572436c6173730016000089494f506c6174666f726d4578706572744465766963650000");
        assert_eq!(captured.len(), 92);
        assert_eq!(word(&captured, 32), Some(56));
        assert_eq!(matching(&captured[36..]), Some(Matching::default()));
        captured[8..12].copy_from_slice(&main.to_le_bytes());
        captured[12..16].copy_from_slice(&local.to_le_bytes());
        memory[..92].copy_from_slice(&captured);
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (92 << 32) | 0x1513,
                ((local as u64) << 32) | main as u64,
                2880 << 32,
                (local as u64) << 32,
                48,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 0), Some(0x8000_1200));
        assert_eq!(word(&memory, 4), Some(40));
        assert_eq!(word(&memory, 12), Some(local));
        assert_eq!(word(&memory, 20), Some(2980));
        let service = word(&memory, 28).unwrap();
        assert_ne!(service, 0);
        assert_ne!(service, main);
        assert!(process.ports.has_receive(service));
        assert!(process.ports.has_send(service));
        assert_eq!(process.io_registry_port.load(Ordering::Acquire), service);
        assert!(process.ports.has_send(main));
        assert_eq!(used(&process), 0);
    }

    #[test]
    fn accelerator_matching_returns_an_empty_iterator() {
        let mut memory = [0; 1024];
        let (process, main, local, wake) = setup(&mut memory);
        process.io_main_port.store(0, Ordering::Release);
        assert_eq!(process.ports.deallocate(main), 0);
        assert!(process.ports.has_receive(main));
        assert!(!process.ports.has_send(main));
        let dictionary = accelerator_dictionary();
        let size = 36 + dictionary.len();
        let mut frame = request(&mut memory, main, local, wake);
        memory[20..24].copy_from_slice(&2881u32.to_le_bytes());
        memory[24..32].copy_from_slice(&NDR);
        memory[32..36].copy_from_slice(&(dictionary.len() as u32).to_le_bytes());
        memory[36..36 + dictionary.len()].copy_from_slice(&dictionary);
        put(&mut memory, 0, 0x1513);
        put(&mut memory, 4, size as u32);
        frame.arguments[2] = ((size as u64) << 32) | 0x1513;
        frame.arguments[4] = 2881u64 << 32;
        frame.arguments[5] = (local as u64) << 32;
        frame.arguments[6] = 48;
        assert_eq!(message2(&process, &frame), Some(0));
        let iterator = word(&memory, 28).unwrap();
        assert_eq!(process.ports.port_type(iterator), Ok(1 << 16));
        assert_eq!(word(&memory, 20), Some(2981));
        memory.fill(0);
        for (at, value) in [(0, 0x1513), (4, 24), (8, iterator), (12, local), (20, 2802)] {
            put(&mut memory, at, value);
        }
        let next = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (24 << 32) | 0x1513,
                ((local as u64) << 32) | iterator as u64,
                2802 << 32,
                (local as u64) << 32,
                48,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &next), Some(0));
        assert_eq!(word(&memory, 32), Some(0xe00002c0));
        process.ports.deallocate(iterator);
    }

    #[test]
    fn core_surface_provider_is_accepted() {
        let mut bytes = Vec::new();
        push_word(&mut bytes, 0xd3);
        push_word(&mut bytes, 0x81000001);
        text(&mut bytes, 0x08000000, b"IONameMatch\0");
        text(&mut bytes, 0x89000000, b"IOCoreSurfaceRoot");
        assert!(matching(&bytes).is_some());
    }

    #[test]
    fn core_surface_matching_returns_a_service_then_exhausts() {
        let mut memory = [0; 1024];
        let (process, main, local, wake) = setup(&mut memory);
        process.io_main_port.store(0, Ordering::Release);
        assert_eq!(process.ports.deallocate(main), 0);
        let mut dictionary = Vec::new();
        push_word(&mut dictionary, 0xd3);
        push_word(&mut dictionary, 0x81000001);
        text(&mut dictionary, 0x08000000, b"IONameMatch\0");
        text(&mut dictionary, 0x89000000, b"IOCoreSurfaceRoot");
        let size = 36 + dictionary.len();
        let mut frame = request(&mut memory, main, local, wake);
        memory[20..24].copy_from_slice(&2881u32.to_le_bytes());
        memory[24..32].copy_from_slice(&NDR);
        memory[32..36].copy_from_slice(&(dictionary.len() as u32).to_le_bytes());
        memory[36..36 + dictionary.len()].copy_from_slice(&dictionary);
        put(&mut memory, 0, 0x1513);
        put(&mut memory, 4, size as u32);
        frame.arguments[2] = ((size as u64) << 32) | 0x1513;
        frame.arguments[4] = 2881u64 << 32;
        frame.arguments[5] = (local as u64) << 32;
        frame.arguments[6] = 48;
        assert_eq!(message2(&process, &frame), Some(0));
        let iterator = word(&memory, 28).unwrap();
        memory.fill(0);
        for (at, value) in [(0, 0x1513), (4, 24), (8, iterator), (12, local), (20, 2802)] {
            put(&mut memory, at, value);
        }
        let next = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (24 << 32) | 0x1513,
                ((local as u64) << 32) | iterator as u64,
                2802 << 32,
                (local as u64) << 32,
                48,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &next), Some(0));
        let service = word(&memory, 28).unwrap();
        assert!(process.ports.has_send(service));
        memory.fill(0);
        for (at, value) in [(0, 0x1513), (4, 24), (8, iterator), (12, local), (20, 2802)] {
            put(&mut memory, at, value);
        }
        assert_eq!(message2(&process, &next), Some(0));
        assert_eq!(word(&memory, 32), Some(0xe00002c0));
    }

    #[test]
    fn io_surface_limits_uses_the_captured_request_layout() {
        let mut memory = [0; 1024];
        let (process, main, local, _) = setup(&mut memory);
        assert_eq!(process.ports.deallocate(main), 0);
        memory.fill(0);
        // physical-ca-method-inspect/live-hilog.log: the complete 84-byte
        // IOConnectMethod(selector 13) request sent by IOSurface on iOS 27.
        let mut captured = hex(concat!(
            "1315000054000000033300000308000000000000310b0000",
            "00000000010000000d000000000000000000000000000000",
            "000000000000000000000000280000000000000000000000",
            "000000000000000000000000"
        ));
        assert_eq!(captured.len(), 84);
        captured[8..12].copy_from_slice(&main.to_le_bytes());
        captured[12..16].copy_from_slice(&local.to_le_bytes());
        memory[..84].copy_from_slice(&captured);
        assert_eq!(word(&captured, 32), Some(13));
        assert_eq!(quad(&captured, 52), Some(0));
        assert_eq!(word(&captured, 60), Some(40));
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (84 << 32) | 0x1513,
                ((local as u64) << 32) | main as u64,
                2865 << 32,
                (local as u64) << 32,
                128,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 0), Some(0x1113));
        assert_eq!(word(&memory, 4), Some(92));
        assert_eq!(word(&memory, 20), Some(2965));
        assert_eq!(&memory[24..32], &NDR);
        assert_eq!(word(&memory, 32), Some(0));
        assert_eq!(word(&memory, 36), Some(40));
        assert_eq!(word(&memory, 74).unwrap() & 0xffff, 1);
        assert_eq!(word(&memory, 80), Some(0));
        assert_eq!(quad(&memory, 84), Some(0));
    }

    #[test]
    fn io_service_close_handles_the_captured_header_only_request() {
        let mut memory = [0; 1024];
        let (process, main, local, _) = setup(&mut memory);
        memory.fill(0);
        // physical-ca-real-limits/live-hilog.log:3679. There is no payload or
        // NDR record in this request: io_service_close takes only connection.
        let mut captured = hex("1315000018000000033300000308000000000000000b0000");
        assert_eq!(captured.len(), 24);
        captured[8..12].copy_from_slice(&main.to_le_bytes());
        captured[12..16].copy_from_slice(&local.to_le_bytes());
        memory[..24].copy_from_slice(&captured);
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (24 << 32) | 0x1513,
                ((local as u64) << 32) | main as u64,
                2816 << 32,
                (local as u64) << 32,
                48,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert_eq!(word(&memory, 0), Some(0x1200));
        assert_eq!(word(&memory, 4), Some(36));
        assert_eq!(word(&memory, 12), Some(local));
        assert_eq!(word(&memory, 20), Some(2916));
        assert_eq!(&memory[24..32], &NDR);
        assert_eq!(word(&memory, 32), Some(0));
        assert_eq!(word(&memory, 40), Some(8));
        // IOServiceClose, rather than the MIG server routine, destroys the
        // user's connect handle after a successful close reply.
        assert!(process.ports.has_send(main));
    }

    #[test]
    fn io_service_open_returns_a_client_right() {
        let mut memory = [0; 1024];
        let (process, main, local, _) = setup(&mut memory);
        assert_eq!(process.ports.deallocate(main), 0);
        memory.fill(0);
        for (at, value) in [
            (0, 0x8000_1513),
            (4, 80),
            (8, main),
            (12, local),
            (20, 2862),
        ] {
            put(&mut memory, at, value);
        }
        put(&mut memory, 24, 2);
        put(&mut memory, 28, main);
        put(&mut memory, 36, 0x13);
        memory[40..48].copy_from_slice(&NDR);
        let frame = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (80 << 32) | 0x8000_1513,
                ((local as u64) << 32) | main as u64,
                2862 << 32,
                ((local as u64) << 32) | 2,
                48,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &frame), Some(0));
        assert!(process.ports.has_send(word(&memory, 28).unwrap()));
        assert_eq!(word(&memory, 20), Some(2962));
        assert_eq!(word(&memory, 4), Some(52));
        assert_eq!(word(&memory, 48), Some(0));
        assert_eq!(word(&memory, 24), Some(1));
        assert_eq!(word(&memory, 36), Some(17 << 16));
    }

    #[test]
    fn notification_returns_an_owned_empty_iterator_and_preserves_callback_bits() {
        let mut memory = [0; 1024];
        let (process, main, local, wake) = setup(&mut memory);
        let frame = request(&mut memory, main, local, wake);
        assert_eq!(message2(&process, &frame), Some(0));
        let iterator = word(&memory, 28).unwrap();
        assert_eq!(process.ports.port_type(iterator), Ok(1 << 16));
        assert_eq!(process.ports.port_type(wake), Ok((1 << 16) | (1 << 17)));
        assert_eq!(word(&memory, 4), Some(40));
        assert_eq!(word(&memory, 20), Some(2984));
        assert_eq!(word(&memory, 44), Some(8));
        process
            .iokit
            .with(|slots| {
                let slot = slots.iter().find(|s| s.iterator == iterator).unwrap();
                assert_eq!(slot.kind, 1);
                assert_eq!(
                    slot.matching,
                    Matching {
                        page: Some(1),
                        usage: Some(5)
                    }
                );
                assert_eq!(slot.reference_count, 3);
                assert_eq!(
                    &slot.references[..3],
                    &[0, 0x8c09005f0d8d9d4c, 0x607ecfc000]
                );
                assert!(!slot.armed);
            })
            .unwrap();

        memory.fill(0);
        for (at, value) in [(0, 0x1513), (4, 24), (8, iterator), (12, local), (20, 2802)] {
            put(&mut memory, at, value);
        }
        let next = TrapFrame {
            number: -47,
            arguments: [
                0,
                0x2_0000_0003,
                (24 << 32) | 0x1513,
                ((local as u64) << 32) | iterator as u64,
                2802 << 32,
                (local as u64) << 32,
                48,
                0,
            ],
            ..Default::default()
        };
        assert_eq!(message2(&process, &next), Some(0));
        assert_eq!(word(&memory, 0), Some(0x1200));
        assert_eq!(word(&memory, 4), Some(36));
        assert_eq!(word(&memory, 32), Some(0xe00002c0));
        assert_eq!(word(&memory, 20), Some(2902));
        assert!(process
            .iokit
            .with(|slots| slots.iter().any(|s| s.iterator == iterator && s.armed))
            .unwrap());

        // IOObjectRetain/Release keep the subscription until the final send
        // reference is released through the actual Mach trap dispatcher.
        assert_eq!(process.ports.modify_send_refs(iterator, 1), 0);
        for (number, delta, expected) in [(-18, 0, 1), (-19, u32::MAX as u64, 0)] {
            let mut release = TrapFrame {
                number,
                arguments: [0x103, iterator as u64, 0, delta, 0, 0, 0, 0],
                ..Default::default()
            };
            assert!(process.dispatch(&mut release));
            assert_eq!(release.result[0], 0);
            assert_eq!(used(&process), expected);
        }
        assert_eq!(process.ports.port_type(iterator), Err(15));
        assert_eq!(process.ports.port_type(wake), Ok(1 << 17));
        let recycled = process.ports.construct_send().unwrap();
        assert_eq!(recycled >> 8, iterator >> 8);
        assert_ne!(recycled, iterator);
    }

    #[test]
    fn malformed_requests_and_failed_copyout_do_not_publish_or_leak_rights() {
        let mut memory = [0; 1024];
        let (mut process, main, local, wake) = setup(&mut memory);
        for (at, value) in [
            (36, 19 << 16),
            (24, 2),
            (52, 129),
            (76, 257),
            (80, 0),
            (184, 9),
            (184, 2),
        ] {
            let frame = request(&mut memory, main, local, wake);
            put(&mut memory, at, value);
            assert_eq!(message2(&process, &frame), None, "offset {at}");
            assert_eq!(used(&process), 0);
            assert!(!process.ports.has_send(wake));
        }
        let mut frame = request(&mut memory, main, local, wake);
        frame.arguments[6] = 47;
        assert_eq!(message2(&process, &frame), Some(TOO_LARGE));
        assert_eq!(used(&process), 0);
        assert!(!process.ports.has_send(wake));
        let frame = request(&mut memory, main, local, 0xfeed);
        assert_eq!(message2(&process, &frame), Some(0x1000000a));
        let frame = request(&mut memory, main, local, wake);
        process.copy_out = Some(fail_write);
        assert_eq!(message2(&process, &frame), Some(0x10004008));
        assert_eq!(used(&process), 0);
        assert!(!process.ports.has_send(wake));
        process.copy_out = Some(write);
        assert_eq!(message2(&process, &frame), Some(0));
        let iterator = word(&memory, 28).unwrap();
        assert_eq!(process.ports.deallocate(iterator), 0);
        process.iokit.reap(&process);
        assert_eq!(used(&process), 0);
        assert!(!process.ports.has_send(wake));
    }

    #[test]
    fn subscription_capacity_is_bounded_and_released_slots_can_be_reused() {
        let mut memory = [0; 1024];
        let (process, main, local, wake) = setup(&mut memory);
        let mut iterators = Vec::new();
        for _ in 0..32 {
            let frame = request(&mut memory, main, local, wake);
            assert_eq!(message2(&process, &frame), Some(0));
            iterators.push(word(&memory, 28).unwrap());
        }
        let frame = request(&mut memory, main, local, wake);
        assert_eq!(message2(&process, &frame), Some(0x10000004));
        assert_eq!(used(&process), 32);
        assert_eq!(process.ports.deallocate(iterators[0]), 0);
        // message2 also reaps before registering, allowing recovery even if
        // another release path did not run the eager cleanup hook.
        assert_eq!(message2(&process, &frame), Some(0));
        let replacement = word(&memory, 28).unwrap();
        assert_ne!(replacement, iterators[0]);
        iterators[0] = replacement;
        for iterator in iterators {
            assert_eq!(process.ports.deallocate(iterator), 0);
        }
        process.iokit.reap(&process);
        assert_eq!(used(&process), 0);
        assert!(!process.ports.has_send(wake));
    }

    #[test]
    fn binary_matching_rejects_unknown_classes_duplicates_and_truncation() {
        let bytes = dictionary();
        assert_eq!(
            matching(&bytes),
            Some(Matching {
                page: Some(1),
                usage: Some(5)
            })
        );
        for size in 0..bytes.len() {
            assert_eq!(matching(&bytes[..size]), None, "size {size}");
        }
        let mut changed = bytes.clone();
        changed[32] = b'X'; // unknown IOProviderClass value
        assert_eq!(matching(&changed), None);
        let mut changed = bytes.clone();
        changed[92..96].copy_from_slice(&0x04000020u32.to_le_bytes()); // missing final END marker
        assert_eq!(matching(&changed), None);
        let mut duplicate = Vec::new();
        push_word(&mut duplicate, 0xd3);
        push_word(&mut duplicate, 0x81000002);
        text(&mut duplicate, 0x08000000, b"IOProviderClass\0");
        text(&mut duplicate, 0x09000000, b"IOHIDDevice\0");
        text(&mut duplicate, 0x08000000, b"IOProviderClass\0");
        text(&mut duplicate, 0x89000000, b"IOHIDDevice\0");
        assert_eq!(matching(&duplicate), None);
        let mut changed = bytes;
        changed.extend([0; 4]);
        assert_eq!(matching(&changed), None);
    }
}
