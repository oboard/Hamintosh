//! Matching notifications for the local IOKit registry's HID inventory.
//! No IOHIDDevice backend is registered yet: matching iterators are empty.
//! Preserve the subscription and callback references without fabricating an
//! input device or dispatching synthetic hardware callbacks.
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
            b"IOProviderClass\0" => {
                if value & 0x7f000000 != 0x09000000 {
                    return None;
                }
                let size = (value & 0xffffff) as usize;
                if bytes.get(at + 4..at + 4 + size)? != b"IOHIDDevice\0" {
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

pub(super) struct State {
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

fn empty_reply(id: u32, local: u32) -> [u8; 44] {
    // XNU's is_io_iterator_next returns kIOReturnNoDevice on exhaustion;
    // MIG encodes that as a simple error reply, without an object descriptor.
    let mut bytes = [0; 44];
    for (index, value) in [0x1200u32, 36, 0, local, 0, id + 100]
        .into_iter()
        .enumerate()
    {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[24..32].copy_from_slice(&NDR);
    bytes[32..36].copy_from_slice(&0xe00002c0u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&8u32.to_le_bytes());
    bytes
}

pub(super) fn message2(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    let id = (a[4] >> 32) as u32;
    if !matches!(id, 2884 | 2802) {
        return None;
    }
    let remote = a[3] as u32;
    if id == 2884 && (remote == 0 || remote != process.io_main_port.load(Ordering::Acquire)) {
        return None;
    }
    let size = (a[2] >> 32) as usize;
    if a[1] != 0x2_0000_0003
        || a[4] as u32 != 0
        || a[5] as u32 > 1
        || a[6] >> 32 != 0
        || a[7] != 0
        || !(24..=512).contains(&size)
    {
        return None;
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
            if id == 2802 {
                if size != 24 || word(request, 0)? != 0x1513 || a[5] as u32 != 0 {
                    return None;
                }
                let slot = slots.iter_mut().find(|slot| slot.iterator == remote)?;
                let bytes = empty_reply(id, local); // no matching HID services registered
                if unsafe { write(process.host_context, a[0], bytes.as_ptr(), bytes.len()) } != 0 {
                    return Some(0x10004008);
                }
                slot.armed = true;
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
