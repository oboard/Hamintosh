//! Bounded local XPC transport for the observed preferences read protocol.
//! No allocation or blocking host locks on the synchronous trap path. The
//! backend currently reports preferences service unavailability explicitly;
//! it never acknowledges a successful read or manufactures preference values.
use super::{Process, TrapFrame};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, Ordering};

const INVALID_DATA: u32 = 0x10000002;
const SEND_TIMED_OUT: u32 = 0x10000004;
const RCV_TOO_LARGE: u32 = 0x10004004;
const RCV_INVALID_DATA: u32 = 0x10004008;
const REPLY_CAPACITY: usize = 8;

#[derive(Clone, Copy)]
struct PendingReply {
    bytes: [u8; 512],
    length: usize,
    port: u32,
}

impl Default for PendingReply {
    fn default() -> Self {
        Self {
            bytes: [0; 512],
            length: 0,
            port: 0,
        }
    }
}

struct Buffers {
    request: [u8; 4096],
    replies: [PendingReply; REPLY_CAPACITY],
    reply_count: usize,
    connections: [u32; 8],
}

pub(crate) struct State {
    busy: AtomicBool,
    buffers: UnsafeCell<Buffers>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            busy: AtomicBool::new(false),
            buffers: UnsafeCell::new(Buffers {
                request: [0; 4096],
                replies: [PendingReply::default(); REPLY_CAPACITY],
                reply_count: 0,
                connections: [0; 8],
            }),
        }
    }
}

// Every access to the buffers is guarded by a nonblocking atomic claim. A
// nested/concurrent trap fails rather than aliasing mutable buffers or spinning.
unsafe impl Sync for State {}
struct Claim<'a>(&'a AtomicBool);
impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl State {
    fn with<T>(&self, operation: impl FnOnce(&mut Buffers) -> T) -> Option<T> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let _claim = Claim(&self.busy);
        Some(operation(unsafe { &mut *self.buffers.get() }))
    }
}

impl Buffers {
    fn push_reply(&mut self, port: u32, build: impl FnOnce(&mut [u8; 512]) -> usize) -> bool {
        if self.reply_count == self.replies.len() {
            return false;
        }
        let reply = &mut self.replies[self.reply_count];
        reply.bytes.fill(0);
        reply.port = port;
        reply.length = build(&mut reply.bytes);
        self.reply_count += 1;
        true
    }

    fn remove_reply(&mut self, index: usize) {
        for position in index..self.reply_count - 1 {
            self.replies[position] = self.replies[position + 1];
        }
        self.reply_count -= 1;
        self.replies[self.reply_count] = PendingReply::default();
    }
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn padded(size: usize) -> Option<usize> {
    Some(size.checked_add(3)? & !3)
}

#[derive(Clone, Copy)]
struct Value<'a> {
    kind: u32,
    body: &'a [u8],
    count: u32,
}
// Validate the entire tree before interpreting a request. Both nesting and
// total node count are bounded independently of the untrusted container sizes.
fn value<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    depth: u32,
    budget: &mut u32,
) -> Option<Value<'a>> {
    if depth > 8 || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let kind = word(bytes, *cursor)?;
    *cursor += 4;
    let mut count = 0;
    let start = *cursor;
    let body = match kind {
        0x1000 => &bytes[start..start],
        0x2000 => {
            if word(bytes, start)? > 1 {
                return None;
            }
            *cursor += 4;
            bytes.get(start..*cursor)?
        }
        0x3000 | 0x4000 => {
            *cursor += 8;
            bytes.get(start..*cursor)?
        }
        0xd000 => {
            *cursor += 4;
            bytes.get(start..*cursor)?
        }
        0xa000 => {
            // XPC UUID values have a fixed 16-byte body and no length prefix.
            *cursor += 16;
            bytes.get(start..*cursor)?
        }
        0x9000 => {
            let size = word(bytes, start)? as usize;
            let content = start.checked_add(4)?;
            let end = content.checked_add(size)?;
            let text = bytes.get(content..end)?;
            if text.last() != Some(&0) || text[..text.len() - 1].contains(&0) {
                return None;
            }
            *cursor = content.checked_add(padded(size)?)?;
            bytes.get(end..*cursor)?;
            text
        }
        0xe000 | 0xf000 => {
            let size = word(bytes, start)? as usize;
            let end = start.checked_add(4)?.checked_add(size)?;
            count = word(bytes, start + 4)?;
            let content = start + 8;
            let body = bytes.get(content..end)?;
            let mut inner = 0;
            for _ in 0..count {
                if kind == 0xf000 {
                    key(body, &mut inner)?;
                }
                value(body, &mut inner, depth + 1, budget)?;
            }
            if inner != body.len() {
                return None;
            }
            *cursor = end;
            body
        }
        _ => return None,
    };
    Some(Value { kind, body, count })
}
fn key<'a>(bytes: &'a [u8], cursor: &mut usize) -> Option<&'a [u8]> {
    let remaining = bytes.get(*cursor..)?;
    let length = remaining.iter().position(|byte| *byte == 0)?;
    let result = &remaining[..length];
    *cursor = cursor.checked_add(padded(length + 1)?)?;
    bytes.get(..*cursor)?;
    Some(result)
}
fn dictionary_get<'a>(dictionary: Value<'a>, name: &[u8]) -> Option<Value<'a>> {
    if dictionary.kind != 0xf000 {
        return None;
    }
    let mut cursor = 0;
    let mut found = None;
    let mut budget = 256;
    for _ in 0..dictionary.count {
        let field = key(dictionary.body, &mut cursor)?;
        let entry = value(dictionary.body, &mut cursor, 0, &mut budget)?;
        if field == name {
            if found.is_some() {
                return None;
            }
            found = Some(entry);
        }
    }
    found
}
fn integer(value: Value<'_>) -> Option<u64> {
    if !matches!(value.kind, 0x3000 | 0x4000) {
        return None;
    }
    Some(u64::from_le_bytes(value.body.try_into().ok()?))
}
fn preferences_read(bytes: &[u8]) -> Option<u32> {
    if word(bytes, 0)? != 0x4058_5043 || word(bytes, 4)? != 5 {
        return None;
    }
    let mut cursor = 8;
    let root = value(bytes, &mut cursor, 0, &mut 256)?;
    if cursor != bytes.len() || root.kind != 0xf000 {
        return None;
    }
    let operation = integer(dictionary_get(root, b"CFPreferencesOperation")?)?;
    if operation == 1 {
        return (dictionary_get(root, b"CFPreferencesDomain")?.kind == 0x9000).then_some(1);
    }
    if operation != 5 || root.count != 2 {
        return None;
    }
    let batch = dictionary_get(root, b"CFPreferencesMessages")?;
    if batch.kind != 0xe000 || batch.count == 0 || batch.count > 32 {
        return None;
    }
    let mut inner = 0;
    let mut budget = 256;
    let mut reads = 0;
    for _ in 0..batch.count {
        let request = value(batch.body, &mut inner, 0, &mut budget)?;
        if request.kind == 0x1000 {
            continue;
        }
        if integer(dictionary_get(request, b"CFPreferencesOperation")?)? != 1 {
            return None;
        }
        if dictionary_get(request, b"CFPreferencesDomain")?.kind != 0x9000 {
            return None;
        }
        reads += 1;
    }
    (reads != 0).then_some(reads)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RbsRequestKind {
    Handshake,
    Assertion,
    Other,
}

pub(super) fn bootstrap_lookup_name(bytes: &[u8]) -> Option<&[u8]> {
    if word(bytes, 0)? != 0x4058_5043 || word(bytes, 4)? != 5 {
        return None;
    }
    let mut cursor = 8;
    let root = value(bytes, &mut cursor, 0, &mut 256)?;
    if cursor != bytes.len() || root.kind != 0xf000 {
        return None;
    }
    let name = dictionary_get(root, b"name")?;
    if name.kind != 0x9000 || name.body.len() < 2 {
        return None;
    }
    let flags = dictionary_get(root, b"flags")?;
    integer(flags)?;
    Some(name.body)
}

fn bootstrap_service_reply(bytes: &mut [u8; 512], port: u32, service: u32) -> usize {
    bytes.fill(0);
    // A complex Mach reply carries one COPY_SEND right after the XPC payload.
    put(bytes, 0, 0x8000_1200);
    put(bytes, 12, port);
    put(bytes, 20, 0x2000_0000);
    put(bytes, 24, 0x4058_5043);
    put(bytes, 28, 5);
    put(bytes, 32, 0xf000);
    put(bytes, 40, 1);
    let mut cursor = 44;
    let key = b"port\0\0\0\0";
    bytes[cursor..cursor + key.len()].copy_from_slice(key);
    cursor += key.len();
    put(bytes, cursor, 0xd000); // XPC_TYPE_MACH_SEND
    cursor += 4;
    put(bytes, cursor, 0); // replaced by the inline port descriptor
    cursor += 4;
    put(bytes, 36, (cursor - 40) as u32);
    put(bytes, cursor, 1); // one Mach port descriptor
    cursor += 4;
    put(bytes, cursor, service);
    cursor += 4;
    put(bytes, cursor, 0);
    cursor += 4;
    put(bytes, cursor, 19 << 16); // MACH_MSG_TYPE_COPY_SEND
    cursor += 4;
    put(bytes, 4, cursor as u32);
    cursor
}

fn notification_center_port(process: &Process) -> Option<u32> {
    let existing = process.notification_center_port.load(Ordering::Acquire);
    if existing != 0 && process.ports.has_receive(existing) {
        return Some(existing);
    }
    let candidate = process.ports.construct(0x10).ok()?;
    match process.notification_center_port.compare_exchange(
        0,
        candidate,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => Some(candidate),
        Err(existing) => {
            process.ports.discard_unpublished(candidate);
            (existing != 0 && process.ports.has_receive(existing)).then_some(existing)
        }
    }
}

fn rbs_message(bytes: &[u8]) -> Option<(RbsRequestKind, Option<Value<'_>>)> {
    if word(bytes, 0)? != 0x4058_5043 || word(bytes, 4)? != 5 {
        return None;
    }
    let mut cursor = 8;
    let root = value(bytes, &mut cursor, 0, &mut 256)?;
    if cursor != bytes.len() || root.kind != 0xf000 {
        return None;
    }
    let selector = dictionary_get(root, b"rbs_selector")?;
    if selector.kind != 0x9000 {
        return None;
    }
    let arg0 = dictionary_get(root, b"rbs_argument_0");
    let kind = if selector.body.starts_with(b"handshakeWithRequest:")
        || selector.body.starts_with(b"handshake")
    {
        RbsRequestKind::Handshake
    } else if selector.body.starts_with(b"acquireAssertion:")
        || selector.body.starts_with(b"invalidateAssertion:")
    {
        RbsRequestKind::Assertion
    } else {
        RbsRequestKind::Other
    };
    Some((kind, arg0))
}

// Minimal RunningBoard service unavailable reply. Encodes __RBSXPCError__ = 1
// (domain error) into an authentic XPC reply dictionary matching the client decoder.
fn rbs_unavailable_reply(bytes: &mut [u8; 512], port: u32) -> usize {
    bytes.fill(0);
    put(bytes, 0, 0x1200);
    put(bytes, 12, port);
    put(bytes, 20, 0x2000_0000);
    put(bytes, 24, 0x4058_5043);
    put(bytes, 28, 5);
    put(bytes, 32, 0xf000);
    put(bytes, 40, 1);
    let mut cursor = 44;
    let name = b"__RBSXPCError__";
    bytes[cursor..cursor + name.len()].copy_from_slice(name);
    cursor += padded(name.len() + 1).unwrap();
    put(bytes, cursor, 0x3000); // int64
    cursor += 4;
    let err_bytes = 1u64.to_le_bytes();
    bytes[cursor..cursor + err_bytes.len()].copy_from_slice(&err_bytes);
    cursor += err_bytes.len();
    put(bytes, 36, (cursor - 40) as u32);
    put(bytes, 4, cursor as u32);
    cursor
}

// The observed CoreFoundation error constructor uses these dictionary fields
// and integer error 0 for a generic failure (cache PC 0x6d689c). The description
// makes the unavailable backend explicit; no successful source data is returned.
fn unavailable_reply(bytes: &mut [u8; 512], port: u32) -> usize {
    bytes.fill(0);
    put(bytes, 0, 0x1200);
    put(bytes, 12, port);
    put(bytes, 20, 0x2000_0000);
    put(bytes, 24, 0x4058_5043);
    put(bytes, 28, 5);
    put(bytes, 32, 0xf000);
    put(bytes, 40, 3);
    let mut cursor = 44;
    for (name, kind, payload) in [
        (
            b"CFPreferencesErrorType".as_slice(),
            0x3000u32,
            0u64.to_le_bytes().as_slice(),
        ),
        (
            b"CFPreferencesErrorClientFault".as_slice(),
            0x2000u32,
            0u32.to_le_bytes().as_slice(),
        ),
    ] {
        bytes[cursor..cursor + name.len()].copy_from_slice(name);
        cursor += padded(name.len() + 1).unwrap();
        put(bytes, cursor, kind);
        cursor += 4;
        bytes[cursor..cursor + payload.len()].copy_from_slice(payload);
        cursor += payload.len();
    }
    let name = b"CFPreferencesErrorDescription";
    bytes[cursor..cursor + name.len()].copy_from_slice(name);
    cursor += padded(name.len() + 1).unwrap();
    let description = b"Harmonios preferences service is unavailable\0";
    put(bytes, cursor, 0x9000);
    put(bytes, cursor + 4, description.len() as u32);
    cursor += 8;
    bytes[cursor..cursor + description.len()].copy_from_slice(description);
    cursor += padded(description.len()).unwrap();
    put(bytes, 36, (cursor - 40) as u32);
    put(bytes, 4, cursor as u32);
    cursor
}

pub(super) fn send(process: &Process, frame: &TrapFrame, address: u64, size: usize) -> Option<u32> {
    if !(24..=4096).contains(&size) {
        return None;
    }
    let read = process.copy_in?;
    process.xpc.with(|buffers| {
        if unsafe {
            read(
                process.host_context,
                address,
                buffers.request.as_mut_ptr(),
                size,
            )
        } != 0
        {
            return Some(INVALID_DATA);
        }
        let request = &buffers.request[..size];
        if word(request, 0)? != frame.arguments[2] as u32
            || word(request, 4)? != size as u32
            || word(request, 8)? != frame.arguments[3] as u32
            || word(request, 12)? != (frame.arguments[3] >> 32) as u32
            || word(request, 16)? != frame.arguments[4] as u32
            || word(request, 20)? != (frame.arguments[4] >> 32) as u32
        {
            return Some(INVALID_DATA);
        }
        let id = word(request, 20)?;
        if id == 0x7730_3074 {
            if size != 52
                || word(request, 0)? & 0x8000_ffff != 0x8000_0013
                || word(request, 12)? != 0
                || word(request, 24)? != 2
                || word(request, 32)? != 0
                || word(request, 36)? != 16 << 16
                || word(request, 44)? != 0
                || word(request, 48)? != 20 << 16
            {
                return None;
            }
            let receive = word(request, 28)?;
            let send = word(request, 40)?;
            if !process.ports.has_receive(receive) || !process.ports.has_receive(send) {
                return None;
            }
            if buffers.connections.contains(&receive) {
                return Some(0);
            }
            let slot = buffers.connections.iter_mut().find(|slot| **slot == 0)?;
            *slot = receive;
            return Some(0);
        }
        let reply_port = word(request, 12)?;
        if !process.ports.has_receive(reply_port) {
            return None;
        }
        let payload = request.get(24..)?;
        if let Some(name) = bootstrap_lookup_name(payload) {
            let name_str =
                std::str::from_utf8(name.strip_suffix(b"\0").unwrap_or(name)).unwrap_or("");
            if !process.bootstrap_namespace.is_registered(name_str) {
                if let Some(console) = process.console {
                    let mut msg = Vec::new();
                    msg.extend_from_slice(b"bootstrap lookup unregistered service: ");
                    msg.extend_from_slice(name);
                    msg.push(b'\n');
                    unsafe {
                        console(process.host_context, 2, msg.as_ptr(), msg.len());
                    }
                }
                return None;
            }
            if name_str == "com.apple.system.notification_center" {
                let Some(service) = notification_center_port(process) else {
                    return Some(0x1000_0003);
                };
                if !buffers.push_reply(reply_port, |reply| {
                    bootstrap_service_reply(reply, reply_port, service)
                }) {
                    return Some(SEND_TIMED_OUT);
                }
                if let Some(console) = process.console {
                    let message = b"local XPC: notification center lookup -> local port\n";
                    unsafe {
                        console(process.host_context, 2, message.as_ptr(), message.len());
                    }
                }
                return Some(0);
            }
            return None;
        }
        if id != 0x4000_0000
            || word(request, 0)? & 0x8000_ffff != 0x1513
            || !buffers.connections.contains(&(frame.arguments[3] as u32))
        {
            return None;
        }
        if preferences_read(payload).is_some() {
            if !buffers.push_reply(reply_port, |reply| unavailable_reply(reply, reply_port)) {
                return Some(SEND_TIMED_OUT);
            }
            if let Some(console) = process.console {
                let message = b"local XPC: preferences read request -> service unavailable
";
                unsafe {
                    console(process.host_context, 2, message.as_ptr(), message.len());
                }
            }
            Some(0)
        } else if let Some((kind, _arg0)) = rbs_message(payload) {
            if !buffers.push_reply(reply_port, |reply| rbs_unavailable_reply(reply, reply_port)) {
                return Some(SEND_TIMED_OUT);
            }
            if let Some(console) = process.console {
                let message = match kind {
                    RbsRequestKind::Handshake => {
                        b"local XPC: runningboard handshake -> service unavailable
"
                        .as_slice()
                    }
                    RbsRequestKind::Assertion => {
                        b"local XPC: runningboard assertion -> service unavailable
"
                        .as_slice()
                    }
                    RbsRequestKind::Other => {
                        b"local XPC: runningboard request -> service unavailable
"
                        .as_slice()
                    }
                };
                unsafe {
                    console(process.host_context, 2, message.as_ptr(), message.len());
                }
            }
            Some(0)
        } else {
            None
        }
    })?
}

pub(super) fn receive(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    if a[1] & 3 != 2 || a[1] & 0x1_0000_0000 != 0 || a[2] != 0 {
        return None;
    }
    let port = (a[5] >> 32) as u32;
    let write = process.copy_out?;
    process.xpc.with(|buffers| {
        let index =
            (0..buffers.reply_count).find(|index| buffers.replies[*index].port == port)?;
        let trailer = match (a[1] >> 24) & 0xff {
            0 => 8,
            7 => 68,
            _ => return None,
        };
        let length = buffers.replies[index].length;
        if (a[6] as u32 as usize) < length + trailer {
            return Some(RCV_TOO_LARGE);
        }
        {
            let reply = &mut buffers.replies[index].bytes;
            reply[length..length + trailer].fill(0);
            put(reply, length + 4, trailer as u32);
            if trailer == 68 {
                put(reply, length + 12, 501);
                put(reply, length + 16, 501);
                for (field, value) in [
                    u32::MAX,
                    501,
                    501,
                    501,
                    501,
                    process.pid,
                    100,
                    process.thread_id as u32,
                ]
                .into_iter()
                .enumerate()
                {
                    put(reply, length + 20 + field * 4, value);
                }
            }
            if unsafe { write(process.host_context, a[0], reply.as_ptr(), length + trailer) } != 0 {
                return Some(RCV_INVALID_DATA);
            }
        }
        buffers.remove_reply(index);
        Some(0)
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    fn number(n: u64) -> Vec<u8> {
        let mut bytes = 0x3000u32.to_le_bytes().to_vec();
        bytes.extend(n.to_le_bytes());
        bytes
    }
    fn text(s: &str) -> Vec<u8> {
        let mut bytes = 0x9000u32.to_le_bytes().to_vec();
        bytes.extend((s.len() as u32 + 1).to_le_bytes());
        bytes.extend(s.as_bytes());
        bytes.push(0);
        bytes.resize(padded(bytes.len()).unwrap(), 0);
        bytes
    }
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&s[at..at + 2], 16).unwrap())
            .collect()
    }
    fn container(kind: u32, count: u32, content: Vec<u8>) -> Vec<u8> {
        let mut bytes = kind.to_le_bytes().to_vec();
        bytes.extend((content.len() as u32 + 4).to_le_bytes());
        bytes.extend(count.to_le_bytes());
        bytes.extend(content);
        bytes
    }
    fn dict(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut content = Vec::new();
        for (name, value) in fields {
            content.extend(name.as_bytes());
            content.push(0);
            content.resize(padded(content.len()).unwrap(), 0);
            content.extend(value);
        }
        container(0xf000, fields.len() as u32, content)
    }
    fn batch(operation: u64) -> Vec<u8> {
        let read = dict(&[
            ("CFPreferencesOperation", number(operation)),
            ("CFPreferencesDomain", text("app.test")),
        ]);
        let array = container(0xe000, 2, [read, 0x1000u32.to_le_bytes().to_vec()].concat());
        let mut bytes = [0x4058_5043u32.to_le_bytes(), 5u32.to_le_bytes()].concat();
        bytes.extend(dict(&[
            ("CFPreferencesOperation", number(5)),
            ("CFPreferencesMessages", array),
        ]));
        bytes
    }
    #[test]
    fn validates_read_batches_and_rejects_truncation_and_other_operations() {
        let good = batch(1);
        assert_eq!(preferences_read(&good), Some(1));
        let mut single = [0x4058_5043u32.to_le_bytes(), 5u32.to_le_bytes()].concat();
        single.extend(dict(&[
            ("CFPreferencesOperation", number(1)),
            ("CFPreferencesDomain", text("app.test")),
        ]));
        assert_eq!(preferences_read(&single), Some(1));
        for end in 0..single.len() {
            assert_eq!(preferences_read(&single[..end]), None);
        }
        for end in 0..good.len() {
            assert_eq!(preferences_read(&good[..end]), None);
        }
        assert_eq!(preferences_read(&batch(2)), None);
        for at in 0..good.len() {
            let mut malformed = good.clone();
            malformed[at] ^= 0xff;
            let _ = preferences_read(&malformed); // no panic for invalid sizes/counts/types
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(preferences_read(&trailing), None);
        let mut nested = 0x1000u32.to_le_bytes().to_vec();
        for _ in 0..12 {
            nested = container(0xe000, 1, nested);
        }
        assert!(value(&nested, &mut 0, 0, &mut 256).is_none());
        let duplicate = dict(&[("op", number(1)), ("op", number(2))]);
        let root = value(&duplicate, &mut 0, 0, &mut 256).unwrap();
        assert!(dictionary_get(root, b"op").is_none());
    }
    #[test]
    #[ignore = "requires a local, uncommitted device capture"]
    fn private_device_preferences_capture_is_a_valid_read_batch() {
        let bytes = std::fs::read(std::env::var("HARMONIOS_XPC_CAPTURE").unwrap()).unwrap();
        let expected = std::env::var("HARMONIOS_XPC_READS")
            .unwrap_or("7".into())
            .parse()
            .unwrap();
        assert_eq!(preferences_read(&bytes[24..]), Some(expected));
    }
    unsafe extern "C" fn read(
        context: *const c_void,
        address: u64,
        out: *mut u8,
        size: usize,
    ) -> u32 {
        let bytes = &*(context as *const [u8; 8192]);
        let Some(end) = (address as usize).checked_add(size) else {
            return 14;
        };
        let Some(part) = bytes.get(address as usize..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(part.as_ptr(), out, size);
        0
    }
    unsafe extern "C" fn write(
        context: *const c_void,
        address: u64,
        data: *const u8,
        size: usize,
    ) -> u32 {
        let bytes = &mut *(context as *mut [u8; 8192]);
        let Some(end) = (address as usize).checked_add(size) else {
            return 14;
        };
        let Some(part) = bytes.get_mut(address as usize..end) else {
            return 14;
        };
        std::ptr::copy_nonoverlapping(data, part.as_mut_ptr(), size);
        0
    }
    fn vector(
        memory: &mut [u8; 8192],
        remote: u32,
        local: u32,
        id: u32,
        bits: u32,
        body: &[u8],
    ) -> TrapFrame {
        let size = 24 + body.len();
        memory[..48].fill(0);
        memory[..8].copy_from_slice(&256u64.to_le_bytes());
        put(memory, 16, size as u32);
        for (index, value) in [bits, size as u32, remote, local, 0, id]
            .into_iter()
            .enumerate()
        {
            put(memory, 256 + index * 4, value);
        }
        memory[280..280 + body.len()].copy_from_slice(body);
        TrapFrame {
            number: -47,
            arguments: [
                0,
                0x5_0000_0001,
                (2 << 32) | u64::from(bits),
                u64::from(remote) | (u64::from(local) << 32),
                u64::from(id) << 32,
                0,
                0,
                0,
            ],
            ..Default::default()
        }
    }
    #[test]
    fn local_transport_preserves_pending_errors_until_successful_copyout() {
        let mut process = Process::new(42, 1, 99);
        let mut memory = [0u8; 8192];
        process.copy_in = Some(read);
        process.copy_out = Some(write);
        process.host_context = memory.as_mut_ptr().cast();
        let listener = process.ports.construct(0x10).unwrap();
        let peer = process.ports.construct(0x10).unwrap();
        let client = process.ports.construct(0x10).unwrap();
        let reply = process.ports.construct(0x10).unwrap();
        let mut checkin = [0u8; 28];
        for (index, value) in [2, peer, 0, 16 << 16, client, 0, 20 << 16]
            .into_iter()
            .enumerate()
        {
            put(&mut checkin, index * 4, value);
        }
        let frame = vector(&mut memory, listener, 0, 0x7730_3074, 0x8000_0013, &checkin);
        assert_eq!(super::super::ipc::message2(&process, &frame), Some(0));
        let frame = vector(&mut memory, peer, reply, 0x4000_0000, 0x1513, &batch(1));
        memory[24..32].copy_from_slice(&6000u64.to_le_bytes());
        put(&mut memory, 40, 40);
        put(&mut memory, 6000, 40);
        put(&mut memory, 6004, 1); // reserved auxiliary header must be zero
        assert_eq!(
            super::super::ipc::message2(&process, &frame),
            Some(INVALID_DATA)
        );
        put(&mut memory, 6004, 0);
        assert_eq!(super::super::ipc::message2(&process, &frame), Some(0));
        assert_eq!(super::super::ipc::message2(&process, &frame), Some(0));
        let mut receive = TrapFrame {
            number: -47,
            arguments: [4096, 0x4_0700_420e, 0, 0, 0, u64::from(reply) << 32, 4, 0],
            ..Default::default()
        };
        assert_eq!(
            super::super::ipc::message2(&process, &receive),
            Some(RCV_TOO_LARGE)
        );
        receive.arguments[6] = 1024;
        receive.arguments[0] = 8192;
        assert_eq!(
            super::super::ipc::message2(&process, &receive),
            Some(RCV_INVALID_DATA)
        );
        receive.arguments[0] = 4096;
        receive.arguments[5] = u64::from(client) << 32;
        assert_eq!(
            super::super::ipc::message2(&process, &receive),
            Some(0x10004003)
        );
        receive.arguments[5] = u64::from(reply) << 32;
        assert_eq!(super::super::ipc::message2(&process, &receive), Some(0));
        let output = &memory[4096..];
        let size = word(output, 4).unwrap() as usize;
        assert_eq!(word(output, 12), Some(reply));
        assert_eq!(word(output, 20), Some(0x2000_0000));
        assert_eq!(word(output, size + 4), Some(68));
        assert_eq!(word(output, size + 40), Some(42)); // peer is this local process
        let mut at = 32;
        let dictionary = value(output, &mut at, 0, &mut 256).unwrap();
        assert_eq!(
            integer(dictionary_get(dictionary, b"CFPreferencesErrorType").unwrap()),
            Some(0)
        );
        assert!(dictionary_get(dictionary, b"CFPreferencesMessages").is_none());
        assert_eq!(super::super::ipc::message2(&process, &receive), Some(0));
        assert_eq!(
            super::super::ipc::message2(&process, &receive),
            Some(0x10004003)
        );
        process
            .xpc
            .with(|_| assert!(process.xpc.with(|_| ()).is_none()));
    }

    #[test]
    fn notification_center_bootstrap_lookup_returns_an_inline_send_right() {
        let mut lookup = [0x4058_5043u32.to_le_bytes(), 5u32.to_le_bytes()].concat();
        lookup.extend(dict(&[
            ("name", text("com.apple.system.notification_center")),
            ("flags", number(0x8000)),
        ]));
        assert_eq!(
            bootstrap_lookup_name(&lookup),
            Some(b"com.apple.system.notification_center\0".as_slice())
        );

        let mut reply = [0u8; 512];
        let length = bootstrap_service_reply(&mut reply, 0x1234, 0xb03);
        assert_eq!(word(&reply, 0), Some(0x8000_1200));
        assert_eq!(word(&reply, 4), Some(length as u32));
        assert_eq!(word(&reply, 12), Some(0x1234));
        assert_eq!(word(&reply, 20), Some(0x2000_0000));
        let mut cursor = 32;
        let root = value(&reply, &mut cursor, 0, &mut 256).unwrap();
        let port = dictionary_get(root, b"port").unwrap();
        assert_eq!(port.kind, 0xd000);
        assert_eq!(word(&reply, length - 16), Some(1));
        assert_eq!(word(&reply, length - 12), Some(0xb03));
        assert_eq!(word(&reply, length - 4), Some(19 << 16));
    }

    #[test]
    fn captured_notification_center_lookup_accepts_uuid_values() {
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
        assert_eq!(
            bootstrap_lookup_name(&request[24..]),
            Some(b"com.apple.system.notification_center\0".as_slice())
        );
    }

    #[test]
    fn rbs_handshake_and_assertion_messages_are_identified_and_replied_with_domain_error() {
        let handshake_dict = dict(&[
            ("rbs_selector", text("handshakeWithRequest:")),
            ("rbs_argument_0", number(42)),
        ]);
        let mut hs_msg = [0x4058_5043u32.to_le_bytes(), 5u32.to_le_bytes()].concat();
        hs_msg.extend(handshake_dict);
        let parsed = rbs_message(&hs_msg);
        assert_eq!(parsed.map(|(k, _)| k), Some(RbsRequestKind::Handshake));

        let assertion_dict = dict(&[
            ("rbs_selector", text("acquireAssertion:error:")),
            ("rbs_argument_0", number(100)),
        ]);
        let mut as_msg = [0x4058_5043u32.to_le_bytes(), 5u32.to_le_bytes()].concat();
        as_msg.extend(assertion_dict);
        let parsed_as = rbs_message(&as_msg);
        assert_eq!(parsed_as.map(|(k, _)| k), Some(RbsRequestKind::Assertion));

        let mut reply_buf = [0u8; 512];
        let reply_len = rbs_unavailable_reply(&mut reply_buf, 0x1234);
        assert!(reply_len > 44);
        assert_eq!(word(&reply_buf, 0), Some(0x1200));
        assert_eq!(word(&reply_buf, 12), Some(0x1234));
        assert_eq!(word(&reply_buf, 20), Some(0x2000_0000));
        assert_eq!(word(&reply_buf, 24), Some(0x4058_5043));
        let mut cursor = 32;
        let root = value(&reply_buf, &mut cursor, 0, &mut 256).unwrap();
        assert_eq!(root.kind, 0xf000);
        assert_eq!(
            integer(dictionary_get(root, b"__RBSXPCError__").unwrap()),
            Some(1)
        );
    }
}
