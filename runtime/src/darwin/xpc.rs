//! Bounded local XPC transport for Darwin compatibility.
//! No allocation or blocking host locks on the synchronous trap path.
//! System services are resolved through `BootstrapNamespace` and `SystemService`.

use super::{Process, TrapFrame};
#[cfg(test)]
use crate::services::runningboard::RbsRequestKind;
#[cfg(test)]
use crate::services::CfprefsdService;
#[cfg(test)]
use crate::services::RunningBoardService;
#[cfg(test)]
use crate::xpc::Value;
use crate::xpc::{XpcDecoder, XpcEncoder};
use std::cell::UnsafeCell;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

const INVALID_DATA: u32 = 0x10000002;
const SEND_TIMED_OUT: u32 = 0x10000004;
const RCV_TOO_LARGE: u32 = 0x10004004;
const RCV_INVALID_DATA: u32 = 0x10004008;
const REPLY_CAPACITY: usize = 8;

/// Zero-allocation bounded stack buffer for logging on the trap hot-path.
struct FixedWriter<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> FixedWriter<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl<const N: usize> Write for FixedWriter<N> {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let remaining = self.buf.len().saturating_sub(self.len);
        let to_copy = data.len().min(remaining);
        self.buf[self.len..self.len + to_copy].copy_from_slice(&data[..to_copy]);
        self.len += to_copy;
        Ok(to_copy)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
enum ReplySender {
    #[default]
    LocalProcess,
    // The compatibility kernel owns the guest's bootstrap namespace.
    Bootstrap,
}

#[derive(Clone, Copy)]
struct PendingReply {
    bytes: [u8; 512],
    length: usize,
    port: u32,
    sender: ReplySender,
}

impl Default for PendingReply {
    fn default() -> Self {
        Self {
            bytes: [0; 512],
            length: 0,
            port: 0,
            sender: ReplySender::LocalProcess,
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
    ready: Condvar,
    epoch: Mutex<u64>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            busy: AtomicBool::new(false),
            ready: Condvar::new(),
            epoch: Mutex::new(0),
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
    fn notify(&self) {
        let mut epoch = self.epoch.lock().unwrap_or_else(|e| e.into_inner());
        *epoch = epoch.wrapping_add(1);
        self.ready.notify_all();
    }

    fn with<T>(&self, operation: impl FnOnce(&mut Buffers) -> T) -> Option<T> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let _claim = Claim(&self.busy);
        Some(operation(unsafe { &mut *self.buffers.get() }))
    }
}

impl Buffers {
    fn push_reply(
        &mut self,
        port: u32,
        sender: ReplySender,
        build: impl FnOnce(&mut [u8; 512]) -> usize,
    ) -> bool {
        if self.reply_count == self.replies.len() {
            return false;
        }
        let reply = &mut self.replies[self.reply_count];
        reply.bytes.fill(0);
        reply.port = port;
        reply.sender = sender;
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

#[inline]
pub(crate) fn word(bytes: &[u8], at: usize) -> Option<u32> {
    XpcDecoder::word(bytes, at)
}

#[inline]
pub(crate) fn put(bytes: &mut [u8], at: usize, value: u32) {
    XpcEncoder::put_word(bytes, at, value);
}

#[cfg(test)]
#[inline]
pub(crate) fn padded(size: usize) -> Option<usize> {
    XpcDecoder::padded(size)
}

#[cfg(test)]
#[inline]
pub(crate) fn value<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    depth: u32,
    budget: &mut u32,
) -> Option<Value<'a>> {
    XpcDecoder::parse_value(bytes, cursor, depth, budget)
}

#[cfg(test)]
#[inline]
pub(crate) fn dictionary_get<'a>(dictionary: Value<'a>, name: &[u8]) -> Option<Value<'a>> {
    XpcDecoder::dictionary_get(dictionary, name)
}

#[cfg(test)]
#[inline]
pub(crate) fn integer(val: Value<'_>) -> Option<u64> {
    XpcDecoder::integer(val)
}

#[inline]
pub(super) fn bootstrap_lookup_name(bytes: &[u8]) -> Option<&[u8]> {
    XpcDecoder::bootstrap_lookup_name(bytes)
}

#[cfg(test)]
#[inline]
pub(crate) fn preferences_read(bytes: &[u8]) -> Option<u32> {
    CfprefsdService::parse_read_request(bytes)
}

#[cfg(test)]
#[inline]
pub(crate) fn rbs_message(bytes: &[u8]) -> Option<(RbsRequestKind, Option<Value<'_>>)> {
    RunningBoardService::parse_message(bytes)
}

#[inline]
fn bootstrap_service_reply(
    bytes: &mut [u8; 512],
    port: u32,
    service: u32,
    request_pid: u32,
    request_execcnt: u32,
) -> usize {
    XpcEncoder::build_bootstrap_service_reply(bytes, port, service, request_pid, request_execcnt)
}

#[inline]
fn bootstrap_lookup_error(bytes: &mut [u8; 512], port: u32, process: &Process) -> usize {
    XpcEncoder::build_bootstrap_lookup_error(
        bytes,
        port,
        process.pid,
        process.thread_id as u32,
    )
}

#[cfg(test)]
#[inline]
fn rbs_unavailable_reply(bytes: &mut [u8; 512], port: u32) -> usize {
    XpcEncoder::build_rbs_unavailable_reply(bytes, port)
}

#[cfg(test)]
#[inline]
fn unavailable_reply(bytes: &mut [u8; 512], port: u32) -> usize {
    XpcEncoder::build_preferences_unavailable_reply(bytes, port)
}

pub(super) fn send(process: &Process, frame: &TrapFrame, address: u64, size: usize) -> Option<u32> {
    if !(24..=4096).contains(&size) {
        return None;
    }
    let read = process.copy_in?;
    let result = process.xpc.with(|buffers| {
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
        if let Some(console) = process.console {
            let mut writer = FixedWriter::<512>::new();
            let _ = write!(
                writer,
                "xpc send: id=0x{:x} size={} remote=0x{:x}",
                id,
                size,
                frame.arguments[3] as u32
            );
            if size >= 40 {
                let payload = &request[24..];
                if word(payload, 0) == Some(0x4058_5043) {
                    let mut cursor = 8;
                    if let Some(root) = XpcDecoder::parse_value(payload, &mut cursor, 0, &mut 256) {
                        if root.kind == 0xf000 {
                            let mut k_cur = 0;
                            let mut budget = 256;
                            for _ in 0..root.count.min(8) {
                                if let Some(k) = XpcDecoder::key(root.body, &mut k_cur) {
                                    if let Some(v) = XpcDecoder::parse_value(root.body, &mut k_cur, 0, &mut budget) {
                                        let k_str = std::str::from_utf8(k).unwrap_or("");
                                        let _ = write!(writer, " k={}", k_str);
                                        if v.kind == 0x9000 {
                                            let s = std::str::from_utf8(v.body.strip_suffix(b"\0").unwrap_or(v.body)).unwrap_or("");
                                            let _ = write!(writer, ":{}", s);
                                        }
                                    }
                                }
                            }
                            let _ = writeln!(writer);
                        }
                    }
                }
            }
            unsafe {
                console(
                    process.host_context,
                    2,
                    writer.as_bytes().as_ptr(),
                    writer.as_bytes().len(),
                );
            }
        }
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
            if let Some(console) = process.console {
                let mut writer = FixedWriter::<128>::new();
                let _ = writeln!(writer, "bootstrap lookup request: {}", name_str);
                unsafe {
                    console(
                        process.host_context,
                        2,
                        writer.as_bytes().as_ptr(),
                        writer.as_bytes().len(),
                    );
                }
            }
            if !process.bootstrap_namespace.is_registered(name_str) {
                if let Some(console) = process.console {
                    let mut writer = FixedWriter::<128>::new();
                    let _ = write!(writer, "bootstrap lookup unregistered service: ");
                    let _ = writer.write_all(name);
                    let _ = writer.write_all(b"\n");
                    unsafe {
                        console(
                            process.host_context,
                            2,
                            writer.as_bytes().as_ptr(),
                            writer.as_bytes().len(),
                        );
                    }
                }
                if !buffers.push_reply(reply_port, ReplySender::Bootstrap, |reply| {
                    bootstrap_lookup_error(reply, reply_port, process)
                }) {
                    return Some(SEND_TIMED_OUT);
                }
                return Some(0);
            }
            let matched_service = process.bootstrap_namespace.get_service_by_name(name_str);
            if matched_service.is_some() && matched_service.as_ref().and_then(|svc| svc.bootstrap_port(process)).is_none() {
                if let Some(console) = process.console {
                    let mut writer = FixedWriter::<128>::new();
                    let _ = writeln!(writer, "local XPC: {} lookup dropped (no bootstrap port)", name_str);
                    unsafe {
                        console(
                            process.host_context,
                            2,
                            writer.as_bytes().as_ptr(),
                            writer.as_bytes().len(),
                        );
                    }
                }
            }
            if let Some(service) = matched_service {
                if let Some(service_port) = service.bootstrap_port(process) {
                    if !buffers.push_reply(reply_port, ReplySender::Bootstrap, |reply| {
                        bootstrap_service_reply(
                            reply,
                            reply_port,
                            service_port,
                            process.pid,
                            process.thread_id as u32,
                        )
                    }) {
                        return Some(SEND_TIMED_OUT);
                    }
                    if let Some(console) = process.console {
                        let mut writer = FixedWriter::<128>::new();
                        let _ = writeln!(
                            writer,
                            "local XPC: {} lookup -> local port",
                            service.name()
                        );
                        unsafe {
                            console(
                                process.host_context,
                                2,
                                writer.as_bytes().as_ptr(),
                                writer.as_bytes().len(),
                            );
                        }
                    }
                    return Some(0);
                }
            }
            return None;
        }

        let remote_dest = frame.arguments[3] as u32;
        if id != 0x4000_0000 || word(request, 0)? & 0x8000_ffff != 0x1513 {
            return None;
        }

        for service in process.bootstrap_namespace.all_services() {
            if service.can_handle_xpc(payload, remote_dest, process, &buffers.connections) {
                let mut temp_reply = [0u8; 512];
                let reply_len = service
                    .handle_xpc(payload, reply_port, remote_dest, process, &mut temp_reply)
                    .unwrap_or(0);
                if !buffers.push_reply(reply_port, ReplySender::LocalProcess, |reply| {
                    reply[..reply_len].copy_from_slice(&temp_reply[..reply_len]);
                    reply_len
                }) {
                    return Some(SEND_TIMED_OUT);
                }
                if let Some(console) = process.console {
                    let mut writer = FixedWriter::<128>::new();
                    let _ = writeln!(writer, "local XPC: {} request -> reply", service.name());
                    unsafe {
                        console(
                            process.host_context,
                            2,
                            writer.as_bytes().as_ptr(),
                            writer.as_bytes().len(),
                        );
                    }
                }
                return Some(0);
            }
        }

        if let Some(console) = process.console {
            static DROPPED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            if DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 24 {
                let mut writer = FixedWriter::<256>::new();
                let _ = writeln!(
                    writer,
                    "xpc send dropped unhandled: id=0x{:x} size={} remote=0x{:x} bits=0x{:x}",
                    id,
                    size,
                    remote_dest,
                    word(request, 0).unwrap_or(0)
                );
                unsafe {
                    console(
                        process.host_context,
                        2,
                        writer.as_bytes().as_ptr(),
                        writer.as_bytes().len(),
                    );
                }
            }
        }

        None
    })?;
    if result == Some(0) {
        process.xpc.notify();
    }
    result
}

pub(super) fn receive(process: &Process, frame: &TrapFrame) -> Option<u32> {
    process.copy_out?;
    let a = frame.arguments;
    if a[1] & 3 != 2
        || a[1] & 0x1_0000_0000 != 0
        || a[2] != 0
        || !matches!((a[1] >> 24) & 0xff, 0 | 1 | 2 | 3 | 4 | 7)
    {
        return None;
    }
    let port = (a[5] >> 32) as u32;
    let (Some(leave), Some(enter)) = (process.wait_leave, process.wait_enter) else {
        return receive_once(process, frame);
    };
    if a[1] & 0x100 != 0 {
        return receive_once(process, frame);
    }
    loop {
        let observed = *process.xpc.epoch.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(result) = receive_once(process, frame) {
            return Some(result);
        }
        if process.stopping.load(Ordering::Acquire) {
            return Some(0x10004005);
        }
        if !process.ports.has_receive(port) {
            return Some(0x10004002);
        }
        let epoch = process.xpc.epoch.lock().unwrap_or_else(|e| e.into_inner());
        if *epoch != observed {
            continue;
        }
        // As with ulock, let another guest worker execute while the calling
        // thread waits for a real reply. Never hold the notification mutex
        // while reacquiring the guest execution gate.
        unsafe {
            leave();
        }
        let (epoch, _) = process
            .xpc
            .ready
            .wait_timeout(epoch, Duration::from_millis(20))
            .unwrap_or_else(|e| e.into_inner());
        drop(epoch);
        unsafe {
            enter();
        }
    }
}

fn receive_once(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let a = frame.arguments;
    if a[1] & 3 != 2 || a[1] & 0x1_0000_0000 != 0 || a[2] != 0 {
        return None;
    }
    let port = (a[5] >> 32) as u32;
    let write = process.copy_out?;
    process.xpc.with(|buffers| {
        let index = (0..buffers.reply_count).find(|index| buffers.replies[*index].port == port)?;
        let trailer = match (a[1] >> 24) & 0xff {
            0 => 8,
            1 => 12,
            2 => 20,
            3 => 52,
            4 => 60,
            7 => 68,
            _ => return None,
        };
        let length = buffers.replies[index].length;
        if (a[6] as u32 as usize) < length + trailer {
            return Some(RCV_TOO_LARGE);
        }
        {
            let (uid, pid) = match buffers.replies[index].sender {
                ReplySender::LocalProcess => (501, process.pid),
                ReplySender::Bootstrap => (0, 1),
            };
            let reply = &mut buffers.replies[index].bytes;
            reply[length..length + trailer].fill(0);
            put(reply, length + 4, trailer as u32);
            if trailer >= 20 {
                put(reply, length + 12, uid);
                put(reply, length + 16, uid);
            }
            if trailer >= 52 {
                for (field, value) in [
                    u32::MAX,
                    uid,
                    uid,
                    uid,
                    uid,
                    pid,
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

    #[test]
    fn untimed_receive_waits_for_a_reply_and_cancels_with_balanced_gate_hooks() {
        use std::sync::atomic::AtomicUsize;
        static LEFT: AtomicUsize = AtomicUsize::new(0);
        static ENTERED: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "C" fn leave() {
            LEFT.fetch_add(1, Ordering::SeqCst);
        }
        unsafe extern "C" fn enter() {
            ENTERED.fetch_add(1, Ordering::SeqCst);
        }
        let mut memory = Box::new([0u8; 8192]);
        let mut process = Box::new(Process::new(42, 1, 99));
        process.host_context = memory.as_mut_ptr().cast();
        process.copy_out = Some(write);
        process.wait_leave = Some(leave);
        process.wait_enter = Some(enter);
        let port = process.ports.construct(0x1000).unwrap();
        let address = (&*process as *const Process) as usize;
        let start_receiver = || {
            std::thread::spawn(move || unsafe {
                receive(
                    &*(address as *const Process),
                    &TrapFrame {
                        number: -47,
                        arguments: [4096, 0x4_0700_020e, 0, 0, 0, u64::from(port) << 32, 512, 0],
                        ..Default::default()
                    },
                )
            })
        };
        let wait_until_left = |prior| {
            let deadline = std::time::Instant::now() + Duration::from_secs(1);
            while LEFT.load(Ordering::SeqCst) <= prior {
                assert!(
                    std::time::Instant::now() < deadline,
                    "receiver never released execution gate"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        let receiver = start_receiver();
        wait_until_left(0);
        assert!(!receiver.is_finished());
        assert_eq!(
            process
                .xpc
                .with(|b| b.push_reply(
                    port,
                    ReplySender::LocalProcess,
                    |bytes| unavailable_reply(bytes, port)
                )),
            Some(true)
        );
        process.xpc.notify();
        assert_eq!(receiver.join().unwrap(), Some(0));
        assert_eq!(word(&memory[4096..], 12), Some(port));
        let prior = LEFT.load(Ordering::SeqCst);
        let receiver = start_receiver();
        wait_until_left(prior);
        process.stopping.store(true, Ordering::Release);
        process.xpc.notify();
        assert_eq!(receiver.join().unwrap(), Some(0x10004005));
        assert_eq!(LEFT.load(Ordering::SeqCst), ENTERED.load(Ordering::SeqCst));
    }

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
            let _ = preferences_read(&malformed);
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
        let length = bootstrap_service_reply(&mut reply, 0x1234, 0xb03, 77, 99);
        assert_eq!(word(&reply, 0), Some(0x8000_1200));
        assert_eq!(word(&reply, 4), Some(length as u32));
        assert_eq!(word(&reply, 12), Some(0x1234));
        assert_eq!(word(&reply, 20), Some(0x2000_0000));
        let mut cursor = 48;
        let root = value(&reply, &mut cursor, 0, &mut 256).unwrap();
        let port = dictionary_get(root, b"port").unwrap();
        assert_eq!(port.kind, 0xd000);
        assert_eq!(integer(dictionary_get(root, b"req_pid").unwrap()), Some(77));
        assert_eq!(
            integer(dictionary_get(root, b"rec_execcnt").unwrap()),
            Some(99)
        );
        assert_eq!(cursor, length);
        assert_eq!(word(&reply, 24), Some(1));
        assert_eq!(word(&reply, 28), Some(0xb03));
        assert_eq!(word(&reply, 36), Some(17 << 16));
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
