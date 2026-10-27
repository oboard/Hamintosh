//! Process workqueue user events and bounded asynchronous workloop requests.
//!
//! The dispatch manager's EVFILT_USER state is separate from workloop event
//! snapshots. Native workers lease real registered events while the execution
//! gate serializes guest/pager access. Ordinary file kqueues, Mach message
//! event delivery and full ownership/QoS inheritance remain unsupported.

use super::{threads, workloop_sync, CopyIn, CopyOut, Process, TrapFrame};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const EFAULT: u32 = 14;
const EINVAL: u32 = 22;
const ENOENT: u32 = 2;
const ENOTSUP: u32 = 45;

const KEVENT_FLAG_IMMEDIATE: u32 = 0x0001;
const KEVENT_FLAG_ERROR_EVENTS: u32 = 0x0002;
const KEVENT_FLAG_STACK_DATA: u32 = 0x0008;
const KEVENT_FLAG_WORKQ: u32 = 0x0020;
const KEVENT_FLAG_WORKLOOP: u32 = 0x0400;
const KEVENT_FLAG_USER: u32 =
    KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS | KEVENT_FLAG_STACK_DATA | KEVENT_FLAG_WORKQ;

const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ENABLE: u16 = 0x0004;
const EV_DISABLE: u16 = 0x0008;
const EV_RECEIPT: u16 = 0x0040;
const EV_ERROR: u16 = 0x4000;

const EVFILT_MACHPORT: i16 = -8;
const EVFILT_USER: i16 = -10;
const EVFILT_MEMORYSTATUS: i16 = -14;
const EVFILT_WORKLOOP: i16 = -17;
const NOTE_TRIGGER: u32 = 0x0100_0000;
const NOTE_FFAND: u32 = 0x4000_0000;
const NOTE_FFOR: u32 = 0x8000_0000;
const NOTE_FFCOPY: u32 = 0xc000_0000;
const NOTE_FFCTRLMASK: u32 = 0xc000_0000;
const NOTE_FFLAGSMASK: u32 = 0x00ff_ffff;

const LEASED: u64 = 1 << 63;
const REDRIVE: u64 = 1 << 62;
const IDENT_MASK: u64 = REDRIVE - 1;
const KEVENT_QOS_SIZE: usize = 72;
const MAX_CHANGES: i32 = 64;
const MAX_EVENTS: i32 = 64;

#[derive(Default)]
pub struct State {
    sync: workloop_sync::State,
    pub(super) workloop_requests: [AtomicU64; 32],
    workloop_events: [[AtomicU64; 9]; 32],
    pub(super) present: AtomicBool,
    pub(super) enabled: AtomicBool,
    pub(super) pending: AtomicBool,
    pub(super) clear: AtomicBool,
    pub(super) ident: AtomicU64,
    pub(super) udata: AtomicU64,
    pub(super) fflags: AtomicU32,
    pub(super) data: AtomicU64,
}

#[derive(Clone, Copy)]
struct UserNote {
    ident: u64,
    filter: i16,
    flags: u16,
    fflags: u32,
    data: u64,
    udata: u64,
}

impl UserNote {
    fn from_bytes(bytes: &[u8; KEVENT_QOS_SIZE]) -> Option<Self> {
        let filter = i16::from_le_bytes(bytes[8..10].try_into().ok()?);
        if !matches!(
            filter,
            EVFILT_MACHPORT | EVFILT_USER | EVFILT_MEMORYSTATUS | EVFILT_WORKLOOP
        ) {
            return None;
        }
        Some(Self {
            ident: read_u64(bytes, 0),
            filter,
            flags: u16::from_le_bytes(bytes[10..12].try_into().ok()?) & !0xf000,
            fflags: u32::from_le_bytes(bytes[24..28].try_into().ok()?),
            data: read_u64(bytes, 32),
            udata: read_u64(bytes, 16),
        })
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

impl State {
    fn matches(&self, note: UserNote) -> bool {
        self.present.load(Ordering::Acquire) && self.ident.load(Ordering::Relaxed) == note.ident
    }

    #[cfg(test)]
    fn apply(&self, note: UserNote) -> Result<(), u32> {
        self.apply_event(note, &[0; KEVENT_QOS_SIZE])
    }

    fn apply_event(&self, note: UserNote, event: &[u8; KEVENT_QOS_SIZE]) -> Result<(), u32> {
        if note.filter == EVFILT_WORKLOOP {
            if note.fflags & 0xf != 1 {
                return Err(if note.fflags & 0xf == 2 {
                    ENOTSUP
                } else {
                    EINVAL
                });
            }
            if note.ident == 0 || note.ident > IDENT_MASK {
                return Err(EINVAL);
            }
            if note.flags & EV_DELETE != 0 {
                for slot in &self.workloop_requests {
                    let value = slot.load(Ordering::Acquire);
                    if value & IDENT_MASK == note.ident {
                        let replacement = if value & LEASED != 0 {
                            note.ident | LEASED
                        } else {
                            0
                        };
                        let _ = slot.compare_exchange(
                            value,
                            replacement,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        );
                    }
                }
                return Ok(());
            }
            // Reserve a slot while publishing all nine ABI words, so a
            // consumer never observes a partially copied event. Guest
            // execution is serialized by the native scheduler gate.
            let slot = self
                .workloop_requests
                .iter()
                .position(|slot| slot.load(Ordering::Acquire) & IDENT_MASK == note.ident)
                .or_else(|| {
                    self.workloop_requests
                        .iter()
                        .position(|slot| slot.load(Ordering::Acquire) == 0)
                });
            let Some(index) = slot else {
                return Err(35);
            };
            let previous = self.workloop_requests[index].load(Ordering::Acquire);
            self.workloop_requests[index]
                .compare_exchange(previous, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| 35u32)?;
            for (i, word) in self.workloop_events[index].iter().enumerate() {
                word.store(read_u64(event, i * 8), Ordering::Relaxed);
            }
            self.workloop_requests[index].store(
                note.ident | (previous & LEASED) | if previous & LEASED != 0 { REDRIVE } else { 0 },
                Ordering::Release,
            );
            return Ok(());
        }
        if matches!(note.filter, EVFILT_MACHPORT | EVFILT_MEMORYSTATUS) {
            const CONTROL_FLAGS: u16 = EV_ADD
                | EV_DELETE
                | EV_ENABLE
                | EV_DISABLE
                | EV_RECEIPT
                | 0x0010
                | 0x0020
                | 0x0080
                | 0x0100
                | 0x0200;
            if note.flags & !CONTROL_FLAGS != 0 || note.flags & (EV_ADD | EV_DELETE) == 0 {
                return Err(EINVAL);
            }
            // Memory-pressure and workloop knotes are control objects for
            // framework event sources. This single-thread runtime cannot
            // execute host worker threads or synthesize pressure callbacks,
            // but registration and soft-delete receipts are valid and must
            // not be reported as an unsupported syscall.
            return Ok(());
        }
        let present = self.matches(note);
        let mut flags = note.flags;
        if flags & EV_DELETE != 0 {
            flags &= !EV_ADD;
        }
        if flags & EV_DISABLE != 0 {
            flags &= !EV_ENABLE;
        }

        if !present && flags & EV_ADD == 0 {
            return Err(ENOENT);
        }
        if present && flags & EV_DELETE != 0 {
            self.present.store(false, Ordering::Release);
            self.enabled.store(false, Ordering::Release);
            self.pending.store(false, Ordering::Release);
            return Ok(());
        }

        if !present {
            self.ident.store(note.ident, Ordering::Relaxed);
            self.udata.store(note.udata, Ordering::Relaxed);
            self.fflags.store(note.fflags, Ordering::Relaxed);
            self.data.store(note.data, Ordering::Relaxed);
            self.clear.store(flags & 0x0020 != 0, Ordering::Relaxed);
            self.enabled
                .store(flags & EV_DISABLE == 0, Ordering::Release);
            self.pending
                .store(note.fflags & NOTE_TRIGGER != 0, Ordering::Release);
            self.present.store(true, Ordering::Release);
            return Ok(());
        }

        self.udata.store(note.udata, Ordering::Relaxed);
        self.data.store(note.data, Ordering::Relaxed);
        let control = note.fflags & NOTE_FFCTRLMASK;
        let value = note.fflags & NOTE_FFLAGSMASK;
        let mut stored = self.fflags.load(Ordering::Relaxed);
        match control {
            NOTE_FFAND => stored &= value,
            NOTE_FFOR => stored |= value,
            NOTE_FFCOPY => stored = value,
            _ => {}
        }
        self.fflags.store(stored, Ordering::Relaxed);
        if note.fflags & NOTE_TRIGGER != 0 {
            self.pending.store(true, Ordering::Release);
        }
        if flags & EV_ENABLE != 0 {
            self.enabled.store(true, Ordering::Release);
        } else if flags & EV_DISABLE != 0 {
            self.enabled.store(false, Ordering::Release);
        }
        Ok(())
    }
}

fn copy_in_event(read: CopyIn, process: &Process, address: u64) -> Result<[u8; 72], u32> {
    let mut event = [0u8; KEVENT_QOS_SIZE];
    let error = unsafe {
        read(
            process.host_context,
            address,
            event.as_mut_ptr(),
            event.len(),
        )
    };
    (error == 0).then_some(event).ok_or(EFAULT)
}

fn copy_out_event(
    write: CopyOut,
    process: &Process,
    address: u64,
    event: &[u8; 72],
) -> Result<(), u32> {
    let error = unsafe { write(process.host_context, address, event.as_ptr(), event.len()) };
    (error == 0).then_some(()).ok_or(EFAULT)
}

fn log_rejected_event(process: &Process, event: &[u8; KEVENT_QOS_SIZE]) {
    let Some(console) = process.console else {
        return;
    };
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut message = [b' '; 2 + 24 * 3 + 1];
    message[0] = b'K';
    message[1] = b'V';
    for (index, byte) in event[..24].iter().copied().enumerate() {
        let at = 2 + index * 3;
        message[at] = HEX[(byte >> 4) as usize];
        message[at + 1] = HEX[(byte & 15) as usize];
        message[at + 2] = b' ';
    }
    message[message.len() - 1] = b'\n';
    unsafe {
        console(process.host_context, 2, message.as_ptr(), message.len());
    }
}

fn receipt(mut event: [u8; 72], error: u32) -> [u8; 72] {
    let flags = u16::from_le_bytes(event[10..12].try_into().unwrap()) | EV_ERROR;
    event[10..12].copy_from_slice(&flags.to_le_bytes());
    write_u64(&mut event, 32, error as u64);
    event
}

/// Handle the audited `kevent_qos` workqueue control path.
///
/// `Ok(count)` is the Darwin syscall result; `Err(errno)` sets BSD carry.
/// `None` leaves the call on the runtime's normal unsupported path.
pub(super) fn qos(process: &Process, frame: &TrapFrame) -> Option<Result<u64, u32>> {
    dispatch_changes(process, frame, false)
}

/// Handle dynamic workloop control through `kevent_id`.
pub(super) fn id(process: &Process, frame: &TrapFrame) -> Option<Result<u64, u32>> {
    if frame.arguments[0] == 0 {
        return Some(Err(EINVAL));
    }
    dispatch_changes(process, frame, true)
}

fn dispatch_changes(
    process: &Process,
    frame: &TrapFrame,
    workloop: bool,
) -> Option<Result<u64, u32>> {
    let (Some(read), Some(write)) = (process.copy_in, process.copy_out) else {
        return None;
    };
    let flags = frame.arguments[7] as u32;
    let required = if workloop {
        KEVENT_FLAG_WORKLOOP
    } else {
        KEVENT_FLAG_WORKQ
    };
    if flags & required == 0 || flags & !(KEVENT_FLAG_USER | KEVENT_FLAG_WORKLOOP) != 0 {
        return None;
    }
    if workloop && flags & KEVENT_FLAG_WORKQ != 0 {
        return Some(Err(EINVAL));
    }
    if !workloop && flags & KEVENT_FLAG_WORKLOOP != 0 {
        return Some(Err(EINVAL));
    }

    let nchanges = frame.arguments[2] as u32 as i32;
    let nevents = frame.arguments[4] as u32 as i32;
    if !(0..=MAX_CHANGES).contains(&nchanges) || !(0..=MAX_EVENTS).contains(&nevents) {
        return Some(Err(EINVAL));
    }
    if frame.arguments[5] != 0 || frame.arguments[6] != 0 {
        return Some(Err(ENOTSUP));
    }
    if nevents > 0 && flags & KEVENT_FLAG_ERROR_EVENTS == 0 {
        // XNU rejects event requests against the process workqueue unless the
        // caller only asked for registration receipts.
        return Some(Err(EINVAL));
    }
    if nchanges > 0 && frame.arguments[1] == 0 {
        return Some(Err(EFAULT));
    }

    let mut output_address = frame.arguments[3];
    let mut stored_error = 0;
    let mut output_count = 0;
    for index in 0..nchanges {
        let address = frame.arguments[1].wrapping_add(index as u64 * KEVENT_QOS_SIZE as u64);
        let event = match copy_in_event(read, process, address) {
            Ok(event) => event,
            Err(error) => return Some(Err(error)),
        };
        let note = match UserNote::from_bytes(&event) {
            Some(note) => note,
            None => {
                log_rejected_event(process, &event);
                return Some(Err(ENOTSUP));
            }
        };
        let apply = || {
            let command = note.fflags & 0xf;
            if note.filter != EVFILT_WORKLOOP || !matches!(command, 4 | 8) {
                return process.workqueue.apply_event(note, &event);
            }
            // XNU only permits a blocking registration as the last change,
            // with a free error-event output slot on a dynamic workloop.
            if !workloop
                || (command == 4
                    && (index + 1 != nchanges
                        || flags & KEVENT_FLAG_ERROR_EVENTS == 0
                        || output_count >= nevents))
            {
                return Err(ENOTSUP);
            }
            let waiter = process.workqueue.sync.change(
                (frame.arguments[0], note.ident),
                note.flags,
                command,
                threads::id(process),
            )?;
            if let Some(waiter) = waiter {
                workloop_sync::wait(
                    &waiter,
                    &process.stopping,
                    process.wait_leave,
                    process.wait_enter,
                )?;
            }
            Ok(())
        };
        let result = if note.filter == EVFILT_WORKLOOP && read_u64(&event, 48) != 0 {
            // XNU EV_EXTIDX_WL_ADDR/MASK/VALUE debounce: no request is
            // registered when userspace queue state has changed.
            let mut bytes = [0u8; 8];
            let addr = read_u64(&event, 48);
            let error = if !addr.is_multiple_of(8)
                || unsafe { read(process.host_context, addr, bytes.as_mut_ptr(), 8) } != 0
            {
                Some(EFAULT)
            } else if (u64::from_le_bytes(bytes) ^ read_u64(&event, 64)) & read_u64(&event, 56) != 0
            {
                Some(70) // ESTALE
            } else {
                None
            };
            match error {
                Some(70) if note.fflags & 0x100 != 0 => Ok(()),
                Some(error) => Err(error),
                None => apply(),
            }
        } else {
            apply()
        };
        if result.is_err() {
            log_rejected_event(process, &event);
        }
        let wants_receipt = note.flags & EV_RECEIPT != 0 || result.is_err();
        if wants_receipt && output_count < nevents {
            if output_address == 0 {
                return Some(Err(EFAULT));
            }
            let error = result.err().unwrap_or(0);
            if let Err(error) =
                copy_out_event(write, process, output_address, &receipt(event, error))
            {
                return Some(Err(error));
            }
            output_address = output_address.wrapping_add(KEVENT_QOS_SIZE as u64);
            output_count += 1;
        } else if let Err(error) = result {
            stored_error = error;
        }
    }
    Some(if stored_error == 0 {
        Ok(output_count as u64)
    } else {
        Err(stored_error)
    })
}

/// # Safety
/// The process is live; output points to 72 writable bytes. Consume only
/// outside guest execution while holding the native scheduler gate.
#[no_mangle]
pub unsafe extern "C" fn hm_process_pop_workloop_event(
    process: *const Process,
    output: *mut u8,
) -> bool {
    let Some(process) = process.as_ref() else {
        return false;
    };
    if output.is_null() {
        return false;
    }
    for (index, slot) in process.workqueue.workloop_requests.iter().enumerate() {
        let ident = slot.load(Ordering::Acquire);
        if ident == 0 || ident & LEASED != 0 {
            continue;
        }
        if slot
            .compare_exchange(ident, u64::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }
        let mut bytes = [0u8; KEVENT_QOS_SIZE];
        for (i, word) in process.workqueue.workloop_events[index].iter().enumerate() {
            write_u64(&mut bytes, i * 8, word.load(Ordering::Relaxed));
        }
        // Deliver the actual registered userspace-work knote, with command
        // modifiers removed. This is not a dummy event to force a callback.
        write_u64(&mut bytes, 0, ident);
        bytes[8..10].copy_from_slice(&EVFILT_WORKLOOP.to_le_bytes());
        let flags = u16::from_le_bytes(bytes[10..12].try_into().unwrap())
            & !(EV_ADD | EV_DELETE | EV_RECEIPT);
        bytes[10..12].copy_from_slice(&flags.to_le_bytes());
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
        slot.store(ident | LEASED, Ordering::Release);
        return true;
    }
    false
}

/// # Safety
/// Call while holding the guest gate after this workloop's upcall parks.
#[no_mangle]
pub unsafe extern "C" fn hm_process_finish_workloop(process: *const Process, ident: u64) {
    let Some(process) = process.as_ref() else {
        return;
    };
    for slot in &process.workqueue.workloop_requests {
        let value = slot.load(Ordering::Acquire);
        if value & IDENT_MASK == ident && value & LEASED != 0 {
            let next = if value & REDRIVE != 0 { ident } else { 0 };
            let _ = slot.compare_exchange(value, next, Ordering::AcqRel, Ordering::Acquire);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    const BASE: u64 = 0x1000;

    struct Memory(Vec<u8>);

    unsafe extern "C" fn copy_in(
        context: *const c_void,
        address: u64,
        output: *mut u8,
        size: usize,
    ) -> u32 {
        let memory = &*(context as *const Memory);
        let Ok(offset) = usize::try_from(address.wrapping_sub(BASE)) else {
            return EFAULT;
        };
        let Some(bytes) = memory.0.get(offset..offset.saturating_add(size)) else {
            return EFAULT;
        };
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, size);
        0
    }

    unsafe extern "C" fn copy_out(
        context: *const c_void,
        address: u64,
        input: *const u8,
        size: usize,
    ) -> u32 {
        let memory = &mut *(context as *mut Memory);
        let Ok(offset) = usize::try_from(address.wrapping_sub(BASE)) else {
            return EFAULT;
        };
        let Some(bytes) = memory.0.get_mut(offset..offset.saturating_add(size)) else {
            return EFAULT;
        };
        std::ptr::copy_nonoverlapping(input, bytes.as_mut_ptr(), size);
        0
    }

    fn process(memory: &mut Memory) -> Process {
        let mut process = Process::new(1, 0, 2);
        process.host_context = memory as *mut Memory as *const c_void;
        process.copy_in = Some(copy_in);
        process.copy_out = Some(copy_out);
        process
    }

    fn write_event(memory: &mut Memory, offset: usize, note: UserNote) {
        let event = &mut memory.0[offset..offset + KEVENT_QOS_SIZE];
        write_u64(event, 0, note.ident);
        event[8..10].copy_from_slice(&note.filter.to_le_bytes());
        event[10..12].copy_from_slice(&note.flags.to_le_bytes());
        write_u64(event, 16, note.udata);
        event[24..28].copy_from_slice(&note.fflags.to_le_bytes());
        write_u64(event, 32, note.data);
    }

    fn frame(changes: u64, nchanges: u64, events: u64, nevents: u64, flags: u64) -> TrapFrame {
        TrapFrame {
            number: 374,
            arguments: [
                -1i64 as u64,
                changes,
                nchanges,
                events,
                nevents,
                0,
                0,
                flags,
            ],
            ..Default::default()
        }
    }

    fn manager_note(flags: u16, fflags: u32) -> UserNote {
        UserNote {
            ident: 1,
            filter: EVFILT_USER,
            flags,
            fflags,
            data: 0,
            udata: !7,
        }
    }

    #[test]
    fn sync_wait_prepost_and_shutdown_use_dynamic_workloop_receipts() {
        let mut memory = Memory(vec![0u8; 0x300]);
        let process = process(&mut memory);
        let mut note = manager_note(EV_ADD | EV_DISABLE, 8);
        note.filter = EVFILT_WORKLOOP;
        note.ident = 0x1203;
        note.udata = 0x4000;
        write_event(&mut memory, 0, note);
        let mut trap = frame(BASE, 1, BASE + 0x100, 1, 0x403);
        trap.number = 375;
        trap.arguments[0] = 0x4000;
        assert!(process.dispatch(&mut trap)); // wake before the wait is posted
        assert_eq!(trap.result[0], 0);
        note.fflags = 4;
        write_event(&mut memory, 0, note);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0], 0);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        note.ident += 4; // a different waiter cannot consume the prepost
        write_event(&mut memory, 0, note);
        process.stopping.store(true, Ordering::Release);
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0], 1);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        assert_eq!(read_u64(&memory.0, 0x120), 4); // EINTR, not successful wake
        let flags = u16::from_le_bytes(memory.0[0x10a..0x10c].try_into().unwrap());
        assert_ne!(flags & EV_ERROR, 0);
        trap.arguments[4] = 0; // blocking register requires an error output slot
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0], u64::from(ENOTSUP));
        assert_ne!(trap.nzcv & super::super::CARRY, 0);
    }

    #[test]
    fn workloop_delivery_preserves_event_and_leases_until_park() {
        let mut memory = Memory(vec![0u8; 0x300]);
        let process = process(&mut memory);
        let mut note = manager_note(EV_ADD | EV_ENABLE, 0x111);
        note.filter = EVFILT_WORKLOOP;
        note.ident = 0x4000;
        note.udata = 0x1234;
        write_event(&mut memory, 0, note);
        memory.0[12..16].copy_from_slice(&0x800008ffu32.to_le_bytes());
        write_u64(&mut memory.0, 48, BASE + 0x200);
        write_u64(&mut memory.0, 56, 1);
        write_u64(&mut memory.0, 64, 1);
        write_u64(&mut memory.0, 0x200, 1);
        let mut trap = frame(BASE, 1, 0, 0, 0x403);
        trap.number = 375;
        trap.arguments[0] = 0x4000;
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result[0], 0);
        let mut event = [0u8; 72];
        unsafe {
            assert!(hm_process_pop_workloop_event(&process, event.as_mut_ptr()));
            assert_eq!(read_u64(&event, 0), 0x4000);
            assert_eq!(read_u64(&event, 16), 0x1234);
            assert_eq!(
                u32::from_le_bytes(event[12..16].try_into().unwrap()),
                0x800008ff
            );
            assert_eq!(u32::from_le_bytes(event[24..28].try_into().unwrap()), 1);
            assert!(!hm_process_pop_workloop_event(&process, event.as_mut_ptr()));
            // Updating an active workloop must not admit a second servicer.
            assert!(process.dispatch(&mut trap));
            assert!(!hm_process_pop_workloop_event(&process, event.as_mut_ptr()));
            hm_process_finish_workloop(&process, 0x4000);
            assert!(hm_process_pop_workloop_event(&process, event.as_mut_ptr()));
            hm_process_finish_workloop(&process, 0x4000);
            assert!(!hm_process_pop_workloop_event(&process, event.as_mut_ptr()));
            // A stale update with IGNORE_ESTALE must not enqueue work.
            write_u64(&mut memory.0, 0x200, 0);
            assert!(process.dispatch(&mut trap));
            assert_eq!(trap.result[0], 0);
            assert!(!hm_process_pop_workloop_event(&process, event.as_mut_ptr()));
            note.fflags = 1;
            write_event(&mut memory, 0, note);
            write_u64(&mut memory.0, 48, BASE + 0x200);
            write_u64(&mut memory.0, 56, 1);
            write_u64(&mut memory.0, 64, 1);
            assert!(process.dispatch(&mut trap));
            assert_eq!(trap.result[0], 70);
            assert!(!hm_process_pop_workloop_event(&process, event.as_mut_ptr()));
        }
    }

    #[test]
    fn workloop_requests_preserve_manager_and_each_other() {
        let state = State::default();
        state
            .apply(manager_note(EV_ADD | 0x20, NOTE_TRIGGER))
            .unwrap();
        let mut request = manager_note(EV_ADD, 1);
        request.filter = EVFILT_WORKLOOP;
        for ident in 2..=33 {
            request.ident = ident;
            state.apply(request).unwrap();
        }
        // Duplicate registration does not consume another slot.
        state.apply(request).unwrap();
        request.ident = 34;
        assert_eq!(state.apply(request), Err(35));
        assert_eq!(state.ident.load(Ordering::Acquire), 1);
        assert!(state.pending.load(Ordering::Acquire));
        assert!(state.clear.load(Ordering::Acquire));
        request.ident = 5;
        request.flags = EV_DELETE;
        state.apply(request).unwrap();
        request.ident = 34;
        request.flags = EV_ADD;
        state.apply(request).unwrap();
        let ids: Vec<_> = state
            .workloop_requests
            .iter()
            .map(|slot| slot.load(Ordering::Acquire))
            .collect();
        assert!(!ids.contains(&5));
        assert!(ids.contains(&2) && ids.contains(&33) && ids.contains(&34));
    }

    #[test]
    fn pop_workloop_request_cannot_consume_manager_event_or_lose_null_output() {
        let mut memory = Memory(vec![0; 0x200]);
        let process = process(&mut memory);
        process
            .workqueue
            .apply(manager_note(EV_ADD, NOTE_TRIGGER))
            .unwrap();
        let mut output = [99u8; 72];
        unsafe {
            assert!(!hm_process_pop_workloop_event(
                &process,
                output.as_mut_ptr()
            ));
            assert_eq!(output, [99; 72]);
            let mut request = manager_note(EV_ADD, 1);
            request.filter = EVFILT_WORKLOOP;
            request.ident = 42;
            process.workqueue.apply(request).unwrap();
            assert!(!hm_process_pop_workloop_event(
                &process,
                std::ptr::null_mut()
            ));
            assert!(hm_process_pop_workloop_event(&process, output.as_mut_ptr()));
            assert_eq!(read_u64(&output, 0), 42);
            assert!(!hm_process_pop_workloop_event(
                &process,
                output.as_mut_ptr()
            ));
            hm_process_finish_workloop(&process, 42);
        }
        assert!(process.workqueue.pending.load(Ordering::Acquire));
    }

    #[test]
    fn registers_the_dispatch_manager_user_event() {
        let mut memory = Memory(vec![0u8; 0x200]);
        write_event(&mut memory, 0, manager_note(EV_ADD | 0x20, 0));
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            0,
            0,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [0, 0]);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        assert!(!process.workqueue.pending.load(Ordering::Relaxed));
    }

    #[test]
    fn unknown_workloop_command_returns_an_error_receipt() {
        let mut memory = Memory(vec![0u8; 0x300]);
        let mut note = manager_note(EV_ADD | EV_ENABLE | 0x0100, 0);
        note.filter = EVFILT_WORKLOOP;
        write_event(&mut memory, 0, note);
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            BASE + 0x100,
            16,
            u64::from(KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS),
        );
        trap.number = 375;
        trap.arguments[0] = 0x607c_03c000;
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [1, 0]);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        assert_eq!(read_u64(&memory.0, 0x120), u64::from(EINVAL));
    }

    #[test]
    fn machport_control_registration_returns_without_faking_events() {
        let mut memory = Memory(vec![0u8; 0x300]);
        let mut note = manager_note(EV_ADD | EV_ENABLE | 0x0080 | 0x0100 | 0x0200, 0);
        note.filter = EVFILT_MACHPORT;
        note.ident = 3;
        write_event(&mut memory, 0, note);
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            BASE + 0x100,
            16,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [0, 0]);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        assert!(!process.workqueue.present.load(Ordering::Relaxed));
    }

    #[test]
    fn memorystatus_control_registration_returns_without_faking_events() {
        let mut memory = Memory(vec![0u8; 0x300]);
        let mut note = manager_note(EV_ADD | EV_ENABLE | 0x0080 | 0x0100, 0);
        note.filter = EVFILT_MEMORYSTATUS;
        note.ident = 0;
        write_event(&mut memory, 0, note);
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            BASE + 0x100,
            16,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [0, 0]);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        assert!(!process.workqueue.present.load(Ordering::Relaxed));
    }

    #[test]
    fn workloop_control_registration_returns_a_receipt_without_faking_events() {
        let mut memory = Memory(vec![0u8; 0x300]);
        let mut note = manager_note(EV_RECEIPT | EV_ADD | EV_DELETE | EV_ENABLE, 0x21);
        note.filter = EVFILT_WORKLOOP;
        write_event(&mut memory, 0, note);
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            BASE + 0x100,
            1,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [1, 0]);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        let flags = u16::from_le_bytes(memory.0[0x10a..0x10c].try_into().unwrap());
        assert_ne!(flags & EV_ERROR, 0);
        assert_eq!(read_u64(&memory.0, 0x120), 0);
        assert!(!process.workqueue.present.load(Ordering::Relaxed));
    }

    #[test]
    fn trigger_updates_the_registered_event_and_clear_receipt_is_copied_out() {
        let mut memory = Memory(vec![0u8; 0x400]);
        let mut note = manager_note(EV_ADD | 0x20, 0);
        write_event(&mut memory, 0, note);
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            0,
            0,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE),
        );
        assert!(process.dispatch(&mut trap));

        note.flags = EV_RECEIPT;
        note.fflags = NOTE_TRIGGER;
        write_event(&mut memory, 0x100, note);
        let mut trap = frame(
            BASE + 0x100,
            1,
            BASE + 0x200,
            1,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [1, 0]);
        assert_eq!(trap.nzcv & super::super::CARRY, 0);
        assert!(process.workqueue.pending.load(Ordering::Relaxed));
        let flags = u16::from_le_bytes(memory.0[0x20a..0x20c].try_into().unwrap());
        assert_ne!(flags & EV_ERROR, 0);
        assert_eq!(read_u64(&memory.0, 0x220), 0);
    }

    #[test]
    fn absent_delete_faults_and_ordinary_polling_remains_unsupported() {
        let mut memory = Memory(vec![0u8; 0x200]);
        write_event(&mut memory, 0, manager_note(EV_DELETE, 0));
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            0,
            0,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [ENOENT as u64, 0]);
        assert_ne!(trap.nzcv & super::super::CARRY, 0);

        let mut trap = frame(
            BASE,
            0,
            BASE + 0x100,
            1,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [EINVAL as u64, 0]);
    }

    #[test]
    fn backend_failures_are_receipts_when_output_space_exists() {
        let mut memory = Memory(vec![0u8; 0x300]);
        write_event(&mut memory, 0, manager_note(EV_RECEIPT | EV_DELETE, 0));
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            BASE + 0x100,
            1,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [1, 0]);
        let flags = u16::from_le_bytes(memory.0[0x10a..0x10c].try_into().unwrap());
        assert_ne!(flags & EV_ERROR, 0);
        assert_eq!(read_u64(&memory.0, 0x120), ENOENT as u64);
    }

    #[test]
    fn non_user_filters_and_data_buffers_stay_outside_the_boundary() {
        let mut memory = Memory(vec![0u8; 0x300]);
        let mut note = manager_note(EV_ADD, 0);
        note.ident = 7;
        write_event(&mut memory, 0, note);
        memory.0[8..10].copy_from_slice(&(-7i16).to_le_bytes());
        let process = process(&mut memory);
        let mut trap = frame(
            BASE,
            1,
            0,
            0,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE),
        );
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [ENOTSUP as u64, 0]);

        write_event(&mut memory, 0, manager_note(EV_ADD, 0));
        let mut trap = frame(
            BASE,
            1,
            0,
            0,
            u64::from(KEVENT_FLAG_WORKQ | KEVENT_FLAG_IMMEDIATE),
        );
        trap.arguments[5] = BASE + 0x100;
        trap.arguments[6] = BASE + 0x108;
        assert!(process.dispatch(&mut trap));
        assert_eq!(trap.result, [ENOTSUP as u64, 0]);
    }
}
