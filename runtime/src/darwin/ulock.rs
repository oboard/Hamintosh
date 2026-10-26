//! Darwin user locks (__ulock_wait/__ulock_wake) with real blocking.
//!
//! Guest threads execute on host threads inside the syscall trap, so a wait
//! blocks the calling host thread on a process-local waiter table while
//! other guest threads keep running and eventually wake it. This module is
//! the deliberate exception to the allocation-free, lock-free dispatch rule:
//! correctness of a blocked guest thread requires a host condvar here.
//!
//! Semantics follow XNU sys_ulock.c: a mismatched comparison value returns
//! success immediately, a successful wait returns the number of remaining
//! waiters on the same address, an empty wake returns ENOENT, and
//! ULF_NO_ERRNO reports errors as a negative return value without carry.

use super::{CopyIn, TrapFrame};
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::{Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

const EFAULT: u32 = 14;
const EINVAL: u32 = 22;
const ENOENT: u32 = 2;
const ESRCH: u32 = 3;
const ETIMEDOUT: u32 = 60;

const UL_OPCODE_MASK: u32 = 0xff;
const UL_COMPARE_AND_WAIT: u32 = 1;
const UL_UNFAIR_LOCK: u32 = 2;
const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
const UL_UNFAIR_LOCK64_SHARED: u32 = 4;
const UL_COMPARE_AND_WAIT64: u32 = 5;
const UL_COMPARE_AND_WAIT64_SHARED: u32 = 6;

const ULF_WAKE_ALL: u32 = 0x100;
const ULF_WAKE_THREAD: u32 = 0x200;
const ULF_WAKE_ALLOW_NON_OWNER: u32 = 0x400;
const ULF_WAKE_MASK: u32 = 0x0000_0700 | ULF_GENERIC_MASK;
const ULF_WAIT_MASK: u32 = 0x0007_0000 | ULF_GENERIC_MASK;
const ULF_NO_ERRNO: u32 = 0x0100_0000;
const ULF_GENERIC_MASK: u32 = 0xffff_0000;

/// A single blocked guest thread. Wake one pops one slot; wake all drains.
struct Slot {
    woken: Mutex<bool>,
    cond: Condvar,
}

type Key = (usize, u64);

static WAITERS: Mutex<Option<HashMap<Key, Vec<Weak<Slot>>>>> = Mutex::new(None);

fn with_table<R>(f: impl FnOnce(&mut HashMap<Key, Vec<Weak<Slot>>>) -> R) -> R {
    let mut guard = WAITERS.lock().unwrap_or_else(|error| error.into_inner());
    if guard.is_none() {
        *guard = Some(HashMap::new());
    }
    f(guard.as_mut().unwrap())
}

fn lock_size(opcode: u32) -> Option<usize> {
    match opcode {
        UL_COMPARE_AND_WAIT | UL_UNFAIR_LOCK | UL_COMPARE_AND_WAIT_SHARED => Some(4),
        UL_COMPARE_AND_WAIT64 | UL_UNFAIR_LOCK64_SHARED | UL_COMPARE_AND_WAIT64_SHARED => Some(8),
        _ => None,
    }
}

fn read_lock_value(
    copy_in: Option<CopyIn>,
    context: *const c_void,
    address: u64,
    size: usize,
) -> Result<u64, u32> {
    let Some(read) = copy_in else {
        return Err(EFAULT);
    };
    let mut bytes = [0u8; 8];
    let error = unsafe { read(context, address, bytes.as_mut_ptr(), size) };
    if error != 0 {
        return Err(EFAULT);
    }
    Ok(match size {
        4 => u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64,
        _ => u64::from_le_bytes(bytes),
    })
}

/// Returns the guest-visible result: Ok(remaining waiters) or Err(errno).
pub(super) fn wait(
    copy_in: Option<CopyIn>,
    context: *const c_void,
    owner: usize,
    frame: &TrapFrame,
) -> Result<u64, u32> {
    let operation = frame.arguments[0] as u32;
    let address = frame.arguments[1];
    let expected = frame.arguments[2];
    let timeout_micros = frame.arguments[3] as u32;
    let opcode = operation & UL_OPCODE_MASK;
    let flags = operation & !UL_OPCODE_MASK;
    if flags & !ULF_WAIT_MASK != 0 {
        return Err(EINVAL);
    }
    let Some(size) = lock_size(opcode) else {
        return Err(EINVAL);
    };
    if address == 0 || !address.is_multiple_of(size as u64) {
        return Err(EFAULT);
    }
    let key = (owner, address);
    let slot = std::sync::Arc::new(Slot {
        woken: Mutex::new(false),
        cond: Condvar::new(),
    });
    // Register before comparing so a concurrent wake cannot be lost between
    // the value check and the block.
    with_table(|table| {
        let list = table.entry(key).or_default();
        list.retain(|weak| weak.strong_count() > 0);
        list.push(std::sync::Arc::downgrade(&slot));
    });
    // Remove this slot and report the remaining waiter count. Never touches
    // the slot's own lock, so it cannot deadlock against a waker.
    let finish = |result: Result<u64, u32>| -> Result<u64, u32> {
        let remaining = with_table(|table| {
            if let Some(list) = table.get_mut(&key) {
                list.retain(|weak| {
                    weak.upgrade()
                        .map(|live| !std::sync::Arc::ptr_eq(&live, &slot))
                        .unwrap_or(false)
                });
                let remaining = list.len();
                if list.is_empty() {
                    table.remove(&key);
                }
                remaining
            } else {
                0
            }
        });
        result.map(|_| remaining as u64)
    };
    match read_lock_value(copy_in, context, address, size) {
        Err(error) => return finish(Err(error)),
        Ok(value) if value != expected => return finish(Ok(0)),
        _ => {}
    }
    let mut woken = slot.woken.lock().unwrap_or_else(|error| error.into_inner());
    let deadline = if timeout_micros == 0 {
        None
    } else {
        Some(Instant::now() + Duration::from_micros(timeout_micros as u64))
    };
    loop {
        if *woken {
            drop(woken);
            return finish(Ok(0));
        }
        match deadline {
            None => {
                woken = slot.cond.wait(woken).unwrap_or_else(|error| error.into_inner());
            }
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    drop(woken);
                    return finish(Err(ETIMEDOUT));
                }
                let (guard, _) = slot
                    .cond
                    .wait_timeout(woken, deadline - now)
                    .unwrap_or_else(|error| error.into_inner());
                woken = guard;
            }
        }
    }
}

pub(super) fn wake(owner: usize, frame: &TrapFrame) -> Result<u64, u32> {
    let operation = frame.arguments[0] as u32;
    let address = frame.arguments[1];
    let opcode = operation & UL_OPCODE_MASK;
    let flags = operation & !UL_OPCODE_MASK;
    if lock_size(opcode).is_none() {
        return Err(EINVAL);
    }
    if flags & !ULF_WAKE_MASK != 0 {
        return Err(EINVAL);
    }
    if flags & ULF_WAKE_THREAD != 0 && (flags & ULF_WAKE_ALL != 0 || opcode == UL_UNFAIR_LOCK) {
        return Err(EINVAL);
    }
    if flags & ULF_WAKE_ALLOW_NON_OWNER != 0 && opcode != UL_UNFAIR_LOCK {
        return Err(EINVAL);
    }
    if address == 0 {
        return Err(EINVAL);
    }
    // Waking a specific guest thread needs Mach thread ports, which this
    // kernel does not model for guest threads.
    if flags & ULF_WAKE_THREAD != 0 {
        return Err(ESRCH);
    }
    let key = (owner, address);
    // Phase 1: detach the target slots under the table lock only.
    let detached = with_table(|table| -> Result<Vec<std::sync::Arc<Slot>>, u32> {
        let Some(list) = table.get_mut(&key) else {
            return Err(ENOENT);
        };
        list.retain(|weak| weak.strong_count() > 0);
        if list.is_empty() {
            table.remove(&key);
            return Err(ENOENT);
        }
        if flags & ULF_WAKE_ALL != 0 {
            let all: Vec<_> = list.iter().filter_map(Weak::upgrade).collect();
            table.remove(&key);
            Ok(all)
        } else {
            match list.first().and_then(Weak::upgrade) {
                Some(slot) => {
                    list.remove(0);
                    if list.is_empty() {
                        table.remove(&key);
                    }
                    Ok(vec![slot])
                }
                None => {
                    table.remove(&key);
                    Err(ENOENT)
                }
            }
        }
    })?;
    // Phase 2: wake outside the table lock; waiters finish by touching the
    // table, so locking in the other order here would deadlock.
    for slot in &detached {
        *slot.woken.lock().unwrap_or_else(|error| error.into_inner()) = true;
        slot.cond.notify_all();
    }
    Ok(0)
}

/// Maps a lock result onto the BSD carry/errno convention used by dispatch.
pub(super) fn apply(frame: &mut TrapFrame, result: Result<u64, u32>, carry: u64) {
    let no_errno = frame.arguments[0] as u32 & ULF_NO_ERRNO != 0;
    match result {
        Ok(value) => {
            frame.result = [value, 0];
            frame.nzcv &= !carry;
        }
        Err(error) if no_errno => {
            frame.result = [(-(error as i64)) as u64, 0];
            frame.nzcv &= !carry;
        }
        Err(error) => {
            frame.result = [error as u64, 0];
            frame.nzcv |= carry;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    unsafe extern "C" fn memcpy_in(
        _context: *const c_void,
        address: u64,
        out: *mut u8,
        size: usize,
    ) -> u32 {
        unsafe { std::ptr::copy_nonoverlapping(address as *const u8, out, size) };
        0
    }

    unsafe extern "C" fn failing_in(
        _context: *const c_void,
        _address: u64,
        _out: *mut u8,
        _size: usize,
    ) -> u32 {
        1
    }

    fn frame(number: i64, operation: u32, address: u64, value: u64, extra: u64) -> TrapFrame {
        TrapFrame {
            number,
            arguments: [operation as u64, address, value, extra, 0, 0, 0, 0],
            ..Default::default()
        }
    }

    #[test]
    fn mismatched_value_returns_success_without_blocking() {
        static LOCK: AtomicU32 = AtomicU32::new(0xaaaa);
        let owner = &LOCK as *const _ as usize;
        let frame = frame(515, UL_COMPARE_AND_WAIT, &LOCK as *const _ as u64, 0xbbbb, 0);
        assert_eq!(wait(Some(memcpy_in), std::ptr::null(), owner, &frame), Ok(0));
    }

    #[test]
    fn faulting_address_reports_efault_and_bad_operations_are_rejected() {
        static LOCK: AtomicU32 = AtomicU32::new(1);
        let owner = &LOCK as *const _ as usize;
        let address = &LOCK as *const _ as u64;
        let bad_read = frame(515, UL_COMPARE_AND_WAIT, address, 1, 0);
        assert_eq!(
            wait(Some(failing_in), std::ptr::null(), owner, &bad_read),
            Err(EFAULT)
        );
        let bad_opcode = frame(515, 42, address, 1, 0);
        assert_eq!(
            wait(Some(memcpy_in), std::ptr::null(), owner, &bad_opcode),
            Err(EINVAL)
        );
        // Bits 8-15 hold wake-only flags and are invalid in a wait.
        let bad_flags = frame(515, UL_COMPARE_AND_WAIT | 0x0000_0100, address, 1, 0);
        assert_eq!(
            wait(Some(memcpy_in), std::ptr::null(), owner, &bad_flags),
            Err(EINVAL)
        );
        let misaligned = frame(515, UL_COMPARE_AND_WAIT, address + 1, 1, 0);
        assert_eq!(
            wait(Some(memcpy_in), std::ptr::null(), owner, &misaligned),
            Err(EFAULT)
        );
    }

    #[test]
    fn timed_wait_expires_with_etimedout() {
        static LOCK: AtomicU32 = AtomicU32::new(7);
        let owner = &LOCK as *const _ as usize;
        let frame = frame(515, UL_COMPARE_AND_WAIT, &LOCK as *const _ as u64, 7, 5_000);
        let started = Instant::now();
        assert_eq!(
            wait(Some(memcpy_in), std::ptr::null(), owner, &frame),
            Err(ETIMEDOUT)
        );
        assert!(started.elapsed() >= Duration::from_millis(5));
    }

    #[test]
    fn blocked_waiter_wakes_after_value_change_and_wake() {
        static LOCK: AtomicU32 = AtomicU32::new(0);
        let owner = &LOCK as *const _ as usize;
        let address = &LOCK as *const _ as u64;
        let waiter = std::thread::spawn(move || {
            let frame = frame(515, UL_COMPARE_AND_WAIT, address, 0, 0);
            wait(Some(memcpy_in), std::ptr::null(), owner, &frame)
        });
        std::thread::sleep(Duration::from_millis(50));
        LOCK.store(1, Ordering::SeqCst);
        let wake_frame = frame(516, UL_COMPARE_AND_WAIT, address, 0, 0);
        assert_eq!(wake(owner, &wake_frame), Ok(0));
        assert_eq!(waiter.join().unwrap(), Ok(0));
        // The lock was consumed by the wake; waking again finds no waiters.
        assert_eq!(wake(owner, &wake_frame), Err(ENOENT));
    }

    #[test]
    fn wake_all_releases_every_waiter() {
        static LOCK: AtomicU32 = AtomicU32::new(3);
        let owner = &LOCK as *const _ as usize;
        let address = &LOCK as *const _ as u64;
        let waiters: Vec<_> = (0..2)
            .map(|_| {
                std::thread::spawn(move || {
                    let frame = frame(515, UL_COMPARE_AND_WAIT, address, 3, 0);
                    wait(Some(memcpy_in), std::ptr::null(), owner, &frame)
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(50));
        LOCK.store(0, Ordering::SeqCst);
        let wake_all = frame(516, UL_COMPARE_AND_WAIT | ULF_WAKE_ALL, address, 0, 0);
        assert!(wake(owner, &wake_all).is_ok());
        for waiter in waiters {
            assert!(waiter.join().unwrap().is_ok());
        }
    }

    #[test]
    fn wake_validates_flag_combinations_and_empty_table() {
        static LOCK: AtomicU32 = AtomicU32::new(0);
        let owner = &LOCK as *const _ as usize;
        let address = &LOCK as *const _ as u64;
        assert_eq!(
            wake(owner, &frame(516, UL_COMPARE_AND_WAIT, 0, 0, 0)),
            Err(EINVAL)
        );
        assert_eq!(
            wake(owner, &frame(516, UL_COMPARE_AND_WAIT, address, 0, 0)),
            Err(ENOENT)
        );
        assert_eq!(
            wake(
                owner,
                &frame(516, UL_COMPARE_AND_WAIT | ULF_WAKE_ALLOW_NON_OWNER, address, 0, 0)
            ),
            Err(EINVAL)
        );
        assert_eq!(
            wake(
                owner,
                &frame(516, UL_COMPARE_AND_WAIT | ULF_WAKE_ALL | ULF_WAKE_THREAD, address, 0, 0)
            ),
            Err(EINVAL)
        );
        assert_eq!(
            wake(owner, &frame(516, 77, address, 0, 0)),
            Err(EINVAL)
        );
    }

    #[test]
    fn no_errno_reports_negative_values_without_carry() {
        let mut no_errno_frame = frame(515, UL_COMPARE_AND_WAIT | ULF_NO_ERRNO, 0, 0, 0);
        no_errno_frame.nzcv = 0;
        ulock_result_apply(&mut no_errno_frame, Err(EINVAL));
        assert_eq!(no_errno_frame.result[0], (-(EINVAL as i64)) as u64);
        assert_eq!(no_errno_frame.nzcv & TEST_CARRY, 0);
        let mut errno_frame = frame(515, UL_COMPARE_AND_WAIT, 0, 0, 0);
        errno_frame.nzcv = 0;
        ulock_result_apply(&mut errno_frame, Err(EINVAL));
        assert_eq!(errno_frame.result[0], EINVAL as u64);
        assert_eq!(errno_frame.nzcv & TEST_CARRY, TEST_CARRY);
    }

    const TEST_CARRY: u64 = 1 << 29;

    fn ulock_result_apply(frame: &mut TrapFrame, result: Result<u64, u32>) {
        apply(frame, result, TEST_CARRY);
    }
}
