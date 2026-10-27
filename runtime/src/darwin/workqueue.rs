//! Bounded outstanding ordinary libdispatch root-queue thread requests.
use super::Process;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub(crate) struct State {
    requests: [AtomicU64; 32],
}

impl State {
    pub(super) fn request(&self, count: u32, priority: u32) -> Result<(), u32> {
        // XNU workq_reqthreads: nonzero uint16 count and a valid thread QoS.
        if count == 0
            || count > u16::MAX.into()
            || priority & 0x3f00 == 0
            || priority & 0x2200_0000 != 0
        {
            return Err(22);
        }
        for slot in &self.requests {
            let mut old = slot.load(Ordering::Acquire);
            loop {
                if old != 0 && (old >> 32) as u32 != priority {
                    break;
                }
                let total = (old as u32)
                    .checked_add(count)
                    .filter(|n| *n <= u16::MAX.into())
                    .ok_or(35u32)?;
                let new = (u64::from(priority) << 32) | u64::from(total);
                match slot.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Ok(()),
                    Err(actual) => old = actual,
                }
            }
        }
        Err(35)
    }

    fn pop(&self) -> Option<u32> {
        for slot in &self.requests {
            let mut old = slot.load(Ordering::Acquire);
            while old != 0 {
                let new = if old as u32 == 1 { 0 } else { old - 1 };
                match slot.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => return Some((old >> 32) as u32),
                    Err(actual) => old = actual,
                }
            }
        }
        None
    }
}

/// # Safety
/// `process` is live and `priority` points to writable u32 storage. Call while
/// holding the native guest execution gate; one pop admits one real upcall.
#[no_mangle]
pub unsafe extern "C" fn hm_process_pop_root_thread(
    process: *const Process,
    priority: *mut u32,
) -> bool {
    let Some(process) = process.as_ref() else {
        return false;
    };
    if priority.is_null() {
        return false;
    }
    if let Some(value) = process.root_threads.pop() {
        *priority = value;
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_and_priorities_are_preserved_and_invalid_requests_are_atomic() {
        let state = State::default();
        for (count, priority) in [(0, 0x8ff), (65536, 0x8ff), (1, 0), (1, 0x220008ff)] {
            assert_eq!(state.request(count, priority), Err(22));
        }
        assert_eq!(state.pop(), None);
        state.request(2, 0x40008ff).unwrap();
        state.request(1, 0x40008ff).unwrap();
        state.request(1, 0x800020ff).unwrap();
        assert_eq!(state.pop(), Some(0x40008ff));
        assert_eq!(state.pop(), Some(0x40008ff));
        assert_eq!(state.pop(), Some(0x40008ff));
        assert_eq!(state.pop(), Some(0x800020ff));
        assert_eq!(state.pop(), None);
        state.request(65535, 0x8ff).unwrap();
        assert_eq!(state.request(1, 0x8ff), Err(35));
        for _ in 0..65535 {
            assert_eq!(state.pop(), Some(0x8ff));
        }
        assert_eq!(state.pop(), None);
    }
    #[test]
    fn null_output_cannot_discard_an_admitted_request() {
        let process = Process::new(1, 0, 2);
        process.root_threads.request(1, 0x8ff).unwrap();
        unsafe {
            assert!(!hm_process_pop_root_thread(&process, std::ptr::null_mut()));
        }
        let mut priority = 0;
        unsafe {
            assert!(hm_process_pop_root_thread(&process, &mut priority));
        }
        assert_eq!(priority, 0x8ff);
    }
}
