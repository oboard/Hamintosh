//! Voucher activity-ID ranges shared by the compatibility-kernel instance.
use super::{Process, TrapFrame};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);

fn reserve(counter: &AtomicU64, count: i32) -> Result<u64, u32> {
    if !(1..=16).contains(&count) {
        return Err(4); // KERN_INVALID_ARGUMENT / MACH_ACTIVITY_ID_COUNT_MAX
    }
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(count as u64)
        })
        .map_err(|_| 6)
}

pub(super) fn generate(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let write = process.copy_out?;
    let start = match reserve(&NEXT, frame.arguments[1] as u32 as i32) {
        Ok(start) => start,
        Err(error) => return Some(error),
    };
    // XNU reserves the whole range before copyout, even on a copyout error.
    // Its target argument is unused. Return only the first ID, not count IDs.
    Some(unsafe {
        write(
            process.host_context,
            frame.arguments[2],
            start.to_le_bytes().as_ptr(),
            8,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activity_ranges_are_nonoverlapping_bounded_and_never_wrap() {
        let counter = AtomicU64::new(1);
        assert_eq!(reserve(&counter, 1), Ok(1));
        assert_eq!(reserve(&counter, 16), Ok(2));
        assert_eq!(reserve(&counter, 3), Ok(18));
        for count in [-1, 0, 17, i32::MAX] {
            assert_eq!(reserve(&counter, count), Err(4));
        }
        assert_eq!(counter.load(Ordering::Relaxed), 21);
        counter.store(u64::MAX - 1, Ordering::Relaxed);
        assert_eq!(reserve(&counter, 2), Err(6));
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX - 1);
        assert_eq!(reserve(&counter, 1), Ok(u64::MAX - 1));
        assert_eq!(reserve(&counter, 1), Err(6));
    }
    #[test]
    fn activity_trap_copies_one_id_and_propagates_copyout_failure() {
        unsafe extern "C" fn write(
            context: *const std::ffi::c_void,
            address: u64,
            data: *const u8,
            size: usize,
        ) -> u32 {
            if address != 32 || size != 8 {
                return 14;
            }
            std::ptr::copy_nonoverlapping(data, context as *mut u8, size);
            0
        }
        let mut process = Process::new(42, 1, 99);
        let mut memory = [0u8; 8];
        process.copy_out = Some(write);
        process.host_context = memory.as_mut_ptr().cast();
        let mut frame = TrapFrame {
            number: -43,
            arguments: [0x103, 16, 32, 0, 0, 0, 0, 0],
            ..Default::default()
        };
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        let first = u64::from_le_bytes(memory);
        assert!(first > 0);
        frame.arguments[2] = 33;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 14);
        assert_eq!(u64::from_le_bytes(memory), first);
        frame.arguments[2] = 32;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 0);
        assert!(u64::from_le_bytes(memory) >= first + 32);
        frame.arguments[1] = 17;
        assert!(process.dispatch(&mut frame));
        assert_eq!(frame.result[0], 4);
    }
}
