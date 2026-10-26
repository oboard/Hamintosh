//! Darwin thread masks are guest state, independent of the host's trap transport.
use super::{Ordering, Process, TrapFrame};
const CANNOT_MASK: u32 = (1 << (9 - 1)) | (1 << (17 - 1)); // Darwin SIGKILL/SIGSTOP

fn update(mask: &std::sync::atomic::AtomicU32, how: u32, set: u32) -> Result<u32, u32> {
    let set = set & !CANNOT_MASK;
    match how {
        1 => Ok(mask.fetch_or(set, Ordering::AcqRel)),
        2 => Ok(mask.fetch_and(!set, Ordering::AcqRel)),
        3 => Ok(mask.swap(set, Ordering::AcqRel)),
        _ => Err(22),
    }
}

pub(super) fn mask(process: &Process, frame: &TrapFrame) -> Option<u32> {
    let old = if frame.arguments[1] == 0 {
        super::threads::mask(process).unwrap_or_else(|| process.signal_mask.load(Ordering::Acquire))
    } else {
        let read = process.copy_in?;
        let mut bytes = [0u8; 4];
        if unsafe {
            read(
                process.host_context,
                frame.arguments[1],
                bytes.as_mut_ptr(),
                bytes.len(),
            )
        } != 0
        {
            return Some(14);
        }
        let thread_mask = super::threads::mask(process);
        let local = std::sync::atomic::AtomicU32::new(thread_mask.unwrap_or(0));
        let target = if thread_mask.is_some() {
            &local
        } else {
            &process.signal_mask
        };
        match update(target, frame.arguments[0] as u32, u32::from_le_bytes(bytes)) {
            Ok(old) => {
                if thread_mask.is_some() {
                    super::threads::set_mask(process, local.load(Ordering::Acquire));
                }
                old
            }
            Err(error) => return Some(error),
        }
    };
    if frame.arguments[2] != 0 {
        let write = process.copy_out?;
        let bytes = old.to_le_bytes();
        if unsafe {
            write(
                process.host_context,
                frame.arguments[2],
                bytes.as_ptr(),
                bytes.len(),
            )
        } != 0
        {
            return Some(14);
        }
    }
    Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn block_unblock_and_replace_preserve_unmaskable_signals() {
        let mask = std::sync::atomic::AtomicU32::new(0);
        assert_eq!(update(&mask, 1, u32::MAX), Ok(0));
        assert_eq!(mask.load(Ordering::Relaxed), !CANNOT_MASK);
        assert_eq!(update(&mask, 2, 1), Ok(!CANNOT_MASK));
        assert_eq!(mask.load(Ordering::Relaxed) & 1, 0);
        assert!(update(&mask, 3, 4).is_ok());
        assert_eq!(update(&mask, 0, 1), Err(22));
        assert_eq!(mask.load(Ordering::Relaxed), 4);
    }
}
