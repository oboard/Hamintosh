//! Darwin semaphore waits in the current single-guest-thread model.
//!
//! A timed wait cannot observe a signal from another guest thread because no
//! such thread can execute while the only guest thread is blocked. Returning
//! the kernel's real timeout result lets libpthread take its normal timed-wait
//! path. Untimed waits remain unsupported rather than pretending to block.

use super::TrapFrame;

const EINVAL: u32 = 22;
const ETIMEDOUT: u32 = 60;

pub(super) fn semwait(frame: &TrapFrame) -> Option<u32> {
    let timeout = frame.arguments[2];
    let relative = frame.arguments[3];
    let seconds = frame.arguments[4];
    let nanoseconds = frame.arguments[5];
    if !matches!(relative, 0 | 1) || nanoseconds >= 1_000_000_000 {
        return Some(EINVAL);
    }
    // An untimed wait has no observable completion in the single-threaded
    // compatibility model. Leave it on the existing ENOSYS path.
    if timeout == 0 {
        return None;
    }
    if timeout != 1 || seconds > i64::MAX as u64 {
        return Some(EINVAL);
    }
    Some(ETIMEDOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(timeout: u64, relative: u64, seconds: u64, nanoseconds: u64) -> TrapFrame {
        TrapFrame {
            number: 423,
            arguments: [2563, 0, timeout, relative, seconds, nanoseconds, 0, 0],
            ..Default::default()
        }
    }

    #[test]
    fn timed_wait_returns_etimedout_and_malformed_values_are_rejected() {
        assert_eq!(semwait(&frame(1, 1, 0, 10_000_000)), Some(ETIMEDOUT));
        assert_eq!(semwait(&frame(1, 0, 2, 0)), Some(ETIMEDOUT));
        for args in [(2, 1, 0, 0), (1, 2, 0, 0), (1, 1, 0, 1_000_000_000)] {
            assert_eq!(
                semwait(&frame(args.0, args.1, args.2, args.3)),
                Some(EINVAL)
            );
        }
        assert_eq!(semwait(&frame(0, 1, 0, 0)), None);
    }
}
