//! Restartable regions for the current single-guest-thread process model.
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub(crate) struct Ranges {
    count: AtomicU32,
    entries: [[AtomicU64; 2]; 64],
}

impl Default for Ranges {
    fn default() -> Self {
        Self {
            count: AtomicU32::new(0),
            entries: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
        }
    }
}

impl Ranges {
    pub(crate) fn register(&self, bytes: &[u8]) -> u32 {
        if bytes.is_empty() || !bytes.len().is_multiple_of(16) {
            return 4;
        }
        let old = self.count.load(Ordering::Acquire);
        let added = bytes.len() / 16;
        if old == u32::MAX {
            return 5;
        }
        let total = added;
        if total > 64 {
            return 3;
        }
        let mut entries = [[0u64; 2]; 64];
        for (out, raw) in entries[..total].iter_mut().zip(bytes.chunks_exact(16)) {
            out[0] = u64::from_le_bytes(raw[..8].try_into().unwrap());
            out[1] = u64::from_le_bytes(raw[8..].try_into().unwrap());
        }
        entries[..total].sort_unstable_by_key(|r| (r[0], r[1] as u16));
        for (index, entry) in entries[..total].iter().enumerate() {
            let length = entry[1] & 0xffff;
            let recovery = (entry[1] >> 16) & 0xffff;
            let Some(end) = entry[0].checked_add(length) else {
                return 4;
            };
            if length > 0x1000
                || recovery > 0x1000
                || entry[1] >> 32 != 0
                || entry[0].checked_add(recovery).is_none()
                || (index + 1 < total && end > entries[index + 1][0])
            {
                return 4;
            }
        }
        // Match a release XNU task: registration is allowed only once.
        if old != 0 {
            return 46;
        }
        if self
            .count
            .compare_exchange(old, u32::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return 5;
        }
        for (stored, entry) in self.entries.iter().zip(&entries).take(total) {
            stored[0].store(entry[0], Ordering::Relaxed);
            stored[1].store(entry[1], Ordering::Relaxed);
        }
        self.count.store(total as u32, Ordering::Release);
        0
    }

    pub(super) fn resume_pc(&self, pc: u64) -> u64 {
        let count = self.count.load(Ordering::Acquire);
        if count > 64 {
            return pc;
        }
        for entry in self.entries.iter().take(count as usize) {
            let start = entry[0].load(Ordering::Relaxed);
            let offsets = entry[1].load(Ordering::Relaxed);
            if start < pc && pc - start < offsets & 0xffff {
                return start + ((offsets >> 16) & 0xffff);
            }
        }
        pc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode(entries: &[[u64; 2]]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|e| e.iter().flat_map(|v| v.to_le_bytes()))
            .collect()
    }
    #[test]
    fn registration_recovers_only_strictly_inside_and_rejects_reregistration() {
        let ranges = Ranges::default();
        assert_eq!(
            ranges.register(&encode(&[
                [0x2000, (16 << 16) | 12],
                [0x1000, (8 << 16) | 8]
            ])),
            0
        );
        for (pc, expected) in [
            (0xfff, 0xfff),
            (0x1000, 0x1000),
            (0x1004, 0x1008),
            (0x1008, 0x1008),
            (0x2004, 0x2010),
            (0x200c, 0x200c),
        ] {
            assert_eq!(ranges.resume_pc(pc), expected);
        }
        assert_eq!(ranges.register(&encode(&[[0x1004, 4]])), 46);
        assert_eq!(ranges.resume_pc(0x1004), 0x1008);
        assert_eq!(ranges.register(&encode(&[[0x3000, (4 << 16) | 4]])), 46);
        assert_eq!(ranges.resume_pc(0x3002), 0x3002);
    }
    #[test]
    fn malformed_overflowing_and_excessive_registrations_leave_state_unchanged() {
        let ranges = Ranges::default();
        for entries in [
            vec![[u64::MAX, 1]],
            vec![[u64::MAX - 4, 8 << 16]],
            vec![[0x1000, 0x1001]],
            vec![[0x1000, 1 << 32]],
            vec![[0x1000, 1]; 65],
        ] {
            assert_ne!(ranges.register(&encode(&entries)), 0);
        }
        assert_eq!(ranges.register(&[0; 15]), 4);
        assert_eq!(ranges.register(&[]), 4);
        assert_eq!(ranges.resume_pc(0x1004), 0x1004);
        assert_eq!(ranges.register(&encode(&[[0x1000, (8 << 16) | 8]])), 0);
        assert_eq!(ranges.resume_pc(0x1004), 0x1008);
        let boundary = Ranges::default();
        assert_eq!(
            boundary.register(&encode(&[[0x1000, (0x1000 << 16) | 0x1000]])),
            0
        );
        assert_eq!(boundary.resume_pc(0x1fff), 0x2000);
    }
}
