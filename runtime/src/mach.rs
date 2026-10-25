//! Per-process Mach names and rights. Fixed storage keeps trap-time allocation
//! independent of the host allocator and signal-unsafe locks.
use std::sync::atomic::{AtomicU64, Ordering};

const GENERATION: u64 = 3;
const RECEIVE: u64 = 1 << 8;
const REPLY: u64 = 1 << 9;
const KERNEL: u64 = 1 << 15;
const SEND_ONE: u64 = 1 << 16;
const CAPACITY: usize = 256;

pub struct Space {
    slots: [AtomicU64; CAPACITY],
}

impl Default for Space {
    fn default() -> Self {
        let space = Self {
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
        };
        // Kernel-backed objects are available before the first self trap.
        // Each self trap creates a new user reference to its send right.
        for slot in &space.slots[..3] {
            slot.store(GENERATION | KERNEL, Ordering::Relaxed);
        }
        space
    }
}

impl Space {
    /// Construct an ordinary or reply receive right, optionally with one send
    /// user ref for ordinary ports. Retain the reply designation for IPC.
    /// Guarding, typed ports and message queue options need separate semantics.
    pub fn construct(&self, flags: u32) -> Result<u32, u32> {
        if !matches!(flags, 0 | 0x10 | 0x1000) {
            return Err(46);
        }
        let name = self.allocate_receive().ok_or(6u32)?;
        if flags == 0x1000 {
            self.slots[(name >> 8) as usize - 1].fetch_or(REPLY, Ordering::Release);
        }
        if flags & 0x10 != 0 {
            self.acquire_send(name);
        }
        Ok(name)
    }

    /// Roll back a name that has not been copied to the guest. No other thread
    /// can own a reference to this unpublished object.
    pub fn discard_unpublished(&self, name: u32) {
        let index = (name >> 8).wrapping_sub(1) as usize;
        if let Some(slot) = self.slots.get(index) {
            let value = slot.load(Ordering::Acquire);
            if value & !REPLY == GENERATION | RECEIVE
                || value & !REPLY == GENERATION | RECEIVE | SEND_ONE
            {
                let _ = slot.compare_exchange(value, 0, Ordering::AcqRel, Ordering::Relaxed);
            }
        }
    }

    pub fn is_reply(&self, name: u32) -> bool {
        let index = (name >> 8).wrapping_sub(1) as usize;
        self.slots.get(index).is_some_and(|slot| {
            let value = slot.load(Ordering::Acquire);
            value & 255 == (name & 255) as u64 && value & (RECEIVE | REPLY) == RECEIVE | REPLY
        })
    }

    pub fn allocate_receive(&self) -> Option<u32> {
        self.slots
            .iter()
            .enumerate()
            .skip(3)
            .find_map(|(index, slot)| {
                slot.compare_exchange(0, GENERATION | RECEIVE, Ordering::AcqRel, Ordering::Relaxed)
                    .ok()
                    .map(|_| (((index + 1) as u32) << 8) | GENERATION as u32)
            })
    }

    pub fn has_receive(&self, name: u32) -> bool {
        let index = (name >> 8).wrapping_sub(1) as usize;
        self.slots.get(index).is_some_and(|slot| {
            let rights = slot.load(Ordering::Acquire);
            rights & 255 == (name & 255) as u64 && rights & RECEIVE != 0
        })
    }

    pub fn acquire_send(&self, name: u32) -> bool {
        let index = (name >> 8).wrapping_sub(1) as usize;
        self.slots.get(index).is_some_and(|slot| {
            slot.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
                (old != 0 && old & 255 == (name & 255) as u64 && old >> 16 < u32::MAX as u64)
                    .then(|| old + SEND_ONE)
            })
            .is_ok()
        })
    }

    pub fn has_send(&self, name: u32) -> bool {
        let index = (name >> 8).wrapping_sub(1) as usize;
        self.slots.get(index).is_some_and(|slot| {
            let value = slot.load(Ordering::Acquire);
            value & 255 == (name & 255) as u64 && value >> 16 != 0
        })
    }

    pub fn deallocate(&self, name: u32) -> u32 {
        let index = (name >> 8).wrapping_sub(1) as usize;
        let Some(slot) = self.slots.get(index) else {
            return 15;
        }; // KERN_INVALID_NAME
        let mut old = slot.load(Ordering::Acquire);
        loop {
            if old == 0 || old & 255 != (name & 255) as u64 {
                return 15;
            }
            let refs = old >> 16;
            if refs == 0 {
                return 17;
            } // KERN_INVALID_RIGHT
            let remaining = refs - 1;
            let value = if remaining == 0 && old & (RECEIVE | KERNEL) == 0 {
                0
            } else {
                (old & 65535) | (remaining << 16)
            };
            match slot.compare_exchange_weak(old, value, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return 0,
                Err(actual) => old = actual,
            }
        }
    }

    pub fn modify_send_refs(&self, name: u32, delta: i32) -> u32 {
        let index = (name >> 8).wrapping_sub(1) as usize;
        let Some(slot) = self.slots.get(index) else {
            return 15;
        }; // KERN_INVALID_NAME
        let mut old = slot.load(Ordering::Acquire);
        loop {
            if old == 0 || old & 255 != (name & 255) as u64 {
                return 15;
            }
            let refs = (old >> 16) as i64;
            if refs == 0 {
                return 17;
            } // KERN_INVALID_RIGHT
            let next = refs + delta as i64;
            if next < 0 {
                return 18;
            } // KERN_INVALID_VALUE
            if next > u32::MAX as i64 {
                return 19;
            } // KERN_UREFS_OVERFLOW
            let value = (old & 65535) | ((next as u64) << 16);
            match slot.compare_exchange_weak(old, value, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return 0,
                Err(actual) => old = actual,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn constructed_ports_own_receive_and_optional_send_rights() {
        let space = Space::default();
        assert_eq!(space.construct(0x20), Err(46));
        let receive = space.construct(0).unwrap();
        assert!(space.has_receive(receive));
        assert_eq!(space.modify_send_refs(receive, -1), 17);
        let both = space.construct(0x10).unwrap();
        assert!(space.has_receive(both));
        assert_eq!(space.modify_send_refs(both, -1), 0);
        space.discard_unpublished(receive);
        assert!(!space.has_receive(receive));
        assert_eq!(space.construct(0x10), Ok(receive));
        let reply = space.construct(0x1000).unwrap();
        assert!(space.is_reply(reply));
        assert!(!space.is_reply(both));
        assert_eq!(space.modify_send_refs(reply, -1), 17);
        space.discard_unpublished(reply);
        assert!(!space.is_reply(reply));
    }
    #[test]
    fn reply_ports_allocate_unique_receive_rights_and_exhaust_without_aliases() {
        let space = Space::default();
        assert!(!space.has_receive(0x103));
        assert!(!space.has_receive(0));
        for index in 4..=CAPACITY {
            let name = space.allocate_receive().unwrap();
            assert_eq!(name, ((index as u32) << 8) | GENERATION as u32);
            assert!(space.has_receive(name));
            assert!(!space.has_receive(name ^ 1));
        }
        assert!(space.allocate_receive().is_none());
    }

    #[test]
    fn duplicate_send_rights_have_checked_user_reference_counts() {
        let space = Space::default();
        assert!(space.acquire_send(0x103));
        assert!(space.acquire_send(0x103));
        assert_eq!(space.modify_send_refs(0x103, -3), 18);
        assert_eq!(space.modify_send_refs(0x103, -1), 0);
        assert_eq!(space.modify_send_refs(0x103, -1), 0);
        assert_eq!(space.modify_send_refs(0x103, -1), 17);
        assert_eq!(space.modify_send_refs(0x104, -1), 15);
        assert!(!space.acquire_send(0x104));
    }
}
