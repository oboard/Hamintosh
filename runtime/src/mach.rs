//! Per-process Mach names and rights. Fixed storage keeps trap-time allocation
//! independent of the host allocator and signal-unsafe locks.
use std::sync::atomic::{AtomicU64, Ordering};

const GENERATION: u64 = 3;
const RECEIVE: u64 = 1 << 8;
const REPLY: u64 = 1 << 9;
const GUARDED: u64 = 1 << 10;
const STRICT_GUARD: u64 = 1 << 11;
const PORT_SET: u64 = 1 << 12;
const TIMER: u64 = 1 << 13;
const KERNEL: u64 = 1 << 15;
const SEND_ONE: u64 = 1 << 16;
const CAPACITY: usize = 256;

pub struct Space {
    slots: [AtomicU64; CAPACITY],
    guards: [AtomicU64; CAPACITY],
    notifications: [AtomicU64; CAPACITY],
    members: [[AtomicU64; 4]; CAPACITY],
    timers: [AtomicU64; CAPACITY],
}

impl Default for Space {
    fn default() -> Self {
        let space = Self {
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
            guards: std::array::from_fn(|_| AtomicU64::new(0)),
            notifications: std::array::from_fn(|_| AtomicU64::new(0)),
            members: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            timers: std::array::from_fn(|_| AtomicU64::new(0)),
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
            let unpublished = value & !(REPLY | GUARDED | STRICT_GUARD);
            if (unpublished == GENERATION | RECEIVE
                || unpublished == GENERATION | RECEIVE | SEND_ONE
                || unpublished == GENERATION | PORT_SET
                || unpublished == GENERATION | RECEIVE | TIMER
                || unpublished == GENERATION | RECEIVE | TIMER | SEND_ONE)
                && slot
                    .compare_exchange(value, 0, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                self.guards[index].store(0, Ordering::Release);
                self.notifications[index].store(0, Ordering::Release);
            }
        }
    }

    /// Report user-visible rights, excluding reserved kernel objects until a
    /// self trap has acquired their first send reference. MACH_PORT_DEAD is a
    /// special name and does not occupy a slot (XNU mach_port_type).
    pub fn port_type(&self, name: u32) -> Result<u32, u32> {
        if name == u32::MAX {
            return Ok(1 << 20);
        }
        let index = (name >> 8).wrapping_sub(1) as usize;
        let value = self.slots.get(index).ok_or(15u32)?.load(Ordering::Acquire);
        if value == 0 || value & 255 != (name & 255) as u64 {
            return Err(15);
        }
        let rights = (if value & PORT_SET != 0 { 1 << 19 } else { 0 })
            | (if value & RECEIVE != 0 { 1 << 17 } else { 0 })
            | (if value >> 16 != 0 { 1 << 16 } else { 0 });
        if rights == 0 {
            Err(15)
        } else {
            Ok(rights)
        }
    }

    /// The XNU fast path merges MAKE_SEND/COPY_SEND into an existing name.
    /// Other dispositions or name aliases need object transfer semantics.
    pub fn insert_send(&self, name: u32, make: bool) -> u32 {
        if let Err(error) = self.port_type(name) {
            return error;
        }
        if !(if make {
            self.has_receive(name)
        } else {
            self.has_send(name)
        }) {
            return 17; // KERN_INVALID_RIGHT
        }
        if self.acquire_send(name) {
            0
        } else {
            19
        }
    }

    pub fn set_guard(&self, name: u32, context: u64) -> bool {
        self.apply_guard(name, context, false) == 0
    }

    pub fn apply_guard(&self, name: u32, context: u64, strict: bool) -> u32 {
        if let Err(error) = self.port_type(name) {
            return error;
        }
        if !self.has_receive(name) {
            return 17;
        }
        let index = (name >> 8) as usize - 1;
        let slot = &self.slots[index];
        // Guest execution is serialized; no host mutex is taken on a trap.
        if self.guards[index].load(Ordering::Acquire) != 0 {
            return 4;
        }
        self.guards[index].store(context, Ordering::Release);
        slot.fetch_or(
            GUARDED | if strict { STRICT_GUARD } else { 0 },
            Ordering::AcqRel,
        );
        0
    }

    pub fn remove_guard(&self, name: u32, context: u64) -> u32 {
        if let Err(error) = self.port_type(name) {
            return error;
        }
        if !self.has_receive(name) {
            return 17;
        }
        let index = (name >> 8) as usize - 1;
        let slot = &self.slots[index];
        if slot.load(Ordering::Acquire) & GUARDED == 0
            || self.guards[index].load(Ordering::Acquire) != context
        {
            return 4;
        }
        slot.fetch_and(!(GUARDED | STRICT_GUARD), Ordering::AcqRel);
        self.guards[index].store(0, Ordering::Release);
        0
    }

    pub fn guard(&self, name: u32) -> Option<u64> {
        let index = (name >> 8).wrapping_sub(1) as usize;
        let value = self.slots.get(index)?.load(Ordering::Acquire);
        (value & 255 == (name & 255) as u64 && value & GUARDED != 0)
            .then(|| self.guards[index].load(Ordering::Acquire))
    }

    pub fn is_reply(&self, name: u32) -> bool {
        let index = (name >> 8).wrapping_sub(1) as usize;
        self.slots.get(index).is_some_and(|slot| {
            let value = slot.load(Ordering::Acquire);
            value & 255 == (name & 255) as u64 && value & (RECEIVE | REPLY) == RECEIVE | REPLY
        })
    }

    pub fn allocate_receive(&self) -> Option<u32> {
        self.allocate_slot(RECEIVE)
    }

    pub fn allocate_port_set(&self) -> Option<u32> {
        self.allocate_slot(PORT_SET)
    }

    pub fn construct_timer(&self) -> Option<u32> {
        let name = self.allocate_slot(RECEIVE | TIMER)?;
        if self.acquire_send(name) {
            Some(name)
        } else {
            self.discard_unpublished(name);
            None
        }
    }

    fn allocate_slot(&self, kind: u64) -> Option<u32> {
        self.slots
            .iter()
            .enumerate()
            .skip(3)
            .find_map(|(index, slot)| {
                slot.compare_exchange(0, GENERATION | kind, Ordering::AcqRel, Ordering::Relaxed)
                    .ok()
                    .map(|_| (((index + 1) as u32) << 8) | GENERATION as u32)
            })
    }

    pub fn has_port_set(&self, name: u32) -> bool {
        let index = (name >> 8).wrapping_sub(1) as usize;
        self.slots.get(index).is_some_and(|slot| {
            let value = slot.load(Ordering::Acquire);
            value & 255 == (name & 255) as u64 && value & PORT_SET != 0
        })
    }

    pub fn is_timer(&self, name: u32) -> bool {
        let index = (name >> 8).wrapping_sub(1) as usize;
        self.slots.get(index).is_some_and(|slot| {
            let value = slot.load(Ordering::Acquire);
            value & 255 == (name & 255) as u64 && value & (RECEIVE | TIMER) == RECEIVE | TIMER
        })
    }

    pub fn arm_timer(&self, name: u32, deadline: u64) -> u32 {
        if !self.is_timer(name) {
            return 17;
        }
        let index = (name >> 8) as usize - 1;
        self.timers[index].store(deadline, Ordering::Release);
        0
    }

    pub fn cancel_timer(&self, name: u32) -> Result<u64, u32> {
        if !self.is_timer(name) {
            return Err(17);
        }
        let index = (name >> 8) as usize - 1;
        Ok(self.timers[index].swap(0, Ordering::AcqRel))
    }

    pub fn timer_deadline(&self, name: u32) -> Option<u64> {
        if !self.is_timer(name) {
            return None;
        }
        let index = (name >> 8) as usize - 1;
        let deadline = self.timers[index].load(Ordering::Acquire);
        (deadline != 0).then_some(deadline)
    }

    /// Destroy a receive right and remove it from any containing port set.
    pub fn destroy(&self, name: u32) -> u32 {
        let index = (name >> 8).wrapping_sub(1) as usize;
        let Some(slot) = self.slots.get(index) else {
            return 15;
        };
        let mut old = slot.load(Ordering::Acquire);
        loop {
            if old == 0 || old & 255 != (name & 255) as u64 {
                return 15;
            }
            if old & RECEIVE == 0 {
                return 17;
            }
            match slot.compare_exchange_weak(old, 0, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => {
                    self.guards[index].store(0, Ordering::Release);
                    self.notifications[index].store(0, Ordering::Release);
                    self.timers[index].store(0, Ordering::Release);
                    self.members[index]
                        .iter()
                        .for_each(|word| word.store(0, Ordering::Release));
                    let bit = 1u64 << (index % 64);
                    let word = index / 64;
                    for port_set in &self.members {
                        port_set[word].fetch_and(!bit, Ordering::AcqRel);
                    }
                    return 0;
                }
                Err(actual) => old = actual,
            }
        }
    }

    /// Add an owned receive right to a port set. Membership is tracked as a
    /// bounded bitmap so receive-on-port-set can be implemented without host
    /// allocation on the trap path.
    pub fn insert_member(&self, member: u32, port_set: u32) -> u32 {
        let member_index = (member >> 8).wrapping_sub(1) as usize;
        let set_index = (port_set >> 8).wrapping_sub(1) as usize;
        let Some(member_slot) = self.slots.get(member_index) else {
            return 15;
        };
        let Some(set_slot) = self.slots.get(set_index) else {
            return 15;
        };
        let member_value = member_slot.load(Ordering::Acquire);
        let set_value = set_slot.load(Ordering::Acquire);
        if member_value & 255 != (member & 255) as u64 || set_value & 255 != (port_set & 255) as u64
        {
            return 15;
        }
        if member_value & RECEIVE == 0 || set_value & PORT_SET == 0 {
            return 17;
        }
        let word = member_index / 64;
        let bit = 1u64 << (member_index % 64);
        if self.members[set_index][word].fetch_or(bit, Ordering::AcqRel) & bit != 0 {
            return 11; // KERN_ALREADY_IN_SET
        }
        0
    }

    pub fn extract_member(&self, member: u32, port_set: u32) -> u32 {
        let member_index = (member >> 8).wrapping_sub(1) as usize;
        let set_index = (port_set >> 8).wrapping_sub(1) as usize;
        let Some(member_slot) = self.slots.get(member_index) else {
            return 15;
        };
        let Some(set_slot) = self.slots.get(set_index) else {
            return 15;
        };
        let member_value = member_slot.load(Ordering::Acquire);
        let set_value = set_slot.load(Ordering::Acquire);
        if member_value & 255 != (member & 255) as u64 || set_value & 255 != (port_set & 255) as u64
        {
            return 15;
        }
        if member_value & RECEIVE == 0 || set_value & PORT_SET == 0 {
            return 17;
        }
        let word = member_index / 64;
        let bit = 1u64 << (member_index % 64);
        if self.members[set_index][word].fetch_and(!bit, Ordering::AcqRel) & bit == 0 {
            return 12; // KERN_NOT_IN_SET
        }
        0
    }

    #[cfg(test)]
    pub fn port_set_contains(&self, port_set: u32, member: u32) -> bool {
        let member_index = (member >> 8).wrapping_sub(1) as usize;
        let set_index = (port_set >> 8).wrapping_sub(1) as usize;
        self.has_port_set(port_set)
            && self.members.get(set_index).is_some_and(|words| {
                words[member_index / 64].load(Ordering::Acquire) & (1u64 << (member_index % 64))
                    != 0
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

    /// Bind or cancel a port-notification target. Notifications themselves are
    /// not delivered until the compatibility kernel models port destruction.
    pub fn request_notification(
        &self,
        name: u32,
        msgid: u32,
        notify: u32,
        notify_poly: u32,
    ) -> Result<u32, u32> {
        let index = (name >> 8).wrapping_sub(1) as usize;
        let valid_name = self.slots.get(index).is_some_and(|slot| {
            let value = slot.load(Ordering::Acquire);
            value != 0 && value & 255 == (name & 255) as u64
        });
        if !valid_name {
            return Err(15); // KERN_INVALID_NAME
        }
        let valid_notify = match notify_poly {
            21 => self.has_receive(notify) || self.has_send(notify),
            17 | 19 | 20 => self.has_send(notify),
            _ => false,
        };
        if notify != 0 && !valid_notify {
            return Err(17); // KERN_INVALID_RIGHT
        }
        if !matches!(msgid, 65 | 66 | 69 | 70 | 71 | 72) {
            return Err(4); // KERN_INVALID_ARGUMENT
        }
        let previous = self.notifications[index].swap(
            if notify == 0 {
                0
            } else {
                (u64::from(msgid) << 32) | u64::from(notify)
            },
            Ordering::AcqRel,
        );
        Ok(previous as u32)
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
    fn notification_requests_validate_rights_and_cancel_cleanly() {
        let space = Space::default();
        let target = space.construct(0x10).unwrap();
        let notify = space.construct(0x10).unwrap();
        assert_eq!(space.request_notification(target, 69, notify, 21), Ok(0));
        assert_eq!(
            space.request_notification(target, 69, notify, 21),
            Ok(notify)
        );
        assert_eq!(space.request_notification(target, 69, 0, 21), Ok(notify));
        assert_eq!(space.request_notification(target, 69, target, 17), Ok(0));
        let receive_only = space.construct(0).unwrap();
        assert_eq!(
            space.request_notification(target, 69, receive_only, 21),
            Ok(target)
        );
        assert_eq!(space.request_notification(target, 68, notify, 21), Err(4));
        assert_eq!(space.request_notification(0xdead, 69, notify, 21), Err(15));
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
