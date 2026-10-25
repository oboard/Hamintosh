//! Guest descriptors own their host handles; arbitrary host descriptor numbers
//! are never accepted from a Darwin caller. Fixed slots support the trap path.
use std::sync::atomic::{AtomicI32, AtomicU8, Ordering};

struct Entry {
    descriptor: AtomicI32,
    path: [AtomicU8; 1024],
}

pub struct Files {
    entries: Box<[Entry]>,
}
impl Default for Files {
    fn default() -> Self {
        Self {
            entries: (0..256)
                .map(|_| Entry {
                    descriptor: AtomicI32::new(-1),
                    path: std::array::from_fn(|_| AtomicU8::new(0)),
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }
}
impl Files {
    pub fn insert(&self, host: i32) -> Option<u32> {
        self.insert_path(host, b"")
    }
    pub fn insert_path(&self, host: i32, path: &[u8]) -> Option<u32> {
        if host < 0 || path.len() >= 1024 || path.contains(&0) {
            return None;
        }
        self.entries
            .iter()
            .enumerate()
            .skip(3)
            .find_map(|(index, entry)| {
                entry
                    .descriptor
                    .compare_exchange(-1, -2, Ordering::AcqRel, Ordering::Relaxed)
                    .ok()?;
                for (slot, value) in entry.path.iter().zip(path) {
                    slot.store(*value, Ordering::Relaxed);
                }
                entry.path[path.len()].store(0, Ordering::Relaxed);
                entry.descriptor.store(host, Ordering::Release);
                Some(index as u32)
            })
    }
    pub fn host(&self, guest: u32) -> Option<i32> {
        self.entries.get(guest as usize).and_then(|slot| {
            let host = slot.descriptor.load(Ordering::Acquire);
            (host >= 0).then_some(host)
        })
    }
    pub fn take(&self, guest: u32) -> Option<i32> {
        self.entries.get(guest as usize).and_then(|slot| {
            let host = slot.descriptor.swap(-1, Ordering::AcqRel);
            (host >= 0).then_some(host)
        })
    }
    pub fn path(&self, guest: u32, output: &mut [u8; 1024]) -> Option<usize> {
        self.host(guest)?;
        let entry = &self.entries[guest as usize];
        for (i, (source, dest)) in entry.path.iter().zip(output.iter_mut()).enumerate() {
            *dest = source.load(Ordering::Acquire);
            if *dest == 0 {
                return Some(i + 1);
            }
        }
        None
    }
    pub fn drain(&self, mut close: impl FnMut(i32)) {
        for index in 3..self.entries.len() {
            if let Some(host) = self.take(index as u32) {
                close(host);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_reuse_preserves_the_virtual_path_for_each_object() {
        let files = Files::default();
        assert_eq!(files.insert_path(91, b"/"), Some(3));
        assert_eq!(files.insert_path(105, b"/usr/lib/dyld"), Some(4));
        let mut path = [0u8; 1024];
        assert_eq!(files.path(3, &mut path), Some(2));
        assert_eq!(&path[..2], b"/\0");
        assert_eq!(files.path(4, &mut path), Some(14));
        assert_eq!(&path[..14], b"/usr/lib/dyld\0");
        assert_eq!(files.take(3), Some(91));
        assert_eq!(files.insert_path(106, b"/usr"), Some(3));
        assert_eq!(files.path(3, &mut path), Some(5));
        assert_eq!(&path[..5], b"/usr\0");
        assert!(files.insert_path(107, b"invalid\0suffix").is_none());
    }
    #[test]
    fn guest_names_are_separate_and_handles_close_exactly_once() {
        let files = Files::default();
        assert_eq!(files.insert(91), Some(3));
        assert_eq!(files.insert(105), Some(4));
        assert_eq!(files.host(3), Some(91));
        assert_eq!(files.host(91), None);
        assert_eq!(files.take(3), Some(91));
        assert_eq!(files.take(3), None);
        let mut closed = vec![];
        files.drain(|fd| closed.push(fd));
        files.drain(|_| panic!("descriptor closed twice"));
        assert_eq!(closed, [105]);
    }
}
