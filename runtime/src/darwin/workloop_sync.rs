//! Disabled EVFILT_WORKLOOP sync knotes: real waits and preposted wakeups.
//! Ownership/QoS inheritance is separate from this wait transport.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

type Hook = Option<unsafe extern "C" fn()>;
type Key = (u64, u64); // dynamic workloop ID, userspace waiter ident

#[derive(Default)]
pub(super) struct State(Mutex<HashMap<Key, Arc<Waiter>>>);

#[derive(Default)]
struct Status {
    woken: bool,
    thread: Option<u64>,
}

#[derive(Default)]
pub(super) struct Waiter {
    status: Mutex<Status>,
    condition: Condvar,
}

impl State {
    pub(super) fn change(
        &self,
        key: Key,
        flags: u16,
        command: u32,
        thread: u64,
    ) -> Result<Option<Arc<Waiter>>, u32> {
        const ADD: u16 = 1;
        const DELETE: u16 = 2;
        const ENABLE: u16 = 4;
        const DISABLE: u16 = 8;
        if key.0 == 0 || key.0 == key.1 || !matches!(command, 4 | 8) {
            return Err(22);
        }
        let mut notes = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if flags & DELETE != 0 {
            let Some(note) = notes.remove(&key) else {
                return Err(2);
            };
            note.status.lock().unwrap_or_else(|e| e.into_inner()).woken = true;
            note.condition.notify_all();
            return Ok(None);
        }
        if flags & ENABLE != 0 {
            return Err(22);
        }
        let note = if let Some(note) = notes.get(&key) {
            Arc::clone(note)
        } else {
            if flags & ADD == 0 {
                return Err(2);
            }
            if flags & DISABLE == 0 {
                return Err(22);
            }
            if notes.len() == 64 {
                return Err(35);
            }
            let note = Arc::new(Waiter::default());
            notes.insert(key, Arc::clone(&note));
            note
        };
        let mut status = note.status.lock().unwrap_or_else(|e| e.into_inner());
        if command == 8 {
            status.woken = true;
            note.condition.notify_all();
            return Ok(None);
        }
        if status.thread.is_some_and(|owner| owner != thread) {
            return Err(18); // EXDEV: a different thread cannot reuse this wait.
        }
        status.thread = Some(thread);
        drop(status);
        Ok(Some(note))
    }
}

pub(super) fn wait(
    note: &Waiter,
    stopping: &AtomicBool,
    leave: Hook,
    enter: Hook,
) -> Result<(), u32> {
    let mut status = note.status.lock().unwrap_or_else(|e| e.into_inner());
    if status.woken {
        return Ok(());
    }
    // Registration and the initial test happen before the guest gate is
    // released, so a handoff cannot be lost between test and sleep.
    if let Some(leave) = leave {
        unsafe { leave() };
    }
    let result = loop {
        if stopping.load(Ordering::Acquire) {
            break Err(4); // EINTR, never a successful handoff.
        }
        if status.woken {
            break Ok(());
        }
        status = note
            .condition
            .wait_timeout(status, Duration::from_millis(25))
            .unwrap_or_else(|e| e.into_inner())
            .0;
    };
    // A waker may still hold the guest gate. Drop every host mutex before
    // re-entering it; retaining status here would invert the lock order.
    drop(status);
    if let Some(enter) = enter {
        unsafe { enter() };
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn wait_requires_matching_handoff_and_preserves_preposted_wake() {
        let state = Arc::new(State::default());
        let key = (0x4000, 0x1203);
        let note = state.change(key, 9, 4, 1).unwrap().unwrap();
        let (send, recv) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            send.send(wait(&note, &AtomicBool::new(false), None, None))
                .unwrap();
        });
        assert!(recv.recv_timeout(Duration::from_millis(20)).is_err());
        state.change((0x5000, key.1), 9, 8, 2).unwrap();
        assert!(recv.recv_timeout(Duration::from_millis(20)).is_err());
        state.change(key, 9, 8, 2).unwrap();
        assert_eq!(recv.recv_timeout(Duration::from_secs(1)).unwrap(), Ok(()));
        worker.join().unwrap();
        state.change(key, 6, 8, 1).unwrap();
        assert!(matches!(state.change(key, 6, 8, 1), Err(2)));
        state.change(key, 9, 8, 2).unwrap();
        let note = state.change(key, 9, 4, 1).unwrap().unwrap();
        assert_eq!(wait(&note, &AtomicBool::new(false), None, None), Ok(()));
        assert!(matches!(state.change(key, 9, 4, 2), Err(18)));
    }

    #[test]
    fn deletion_wakes_a_waiter_and_shutdown_is_interrupted() {
        let state = State::default();
        let key = (0x4000, 0x1203);
        let note = state.change(key, 9, 4, 1).unwrap().unwrap();
        assert_eq!(wait(&note, &AtomicBool::new(true), None, None), Err(4));
        state.change(key, 6, 8, 2).unwrap();
        assert_eq!(wait(&note, &AtomicBool::new(false), None, None), Ok(()));
        for n in 0..64 {
            state.change((0x4000, n), 9, 8, 1).unwrap();
        }
        assert!(matches!(state.change((0x4000, 65), 9, 8, 1), Err(35)));
    }
}
