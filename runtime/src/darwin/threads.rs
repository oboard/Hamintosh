//! Guest thread state follows the host thread without replacing host TLS.
use super::Process;
use std::cell::Cell;
use std::sync::atomic::Ordering;

#[derive(Clone, Copy, Default)]
struct Current {
    owner: usize,
    id: u64,
    port: u32,
    tsd: u64,
    reply: u32,
    mask: u32,
}

thread_local! {
    static CURRENT: Cell<Current> = const { Cell::new(Current { owner: 0, id: 0, port: 0, tsd: 0, reply: 0, mask: 0 }) };
}

fn get(process: &Process) -> Option<Current> {
    let current = CURRENT.get();
    (current.owner == process as *const Process as usize).then_some(current)
}

pub(super) fn tsd(process: &Process) -> u64 {
    get(process).map_or_else(
        || process.tsd_base.load(Ordering::Acquire),
        |state| state.tsd,
    )
}

pub(super) fn set_tsd(process: &Process, tsd: u64) {
    if let Some(mut state) = get(process) {
        state.tsd = tsd;
        CURRENT.set(state);
    } else {
        process.tsd_base.store(tsd, Ordering::Release);
    }
}

pub(super) fn id(process: &Process) -> u64 {
    get(process).map_or(process.thread_id, |state| state.id)
}

pub(super) fn port(process: &Process) -> Option<u32> {
    get(process).map(|state| state.port)
}

pub(super) fn mask(process: &Process) -> Option<u32> {
    get(process).map(|state| state.mask)
}
pub(super) fn set_mask(process: &Process, mask: u32) {
    if let Some(mut state) = get(process) {
        state.mask = mask;
        CURRENT.set(state);
    }
}

pub(super) fn swap_reply(process: &Process, reply: u32) -> u32 {
    if let Some(mut state) = get(process) {
        let old = state.reply;
        state.reply = reply;
        CURRENT.set(state);
        old
    } else {
        process.special_reply_port.swap(reply, Ordering::AcqRel)
    }
}

/// # Safety
/// The process must outlive this thread's attachment. Call only outside guest
/// execution; one attachment per host thread, detached before process teardown.
#[no_mangle]
pub unsafe extern "C" fn hm_process_attach_thread(
    process: *const Process,
    id: u64,
    tsd: u64,
) -> u32 {
    let Some(process) = process.as_ref() else {
        return 0;
    };
    if CURRENT.get().owner != 0 || id == 0 {
        return 0;
    }
    let Ok(port) = process.ports.construct(0x10) else {
        return 0;
    };
    CURRENT.set(Current {
        owner: process as *const Process as usize,
        id,
        port,
        tsd,
        reply: 0,
        mask: 0,
    });
    port
}

/// # Safety
/// The attached process must still be live; no guest code may run after detach.
#[no_mangle]
pub unsafe extern "C" fn hm_process_detach_thread(process: *const Process) {
    let Some(process) = process.as_ref() else {
        return;
    };
    if let Some(state) = get(process) {
        // The pthread's port may have published send refs, so leave that name
        // owned by the process until teardown rather than recycling it early.
        if state.reply != 0 {
            process.ports.discard_unpublished(state.reply);
        }
        CURRENT.set(Current::default());
    }
}
