use super::system_service::{SystemService, XpcMessage};
use crate::darwin::Process;
use crate::xpc::XpcEncoder;
use std::sync::atomic::Ordering;

#[derive(Debug, Default)]
pub struct BackBoardHidService;

impl SystemService for BackBoardHidService {
    fn name(&self) -> &'static str {
        "com.apple.backboard.hid-services.xpc"
    }

    fn bootstrap_port(&self, process: &Process) -> Option<u32> {
        let existing = process.backboard_hid_services_port.load(Ordering::Acquire);
        if existing != 0 && process.ports.has_receive(existing) {
            return Some(existing);
        }
        let candidate = process.ports.construct(0x10).ok()?;
        match process.backboard_hid_services_port.compare_exchange(
            0,
            candidate,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Some(candidate),
            Err(existing) => {
                process.ports.discard_unpublished(candidate);
                (existing != 0 && process.ports.has_receive(existing)).then_some(existing)
            }
        }
    }

    fn can_handle_xpc(
        &self,
        _payload: &[u8],
        remote_dest: u32,
        process: &Process,
        _connections: &[u32],
    ) -> bool {
        let hid_port = process.backboard_hid_services_port.load(Ordering::Acquire);
        hid_port != 0 && hid_port == remote_dest
    }

    fn handle_xpc(
        &self,
        _payload: &[u8],
        reply_port: u32,
        _remote_dest: u32,
        _process: &Process,
        reply_buf: &mut [u8; 512],
    ) -> Option<usize> {
        Some(XpcEncoder::build_preferences_unavailable_reply(
            reply_buf, reply_port,
        ))
    }

    fn handle(&self, _request: &XpcMessage) -> Option<XpcMessage> {
        None
    }
}
