use super::system_service::{SystemService, XpcMessage};
use crate::darwin::Process;
use std::sync::atomic::Ordering;

#[derive(Debug, Default)]
pub struct NotificationCenterService;

impl SystemService for NotificationCenterService {
    fn name(&self) -> &'static str {
        "com.apple.system.notification_center"
    }

    fn bootstrap_port(&self, process: &Process) -> Option<u32> {
        let existing = process.notification_center_port.load(Ordering::Acquire);
        if existing != 0 && process.ports.has_receive(existing) {
            return Some(existing);
        }
        let candidate = process.ports.construct(0x10).ok()?;
        match process.notification_center_port.compare_exchange(
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

    fn handle(&self, _request: &XpcMessage) -> Option<XpcMessage> {
        None
    }
}
