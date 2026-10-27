use super::system_service::{SystemService, XpcMessage};

#[derive(Debug, Default)]
pub struct NotificationCenterService;

impl SystemService for NotificationCenterService {
    fn name(&self) -> &'static str {
        "com.apple.system.notification_center"
    }

    fn handle(&self, _request: &XpcMessage) -> Option<XpcMessage> {
        // NotificationCenter notifications: registration and posted notifications
        None
    }
}
