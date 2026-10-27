use super::system_service::{SystemService, XpcMessage};

#[derive(Debug, Default)]
pub struct CfprefsdService;

impl SystemService for CfprefsdService {
    fn name(&self) -> &'static str {
        "com.apple.cfprefsd.daemon"
    }

    fn handle(&self, _request: &XpcMessage) -> Option<XpcMessage> {
        // Preferences read/write handling
        None
    }
}
