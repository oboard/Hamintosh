use super::system_service::{SystemService, XpcMessage};

#[derive(Debug, Default)]
pub struct RunningBoardService;

impl SystemService for RunningBoardService {
    fn name(&self) -> &'static str {
        "com.apple.runningboard"
    }

    fn handle(&self, _request: &XpcMessage) -> Option<XpcMessage> {
        // RunningBoard handshake and process state management
        None
    }
}
