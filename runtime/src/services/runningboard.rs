use super::system_service::{SystemService, XpcMessage};
use crate::darwin::Process;
use crate::xpc::{Value, XpcDecoder, XpcEncoder, XPC_TYPE_STRING};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RbsRequestKind {
    Handshake,
    Assertion,
    Other,
}

#[derive(Debug, Default)]
pub struct RunningBoardService;

impl RunningBoardService {
    /// Inspect an XPC message payload for RunningBoard selectors.
    pub fn parse_message(bytes: &[u8]) -> Option<(RbsRequestKind, Option<Value<'_>>)> {
        let root = XpcDecoder::parse_root(bytes)?;
        let selector = XpcDecoder::dictionary_get(root, b"rbs_selector")?;
        if selector.kind != XPC_TYPE_STRING {
            return None;
        }
        let arg0 = XpcDecoder::dictionary_get(root, b"rbs_argument_0");
        let kind = if selector.body.starts_with(b"handshakeWithRequest:")
            || selector.body.starts_with(b"handshake")
        {
            RbsRequestKind::Handshake
        } else if selector.body.starts_with(b"acquireAssertion:")
            || selector.body.starts_with(b"invalidateAssertion:")
        {
            RbsRequestKind::Assertion
        } else {
            RbsRequestKind::Other
        };
        Some((kind, arg0))
    }
}

impl SystemService for RunningBoardService {
    fn name(&self) -> &'static str {
        "com.apple.runningboard"
    }

    fn can_handle_xpc(
        &self,
        payload: &[u8],
        remote_dest: u32,
        _process: &Process,
        connections: &[u32],
    ) -> bool {
        connections.contains(&remote_dest) && Self::parse_message(payload).is_some()
    }

    fn handle_xpc(
        &self,
        _payload: &[u8],
        reply_port: u32,
        _remote_dest: u32,
        _process: &Process,
        reply_buf: &mut [u8; 512],
    ) -> Option<usize> {
        Some(XpcEncoder::build_rbs_unavailable_reply(
            reply_buf, reply_port,
        ))
    }

    fn handle(&self, _request: &XpcMessage) -> Option<XpcMessage> {
        None
    }
}
