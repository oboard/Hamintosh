use super::system_service::{SystemService, XpcMessage};
use crate::darwin::Process;
use crate::xpc::{XpcDecoder, XpcEncoder, XPC_TYPE_ARRAY, XPC_TYPE_NULL, XPC_TYPE_STRING};

#[derive(Debug, Default)]
pub struct CfprefsdService;

impl CfprefsdService {
    /// Validate and parse a CFPreferences read request or batch.
    pub fn parse_read_request(bytes: &[u8]) -> Option<u32> {
        let root = XpcDecoder::parse_root(bytes)?;
        let operation = XpcDecoder::integer(XpcDecoder::dictionary_get(
            root,
            b"CFPreferencesOperation",
        )?)?;
        if operation == 1 || operation == 7 {
            return (XpcDecoder::dictionary_get(root, b"CFPreferencesDomain")?.kind
                == XPC_TYPE_STRING)
                .then_some(1);
        }
        if operation != 5 || root.count != 2 {
            return None;
        }
        let batch = XpcDecoder::dictionary_get(root, b"CFPreferencesMessages")?;
        if batch.kind != XPC_TYPE_ARRAY || batch.count == 0 || batch.count > 32 {
            return None;
        }
        let mut inner = 0;
        let mut budget = 256;
        let mut reads = 0;
        for _ in 0..batch.count {
            let request = XpcDecoder::parse_value(batch.body, &mut inner, 0, &mut budget)?;
            if request.kind == XPC_TYPE_NULL {
                continue;
            }
            let op = XpcDecoder::integer(XpcDecoder::dictionary_get(
                request,
                b"CFPreferencesOperation",
            )?)?;
            if op != 1 && op != 7 {
                return None;
            }
            if XpcDecoder::dictionary_get(request, b"CFPreferencesDomain")?.kind != XPC_TYPE_STRING {
                return None;
            }
            reads += 1;
        }
        (reads != 0).then_some(reads)
    }
}

impl SystemService for CfprefsdService {
    fn name(&self) -> &'static str {
        "com.apple.cfprefsd.daemon"
    }

    fn can_handle_xpc(
        &self,
        payload: &[u8],
        remote_dest: u32,
        _process: &Process,
        connections: &[u32],
    ) -> bool {
        connections.contains(&remote_dest) && Self::parse_read_request(payload).is_some()
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
