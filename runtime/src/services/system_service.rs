use crate::darwin::Process;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct XpcMessage {
    pub raw: Vec<u8>,
}

impl XpcMessage {
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            raw: bytes.to_vec(),
        }
    }
}

pub trait SystemService: Send + Sync + Debug {
    fn name(&self) -> &'static str;

    /// Allocate or retrieve a service Mach port for bootstrap lookup.
    fn bootstrap_port(&self, _process: &Process) -> Option<u32> {
        None
    }

    /// Check if this service handles an incoming XPC message.
    fn can_handle_xpc(
        &self,
        _payload: &[u8],
        _remote_dest: u32,
        _process: &Process,
        _connections: &[u32],
    ) -> bool {
        false
    }

    /// Process the request and serialize a reply into `reply_buf`.
    /// Returns the length of the serialized Mach reply message.
    fn handle_xpc(
        &self,
        _payload: &[u8],
        _reply_port: u32,
        _remote_dest: u32,
        _process: &Process,
        _reply_buf: &mut [u8; 512],
    ) -> Option<usize> {
        None
    }

    fn handle(&self, _request: &XpcMessage) -> Option<XpcMessage> {
        None
    }
}
