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
    fn handle(&self, request: &XpcMessage) -> Option<XpcMessage>;
}
