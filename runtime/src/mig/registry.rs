use super::message::{MachMessage, MigReply};
use crate::darwin::{Process, TrapFrame};
use std::sync::Arc;

pub trait MigSubsystem: Send + Sync {
    fn subsystem_id(&self) -> u32;
    fn can_handle(&self, id: u32) -> bool;
    fn dispatch(
        &self,
        process: &Process,
        frame: &TrapFrame,
        request: &MachMessage<'_>,
    ) -> Option<MigReply>;
}

pub struct MigRegistry {
    subsystems: Vec<Arc<dyn MigSubsystem>>,
}

impl Default for MigRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MigRegistry {
    pub fn new() -> Self {
        Self {
            subsystems: Vec::new(),
        }
    }

    pub fn register(&mut self, subsystem: Arc<dyn MigSubsystem>) {
        self.subsystems.push(subsystem);
    }

    pub fn count(&self) -> usize {
        self.subsystems.len()
    }

    pub fn dispatch(
        &self,
        process: &Process,
        frame: &TrapFrame,
        request: &MachMessage<'_>,
    ) -> Option<MigReply> {
        for sub in &self.subsystems {
            if sub.can_handle(request.id) {
                if let Some(reply) = sub.dispatch(process, frame, request) {
                    return Some(reply);
                }
            }
        }
        None
    }
}
