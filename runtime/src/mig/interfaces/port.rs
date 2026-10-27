use crate::darwin::{Process, TrapFrame};
use crate::mig::encoder::MigEncoder;
use crate::mig::message::{MachMessage, MigReply, MACH_RCV_TOO_LARGE, NDR};
use crate::mig::registry::MigSubsystem;

pub struct PortSubsystem;

impl MigSubsystem for PortSubsystem {
    fn subsystem_id(&self) -> u32 {
        3200
    }

    fn can_handle(&self, id: u32) -> bool {
        id == 3218
    }

    fn dispatch(
        &self,
        process: &Process,
        frame: &TrapFrame,
        request: &MachMessage<'_>,
    ) -> Option<MigReply> {
        if request.remote != 0x103 {
            return None;
        }
        let a = frame.arguments;
        if request.id == 3218 {
            if request.size < 44 || !request.has_ndr_at(24) || request.is_complex() {
                return None;
            }
            if (a[6] as u32) < 36 {
                return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
            }
            let count = request.word(40)? as usize;
            if count > 17 || request.size != 44 + 4 * count {
                return None;
            }
            let error = if request.word(36)? != 1 {
                4
            } else if count == 0 {
                5
            } else {
                process
                    .ports
                    .set_queue_limit(request.word(32)?, request.word(44)?)
                    .err()
                    .unwrap_or(0)
            };
            let mut reply = [0u8; 72];
            reply[24..32].copy_from_slice(&NDR);
            MigEncoder::write_word(&mut reply, 32, error);
            Some(MigReply::Buffer {
                bytes: reply,
                size: 36,
                complex: false,
            })
        } else {
            None
        }
    }
}
