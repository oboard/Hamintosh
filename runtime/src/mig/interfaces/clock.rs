use crate::darwin::{Process, TrapFrame};
use crate::mig::encoder::MigEncoder;
use crate::mig::message::{MachMessage, MigReply, MACH_RCV_TOO_LARGE, MACH_SEND_INVALID_DEST, NDR};
use crate::mig::registry::MigSubsystem;

pub struct ClockSubsystem;

impl MigSubsystem for ClockSubsystem {
    fn subsystem_id(&self) -> u32 {
        1000
    }

    fn can_handle(&self, id: u32) -> bool {
        id == 1000
    }

    fn dispatch(
        &self,
        process: &Process,
        frame: &TrapFrame,
        request: &MachMessage<'_>,
    ) -> Option<MigReply> {
        let a = frame.arguments;
        if request.id == 1000 {
            if request.size != 24 {
                return None;
            }
            let size = 44;
            if (a[6] as u32) < size {
                return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
            }
            let mut value = 0;
            let Some(read_clock) = process.clock else {
                return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
            };
            let error = unsafe { read_clock(process.host_context, 0, &mut value) };
            let mut reply = [0u8; 72];
            reply[24..32].copy_from_slice(&NDR);
            MigEncoder::write_word(&mut reply, 32, error);
            if error == 0 {
                MigEncoder::write_word(&mut reply, 36, (value / 1_000_000_000) as u32);
                MigEncoder::write_word(&mut reply, 40, (value % 1_000_000_000) as u32);
            }
            Some(MigReply::Buffer {
                bytes: reply,
                size: size as usize,
                complex: false,
            })
        } else {
            None
        }
    }
}
