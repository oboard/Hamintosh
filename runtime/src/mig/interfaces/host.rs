use crate::darwin::{Process, TrapFrame};
use crate::mig::encoder::MigEncoder;
use crate::mig::message::{MachMessage, MigReply, MACH_RCV_TOO_LARGE, MACH_SEND_INVALID_DEST, NDR};
use crate::mig::registry::MigSubsystem;

const PRIORITIES: [u32; 8] = [80, 80, 64, 31, 0, 0, 0, 79];

pub struct HostSubsystem;

impl MigSubsystem for HostSubsystem {
    fn subsystem_id(&self) -> u32 {
        200
    }

    fn can_handle(&self, id: u32) -> bool {
        matches!(id, 200 | 205 | 206 | 412)
    }

    fn dispatch(
        &self,
        process: &Process,
        frame: &TrapFrame,
        request: &MachMessage<'_>,
    ) -> Option<MigReply> {
        if request.remote != 0x303 {
            return None;
        }
        let a = frame.arguments;
        match request.id {
            200 => {
                if request.size != 40 || !request.has_ndr_at(24) || request.word(32)? != 5 {
                    return None;
                }
                let count = request.word(36)?;
                let size = if count >= 8 { 72 } else { 36 };
                if (a[6] as u32) < size {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let mut reply = [0u8; 72];
                reply[24..32].copy_from_slice(&NDR);
                if count < 8 {
                    MigEncoder::write_word(&mut reply, 32, 5); // KERN_FAILURE
                } else {
                    MigEncoder::write_word(&mut reply, 32, 0);
                    MigEncoder::write_word(&mut reply, 36, 8);
                    for (i, priority) in PRIORITIES.iter().enumerate() {
                        MigEncoder::write_word(&mut reply, 40 + i * 4, *priority);
                    }
                }
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: size as usize,
                    complex: false,
                })
            }
            205 => {
                if request.size != 24 || request.is_complex() {
                    return None;
                }
                if (a[6] as u32) < 40 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let Some(service) = crate::darwin::ipc::io_main_service(process) else {
                    return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                };
                let mut reply = [0u8; 72];
                MigEncoder::write_word(&mut reply, 24, 1);
                MigEncoder::write_word(&mut reply, 28, service);
                MigEncoder::write_word(&mut reply, 32, 0);
                MigEncoder::write_word(&mut reply, 36, 17 << 16); // MOVE_SEND
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: 40,
                    complex: true,
                })
            }
            206 => {
                if request.size != 36 || !request.has_ndr_at(24) || request.word(32)? > 1 {
                    return None;
                }
                let Some(service) = crate::darwin::ipc::clock_service(process) else {
                    return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                };
                if (a[6] as u32) < 40 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let mut reply = [0u8; 72];
                MigEncoder::write_word(&mut reply, 24, 1);
                MigEncoder::write_word(&mut reply, 28, service);
                MigEncoder::write_word(&mut reply, 32, 0);
                MigEncoder::write_word(&mut reply, 36, 17 << 16);
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: 40,
                    complex: true,
                })
            }
            412 => {
                if request.size != 40
                    || !request.has_ndr_at(24)
                    || request.word(32)? != u32::MAX
                    || request.word(36)? != 1
                {
                    return None;
                }
                if (a[6] as u32) < 40 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let mut reply = [0u8; 72];
                MigEncoder::write_word(&mut reply, 24, 1);
                MigEncoder::write_word(&mut reply, 28, 0x303);
                MigEncoder::write_word(&mut reply, 32, 0);
                MigEncoder::write_word(&mut reply, 36, 19 << 16); // COPY_SEND
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: 40,
                    complex: true,
                })
            }
            _ => None,
        }
    }
}
