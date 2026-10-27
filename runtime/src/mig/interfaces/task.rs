use crate::darwin::ipc::{bootstrap_service, semaphore_service};
use crate::darwin::{Process, TrapFrame};
use crate::mig::encoder::MigEncoder;
use crate::mig::message::{MachMessage, MigReply, MACH_RCV_TOO_LARGE, MACH_SEND_INVALID_DEST, NDR};
use crate::mig::registry::MigSubsystem;

pub struct TaskSubsystem;

impl MigSubsystem for TaskSubsystem {
    fn subsystem_id(&self) -> u32 {
        3400
    }

    fn can_handle(&self, id: u32) -> bool {
        matches!(id, 3405 | 3409 | 3410 | 3418 | 8000 | 8001)
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
        match request.id {
            3405 => {
                if request.size != 40
                    || !request.has_ndr_at(24)
                    || request.word(32)? != 15
                    || request.word(36)? < 8
                {
                    return None;
                }
                const TOKEN_WORDS: u32 = 8;
                const REPLY_SIZE: u32 = 40 + TOKEN_WORDS * 4;
                if (a[6] as u32) < REPLY_SIZE {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let mut reply = [0u8; 72];
                reply[24..32].copy_from_slice(&NDR);
                MigEncoder::write_word(&mut reply, 32, 0);
                MigEncoder::write_word(&mut reply, 36, TOKEN_WORDS);
                let token = [
                    u32::MAX,    // unset audit id
                    501,         // effective uid
                    501,         // effective gid
                    501,         // real uid
                    501,         // real gid
                    process.pid, // process id
                    100,         // default audit session id
                    process.thread_id as u32,
                ];
                for (index, value) in token.into_iter().enumerate() {
                    MigEncoder::write_word(&mut reply, 40 + index * 4, value);
                }
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: REPLY_SIZE as usize,
                    complex: false,
                })
            }
            3409 => {
                if request.is_complex() {
                    return None;
                }
                let which_port = if request.size == 36 && request.has_ndr_at(24) {
                    request.word(32)?
                } else if request.size == 36 && request.word(24)? == 1 && request.word(32)? == 0 {
                    request.word(28)?
                } else {
                    return None;
                };
                let service = match which_port {
                    4 => bootstrap_service(process),
                    10 => {
                        let port = process
                            .debug_control_port
                            .load(std::sync::atomic::Ordering::Acquire);
                        (port != 0 && process.ports.has_send(port)).then_some(port)
                    }
                    _ => return None,
                };
                if (a[6] as u32) < 40 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let Some(service) = service else {
                    return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                };
                let mut reply = [0u8; 72];
                MigEncoder::write_word(&mut reply, 24, 1);
                MigEncoder::write_word(&mut reply, 28, service);
                MigEncoder::write_word(&mut reply, 32, 0);
                MigEncoder::write_word(&mut reply, 36, 17 << 16); // MOVE_SEND port descriptor
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: 40,
                    complex: true,
                })
            }
            3410 => {
                if request.size != 52
                    || request.word(24)? != 1
                    || request.word(28)? & 0x0fff_ffff == 0
                    || (request.word(36)? >> 16) & 0xff != 19 // COPY_SEND
                    || request.word(36)? >> 24 != 0 // MACH_MSG_PORT_DESCRIPTOR
                    || !request.has_ndr_at(40)
                    || request.word(48)? != 10
                {
                    return None;
                }
                let port = request.word(28)? & 0x0fff_ffff;
                if !process.ports.has_send(port) {
                    return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                }
                if (a[6] as u32) < 36 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                process
                    .debug_control_port
                    .store(port, std::sync::atomic::Ordering::Release);
                let mut reply = [0u8; 72];
                reply[24..32].copy_from_slice(&NDR);
                MigEncoder::write_word(&mut reply, 32, 0);
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: 36,
                    complex: false,
                })
            }
            3418 => {
                if request.size != 40 || !request.has_ndr_at(24) {
                    return None;
                }
                let Some(service) = semaphore_service(process) else {
                    return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                };
                let size = 40;
                if (a[6] as u32) < size {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let mut reply = [0u8; 72];
                MigEncoder::write_word(&mut reply, 24, 1);
                MigEncoder::write_word(&mut reply, 28, service);
                MigEncoder::write_word(&mut reply, 32, 0);
                MigEncoder::write_word(&mut reply, 36, 17 << 16);
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: size as usize,
                    complex: true,
                })
            }
            8000 => {
                if request.size < 36 || !request.has_ndr_at(24) || request.is_complex() {
                    return None;
                }
                let count = request.word(32)? as usize;
                if count > 64 || request.size != 36 + count * 16 {
                    return None;
                }
                if (a[6] as u32) < 36 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let mut reply = [0u8; 72];
                reply[24..32].copy_from_slice(&NDR);
                MigEncoder::write_word(
                    &mut reply,
                    32,
                    process.restartable.register(&request.raw[36..request.size]),
                );
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: 36,
                    complex: false,
                })
            }
            8001 => {
                if request.size != 24 || request.is_complex() {
                    return None;
                }
                if (a[6] as u32) < 36 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let mut reply = [0u8; 72];
                reply[24..32].copy_from_slice(&NDR);
                MigEncoder::write_word(&mut reply, 32, 0);
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: 36,
                    complex: false,
                })
            }
            _ => None,
        }
    }
}
