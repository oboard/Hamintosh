use crate::darwin::ipc::{io_display_service, io_registry_service};
use crate::darwin::{Process, TrapFrame};
use crate::mig::encoder::MigEncoder;
use crate::mig::message::{MachMessage, MigReply, MACH_RCV_TOO_LARGE, MACH_SEND_INVALID_DEST, NDR};
use crate::mig::registry::MigSubsystem;

pub struct IOKitSubsystem;

impl MigSubsystem for IOKitSubsystem {
    fn subsystem_id(&self) -> u32 {
        2800
    }

    fn can_handle(&self, id: u32) -> bool {
        matches!(id, 2809 | 2877 | 2880 | 2889)
    }

    fn dispatch(
        &self,
        process: &Process,
        frame: &TrapFrame,
        request: &MachMessage<'_>,
    ) -> Option<MigReply> {
        let a = frame.arguments;
        match request.id {
            2809 => {
                if !(44..=552).contains(&request.size)
                    || !request.size.is_multiple_of(4)
                    || !request.has_ndr_at(24)
                    || request.word(32)? != 0
                {
                    return None;
                }
                let path_size = request.word(36)? as usize;
                let path_end = 40usize.checked_add(path_size)?;
                if !(2..=512).contains(&path_size)
                    || path_end > request.size
                    || (path_end + 3) & !3 != request.size
                    || request.raw[path_end - 1] != 0
                    || request.raw[40..path_end - 1].contains(&0)
                {
                    return None;
                }
                if (a[6] as u32) < 40 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let path = &request.raw[40..path_end - 1];
                let service =
                    if path == b"IODeviceTree:/arm-io/disp0" || path == b"IODeviceTree:/product" {
                        // /product is a real IOPlatformDevice registry entry, not
                        // an alias for an AGX or display service.
                        let Some(service) = io_registry_service(process) else {
                            return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                        };
                        service
                    } else {
                        0
                    };
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
            2877 => {
                if request.size != 24 {
                    return None;
                }
                let size = 44;
                if (a[6] as u32) < size {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let mut reply = [0u8; 72];
                reply[24..32].copy_from_slice(&NDR);
                MigEncoder::write_word(&mut reply, 32, 0);
                reply[36..44].copy_from_slice(&20_210_810u64.to_le_bytes());
                Some(MigReply::Buffer {
                    bytes: reply,
                    size: size as usize,
                    complex: false,
                })
            }
            2880 => {
                if request.size != 80
                    || !request
                        .raw
                        .windows(15)
                        .any(|window| window == b"IOProviderClass")
                    || !request.raw.windows(9).any(|window| window == b"AppleCLCD")
                {
                    return None;
                }
                if (a[6] as u32) < 40 {
                    return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                }
                let Some(service) = io_display_service(process) else {
                    return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                };
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
            2889 => {
                if !matches!(request.size, 84 | 88 | 92 | 96 | 100 | 104) || !request.has_ndr_at(24)
                {
                    return None;
                }
                // io_registry_entry_get_property_bin_buf: optional empty plane,
                // or one NUL byte; then the property name, options, caller
                // buffer and its inout capacity. Preserve the older zero-plane
                // captures as well as the full 104-byte form.
                if request.word(32)? != 0
                    || !matches!(request.word(36)?, 0 | 1)
                    || (request.word(36)? == 1 && request.raw[40] != 0)
                    || request.word(44)? != 0
                {
                    return None;
                }
                let name_size = request.word(48)? as usize;
                let name_end = 52usize.checked_add(name_size)?;
                let options_offset = (name_end + 3) & !3;
                let output_offset = options_offset.checked_add(4)?;
                let capacity_offset = output_offset.checked_add(8)?;
                if !(2..=128).contains(&name_size)
                    || name_end > request.size
                    || request.raw[name_end - 1] != 0
                    || request.raw[52..name_end - 1].contains(&0)
                    || capacity_offset + 8 != request.size
                    || request.word(options_offset)? != 0
                {
                    return None;
                }
                let property = &request.raw[52..name_end - 1];
                if property != b"APTDevice"
                    && property != b"supports-apt"
                    && property != b"artwork-display-gamut"
                {
                    if (a[6] as u32) < 36 {
                        return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                    }
                    let mut reply = [0u8; 72];
                    reply[24..32].copy_from_slice(&NDR);
                    MigEncoder::write_word(&mut reply, 32, 0xe000_02f0); // kIOReturnNotFound
                    Some(MigReply::Buffer {
                        bytes: reply,
                        size: 36,
                        complex: false,
                    })
                } else {
                    let value_size = match property {
                        b"supports-apt" => 8,
                        b"artwork-display-gamut" => 12,
                        _ => 16,
                    };
                    let output = request.quad(output_offset)?;
                    let capacity = request.quad(capacity_offset)?;
                    if output == 0 || capacity < value_size as u64 {
                        return None;
                    }
                    if (a[6] as u32) < 64 {
                        return Some(MigReply::Status(MACH_RCV_TOO_LARGE));
                    }
                    let Some(write) = process.copy_out else {
                        return Some(MigReply::Status(0x10004008));
                    };
                    let mut value = [0u8; 16];
                    value[..4].copy_from_slice(&[0xd3, 0, 0, 0]);
                    if property == b"supports-apt" {
                        value[4..8].copy_from_slice(&0x8b00_0001u32.to_le_bytes());
                    } else if property == b"artwork-display-gamut" {
                        // Apple's native /product registry stores the CFString "P3".
                        value[4..8].copy_from_slice(&0x8900_0002u32.to_le_bytes());
                        value[8..12].copy_from_slice(b"P3\0\0");
                    } else {
                        value[4..8].copy_from_slice(&0x8400_0040u32.to_le_bytes());
                        value[8..].copy_from_slice(&1u64.to_le_bytes());
                    }
                    if unsafe { write(process.host_context, output, value.as_ptr(), value_size) }
                        != 0
                    {
                        return Some(MigReply::Status(0x10004008));
                    }
                    let mut reply = [0u8; 72];
                    MigEncoder::write_word(&mut reply, 24, 1);
                    MigEncoder::write_word(&mut reply, 36, 1 << 24); // OOL
                    MigEncoder::write_word(&mut reply, 40, 0);
                    reply[44..52].copy_from_slice(&NDR);
                    reply[52..60].copy_from_slice(&(value_size as u64).to_le_bytes());
                    MigEncoder::write_word(&mut reply, 60, 0);
                    Some(MigReply::Buffer {
                        bytes: reply,
                        size: 64,
                        complex: true,
                    })
                }
            }
            _ => None,
        }
    }
}
