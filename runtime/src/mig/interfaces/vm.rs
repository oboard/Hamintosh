use crate::darwin::{Process, TrapFrame};
use crate::mig::encoder::MigEncoder;
use crate::mig::message::{MachMessage, MigReply, MACH_SEND_INVALID_DEST, NDR};
use crate::mig::registry::MigSubsystem;

pub struct VmSubsystem;

impl MigSubsystem for VmSubsystem {
    fn subsystem_id(&self) -> u32 {
        4800
    }

    fn can_handle(&self, id: u32) -> bool {
        matches!(id, 4811 | 4813)
    }

    fn dispatch(
        &self,
        process: &Process,
        _frame: &TrapFrame,
        request: &MachMessage<'_>,
    ) -> Option<MigReply> {
        if request.remote != 0x103 {
            return None;
        }
        match request.id {
            4811 => {
                if request.size != 100
                    || !request.is_complex()
                    || request.word(24)? != 1
                    || request.word(28)? != 0
                {
                    return None;
                }
                let Some(map) = process.vm_map else {
                    return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                };
                let mut address = request.quad(48)?;
                let size = request.quad(56)?;
                let mask = request.quad(64)?;
                let flags = request.word(72)?;
                let current_protection = request.word(88)?;
                let maximum_protection = request.word(92)?;
                if current_protection & !maximum_protection != 0 {
                    return None;
                }
                let error = unsafe {
                    map(
                        process.host_context,
                        &mut address,
                        size,
                        mask,
                        flags,
                        current_protection,
                    )
                };
                let mut reply = [0u8; 72];
                reply[24..32].copy_from_slice(&NDR);
                MigEncoder::write_word(&mut reply, 32, error);
                let size = if error == 0 {
                    reply[36..44].copy_from_slice(&address.to_le_bytes());
                    44
                } else {
                    36
                };
                Some(MigReply::Buffer {
                    bytes: reply,
                    size,
                    complex: false,
                })
            }
            4813 => {
                if request.size != 92
                    || !request.is_complex()
                    || request.word(24)? != 1
                    || request.word(28)? != 0x103
                    || request.word(32)? != 0
                    || request.word(36)? != 19 << 16
                    || !request.has_ndr_at(40)
                {
                    return None;
                }
                let Some(remap) = process.vm_remap else {
                    return Some(MigReply::Status(MACH_SEND_INVALID_DEST));
                };
                let mut address = request.quad(48)?;
                let mut current = 0;
                let mut maximum = 0;
                let error = unsafe {
                    remap(
                        process.host_context,
                        &mut address,
                        request.quad(56)?,
                        request.quad(64)?,
                        request.word(72)?,
                        request.quad(76)?,
                        request.word(84)?,
                        &mut current,
                        &mut maximum,
                        request.word(88)?,
                    )
                };
                let mut reply = [0u8; 72];
                reply[24..32].copy_from_slice(&NDR);
                MigEncoder::write_word(&mut reply, 32, error);
                let size = if error == 0 {
                    reply[36..44].copy_from_slice(&address.to_le_bytes());
                    MigEncoder::write_word(&mut reply, 44, current);
                    MigEncoder::write_word(&mut reply, 48, maximum);
                    52
                } else {
                    36
                };
                Some(MigReply::Buffer {
                    bytes: reply,
                    size,
                    complex: false,
                })
            }
            _ => None,
        }
    }
}
