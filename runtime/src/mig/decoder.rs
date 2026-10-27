use super::message::MachMessage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortDisposition {
    MoveReceive = 16,
    MoveSend = 17,
    MoveSendOnce = 18,
    CopySend = 19,
    MakeSend = 20,
    MakeSendOnce = 21,
}

#[derive(Debug, Clone, Copy)]
pub struct PortDescriptor {
    pub name: u32,
    pub disposition: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct OolDescriptor {
    pub address: u64,
    pub size: u32,
    pub deallocate: bool,
    pub copy: u32,
}

pub struct MigDecoder;

impl MigDecoder {
    pub fn parse_port_descriptor(msg: &MachMessage<'_>, offset: usize) -> Option<PortDescriptor> {
        let name = msg.word(offset)?;
        let descriptor_type_and_disp = msg.word(offset + 8)?;
        let desc_type = descriptor_type_and_disp >> 24;
        let disposition = (descriptor_type_and_disp >> 16) & 0xff;
        if desc_type != 0 {
            // Not a port descriptor
            return None;
        }
        Some(PortDescriptor { name, disposition })
    }

    pub fn parse_ool_descriptor(msg: &MachMessage<'_>, offset: usize) -> Option<OolDescriptor> {
        let address = msg.quad(offset)?;
        let dealloc_and_copy = msg.word(offset + 8)?;
        let size = msg.word(offset + 12)?;
        let desc_type = dealloc_and_copy >> 24;
        if desc_type != 1 {
            // MACH_MSG_OOL_DESCRIPTOR = 1
            return None;
        }
        Some(OolDescriptor {
            address,
            size,
            deallocate: (dealloc_and_copy & 0x0100) != 0,
            copy: (dealloc_and_copy >> 16) & 0xff,
        })
    }
}
