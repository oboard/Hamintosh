pub const NDR: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

pub const MACH_RCV_TOO_LARGE: u32 = 0x10004004;
pub const MACH_RCV_INVALID_DATA: u32 = 0x10004008;
pub const MACH_SEND_INVALID_DEST: u32 = 0x10000003;
pub const MACH_SEND_TIMED_OUT: u32 = 0x10000004;
pub const MACH_SEND_MSG_TOO_SMALL: u32 = 0x10000010;

#[derive(Debug, Clone, Copy)]
pub struct MachMessage<'a> {
    pub raw: &'a [u8],
    pub bits: u32,
    pub size: usize,
    pub remote: u32,
    pub local: u32,
    pub voucher: u32,
    pub id: u32,
}

impl<'a> MachMessage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 24 {
            return None;
        }
        let word = |at: usize| -> u32 {
            u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
        };
        Some(Self {
            raw: bytes,
            bits: word(0),
            size: bytes.len(),
            remote: word(8),
            local: word(12),
            voucher: word(16),
            id: word(20),
        })
    }

    pub fn is_complex(&self) -> bool {
        self.bits & 0x8000_0000 != 0
    }

    pub fn payload(&self) -> &'a [u8] {
        if self.raw.len() >= 24 {
            &self.raw[24..]
        } else {
            &[]
        }
    }

    pub fn word(&self, offset: usize) -> Option<u32> {
        if offset + 4 <= self.raw.len() {
            Some(u32::from_le_bytes(
                self.raw[offset..offset + 4].try_into().unwrap(),
            ))
        } else {
            None
        }
    }

    pub fn quad(&self, offset: usize) -> Option<u64> {
        if offset + 8 <= self.raw.len() {
            Some(u64::from_le_bytes(
                self.raw[offset..offset + 8].try_into().unwrap(),
            ))
        } else {
            None
        }
    }

    pub fn has_ndr_at(&self, offset: usize) -> bool {
        self.raw.get(offset..offset + 8) == Some(&NDR)
    }
}

#[derive(Debug, Clone)]
pub enum MigReply {
    /// Normal inline reply bytes (up to 72 bytes) with actual written length and optional complex flag
    Buffer {
        bytes: [u8; 72],
        size: usize,
        complex: bool,
    },
    /// Direct error code returned to the trap frame without writing a Mach reply body
    Status(u32),
}

impl MigReply {
    pub fn success_scalar(ret_code: u32) -> Self {
        let mut bytes = [0u8; 72];
        bytes[24..32].copy_from_slice(&NDR);
        bytes[32..36].copy_from_slice(&ret_code.to_le_bytes());
        Self::Buffer {
            bytes,
            size: 36,
            complex: false,
        }
    }

    pub fn failure(ret_code: u32) -> Self {
        Self::success_scalar(ret_code)
    }
}
