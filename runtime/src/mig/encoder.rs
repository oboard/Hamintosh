use super::message::NDR;

pub struct MigEncoder;

impl MigEncoder {
    pub fn write_word(buf: &mut [u8], offset: usize, value: u32) {
        if offset + 4 <= buf.len() {
            buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    pub fn write_quad(buf: &mut [u8], offset: usize, value: u64) {
        if offset + 8 <= buf.len() {
            buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
    }

    pub fn write_ndr(buf: &mut [u8], offset: usize) {
        if offset + 8 <= buf.len() {
            buf[offset..offset + 8].copy_from_slice(&NDR);
        }
    }

    pub fn write_port_descriptor(buf: &mut [u8], offset: usize, port: u32, disposition: u32) {
        Self::write_word(buf, offset, port);
        Self::write_word(buf, offset + 4, 0);
        Self::write_word(buf, offset + 8, (disposition & 0xff) << 16);
    }
}
