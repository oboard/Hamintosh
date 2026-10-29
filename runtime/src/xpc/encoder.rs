//! Zero-allocation XPC and Mach message reply encoder / builder.

use super::decoder::XpcDecoder;
use super::types::*;

pub struct XpcEncoder;

impl XpcEncoder {
    #[inline]
    pub fn put_word(bytes: &mut [u8], at: usize, value: u32) {
        if at + 4 <= bytes.len() {
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    #[inline]
    pub fn put_quad(bytes: &mut [u8], at: usize, value: u64) {
        if at + 8 <= bytes.len() {
            bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
    }
}

pub struct XpcReplyBuilder<'a> {
    buf: &'a mut [u8],
    cursor: usize,
    dict_length_offset: usize,
    dict_content_start: usize,
    dict_entry_count: u32,
}

impl<'a> XpcReplyBuilder<'a> {
    /// Initialize a simple Mach message reply carrying an XPC root dictionary.
    pub fn new_simple(buf: &'a mut [u8], reply_port: u32) -> Option<Self> {
        if buf.len() < 44 {
            return None;
        }
        buf.fill(0);
        XpcEncoder::put_word(buf, 0, 0x1200);
        XpcEncoder::put_word(buf, 12, reply_port);
        XpcEncoder::put_word(buf, 20, 0x2000_0000);
        XpcEncoder::put_word(buf, 24, XPC_MAGIC);
        XpcEncoder::put_word(buf, 28, XPC_VERSION);
        XpcEncoder::put_word(buf, 32, XPC_TYPE_DICTIONARY);
        Some(Self {
            buf,
            cursor: 44,
            dict_length_offset: 36,
            dict_content_start: 40,
            dict_entry_count: 0,
        })
    }

    /// Initialize a complex Mach message reply carrying 1 port descriptor and an XPC dictionary.
    pub fn new_complex_with_port(
        buf: &'a mut [u8],
        reply_port: u32,
        service_port: u32,
    ) -> Option<Self> {
        if buf.len() < 60 {
            return None;
        }
        buf.fill(0);
        XpcEncoder::put_word(buf, 0, 0x8000_1200);
        XpcEncoder::put_word(buf, 12, reply_port);
        XpcEncoder::put_word(buf, 20, 0x2000_0000);
        XpcEncoder::put_word(buf, 24, 1); // 1 descriptor
        XpcEncoder::put_word(buf, 28, service_port);
        XpcEncoder::put_word(buf, 32, 0);
        XpcEncoder::put_word(buf, 36, 17 << 16); // MACH_MSG_TYPE_PORT_SEND
        XpcEncoder::put_word(buf, 40, XPC_MAGIC);
        XpcEncoder::put_word(buf, 44, XPC_VERSION);
        XpcEncoder::put_word(buf, 48, XPC_TYPE_DICTIONARY);
        Some(Self {
            buf,
            cursor: 60,
            dict_length_offset: 52,
            dict_content_start: 56,
            dict_entry_count: 0,
        })
    }

    fn write_key(&mut self, key: &[u8]) -> Option<()> {
        let has_null = key.last() == Some(&0);
        let total_len = if has_null {
            key.len()
        } else {
            key.len().checked_add(1)?
        };
        let padded_len = XpcDecoder::padded(total_len)?;
        if self.cursor.checked_add(padded_len)? > self.buf.len() {
            return None;
        }
        self.buf[self.cursor..self.cursor + key.len()].copy_from_slice(key);
        if !has_null {
            self.buf[self.cursor + key.len()] = 0;
        }
        self.buf[self.cursor + total_len..self.cursor + padded_len].fill(0);
        self.cursor += padded_len;
        Some(())
    }

    pub fn put_int64(&mut self, key: &[u8], val: i64) -> Option<()> {
        self.write_key(key)?;
        if self.cursor.checked_add(12)? > self.buf.len() {
            return None;
        }
        XpcEncoder::put_word(self.buf, self.cursor, XPC_TYPE_INT64);
        self.cursor += 4;
        self.buf[self.cursor..self.cursor + 8].copy_from_slice(&val.to_le_bytes());
        self.cursor += 8;
        self.dict_entry_count += 1;
        Some(())
    }

    pub fn put_uint64(&mut self, key: &[u8], val: u64) -> Option<()> {
        self.write_key(key)?;
        if self.cursor.checked_add(12)? > self.buf.len() {
            return None;
        }
        XpcEncoder::put_word(self.buf, self.cursor, XPC_TYPE_UINT64);
        self.cursor += 4;
        self.buf[self.cursor..self.cursor + 8].copy_from_slice(&val.to_le_bytes());
        self.cursor += 8;
        self.dict_entry_count += 1;
        Some(())
    }

    pub fn put_bool(&mut self, key: &[u8], val: bool) -> Option<()> {
        self.write_key(key)?;
        if self.cursor.checked_add(8)? > self.buf.len() {
            return None;
        }
        XpcEncoder::put_word(self.buf, self.cursor, XPC_TYPE_BOOL);
        self.cursor += 4;
        XpcEncoder::put_word(self.buf, self.cursor, if val { 1 } else { 0 });
        self.cursor += 4;
        self.dict_entry_count += 1;
        Some(())
    }

    pub fn put_mach_send(&mut self, key: &[u8]) -> Option<()> {
        self.write_key(key)?;
        if self.cursor.checked_add(8)? > self.buf.len() {
            return None;
        }
        XpcEncoder::put_word(self.buf, self.cursor, XPC_TYPE_MACH_SEND);
        self.cursor += 4;
        XpcEncoder::put_word(self.buf, self.cursor, 0);
        self.cursor += 4;
        self.dict_entry_count += 1;
        Some(())
    }

    pub fn put_string(&mut self, key: &[u8], val: &[u8]) -> Option<()> {
        self.write_key(key)?;
        let has_null = val.last() == Some(&0);
        let str_len = if has_null {
            val.len()
        } else {
            val.len().checked_add(1)?
        };
        let padded_len = XpcDecoder::padded(str_len)?;
        let total_needed = 8usize.checked_add(padded_len)?;
        if self.cursor.checked_add(total_needed)? > self.buf.len() {
            return None;
        }
        XpcEncoder::put_word(self.buf, self.cursor, XPC_TYPE_STRING);
        XpcEncoder::put_word(self.buf, self.cursor + 4, str_len as u32);
        self.cursor += 8;
        self.buf[self.cursor..self.cursor + val.len()].copy_from_slice(val);
        if !has_null {
            self.buf[self.cursor + val.len()] = 0;
        }
        self.buf[self.cursor + str_len..self.cursor + padded_len].fill(0);
        self.cursor += padded_len;
        self.dict_entry_count += 1;
        Some(())
    }

    /// Complete serialization and return the total Mach message byte count.
    pub fn finish(self) -> Option<usize> {
        let total_size = self.cursor;
        let dict_payload_size = total_size.checked_sub(self.dict_content_start)?;
        XpcEncoder::put_word(self.buf, 4, total_size as u32);
        XpcEncoder::put_word(self.buf, self.dict_length_offset, dict_payload_size as u32);
        XpcEncoder::put_word(self.buf, self.dict_content_start, self.dict_entry_count);
        Some(total_size)
    }
}

impl XpcEncoder {
    pub fn build_bootstrap_service_reply(
        bytes: &mut [u8; 512],
        port: u32,
        service: u32,
        request_pid: u32,
        request_execcnt: u32,
    ) -> usize {
        let mut b = XpcReplyBuilder::new_complex_with_port(bytes, port, service).expect("buffer space");
        b.put_mach_send(b"port").expect("put port");
        b.put_uint64(b"req_pid", u64::from(request_pid))
            .expect("put req_pid");
        b.put_uint64(b"rec_execcnt", u64::from(request_execcnt))
            .expect("put rec_execcnt");
        b.finish().expect("finish")
    }

    pub fn build_bootstrap_lookup_error(
        bytes: &mut [u8; 512],
        port: u32,
        request_pid: u32,
        request_execcnt: u32,
    ) -> usize {
        let mut b = XpcReplyBuilder::new_simple(bytes, port).expect("buffer space");
        b.put_int64(b"error", 3).expect("put error"); // ESRCH
        b.put_int64(b"req_pid", i64::from(request_pid))
            .expect("put req_pid");
        b.put_int64(b"rec_execcnt", i64::from(request_execcnt))
            .expect("put rec_execcnt");
        b.finish().expect("finish")
    }

    pub fn build_rbs_unavailable_reply(bytes: &mut [u8; 512], port: u32) -> usize {
        let mut b = XpcReplyBuilder::new_simple(bytes, port).expect("buffer space");
        b.put_int64(b"__RBSXPCError__", 1)
            .expect("put __RBSXPCError__");
        b.finish().expect("finish")
    }

    pub fn build_preferences_unavailable_reply(bytes: &mut [u8; 512], port: u32) -> usize {
        let mut b = XpcReplyBuilder::new_simple(bytes, port).expect("buffer space");
        b.put_int64(b"CFPreferencesErrorType", 0)
            .expect("put CFPreferencesErrorType");
        b.put_bool(b"CFPreferencesErrorClientFault", false)
            .expect("put CFPreferencesErrorClientFault");
        b.put_string(
            b"CFPreferencesErrorDescription",
            b"Harmonios preferences service is unavailable",
        )
        .expect("put CFPreferencesErrorDescription");
        b.finish().expect("finish")
    }
}
