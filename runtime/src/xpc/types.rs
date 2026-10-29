//! XPC wire protocol constants and value representations.

pub const XPC_MAGIC: u32 = 0x4058_5043; // "CPX@" in little-endian
pub const XPC_VERSION: u32 = 5;

pub const XPC_TYPE_NULL: u32 = 0x1000;
pub const XPC_TYPE_BOOL: u32 = 0x2000;
pub const XPC_TYPE_INT64: u32 = 0x3000;
pub const XPC_TYPE_UINT64: u32 = 0x4000;
pub const XPC_TYPE_STRING: u32 = 0x9000;
pub const XPC_TYPE_UUID: u32 = 0xa000;
pub const XPC_TYPE_MACH_SEND: u32 = 0xd000;
pub const XPC_TYPE_ARRAY: u32 = 0xe000;
pub const XPC_TYPE_DICTIONARY: u32 = 0xf000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Value<'a> {
    pub kind: u32,
    pub body: &'a [u8],
    pub count: u32,
}
