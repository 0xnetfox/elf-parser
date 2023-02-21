#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct Address(u64);

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Address({:#08x})", self.0)
    }
}

pub trait GenericBytes<const N: usize> {
    fn from_le_bytes(bytes: [u8; N]) -> Self;
    fn from_be_bytes(bytes: [u8; N]) -> Self;
}

impl GenericBytes<2> for u16 {
    fn from_le_bytes(bytes: [u8; 2]) -> Self { u16::from_le_bytes(bytes) }
    fn from_be_bytes(bytes: [u8; 2]) -> Self { u16::from_be_bytes(bytes) }
}

impl GenericBytes<4> for u32 {
    fn from_le_bytes(bytes: [u8; 4]) -> Self { u32::from_le_bytes(bytes) }
    fn from_be_bytes(bytes: [u8; 4]) -> Self { u32::from_be_bytes(bytes) }
}

impl GenericBytes<8> for u64 {
    fn from_le_bytes(bytes: [u8; 8]) -> Self { u64::from_le_bytes(bytes) }
    fn from_be_bytes(bytes: [u8; 8]) -> Self { u64::from_be_bytes(bytes) }
}

impl GenericBytes<8> for Address {
    fn from_le_bytes(bytes: [u8; 8]) -> Self {
        Address(u64::from_le_bytes(bytes))
    }

    fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Address(u64::from_be_bytes(bytes))
    }
}