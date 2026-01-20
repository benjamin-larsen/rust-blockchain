// All integer types are Little Endian variant.

#[derive(Debug)]
pub enum ReadError {
    Error
}

pub fn try_read_array<const N: usize>(buf: &[u8], offset: &mut usize) -> Result<[u8; N], ReadError> {
    let start_offset = *offset;
    let end_offset = start_offset + N;

    *offset += N;

    buf[start_offset..end_offset].try_into().map_err(|_| ReadError::Error)
}

pub fn try_read_uint16(buf: &[u8], offset: &mut usize) -> Result<u16, ReadError> {
    Ok(
        u16::from_le_bytes(
            try_read_array::<2>(buf, offset)?
        )
    )
}

pub fn read_uint16(buf: &[u8], offset: &mut usize) -> u16 {
    try_read_uint16(buf, offset).expect("Read UInt16 failed")
}

pub fn try_read_uint32(buf: &[u8], offset: &mut usize) -> Result<u32, ReadError> {
    Ok(
        u32::from_le_bytes(
            try_read_array::<4>(buf, offset)?
        )
    )
}

pub fn read_uint32(buf: &[u8], offset: &mut usize) -> u32 {
    try_read_uint32(buf, offset).expect("Read UInt32 failed")
}

pub fn try_read_uint64(buf: &[u8], offset: &mut usize) -> Result<u64, ReadError> {
    Ok(
        u64::from_le_bytes(
            try_read_array::<8>(buf, offset)?
        )
    )
}

pub fn read_uint64(buf: &[u8], offset: &mut usize) -> u64 {
    try_read_uint64(buf, offset).expect("Read UInt64 failed")
}