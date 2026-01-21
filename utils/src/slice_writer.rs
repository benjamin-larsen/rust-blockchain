// All integer types are Little Endian variant.

#[derive(Debug)]
pub struct WriteError;

pub fn try_write_array<const N: usize>(src: &[u8; N], dest: &mut [u8], offset: &mut usize) -> Result<(), WriteError> {
    let start_offset = *offset;
    let end_offset = start_offset + N;

    if end_offset > dest.len() {
        return Err(WriteError);
    }

    *offset += N;

    dest[start_offset..end_offset].copy_from_slice(src.as_slice());

    Ok(())
}

pub fn try_write_uint16(src: u16, dest: &mut [u8], offset: &mut usize) -> Result<(), WriteError> {
    try_write_array(&src.to_le_bytes(), dest, offset)
}

pub fn write_uint16(src: u16, dest: &mut [u8], offset: &mut usize) {
    try_write_uint16(src, dest, offset).expect("Write UInt16 failed")
}

pub fn try_write_uint32(src: u32, dest: &mut [u8], offset: &mut usize) -> Result<(), WriteError> {
    try_write_array(&src.to_le_bytes(), dest, offset)
}

pub fn write_uint32(src: u32, dest: &mut [u8], offset: &mut usize) {
    try_write_uint32(src, dest, offset).expect("Write UInt32 failed")
}

pub fn try_write_uint64(src: u64, dest: &mut [u8], offset: &mut usize) -> Result<(), WriteError> {
    try_write_array(&src.to_le_bytes(), dest, offset)
}

pub fn write_uint64(src: u64, dest: &mut [u8], offset: &mut usize) {
    try_write_uint64(src, dest, offset).expect("Write UInt64 failed")
}