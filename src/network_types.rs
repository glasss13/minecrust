use crate::byte_buffer::{ByteBuffer, FromByteBuffer};

/// A variable length, dynamically allocated, signed 32 bit integer type used over the [Minecraft network protocol](https://wiki.vg/index.php?title=Protocol&oldid=7368).
///
/// For internal byte encoding see https://wiki.vg/index.php?title=Protocol&oldid=7368#VarInt_and_VarLong.
pub(crate) struct Varint {
    bytes: Vec<u8>,
}

impl FromByteBuffer for Varint {
    fn from_byte_buffer(buffer: &mut ByteBuffer) -> Option<Self> {
        let bytes = buffer.consume_bytes(Varint::size_from_byte_buffer(buffer)?)?;

        Varint::from_slice(bytes)
    }

    fn size_from_byte_buffer(buffer: &ByteBuffer) -> Option<usize> {
        let bytes = buffer.peek_up_to_bytes(Varint::MAX_SIZE);
        for (i, byte) in bytes.into_iter().enumerate() {
            if byte & 0b10000000 == 0 {
                return Some(i + 1);
            }
        }
        None
    }
}

impl Varint {
    /// Maximum possible size in bytes of a `Varint`.
    pub(crate) const MAX_SIZE: usize = 5;

    /// Constructs a new unallocated `Varint`.
    pub(crate) fn new() -> Varint {
        Varint { bytes: Vec::new() }
    }

    /// Constructs a new `Varint` from `num`.
    pub(crate) fn from_i32(num: i32) -> Varint {
        let mut input = num;
        let mut out_vec = Vec::new();

        while input != 0 {
            let mut temp_byte = (input & 0b01111111) as u8;
            // Convert to unsigned to enforce logical bit shift
            input = (input as u32 >> 7) as i32;

            if input != 0 {
                temp_byte |= 0b10000000;
            }

            out_vec.push(temp_byte);
        }

        Varint { bytes: out_vec }
    }

    /// Constructs a `Varint` from a slice of `u8`'s and copies.
    ///
    /// Returns `None` if the passed bytes are not encoded properly as a `Varint`
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Varint> {
        if !Varint::bytes_are_valid_varint(bytes) {
            return None;
        }

        Some(Varint {
            bytes: bytes.to_vec(),
        })
    }

    /// Gets the value of the `Varint` as an `i32`.
    pub(crate) fn to_i32(&self) -> i32 {
        let test = 32;

        let mut result = 0;

        for (i, byte) in self.bytes.iter().enumerate() {
            let value = byte & 0b01111111;

            result |= (value as i32) << (i * 7);
        }
        result
    }

    /// Checks encoding of bytes for proper `Varint`.
    fn bytes_are_valid_varint(buffer: &[u8]) -> bool {
        if buffer.len() < 1 || buffer.len() > 5 {
            return false;
        }

        for i in 0..buffer.len() - 1 {
            if buffer[i] & 0b10000000 == 0 {
                return false;
            }
        }

        if buffer.last().unwrap() & 0b10000000 == 128 {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// values from https://wiki.vg/index.php?title=Protocol&oldid=7368#VarInt_and_VarLong
    #[test]
    fn test_from_i32() {
        let mut varint = Varint::from_i32(127);
        assert_eq!(varint.bytes, vec![0x7f]);

        varint = Varint::from_i32(128);
        assert_eq!(varint.bytes, vec![0x80, 0x01]);

        varint = Varint::from_i32(2097151);
        assert_eq!(varint.bytes, vec![0xff, 0xff, 0x7f]);

        varint = Varint::from_i32(2147483647);
        assert_eq!(varint.bytes, vec![0xff, 0xff, 0xff, 0xff, 0x07]);

        varint = Varint::from_i32(-1);
        assert_eq!(varint.bytes, vec![0xff, 0xff, 0xff, 0xff, 0x0f]);
    }

    #[test]
    fn test_to_i32() {
        let mut varint = Varint::from_i32(127);
        assert_eq!(varint.to_i32(), 127);

        varint = Varint::from_i32(128);
        assert_eq!(varint.to_i32(), 128);

        varint = Varint::from_i32(2097151);
        assert_eq!(varint.to_i32(), 2097151);

        varint = Varint::from_i32(2147483647);
        assert_eq!(varint.to_i32(), 2147483647);

        varint = Varint::from_i32(-1);
        assert_eq!(varint.to_i32(), -1);
    }

    #[test]
    fn test_valid_varint() {
        assert!(Varint::bytes_are_valid_varint(&vec![0x7f]));
        assert!(Varint::bytes_are_valid_varint(&vec![0x80, 0x01]));
        assert!(Varint::bytes_are_valid_varint(&vec![0xff, 0xff, 0x7f]));
        assert!(Varint::bytes_are_valid_varint(&vec![
            0xff, 0xff, 0xff, 0xff, 0x07
        ]));
        assert!(Varint::bytes_are_valid_varint(&vec![
            0xff, 0xff, 0xff, 0xff, 0x0f
        ]));

        assert!(!Varint::bytes_are_valid_varint(&vec![]));
        assert!(!Varint::bytes_are_valid_varint(&vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0x0f
        ]));
        assert!(!Varint::bytes_are_valid_varint(&vec![0xff, 0xff]));
    }

    #[test]
    fn test_from_slice() {
        let mut varint = Varint::from_slice(&vec![0x7f]).unwrap();
        assert_eq!(varint.bytes, vec![0x7f]);

        varint = Varint::from_slice(&vec![0xff, 0xff, 0xff, 0xff, 0x0f]).unwrap();
        assert_eq!(varint.bytes, vec![0xff, 0xff, 0xff, 0xff, 0x0f]);

        let none_varint = Varint::from_slice(&vec![0xff, 0xff, 0xff, 0xff, 0xff, 0x0f]);
        match none_varint {
            Some(_) => assert!(false),
            None => assert!(true),
        }
    }

    #[test]
    fn test_from_byte_buffer_fns() {
        let mut buffer = ByteBuffer::with_size(3);
        buffer.buffer_mut().append(&mut vec![0xff, 0xff, 0x7f]);
        assert_eq!(Varint::size_from_byte_buffer(&buffer).unwrap(), 3);

        let varint = Varint::from_byte_buffer(&mut buffer).unwrap();
        assert_eq!(varint.bytes, vec![0xff, 0xff, 0x7f])
    }
}
