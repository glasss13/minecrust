//! Types that are used to communicate over a TCP stream with the Minecraft Protocol.
//! A full list of the types can be found at <https://wiki.vg/index.php?title=Protocol&oldid=7368#Data_types>.
//!
//! Every type that is going to be received or sent should implement the [`NetworkType`] trait.

use std::convert::TryInto;

/// A trait that can be implemented on a [`BufRead`] to consume it and construct a [`NetworkType`].
///
/// [`BufRead`]: std::io::BufRead
pub(crate) trait NetworkTypeReader
where
    Self: std::io::BufRead,
{
    /// Creates a network type by consuming from a [`std::io::BufRead`].
    ///
    /// # Panics
    ///
    /// This function will panic if the underlying reader was read, but returned an error.
    fn read_network_type<T: NetworkType>(&mut self) -> Option<T> {
        let bytes = self.fill_buf().expect("Reached end of stream.");

        let size_to_consume = T::size_from_bytes(bytes)?;

        let result = T::from_bytes(bytes)?;
        self.consume(size_to_consume);

        Some(result)
    }

    /// Creates a network type by consuming from a [`std::io::BufRead`] but is different from `read_network_type` in that you can specify a size.
    ///
    /// This is useful for data types where the size is context dependant.
    ///
    /// The `NetworkType` in question's `from_bytes` function must use the length of the passed slice as the context-defined length.
    ///
    /// # Panics
    ///
    /// This function will panic if the underlying reader was read, but returned an error.
    fn read_network_type_with_size<T: NetworkType>(&mut self, size: usize) -> Option<T> {
        let bytes = self.fill_buf().expect("Reached end of stream.");

        let result = T::from_bytes(&bytes[0..size])?;
        self.consume(size);

        Some(result)
    }
}

pub(crate) trait NetworkTypeWriter
where
    Self: std::io::Write,
{
    fn write_network_type<T: NetworkType>(&mut self, network_type: &T) -> std::io::Result<()> {
        self.write_all(network_type.as_bytes())?;

        Ok(())
    }
}

/// Types that are used in the [Minecraft network protocol](https://wiki.vg/index.php?title=Protocol&oldid=7368).
pub(crate) trait NetworkType: Sized {
    /// Constructs the [`NetworkType`] from a collection of bytes.
    ///
    /// Returns [`None`] if the bytes don't encode the [`NetworkType`] properly.
    fn from_bytes(bytes: &[u8]) -> Option<Self>;

    /// Gets the size of the raw data of the [`NetworkType`] from a collection of bytes.
    ///
    /// For example, it can be used to determine how many bytes long a [`Varint`] is in a buffer of bytes.
    ///
    /// Often can be called with slices of length [`SIZE_TO_READ`]
    ///
    /// Returns [`None`] if the [`NetworkType`] is not encoded in the collection.
    ///
    /// [`SIZE_TO_READ`]: NetworkType::SIZE_TO_READ
    fn size_from_bytes(bytes: &[u8]) -> Option<usize>;

    /// Size of the [`NetworkType`] when represented as a pure stream of bytes.
    fn size_as_bytes(&self) -> usize;

    /// Returns the actual byte representation of the `NetworkType` to be sent over the stream.
    fn as_bytes(&self) -> &[u8];

    /// If no assumptions can be made about the data, this is the minimum amount of bytes recommended to be passed to [`size_from_bytes`] to determine
    /// the length.
    ///
    /// [`size_from_bytes`]: NetworkType::size_from_bytes
    const SIZE_TO_READ: usize;
}

/// A variable length, heap allocated, signed 32 bit integer type used over the [Minecraft network protocol](https://wiki.vg/index.php?title=Protocol&oldid=7368).
///
/// For internal byte encoding see <https://wiki.vg/index.php?title=Protocol&oldid=7368#VarInt_and_VarLong>.
#[derive(Debug)]
pub(crate) struct Varint {
    bytes: Vec<u8>,
}

impl NetworkType for Varint {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let sizeof_out_varint = Varint::size_from_bytes(bytes)?;

        Some(Varint {
            bytes: bytes[0..sizeof_out_varint].to_vec(),
        })
    }

    fn size_from_bytes(bytes: &[u8]) -> Option<usize> {
        for i in 0..Self::SIZE_TO_READ {
            if bytes.get(i)? & 0b10000000 == 0 && Varint::bytes_are_valid_varint(&bytes[0..=i]) {
                return Some(i + 1);
            }
        }
        None
    }

    fn size_as_bytes(&self) -> usize {
        self.bytes.len()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    const SIZE_TO_READ: usize = 5;
}

impl Varint
where
    Self: NetworkType,
{
    /// Constructs a new unallocated `Varint`.
    pub(crate) fn new() -> Varint {
        Varint { bytes: Vec::new() }
    }

    pub(crate) fn own_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Constructs a new `Varint` from `num`.
    pub(crate) fn from_i32(num: i32) -> Varint {
        let mut input = num;
        let mut temp_out_array = [0u8; 5];
        let mut output = Vec::with_capacity(5);

        for byte in &mut temp_out_array {
            let mut temp_byte = (input & 0b01111111) as u8;
            // Convert to unsigned to enforce logical bit shift
            input = (input as u32 >> 7) as i32;

            if input != 0 {
                temp_byte |= 0b10000000;
            }

            output.push(temp_byte);

            *byte = temp_byte;

            // array_pos += 1;

            if input == 0 {
                break;
            }
        }

        Varint { bytes: output }
    }

    /// Gets the value of the `Varint` as an `i32`.
    pub(crate) fn to_i32(&self) -> i32 {
        let mut result = 0;

        for (i, byte) in self.bytes.iter().enumerate() {
            let value = byte & 0b01111111;

            result |= (value as i32) << (i * 7);
        }
        result
    }

    pub(crate) fn size_from_int32(num: i32) -> usize {
        let mut input = num;
        for i in 0..5 {
            input = (input as u32 >> 7) as i32;

            if input == 0 {
                return i + 1;
            }
        }
        unreachable!();
    }

    /// Checks encoding of bytes for proper `Varint`.
    fn bytes_are_valid_varint(buffer: &[u8]) -> bool {
        if buffer.is_empty() || buffer.len() > 5 {
            return false;
        }

        for byte in buffer.iter().take(buffer.len() - 1) {
            if byte & 0b10000000 == 0 {
                return false;
            }
        }

        if buffer.last().unwrap() & 0b10000000 > 0 {
            return false;
        }

        true
    }
}

/// UTF-8 string prefixed with its size in bytes as a VarInt.
///
/// <https://wiki.vg/index.php?title=Protocol&oldid=7368#Data_types>.
#[derive(Debug)]
pub(crate) struct NetworkString {
    bytes: Vec<u8>,
}

impl NetworkString {
    pub(crate) fn from_string(string: &str) -> NetworkString {
        let str_bytes = string.as_bytes();

        let mut length_varint_bytes = Varint::from_i32(string.len() as i32).as_bytes().to_vec();

        length_varint_bytes.extend_from_slice(str_bytes);

        NetworkString {
            bytes: length_varint_bytes,
        }
    }

    pub(crate) fn len(&self) -> usize {
        Varint::from_bytes(&self.bytes).unwrap().to_i32() as usize
    }

    fn string_bytes(&self) -> &[u8] {
        let offset = Varint::size_from_bytes(&self.bytes).unwrap();
        &self.bytes[offset..]
    }
}

impl std::fmt::Display for NetworkString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            String::from_utf8(self.string_bytes().to_vec()).unwrap()
        )
    }
}

impl NetworkType for NetworkString {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let string_length_varint = Varint::from_bytes(bytes)?;
        let string_length = string_length_varint.to_i32();

        let sizeof_string_length = string_length_varint.as_bytes().len();

        Some(NetworkString {
            bytes: bytes
                .get(..string_length as usize + sizeof_string_length)?
                .to_vec(),
        })
    }

    fn size_from_bytes(bytes: &[u8]) -> Option<usize> {
        let string_length = Varint::from_bytes(bytes)?.to_i32();

        let sizeof_string_length = Varint::size_from_int32(string_length);

        Some(string_length as usize + sizeof_string_length)
    }

    fn size_as_bytes(&self) -> usize {
        self.bytes.len()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    const SIZE_TO_READ: usize = 5;
}

/// An integer between 0 and 65535.
///
/// Internally represents itself as a big endian array of two bytes. Returns and expects all byte arrays to be big endian.
///
/// <https://wiki.vg/index.php?title=Protocol&oldid=7368#Data_types>.
pub(crate) struct UnsignedShort {
    bytes: [u8; 2],
}

impl UnsignedShort {
    pub(crate) fn from_u16(val: u16) -> UnsignedShort {
        UnsignedShort {
            bytes: val.to_be_bytes(),
        }
    }
}

impl NetworkType for UnsignedShort {
    /// `bytes` must be big endian.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if UnsignedShort::size_from_bytes(bytes).is_some() {
            Some(UnsignedShort {
                bytes: bytes.try_into().ok()?,
            })
        } else {
            None
        }
    }

    fn size_from_bytes(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 2 {
            None
        } else {
            Some(2)
        }
    }

    fn size_as_bytes(&self) -> usize {
        2
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    const SIZE_TO_READ: usize = 2;
}

/// This is just a sequence of zero or more bytes, its meaning should be explained somewhere else, e.g. in the packet description. The length must also be known from the context.
///
/// <https://wiki.vg/index.php?title=Protocol&oldid=7368#Data_types>.
#[derive(Debug)]
pub(crate) struct ByteArray {
    bytes: Vec<u8>,
}

impl NetworkType for ByteArray {
    /// expects `bytes` to encode the length.
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(ByteArray {
            bytes: bytes.to_vec(),
        })
    }

    fn size_from_bytes(bytes: &[u8]) -> Option<usize> {
        Some(bytes.len())
    }

    fn size_as_bytes(&self) -> usize {
        self.bytes.len()
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// context dependant
    const SIZE_TO_READ: usize = 0;
}

#[cfg(test)]
mod tests {
    mod varint {
        use super::super::*;

        /// values from https://wiki.vg/index.php?title=Protocol&oldid=7368#VarInt_and_VarLong
        #[test]
        fn test_from_i32() {
            assert_eq!(Varint::size_from_int32(127), 1);
            assert_eq!(Varint::size_from_int32(128), 2);
            assert_eq!(Varint::size_from_int32(2097151), 3);
            assert_eq!(Varint::size_from_int32(2147483647), 5);
            assert_eq!(Varint::size_from_int32(-1), 5);

            let varint = Varint::from_i32(0);
            assert_eq!(varint.bytes, vec![0]);

            let varint = Varint::from_i32(127);
            assert_eq!(varint.bytes, vec![0x7f]);

            let varint = Varint::from_i32(128);
            assert_eq!(varint.bytes, vec![0x80, 0x01]);

            let varint = Varint::from_i32(2097151);
            assert_eq!(varint.bytes, vec![0xff, 0xff, 0x7f]);

            let varint = Varint::from_i32(2147483647);
            assert_eq!(varint.bytes, vec![0xff, 0xff, 0xff, 0xff, 0x07]);

            let varint = Varint::from_i32(-1);
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
            assert!(Varint::bytes_are_valid_varint(&[0x7f]));
            assert!(Varint::bytes_are_valid_varint(&[0x80, 0x01]));
            assert!(Varint::bytes_are_valid_varint(&[0xff, 0xff, 0x7f]));
            assert!(Varint::bytes_are_valid_varint(&[
                0xff, 0xff, 0xff, 0xff, 0x07
            ]));
            assert!(Varint::bytes_are_valid_varint(&[
                0xff, 0xff, 0xff, 0xff, 0x0f
            ]));

            assert!(!Varint::bytes_are_valid_varint(&[]));
            assert!(!Varint::bytes_are_valid_varint(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0x0f
            ]));
            assert!(!Varint::bytes_are_valid_varint(&[0xff, 0xff]));
        }

        macro_rules! test_from_bytes_vec {
            ($vec:expr) => {
                let bytes = $vec;
                let size = Varint::size_from_bytes(&bytes).unwrap();
                let varint = Varint::from_bytes(&bytes).unwrap();
                assert_eq!(varint.bytes, bytes);
                assert_eq!(varint.bytes.len(), size);
            };
        }

        #[test]
        fn test_from_bytes() {
            test_from_bytes_vec!(vec![0x7f]);

            test_from_bytes_vec!(vec![0xff, 0xff, 0xff, 0xff, 0x0f]);

            let varint = Varint::from_bytes(&[0xff, 0xff, 0xff, 0xff, 0x0f, 0x0f]).unwrap();
            assert_eq!(varint.bytes, vec![0xff, 0xff, 0xff, 0xff, 0x0f]);

            let bad_varint = Varint::from_bytes(&[0xff]);
            assert!(bad_varint.is_none());

            let bad_varint = Varint::from_bytes(&[0xff, 0xff, 0xff, 0xff, 0xff]);
            assert!(bad_varint.is_none());

            let bad_varint = Varint::from_bytes(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x0f]);
            assert!(bad_varint.is_none());
        }
    }

    mod string {
        use super::super::*;

        #[test]
        fn test_construct() {
            let string =
                NetworkString::from_bytes(String::from("\x0bhello there").as_bytes()).unwrap();

            assert_eq!(string.bytes, b"\x0bhello there");

            let string = NetworkString::from_bytes(String::from("\x02§").as_bytes()).unwrap();

            assert_eq!(string.bytes, "\x02§".as_bytes());

            let string = NetworkString::from_string("hello there");
            assert_eq!(string.as_bytes(), b"\x0bhello there");
        }
    }
}
