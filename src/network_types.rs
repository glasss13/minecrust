//! Types that are used to communicate over a TCP stream with the Minecraft Protocol.
//! A full list of the types can be found at https://wiki.vg/index.php?title=Protocol&oldid=7368#Data_types.
//!
//! Every type that is going to be received or sent should implement the [`NetworkType`] trait.

/// A trait that can be implemented on a [`BufRead`] to consume it and construct a [`NetworkType`].
///
/// [`BufRead`]: std::io::BufRead
pub(crate) trait NetworkTypeProducer
where
    Self: std::io::BufRead,
{
    /// Creates a network type from a [`std::io::BufRead`].
    ///
    /// # Panics
    ///
    /// This function will panic if the underlying reader was read, but returned an error.
    fn produce_network_type<T: NetworkType>(&mut self) -> Option<T> {
        let bytes = self.fill_buf().expect("Reached end of stream.");

        let size_to_consume = T::size_from_bytes(bytes)?;

        let result = T::from_bytes(bytes)?;
        self.consume(size_to_consume);

        Some(result)
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

    /// If no assumptions can be made about the data, this is the minimum amount of bytes recommended to be passed to [`size_from_bytes`] to determine
    /// the length.
    ///
    /// [`size_from_bytes`]: NetworkType::size_from_bytes
    const SIZE_TO_READ: usize;
}

/// A variable length, heap allocated, signed 32 bit integer type used over the [Minecraft network protocol](https://wiki.vg/index.php?title=Protocol&oldid=7368).
///
/// For internal byte encoding see https://wiki.vg/index.php?title=Protocol&oldid=7368#VarInt_and_VarLong.
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
            if bytes.get(i)? & 0b10000000 == 0 {
                if Varint::bytes_are_valid_varint(&bytes[0..=i]) {
                    return Some(i + 1);
                }
            }
        }
        None
    }

    fn size_as_bytes(&self) -> usize {
        self.bytes.len()
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

    /// Constructs a new `Varint` from `num`.
    pub(crate) fn from_i32(num: i32) -> Varint {
        let mut input = num;
        let mut temp_out_array = [0u8; 5];
        let mut array_pos = 0;

        while input != 0 {
            let mut temp_byte = (input & 0b01111111) as u8;
            // Convert to unsigned to enforce logical bit shift
            input = (input as u32 >> 7) as i32;

            if input != 0 {
                temp_byte |= 0b10000000;
            }

            temp_out_array[array_pos] = temp_byte;

            array_pos += 1;
        }

        let mut out_vec = Vec::with_capacity(array_pos);
        out_vec.extend_from_slice(&temp_out_array[0..array_pos]);

        Varint { bytes: out_vec }
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

        if buffer.last().unwrap() & 0b10000000 > 0 {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    mod varint {
        use super::super::*;

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

        macro_rules! test_from_bytes_vec {
            ($vec:expr) => {
                let bytes = $vec;
                let size = Varint::size_from_bytes(&bytes).unwrap();
                let varint = Varint::from_bytes(&bytes).unwrap();
                assert_eq!(varint.bytes, vec![0x7f]);
                assert_eq!(varint.bytes.len(), size);
            };
        }

        #[test]
        fn test_from_bytes() {
            test_from_bytes_vec!(vec![0x7f]);

            test_from_bytes_vec!(vec![0xff, 0xff, 0xff, 0xff, 0x0f]);

            let varint = Varint::from_bytes(&vec![0xff, 0xff, 0xff, 0xff, 0x0f, 0x0f]).unwrap();
            assert_eq!(varint.bytes, vec![0xff, 0xff, 0xff, 0xff, 0x0f]);

            let bad_varint = Varint::from_bytes(&vec![0xff]);
            assert!(bad_varint.is_none());

            let bad_varint = Varint::from_bytes(&vec![0xff, 0xff, 0xff, 0xff, 0xff]);
            assert!(bad_varint.is_none());

            let bad_varint = Varint::from_bytes(&vec![0xff, 0xff, 0xff, 0xff, 0xff, 0x0f]);
            assert!(bad_varint.is_none());
        }
    }
}
