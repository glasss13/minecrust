//! A growable, heap-allocated stream of bytes that can be manipulated with the `FromByteBuffer` trait

/// The main interface between [`ByteBuffer`] and [`network_types`].
///
/// Implementing this trait for a type allows the type to be constructed out of a [`ByteBuffer`].
///
///
/// [`network_types`]: crate::network_types
pub trait FromByteBuffer: Sized {
    fn from_byte_buffer(buffer: &ByteBuffer) -> Option<Self>;

    fn size_from_byte_buffer(buffer: &ByteBuffer) -> Option<usize>;
}

/// Represents a stream of bytes and allows for conversion to and from different types.
/// Internally keeps track of position in the buffer to allow for behavior similiar to `Iterators`.
///
/// Used in conjuction with [`FromByteBuffer`].
pub struct ByteBuffer {
    buffer: Vec<u8>,
    position: usize,
}

impl ByteBuffer {
    /// Constructs a new, empty `ByteBuffer` at position 0.
    ///
    /// Does not allocate until told to with [`resize`]
    ///
    /// [`resize`]: crate::byte_buffer::ByteBuffer::resize
    pub fn new() -> ByteBuffer {
        ByteBuffer {
            buffer: Vec::new(),
            position: 0,
        }
    }

    /// Constructs a new `ByteBuffer` with the specified size at position 0.
    pub fn with_size(size: usize) -> ByteBuffer {
        ByteBuffer {
            buffer: Vec::with_capacity(size),
            position: 0,
        }
    }

    /// Changes the size of the buffer in place, if expanding fills with zeros
    ///
    /// If the current position would be out of bounds after the resize, the position is set to the last position
    pub fn resize(&mut self, new_size: usize) {
        if self.position >= new_size {
            self.position = new_size - 1;
        }
        self.buffer.resize(new_size, 0);
    }

    /// Gets the number of bytes not yet consumed - calculated off the current internal position
    pub fn bytes_not_consumed(&self) -> usize {
        self.buffer.len() - self.position
    }

    /// Used with the [`FromByteBuffer`] trait to try to consume a buffer and construct the generically specified type
    ///
    /// Returns `None` if the buffer runs out or if the type is not encoded in the buffer
    pub fn consume<T: FromByteBuffer>(&mut self) -> Option<T> {
        T::from_byte_buffer(self)
    }

    /// Consume the passed amount of bytes
    ///
    /// Returns `None` if it reaches the end of the buffer before it gets all the bytes
    pub fn consume_bytes(&mut self, num_bytes: usize) -> Option<&[u8]> {
        let out = self.buffer.get(self.position..self.position + num_bytes);

        if let Some(ret_bytes) = out {
            self.position += num_bytes;
            return out;
        }
        None
    }

    /// Peeking is similiar to consuming except it doen't increment the internal position.
    /// Because it doesn't increment the internal position it doesn't effectively consume the bytes, hence why it "peeks."
    ///
    /// Returns none if the buffer isn't big enough
    pub fn peek_bytes(&self, num_bytes: usize) -> Option<&[u8]> {
        self.buffer.get(self.position..self.position + num_bytes)
    }

    /// Similiar to [`peek_bytes`] except it guarantees that it returns a valid buffer.
    /// This is possible because it will return either up to the amount of bytes specified or until the end of the buffer, whichever comes first.
    ///
    /// [`peek_bytes`]: crate::byte_buffer::ByteBuffer::peek_bytes
    pub fn peek_up_to_bytes(&self, num_bytes: usize) -> &[u8] {
        let bytes_to_peak = num_bytes.min(self.bytes_not_consumed());

        self.peek_bytes(bytes_to_peak).unwrap()
    }
}
