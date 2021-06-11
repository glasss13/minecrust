//! A growable, heap-allocated stream of bytes that can be manipulated with the `FromByteBuffer` trait

/// The main interface between [`ByteBuffer`] and [`network_types`].
///
/// Implementing this trait for a type allows the type to be constructed out of a [`ByteBuffer`].
///
///
/// [`network_types`]: crate::network_types
pub(crate) trait FromByteBuffer: Sized {
    fn from_byte_buffer(buffer: &ByteBuffer) -> Option<Self>;

    fn size_from_byte_buffer(buffer: &ByteBuffer) -> Option<usize>;
}

/// Represents a stream of bytes and allows for conversion to and from different types.
/// Internally keeps track of position in the buffer to allow for behavior similar to `Iterators`.
///
/// Differs from [`Vec`] in terms of memory as all memory allocations are explicit using functions like [`with_size`] or [`resize`]
///
/// Used in conjunction with [`FromByteBuffer`].
///
/// [`with_size`]: crate::byte_buffer::ByteBuffer::with_size
/// [`resize`]: crate::byte_buffer::ByteBuffer::resize
pub(crate) struct ByteBuffer {
    buffer: Vec<u8>,
    position: Option<usize>,
}

impl ByteBuffer {
    /// Constructs a new, empty `ByteBuffer` with an uninitialized position
    ///
    /// Does not allocate until told to with [`resize`]
    ///
    /// [`resize`]: crate::byte_buffer::ByteBuffer::resize
    pub(crate) fn new() -> ByteBuffer {
        ByteBuffer {
            buffer: Vec::new(),
            position: None,
        }
    }

    /// Constructs a new `ByteBuffer` with the specified size at position 0.
    pub(crate) fn with_size(size: usize) -> ByteBuffer {
        if size == 0 {
            return ByteBuffer::new();
        }

        ByteBuffer {
            buffer: Vec::with_capacity(size),
            position: Some(0),
        }
    }

    /// Changes the size of the buffer.
    ///
    /// If the current position would be out of bounds after the resize, the position is set to the last position otherwise it is preserved
    ///
    /// # Notes
    ///
    /// This function is very expensive.
    pub(crate) fn resize(&mut self, new_size: usize) {
        // make sure the `position` is updated properly
        if new_size == 0 {
            self.position = None;
        } else if self.position == None {
            self.position = Some(0);
        } else if self.position.unwrap() >= new_size {
            self.position = Some(new_size - 1);
        }

        let mut new_buf = Vec::with_capacity(new_size);

        if self.buffer.capacity() > new_size {
            new_buf.extend_from_slice(&self.buffer[..new_size]);
        } else {
            new_buf.extend_from_slice(&self.buffer);
        }

        self.buffer = new_buf;
    }

    /// Gets the number of bytes not yet consumed - calculated off the current internal position.
    ///
    /// If the position is uninitialized returns 0.
    pub(crate) fn bytes_not_consumed(&self) -> usize {
        self.buffer.len() - self.position.unwrap_or_else(|| self.buffer.len())
    }

    /// Used with the [`FromByteBuffer`] trait to try to consume a buffer and construct the generically specified type
    ///
    /// Returns `None` if it out of bounds or the buffer hasn't been filled to the position yet.
    /// Also if the type is not encoded in the buffer properly.
    pub(crate) fn consume<T: FromByteBuffer>(&mut self) -> Option<T> {
        let out = T::from_byte_buffer(self);

        if let Some(_) = out {
            self.position = Some(self.position? + T::size_from_byte_buffer(self)?);
        }
        out
    }

    /// Consume the passed amount of bytes
    ///
    /// Returns `None` if it out of bounds or the buffer hasn't been filled to the position yet.
    pub(crate) fn consume_bytes(&mut self, num_bytes: usize) -> Option<&[u8]> {
        let position = self.position?;
        let out = self.buffer.get(position..position + num_bytes);

        if let Some(_) = out {
            self.position = Some(position + num_bytes);
        }
        out
    }

    /// Peeking is similar to consuming except it don't increment the internal position.
    /// Because it doesn't increment the internal position it doesn't effectively consume the bytes, hence why it "peeks."
    ///
    /// Returns `None` if it out of bounds or the buffer hasn't been filled to the position yet.
    pub(crate) fn peek_bytes(&self, num_bytes: usize) -> Option<&[u8]> {
        let position = self.position?;
        self.buffer.get(position..position + num_bytes)
    }

    /// Similar to [`peek_bytes`] except it guarantees that it returns a valid buffer.
    /// This is possible because it will return either up to the amount of bytes specified or until the end of the bound of the buffer, whichever comes first.
    ///
    /// [`peek_bytes`]: crate::byte_buffer::ByteBuffer::peek_bytes
    pub(crate) fn peek_up_to_bytes(&self, num_bytes: usize) -> &[u8] {
        let bytes_to_peak = num_bytes.min(self.bytes_not_consumed());

        self.peek_bytes(bytes_to_peak).unwrap()
    }
}
