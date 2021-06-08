pub trait FromByteBuffer: Sized {
    fn from_byte_buffer(buffer: &ByteBuffer) -> Option<Self>;

    fn size_from_byte_buffer(buffer: &ByteBuffer) -> Option<usize>;
}

pub struct ByteBuffer {
    buffer: Vec<u8>,
    position: usize,
}

impl ByteBuffer {
    pub fn new() -> ByteBuffer {
        ByteBuffer {
            buffer: Vec::new(),
            position: 0,
        }
    }

    pub fn with_size(size: usize) -> ByteBuffer {
        ByteBuffer {
            buffer: Vec::with_capacity(size),
            position: 0,
        }
    }

    pub fn resize(&mut self, new_size: usize) {
        self.buffer.resize(new_size, 0);
    }

    pub fn bytes_not_consumed(&self) -> usize {
        self.buffer.len() - self.position
    }

    pub fn consume<T: FromByteBuffer>(&mut self) -> Option<T> {
        T::from_byte_buffer(self)
    }

    pub fn consume_bytes(&mut self, num_bytes: usize) -> Option<&[u8]> {
        let out = self.buffer.get(self.position..self.position + num_bytes);
        self.position += num_bytes;
        out
    }

    pub fn peek_bytes(&self, num_bytes: usize) -> Option<&[u8]> {
        self.buffer.get(self.position..self.position + num_bytes)
    }

    pub fn peek_up_to_bytes(&self, num_bytes: usize) -> &[u8] {
        let bytes_to_peak = num_bytes.min(self.bytes_not_consumed());

        self.peek_bytes(bytes_to_peak).unwrap()
    }
}
