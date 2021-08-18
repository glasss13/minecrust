use super::network_type::NetworkType;
use super::packets::ConnectionState;

use aes::cipher::{AsyncStreamCipher, NewCipher};
use aes::Aes128;
use bytes::{Buf, BufMut, BytesMut};
use cfb8::Cfb8;
use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

#[derive(Default)]
struct EncryptionState {
    encryption_enabled: bool,
    aes_encrypt_cipher: Option<Cfb8<Aes128>>,
    aes_decrypt_cipher: Option<Cfb8<Aes128>>,
}

impl EncryptionState {
    fn new() -> EncryptionState {
        EncryptionState {
            aes_decrypt_cipher: None,
            aes_encrypt_cipher: None,
            encryption_enabled: false,
        }
    }

    fn encryption_cipher(&mut self) -> Option<&mut Cfb8<Aes128>> {
        self.aes_encrypt_cipher.as_mut()
    }

    fn decryption_cipher(&mut self) -> Option<&mut Cfb8<Aes128>> {
        self.aes_decrypt_cipher.as_mut()
    }
}

struct CompressionState {
    // compressor: CompressorOxide,
    decompressor: DecompressorOxide,
    threshold: i32,
    /// buffer to hold compressed data - only used if compression is actually enabled.
    decompressed_buffer: BytesMut,
}

impl CompressionState {
    fn new() -> CompressionState {
        let decompressed_buffer = BytesMut::from(vec![0; 4096].as_slice());
        println!(
            "length of decompressed buffer: {}",
            decompressed_buffer.len()
        );
        CompressionState {
            // compressor: CompressorOxide::default(),
            decompressor: DecompressorOxide::default(),
            threshold: -1,
            decompressed_buffer,
        }
    }
}

pub(crate) struct BufferedReader {
    stream: OwnedReadHalf,
    buffer: BytesMut,
}

impl BufferedReader {
    pub(crate) fn new(stream: OwnedReadHalf) -> BufferedReader {
        BufferedReader::with_capacity(stream, 4096)
    }

    pub(crate) fn with_capacity(stream: OwnedReadHalf, capacity: usize) -> BufferedReader {
        BufferedReader {
            stream,
            buffer: BytesMut::with_capacity(capacity),
        }
    }
}

pub(crate) struct Connection {
    reader: BufferedReader,
    writer: BufWriter<OwnedWriteHalf>,
    connection_state: ConnectionState,
    encryption_state: EncryptionState,
    compression_state: CompressionState,
}

impl Connection {
    async fn read_buf(&mut self) -> Result<usize, std::io::Error> {
        let bytes_read = self.reader.stream.read_buf(&mut self.reader.buffer).await?;

        if bytes_read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection reset by peer",
            ));
        }

        if self.encryption_enabled() {
            let decryption_starting_idx = self.reader.buffer.len() - bytes_read;

            self.encryption_state.decryption_cipher().unwrap().decrypt(
                &mut self.reader.buffer
                    [decryption_starting_idx..bytes_read + decryption_starting_idx],
            );
        }
        Ok(bytes_read)
    }

    async fn write_all(&mut self, to_write: &[u8]) -> Result<(), std::io::Error> {
        todo!()
    }

    pub(crate) async fn new(ip: String, port: u16) -> Result<Connection, std::io::Error> {
        let stream = TcpStream::connect((ip, port)).await?;

        let (reader, writer) = stream.into_split();

        Ok(Connection {
            reader: BufferedReader::with_capacity(reader, 1000000),
            writer: BufWriter::new(writer),
            connection_state: ConnectionState::Handshaking,
            encryption_state: EncryptionState::default(),
            compression_state: CompressionState::new(),
        })
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), std::io::Error> {
        self.writer.shutdown().await
    }

    pub(crate) async fn read_network_type<T: NetworkType>(&mut self) -> Result<T, std::io::Error> {
        while self.reader.buffer.remaining() < T::SIZE_TO_READ {
            self.read_buf().await?;
        }

        loop {
            let size = T::size_from_bytes(&self.reader.buffer)?;
            if size <= self.reader.buffer.remaining() {
                return T::from_bytes(&self.reader.buffer[..size]).map(|output| {
                    self.reader.buffer.advance(size);
                    output
                });
            }

            self.read_buf().await?;
        }
    }

    pub(crate) async fn read_network_type_with_size<T: NetworkType>(
        &mut self,
        size: usize,
    ) -> Result<T, std::io::Error> {
        while self.reader.buffer.remaining() < size {
            self.read_buf().await?;
        }

        T::from_bytes(&self.reader.buffer[..size]).map(|output| {
            self.reader.buffer.advance(size);
            output
        })
    }

    pub(crate) async fn write_network_type<T: NetworkType>(
        &mut self,
        network_type: &T,
    ) -> Result<(), std::io::Error> {
        let to_write = network_type.as_bytes();

        if self.encryption_enabled() {
            let mut to_write = vec![0; to_write.len()];
            to_write.clone_from_slice(network_type.as_bytes());
            self.encryption_state
                .encryption_cipher()
                .unwrap()
                .encrypt(&mut to_write);
        }
        self.writer.write_all(to_write).await
    }

    pub(crate) async fn flush_writer(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush().await
    }

    pub(crate) fn connection_state(&self) -> ConnectionState {
        self.connection_state
    }

    pub(crate) fn encryption_enabled(&self) -> bool {
        self.encryption_state.encryption_enabled
    }

    pub(crate) fn enable_encryption(&mut self, shared_secret: &[u8; 16]) {
        type AesCfb8 = Cfb8<Aes128>;

        let cipher_encrypt = AesCfb8::new_from_slices(shared_secret, shared_secret).unwrap();
        let cipher_decrypt = AesCfb8::new_from_slices(shared_secret, shared_secret).unwrap();

        self.encryption_state.encryption_enabled = true;
        self.encryption_state.aes_encrypt_cipher = Some(cipher_encrypt);
        self.encryption_state.aes_decrypt_cipher = Some(cipher_decrypt);
    }

    pub(crate) fn set_connection_state(&mut self, new_state: ConnectionState) {
        self.connection_state = new_state;
    }

    pub(crate) fn set_compression(&mut self, threshold: i32) {
        self.compression_state.threshold = threshold;
    }

    pub(crate) fn compression_threshold(&self) -> i32 {
        self.compression_state.threshold
    }

    pub(crate) fn compression_enabled(&self) -> bool {
        self.compression_state.threshold > 0
    }

    pub(crate) async fn decompress_data(
        &mut self,
        data_length: usize,
    ) -> Result<(), std::io::Error> {
        while self.reader.buffer.remaining() < data_length {
            self.read_buf().await?;
        }

        let (_, _, decompressed_length) = decompress(
            &mut self.compression_state.decompressor,
            &self.reader.buffer[..data_length],
            &mut self.compression_state.decompressed_buffer[..],
            0,
            inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
                | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        self.reader.buffer.advance(data_length);

        // put the decompressed data at the start of the buffer
        self.reader.buffer.reverse();
        self.compression_state.decompressed_buffer.reverse();

        self.reader.buffer.put_slice(
            &self.compression_state.decompressed_buffer
                [self.compression_state.decompressed_buffer.len() - decompressed_length..],
        );
        self.reader.buffer.reverse();

        self.compression_state.decompressor.init();
        Ok(())
    }
}
