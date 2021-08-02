use super::network_type::NetworkType;
use super::packets::ConnectionState;

use aes::cipher::{AsyncStreamCipher, NewCipher};
use aes::Aes128;
use bytes::{Buf, BytesMut};
use cfb8::Cfb8;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

pub(crate) struct Connection {
    reader: BufferedReader,
    writer: BufWriter<OwnedWriteHalf>,
    connection_state: ConnectionState,
    encryption_enabled: bool,
    aes_encrypt_cipher: Option<Cfb8<Aes128>>,
    aes_decrypt_cipher: Option<Cfb8<Aes128>>,
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

impl Connection {
    pub(crate) async fn new(ip: String, port: u16) -> Result<Connection, std::io::Error> {
        let stream = TcpStream::connect((ip, port)).await?;

        let (reader, writer) = stream.into_split();

        Ok(Connection {
            reader: BufferedReader::with_capacity(reader, 1000000),
            writer: BufWriter::new(writer),
            connection_state: ConnectionState::Handshaking,
            encryption_enabled: false,
            aes_encrypt_cipher: None,
            aes_decrypt_cipher: None,
        })
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), std::io::Error> {
        self.writer.shutdown().await
    }

    pub(crate) async fn read_network_type<T: NetworkType>(&mut self) -> Result<T, std::io::Error> {
        while self.reader.buffer.remaining() < T::SIZE_TO_READ {
            let bytes_read = self.reader.stream.read_buf(&mut self.reader.buffer).await?;
            if bytes_read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                ));
            }
            if self.encryption_enabled {
                let decryption_starting_idx = self.reader.buffer.len() - bytes_read;

                self.aes_decrypt_cipher.as_mut().unwrap().decrypt(
                    &mut self.reader.buffer
                        [decryption_starting_idx..bytes_read + decryption_starting_idx],
                );
            }
        }

        loop {
            let size = T::size_from_bytes(&self.reader.buffer)?;

            if size <= self.reader.buffer.remaining() {
                return T::from_bytes(&self.reader.buffer[..size]).map(|output| {
                    self.reader.buffer.advance(size);
                    output
                });
            }

            let bytes_read = self.reader.stream.read_buf(&mut self.reader.buffer).await?;
            if bytes_read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                ));
            }
            if self.encryption_enabled {
                let decryption_starting_idx = self.reader.buffer.len() - bytes_read;
                self.aes_decrypt_cipher.as_mut().unwrap().decrypt(
                    &mut self.reader.buffer
                        [decryption_starting_idx..bytes_read + decryption_starting_idx],
                );
            }
        }
    }

    pub(crate) async fn read_network_type_with_size<T: NetworkType>(
        &mut self,
        size: usize,
    ) -> Result<T, std::io::Error> {
        while self.reader.buffer.remaining() < size {
            let bytes_read = dbg!(self.reader.stream.read_buf(&mut self.reader.buffer).await?);
            if bytes_read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "connection reset by peer",
                ));
            }

            if self.encryption_enabled {
                let decryption_starting_idx = self.reader.buffer.len() - bytes_read;
                self.aes_decrypt_cipher.as_mut().unwrap().decrypt(
                    &mut self.reader.buffer
                        [decryption_starting_idx..bytes_read + decryption_starting_idx],
                );
            }
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
            self.aes_encrypt_cipher
                .as_mut()
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
        self.encryption_enabled
    }

    pub(crate) fn enable_encryption(&mut self, shared_secret: &[u8; 16]) {
        type AesCfb8 = Cfb8<Aes128>;

        let cipher_encrypt = AesCfb8::new_from_slices(shared_secret, shared_secret).unwrap();
        let cipher_decrypt = AesCfb8::new_from_slices(shared_secret, shared_secret).unwrap();

        self.encryption_enabled = true;
        self.aes_encrypt_cipher = Some(cipher_encrypt);
        self.aes_decrypt_cipher = Some(cipher_decrypt);
    }

    pub(crate) fn set_connection_state(&mut self, new_state: ConnectionState) {
        self.connection_state = new_state;
    }
}
