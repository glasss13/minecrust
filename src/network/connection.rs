use super::buf_reader::BufReader;
use super::network_type::NetworkType;
use super::packets::ConnectionState;

use aes::cipher::{AsyncStreamCipher, NewCipher};
use aes::Aes128;
use cfb8::Cfb8;
use std::pin::Pin;
use tokio::io::BufWriter;
use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

pub(crate) struct Connection {
    reader: BufReader<OwnedReadHalf>,
    writer: BufWriter<OwnedWriteHalf>,
    connection_state: ConnectionState,
    encryption_enabled: bool,
    aes_encrypt_cipher: Option<Cfb8<Aes128>>,
    aes_decrypt_cipher: Option<Cfb8<Aes128>>,
}

impl Connection {
    pub(crate) async fn new(ip: String, port: u16) -> Result<Connection, std::io::Error> {
        let stream = TcpStream::connect((ip, port)).await?;

        let (reader, writer) = stream.into_split();

        Ok(Connection {
            reader: BufReader::new(reader),
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
        let encryption_enabled = self.encryption_enabled();
        let bytes_decrypted = self.reader.bytes_decrypted();
        let mut pinned_reader = Pin::new(&mut self.reader);

        while pinned_reader.buffer().len() < T::SIZE_TO_READ {
            // reads 0 bytes, just a way to fill the backing buffer, similar to the `fill_buffer` function.
            let bytes_read = pinned_reader.read(&mut [0; 0]).await?;
            assert_eq!(bytes_read, 0);
        }

        if encryption_enabled {
            // we haven't already decrypted all of it, so decrypt the rest now.
            if bytes_decrypted < T::SIZE_TO_READ {
                self.aes_decrypt_cipher
                    .as_mut()
                    .unwrap()
                    .decrypt(&mut pinned_reader.buffer_mut()[bytes_decrypted..T::SIZE_TO_READ]);
            }
            pinned_reader.mark_decrypted(T::SIZE_TO_READ - bytes_decrypted);
        }
        let sizeof_output = T::size_from_bytes(&pinned_reader.buffer()[..T::SIZE_TO_READ])?;

        while pinned_reader.buffer().len() < sizeof_output {
            let bytes_read = pinned_reader.read(&mut [0; 0]).await?;
            assert_eq!(bytes_read, 0);
        }

        let bytes_decrypted = pinned_reader.bytes_decrypted();
        if encryption_enabled && bytes_decrypted < sizeof_output {
            self.aes_decrypt_cipher
                .as_mut()
                .unwrap()
                .decrypt(&mut pinned_reader.buffer_mut()[bytes_decrypted..sizeof_output]);
            pinned_reader.mark_decrypted(sizeof_output - bytes_decrypted);
        }

        T::from_bytes(&pinned_reader.buffer()[..sizeof_output]).map(|output| {
            pinned_reader.consume(sizeof_output);
            output
        })
    }

    pub(crate) async fn read_network_type_with_size<T: NetworkType>(
        &mut self,
        size: usize,
    ) -> Result<T, std::io::Error> {
        let encryption_enabled = self.encryption_enabled();
        let bytes_decrypted = self.reader.bytes_decrypted();
        let mut pinned_reader = std::pin::Pin::new(&mut self.reader);

        while pinned_reader.buffer().len() < size {
            // reads 0 bytes, just a way to fill the backing buffer, similar to the `fill_buffer` function.
            let bytes_read = pinned_reader.read(&mut [0; 0]).await?;
            assert_eq!(bytes_read, 0);
        }

        if encryption_enabled && bytes_decrypted < size {
            self.aes_decrypt_cipher
                .as_mut()
                .unwrap()
                .decrypt(&mut pinned_reader.buffer_mut()[bytes_decrypted..size]);
            pinned_reader.mark_decrypted(size - bytes_decrypted);
        }

        T::from_bytes(&pinned_reader.buffer()[0..size]).map(|output| {
            pinned_reader.consume(size);
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
