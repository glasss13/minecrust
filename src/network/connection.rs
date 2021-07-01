use super::packets::ConnectionState;
use super::types::NetworkType;

use tokio::net::TcpStream;

use tokio::io::{AsyncBufRead, AsyncReadExt, AsyncWriteExt};
use tokio::io::{BufReader, BufWriter};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub(crate) struct Connection {
    reader: BufReader<OwnedReadHalf>,
    writer: BufWriter<OwnedWriteHalf>,
    connection_state: ConnectionState,
}

impl Connection {
    pub(crate) async fn new(ip: String, port: u16) -> Result<Connection, std::io::Error> {
        let stream = TcpStream::connect((ip, port)).await?;

        let (reader, writer) = stream.into_split();

        Ok(Connection {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
            connection_state: ConnectionState::Handshaking,
        })
    }

    pub(crate) async fn read_network_type<T: NetworkType>(&mut self) -> Option<T> {
        let mut pinned_reader = std::pin::Pin::new(&mut self.reader);

        while pinned_reader.buffer().len() < T::SIZE_TO_READ {
            // reads 0 bytes, just a way to fill the backing buffer, similar to the `fill_buffer` function.
            let bytes_read = pinned_reader.read(&mut [0; 0]).await.unwrap();
            assert_eq!(bytes_read, 0);
        }
        let sizeof_output = T::size_from_bytes(pinned_reader.buffer())?;

        while pinned_reader.buffer().len() < sizeof_output {
            let bytes_read = pinned_reader.read(&mut [0; 0]).await.unwrap();
            assert_eq!(bytes_read, 0);
        }

        let output = T::from_bytes(pinned_reader.buffer())?;
        pinned_reader.consume(sizeof_output);
        Some(output)
    }

    pub(crate) async fn read_network_type_with_size<T: NetworkType>(
        &mut self,
        size: usize,
    ) -> Option<T> {
        let mut pinned_reader = std::pin::Pin::new(&mut self.reader);

        while pinned_reader.buffer().len() < size {
            // reads 0 bytes, just a way to fill the backing buffer, similar to the `fill_buffer` function.
            let bytes_read = pinned_reader.read(&mut [0; 0]).await.unwrap();
            assert_eq!(bytes_read, 0);
        }

        let output = T::from_bytes(&pinned_reader.buffer()[0..size])?;
        pinned_reader.consume(size);
        Some(output)
    }

    pub(crate) async fn write_network_type<T: NetworkType>(&mut self, network_type: &T) {
        self.writer
            .write_all(network_type.as_bytes())
            .await
            .unwrap();
    }

    pub(crate) async fn flush_writer(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush().await
    }

    pub(crate) fn connection_state(&self) -> ConnectionState {
        self.connection_state
    }

    pub(crate) fn set_connection_state(&mut self, new_state: ConnectionState) {
        self.connection_state = new_state;
    }
}
