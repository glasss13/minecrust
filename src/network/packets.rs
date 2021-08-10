use rand::{self, Rng};
use sha1::Sha1;
use std::fmt::{format, Write};

use crate::network::authentication::yggdrasil;
use crate::ClientData;

use super::connection::Connection;
use super::network_type::{ByteArray, NetworkString, NetworkType, UnsignedShort, Varint};

pub(crate) trait Packet {
    fn packet_id(&self) -> u8;

    fn connection_state(&self) -> ConnectionState;
}

pub(crate) enum ServerBoundPacket {
    /// <https://wiki.vg/index.php?title=Protocol&oldid=7368#Handshake>.
    Handshake {
        protocol_version: Varint,
        server_address: NetworkString,
        server_port: UnsignedShort,
        next_state: Varint,
    },
    /// <https://wiki.vg/index.php?title=Protocol&oldid=7368#Login_Start>.
    LoginStart { username: NetworkString },
    /// <https://wiki.vg/index.php?title=Protocol&oldid=7368#Encryption_Response>.
    EncryptionResponse {
        shared_secret_length: Varint,
        shared_secret: ByteArray,
        verify_token_length: Varint,
        verify_token: ByteArray,
    },
}

impl Packet for ServerBoundPacket {
    fn packet_id(&self) -> u8 {
        match self {
            ServerBoundPacket::Handshake { .. } => 0x00,
            ServerBoundPacket::LoginStart { .. } => 0x00,
            ServerBoundPacket::EncryptionResponse { .. } => 0x01,
        }
    }

    fn connection_state(&self) -> ConnectionState {
        match self {
            ServerBoundPacket::Handshake { .. } => ConnectionState::Handshaking,
            ServerBoundPacket::LoginStart { .. } => ConnectionState::Login,
            ServerBoundPacket::EncryptionResponse { .. } => ConnectionState::Login,
        }
    }
}

impl ServerBoundPacket {
    pub(crate) async fn send(&self, connection: &mut Connection) -> Result<(), std::io::Error> {
        let encoded_packet_id = Varint::from_i32(self.packet_id().into());

        match self {
            ServerBoundPacket::Handshake {
                protocol_version,
                server_address,
                server_port,
                next_state,
            } => {
                let len = protocol_version.size_as_bytes()
                    + server_address.size_as_bytes()
                    + server_port.size_as_bytes()
                    + next_state.size_as_bytes()
                    + encoded_packet_id.size_as_bytes();

                assert!(
                    next_state.to_i32() == ConnectionState::Login as i32
                        || next_state.to_i32() == ConnectionState::Status as i32
                );

                connection
                    .write_network_type(&Varint::from_i32(len as i32))
                    .await?;
                connection.write_network_type(&encoded_packet_id).await?;
                connection.write_network_type(protocol_version).await?;
                connection.write_network_type(server_address).await?;
                connection.write_network_type(server_port).await?;
                connection.write_network_type(next_state).await?;
                connection.flush_writer().await?;

                connection.set_connection_state(match next_state.to_i32() {
                    1 => ConnectionState::Status,
                    2 => ConnectionState::Login,
                    _ => unreachable!(),
                });
            }
            ServerBoundPacket::LoginStart { username } => {
                let len = username.size_as_bytes() + encoded_packet_id.size_as_bytes();

                connection
                    .write_network_type(&Varint::from_i32(len as i32))
                    .await?;
                connection.write_network_type(&encoded_packet_id).await?;
                connection.write_network_type(username).await?;
                connection.flush_writer().await?;
            }
            ServerBoundPacket::EncryptionResponse {
                shared_secret_length,
                shared_secret,
                verify_token_length,
                verify_token,
            } => {
                let len = shared_secret_length.size_as_bytes()
                    + shared_secret_length.to_i32() as usize
                    + verify_token_length.size_as_bytes()
                    + verify_token_length.to_i32() as usize
                    + encoded_packet_id.size_as_bytes();

                connection
                    .write_network_type(&Varint::from_i32(len as i32))
                    .await?;

                connection.write_network_type(&encoded_packet_id).await?;
                connection.write_network_type(shared_secret_length).await?;
                connection.write_network_type(shared_secret).await?;
                connection.write_network_type(verify_token_length).await?;
                connection.write_network_type(verify_token).await?;
                connection.flush_writer().await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum ClientBoundPacket {
    /// <https://wiki.vg/index.php?title=Protocol&oldid=7368#Encryption_Request>.
    EncryptionRequest {
        server_id: NetworkString,
        public_key_length: Varint,
        public_key: ByteArray,
        verify_token_length: Varint,
        verify_token: ByteArray,
    },
    /// <https://wiki.vg/index.php?title=Protocol&oldid=7368#Login_Success>.
    LoginSuccess {
        uuid: NetworkString,
        username: NetworkString,
    },
}

impl std::fmt::Display for ClientBoundPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientBoundPacket::EncryptionRequest {
                server_id,
                public_key_length,
                public_key,
                verify_token_length,
                verify_token,
            } => f
                .debug_struct("EncryptionRequest")
                .field("server_id", &format_args!("{}", server_id))
                .field("public_key_len", &format_args!("{}", public_key_length))
                .field("public_key", &format_args!("{}", public_key))
                .field("verify_token_len", &format_args!("{}", verify_token_length))
                .field("verify_token", &format_args!("{}", verify_token))
                .finish(),
            ClientBoundPacket::LoginSuccess { uuid, username } => f
                .debug_struct("LoginSuccess")
                .field("uuid", &format_args!("{}", uuid))
                .field("username", &format_args!("{}", username))
                .finish(),
        }
    }
}

impl ClientBoundPacket {
    pub(crate) async fn from_connection(
        connection: &mut Connection,
    ) -> Result<ClientBoundPacket, std::io::Error> {
        let packet_length = connection.read_network_type::<Varint>().await?.to_i32();
        let packet_id = connection.read_network_type::<Varint>().await?.to_i32();

        match connection.connection_state() {
            ConnectionState::Handshaking => unreachable!(),
            ConnectionState::Play => todo!("id: {:#2x}", packet_id),
            ConnectionState::Status => todo!("id: {:#2x}", packet_id),
            ConnectionState::Login => match packet_id {
                0x01 => {
                    let server_id = connection.read_network_type::<NetworkString>().await?;
                    let public_key_length = connection.read_network_type::<Varint>().await?;
                    let public_key = connection
                        .read_network_type_with_size::<ByteArray>(
                            public_key_length.to_i32() as usize
                        )
                        .await?;
                    let verify_token_length = connection.read_network_type::<Varint>().await?;
                    let verify_token = connection
                        .read_network_type_with_size::<ByteArray>(
                            verify_token_length.to_i32() as usize
                        )
                        .await?;

                    Ok(ClientBoundPacket::EncryptionRequest {
                        server_id,
                        public_key_length,
                        public_key,
                        verify_token_length,
                        verify_token,
                    })
                }
                0x02 => {
                    let uuid = connection.read_network_type::<NetworkString>().await?;
                    let username = connection.read_network_type::<NetworkString>().await?;

                    Ok(ClientBoundPacket::LoginSuccess { uuid, username })
                }
                _ => todo!("id: {:#2x}", packet_id),
            },
        }
    }

    pub(crate) async fn process(
        &self,
        client: &mut ClientData,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            ClientBoundPacket::EncryptionRequest {
                server_id: _,
                public_key,
                verify_token,
                ..
            } => {
                let shared_secret: [u8; 16] = rand::thread_rng().gen();
                let server_hash_string =
                    mc_hex_digest(&[&shared_secret, public_key.as_bytes()]).unwrap();

                let session = client.session.as_ref().expect(
                    "attempted to log in to online mode server with unauthenticated account",
                );
                yggdrasil::join_server(session.access_token(), session.uuid(), &server_hash_string)
                    .await?;

                let public_key =
                    openssl::rsa::Rsa::public_key_from_der(public_key.as_bytes()).unwrap();

                let mut encrypted_shared_secret = vec![0; public_key.size() as usize];
                let mut encrypted_verify_token = vec![0; public_key.size() as usize];

                public_key
                    .public_encrypt(
                        &shared_secret,
                        &mut encrypted_shared_secret,
                        openssl::rsa::Padding::PKCS1,
                    )
                    .unwrap();
                public_key
                    .public_encrypt(
                        verify_token.as_bytes(),
                        &mut encrypted_verify_token,
                        openssl::rsa::Padding::PKCS1,
                    )
                    .unwrap();

                ServerBoundPacket::EncryptionResponse {
                    shared_secret_length: Varint::from_i32(encrypted_shared_secret.len() as i32),
                    shared_secret: ByteArray::from_bytes(&encrypted_shared_secret).unwrap(),
                    verify_token_length: Varint::from_i32(encrypted_verify_token.len() as i32),
                    verify_token: ByteArray::from_bytes(&encrypted_verify_token).unwrap(),
                }
                .send(&mut client.connection.as_mut().unwrap())
                .await?;
                println!("enabling encryption");
                client.connection_mut().enable_encryption(&shared_secret);
                // let to_encrypt_string = String::from("yawmadah");

                // let mut to_encrypt = to_encrypt_string.into_bytes();

                // cipher_encrypt.encrypt(&mut to_encrypt);

                // cipher_decrypt.decrypt(&mut to_encrypt);

                // println!(
                //     "the unencrypted data is {}",
                //     String::from_utf8(to_encrypt).unwrap()
                // );
            }
            ClientBoundPacket::LoginSuccess { uuid, username } => {
                client
                    .connection
                    .as_mut()
                    .unwrap()
                    .set_connection_state(ConnectionState::Play);

                for listener in &client.login_listeners {
                    let _ = listener.send((username.to_string(), uuid.to_string()));
                }

                println!(
                    "{} logged on with UUID {}",
                    username.to_string(),
                    uuid.to_string()
                )
            }
        }
        Ok(())
    }
}

fn mc_hex_digest(to_digest_list: &[&[u8]]) -> Option<String> {
    let mut hasher = Sha1::new();

    for to_digest in to_digest_list {
        hasher.update(*to_digest);
    }
    let mut hash_bytes = hasher.digest().bytes();
    let hash_is_negative = hash_bytes[0] > 127;
    let mut hash_string = String::with_capacity(21);

    if hash_is_negative {
        let mut carry = true;

        for i in (0..hash_bytes.len()).rev() {
            hash_bytes[i] = !hash_bytes[i];
            if carry {
                carry = hash_bytes[i] == 0xff;
                hash_bytes[i] += 1;
            }
        }
    }

    for byte in &hash_bytes {
        write!(&mut hash_string, "{:02x}", byte).ok()?;
    }

    // get rid of leading zero's since the array is meant to be one large integer.
    let hash_string = hash_string.trim_start_matches('0').to_owned();

    if hash_is_negative {
        return Some(format!("-{}", hash_string));
    }
    Some(hash_string)
}

impl Packet for ClientBoundPacket {
    fn packet_id(&self) -> u8 {
        match self {
            ClientBoundPacket::EncryptionRequest { .. } => 0x01,
            ClientBoundPacket::LoginSuccess { .. } => 0x02,
        }
    }

    fn connection_state(&self) -> ConnectionState {
        match self {
            ClientBoundPacket::EncryptionRequest { .. } => ConnectionState::Login,
            ClientBoundPacket::LoginSuccess { .. } => ConnectionState::Login,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ConnectionState {
    Handshaking = -1,
    Play = 0,
    Status = 1,
    Login = 2,
}

impl ConnectionState {
    pub(crate) fn to_varint(self) -> Varint {
        Varint::from_i32(self as i32)
    }
}
