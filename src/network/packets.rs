use aes::cipher::AsyncStreamCipher;
use aes::Aes128;
use cfb8::cipher::NewCipher;
use cfb8::Cfb8;
type AesCfb8 = Cfb8<Aes128>;

use rand::{self, Rng};
use sha1::Sha1;
use std::fmt::Write;

use super::types::{
    ByteArray, NetworkString, NetworkType, NetworkTypeReader, NetworkTypeWriter, UnsignedShort,
    Varint,
};

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
}

impl Packet for ServerBoundPacket {
    fn packet_id(&self) -> u8 {
        match self {
            ServerBoundPacket::Handshake { .. } => 0x00,
            ServerBoundPacket::LoginStart { .. } => 0x00,
        }
    }

    fn connection_state(&self) -> ConnectionState {
        match self {
            ServerBoundPacket::Handshake { .. } => ConnectionState::Handshaking,
            ServerBoundPacket::LoginStart { .. } => ConnectionState::Login,
        }
    }
}

impl ServerBoundPacket {
    pub(crate) fn send<W: NetworkTypeWriter>(&self, writer: &mut W) -> Result<(), std::io::Error> {
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

                writer.write_network_type(&Varint::from_i32(len as i32))?;
                writer.write_network_type(&encoded_packet_id)?;
                writer.write_network_type(protocol_version)?;
                writer.write_network_type(server_address)?;
                writer.write_network_type(server_port)?;
                writer.write_network_type(next_state)?;
                writer.flush()?;
            }
            ServerBoundPacket::LoginStart { username } => {
                let len = username.size_as_bytes() + encoded_packet_id.size_as_bytes();

                writer.write_network_type(&Varint::from_i32(len as i32))?;
                writer.write_network_type(&encoded_packet_id)?;
                writer.write_network_type(username)?;
                writer.flush()?;
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
    let hash_string = hash_string.trim_matches('0').to_owned();

    if hash_is_negative {
        return Some(format!("-{}", hash_string));
    }
    Some(hash_string)
}

impl ClientBoundPacket {
    pub(crate) fn from_reader<R: NetworkTypeReader>(
        packet_length: i32,
        packet_id: i32,
        reader: &mut R,
        connection_state: ConnectionState,
    ) -> Option<ClientBoundPacket> {
        match connection_state {
            ConnectionState::Handshaking => unreachable!(),
            ConnectionState::Play => todo!(),
            ConnectionState::Status => todo!(),
            ConnectionState::Login => match packet_id {
                0x01 => {
                    let server_id = reader.read_network_type::<NetworkString>()?;
                    let public_key_length = reader.read_network_type::<Varint>()?;
                    let public_key = reader.read_network_type_with_size::<ByteArray>(
                        public_key_length.to_i32() as usize,
                    )?;
                    let verify_token_length = reader.read_network_type::<Varint>()?;
                    let verify_token = reader.read_network_type_with_size::<ByteArray>(
                        verify_token_length.to_i32() as usize,
                    )?;

                    Some(ClientBoundPacket::EncryptionRequest {
                        server_id,
                        public_key_length,
                        public_key,
                        verify_token_length,
                        verify_token,
                    })
                }
                0x02 => Some(ClientBoundPacket::LoginSuccess {
                    uuid: reader.read_network_type::<NetworkString>()?,
                    username: reader.read_network_type::<NetworkString>()?,
                }),
                _ => todo!(),
            },
        }
    }

    pub(crate) fn process(&self) {
        match self {
            ClientBoundPacket::EncryptionRequest {
                server_id: _,
                public_key_length,
                public_key,
                verify_token_length,
                verify_token,
            } => {
                println!("Enabling encryption...");
                let shared_secret: [u8; 16] = rand::thread_rng().gen();
                let server_hash_string =
                    mc_hex_digest(&[&shared_secret, public_key.as_bytes()]).unwrap();

                println!("server hash: {}", server_hash_string);

                let access_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjNzdkYWI5NzNlYzA0OTlmYmQ0MWQxODRjODMyNzZjNiIsInlnZ3QiOiIxOGVjOGU2Nzc0YWE0MTRlYTJkNmVkMzY3NTIwMzA2MSIsInNwciI6IjQ4Y2U4Mjg5MDU4NTRiNzRiNTE1ZTUyMDdmZDAwOWI0IiwiaXNzIjoiWWdnZHJhc2lsLUF1dGgiLCJleHAiOjE2MjQ1NTgyNjIsImlhdCI6MTYyNDM4NTQ2Mn0.bZJMM7ofR4k3LmFsQOKG_ZDmA61pMnB-qdP8jiOmpN4";
                let uuid = "48ce828905854b74b515e5207fd009b4";

                let response =
                    ureq::post("https://sessionserver.mojang.com/session/minecraft/join")
                        .send_json(ureq::json!({
                            "accessToken": access_token,
                            "selectedProfile": uuid,
                            "serverId": server_hash_string
                        }))
                        .unwrap();

                println!(
                    "public_key_length: {} public_key length {}",
                    public_key_length.to_i32(),
                    public_key.as_bytes().len()
                );

                let mut cipher_encrypt = AesCfb8::new_from_slices(&shared_secret, &shared_secret)
                    .expect("something went wrong");

                let mut cipher_decrypt = AesCfb8::new_from_slices(&shared_secret, &shared_secret)
                    .expect("something went wrong");

                let to_encrypt_string = String::from("yawmadah");

                let mut to_encrypt = to_encrypt_string.into_bytes();

                cipher_encrypt.encrypt(&mut to_encrypt);

                cipher_decrypt.decrypt(&mut to_encrypt);

                println!(
                    "the unencrypted data is {}",
                    String::from_utf8(to_encrypt).unwrap()
                );
            }
            ClientBoundPacket::LoginSuccess { uuid, username } => println!(
                "{} logged on with UUID {}",
                username.to_string(),
                uuid.to_string()
            ),
        }
    }
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

#[derive(Clone, Copy)]
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
