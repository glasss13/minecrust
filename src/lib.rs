use network::authentication::yggdrasil;
use network::authentication::yggdrasil::Session;
use network::connection::Connection;
use network::network_type::{NetworkString, UnsignedShort, Varint};
use network::packets::{ClientBoundPacket, ConnectionState, ServerBoundPacket};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

mod network;

struct ClientData {
    session: Option<Session>,
    connected_to_server: bool,
    connection: Option<Connection>,
    login_listeners: Vec<watch::Sender<(String, String)>>,
}

impl ClientData {
    fn connection_mut(&mut self) -> &mut Connection {
        self.connection.as_mut().unwrap()
    }
}

impl std::fmt::Debug for ClientData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientData")
            .field("session", &self.session)
            .field("connected_to_server", &self.connected_to_server)
            .field("login_listeners", &self.login_listeners.len())
            .finish()
    }
}

#[derive(Debug)]
enum ClientCommand {
    Ping {
        payload: String,
        resp: oneshot::Sender<String>,
    },
    Disconnect,
    OnLogin {
        resp: watch::Sender<(String, String)>,
    },
}

#[derive(Debug)]
pub struct Client {
    sender: mpsc::Sender<ClientCommand>,
    packet_process_task: JoinHandle<()>,
}

impl Client {
    pub async fn ping(&mut self) {
        let (resp_tx, resp_rx) = oneshot::channel();
        let msg = ClientCommand::Ping {
            payload: "ping".into(),
            resp: resp_tx,
        };
        self.sender.send(msg).await.unwrap();

        let res = resp_rx.await;
        println!("we pinged and they ponged: {}", res.unwrap());
    }

    pub async fn disconnect(&mut self) {
        self.sender.send(ClientCommand::Disconnect).await.unwrap();
    }

    pub fn on_login<Fut>(
        &mut self,
        callback: impl Fn(String, String) -> Fut + Send + Sync + 'static,
    ) where
        Fut: std::future::Future<Output = ()> + Send,
    {
        let (resp_tx, mut resp_rx) = watch::channel((String::new(), String::new()));
        let msg = ClientCommand::OnLogin { resp: resp_tx };

        let sender = self.sender.clone();

        tokio::spawn(async move {
            sender.send(msg).await.unwrap();

            while resp_rx.changed().await.is_ok() {
                let res = resp_rx.borrow().clone();
                callback(res.0, res.1).await;
            }
        });
    }
    pub async fn join(self) {
        let _ = self.packet_process_task.await;
    }
}

pub struct ClientBuilder {
    account_name: String,
    port: u16,
    ip: Option<String>,
    password: Option<String>,
    client_token: Option<String>,
    access_token: Option<String>,
}

impl ClientBuilder {
    pub fn new<S: Into<String>>(account_name: S) -> ClientBuilder {
        ClientBuilder {
            account_name: account_name.into(),
            port: 25565,
            ip: None,
            password: None,
            client_token: None,
            access_token: None,
        }
    }

    pub fn ip<S: Into<String>>(mut self, ip: S) -> ClientBuilder {
        self.ip = Some(ip.into());
        self
    }

    pub fn port(mut self, port: u16) -> ClientBuilder {
        self.port = port;
        self
    }

    pub fn password<S: Into<String>>(mut self, password: S) -> ClientBuilder {
        self.password = Some(password.into());
        self
    }

    pub fn client_token<S: Into<String>>(mut self, client_token: S) -> ClientBuilder {
        self.client_token = Some(client_token.into());
        self
    }

    pub fn access_token<S: Into<String>>(mut self, access_token: S) -> ClientBuilder {
        self.access_token = Some(access_token.into());
        self
    }

    pub async fn login(self) -> Result<Client, Box<dyn std::error::Error>> {
        let session = if let Some(access_token) = &self.access_token {
            println!("authenticating with token");
            if yggdrasil::is_token_valid(access_token).await? {
                // no need to refresh the token, but don't know how to create a session so for now its a no-op
                println!("token is already valid, no need to refresh");
            }
            Some(
                yggdrasil::refresh_token(
                    access_token,
                    &self
                        .client_token
                        .expect("client token is required to login with access token"),
                )
                .await?,
            )
        } else if let Some(password) = &self.password {
            println!("authenticating with password");
            Some(
                yggdrasil::authenticate_password(
                    &self.account_name,
                    password,
                    self.client_token.as_deref(),
                )
                .await?,
            )
        } else {
            None
        };

        let mut connection = Connection::new(self.ip.as_ref().unwrap().into(), self.port).await?;

        let handshake_packet = ServerBoundPacket::Handshake {
            protocol_version: Varint::from_i32(47),
            server_address: NetworkString::from_string(self.ip.as_ref().unwrap()),
            server_port: UnsignedShort::from_u16(self.port),
            next_state: ConnectionState::Login.to_varint(),
        };

        let login_packet = ServerBoundPacket::LoginStart {
            username: NetworkString::from_string(match &session {
                Some(session) => session.username(),
                None => &self.account_name,
            }),
        };

        handshake_packet.send(&mut connection).await?;
        login_packet.send(&mut connection).await?;

        let mut client = ClientData {
            session,
            connection: Some(connection),
            connected_to_server: true,
            login_listeners: vec![],
        };

        let (sender, mut receiver) = mpsc::channel(100);

        let packet_process_task = tokio::spawn(async move {
            loop {
                let connection = client.connection.as_mut().unwrap();
                tokio::select! {
                    Ok(packet) = ClientBoundPacket::from_connection(connection) => {
                        packet.process(&mut client).await.unwrap();
                    },
                    Some(msg) = receiver.recv() => {
                        match msg {
                            ClientCommand::Ping { resp , .. } => {
                                let _ = resp.send("pong".to_string());
                            },
                            ClientCommand::Disconnect => {
                                connection.shutdown().await.unwrap();
                                break;
                            }
                            ClientCommand::OnLogin {resp} => {
                                client.login_listeners.push(resp);
                            }
                        }
                    }
                };
            }
        });
        Ok(Client {
            sender,
            packet_process_task,
        })
    }
}

#[tokio::test]
async fn test_connect_to_server() {
    let mut client = ClientBuilder::new("email")
        .ip("localhost")
        .password("password")
        .login()
        .await
        .unwrap();

    client.on_login(|username, uuid| async move {
        println!("username: {}, uuid: {}", username, uuid);
    });

    client.join().await;
}
