use hyper::body::HttpBody;
use network::connection::Connection;
use network::network_type::{NetworkString, UnsignedShort, Varint};
use network::packets::{ClientBoundPacket, ConnectionState, ServerBoundPacket};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use std::error::Error;

mod network;

#[derive(Debug)]
struct ClientData {
    username: String,
    uuid: String,
    connected: bool,
    connection: Option<Connection>,
    authenticated: bool,
    access_token: Option<String>,
    login_listeners: Vec<watch::Sender<(String, String)>>,
}

#[derive(Debug)]
enum ClientCommand {
    Ping {
        payload: String,
        resp: oneshot::Sender<String>,
    },
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
}

impl ClientBuilder {
    pub fn new<S: Into<String>>(account_name: S) -> ClientBuilder {
        ClientBuilder {
            account_name: account_name.into(),
            port: 25565,
            ip: None,
            password: None,
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

    pub async fn login(self) -> Result<Client, std::io::Error> {
        let should_authenticate = self.password.is_some();
        if should_authenticate {
            todo!()
        }

        let mut connection = Connection::new(self.ip.as_ref().unwrap().into(), self.port).await?;

        // make the packets actually reflect the Client args
        let handshake_packet = ServerBoundPacket::Handshake {
            protocol_version: Varint::from_i32(47),
            server_address: NetworkString::from_string(self.ip.as_ref().unwrap()),
            server_port: UnsignedShort::from_u16(25565),
            next_state: ConnectionState::Login.to_varint(),
        };

        let login_packet = ServerBoundPacket::LoginStart {
            username: NetworkString::from_string(&self.account_name),
        };

        handshake_packet.send(&mut connection).await?;
        login_packet.send(&mut connection).await?;

        let mut client = ClientData {
            username: self.account_name,
            uuid: "".into(),
            connection: Some(connection),
            authenticated: false,
            access_token: None,
            connected: true,
            login_listeners: vec![],
        };

        let (sender, mut receiver) = mpsc::channel::<ClientCommand>(100);

        let packet_process_task = tokio::spawn(async move {
            loop {
                let connection = client.connection.as_mut().unwrap();
                tokio::select! {
                    Ok(packet) = ClientBoundPacket::from_connection(connection) => {
                        packet.process(&mut client).await;
                    },
                    Some(msg) = receiver.recv() => {
                        match msg {
                            ClientCommand::Ping { payload, resp } => {
                                let _ = resp.send("pong".to_string());
                            },
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

    pub async fn authenticate(self) -> Result<Client, Box<dyn Error>> {
        let client =
            hyper::Client::builder().build::<_, hyper::Body>(hyper_tls::HttpsConnector::new());

        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://authserver.mojang.com/authenticate")
            .body(hyper::Body::from(
                json!({
                    "agent": {
                        "name": "Minecraft",
                        "version": 1
                    },
                    "username": self.account_name,
                    "password": self.password
                })
                .to_string(),
            ))?;

        let mut resp = client.request(req).await?;

        if resp.status() != hyper::StatusCode::OK {
            return Err(format!("unexpected status code {}", resp.status()).into());
        }

        let body: Value = serde_json::from_slice(&resp.body_mut().data().await.unwrap()?)?;
        let selected_profile = &body["selectedProfile"];

        let thing = ClientData {
            username: selected_profile["name"].as_str().unwrap().to_string(),
            uuid: selected_profile["id"].as_str().unwrap().to_string(),
            access_token: Some(body["accessToken"].as_str().unwrap().to_string()),
            authenticated: true,
            connection: None,
            connected: false,
            login_listeners: vec![],
        };

        todo!()
    }
}

#[tokio::test]
async fn test_connect_to_server() {
    let mut client = ClientBuilder::new("Player")
        .ip("localhost")
        .login()
        .await
        .unwrap();

    client.ping().await;

    client.on_login(|username, uuid| async move {
        println!("username: {}, uuid: {}", username, uuid);
    });

    client.join().await;
}
