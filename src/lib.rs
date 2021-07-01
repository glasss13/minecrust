use std::error::Error;
use std::marker::PhantomData;

use hyper::body::HttpBody;
use serde_json::{json, Value};

mod network;

#[derive(Debug)]
pub struct Client {
    username: String,
    /// non-hyphenated
    uuid: String,
    access_token: Option<String>,
    authenticated: bool,
    connected_to_server: bool,
}

#[doc(hidden)]
/// Used in [ClientBuilder] as generic flags
pub struct Set;
#[doc(hidden)]
/// Used in [ClientBuilder] as generic flags
pub struct Unset;
pub struct ClientBuilder<IpSet, PasswordSet> {
    mojang_account_name: String,
    port: u16,

    ip: Option<String>,
    password: Option<String>,

    ip_set: PhantomData<IpSet>,
    password_set: PhantomData<PasswordSet>,
}

impl ClientBuilder<Unset, Unset> {
    pub fn new<S: Into<String>>(mojang_account_name: S) -> ClientBuilder<Unset, Unset> {
        ClientBuilder {
            mojang_account_name: mojang_account_name.into(),
            ip: None,
            port: 25565,
            password: None,
            ip_set: PhantomData,
            password_set: PhantomData,
        }
    }
}

impl<IpSet, PasswordSet> ClientBuilder<IpSet, PasswordSet> {
    pub fn ip<S: Into<String>>(self, ip: S) -> ClientBuilder<Set, PasswordSet> {
        ClientBuilder {
            mojang_account_name: self.mojang_account_name,
            port: self.port,
            ip: Some(ip.into()),
            password: self.password,
            ip_set: PhantomData,
            password_set: self.password_set,
        }
    }

    pub fn port(self, port: u16) -> ClientBuilder<IpSet, PasswordSet> {
        ClientBuilder { port, ..self }
    }

    pub fn password<S: Into<String>>(self, password: S) -> ClientBuilder<IpSet, Set> {
        ClientBuilder {
            mojang_account_name: self.mojang_account_name,
            port: self.port,
            ip: self.ip,
            password: Some(password.into()),
            ip_set: self.ip_set,
            password_set: PhantomData,
        }
    }
}

impl<PasswordSet> ClientBuilder<Set, PasswordSet> {
    pub async fn join_unauth(self) -> Client {
        todo!()
    }
}

impl ClientBuilder<Set, Set> {
    pub fn join_auth(self) -> Client {
        todo!()
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
                    "username": self.mojang_account_name,
                    "password": self.password
                })
                .to_string(),
            ))?;

        let mut resp = client.request(req).await?;

        let body: Value = serde_json::from_slice(&resp.body_mut().data().await.unwrap().unwrap())?;
        let selected_profile = &body["selectedProfile"];

        Ok(Client {
            username: selected_profile["name"].as_str().unwrap().to_string(),
            uuid: selected_profile["id"].as_str().unwrap().to_string(),
            access_token: Some(body["accessToken"].as_str().unwrap().to_string()),
            authenticated: true,
            connected_to_server: false,
        })
    }
}
