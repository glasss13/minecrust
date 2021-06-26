use std::io::{prelude::*, BufReader, BufWriter};
use std::marker::PhantomData;

mod network;

use network::types::{NetworkTypeReader, NetworkTypeWriter};

impl<R: Read> NetworkTypeReader for BufReader<R> {}
impl<W: Write> NetworkTypeWriter for BufWriter<W> {}

pub struct Client {
    username: String,
    /// non-hyphenated
    uuid: String,
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
    username: String,
    port: u16,

    ip: Option<String>,
    password: Option<String>,

    ip_set: PhantomData<IpSet>,
    password_set: PhantomData<PasswordSet>,
}

impl ClientBuilder<Unset, Unset> {
    pub fn new<S: Into<String>>(username: S) -> ClientBuilder<Unset, Unset> {
        ClientBuilder {
            username: username.into(),
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
            username: self.username,
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
            username: self.username,
            port: self.port,
            ip: self.ip,
            password: Some(password.into()),
            ip_set: self.ip_set,
            password_set: PhantomData,
        }
    }
}

impl<PasswordSet> ClientBuilder<Set, PasswordSet> {
    pub fn join_unauth(self) -> Client {
        todo!()
    }
}

impl ClientBuilder<Set, Set> {
    pub fn join_auth(self) -> Client {
        todo!()
    }

    pub fn authenticate(self) -> Client {
        todo!()
    }
}
