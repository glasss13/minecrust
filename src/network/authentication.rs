#[derive(Debug)]
struct AuthError {
    error: String,
}

impl AuthError {
    fn new(error: String) -> AuthError {
        AuthError { error }
    }
}

impl std::error::Error for AuthError {}
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.error)
    }
}

pub(crate) mod yggdrasil {
    use hyper::body::HttpBody;
    use serde_json::{json, Value};
    use std::error::Error;
    use uuid::Uuid;

    use super::AuthError;

    #[derive(Debug)]
    pub(crate) struct Session {
        username: String,
        uuid: Uuid,
        access_token: String,
    }

    impl Session {
        pub(crate) fn username(&self) -> &str {
            &self.username
        }

        pub(crate) fn uuid(&self) -> &Uuid {
            &self.uuid
        }

        pub(crate) fn access_token(&self) -> &str {
            &self.access_token
        }
    }

    pub(crate) async fn authenticate_password(
        username: &str,
        password: &str,
        client_token: Option<&str>,
    ) -> Result<Session, Box<dyn Error>> {
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
                    "username": username,
                    "password": password,
                    "clientToken": client_token.unwrap_or("1"),
                })
                .to_string(),
            ))?;

        let mut resp = client.request(req).await?;
        let body: Value = serde_json::from_slice(&resp.body_mut().data().await.unwrap()?)?;

        if resp.status() != hyper::StatusCode::OK {
            return Err(AuthError::new(body["errorMessage"].as_str().unwrap().to_string()).into());
        }

        Ok(Session {
            username: body["selectedProfile"]["name"].as_str().unwrap().into(),
            access_token: body["accessToken"].as_str().unwrap().into(),
            uuid: Uuid::parse_str(body["selectedProfile"]["id"].as_str().unwrap()).unwrap(),
        })
    }

    pub(crate) async fn refresh_token(
        access_token: &str,
        client_token: &str,
    ) -> Result<Session, Box<dyn Error>> {
        let client =
            hyper::Client::builder().build::<_, hyper::Body>(hyper_tls::HttpsConnector::new());

        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://authserver.mojang.com/refresh")
            .body(hyper::Body::from(
                json!({
                    "accessToken": access_token,
                    "clientToken": client_token,
                })
                .to_string(),
            ))?;

        let mut resp = client.request(req).await?;
        let body: Value = serde_json::from_slice(&resp.body_mut().data().await.unwrap()?)?;

        if resp.status() != hyper::StatusCode::OK {
            return Err(AuthError::new(body["errorMessage"].as_str().unwrap().to_string()).into());
        }

        Ok(Session {
            username: body["selectedProfile"]["name"].as_str().unwrap().into(),
            uuid: Uuid::parse_str(body["selectedProfile"]["id"].as_str().unwrap()).unwrap(),
            access_token: body["accessToken"].as_str().unwrap().into(),
        })
    }

    pub(crate) async fn is_token_valid(access_token: &str) -> Result<bool, Box<dyn Error>> {
        let client =
            hyper::Client::builder().build::<_, hyper::Body>(hyper_tls::HttpsConnector::new());

        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://authserver.mojang.com/validate")
            .body(hyper::Body::from(
                json!({
                    "accessToken": access_token,
                })
                .to_string(),
            ))?;

        let resp = client.request(req).await?;

        Ok(resp.status() == hyper::StatusCode::NO_CONTENT)
    }

    pub(crate) async fn join_server(
        access_token: &str,
        selected_profile: &Uuid,
        server_id: &str,
    ) -> Result<(), Box<dyn Error>> {
        let client =
            hyper::Client::builder().build::<_, hyper::Body>(hyper_tls::HttpsConnector::new());

        let req = hyper::Request::builder()
            .method("POST")
            .uri("https://sessionserver.mojang.com/session/minecraft/join")
            .body(hyper::Body::from(
                json!({
                    "accessToken": access_token,
                    "selectedProfile": selected_profile.to_simple().to_string(),
                    "serverId": server_id,
                })
                .to_string(),
            ))?;

        let mut resp = client.request(req).await?;

        if resp.status() == hyper::StatusCode::NO_CONTENT {
            Ok(())
        } else {
            let body: Value = serde_json::from_slice(&resp.body_mut().data().await.unwrap()?)?;
            Err(AuthError::new(
                body["errorMessage"]
                    .as_str()
                    .unwrap_or_else(|| body["error"].as_str().unwrap())
                    .to_string(),
            )
            .into())
        }
    }
}
