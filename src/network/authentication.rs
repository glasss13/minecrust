pub(crate) mod yggdrasil {
    use hyper::body::HttpBody;
    use serde_json::{json, Value};
    use std::error::Error;
    use uuid::Uuid;

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

        if resp.status() != hyper::StatusCode::OK {
            return Err(format!("unexpected status code {}", resp.status()).into());
        }
        let body: Value = serde_json::from_slice(&resp.body_mut().data().await.unwrap()?)?;

        let username = body["selectedProfile"]["name"].as_str().unwrap().into();
        let access_token = body["accessToken"].as_str().unwrap().into();
        let uuid = Uuid::parse_str(body["selectedProfile"]["id"].as_str().unwrap()).unwrap();

        Ok(Session {
            username,
            uuid,
            access_token,
        })
    }

    pub(crate) async fn refresh_token() {
        todo!()
    }
}
