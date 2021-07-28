use minecrust::ClientBuilder;

#[tokio::test]
async fn test_connect_to_server() {
    let mut client = ClientBuilder::new("Player")
        .ip("localhost")
        .login()
        .await
        .unwrap();

    client.on_login(|username, uuid| async move {
        println!("username: {}, uuid: {}", username, uuid);
    });

    client.join().await;
}
