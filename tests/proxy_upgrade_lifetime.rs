use futures_util::StreamExt;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{handshake::derive_accept_key, protocol::WebSocketConfig};
#[tokio::test]
async fn upgrade_preserves_read_ahead_and_survives_handshake_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 8192);
            bytes.push(socket.read_u8().await.unwrap());
        }
        let head = String::from_utf8(bytes).unwrap();
        let key = head
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-key"))
                    .map(|(_, v)| v.trim())
            })
            .unwrap();
        let mut packet=format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",derive_accept_key(key.as_bytes())).into_bytes();
        packet.extend_from_slice(b"\x81\x05early");
        socket.write_all(&packet).await.unwrap();
        tokio::time::sleep(Duration::from_secs(16)).await;
        socket.write_all(b"\x81\x04late").await.unwrap();
    });
    let mut socket = ferroc::network::Network::direct()
        .websocket(
            reqwest::Url::parse(&format!("ws://{address}/ws")).unwrap(),
            "synthetic-token",
            WebSocketConfig::default(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        socket.next().await.unwrap().unwrap().into_text().unwrap(),
        "early"
    );
    let late = tokio::time::timeout(Duration::from_secs(20), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(late.into_text().unwrap(), "late");
    server.await.unwrap();
}
