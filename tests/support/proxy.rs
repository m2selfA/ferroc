//! Recording loopback-only proxy fixtures, never production services.
#![allow(dead_code)]
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;
pub const USER: &str = "fixture-user";
pub const PASSWORD: &str = "proxy-secret-must-not-appear";
pub fn ca_file() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proxy-test-root.pem")
}
pub fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(
            include_bytes!("../fixtures/proxy-test-leaf.der").to_vec(),
        )],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../fixtures/proxy-test-key.der").to_vec(),
        )),
    )
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}
pub async fn head<S: AsyncRead + Unpin + ?Sized>(s: &mut S) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        ensure!(bytes.len() < 32768, "fixture header limit");
        let byte = s.read_u8().await?;
        bytes.push(byte);
    }
    Ok(bytes)
}
pub fn header<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}
pub async fn reply(s: &mut Stream, status: &str, body: &str) -> Result<()> {
    s.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await?;
    Ok(())
}
#[derive(Clone, Copy)]
pub enum Kind {
    Http,
    Https,
    Socks,
}
#[derive(Default)]
pub struct Records {
    pub connections: AtomicUsize,
    pub targets: Mutex<Vec<String>>,
    pub socks_types: Mutex<Vec<u8>>,
}
pub struct ProxyFixture {
    pub address: SocketAddr,
    pub records: Arc<Records>,
    task: JoinHandle<()>,
}
impl Drop for ProxyFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ProxyFixture {
    pub async fn start(kind: Kind, target: SocketAddr, auth: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let records = Arc::new(Records::default());
        let r = records.clone();
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    next=listener.accept()=>{let (socket,_)=next.unwrap();let r=r.clone();children.spawn(async move {let _=serve(kind,socket,target,auth,r).await;});},
                    _=children.join_next(),if !children.is_empty()=>{}
                }
            }
        });
        Self {
            address,
            records,
            task,
        }
    }
    pub fn url(&self, scheme: &str, auth: bool) -> String {
        let info = if auth {
            format!("{USER}:{PASSWORD}@")
        } else {
            String::new()
        };
        format!("{scheme}://{info}{}", self.address)
    }
    pub fn count(&self) -> usize {
        self.records.connections.load(Ordering::SeqCst)
    }
}
async fn serve(
    kind: Kind,
    socket: TcpStream,
    target: SocketAddr,
    auth: bool,
    r: Arc<Records>,
) -> Result<()> {
    let mut socket: Stream = if matches!(kind, Kind::Https) {
        Box::new(tls_acceptor().accept(socket).await?)
    } else {
        Box::new(socket)
    };
    if matches!(kind, Kind::Socks) {
        let version = socket.read_u8().await?;
        let n = socket.read_u8().await?;
        let mut methods = vec![0; n as usize];
        socket.read_exact(&mut methods).await?;
        let method = if auth { 2 } else { 0 };
        ensure!(
            version == 5 && methods.contains(&method),
            "fixture SOCKS greeting"
        );
        socket.write_all(&[5, method]).await?;
        if auth {
            ensure!(socket.read_u8().await? == 1, "fixture auth version");
            let n = socket.read_u8().await?;
            let mut user = vec![0; n as usize];
            socket.read_exact(&mut user).await?;
            let n = socket.read_u8().await?;
            let mut pass = vec![0; n as usize];
            socket.read_exact(&mut pass).await?;
            if user != USER.as_bytes() || pass != PASSWORD.as_bytes() {
                socket.write_all(&[1, 1]).await?;
                return Ok(());
            }
            socket.write_all(&[1, 0]).await?;
        }
        let mut prefix = [0; 4];
        socket.read_exact(&mut prefix).await?;
        ensure!(prefix[..3] == [5, 1, 0], "fixture SOCKS connect");
        let host = match prefix[3] {
            1 => {
                let mut b = [0; 4];
                socket.read_exact(&mut b).await?;
                std::net::Ipv4Addr::from(b).to_string()
            }
            4 => {
                let mut b = [0; 16];
                socket.read_exact(&mut b).await?;
                std::net::Ipv6Addr::from(b).to_string()
            }
            3 => {
                let n = socket.read_u8().await?;
                let mut b = vec![0; n as usize];
                socket.read_exact(&mut b).await?;
                String::from_utf8(b)?
            }
            _ => anyhow::bail!("fixture SOCKS address type"),
        };
        let port = socket.read_u16().await?;
        validate(&host, port, target)?;
        r.socks_types.lock().unwrap().push(prefix[3]);
        r.targets.lock().unwrap().push(format!("{host}:{port}"));
        r.connections.fetch_add(1, Ordering::SeqCst);
        let mut upstream = TcpStream::connect(target).await?;
        socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
        tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
    } else {
        let bytes = head(&mut *socket).await?;
        let text = std::str::from_utf8(&bytes)?;
        if auth
            && header(text, "proxy-authorization")
                != Some(format!("Basic {}", STANDARD.encode(format!("{USER}:{PASSWORD}"))).as_str())
        {
            // Drain the known fixture body before closing: isolate auth refusal from TCP reset.
            let length = header(text, "content-length")
                .unwrap_or("0")
                .parse::<usize>()?;
            ensure!(length <= 2 * 1024 * 1024, "fixture rejected body limit");
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await?;
            reply(
                &mut socket,
                "407 Proxy Authentication Required",
                "{\"error\":\"proxy_auth\"}",
            )
            .await?;
            return Ok(());
        }
        let first = text.lines().next().context("request line")?;
        let mut fields = first.split_whitespace();
        let method = fields.next().context("method")?;
        let destination = fields.next().context("destination")?;
        let (host, port, forward) = if method == "CONNECT" {
            let url = reqwest::Url::parse(&format!("http://{destination}"))?;
            (
                url.host_str().context("host")?.to_owned(),
                url.port_or_known_default().unwrap(),
                None,
            )
        } else {
            let url = reqwest::Url::parse(destination)?;
            ensure!(url.scheme() == "http", "fixture absolute HTTP URI");
            let mut path = url.path().to_owned();
            if let Some(q) = url.query() {
                path.push('?');
                path.push_str(q);
            }
            let upgrading =
                header(text, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
            let mut rewritten = format!("{method} {path} HTTP/1.1\r\n");
            for line in text.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
                if !line
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("proxy-authorization")
                    && (upgrading
                        || !line
                            .split(':')
                            .next()
                            .unwrap_or("")
                            .eq_ignore_ascii_case("connection"))
                {
                    rewritten.push_str(line);
                    rewritten.push_str("\r\n");
                }
            }
            // One plain HTTP request per connection: never forward a later Proxy-Authorization header.
            if !upgrading {
                rewritten.push_str("Connection: close\r\n");
            }
            rewritten.push_str("\r\n");
            (
                url.host_str().context("host")?.to_owned(),
                url.port_or_known_default().unwrap(),
                Some(rewritten),
            )
        };
        validate(&host, port, target)?;
        r.targets.lock().unwrap().push(format!("{host}:{port}"));
        r.connections.fetch_add(1, Ordering::SeqCst);
        let mut upstream = TcpStream::connect(target).await?;
        if let Some(forward) = forward {
            upstream.write_all(forward.as_bytes()).await?;
        } else {
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
        }
        tokio::io::copy_bidirectional(&mut socket, &mut upstream).await?;
    }
    Ok(())
}
fn validate(host: &str, port: u16, target: SocketAddr) -> Result<()> {
    ensure!(
        port == target.port()
            && matches!(
                host,
                "127.0.0.1"
                    | "127.0.0.2"
                    | "localhost"
                    | "::1"
                    | "[::1]"
                    | "relay.invalid"
                    | "unlisted.invalid"
            ),
        "fixture prohibits external forwarding"
    );
    Ok(())
}
