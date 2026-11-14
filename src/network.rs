//! Shared outbound route policy. No raw proxy URLs/credentials are formatted or persisted.
use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, Proxy, Url, header::HeaderMap};
use serde_json::{Value, json};
use std::{fmt, path::Path, time::Duration};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        handshake::{client::generate_key, derive_accept_key},
        protocol::{Role, WebSocketConfig},
    },
};

#[derive(Clone, Default)]
enum Route {
    #[default]
    Environment,
    Direct,
    Explicit {
        proxy: Box<Proxy>,
        endpoint: String,
        scheme: String,
        authenticated: bool,
    },
}
#[derive(Clone, Default)]
pub struct Network {
    route: Route,
    roots: Vec<reqwest::Certificate>,
}
impl fmt::Debug for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Network").field(&self.describe()).finish()
    }
}
impl Network {
    pub fn direct() -> Self {
        Self {
            route: Route::Direct,
            ..Self::default()
        }
    }
    pub fn proxy(input: &str) -> Result<Self> {
        ensure!(
            input.len() <= 4096
                && !input.chars().any(char::is_whitespace)
                && !input.chars().any(char::is_control),
            "proxy URL is invalid (value omitted)"
        );
        let url =
            Url::parse(input).map_err(|_| anyhow::anyhow!("invalid proxy URL (value omitted)"))?;
        ensure!(
            matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h"),
            "proxy scheme must be http, https, socks5 or socks5h"
        );
        ensure!(
            url.host_str().is_some()
                && !url.cannot_be_a_base()
                && matches!(url.path(), "" | "/")
                && url.query().is_none()
                && url.fragment().is_none(),
            "proxy URL needs a host and must not contain a path, query or fragment"
        );
        let port = url
            .port_or_known_default()
            .context("SOCKS proxy URL requires an explicit port")?;
        ensure!(port != 0, "proxy port must be 1..65535");
        let endpoint = format!(
            "{}://{}:{port}",
            url.scheme(),
            url.host_str().expect("validated host")
        );
        let authenticated = !url.username().is_empty() || url.password().is_some();
        let proxy = Proxy::all(url.clone())
            .map_err(|_| anyhow::anyhow!("invalid proxy configuration (value omitted)"))?;
        Ok(Self {
            route: Route::Explicit {
                proxy: Box::new(proxy),
                endpoint,
                scheme: url.scheme().into(),
                authenticated,
            },
            roots: Vec::new(),
        })
    }
    /// The dedicated environment value is supplied by the CLI, never read/mutated globally here.
    pub fn select(cli: Option<&str>, no_proxy: bool, dedicated_env: Option<&str>) -> Result<Self> {
        ensure!(
            !(no_proxy && cli.is_some()),
            "--proxy conflicts with --no-proxy"
        );
        if no_proxy {
            return Ok(Self::direct());
        }
        match cli.or(dedicated_env.filter(|v| !v.is_empty())) {
            Some(v) => Self::proxy(v),
            None => Ok(Self::default()),
        }
    }
    pub fn with_ca_file(mut self, path: &Path) -> Result<Self> {
        use std::io::Read;
        let file = std::fs::File::open(path).context("cannot read --ca-cert file")?;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .context("cannot read --ca-cert file")?;
        ensure!(bytes.len() <= 1024 * 1024, "CA bundle exceeds 1 MiB");
        let roots = reqwest::Certificate::from_pem_bundle(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid PEM CA bundle"))?;
        ensure!(
            !roots.is_empty() && roots.len() <= 32,
            "CA bundle must contain 1..32 certificates"
        );
        self.roots = roots;
        Ok(self)
    }
    pub fn describe(&self) -> Value {
        let mut value = match &self.route {
            Route::Environment => json!({"mode":"environment"}),
            Route::Direct => json!({"mode":"direct"}),
            Route::Explicit {
                endpoint,
                scheme,
                authenticated,
                ..
            } => {
                json!({"mode":"explicit","endpoint":endpoint,"scheme":scheme,"authenticationConfigured":authenticated})
            }
        };
        value["additionalCaCertificates"] = json!(self.roots.len());
        value
    }
    pub fn client(&self, budget: Option<Duration>) -> Result<Client> {
        let mut builder = Client::builder()
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5));
        builder = match &self.route {
            Route::Environment if environment_bypass_all() => builder.no_proxy(),
            Route::Environment => builder,
            Route::Direct => builder.no_proxy(),
            Route::Explicit { proxy, .. } => builder.no_proxy().proxy((**proxy).clone()),
        };
        for root in &self.roots {
            builder = builder.add_root_certificate(root.clone());
        }
        if let Some(budget) = budget {
            builder = builder.timeout(budget);
        }
        builder.build().map_err(http_error)
    }
    /// Use the SAME proxy/DNS/TLS connector as HTTP, then validate RFC6455 before framing.
    /// None means relay 401/403, never a proxy 407. No direct fallback is performed.
    pub async fn websocket(
        &self,
        url: Url,
        token: &str,
        config: WebSocketConfig,
    ) -> Result<Option<WebSocketStream<reqwest::Upgraded>>> {
        self.websocket_inner(url, token, config, None).await
    }
    /// Same route/TLS/HTTP-upgrade validation; private join secret never in URL.
    #[cfg(feature = "fleet-core")]
    pub async fn fleet_websocket(
        &self,
        url: Url,
        token: &str,
        join: &str,
        config: WebSocketConfig,
    ) -> Result<Option<WebSocketStream<reqwest::Upgraded>>> {
        ensure!(
            join.len() == 64 && join.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid fleet join credential"
        );
        self.websocket_inner(url, token, config, Some(join)).await
    }
    async fn websocket_inner(
        &self,
        mut url: Url,
        token: &str,
        config: WebSocketConfig,
        join: Option<&str>,
    ) -> Result<Option<WebSocketStream<reqwest::Upgraded>>> {
        let scheme = match url.scheme() {
            "wss" => "https",
            "ws" => "http",
            _ => bail!("expected ws or wss URL"),
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("invalid WebSocket URL"))?;
        let connect = async {
            let key = generate_key();
            let request = self.client(None)?.get(url).bearer_auth(token);
            let request = if let Some(ticket) = join {
                let mut value = reqwest::header::HeaderValue::from_str(ticket)?;
                value.set_sensitive(true);
                request
                    .header("X-Ferroc-Fleet-Join", value)
                    .header("X-Ferroc-Fleet-Protocol", "1")
            } else {
                request.header("X-BRC-Protocol", "1")
            };
            let response = request
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Version", "13")
                .header("Sec-WebSocket-Key", &key)
                .send()
                .await
                .map_err(http_error)?;
            if matches!(response.status().as_u16(), 401 | 403) {
                return Ok(None);
            }
            ensure!(
                response.status() == reqwest::StatusCode::SWITCHING_PROTOCOLS,
                "WebSocket handshake rejected (HTTP {})",
                response.status()
            );
            validate_upgrade(response.headers(), &key)?;
            let stream = response.upgrade().await.map_err(http_error)?;
            Ok(Some(
                WebSocketStream::from_raw_socket(stream, Role::Client, Some(config)).await,
            ))
        };
        tokio::time::timeout(Duration::from_secs(15), connect)
            .await
            .context("WebSocket/proxy handshake timed out after 15s")?
    }
}
// hyper-util0.1.21 checks IPs separately and misses the domain-only wildcard.
// Honor NO_PROXY=* for BOTH domains and IPs, but only in environment mode.
fn environment_bypass_all() -> bool {
    std::env::var("NO_PROXY")
        .or_else(|_| std::env::var("no_proxy"))
        .is_ok_and(|value| value.split(',').any(|part| part.trim() == "*"))
}
fn one<'a>(headers: &'a HeaderMap, key: &str) -> Option<&'a str> {
    let mut values = headers.get_all(key).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}
fn validate_upgrade(headers: &HeaderMap, key: &str) -> Result<()> {
    ensure!(
        one(headers, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")),
        "invalid WebSocket Upgrade header"
    );
    ensure!(
        headers
            .get_all("connection")
            .iter()
            .any(|h| h.to_str().is_ok_and(|s| s
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("upgrade")))),
        "missing WebSocket Connection upgrade token"
    );
    ensure!(
        one(headers, "sec-websocket-accept") == Some(derive_accept_key(key.as_bytes()).as_str()),
        "invalid WebSocket accept key"
    );
    ensure!(
        !headers.contains_key("sec-websocket-protocol")
            && !headers.contains_key("sec-websocket-extensions"),
        "unsolicited WebSocket protocol or extension"
    );
    Ok(())
}
/// Do not attach raw connector errors: some contain proxy URLs or peer-supplied text.
pub fn http_error(error: reqwest::Error) -> anyhow::Error {
    if let Some(status) = error.status() {
        return anyhow::anyhow!("outbound HTTP request failed ({status})");
    }
    let kind = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection/proxy/DNS/TLS failure"
    } else if error.is_builder() {
        "invalid request or client configuration"
    } else if error.is_body() || error.is_decode() {
        "response body failure"
    } else {
        "request/upgrade failure"
    };
    anyhow::anyhow!(
        "outbound HTTP {kind}; check the configured route and certificates (connector details omitted to protect credentials)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_proxy_urls_and_redacted_status() {
        for url in [
            "http://user:do-not-print@127.0.0.1:8080",
            "https://user:do-not-print@localhost:443",
            "socks5://user:do-not-print@localhost:1080",
            "socks5h://user:do-not-print@[::1]:1080",
        ] {
            let n = Network::proxy(url).unwrap();
            let text = format!("{n:?} {}", n.describe());
            assert!(!text.contains("do-not-print") && !text.contains("user@"));
            assert_eq!(n.describe()["authenticationConfigured"], true);
        }
        for bad in [
            "user:do-not-print@localhost",
            "ftp://user:do-not-print@localhost:21",
            "http://localhost:0",
            "http://localhost/path",
            "http://localhost?password=do-not-print",
            "socks5://localhost",
            "http://localhost/#do-not-print",
            "http://user:do-not-print@localhost\n",
        ] {
            let error = Network::proxy(bad).unwrap_err();
            assert!(!format!("{error:#}").contains("do-not-print"));
        }
    }
    #[test]
    fn explicit_flags_override_environment_without_fallback() {
        assert_eq!(
            Network::select(Some("http://localhost:8080"), false, Some("invalid"))
                .unwrap()
                .describe()["mode"],
            "explicit"
        );
        assert_eq!(
            Network::select(None, true, Some("invalid"))
                .unwrap()
                .describe()["mode"],
            "direct"
        );
        assert!(Network::select(Some("http://localhost:8080"), true, None).is_err());
        assert!(Network::select(None, false, Some("invalid")).is_err());
        assert_eq!(
            Network::select(None, false, None).unwrap().describe()["mode"],
            "environment"
        );
    }
    #[test]
    fn upgrade_checks_accept_tokens_and_reject_unsolicited_or_duplicate_fields() {
        let mut headers = HeaderMap::new();
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        headers.insert("connection", "keep-alive, Upgrade".parse().unwrap());
        headers.insert(
            "sec-websocket-accept",
            derive_accept_key(b"test-key").parse().unwrap(),
        );
        validate_upgrade(&headers, "test-key").unwrap();
        for name in ["sec-websocket-extensions", "sec-websocket-protocol"] {
            let mut h = headers.clone();
            h.insert(name, "unexpected".parse().unwrap());
            assert!(validate_upgrade(&h, "test-key").is_err());
        }
        for name in ["upgrade", "connection", "sec-websocket-accept"] {
            let mut h = headers.clone();
            h.remove(name);
            assert!(validate_upgrade(&h, "test-key").is_err());
        }
        headers.append(
            "sec-websocket-accept",
            derive_accept_key(b"test-key").parse().unwrap(),
        );
        assert!(validate_upgrade(&headers, "test-key").is_err());
    }
}
