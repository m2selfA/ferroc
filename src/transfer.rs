//! BRCX1 v1 compatibility, pinned to upstream cbe5117 file-transfer.ts.
//! Never a sender-identity protocol. Provider URLs are fixed/validated; no redirect following.
use crate::config::{Policy, boolean, integer, string};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag, aead::AeadInPlace};
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use reqwest::{
    Client, Url,
    multipart::{Form, Part},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
#[path = "transfer_tests.rs"]
mod tests;

const MAX_BYTES: usize = 99_000_000;
const MAX_KEYS: usize = 128;
const SPKI: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0,
];
const FILE_AAD: &[u8] = b"BRCX1:file";
const WRAP_AAD: &[u8] = b"BRCX1:key";
const WRAP_INFO: &[u8] = b"brc-file-transfer-v1";
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn iso(ms: u64) -> String {
    humantime::format_rfc3339_millis(UNIX_EPOCH + Duration::from_millis(ms)).to_string()
}
fn random<const N: usize>() -> [u8; N] {
    let mut a = [0; N];
    OsRng.fill_bytes(&mut a);
    a
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
fn fixed<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = STANDARD.decode(s).context("invalid base64 field")?;
    v.try_into()
        .map_err(|_| anyhow::anyhow!("invalid base64 field length"))
}
fn public(s: &str) -> Result<PublicKey> {
    let der = fixed::<44>(s)?;
    ensure!(der[..12] == SPKI, "expected X25519 SPKI public key");
    Ok(PublicKey::from(<[u8; 32]>::try_from(&der[12..])?))
}
fn public_b64(secret: &StaticSecret) -> String {
    let mut der = SPKI.to_vec();
    der.extend(PublicKey::from(secret).as_bytes());
    b64(&der)
}
fn wrapping(
    secret: &StaticSecret,
    peer: &PublicKey,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(peer);
    ensure!(
        shared.was_contributory(),
        "invalid low-order X25519 public key"
    );
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(salt), shared.as_bytes())
        .expand(WRAP_INFO, key.as_mut())
        .map_err(|_| anyhow::anyhow!("HKDF failed"))?;
    Ok(key)
}
fn encrypt(key: &[u8; 32], iv: &[u8; 12], aad: &[u8], data: &mut [u8]) -> Result<[u8; 16]> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid AES key"))?;
    Ok(cipher
        .encrypt_in_place_detached(Nonce::from_slice(iv), aad, data)
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?
        .into())
}
fn decrypt(
    key: &[u8; 32],
    iv: &[u8; 12],
    tag: &[u8; 16],
    aad: &[u8],
    data: &mut [u8],
) -> Result<()> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("invalid AES key"))?
        .decrypt_in_place_detached(Nonce::from_slice(iv), aad, data, Tag::from_slice(tag))
        .map_err(|_| anyhow::anyhow!("AES-GCM authentication failed"))
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Envelope {
    v: u8,
    provider: String,
    url: String,
    size: usize,
    sha256: String,
    expires_at: u64,
    file_iv: String,
    file_tag: String,
    sender_public_key: String,
    wrap_salt: String,
    wrap_iv: String,
    wrap_tag: String,
    wrapped_key: String,
}
fn provider_url(s: &str) -> Result<Url> {
    ensure!(s.len() <= 4096, "provider URL too long");
    let u = Url::parse(s)?;
    ensure!(
        u.scheme() == "https"
            && matches!(u.host_str(), Some("tmpfiles.org" | "www.tmpfiles.org"))
            && u.port_or_known_default() == Some(443)
            && u.username().is_empty()
            && u.password().is_none()
            && u.fragment().is_none(),
        "unsupported provider URL"
    );
    Ok(u)
}
impl Envelope {
    fn decode(token: &str) -> Result<Self> {
        ensure!(token.len() <= 16384, "transfer token too long");
        let e: Self = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(token)
                .context("invalid BRCX1 token encoding")?,
        )
        .context("invalid BRCX1 envelope")?;
        ensure!(
            e.v == 1 && e.provider == "tmpfiles.org",
            "unsupported BRCX1 version/provider"
        );
        provider_url(&e.url)?;
        ensure!(e.size <= MAX_BYTES, "invalid transfer size");
        ensure!(
            e.sha256.len() == 64
                && e.sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid SHA-256"
        );
        ensure!(e.expires_at > now(), "transfer token expired");
        ensure!(
            e.expires_at <= now() + 7_200_000,
            "transfer token expiry exceeds maximum TTL"
        );
        fixed::<12>(&e.file_iv)?;
        fixed::<16>(&e.file_tag)?;
        public(&e.sender_public_key)?;
        fixed::<16>(&e.wrap_salt)?;
        fixed::<12>(&e.wrap_iv)?;
        fixed::<16>(&e.wrap_tag)?;
        fixed::<32>(&e.wrapped_key)?;
        Ok(e)
    }
    fn encode(&self) -> Result<String> {
        Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(self)?))
    }
}
fn seal(mut data: Zeroizing<Vec<u8>>, recipient: &str, ttl: u64) -> Result<(Envelope, Vec<u8>)> {
    ensure!(data.len() <= MAX_BYTES, "file exceeds 99 MB transfer limit");
    let recipient = public(recipient)?;
    let sender = StaticSecret::random();
    let salt = random::<16>();
    let wrap = wrapping(&sender, &recipient, &salt)?;
    let mut file_key = Zeroizing::new(random::<32>());
    let file_iv = random::<12>();
    let sha256 = hex(&Sha256::digest(&*data));
    let file_tag = encrypt(&file_key, &file_iv, FILE_AAD, &mut data)?;
    let wrap_iv = random::<12>();
    let mut wrapped = Zeroizing::new(file_key.to_vec());
    let wrap_tag = encrypt(&wrap, &wrap_iv, WRAP_AAD, &mut wrapped)?;
    file_key.zeroize();
    let e = Envelope {
        v: 1,
        provider: "tmpfiles.org".into(),
        url: String::new(),
        size: data.len(),
        sha256,
        expires_at: now() + ttl * 1000,
        file_iv: b64(&file_iv),
        file_tag: b64(&file_tag),
        sender_public_key: public_b64(&sender),
        wrap_salt: b64(&salt),
        wrap_iv: b64(&wrap_iv),
        wrap_tag: b64(&wrap_tag),
        wrapped_key: b64(&wrapped),
    };
    Ok((e, std::mem::take(&mut *data)))
}
fn unseal(
    e: &Envelope,
    secret: &StaticSecret,
    mut data: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(data.len() == e.size, "transfer ciphertext size mismatch");
    let salt = fixed::<16>(&e.wrap_salt)?;
    let wrap = wrapping(secret, &public(&e.sender_public_key)?, &salt)?;
    let mut key = Zeroizing::new(fixed::<32>(&e.wrapped_key)?);
    decrypt(
        &wrap,
        &fixed(&e.wrap_iv)?,
        &fixed(&e.wrap_tag)?,
        WRAP_AAD,
        &mut *key,
    )?;
    decrypt(
        &key,
        &fixed(&e.file_iv)?,
        &fixed(&e.file_tag)?,
        FILE_AAD,
        &mut data,
    )?;
    ensure!(
        hex(&Sha256::digest(&*data)) == e.sha256,
        "transfer SHA-256 mismatch"
    );
    Ok(data)
}
struct ReceiveKey {
    secret: StaticSecret,
    expires: u64,
}
pub(crate) struct Transfers {
    keys: Arc<Mutex<HashMap<String, ReceiveKey>>>,
    gate: Arc<Semaphore>,
    #[cfg(test)]
    origin_override: Option<String>,
    #[cfg(test)]
    commit_ready: Option<Arc<tokio::sync::Notify>>,
}
impl Default for Transfers {
    fn default() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            gate: Arc::new(Semaphore::new(1)),
            #[cfg(test)]
            origin_override: None,
            #[cfg(test)]
            commit_ready: None,
        }
    }
}
impl Transfers {
    pub(crate) fn shutdown(&self) {
        self.keys.lock().expect("receive keys").clear();
    }
    fn request_url(&self, url: &str) -> Result<Url> {
        let url = provider_url(url)?;
        #[cfg(test)]
        if let Some(base) = &self.origin_override {
            let mut target = Url::parse(base)?;
            target.set_path(url.path());
            target.set_query(url.query());
            return Ok(target);
        }
        Ok(url)
    }
    fn prepare(&self, args: &Value) -> Result<Value> {
        let ttl = integer(args, "ttlSeconds", 3600, 60, 7200)? as u64;
        let mut keys = self.keys.lock().expect("receive keys");
        keys.retain(|_, k| k.expires > now());
        ensure!(keys.len() < MAX_KEYS, "too many pending receive keys");
        let secret = StaticSecret::random();
        let id = hex(&random::<16>());
        let expires = now() + ttl * 1000;
        let public = public_b64(&secret);
        keys.insert(id.clone(), ReceiveKey { secret, expires });
        let weak = Arc::downgrade(&self.keys);
        let expiry_id = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(ttl)).await;
            if let Some(keys) = weak.upgrade() {
                let mut keys = keys.lock().expect("receive keys");
                if keys.get(&expiry_id).is_some_and(|k| k.expires <= now()) {
                    keys.remove(&expiry_id);
                }
            }
        });
        Ok(json!({"receiveId":id,"recipientPublicKey":public,"expiresAt":iso(expires)}))
    }
    pub(crate) async fn call(
        &self,
        policy: &Policy,
        tool: &str,
        args: Value,
        fs_gate: Arc<Mutex<()>>,
    ) -> Result<Value> {
        ensure!(
            policy.allow_transfers,
            "encrypted transfers disabled by local --no-transfers policy"
        );
        let permit = Arc::new(
            self.gate
                .clone()
                .try_acquire_owned()
                .context("another transfer is active; retry after it finishes")?,
        );
        match tool {
            "prepare_file_transfer" => self.prepare(&args),
            "send_file_transfer" => {
                let ttl = integer(&args, "expireSeconds", 3600, 60, 7200)? as u64;
                let recipient = string(&args, "recipientPublicKey")?.to_owned();
                public(&recipient)?;
                let path = policy.resolve(string(&args, "sourcePath")?)?;
                let read_permit = permit.clone();
                let (mut e, ciphertext) = tokio::task::spawn_blocking(move || {
                    let _permit = read_permit;
                    let _lock = fs_gate.lock().expect("filesystem gate");
                    ensure!(
                        fs::metadata(&path)?.is_file(),
                        "source must be a regular file"
                    );
                    let file = fs::File::open(path)?;
                    let m = file.metadata()?;
                    ensure!(
                        m.is_file() && m.len() <= MAX_BYTES as u64,
                        "source must be a regular file at most 99 MB"
                    );
                    let mut data = Zeroizing::new(Vec::with_capacity(m.len() as usize));
                    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut data)?;
                    seal(data, &recipient, ttl)
                })
                .await??;
                let client = client(&policy.network)?;
                let form = Form::new()
                    .part(
                        "file",
                        Part::bytes(ciphertext)
                            .file_name(format!("{}.brcx", hex(&random::<12>())))
                            .mime_str("application/octet-stream")?,
                    )
                    .text("expire", ttl.to_string());
                let response = client
                    .post(self.request_url("https://tmpfiles.org/api/v1/upload")?)
                    .multipart(form)
                    .send()
                    .await
                    .map_err(crate::network::http_error)?
                    .error_for_status()
                    .map_err(crate::network::http_error)?;
                let reply: Value = serde_json::from_slice(&body(response, 65536).await?)?;
                ensure!(reply["status"] == "success", "provider upload rejected");
                e.url = provider_url(
                    reply["data"]["url"]
                        .as_str()
                        .context("missing provider URL")?,
                )?
                .to_string();
                ensure!(e.expires_at > now(), "transfer expired during upload");
                Ok(
                    json!({"transferToken":e.encode()?,"size":e.size,"sha256":e.sha256,"expiresAt":iso(e.expires_at),"provider":"tmpfiles.org","encrypted":true}),
                )
            }
            "receive_file_transfer" => {
                let id = string(&args, "receiveId")?;
                ensure!(
                    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
                    "invalid receiveId"
                );
                let overwrite = boolean(&args, "overwrite", false)?;
                let e = Envelope::decode(string(&args, "transferToken")?)?;
                let destination = policy.resolve(string(&args, "destinationPath")?)?;
                check_destination(&destination, overwrite)?;
                let (secret, expires) = {
                    let mut keys = self.keys.lock().expect("receive keys");
                    keys.retain(|_, k| k.expires > now());
                    let k = keys.get(id).context("receive session missing or expired")?;
                    (k.secret.clone(), k.expires)
                };
                // Authenticate the wrapped key BEFORE any remote request. Failed attempts retain the key.
                let salt = fixed::<16>(&e.wrap_salt)?;
                let wrap = wrapping(&secret, &public(&e.sender_public_key)?, &salt)?;
                let mut key = Zeroizing::new(fixed::<32>(&e.wrapped_key)?);
                decrypt(
                    &wrap,
                    &fixed(&e.wrap_iv)?,
                    &fixed(&e.wrap_tag)?,
                    WRAP_AAD,
                    &mut *key,
                )?;
                drop(key);
                let client = client(&policy.network)?;
                let mut url = provider_url(&e.url)?;
                if !url.path().starts_with("/dl/") {
                    let html = String::from_utf8(
                        body(
                            client
                                .get(self.request_url(url.as_str())?)
                                .send()
                                .await
                                .map_err(crate::network::http_error)?
                                .error_for_status()
                                .map_err(crate::network::http_error)?,
                            1024 * 1024,
                        )
                        .await?,
                    )?;
                    let re = regex::Regex::new(
                        r#"(?i)<a[^>]+class=["']download["'][^>]+href=["']([^"']+)["']"#,
                    )?;
                    let captures = re
                        .captures(&html)
                        .context("provider page missing download link")?;
                    url = provider_url(url.join(&captures[1])?.as_str())?;
                    ensure!(
                        url.path().starts_with("/dl/"),
                        "provider returned invalid download path"
                    );
                }
                let ciphertext = body(
                    client
                        .get(self.request_url(url.as_str())?)
                        .send()
                        .await
                        .map_err(crate::network::http_error)?
                        .error_for_status()
                        .map_err(crate::network::http_error)?,
                    e.size,
                )
                .await?;
                let policy = policy.clone();
                let token_expiry = e.expires_at;
                let size = e.size;
                let hash = e.sha256.clone();
                let commit_permit = permit.clone();
                let keys = self.keys.clone();
                let receive_id = id.to_owned();
                #[cfg(test)]
                let commit_ready = self.commit_ready.clone();
                let output = tokio::task::spawn_blocking(move || {
                    let _permit = commit_permit;
                    let data = unseal(&e, &secret, Zeroizing::new(ciphertext))?;
                    #[cfg(test)]
                    if let Some(ready) = commit_ready {
                        ready.notify_one();
                    }
                    let _lock = fs_gate.lock().expect("filesystem gate");
                    ensure!(
                        now() < expires && now() < token_expiry,
                        "receive session or token expired before commit"
                    );
                    // Re-check policy and no-clobber condition after IO/crypto, with the shared mutation gate.
                    let destination =
                        policy.resolve(destination.to_str().context("non-UTF8 destination")?)?;
                    check_destination(&destination, overwrite)?;
                    let parent = destination.parent().context("destination has no parent")?;
                    fs::create_dir_all(parent)?;
                    let mut stage = tempfile::NamedTempFile::new_in(parent)?;
                    stage.write_all(&data)?;
                    stage.as_file().sync_all()?;
                    ensure!(
                        now() < expires && now() < token_expiry,
                        "receive session or token expired before commit"
                    );
                    if overwrite {
                        stage.persist(&destination).map_err(|e| e.error)?;
                    } else {
                        stage.persist_noclobber(&destination).map_err(|e| e.error)?;
                    }
                    keys.lock().expect("receive keys").remove(&receive_id);
                    Ok::<PathBuf, anyhow::Error>(destination)
                })
                .await??;
                Ok(json!({"path":output,"size":size,"sha256":hash,"verified":true}))
            }
            _ => bail!("unknown transfer tool"),
        }
    }
}
fn client(network: &crate::network::Network) -> Result<Client> {
    network.client(Some(Duration::from_secs(30)))
}
async fn body(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    if let Some(n) = response.content_length() {
        ensure!(n <= max as u64, "provider body exceeds byte limit");
    }
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(crate::network::http_error)? {
        ensure!(
            out.len().saturating_add(chunk.len()) <= max,
            "provider body exceeds byte limit"
        );
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
fn check_destination(path: &std::path::Path, overwrite: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) => ensure!(
            m.is_file() && overwrite,
            "destination exists or is not a regular file; overwrite must be true"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
