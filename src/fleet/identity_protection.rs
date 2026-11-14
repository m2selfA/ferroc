//! Encrypted at-rest payloads. External key provision is explicit; we never
//! generate/persist a wrapping key beside ciphertext, or fall back to plaintext.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Result, ensure};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;
const MAGIC: &[u8] = b"FROC-VAULT\x01";
pub struct Protection(Backend);
enum Backend {
    #[cfg(windows)]
    CurrentUser,
    External(Zeroizing<[u8; 32]>),
}
impl Protection {
    pub fn windows_current_user() -> Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self(Backend::CurrentUser))
        }
        #[cfg(not(windows))]
        {
            anyhow::bail!("CurrentUser DPAPI unavailable; explicit external wrapping key required")
        }
    }
    /// Key must come from an independently protected caller-approved source.
    /// Not a password KDF or automatic OS credential provider. No Debug/Clone.
    pub fn supplied_key(key: Zeroizing<[u8; 32]>) -> Result<Self> {
        ensure!(*key != [0; 32], "empty wrapping key");
        Ok(Self(Backend::External(key)))
    }
    fn id(&self) -> u8 {
        match self.0 {
            #[cfg(windows)]
            Backend::CurrentUser => 1,
            Backend::External(_) => 2,
        }
    }
    pub(super) fn seal(&self, context: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
        ensure!(plain.len() <= 2048, "oversized protected plaintext");
        let mut out = MAGIC.to_vec();
        out.push(self.id());
        match &self.0 {
            #[cfg(windows)]
            Backend::CurrentUser => {
                out.extend_from_slice(&super::identity_windows::protect(context, plain)?)
            }
            Backend::External(key) => {
                let mut nonce = [0; 12];
                OsRng.fill_bytes(&mut nonce);
                out.extend_from_slice(&nonce);
                let encrypted = Aes256Gcm::new_from_slice(key.as_ref())
                    .expect("32byte wrapping key")
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: plain,
                            aad: context,
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("external identity protection failed"))?;
                out.extend_from_slice(&encrypted);
            }
        }
        Ok(out)
    }
    pub(super) fn open(&self, context: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(
            blob.len() > MAGIC.len() && blob.starts_with(MAGIC) && blob[MAGIC.len()] == self.id(),
            "invalid vault version/backend; no downgrade"
        );
        let rest = &blob[MAGIC.len() + 1..];
        let plain = match &self.0 {
            #[cfg(windows)]
            Backend::CurrentUser => super::identity_windows::unprotect(context, rest)?,
            Backend::External(key) => {
                ensure!(rest.len() >= 28, "truncated wrapped identity");
                Zeroizing::new(
                    Aes256Gcm::new_from_slice(key.as_ref())
                        .expect("32byte wrapping key")
                        .decrypt(
                            Nonce::from_slice(&rest[..12]),
                            Payload {
                                msg: &rest[12..],
                                aad: context,
                            },
                        )
                        .map_err(|_| anyhow::anyhow!("external identity authentication failed"))?,
                )
            }
        };
        ensure!(plain.len() <= 2048, "oversized decrypted identity record");
        Ok(plain)
    }
}
