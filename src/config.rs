use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};

pub const MAX_FILE: u64 = 8 * 1024 * 1024;

/// Directory policy is a convenience guard, NOT a sandbox against local races or shell access.
#[derive(Clone)]
pub struct Policy {
    pub roots: Vec<PathBuf>,
    pub allow_shell: bool,
    pub allow_transfers: bool,
    pub network: crate::network::Network,
}
impl Policy {
    pub fn new(roots: Vec<PathBuf>, allow_shell: bool) -> Result<Self> {
        ensure!(!roots.is_empty(), "at least one --allow-dir is required");
        let roots = roots
            .into_iter()
            .map(|p| {
                let p = fs::canonicalize(p).context("resolve allowed directory")?;
                ensure!(p.is_dir(), "allowed root must be a directory");
                Ok(p)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            roots,
            allow_shell,
            allow_transfers: true,
            network: crate::network::Network::default(),
        })
    }
    pub fn resolve(&self, input: &str) -> Result<PathBuf> {
        let path = Path::new(input);
        ensure!(path.is_absolute(), "absolute paths are required");
        ensure!(
            !path.components().any(|c| matches!(c, Component::ParentDir)),
            "parent traversal is forbidden"
        );
        #[cfg(windows)]
        {
            for component in path.components() {
                match component {
                    Component::Normal(name) => ensure!(
                        !name.to_string_lossy().contains(':'),
                        "alternate data streams are forbidden"
                    ),
                    Component::Prefix(prefix) => ensure!(
                        matches!(
                            prefix.kind(),
                            std::path::Prefix::Disk(_)
                                | std::path::Prefix::VerbatimDisk(_)
                                | std::path::Prefix::UNC(..)
                                | std::path::Prefix::VerbatimUNC(..)
                        ),
                        "device namespace paths are forbidden"
                    ),
                    _ => {}
                }
            }
        }
        // Resolve through the nearest existing ancestor to cover not-yet-created destinations.
        let mut ancestor = path;
        let mut suffix = Vec::new();
        loop {
            match fs::symlink_metadata(ancestor) {
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    suffix.push(ancestor.file_name().context("invalid path")?.to_os_string());
                    ancestor = ancestor.parent().context("no existing ancestor")?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        let mut resolved =
            fs::canonicalize(ancestor).context("canonicalize path (dangling links are denied)")?;
        for part in suffix.into_iter().rev() {
            resolved.push(part);
        }
        ensure!(
            self.roots.iter().any(|root| resolved.starts_with(root)),
            "path outside allowed directories"
        );
        Ok(resolved)
    }
    pub fn describe(&self) -> Value {
        json!({"allowedDirectories":self.roots,"shellEnabled":self.allow_shell,"encryptedTransfersEnabled":self.allow_transfers,
            "telemetryEnabled":false,"fileReadLineLimit":1000,"maxFileBytes":MAX_FILE,
            "policyMutableRemotely":false,"outboundNetwork":self.network.describe(),"version":env!("CARGO_PKG_VERSION")})
    }
    pub fn read_text(&self, path: &str) -> Result<String> {
        let path = self.resolve(path)?;
        let metadata = fs::metadata(&path)?;
        ensure!(metadata.is_file(), "not a regular file");
        ensure!(metadata.len() <= MAX_FILE, "file exceeds 8 MiB text limit");
        // Take protects against growth after metadata was inspected.
        use std::io::Read;
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(MAX_FILE + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_FILE,
            "file exceeds 8 MiB text limit"
        );
        let text = String::from_utf8(bytes).context("only UTF-8 text is supported")?;
        if text.contains('\0') {
            bail!("binary document not supported by text tools");
        }
        Ok(text)
    }
}

pub fn string<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{key} must be a string"))
}
pub fn integer(args: &Value, key: &str, default: i64, min: i64, max: i64) -> Result<i64> {
    let n = match args.get(key) {
        None => default,
        Some(v) => v
            .as_i64()
            .with_context(|| format!("{key} must be an integer"))?,
    };
    ensure!((min..=max).contains(&n), "{key} must be in {min}..={max}");
    Ok(n)
}
pub fn boolean(args: &Value, key: &str, default: bool) -> Result<bool> {
    match args.get(key) {
        None => Ok(default),
        Some(v) => v
            .as_bool()
            .with_context(|| format!("{key} must be boolean")),
    }
}
