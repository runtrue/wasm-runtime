use crate::{Error, Result, WASMTIME_VERSION, WasiProfile};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

type HmacSha256 = Hmac<Sha256>;
const CACHE_DOMAIN: &[u8] = b"runtrue-wasm-runtime.aot.v1\0";
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Secret key used to authenticate native AOT bytes before deserialization.
#[derive(Clone)]
pub struct AotAuthenticationKey([u8; 32]);

impl std::fmt::Debug for AotAuthenticationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AotAuthenticationKey([REDACTED])")
    }
}

impl AotAuthenticationKey {
    /// Construct an authentication key. Production callers should load these
    /// bytes from a private installation secret.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Authenticated on-disk AOT cache configuration.
#[derive(Debug, Clone)]
pub struct DiskCacheConfig {
    /// Private cache directory.
    pub root: PathBuf,
    /// Installation-scoped artifact authentication key.
    pub authentication_key: AotAuthenticationKey,
    /// Maximum accepted or published AOT artifact size.
    pub max_entry_bytes: usize,
}

impl DiskCacheConfig {
    /// Construct a disk cache with a 256 MiB per-entry limit.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, authentication_key: AotAuthenticationKey) -> Self {
        Self {
            root: root.into(),
            authentication_key,
            max_entry_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CacheIdentity {
    format: u8,
    component_digest: String,
    profile: String,
    wasmtime_version: String,
    target: String,
    compiler_profile: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheMetadata {
    identity: CacheIdentity,
    artifact_len: usize,
    authentication_tag: String,
}

pub(crate) struct DiskCache {
    config: DiskCacheConfig,
    target: String,
}

impl DiskCache {
    pub(crate) fn prepare(config: DiskCacheConfig, target: String) -> Result<Self> {
        if config.max_entry_bytes == 0 {
            return Err(Error::Configuration(
                "disk cache entry limit must be positive".to_owned(),
            ));
        }
        fs::create_dir_all(&config.root)?;
        set_private_directory(&config.root)?;
        Ok(Self { config, target })
    }

    pub(crate) fn contains(&self, digest: &str, profile: WasiProfile) -> bool {
        let (artifact, metadata) = self.paths(digest, profile);
        artifact.is_file() && metadata.is_file()
    }

    pub(crate) fn load(&self, digest: &str, profile: WasiProfile) -> Result<Option<Vec<u8>>> {
        let identity = self.identity(digest, profile);
        let (artifact_path, metadata_path) = self.paths(digest, profile);
        if !artifact_path.exists() && !metadata_path.exists() {
            return Ok(None);
        }
        let metadata_bytes = fs::read(&metadata_path)
            .map_err(|error| Error::Cache(format!("metadata read failed: {error}")))?;
        let metadata: CacheMetadata = serde_json::from_slice(&metadata_bytes)
            .map_err(|error| Error::Cache(format!("metadata is malformed: {error}")))?;
        if metadata.identity != identity {
            return Err(Error::Cache("artifact identity is incompatible".to_owned()));
        }
        if metadata.artifact_len > self.config.max_entry_bytes {
            return Err(Error::Cache(
                "artifact exceeds the configured limit".to_owned(),
            ));
        }
        let artifact = fs::read(&artifact_path)
            .map_err(|error| Error::Cache(format!("artifact read failed: {error}")))?;
        if artifact.len() != metadata.artifact_len {
            return Err(Error::Cache(
                "artifact length does not match metadata".to_owned(),
            ));
        }
        let expected = self.authentication_tag(&identity, &artifact)?;
        let supplied = hex::decode(metadata.authentication_tag)
            .map_err(|_| Error::Cache("authentication tag is malformed".to_owned()))?;
        expected
            .verify_slice(&supplied)
            .map_err(|_| Error::Cache("artifact authentication failed".to_owned()))?;
        Ok(Some(artifact))
    }

    pub(crate) fn publish(
        &self,
        digest: &str,
        profile: WasiProfile,
        artifact: &[u8],
    ) -> Result<()> {
        if artifact.len() > self.config.max_entry_bytes {
            return Err(Error::Cache(
                "artifact exceeds the configured limit".to_owned(),
            ));
        }
        let identity = self.identity(digest, profile);
        let tag = self
            .authentication_tag(&identity, artifact)?
            .finalize()
            .into_bytes();
        let metadata = CacheMetadata {
            identity,
            artifact_len: artifact.len(),
            authentication_tag: hex::encode(tag),
        };
        let metadata = serde_json::to_vec(&metadata)
            .map_err(|error| Error::Cache(format!("metadata encoding failed: {error}")))?;
        let (artifact_path, metadata_path) = self.paths(digest, profile);
        atomic_publish(&artifact_path, artifact)?;
        atomic_publish(&metadata_path, &metadata)?;
        Ok(())
    }

    fn identity(&self, digest: &str, profile: WasiProfile) -> CacheIdentity {
        CacheIdentity {
            format: 1,
            component_digest: digest.to_owned(),
            profile: profile.cache_id().to_owned(),
            wasmtime_version: WASMTIME_VERSION.to_owned(),
            target: self.target.clone(),
            compiler_profile: "cranelift-speed-and-size;component-async;fuel;epoch;baseline"
                .to_owned(),
        }
    }

    fn paths(&self, digest: &str, profile: WasiProfile) -> (PathBuf, PathBuf) {
        let profile = match profile {
            WasiProfile::Cli0_3 => "cli-p3",
            WasiProfile::Cli0_2 => "cli-p2",
            WasiProfile::Http0_3 => "http-p3",
            WasiProfile::Http0_2 => "http-p2",
        };
        let stem = format!("{digest}-{profile}");
        (
            self.config.root.join(format!("{stem}.aot")),
            self.config.root.join(format!("{stem}.aot.json")),
        )
    }

    fn authentication_tag(&self, identity: &CacheIdentity, artifact: &[u8]) -> Result<HmacSha256> {
        let mut mac = HmacSha256::new_from_slice(&self.config.authentication_key.0)
            .map_err(|_| Error::Cache("authentication key is invalid".to_owned()))?;
        mac.update(CACHE_DOMAIN);
        mac.update(
            &serde_json::to_vec(identity)
                .map_err(|error| Error::Cache(format!("identity encoding failed: {error}")))?,
        );
        mac.update(artifact);
        Ok(mac)
    }
}

pub(crate) fn component_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn atomic_publish(path: &Path, bytes: &[u8]) -> Result<()> {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = path.with_extension(format!("tmp-{}-{sequence}", std::process::id()));
    fs::write(&temporary, bytes)?;
    set_private_file(&temporary)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file(_path: &Path) -> Result<()> {
    Ok(())
}
