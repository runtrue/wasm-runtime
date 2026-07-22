use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const IDENTITY_DOMAIN: &[u8] = b"runtrue.environment\0v1\0";
const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_LIST_ENTRIES: usize = 256;
const MAX_TOKEN_BYTES: usize = 256;

#[derive(Deserialize)]
struct ManifestEnvelope {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
}

/// Version 1 of the immutable WASIX environment manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentManifest {
    /// Manifest schema version. Version 1 is the only supported value.
    pub schema_version: u32,
    /// Content identity calculated from every other manifest field.
    pub environment_id: String,
    /// Execution ABI profile. Version 1 requires `wasix32-v1`.
    pub execution_profile: String,
    /// Guest language runtime identity.
    pub language: EnvironmentLanguage,
    /// Immutable executable artifact metadata.
    pub artifact: EnvironmentArtifact,
    /// WebAssembly features required by the artifact, sorted lexically.
    pub required_wasm_features: Vec<String>,
    /// Callable command catalog.
    pub commands: EnvironmentCommands,
    /// Guest filesystem policy.
    pub filesystem: EnvironmentFilesystem,
    /// Reproducible build identity inputs.
    pub build: EnvironmentBuild,
}

/// Language identity recorded in an environment manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentLanguage {
    /// Customer-facing language name.
    pub name: String,
    /// Pinned language runtime version.
    pub version: String,
    /// Concrete runtime implementation.
    pub implementation: String,
}

/// Immutable environment artifact reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentArtifact {
    /// Artifact format. Version 1 requires `webc`.
    pub format: String,
    /// Portable artifact basename. Version 1 requires `environment.webc`.
    pub path: String,
    /// Lowercase SHA-256 hex digest of the artifact bytes.
    pub sha256: String,
}

/// Command catalog embedded in an environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentCommands {
    /// Command selected when no override is supplied.
    pub default: String,
    /// Complete, lexically sorted set of callable command names.
    pub available: Vec<String>,
}

/// Guest filesystem policy declared by the environment builder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentFilesystem {
    /// Lexically sorted absolute guest paths sourced from the sealed package.
    pub immutable: Vec<String>,
    /// Fresh writable guest paths. Version 1 requires `/tmp` and `/work`.
    pub writable: Vec<String>,
}

/// Deterministic build inputs that participate in environment identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentBuild {
    /// Pinned toolchain cohort identity.
    pub toolchain_id: String,
    /// Source tree digest or content identity.
    pub source_digest: String,
    /// Dependency lockfile digest or content identity.
    pub lock_digest: String,
}

impl EnvironmentManifest {
    /// Parse and validate a bounded version 1 manifest.
    ///
    /// JSON whitespace, object-key order, and escape spelling do not affect
    /// the environment identity. Arrays that model sets must already be in
    /// lexical order so every producer emits the same version 1 manifest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed JSON, an unsupported schema, a
    /// non-canonical field, or an identity mismatch.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Limit("environment manifest bytes"));
        }
        let envelope: ManifestEnvelope = serde_json::from_slice(bytes).map_err(|error| {
            Error::Preparation(format!("invalid environment manifest: {error}"))
        })?;
        if envelope.schema_version != 1 {
            return Err(Error::UnsupportedComponent(format!(
                "unsupported environment schema version {}",
                envelope.schema_version
            )));
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|error| {
            Error::Preparation(format!("invalid environment manifest: {error}"))
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Validate all version 1 invariants and the content identity.
    ///
    /// # Errors
    ///
    /// Returns an error when any manifest field is unsupported,
    /// non-canonical, or inconsistent with `environment_id`.
    pub fn validate(&self) -> Result<()> {
        self.validate_identity_fields()?;
        validate_prefixed_sha256("environment ID", &self.environment_id)?;
        let calculated = self.calculate_environment_id()?;
        if self.environment_id != calculated {
            return Err(Error::Preparation(format!(
                "environment ID mismatch: expected {calculated}, got {}",
                self.environment_id
            )));
        }
        Ok(())
    }

    /// Calculate the version 1 content identity, excluding `environment_id`.
    ///
    /// The hash preimage starts with `runtrue.environment`, a NUL byte, `v1`,
    /// and another NUL byte. It then uses fixed field order with big-endian
    /// lengths before every string and list. This encoding is independent of
    /// JSON formatting and map-key order.
    ///
    /// After the domain, the fields are: schema as a big-endian `u32`, then
    /// execution profile; language name, version, and implementation;
    /// artifact format, path, and digest; required features; default command;
    /// available commands; immutable and writable paths; toolchain ID; source
    /// digest; and lock digest. Each string is its UTF-8 byte length as a
    /// big-endian `u64` followed by its bytes. Each list is its element count
    /// as a big-endian `u64` followed by its encoded strings. Version 1 set
    /// lists are strictly ordered by their ASCII bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if an identity-bearing field is not canonical.
    pub fn calculate_environment_id(&self) -> Result<String> {
        self.validate_identity_fields()?;

        let mut hash = Sha256::new();
        hash.update(IDENTITY_DOMAIN);
        hash.update(self.schema_version.to_be_bytes());
        hash_string(&mut hash, &self.execution_profile);
        hash_string(&mut hash, &self.language.name);
        hash_string(&mut hash, &self.language.version);
        hash_string(&mut hash, &self.language.implementation);
        hash_string(&mut hash, &self.artifact.format);
        hash_string(&mut hash, &self.artifact.path);
        hash_string(&mut hash, &self.artifact.sha256);
        hash_strings(&mut hash, &self.required_wasm_features);
        hash_string(&mut hash, &self.commands.default);
        hash_strings(&mut hash, &self.commands.available);
        hash_strings(&mut hash, &self.filesystem.immutable);
        hash_strings(&mut hash, &self.filesystem.writable);
        hash_string(&mut hash, &self.build.toolchain_id);
        hash_string(&mut hash, &self.build.source_digest);
        hash_string(&mut hash, &self.build.lock_digest);

        Ok(format!("sha256:{}", hex::encode(hash.finalize())))
    }

    /// Replace `environment_id` with the calculated version 1 identity.
    ///
    /// # Errors
    ///
    /// Returns an error if an identity-bearing field is not canonical.
    pub fn with_calculated_environment_id(mut self) -> Result<Self> {
        self.environment_id = self.calculate_environment_id()?;
        Ok(self)
    }

    fn validate_identity_fields(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(Error::UnsupportedComponent(format!(
                "unsupported environment schema version {}",
                self.schema_version
            )));
        }
        if self.execution_profile != "wasix32-v1" {
            return Err(Error::UnsupportedComponent(format!(
                "unsupported environment execution profile {:?}",
                self.execution_profile
            )));
        }
        if self.artifact.format != "webc" {
            return Err(Error::UnsupportedComponent(format!(
                "unsupported environment artifact format {:?}",
                self.artifact.format
            )));
        }
        if self.artifact.path != "environment.webc" {
            return Err(Error::Preparation(
                "schema 1 artifact path must be exactly environment.webc".to_owned(),
            ));
        }
        validate_hex_sha256("artifact SHA-256", &self.artifact.sha256)?;

        validate_text("language name", &self.language.name)?;
        validate_text("language version", &self.language.version)?;
        validate_text("language implementation", &self.language.implementation)?;
        validate_token("toolchain ID", &self.build.toolchain_id)?;
        validate_prefixed_sha256("source digest", &self.build.source_digest)?;
        validate_prefixed_sha256("lock digest", &self.build.lock_digest)?;

        validate_sorted_tokens(
            "required WebAssembly features",
            &self.required_wasm_features,
        )?;
        validate_token("default command", &self.commands.default)?;
        validate_sorted_tokens("available commands", &self.commands.available)?;
        if self
            .commands
            .available
            .binary_search(&self.commands.default)
            .is_err()
        {
            return Err(Error::Preparation(
                "environment default command is missing from the command catalog".to_owned(),
            ));
        }

        validate_sorted_guest_paths("immutable guest paths", &self.filesystem.immutable)?;
        if self.filesystem.writable != ["/tmp", "/work"] {
            return Err(Error::UnsupportedComponent(
                "schema 1 requires fresh writable /tmp and /work only".to_owned(),
            ));
        }
        if self.filesystem.immutable.iter().any(|path| {
            path == "/tmp"
                || path.starts_with("/tmp/")
                || path == "/work"
                || path.starts_with("/work/")
        }) {
            return Err(Error::Preparation(
                "immutable guest paths overlap a writable guest path".to_owned(),
            ));
        }
        let mut round_trip = self.clone();
        round_trip.environment_id = format!("sha256:{}", "0".repeat(64));
        let encoded = serde_json::to_vec(&round_trip).map_err(|error| {
            Error::Preparation(format!("environment manifest cannot be encoded: {error}"))
        })?;
        if encoded.len() > MAX_MANIFEST_BYTES {
            return Err(Error::Limit("environment manifest bytes"));
        }
        Ok(())
    }
}

fn hash_string(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

fn hash_strings(hash: &mut Sha256, values: &[String]) {
    hash.update((values.len() as u64).to_be_bytes());
    for value in values {
        hash_string(hash, value);
    }
}

fn validate_prefixed_sha256(label: &str, value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Preparation(format!("{label} must start with sha256:")))?;
    validate_hex_sha256(label, digest)
}

fn validate_hex_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::Preparation(format!(
            "{label} must contain exactly 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
    {
        return Err(Error::Preparation(format!(
            "{label} must be 1 to {MAX_TOKEN_BYTES} printable ASCII bytes"
        )));
    }
    Ok(())
}

fn validate_token(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+' | b':')
        })
    {
        return Err(Error::Preparation(format!(
            "{label} must be a bounded portable ASCII token"
        )));
    }
    Ok(())
}

fn validate_sorted_tokens(label: &str, values: &[String]) -> Result<()> {
    if values.len() > MAX_LIST_ENTRIES {
        return Err(Error::Preparation(format!(
            "{label} exceeds {MAX_LIST_ENTRIES} entries"
        )));
    }
    for value in values {
        validate_token(label, value)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Preparation(format!(
            "{label} must be lexically sorted and unique"
        )));
    }
    Ok(())
}

fn validate_sorted_guest_paths(label: &str, values: &[String]) -> Result<()> {
    if values.len() > MAX_LIST_ENTRIES {
        return Err(Error::Preparation(format!(
            "{label} exceeds {MAX_LIST_ENTRIES} entries"
        )));
    }
    for value in values {
        validate_guest_path(label, value)?;
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Preparation(format!(
            "{label} must be lexically sorted and unique"
        )));
    }
    if values.iter().enumerate().any(|(index, ancestor)| {
        values[index + 1..].iter().any(|candidate| {
            candidate
                .strip_prefix(ancestor)
                .is_some_and(|suffix| suffix.starts_with('/'))
        })
    }) {
        return Err(Error::Preparation(format!(
            "{label} must not contain overlapping ancestor paths"
        )));
    }
    Ok(())
}

fn validate_guest_path(label: &str, value: &str) -> Result<()> {
    if value.len() < 2
        || value.len() > MAX_TOKEN_BYTES
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value.split('/').skip(1).any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || !segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+')
                })
        })
    {
        return Err(Error::Preparation(format!(
            "{label} contains a non-canonical absolute POSIX path"
        )));
    }
    Ok(())
}
