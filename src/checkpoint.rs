use crate::{Error, Result, WASIX_COHORT_ID, WASIX_WORKER_PROTOCOL_VERSION};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::ops::Range;

type HmacSha256 = Hmac<Sha256>;

const CHECKPOINT_MAGIC: &[u8; 8] = b"RTWCPKT\0";
const CHECKPOINT_FORMAT_VERSION: u16 = 2;
const CHECKPOINT_DOMAIN: &[u8] = b"runtrue-wasm-runtime.wasix-checkpoint.v2\0";
const CHECKPOINT_ENGINE_PROFILE: &str = "runtrue-wasix-engine-v1";
const CHECKPOINT_JOURNAL_FORMAT: &str = "wasmer-log-file-v1";
const CHECKPOINT_EXECUTION_ABI: &str = "wasix_32v1+asyncify";
const CHECKPOINT_ISOLATION_POLICY: &str = "runtrue-wasix-isolation-v1";
const CHECKPOINT_SNAPSHOT_TRIGGER: &str = "explicit";
const JOURNAL_MAGIC: &[u8; 8] = &0x310d_6dd0_2736_2979_u64.to_be_bytes();
const JOURNAL_SNAPSHOT_V1: u16 = 59;
const CHECKPOINT_HEADER_BYTES: usize = 8 + 2 + 4 + 8;
const CHECKPOINT_TAG_BYTES: usize = 32;
const MAX_CHECKPOINT_METADATA_BYTES: usize = 16 * 1024;

/// Secret key used to authenticate WASIX checkpoint artifacts.
#[derive(Clone)]
pub struct CheckpointAuthenticationKey([u8; 32]);

impl std::fmt::Debug for CheckpointAuthenticationKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CheckpointAuthenticationKey([REDACTED])")
    }
}

impl CheckpointAuthenticationKey {
    /// Construct a checkpoint authentication key from installation-secret bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Immutable workload identity to which a checkpoint is bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WasixCheckpointBinding {
    environment_id: String,
    module_sha256: String,
    command: String,
    instance_id: String,
    generation: u64,
}

impl WasixCheckpointBinding {
    /// Bind a checkpoint to one canonical environment and exact WebAssembly module.
    ///
    /// `environment_id` must be a lowercase `sha256:` identifier and
    /// `module_sha256` must be a lowercase, unprefixed SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error when either digest is not canonical.
    pub fn new(
        environment_id: impl Into<String>,
        module_sha256: impl Into<String>,
        command: impl Into<String>,
        instance_id: impl Into<String>,
        generation: u64,
    ) -> Result<Self> {
        let binding = Self {
            environment_id: environment_id.into(),
            module_sha256: module_sha256.into(),
            command: command.into(),
            instance_id: instance_id.into(),
            generation,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Canonical environment identity captured by the checkpoint.
    #[must_use]
    pub fn environment_id(&self) -> &str {
        &self.environment_id
    }

    /// Exact SHA-256 digest of the checkpointed WebAssembly module.
    #[must_use]
    pub fn module_sha256(&self) -> &str {
        &self.module_sha256
    }

    /// Selected command or entry point captured by the checkpoint.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Stable execution-lineage identifier used by external migration fencing.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Monotonic checkpoint generation used by external migration fencing.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    fn validate(&self) -> Result<()> {
        validate_prefixed_sha256("checkpoint environment ID", &self.environment_id)?;
        validate_sha256("checkpoint module digest", &self.module_sha256)?;
        validate_token("checkpoint command", &self.command, 256)?;
        validate_token("checkpoint instance ID", &self.instance_id, 128)?;
        if self.generation == 0 {
            return Err(Error::Checkpoint(
                "checkpoint generation must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Authenticated WASIX checkpoint artifact encoder and verifier.
///
/// Verification authenticates the complete envelope before parsing its JSON
/// metadata and independently checks record framing before exposing bytes.
/// Record bodies remain trusted runtime output: callers must never use this
/// codec to sign arbitrary tenant-provided journal bodies.
/// Authentication establishes integrity and compatibility, not freshness;
/// migration generation fencing is an orchestrator responsibility.
/// Checkpoints can contain guest memory, arguments, environment values, and
/// file data. This format does not provide confidentiality, so artifacts must
/// remain in private storage and travel over a confidential channel.
#[derive(Debug, Clone)]
pub struct WasixCheckpointCodec {
    authentication_key: CheckpointAuthenticationKey,
    max_journal_bytes: usize,
}

/// Journal state produced and attested by the runtime's snapshot capture path.
///
/// This type deliberately has no public constructor. Journal framing cannot
/// validate rkyv record bodies, the module hash inside `InitModuleV1`, or the
/// trigger inside `SnapshotV1`. Only the worker capture path may construct it
/// after validating those values on its own trusted output.
pub struct CapturedWasixJournal {
    bytes: Vec<u8>,
    binding: WasixCheckpointBinding,
    worker_build_sha256: String,
    explicit_snapshot: bool,
}

impl std::fmt::Debug for CapturedWasixJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CapturedWasixJournal")
            .field("bytes", &self.bytes.len())
            .field("binding", &self.binding)
            .field("worker_build_sha256", &self.worker_build_sha256)
            .field("explicit_snapshot", &self.explicit_snapshot)
            .finish()
    }
}

impl CapturedWasixJournal {
    #[cfg(any(feature = "wasix-checkpoint", test))]
    pub(crate) fn from_attested_worker_capture(
        bytes: Vec<u8>,
        binding: WasixCheckpointBinding,
        worker_build_sha256: String,
    ) -> Result<Self> {
        binding.validate()?;
        validate_sha256("captured worker build digest", &worker_build_sha256)?;
        scan_journal(&bytes)?;
        Ok(Self {
            bytes,
            binding,
            worker_build_sha256,
            explicit_snapshot: true,
        })
    }

    /// Exact workload identity supplied to the attested capture operation.
    #[must_use]
    pub const fn binding(&self) -> &WasixCheckpointBinding {
        &self.binding
    }

    /// Size of the captured journal prefix.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the captured journal prefix is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl WasixCheckpointCodec {
    /// Construct a codec with a 512 MiB journal limit.
    #[must_use]
    pub const fn new(authentication_key: CheckpointAuthenticationKey) -> Self {
        Self {
            authentication_key,
            max_journal_bytes: 512 * 1024 * 1024,
        }
    }

    /// Set the maximum journal size accepted for sealing or verification.
    #[must_use]
    pub const fn with_max_journal_bytes(mut self, max_journal_bytes: usize) -> Self {
        self.max_journal_bytes = max_journal_bytes;
        self
    }

    /// Seal trusted, locally produced journal bytes into a versioned artifact.
    ///
    /// The artifact inherits its complete workload identity from the attested
    /// capture, so callers cannot relabel a capture during sealing.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture binding, an empty journal, a
    /// configured zero limit, an oversized journal, or an encoding failure.
    pub fn seal_capture(&self, journal: &CapturedWasixJournal) -> Result<Vec<u8>> {
        self.seal_bound_capture(&journal.binding, journal)
    }

    /// Seal a trusted capture after checking an expected workload identity.
    ///
    /// Prefer [`Self::seal_capture`] when the caller does not independently
    /// need to assert an expected binding. This compatibility API rejects any
    /// difference between `binding` and the complete identity recorded during
    /// capture, including environment, command, instance, and generation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid binding, an empty journal, a configured
    /// zero limit, an oversized journal, or an encoding failure.
    pub fn seal(
        &self,
        binding: &WasixCheckpointBinding,
        journal: &CapturedWasixJournal,
    ) -> Result<Vec<u8>> {
        binding.validate()?;
        if binding != &journal.binding {
            return Err(Error::Checkpoint(
                "captured journal binding does not match the checkpoint binding".to_owned(),
            ));
        }
        self.seal_bound_capture(binding, journal)
    }

    fn seal_bound_capture(
        &self,
        binding: &WasixCheckpointBinding,
        journal: &CapturedWasixJournal,
    ) -> Result<Vec<u8>> {
        let prepared = self.prepare_seal(binding, journal)?;
        let mut artifact = Vec::new();
        artifact
            .try_reserve_exact(prepared.artifact_len)
            .map_err(|error| {
                Error::Checkpoint(format!(
                    "checkpoint artifact allocation failed during seal: {error}"
                ))
            })?;
        self.write_prepared_checkpoint(&prepared, &mut artifact)?;
        Ok(artifact)
    }

    /// Stream a trusted capture into a versioned artifact.
    ///
    /// This is the streaming counterpart to [`Self::seal_capture`] and inherits
    /// the complete workload identity from the attested capture.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid capture binding, an empty or oversized
    /// journal, metadata encoding or allocation failure, or a destination
    /// write failure.
    pub fn seal_capture_into<W: Write>(
        &self,
        journal: &CapturedWasixJournal,
        writer: &mut W,
    ) -> Result<usize> {
        self.seal_bound_capture_into(&journal.binding, journal, writer)
    }

    /// Stream a trusted, locally produced journal into a versioned artifact.
    ///
    /// This avoids constructing a second, artifact-sized buffer. The writer
    /// may contain a partial, unauthenticated artifact when an I/O error is
    /// returned and must discard it in that case.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid binding, an empty or oversized journal,
    /// metadata encoding or allocation failure, or a destination write failure.
    pub fn seal_into<W: Write>(
        &self,
        binding: &WasixCheckpointBinding,
        journal: &CapturedWasixJournal,
        writer: &mut W,
    ) -> Result<usize> {
        binding.validate()?;
        if binding != &journal.binding {
            return Err(Error::Checkpoint(
                "captured journal binding does not match the checkpoint binding".to_owned(),
            ));
        }
        self.seal_bound_capture_into(binding, journal, writer)
    }

    fn seal_bound_capture_into<W: Write>(
        &self,
        binding: &WasixCheckpointBinding,
        journal: &CapturedWasixJournal,
        writer: &mut W,
    ) -> Result<usize> {
        let prepared = self.prepare_seal(binding, journal)?;
        self.write_prepared_checkpoint(&prepared, writer)?;
        Ok(prepared.artifact_len)
    }

    fn prepare_seal<'a>(
        &self,
        binding: &WasixCheckpointBinding,
        journal: &'a CapturedWasixJournal,
    ) -> Result<PreparedCheckpoint<'a>> {
        self.validate_limit()?;
        binding.validate()?;
        if binding != &journal.binding || !journal.explicit_snapshot {
            return Err(Error::Checkpoint(
                "captured journal does not match the checkpoint binding".to_owned(),
            ));
        }
        self.validate_journal_length(journal.bytes.len())?;
        scan_journal(&journal.bytes)?;

        let metadata = CheckpointMetadata::current(
            binding.clone(),
            &journal.worker_build_sha256,
            &journal.bytes,
        );
        let mut metadata_writer = FallibleBoundedVec::new(MAX_CHECKPOINT_METADATA_BYTES);
        serde_json::to_writer(&mut metadata_writer, &metadata).map_err(|error| {
            Error::Checkpoint(format!("checkpoint metadata encoding failed: {error}"))
        })?;
        let metadata = metadata_writer.into_inner();
        if metadata.is_empty() || metadata.len() > MAX_CHECKPOINT_METADATA_BYTES {
            return Err(Error::Checkpoint(
                "checkpoint metadata exceeds the format limit".to_owned(),
            ));
        }

        let capacity = CHECKPOINT_HEADER_BYTES
            .checked_add(metadata.len())
            .and_then(|length| length.checked_add(journal.bytes.len()))
            .and_then(|length| length.checked_add(CHECKPOINT_TAG_BYTES))
            .ok_or_else(|| Error::Checkpoint("checkpoint length overflows usize".to_owned()))?;
        let metadata_len = u32::try_from(metadata.len()).map_err(|_| {
            Error::Checkpoint("checkpoint metadata length overflows u32".to_owned())
        })?;
        let journal_len = u64::try_from(journal.bytes.len())
            .map_err(|_| Error::Checkpoint("checkpoint journal length overflows u64".to_owned()))?;

        let mut header = [0_u8; CHECKPOINT_HEADER_BYTES];
        header[..8].copy_from_slice(CHECKPOINT_MAGIC);
        header[8..10].copy_from_slice(&CHECKPOINT_FORMAT_VERSION.to_be_bytes());
        header[10..14].copy_from_slice(&metadata_len.to_be_bytes());
        header[14..22].copy_from_slice(&journal_len.to_be_bytes());

        Ok(PreparedCheckpoint {
            header,
            metadata,
            journal: &journal.bytes,
            artifact_len: capacity,
        })
    }

    fn write_prepared_checkpoint<W: Write>(
        &self,
        prepared: &PreparedCheckpoint<'_>,
        writer: &mut W,
    ) -> Result<()> {
        let mut mac = self.authentication_state()?;
        write_authenticated_chunk(writer, &mut mac, &prepared.header, "header")?;
        write_authenticated_chunk(writer, &mut mac, &prepared.metadata, "metadata")?;
        write_authenticated_chunk(writer, &mut mac, prepared.journal, "journal")?;
        let tag = mac.finalize().into_bytes();
        writer.write_all(&tag).map_err(|error| {
            Error::Checkpoint(format!("checkpoint artifact tag write failed: {error}"))
        })
    }

    /// Authenticate and validate a checkpoint before exposing its journal.
    ///
    /// The exact artifact length and configured journal limit are checked
    /// before metadata parsing or copying journal bytes. Untrusted readers and
    /// network frames must apply the same limit before allocating this slice.
    /// The HMAC is verified before deserializing metadata or scanning records.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed framing, an unsupported format,
    /// authentication failure, incompatible identity, or an invalid digest.
    pub fn open(
        &self,
        expected_binding: &WasixCheckpointBinding,
        artifact: &[u8],
    ) -> Result<VerifiedWasixCheckpoint> {
        let parts = self.verify_parts(expected_binding, artifact)?;
        let journal = &artifact[parts.journal.clone()];
        let mut journal_copy = Vec::new();
        journal_copy
            .try_reserve_exact(journal.len())
            .map_err(|error| {
                Error::Checkpoint(format!(
                    "checkpoint journal allocation failed during open: {error}"
                ))
            })?;
        journal_copy.extend_from_slice(journal);

        Ok(VerifiedWasixCheckpoint {
            binding: parts.binding,
            bytes: journal_copy,
            journal: 0..journal.len(),
            artifact_sha256: parts.artifact_sha256,
            worker_build_sha256: parts.worker_build_sha256,
        })
    }

    /// Authenticate an in-memory artifact without copying its journal.
    ///
    /// The returned view borrows the artifact and is valid only while the
    /// artifact remains unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed framing, an unsupported format,
    /// authentication failure, incompatible identity, or an invalid digest.
    pub fn verify<'a>(
        &self,
        expected_binding: &WasixCheckpointBinding,
        artifact: &'a [u8],
    ) -> Result<VerifiedWasixCheckpointView<'a>> {
        let parts = self.verify_parts(expected_binding, artifact)?;
        Ok(VerifiedWasixCheckpointView {
            binding: parts.binding,
            journal: &artifact[parts.journal],
            artifact_sha256: parts.artifact_sha256,
            worker_build_sha256: parts.worker_build_sha256,
        })
    }

    /// Read, authenticate, and validate a bounded checkpoint stream.
    ///
    /// The fixed header is validated before one exact, fallible allocation is
    /// made for the declared artifact length. The verified value retains that
    /// buffer, avoiding both growth reallocations and a second journal-sized
    /// allocation and copy.
    ///
    /// # Errors
    ///
    /// Returns an error for a source read or allocation failure, input beyond
    /// the configured artifact limit, malformed framing, failed authentication,
    /// incompatible identity, or an invalid digest.
    pub fn open_reader<R: Read>(
        &self,
        expected_binding: &WasixCheckpointBinding,
        mut reader: R,
    ) -> Result<VerifiedWasixCheckpoint> {
        self.validate_limit()?;
        expected_binding.validate()?;
        let maximum_artifact_bytes = self.maximum_artifact_bytes()?;
        let mut header = [0_u8; CHECKPOINT_HEADER_BYTES];
        read_checkpoint_exact(&mut reader, &mut header, "header")?;
        let layout = self.validate_header(&header)?;

        let mut artifact = Vec::new();
        artifact
            .try_reserve_exact(layout.artifact_len)
            .map_err(|error| {
                Error::Checkpoint(format!(
                    "checkpoint artifact allocation failed while reading: {error}"
                ))
            })?;
        artifact.extend_from_slice(&header);
        artifact.resize(layout.artifact_len, 0);
        read_checkpoint_exact(
            &mut reader,
            &mut artifact[CHECKPOINT_HEADER_BYTES..],
            "body",
        )?;

        let mut trailing = [0_u8; 1];
        let trailing_bytes = read_checkpoint_trailing_byte(&mut reader, &mut trailing)?;
        if trailing_bytes != 0 {
            let message = if layout.artifact_len == maximum_artifact_bytes {
                "checkpoint artifact exceeds the configured limit while reading"
            } else {
                "checkpoint artifact length does not match its header"
            };
            return Err(Error::Checkpoint(message.to_owned()));
        }

        let parts = self.verify_parts(expected_binding, &artifact)?;
        Ok(VerifiedWasixCheckpoint {
            binding: parts.binding,
            bytes: artifact,
            journal: parts.journal,
            artifact_sha256: parts.artifact_sha256,
            worker_build_sha256: parts.worker_build_sha256,
        })
    }

    fn verify_parts(
        &self,
        expected_binding: &WasixCheckpointBinding,
        artifact: &[u8],
    ) -> Result<VerifiedCheckpointParts> {
        self.validate_limit()?;
        expected_binding.validate()?;
        let maximum_artifact_bytes = self.maximum_artifact_bytes()?;
        if artifact.len() > maximum_artifact_bytes {
            return Err(Error::Checkpoint(
                "checkpoint artifact exceeds the configured limit".to_owned(),
            ));
        }
        if artifact.len() < CHECKPOINT_HEADER_BYTES + CHECKPOINT_TAG_BYTES {
            return Err(Error::Checkpoint(
                "checkpoint artifact is truncated".to_owned(),
            ));
        }
        let header: &[u8; CHECKPOINT_HEADER_BYTES] = artifact
            .get(..CHECKPOINT_HEADER_BYTES)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::Checkpoint("checkpoint artifact is truncated".to_owned()))?;
        let layout = self.validate_header(header)?;
        if artifact.len() != layout.artifact_len {
            return Err(Error::Checkpoint(
                "checkpoint artifact length does not match its header".to_owned(),
            ));
        }

        let authenticated_len = layout.authenticated_len;
        let supplied_tag = &artifact[authenticated_len..];
        self.authentication_tag(&artifact[..authenticated_len])?
            .verify_slice(supplied_tag)
            .map_err(|_| Error::Checkpoint("checkpoint authentication failed".to_owned()))?;

        let metadata_end = layout.metadata_end;
        let metadata: CheckpointMetadata = serde_json::from_slice(
            &artifact[CHECKPOINT_HEADER_BYTES..metadata_end],
        )
        .map_err(|error| Error::Checkpoint(format!("checkpoint metadata is malformed: {error}")))?;
        metadata.validate(expected_binding)?;
        let journal = &artifact[metadata_end..authenticated_len];
        if metadata.journal_sha256 != hex::encode(Sha256::digest(journal)) {
            return Err(Error::Checkpoint(
                "checkpoint journal digest is invalid".to_owned(),
            ));
        }
        scan_journal(journal)?;

        Ok(VerifiedCheckpointParts {
            binding: metadata.binding,
            journal: metadata_end..authenticated_len,
            artifact_sha256: hex::encode(Sha256::digest(artifact)),
            worker_build_sha256: metadata.worker_build_sha256,
        })
    }

    fn validate_header(
        &self,
        header: &[u8; CHECKPOINT_HEADER_BYTES],
    ) -> Result<CheckpointArtifactLayout> {
        if &header[..CHECKPOINT_MAGIC.len()] != CHECKPOINT_MAGIC {
            return Err(Error::Checkpoint(
                "checkpoint artifact magic is invalid".to_owned(),
            ));
        }

        let version = u16::from_be_bytes([header[8], header[9]]);
        if version != CHECKPOINT_FORMAT_VERSION {
            return Err(Error::Checkpoint(format!(
                "checkpoint format {version} is unsupported"
            )));
        }
        let metadata_len = usize::try_from(u32::from_be_bytes([
            header[10], header[11], header[12], header[13],
        ]))
        .unwrap_or(usize::MAX);
        if metadata_len == 0 || metadata_len > MAX_CHECKPOINT_METADATA_BYTES {
            return Err(Error::Checkpoint(
                "checkpoint metadata length is invalid".to_owned(),
            ));
        }
        let journal_len_u64 = u64::from_be_bytes([
            header[14], header[15], header[16], header[17], header[18], header[19], header[20],
            header[21],
        ]);
        let journal_len = usize::try_from(journal_len_u64).map_err(|_| {
            Error::Checkpoint("checkpoint journal length overflows usize".to_owned())
        })?;
        self.validate_journal_length(journal_len)?;

        let metadata_end = CHECKPOINT_HEADER_BYTES
            .checked_add(metadata_len)
            .ok_or_else(|| Error::Checkpoint("checkpoint length overflows usize".to_owned()))?;
        let authenticated_len = metadata_end
            .checked_add(journal_len)
            .ok_or_else(|| Error::Checkpoint("checkpoint length overflows usize".to_owned()))?;
        let artifact_len = authenticated_len
            .checked_add(CHECKPOINT_TAG_BYTES)
            .ok_or_else(|| Error::Checkpoint("checkpoint length overflows usize".to_owned()))?;
        Ok(CheckpointArtifactLayout {
            metadata_end,
            authenticated_len,
            artifact_len,
        })
    }

    fn maximum_artifact_bytes(&self) -> Result<usize> {
        CHECKPOINT_HEADER_BYTES
            .checked_add(MAX_CHECKPOINT_METADATA_BYTES)
            .and_then(|length| length.checked_add(self.max_journal_bytes))
            .and_then(|length| length.checked_add(CHECKPOINT_TAG_BYTES))
            .ok_or_else(|| Error::Checkpoint("checkpoint length overflows usize".to_owned()))
    }

    fn validate_limit(&self) -> Result<()> {
        if self.max_journal_bytes == 0 {
            return Err(Error::Configuration(
                "checkpoint journal limit must be positive".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_journal_length(&self, length: usize) -> Result<()> {
        if length == 0 {
            return Err(Error::Checkpoint(
                "checkpoint journal must not be empty".to_owned(),
            ));
        }
        if length > self.max_journal_bytes {
            return Err(Error::Checkpoint(
                "checkpoint journal exceeds the configured limit".to_owned(),
            ));
        }
        Ok(())
    }

    fn authentication_tag(&self, bytes: &[u8]) -> Result<HmacSha256> {
        let mut mac = self.authentication_state()?;
        mac.update(bytes);
        Ok(mac)
    }

    fn authentication_state(&self) -> Result<HmacSha256> {
        let mut mac = HmacSha256::new_from_slice(&self.authentication_key.0).map_err(|_| {
            Error::Checkpoint("checkpoint authentication key is invalid".to_owned())
        })?;
        mac.update(CHECKPOINT_DOMAIN);
        Ok(mac)
    }
}

struct PreparedCheckpoint<'a> {
    header: [u8; CHECKPOINT_HEADER_BYTES],
    metadata: Vec<u8>,
    journal: &'a [u8],
    artifact_len: usize,
}

struct VerifiedCheckpointParts {
    binding: WasixCheckpointBinding,
    journal: Range<usize>,
    artifact_sha256: String,
    worker_build_sha256: String,
}

struct CheckpointArtifactLayout {
    metadata_end: usize,
    authenticated_len: usize,
    artifact_len: usize,
}

struct FallibleBoundedVec {
    bytes: Vec<u8>,
    maximum_bytes: usize,
}

impl FallibleBoundedVec {
    const fn new(maximum_bytes: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum_bytes,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for FallibleBoundedVec {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("metadata length overflows usize"))?;
        if new_len > self.maximum_bytes {
            return Err(std::io::Error::other(
                "metadata exceeds the checkpoint format limit",
            ));
        }
        self.bytes.try_reserve_exact(bytes.len()).map_err(|error| {
            std::io::Error::other(format!("metadata allocation failed: {error}"))
        })?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_authenticated_chunk<W: Write>(
    writer: &mut W,
    mac: &mut HmacSha256,
    bytes: &[u8],
    phase: &str,
) -> Result<()> {
    writer.write_all(bytes).map_err(|error| {
        Error::Checkpoint(format!("checkpoint artifact {phase} write failed: {error}"))
    })?;
    mac.update(bytes);
    Ok(())
}

fn read_checkpoint_exact<R: Read>(reader: &mut R, bytes: &mut [u8], phase: &str) -> Result<()> {
    reader.read_exact(bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::Checkpoint("checkpoint artifact is truncated".to_owned())
        } else {
            Error::Checkpoint(format!("checkpoint artifact {phase} read failed: {error}"))
        }
    })
}

fn read_checkpoint_trailing_byte<R: Read>(reader: &mut R, byte: &mut [u8; 1]) -> Result<usize> {
    loop {
        match reader.read(byte) {
            Ok(read) => return Ok(read),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(Error::Checkpoint(format!(
                    "checkpoint artifact trailing-byte check failed: {error}"
                )));
            }
        }
    }
}

/// Journal bytes from a fully authenticated and compatibility-checked artifact.
pub struct VerifiedWasixCheckpoint {
    binding: WasixCheckpointBinding,
    bytes: Vec<u8>,
    journal: Range<usize>,
    artifact_sha256: String,
    worker_build_sha256: String,
}

impl std::fmt::Debug for VerifiedWasixCheckpoint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedWasixCheckpoint")
            .field("binding", &self.binding)
            .field("backing_bytes", &self.bytes.len())
            .field("journal_bytes", &self.journal.len())
            .field("artifact_sha256", &self.artifact_sha256)
            .field("worker_build_sha256", &self.worker_build_sha256)
            .finish()
    }
}

impl VerifiedWasixCheckpoint {
    /// Workload identity authenticated by the artifact.
    #[must_use]
    pub const fn binding(&self) -> &WasixCheckpointBinding {
        &self.binding
    }

    /// Authenticated Wasmer journal bytes.
    #[must_use]
    pub fn journal(&self) -> &[u8] {
        &self.bytes[self.journal.clone()]
    }

    /// Lowercase SHA-256 digest of the complete sealed artifact.
    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    /// Lowercase SHA-256 digest of the source worker executable.
    #[must_use]
    pub fn worker_build_sha256(&self) -> &str {
        &self.worker_build_sha256
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, String) {
        let mut bytes = self.bytes;
        if self.journal.start != 0 {
            bytes.copy_within(self.journal.clone(), 0);
        }
        bytes.truncate(self.journal.len());
        (bytes, self.worker_build_sha256)
    }
}

/// Borrowed journal view from a fully authenticated checkpoint artifact.
pub struct VerifiedWasixCheckpointView<'a> {
    binding: WasixCheckpointBinding,
    journal: &'a [u8],
    artifact_sha256: String,
    worker_build_sha256: String,
}

impl std::fmt::Debug for VerifiedWasixCheckpointView<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedWasixCheckpointView")
            .field("binding", &self.binding)
            .field("journal_bytes", &self.journal.len())
            .field("artifact_sha256", &self.artifact_sha256)
            .field("worker_build_sha256", &self.worker_build_sha256)
            .finish()
    }
}

impl<'a> VerifiedWasixCheckpointView<'a> {
    /// Workload identity authenticated by the artifact.
    #[must_use]
    pub const fn binding(&self) -> &WasixCheckpointBinding {
        &self.binding
    }

    /// Authenticated Wasmer journal bytes borrowed from the artifact.
    #[must_use]
    pub const fn journal(&self) -> &'a [u8] {
        self.journal
    }

    /// Lowercase SHA-256 digest of the complete sealed artifact.
    #[must_use]
    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    /// Lowercase SHA-256 digest of the source worker executable.
    #[must_use]
    pub fn worker_build_sha256(&self) -> &str {
        &self.worker_build_sha256
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointMetadata {
    binding: WasixCheckpointBinding,
    runtime_version: String,
    worker_protocol_version: u32,
    cohort_id: String,
    worker_build_sha256: String,
    engine_profile: String,
    platform: String,
    journal_format: String,
    execution_abi: String,
    isolation_policy: String,
    snapshot_trigger: String,
    journal_sha256: String,
}

impl CheckpointMetadata {
    fn current(binding: WasixCheckpointBinding, worker_build_sha256: &str, journal: &[u8]) -> Self {
        Self {
            binding,
            runtime_version: env!("CARGO_PKG_VERSION").to_owned(),
            worker_protocol_version: WASIX_WORKER_PROTOCOL_VERSION,
            cohort_id: WASIX_COHORT_ID.to_owned(),
            worker_build_sha256: worker_build_sha256.to_owned(),
            engine_profile: CHECKPOINT_ENGINE_PROFILE.to_owned(),
            platform: checkpoint_platform(),
            journal_format: CHECKPOINT_JOURNAL_FORMAT.to_owned(),
            execution_abi: CHECKPOINT_EXECUTION_ABI.to_owned(),
            isolation_policy: CHECKPOINT_ISOLATION_POLICY.to_owned(),
            snapshot_trigger: CHECKPOINT_SNAPSHOT_TRIGGER.to_owned(),
            journal_sha256: hex::encode(Sha256::digest(journal)),
        }
    }

    fn validate(&self, expected_binding: &WasixCheckpointBinding) -> Result<()> {
        self.binding.validate()?;
        validate_sha256("checkpoint journal digest", &self.journal_sha256)?;
        validate_sha256("checkpoint worker build digest", &self.worker_build_sha256)?;
        let expected = Self::current(expected_binding.clone(), &self.worker_build_sha256, &[]);
        if self.binding != expected.binding
            || self.runtime_version != expected.runtime_version
            || self.worker_protocol_version != expected.worker_protocol_version
            || self.cohort_id != expected.cohort_id
            || self.engine_profile != expected.engine_profile
            || self.platform != expected.platform
            || self.journal_format != expected.journal_format
            || self.execution_abi != expected.execution_abi
            || self.isolation_policy != expected.isolation_policy
            || self.snapshot_trigger != expected.snapshot_trigger
        {
            return Err(Error::Checkpoint(
                "checkpoint identity is incompatible".to_owned(),
            ));
        }
        Ok(())
    }
}

fn checkpoint_platform() -> String {
    format!(
        "{};endian={};pointer={}",
        env!("RUNTRUE_BUILD_TARGET"),
        if cfg!(target_endian = "little") {
            "little"
        } else {
            "big"
        },
        usize::BITS
    )
}

fn validate_prefixed_sha256(label: &str, value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Checkpoint(format!("{label} must start with sha256:")))?;
    validate_sha256(label, digest)
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::Checkpoint(format!(
            "{label} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_token(label: &str, value: &str, maximum_bytes: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\\' && byte != b'\"')
    {
        return Err(Error::Checkpoint(format!(
            "{label} must be a nonempty printable token of at most {maximum_bytes} bytes"
        )));
    }
    Ok(())
}

fn scan_journal(journal: &[u8]) -> Result<()> {
    if journal.len() < JOURNAL_MAGIC.len() || &journal[..JOURNAL_MAGIC.len()] != JOURNAL_MAGIC {
        return Err(Error::Checkpoint(
            "checkpoint journal magic is invalid".to_owned(),
        ));
    }

    let mut cursor = JOURNAL_MAGIC.len();
    let mut final_record = None;
    let mut record_count = 0_usize;
    let mut init_module_records = 0_usize;
    let mut set_thread_records = 0_usize;
    let mut snapshot_records = 0_usize;
    while cursor < journal.len() {
        let header_end = cursor
            .checked_add(8)
            .ok_or_else(|| Error::Checkpoint("checkpoint journal length overflows".to_owned()))?;
        if header_end > journal.len() {
            return Err(Error::Checkpoint(
                "checkpoint journal record header is truncated".to_owned(),
            ));
        }
        let header = &journal[cursor..header_end];
        if header == JOURNAL_MAGIC {
            return Err(Error::Checkpoint(
                "checkpoint journal contains a repeated magic marker".to_owned(),
            ));
        }
        let record_type = u16::from_be_bytes([header[0], header[1]]);
        if !is_known_journal_record_type(record_type) {
            return Err(Error::Checkpoint(format!(
                "checkpoint journal record type {record_type} is unsupported"
            )));
        }
        let record_len_u64 = u64::from_be_bytes([
            0, 0, header[2], header[3], header[4], header[5], header[6], header[7],
        ]);
        let record_len = usize::try_from(record_len_u64).map_err(|_| {
            Error::Checkpoint("checkpoint journal record length overflows usize".to_owned())
        })?;
        if record_len == 0 && !is_zero_sized_journal_record_type(record_type) {
            return Err(Error::Checkpoint(
                "checkpoint journal contains an invalid empty record".to_owned(),
            ));
        }
        cursor = header_end
            .checked_add(record_len)
            .ok_or_else(|| Error::Checkpoint("checkpoint journal length overflows".to_owned()))?;
        if cursor > journal.len() {
            return Err(Error::Checkpoint(
                "checkpoint journal record is truncated".to_owned(),
            ));
        }
        if record_type == 1 {
            init_module_records += 1;
            if record_count != 0 || init_module_records != 1 {
                return Err(Error::Checkpoint(
                    "checkpoint journal has an invalid module initialization sequence".to_owned(),
                ));
            }
        } else if record_type == 3 {
            set_thread_records += 1;
        } else if record_type == JOURNAL_SNAPSHOT_V1 {
            snapshot_records += 1;
            if cursor != journal.len() {
                return Err(Error::Checkpoint(
                    "checkpoint journal contains records after its snapshot".to_owned(),
                ));
            }
        }
        record_count += 1;
        final_record = Some(record_type);
    }

    if init_module_records != 1
        || set_thread_records == 0
        || snapshot_records != 1
        || final_record != Some(JOURNAL_SNAPSHOT_V1)
    {
        return Err(Error::Checkpoint(
            "checkpoint journal lifecycle is incomplete".to_owned(),
        ));
    }
    Ok(())
}

const fn is_known_journal_record_type(record_type: u16) -> bool {
    matches!(record_type, 1..=7 | 9..=64)
}

const fn is_zero_sized_journal_record_type(record_type: u16) -> bool {
    matches!(record_type, 35 | 37 | 38 | 41 | 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens_only_attested_runtime_capture() {
        let codec = codec();
        let binding = binding();
        let captured = captured(valid_journal());
        let first = codec.seal_capture(&captured).unwrap();
        let second = codec.seal_capture(&captured).unwrap();
        assert_eq!(first, second);
        assert_eq!(captured.binding(), &binding);

        let verified = codec.open(&binding, &first).unwrap();
        assert_eq!(verified.binding(), &binding);
        assert_eq!(verified.journal(), captured.bytes);
        assert_eq!(verified.artifact_sha256().len(), 64);
        assert!(!format!("{verified:?}").contains("[49, 13"));
        assert!(!format!("{captured:?}").contains("[49, 13"));
        assert_eq!(
            format!("{:?}", CheckpointAuthenticationKey::new([9; 32])),
            "CheckpointAuthenticationKey([REDACTED])"
        );
    }

    #[test]
    fn refuses_capture_attestation_mismatches() {
        let codec = codec();
        let binding = binding();
        let mut wrong_module = captured(valid_journal());
        wrong_module.binding.module_sha256 = "3".repeat(64);
        assert!(matches!(
            codec.seal(&binding, &wrong_module),
            Err(Error::Checkpoint(message)) if message == "captured journal binding does not match the checkpoint binding"
        ));

        let mut implicit = captured(valid_journal());
        implicit.explicit_snapshot = false;
        assert!(matches!(
            codec.seal(&binding, &implicit),
            Err(Error::Checkpoint(message)) if message == "captured journal does not match the checkpoint binding"
        ));
    }

    #[test]
    fn refuses_to_relabel_a_capture_with_the_same_module() {
        let codec = codec();
        let binding = binding();
        let captured = captured(valid_journal());
        let relabeled = [
            WasixCheckpointBinding::new(
                format!("sha256:{}", "3".repeat(64)),
                binding.module_sha256(),
                binding.command(),
                binding.instance_id(),
                binding.generation(),
            )
            .unwrap(),
            WasixCheckpointBinding::new(
                binding.environment_id(),
                binding.module_sha256(),
                "other-command",
                binding.instance_id(),
                binding.generation(),
            )
            .unwrap(),
            WasixCheckpointBinding::new(
                binding.environment_id(),
                binding.module_sha256(),
                binding.command(),
                "instance-2",
                binding.generation(),
            )
            .unwrap(),
            WasixCheckpointBinding::new(
                binding.environment_id(),
                binding.module_sha256(),
                binding.command(),
                binding.instance_id(),
                binding.generation() + 1,
            )
            .unwrap(),
        ];

        for relabeled_binding in relabeled {
            assert!(matches!(
                codec.seal(&relabeled_binding, &captured),
                Err(Error::Checkpoint(message))
                    if message == "captured journal binding does not match the checkpoint binding"
            ));
        }

        let artifact = codec.seal_capture(&captured).unwrap();
        assert_eq!(codec.open(&binding, &artifact).unwrap().binding(), &binding);
    }

    #[test]
    fn authentication_precedes_metadata_deserialization() {
        let codec = codec();
        let binding = binding();
        let journal = valid_journal();
        let malformed = envelope(&codec, b"{", &journal);
        let error = codec.open(&binding, &malformed).unwrap_err();
        assert!(
            matches!(error, Error::Checkpoint(ref message) if message.starts_with("checkpoint metadata is malformed:")),
            "unexpected error: {error:?}"
        );

        let mut unauthenticated = malformed;
        unauthenticated[CHECKPOINT_HEADER_BYTES] ^= 1;
        let error = codec.open(&binding, &unauthenticated).unwrap_err();
        assert!(
            matches!(error, Error::Checkpoint(message) if message == "checkpoint authentication failed")
        );
    }

    #[test]
    fn rejects_every_authenticated_compatibility_mismatch() {
        let codec = codec();
        let binding = binding();
        let journal = valid_journal();
        let current =
            CheckpointMetadata::current(binding.clone(), &worker_build_sha256(), &journal);
        let mut mismatches = Vec::new();

        let mut metadata = current.clone();
        metadata.runtime_version.push_str("-other");
        mismatches.push(metadata);
        let mut metadata = current.clone();
        metadata.worker_protocol_version += 1;
        mismatches.push(metadata);
        let mut metadata = current.clone();
        metadata.cohort_id.push_str("-other");
        mismatches.push(metadata);
        let mut metadata = current.clone();
        metadata.engine_profile.push_str("-other");
        mismatches.push(metadata);
        let mut metadata = current.clone();
        metadata.platform.push_str("-other");
        mismatches.push(metadata);
        let mut metadata = current.clone();
        metadata.journal_format.push_str("-other");
        mismatches.push(metadata);
        let mut metadata = current.clone();
        metadata.execution_abi.push_str("-other");
        mismatches.push(metadata);
        let mut metadata = current.clone();
        metadata.isolation_policy.push_str("-other");
        mismatches.push(metadata);
        let mut metadata = current;
        metadata.snapshot_trigger.push_str("-other");
        mismatches.push(metadata);

        for metadata in mismatches {
            let metadata = serde_json::to_vec(&metadata).unwrap();
            let artifact = envelope(&codec, &metadata, &journal);
            let error = codec.open(&binding, &artifact).unwrap_err();
            assert!(
                matches!(error, Error::Checkpoint(message) if message == "checkpoint identity is incompatible")
            );
        }
    }

    #[test]
    fn scans_authenticated_journal_framing_before_exposure() {
        let codec = codec();
        let binding = binding();
        let journal = JOURNAL_MAGIC.to_vec();
        let metadata = serde_json::to_vec(&CheckpointMetadata::current(
            binding.clone(),
            &worker_build_sha256(),
            &journal,
        ))
        .unwrap();
        let artifact = envelope(&codec, &metadata, &journal);
        let error = codec.open(&binding, &artifact).unwrap_err();
        assert!(
            matches!(error, Error::Checkpoint(message) if message == "checkpoint journal lifecycle is incomplete")
        );
    }

    #[test]
    fn rejects_wrong_keys_mutation_and_cross_workload_restore() {
        let codec = codec();
        let binding = binding();
        let artifact = codec.seal(&binding, &captured(valid_journal())).unwrap();
        let wrong_key = WasixCheckpointCodec::new(CheckpointAuthenticationKey::new([8; 32]));
        assert!(matches!(
            wrong_key.open(&binding, &artifact),
            Err(Error::Checkpoint(message)) if message == "checkpoint authentication failed"
        ));

        let metadata_len =
            usize::try_from(u32::from_be_bytes(artifact[10..14].try_into().unwrap())).unwrap();
        for offset in [22, 22 + metadata_len, artifact.len() - 1] {
            let mut mutated = artifact.clone();
            mutated[offset] ^= 1;
            assert!(matches!(
                codec.open(&binding, &mutated),
                Err(Error::Checkpoint(message)) if message == "checkpoint authentication failed"
            ));
        }

        let other = WasixCheckpointBinding::new(
            binding.environment_id(),
            binding.module_sha256(),
            binding.command(),
            "instance-2",
            binding.generation(),
        )
        .unwrap();
        assert!(matches!(
            codec.open(&other, &artifact),
            Err(Error::Checkpoint(message)) if message == "checkpoint identity is incompatible"
        ));
    }

    #[test]
    fn rejects_noncanonical_bindings_and_invalid_limits() {
        assert!(
            WasixCheckpointBinding::new("1".repeat(64), "2".repeat(64), "_start", "instance", 1)
                .is_err()
        );
        assert!(
            WasixCheckpointBinding::new(
                format!("sha256:{}", "1".repeat(64)),
                "A".repeat(64),
                "_start",
                "instance",
                1
            )
            .is_err()
        );
        assert!(
            WasixCheckpointBinding::new(
                format!("sha256:{}", "1".repeat(64)),
                "2".repeat(64),
                "_start",
                "bad id",
                1
            )
            .is_err()
        );
        assert!(
            WasixCheckpointBinding::new(
                format!("sha256:{}", "1".repeat(64)),
                "2".repeat(64),
                "_start",
                "instance",
                0
            )
            .is_err()
        );

        let zero_limit = WasixCheckpointCodec::new(CheckpointAuthenticationKey::new([7; 32]))
            .with_max_journal_bytes(0);
        assert!(matches!(
            zero_limit.seal(&binding(), &captured(valid_journal())),
            Err(Error::Configuration(_))
        ));
        let small_limit = codec().with_max_journal_bytes(valid_journal().len() - 1);
        assert!(matches!(
            small_limit.seal(&binding(), &captured(valid_journal())),
            Err(Error::Checkpoint(message)) if message == "checkpoint journal exceeds the configured limit"
        ));
    }

    #[test]
    fn rejects_malformed_envelope_lengths_and_trailing_bytes() {
        let codec = codec();
        let binding = binding();
        let artifact = codec.seal(&binding, &captured(valid_journal())).unwrap();
        for truncated in [
            &artifact[..0],
            &artifact[..21],
            &artifact[..artifact.len() - 1],
        ] {
            assert!(matches!(
                codec.open(&binding, truncated),
                Err(Error::Checkpoint(_))
            ));
        }
        let mut trailing = artifact.clone();
        trailing.push(0);
        assert!(matches!(
            codec.open(&binding, &trailing),
            Err(Error::Checkpoint(message)) if message == "checkpoint artifact length does not match its header"
        ));
        let mut oversized = artifact;
        oversized[14..22].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(codec.open(&binding, &oversized).is_err());
    }

    #[test]
    fn scanner_enforces_lifecycle_and_accepts_known_zero_sized_records() {
        let valid = valid_journal();
        scan_journal(&valid).unwrap();

        let mut missing_thread = JOURNAL_MAGIC.to_vec();
        push_record(&mut missing_thread, 1, &[0]);
        push_record(&mut missing_thread, 59, &[0]);
        assert!(scan_journal(&missing_thread).is_err());

        let mut repeated_init = JOURNAL_MAGIC.to_vec();
        push_record(&mut repeated_init, 1, &[0]);
        push_record(&mut repeated_init, 1, &[0]);
        push_record(&mut repeated_init, 3, &[0]);
        push_record(&mut repeated_init, 59, &[0]);
        assert!(scan_journal(&repeated_init).is_err());

        let mut after_snapshot = valid;
        push_record(&mut after_snapshot, 60, &[]);
        assert!(scan_journal(&after_snapshot).is_err());
    }

    #[test]
    fn streaming_seal_and_borrowed_verify_match_legacy_artifact() {
        let codec = codec();
        let binding = binding();
        let captured = captured(valid_journal());
        let legacy = codec.seal(&binding, &captured).unwrap();
        let mut streamed = Vec::new();

        let written = codec.seal_capture_into(&captured, &mut streamed).unwrap();
        assert_eq!(written, legacy.len());
        assert_eq!(streamed, legacy);

        let metadata_len =
            usize::try_from(u32::from_be_bytes(legacy[10..14].try_into().unwrap())).unwrap();
        let journal_start = CHECKPOINT_HEADER_BYTES + metadata_len;
        let verified = codec.verify(&binding, &legacy).unwrap();
        assert_eq!(verified.binding(), &binding);
        assert_eq!(verified.journal(), captured.bytes);
        assert_eq!(
            verified.journal().as_ptr(),
            legacy[journal_start..].as_ptr()
        );
        assert_eq!(verified.artifact_sha256().len(), 64);
    }

    #[test]
    fn streaming_reader_reuses_its_artifact_allocation_for_the_journal() {
        let codec = codec();
        let binding = binding();
        let expected_journal = valid_journal();
        let artifact = codec
            .seal(&binding, &captured(expected_journal.clone()))
            .unwrap();

        let verified = codec
            .open_reader(
                &binding,
                ChunkedReader {
                    bytes: &artifact,
                    cursor: 0,
                    maximum_read: 3,
                },
            )
            .unwrap();
        assert_eq!(verified.bytes.len(), artifact.len());
        assert!(verified.journal.start > 0);
        assert_eq!(verified.journal(), expected_journal);

        let backing_allocation = verified.bytes.as_ptr();
        let (journal, source_worker_build_sha256) = verified.into_parts();
        assert_eq!(journal.as_ptr(), backing_allocation);
        assert_eq!(journal, expected_journal);
        assert_eq!(source_worker_build_sha256, worker_build_sha256());
    }

    #[test]
    fn enforces_stream_boundaries_at_zero_exact_max_over_max_and_truncation() {
        let maximum_journal_bytes = 128;
        let codec = codec().with_max_journal_bytes(maximum_journal_bytes);
        let binding = binding();
        let exact_journal = journal_with_len(maximum_journal_bytes);
        let metadata =
            CheckpointMetadata::current(binding.clone(), &worker_build_sha256(), &exact_journal);
        let mut metadata = serde_json::to_vec(&metadata).unwrap();
        metadata.resize(MAX_CHECKPOINT_METADATA_BYTES, b' ');
        let artifact = envelope(&codec, &metadata, &exact_journal);
        assert_eq!(artifact.len(), codec.maximum_artifact_bytes().unwrap());
        let verified = codec
            .open_reader(&binding, std::io::Cursor::new(&artifact))
            .unwrap();
        assert_eq!(verified.journal(), exact_journal);

        assert!(matches!(
            codec.seal(&binding, &captured(Vec::new())),
            Err(Error::Checkpoint(message))
                if message == "checkpoint journal must not be empty"
        ));
        let over_journal = captured(journal_with_len(maximum_journal_bytes + 1));
        assert!(matches!(
            codec.seal(&binding, &over_journal),
            Err(Error::Checkpoint(message))
                if message == "checkpoint journal exceeds the configured limit"
        ));

        assert!(matches!(
            codec.open_reader(&binding, std::io::Cursor::new(Vec::<u8>::new())),
            Err(Error::Checkpoint(message)) if message == "checkpoint artifact is truncated"
        ));
        assert!(matches!(
            codec.open_reader(
                &binding,
                std::io::Cursor::new(&artifact[..artifact.len() - 1]),
            ),
            Err(Error::Checkpoint(message))
                if message == "checkpoint artifact is truncated"
        ));

        let mut oversized = artifact;
        oversized.push(0);
        assert!(matches!(
            codec.open_reader(&binding, std::io::Cursor::new(oversized)),
            Err(Error::Checkpoint(message))
                if message == "checkpoint artifact exceeds the configured limit while reading"
        ));
    }

    #[test]
    fn streaming_failures_report_their_io_phase() {
        let codec = codec();
        let binding = binding();
        let captured = captured(valid_journal());
        let mut writer = FailingWriter {
            remaining: CHECKPOINT_HEADER_BYTES,
        };
        assert!(matches!(
            codec.seal_into(&binding, &captured, &mut writer),
            Err(Error::Checkpoint(message))
                if message.starts_with("checkpoint artifact metadata write failed:")
        ));

        let reader = FailingReader;
        assert!(matches!(
            codec.open_reader(&binding, reader),
            Err(Error::Checkpoint(message))
                if message.starts_with("checkpoint artifact header read failed:")
        ));
    }

    #[test]
    fn streaming_seal_does_not_build_an_artifact_sized_write_chunk() {
        let codec = codec();
        let binding = binding();
        let captured = captured(journal_with_len(1024));
        let mut writer = CountingWriter::default();

        let written = codec.seal_into(&binding, &captured, &mut writer).unwrap();
        assert_eq!(writer.total_bytes, written);
        assert_eq!(writer.writes, 4);
        assert!(writer.largest_write < written);
    }

    fn binding() -> WasixCheckpointBinding {
        WasixCheckpointBinding::new(
            format!("sha256:{}", "1".repeat(64)),
            "2".repeat(64),
            "_start",
            "instance-1",
            1,
        )
        .unwrap()
    }

    fn codec() -> WasixCheckpointCodec {
        WasixCheckpointCodec::new(CheckpointAuthenticationKey::new([7; 32]))
            .with_max_journal_bytes(1024)
    }

    fn valid_journal() -> Vec<u8> {
        let mut journal = JOURNAL_MAGIC.to_vec();
        push_record(&mut journal, 1, &[0]);
        push_record(&mut journal, 3, &[0]);
        push_record(&mut journal, 60, &[]);
        push_record(&mut journal, JOURNAL_SNAPSHOT_V1, &[0]);
        journal
    }

    fn journal_with_len(length: usize) -> Vec<u8> {
        const FRAMING_BYTES: usize = 42;
        assert!(length > FRAMING_BYTES);
        let mut journal = JOURNAL_MAGIC.to_vec();
        push_record(&mut journal, 1, &vec![0; length - FRAMING_BYTES]);
        push_record(&mut journal, 3, &[0]);
        push_record(&mut journal, 60, &[]);
        push_record(&mut journal, JOURNAL_SNAPSHOT_V1, &[0]);
        assert_eq!(journal.len(), length);
        journal
    }

    struct FailingWriter {
        remaining: usize,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::other("injected write failure"));
            }
            let written = bytes.len().min(self.remaining);
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _bytes: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected read failure"))
        }
    }

    struct ChunkedReader<'a> {
        bytes: &'a [u8],
        cursor: usize,
        maximum_read: usize,
    }

    impl Read for ChunkedReader<'_> {
        fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
            let remaining = &self.bytes[self.cursor..];
            let read = destination
                .len()
                .min(self.maximum_read)
                .min(remaining.len());
            destination[..read].copy_from_slice(&remaining[..read]);
            self.cursor += read;
            Ok(read)
        }
    }

    #[derive(Default)]
    struct CountingWriter {
        total_bytes: usize,
        largest_write: usize,
        writes: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.total_bytes += bytes.len();
            self.largest_write = self.largest_write.max(bytes.len());
            self.writes += 1;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn constructs_only_a_canonical_attested_worker_capture() {
        let bytes = valid_journal();
        let binding = binding();
        let captured = CapturedWasixJournal::from_attested_worker_capture(
            bytes.clone(),
            binding.clone(),
            worker_build_sha256(),
        )
        .unwrap();

        assert_eq!(captured.bytes, bytes);
        assert_eq!(captured.binding, binding);
        assert!(captured.explicit_snapshot);
    }

    #[test]
    fn rejects_malformed_or_noncanonical_attested_worker_capture() {
        let binding = binding();
        let mut malformed = valid_journal();
        push_record(&mut malformed, 60, &[]);
        assert!(matches!(
            CapturedWasixJournal::from_attested_worker_capture(
                malformed,
                binding.clone(),
                worker_build_sha256(),
            ),
            Err(Error::Checkpoint(message))
                if message == "checkpoint journal contains records after its snapshot"
        ));

        let mut noncanonical = binding.clone();
        noncanonical.module_sha256.replace_range(..1, "A");
        assert!(matches!(
            CapturedWasixJournal::from_attested_worker_capture(
                valid_journal(),
                noncanonical,
                worker_build_sha256(),
            ),
            Err(Error::Checkpoint(message))
                if message
                    == "checkpoint module digest must be 64 lowercase hexadecimal characters"
        ));

        assert!(matches!(
            CapturedWasixJournal::from_attested_worker_capture(
                valid_journal(),
                binding,
                "not-a-worker-digest".to_owned(),
            ),
            Err(Error::Checkpoint(message))
                if message
                    == "captured worker build digest must be 64 lowercase hexadecimal characters"
        ));
    }

    fn captured(bytes: Vec<u8>) -> CapturedWasixJournal {
        CapturedWasixJournal {
            bytes,
            binding: binding(),
            worker_build_sha256: worker_build_sha256(),
            explicit_snapshot: true,
        }
    }

    fn worker_build_sha256() -> String {
        "4".repeat(64)
    }

    fn push_record(journal: &mut Vec<u8>, record_type: u16, body: &[u8]) {
        journal.extend_from_slice(&record_type.to_be_bytes());
        journal.extend_from_slice(&u64::try_from(body.len()).unwrap().to_be_bytes()[2..]);
        journal.extend_from_slice(body);
    }

    fn envelope(codec: &WasixCheckpointCodec, metadata: &[u8], journal: &[u8]) -> Vec<u8> {
        let mut artifact = Vec::new();
        artifact.extend_from_slice(CHECKPOINT_MAGIC);
        artifact.extend_from_slice(&CHECKPOINT_FORMAT_VERSION.to_be_bytes());
        artifact.extend_from_slice(&u32::try_from(metadata.len()).unwrap().to_be_bytes());
        artifact.extend_from_slice(&u64::try_from(journal.len()).unwrap().to_be_bytes());
        artifact.extend_from_slice(metadata);
        artifact.extend_from_slice(journal);
        let tag = codec
            .authentication_tag(&artifact)
            .unwrap()
            .finalize()
            .into_bytes();
        artifact.extend_from_slice(&tag);
        artifact
    }
}
