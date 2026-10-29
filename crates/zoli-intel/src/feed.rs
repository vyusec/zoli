//! Feed verification, bounded snapshot/delta decoding and atomic trusted storage.
use crate::{json, model::*, net::Fetch};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
};

/// Maximum manifest envelope size.
pub const MAX_MANIFEST: usize = 2 << 20;
/// Maximum compressed artifact size.
pub const MAX_ARTIFACT: usize = 256 << 20;
/// Reaching the Go expansion limit is an error.
pub const MAX_EXPANDED: usize = 512 << 20;
const MAX_ROW: usize = 2 << 20;

/// Signed envelope; the exact raw manifest bytes are never reconstructed.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Envelope {
    /// Original manifest JSON value.
    pub manifest: Box<serde_json::value::RawValue>,
    /// First sixteen hex characters of the pinned public key hash.
    pub key_id: String,
    /// Padded standard base64 Ed25519 signature.
    pub signature: String,
}
/// Go-compatible verified cache representation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Snapshot {
    /// Signed envelope.
    pub envelope: Envelope,
    /// Ordered records, without re-normalization on cache load.
    pub records: Vec<Record>,
}
/// SHA-256 hex digest used by the feed and artifact identity.
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
/// Derive the Go public-key identifier.
pub fn key_id(key: &[u8; 32]) -> String {
    sha256(key)[..16].to_owned()
}
/// Go's safePath predicate on supported Unix platforms, including `.` and `..`.
pub fn safe_path(path: &str) -> bool {
    if path == "." || path == ".." {
        return true;
    }
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}
impl Envelope {
    /// Authenticate before parsing or acting on any manifest fields.
    pub fn verify(&self, key: &[u8; 32]) -> Result<Manifest> {
        ensure!(
            self.key_id == key_id(key) && !self.signature.contains(['\r', '\n']),
            "invalid manifest signature"
        );
        let signature = STANDARD
            .decode(&self.signature)
            .context("invalid manifest signature encoding")?;
        let signature =
            Signature::from_slice(&signature).context("invalid manifest signature length")?;
        VerifyingKey::from_bytes(key)?
            .verify_strict(self.manifest.get().as_bytes(), &signature)
            .context("invalid manifest signature")?;
        let m: Manifest = json::decode(self.manifest.get().as_bytes())?;
        ensure!(
            m.schema_version == "1.0" && m.sequence >= 0,
            "unsupported schema or invalid sequence"
        );
        for a in m.files.iter().flatten() {
            ensure!(
                safe_path(&a.path) && a.sha256.len() == 64 && a.bytes >= 0,
                "invalid artifact descriptor"
            );
        }
        Ok(m)
    }
    /// Identity of the signed message for equivocation and cache/state binding.
    pub fn digest(&self) -> String {
        sha256(self.manifest.get().as_bytes())
    }
}
impl Snapshot {
    /// Check the signature, count and full ordered record hash without mutation.
    pub fn verify(&self, key: &[u8; 32]) -> Result<Manifest> {
        let m = self.envelope.verify(key)?;
        ensure!(
            i64::try_from(self.records.len())? == m.record_count
                && records_hash(&self.records)? == m.records_sha256,
            "cached records do not match signed manifest"
        );
        Ok(m)
    }
}
/// Verify compressed bytes before decompressing or decoding any row.
pub fn verify_artifact(bytes: &[u8], artifact: &Artifact) -> Result<()> {
    ensure!(
        artifact.bytes >= 0
            && artifact.bytes <= MAX_ARTIFACT as i64
            && bytes.len() as i64 == artifact.bytes
            && sha256(bytes) == artifact.sha256,
        "artifact checksum or size mismatch"
    );
    Ok(())
}
/// Decode concatenated gzip members with Go row semantics and bounded memory.
pub fn decode_rows<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<Vec<T>> {
    let decoder = flate2::read::MultiGzDecoder::new(bytes);
    let mut reader = BufReader::new(decoder.take(MAX_EXPANDED as u64));
    let mut total = 0usize;
    let mut result = vec![];
    loop {
        let mut row = vec![];
        let n = reader
            .by_ref()
            .take(MAX_ROW as u64 + 1)
            .read_until(b'\n', &mut row)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n).context("expansion overflow")?;
        ensure!(total < MAX_EXPANDED, "feed expansion limit exceeded");
        ensure!(n < MAX_ROW, "feed row exceeds scanner limit");
        if row.last() == Some(&b'\n') {
            row.pop();
        }
        if row.last() == Some(&b'\r') {
            row.pop();
        }
        ensure!(!row.is_empty(), "blank feed row");
        result.push(json::decode(&row)?);
    }
    Ok(result)
}
/// Apply normalized deltas and sort the result by record ID, like Go.
pub fn apply_delta(records: &[Record], deltas: Vec<Delta>) -> Result<Vec<Record>> {
    let mut by_id: BTreeMap<_, _> = records.iter().map(|r| (r.id.clone(), r.clone())).collect();
    for d in deltas {
        match d.operation.as_str() {
            "upsert" | "withdraw" => {
                let mut r = d.record.context("delta record identity mismatch")?;
                ensure!(d.id == r.id, "delta record identity mismatch");
                ensure!(
                    d.operation != "withdraw" || r.status == "withdrawn",
                    "invalid withdrawal delta"
                );
                r.validate()?;
                by_id.insert(d.id, r);
            }
            "remove" => {
                ensure!(d.record.is_none(), "remove delta cannot contain record");
                by_id.remove(&d.id);
            }
            _ => bail!("unknown delta operation"),
        }
    }
    Ok(by_id.into_values().collect())
}
/// Fetch and verify a publication, respecting Go's delta fallback rules.
pub fn fetch_snapshot(
    fetch: &impl Fetch,
    base: &str,
    key: &[u8; 32],
    previous: Option<&Snapshot>,
    floor: Option<(i64, &str)>,
) -> Result<Snapshot> {
    let base = base.trim_end_matches('/');
    let envelope: Envelope =
        json::decode(&fetch.get(&format!("{base}/latest.json"), MAX_MANIFEST)?)?;
    let manifest = envelope.verify(key)?;
    if let Some((sequence, digest)) = floor {
        ensure!(manifest.sequence >= sequence, "feed rollback rejected");
        ensure!(
            manifest.sequence != sequence || envelope.digest() == digest,
            "same-sequence manifest equivocation rejected"
        );
    }
    let last = previous.map(|s| s.verify(key)).transpose()?;
    if let Some(last) = &last {
        ensure!(manifest.sequence >= last.sequence, "feed rollback rejected");
        if manifest.sequence == last.sequence {
            let previous = previous.context("previous snapshot missing")?;
            ensure!(
                envelope.digest() == previous.envelope.digest(),
                "same-sequence manifest equivocation rejected"
            );
            return Ok(previous.clone());
        }
    }
    let get = |a: &Artifact| -> Result<Vec<u8>> {
        let bytes = fetch.get(&format!("{base}/{}", a.path), MAX_ARTIFACT)?;
        verify_artifact(&bytes, a)?;
        Ok(bytes)
    };
    if let (Some(previous), Some(last)) = (previous, last) {
        let mut records = previous.records.clone();
        let mut sequence = last.sequence;
        while sequence < manifest.sequence {
            let next = manifest.files.iter().flatten().find(|a| {
                a.kind == "delta" && a.from_sequence == sequence && a.to_sequence > sequence
            });
            let Some(next) = next else {
                break;
            };
            records = apply_delta(&records, decode_rows::<Delta>(&get(next)?)?)?;
            sequence = next.to_sequence;
        }
        if sequence == manifest.sequence {
            let snapshot = Snapshot { envelope, records };
            snapshot.verify(key)?;
            return Ok(snapshot);
        }
    }
    let artifact = manifest
        .files
        .iter()
        .flatten()
        .find(|a| a.kind == "snapshot" && a.ecosystem.is_empty())
        .context("manifest lacks full snapshot")?;
    let mut records: Vec<Record> = decode_rows(&get(artifact)?)?;
    for r in &mut records {
        r.validate()?;
    }
    let snapshot = Snapshot { envelope, records };
    snapshot.verify(key)?;
    Ok(snapshot)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u32,
    key_id: String,
    sequence: i64,
    manifest_sha256: String,
}
/// Filesystem store with a high-water mark independent of the verified cache.
pub struct Store {
    home: PathBuf,
}
impl Store {
    /// Use a dedicated operator/user-owned Zoli state directory.
    pub fn new(home: PathBuf) -> Self {
        Self { home }
    }
    fn cache(&self) -> PathBuf {
        self.home.join("cache/feed.json")
    }
    fn state(&self) -> PathBuf {
        self.home.join("state.json")
    }
    fn lock(&self, shared: bool) -> Result<File> {
        private_dir(&self.home)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(self.home.join("update.lock"))?;
        if shared {
            file.lock_shared()?;
        } else {
            file.lock()?;
        }
        Ok(file)
    }
    fn read_state(&self, key: &[u8; 32]) -> Result<Option<State>> {
        if !self.state().exists() {
            ensure!(
                !self.cache().exists(),
                "high-water state missing beside existing cache; recovery required"
            );
            return Ok(None);
        }
        let state: State = json::decode(&read_bounded(&self.state(), MAX_MANIFEST)?)?;
        ensure!(
            state.schema == 1
                && state.key_id == key_id(key)
                && state.sequence >= 0
                && hex::decode(&state.manifest_sha256).is_ok_and(|v| v.len() == 32),
            "invalid or mismatched high-water state; recovery required"
        );
        Ok(Some(state))
    }
    fn read_cache(&self, key: &[u8; 32], state: &State) -> Result<Snapshot> {
        let snapshot: Snapshot = json::decode(&read_bounded(&self.cache(), MAX_EXPANDED)?)?;
        let m = snapshot.verify(key)?;
        ensure!(
            m.sequence == state.sequence && snapshot.envelope.digest() == state.manifest_sha256,
            "cache and high-water state disagree; run zoli update"
        );
        Ok(snapshot)
    }
    /// Load only a cache that agrees with independently persisted trusted state.
    pub fn load(&self, key: &[u8; 32]) -> Result<Snapshot> {
        let _guard = self.lock(true)?;
        let state = self
            .read_state(key)?
            .context("no verified feed; run zoli update")?;
        self.read_cache(key, &state)
    }
    /// Authenticate fully, then commit state before cache, remaining fail closed
    /// if interrupted between the two atomic renames. A later update repairs it.
    pub fn update(&self, fetch: &impl Fetch, base: &str, key: &[u8; 32]) -> Result<Snapshot> {
        let _guard = self.lock(false)?;
        let state = self.read_state(key)?;
        let previous = state.as_ref().and_then(|s| self.read_cache(key, s).ok());
        let snapshot = fetch_snapshot(
            fetch,
            base,
            key,
            previous.as_ref(),
            state
                .as_ref()
                .map(|s| (s.sequence, s.manifest_sha256.as_str())),
        )?;
        let m = snapshot.verify(key)?;
        let bytes = serde_json::to_vec(&snapshot)?;
        ensure!(
            bytes.len() <= MAX_EXPANDED,
            "verified cache exceeds local storage limit"
        );
        private_dir(self.cache().parent().context("cache directory missing")?)?;
        let mut temporary = tempfile::NamedTempFile::new_in(
            self.cache().parent().context("cache directory missing")?,
        )?;
        temporary.write_all(&bytes)?;
        temporary.as_file().sync_all()?;
        let state = State {
            schema: 1,
            key_id: key_id(key),
            sequence: m.sequence,
            manifest_sha256: snapshot.envelope.digest(),
        };
        atomic_write(&self.state(), &serde_json::to_vec(&state)?)?;
        temporary.persist(self.cache()).map_err(|e| e.error)?;
        File::open(self.cache().parent().context("cache directory missing")?)?.sync_all()?;
        Ok(snapshot)
    }
}
/// Create private data directories without changing unrelated existing paths.
pub fn private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}
/// Bounded file input used by configuration, caches and package metadata.
pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = File::open(path).context("cannot open required input file")?;
    ensure!(
        file.metadata()?.len() <= max as u64,
        "input file exceeds byte limit"
    );
    let mut bytes = vec![];
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "input file exceeds byte limit");
    Ok(bytes)
}
/// Durable same-directory replacement, with private file mode.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    private_dir(parent)?;
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    f.write_all(bytes)?;
    f.as_file().sync_all()?;
    f.persist(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
