//! Network-free artifact inspection. No package-provided code is executed.
use serde::{Deserialize, Serialize};
use zoli_intel::{feed::sha256, model::Identity};
mod analysis;
mod archive;

/// Analyzer version included in every artifact report.
pub const ANALYZER_VERSION: &str = "static-v1";
/// Resource limits apply even when assessment latency is not a product target.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Compressed archive bytes.
    pub max_artifact_bytes: usize,
    /// Total regular-file expansion bytes.
    pub max_expanded_bytes: usize,
    /// All entries, including directories and rejected entries.
    pub max_files: usize,
    /// Source-file bytes retained for parsing.
    pub max_source_bytes: usize,
    /// Worker deadline in seconds.
    pub worker_seconds: u64,
    /// Parent-enforced worker RSS budget in bytes.
    pub worker_memory_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_artifact_bytes: 20 << 20,
            max_expanded_bytes: 100 << 20,
            max_files: 10_000,
            max_source_bytes: 8 << 20,
            worker_seconds: 120,
            worker_memory_bytes: 512 << 20,
        }
    }
}
/// A local observation. Suspicion is separate from a feed malware classification.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Finding {
    /// Stable versioned local rule identifier.
    pub rule_id: String,
    /// Rule version; code digest additionally binds the exact implementation.
    pub rule_version: String,
    /// `informational`, `medium` or `high`.
    pub severity: String,
    /// Evidence confidence, independent of severity.
    pub confidence: String,
    /// Original archive path, never an extracted file path.
    pub file: String,
    /// Original one-based source line (manifest line for inline hooks).
    pub line: usize,
    /// Explanation without source values or secret contents.
    pub explanation: String,
    /// Source/transform steps, retaining locations but no literal credentials.
    pub observations: Vec<String>,
}
/// A package bundled inside the containing artifact.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Bundled {
    /// Directory inside the containing archive.
    pub path: String,
    /// Identity from the bundled package manifest; parent digest is not its hash.
    pub identity: Identity,
}
/// Local analysis result; `complete` means the declared static checks completed,
/// never a proof that every possible program behavior is safe.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Report {
    /// Report format version.
    pub schema: u32,
    /// Exact artifact identity requested by the caller.
    pub identity: Identity,
    /// Digest of the actual archive bytes; empty when bytes could not be acquired.
    pub artifact_sha256: String,
    /// Analyzer version.
    pub analyzer_version: String,
    /// Digest of the actual bundled analyzer/rule implementation.
    pub rules_sha256: String,
    /// Effective budgets used for this result, including failed workers.
    pub limits: Limits,
    /// Host context for future cache identities; no result reuse is implemented.
    pub platform: String,
    /// All required checks completed within their stated scope.
    pub complete: bool,
    /// Archive entries processed.
    pub entries: usize,
    /// Regular-file expansion bytes processed.
    pub expanded_bytes: u64,
    /// JavaScript/TypeScript/inline files parsed.
    pub source_files: usize,
    /// Non-executable data files recorded but not parsed as code.
    pub data_files: usize,
    /// Explicit archive, format and analysis gaps.
    pub gaps: Vec<String>,
    /// Local observations.
    pub findings: Vec<Finding>,
    /// Embedded package identities, bound to the containing artifact only.
    pub bundled: Vec<Bundled>,
    /// Permanent static-analysis limitations, including completed scans.
    pub limitations: Vec<String>,
}
impl Report {
    /// Initialize a report before reading untrusted archive content.
    pub fn new(identity: Identity, bytes: &[u8], limits: &Limits) -> Self {
        Self {
            schema: 1, identity, artifact_sha256: sha256(bytes),
            analyzer_version: ANALYZER_VERSION.into(),
            rules_sha256: sha256(concat!(include_str!("archive.rs"),include_str!("analysis.rs")).as_bytes()),
            limits: limits.clone(),
            platform: format!("{}-{}",std::env::consts::OS,std::env::consts::ARCH),
            complete:false, entries:0, expanded_bytes:0, source_files:0, data_files:0,
            gaps:vec![],findings:vec![],bundled:vec![],
            limitations:vec![
                "Static analysis does not prove safety".into(),
                "Versioned checks use per-file bounded flow; whole-program reachability and arbitrary runtime behavior are not proven".into(),
                "No package code, hooks, imports, builds or package-provided commands were executed".into(),
            ],
        }
    }
    /// Record an unavailable or failed worker as incomplete.
    pub fn failed(identity: Identity, bytes: &[u8], limits: &Limits, reason: &str) -> Self {
        let mut r = Self::new(identity, bytes, limits);
        r.gaps.push(reason.to_owned());
        r
    }
    /// Refuse an artifact before reading its bytes, without inventing a digest.
    pub fn unavailable(identity: Identity, limits: &Limits, reason: &str) -> Self {
        let mut report = Self::new(identity, &[], limits);
        report.artifact_sha256.clear();
        report.gaps.push(reason.into());
        report
            .limitations
            .push("Archive bytes were not acquired; the artifact digest is unavailable".into());
        report
    }
}
/// Inspect bytes without extraction, execution or network access. Archive errors
/// preserve an explicit incomplete report instead of becoming an empty success.
pub fn inspect(bytes: &[u8], identity: Identity, limits: &Limits) -> Report {
    let mut report = Report::new(identity, bytes, limits);
    if let Err(error) = archive::inspect(bytes, limits, &mut report) {
        report
            .gaps
            .push(format!("archive_inspection_failed:{error}"));
    }
    report
        .findings
        .sort_by(|a, b| (&a.file, a.line, &a.rule_id).cmp(&(&b.file, b.line, &b.rule_id)));
    report
        .findings
        .dedup_by(|a, b| a.file == b.file && a.line == b.line && a.rule_id == b.rule_id);
    report.gaps.sort();
    report.gaps.dedup();
    report.complete = report.gaps.is_empty();
    report
}
