//! Feed wire models and explicit, ordered Go JSON encoding.
use crate::wire::{Mode, write_string};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// A Go `time.Time`, preserving nanoseconds and the parsed UTC offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoTime(pub OffsetDateTime);
impl Default for GoTime {
    fn default() -> Self {
        Self(time::macros::datetime!(0001-01-01 0:00 UTC))
    }
}
impl GoTime {
    /// Parse the supported RFC3339 wire form.
    pub fn parse(value: &str) -> Result<Self> {
        Ok(Self(OffsetDateTime::parse(value, &Rfc3339)?))
    }
    /// Current UTC wall clock; query callers can inject a different clock.
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }
    /// Age in seconds, without truncation at the one-hour boundary.
    pub fn age(&self, now: &Self) -> time::Duration {
        now.0 - self.0
    }
    /// Go's timestamp representation, including zero-valued struct fields.
    pub fn text(&self) -> Result<String> {
        let t = self.0;
        ensure!(
            (0..=9999).contains(&t.year()),
            "timestamp year outside Go JSON range"
        );
        let mut out = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        if t.nanosecond() != 0 {
            let fraction = format!("{:09}", t.nanosecond());
            out.push('.');
            out.push_str(fraction.trim_end_matches('0'));
        }
        let seconds = t.offset().whole_seconds();
        ensure!(seconds % 60 == 0, "non-minute timezone offset");
        if seconds == 0 {
            out.push('Z');
        } else {
            let minutes = seconds.unsigned_abs() / 60;
            write!(
                out,
                "{}{:02}:{:02}",
                if seconds < 0 { '-' } else { '+' },
                minutes / 60,
                minutes % 60
            )?;
        }
        Ok(out)
    }
}
impl<'de> Deserialize<'de> for GoTime {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        match Option::<String>::deserialize(d)? {
            None => Ok(Self::default()),
            Some(s) => Self::parse(&s).map_err(serde::de::Error::custom),
        }
    }
}
impl Serialize for GoTime {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.text().map_err(serde::ser::Error::custom)?)
    }
}

/// A value encoded with Go's field and escaping rules, rather than serde derive.
pub trait GoWire {
    /// Append this value in the chosen wire mode.
    fn write_go(&self, output: &mut String, mode: Mode) -> Result<()>;
    /// Whether Go's `omitempty` omits this value.
    fn omitted(&self) -> bool {
        false
    }
    /// Encode one value without a trailing row delimiter.
    fn go_json(&self, mode: Mode) -> Result<String> {
        let mut out = String::new();
        self.write_go(&mut out, mode)?;
        Ok(out)
    }
}
impl GoWire for String {
    fn write_go(&self, out: &mut String, mode: Mode) -> Result<()> {
        write_string(out, self, mode);
        Ok(())
    }
    fn omitted(&self) -> bool {
        self.is_empty()
    }
}
impl GoWire for i64 {
    fn write_go(&self, out: &mut String, _: Mode) -> Result<()> {
        write!(out, "{self}")?;
        Ok(())
    }
    fn omitted(&self) -> bool {
        *self == 0
    }
}
impl GoWire for GoTime {
    fn write_go(&self, out: &mut String, mode: Mode) -> Result<()> {
        write_string(out, &self.text()?, mode);
        Ok(())
    }
}
impl<T: GoWire> GoWire for Vec<T> {
    fn write_go(&self, out: &mut String, mode: Mode) -> Result<()> {
        out.push('[');
        for (i, v) in self.iter().enumerate() {
            if i != 0 {
                out.push(',');
            }
            v.write_go(out, mode)?;
        }
        out.push(']');
        Ok(())
    }
    fn omitted(&self) -> bool {
        self.is_empty()
    }
}
impl<T: GoWire> GoWire for Option<T> {
    fn write_go(&self, out: &mut String, mode: Mode) -> Result<()> {
        if let Some(v) = self {
            v.write_go(out, mode)
        } else {
            out.push_str("null");
            Ok(())
        }
    }
    fn omitted(&self) -> bool {
        self.as_ref().is_none_or(GoWire::omitted)
    }
}

// Every wire name, order, and omission flag is explicit and follows its Go
// struct declaration. The macro only removes mechanical punctuation handling.
macro_rules! model {
    ($name:ident { $($field:ident: $ty:ty => $wire:literal, $omit:literal;)* }) => {
        #[doc = concat!("Go-compatible `", stringify!($name), "` wire model.")]
        #[derive(Debug, Clone, Default, Deserialize)]
        #[serde(default)]
        pub struct $name { $(#[doc = concat!("Wire field `", $wire, "`.")] #[serde(rename = $wire)] pub $field: $ty,)* }
        impl GoWire for $name {
            fn write_go(&self, out: &mut String, mode: Mode) -> Result<()> {
                out.push('{'); let mut first = true;
                $(if !$omit || !self.$field.omitted() {
                    if !first { out.push(','); } first = false;
                    write_string(out, $wire, mode); out.push(':'); self.$field.write_go(out, mode)?;
                })*
                let _ = first; out.push('}'); Ok(())
            }
        }
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                let raw = serde_json::value::RawValue::from_string(self.go_json(Mode::Marshal).map_err(serde::ser::Error::custom)?).map_err(serde::ser::Error::custom)?;
                raw.serialize(s)
            }
        }
    }
}
model!(Identity {
    ecosystem: String => "ecosystem", false; name: String => "name", false;
    version: String => "version", true; registry: String => "registry", true;
    sha256: String => "sha256", true; channel: String => "channel", true;
    subdir: String => "subdir", true; build: String => "build", true;
});
model!(Event {
    introduced: String => "introduced", true; fixed: String => "fixed", true;
    last_affected: String => "last_affected", true; limit: String => "limit", true;
});
model!(Range {
    kind: String => "type", false; constraint: String => "constraint", true;
    events: Option<Vec<Event>> => "events", true;
});
model!(Affected {
    package: Identity => "package", false; versions: Option<Vec<String>> => "versions", true;
    ranges: Option<Vec<Range>> => "ranges", true; scope: String => "scope", false;
});
model!(Provenance {
    source: String => "source", false; id: String => "id", false; url: String => "url", false;
    license: String => "license", false; revision: String => "revision", false;
    retrieved_at: GoTime => "retrieved_at", false;
});
model!(Evidence {
    rule_id: String => "rule_id", true; rule_version: String => "rule_version", true;
    artifact_sha256: String => "artifact_sha256", true; file: String => "file", true;
    line: i64 => "line", true; explanation: String => "explanation", false;
    observations: Option<Vec<String>> => "observations", true; reproduce: String => "reproduce", true;
    limitations: Option<Vec<String>> => "limitations", true;
});
model!(Review {
    action: String => "action", false; reviewer: String => "reviewer", false;
    rationale: String => "rationale", false; at: GoTime => "at", false;
    revision: i64 => "revision", false;
});
model!(Record {
    schema_version: String => "schema_version", false; id: String => "id", false;
    aliases: Option<Vec<String>> => "aliases", true; classification: String => "classification", false;
    status: String => "status", false; summary: String => "summary", false;
    affected: Option<Vec<Affected>> => "affected", false; evidence: Option<Vec<Evidence>> => "evidence", false;
    sources: Option<Vec<Provenance>> => "sources", false; references: Option<Vec<String>> => "references", true;
    published_at: GoTime => "published_at", false; modified_at: GoTime => "modified_at", false;
    withdrawn_at: Option<GoTime> => "withdrawn_at", true; revision: i64 => "revision", false;
    reviews: Option<Vec<Review>> => "reviews", true; original_license: String => "original_license", true;
});
model!(SourceState {
    name: String => "name", false; cursor: String => "cursor", true;
    last_success: Option<GoTime> => "last_success", true; last_attempt: Option<GoTime> => "last_attempt", true;
    error: String => "error", true; coverage: String => "coverage", false;
    gaps: Option<Vec<String>> => "gaps", true;
});
model!(Coverage {
    ecosystem: String => "ecosystem", false; mode: String => "mode", false;
    limitations: Option<Vec<String>> => "limitations", false;
});
model!(Artifact {
    path: String => "path", false; sha256: String => "sha256", false; bytes: i64 => "bytes", false;
    kind: String => "kind", false; ecosystem: String => "ecosystem", true;
    from_sequence: i64 => "from_sequence", true; to_sequence: i64 => "to_sequence", true;
    created_at: GoTime => "created_at", false;
});
model!(Manifest {
    schema_version: String => "schema_version", false; sequence: i64 => "sequence", false;
    generated_at: GoTime => "generated_at", false; record_count: i64 => "record_count", false;
    records_sha256: String => "records_sha256", false; rule_set_sha256: String => "rule_set_sha256", false;
    coverage: Option<Vec<Coverage>> => "coverage", false; sources: Option<Vec<SourceState>> => "sources", false;
    files: Option<Vec<Artifact>> => "files", false; original_data_license: String => "original_data_license", false;
    imported_data_license: String => "imported_data_license", false;
});
model!(Delta {
    operation: String => "operation", false; id: String => "id", false;
    record: Option<Record> => "record", true;
});
model!(Match {
    record: Record => "record", false; certainty: String => "certainty", false;
    reasons: Option<Vec<String>> => "reasons", true;
});
model!(QueryResponse {
    status: String => "status", false; matches: Option<Vec<Match>> => "matches", false;
    sequence: i64 => "sequence", false; generated_at: GoTime => "generated_at", false;
    coverage: Coverage => "coverage", false; freshness: String => "freshness", false;
});

impl Identity {
    /// Apply the Go identity normalization and validation rules.
    pub fn normalize(&mut self) -> Result<()> {
        self.ecosystem = match self.ecosystem.to_lowercase().as_str() {
            "pypi" | "pip" | "poetry" | "pipenv" => {
                self.name = regex::Regex::new("[-_.]+")?
                    .replace_all(&self.name.to_lowercase(), "-")
                    .to_string();
                "PyPI"
            }
            "npm" | "pnpm" => "npm",
            "cargo" | "crates" | "rust" => {
                self.name = self.name.to_lowercase();
                "Cargo"
            }
            "maven" => "Maven",
            "conda" => {
                self.name = self.name.to_lowercase();
                "Conda"
            }
            _ => bail!("unsupported ecosystem"),
        }
        .to_owned();
        ensure!(
            self.name.len() <= 214 && self.version.len() <= 200,
            "package identity too long"
        );
        let simple = regex::Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")?;
        let valid = match self.ecosystem.as_str() {
            "npm" => regex::Regex::new(r"^(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*$")?
                .is_match(&self.name),
            "Maven" => {
                let parts: Vec<_> = self.name.split(':').collect();
                parts.len() == 2 && parts.iter().all(|s| simple.is_match(s))
            }
            _ => simple.is_match(&self.name),
        };
        ensure!(valid, "invalid {} package name", self.ecosystem);
        if self.registry.is_empty() {
            self.registry = match self.ecosystem.as_str() {
                "npm" => "https://registry.npmjs.org",
                "PyPI" => "https://pypi.org",
                "Cargo" => "https://crates.io",
                "Maven" => "https://repo.maven.apache.org/maven2",
                _ => "",
            }
            .to_owned();
        }
        if self.ecosystem == "PyPI"
            && self.registry.trim_end_matches('/') == "https://pypi.org/simple"
        {
            self.registry = "https://pypi.org".to_owned();
        }
        if self.ecosystem == "Cargo"
            && [
                "https://github.com/rust-lang/crates.io-index",
                "sparse+https://index.crates.io",
                "https://index.crates.io",
            ]
            .contains(&self.registry.trim_end_matches('/'))
        {
            self.registry = "https://crates.io".to_owned();
        }
        if !self.registry.is_empty() {
            self.registry = normalize_registry(&self.registry)?;
        }
        if !self.sha256.is_empty() {
            self.sha256 = self.sha256.to_lowercase();
            ensure!(
                hex::decode(&self.sha256).is_ok_and(|b| b.len() == 32),
                "sha256 must contain 64 hex characters"
            );
        }
        Ok(())
    }
}
/// Canonicalize a registry without losing Go's explicit ports or path spelling.
pub fn normalize_registry(value: &str) -> Result<String> {
    let u = url::Url::parse(value)
        .map_err(|_| anyhow::anyhow!("registry must be an HTTPS base URL without credentials"))?;
    ensure!(
        value.starts_with("https://")
            && !u.host_str().unwrap_or_default().is_empty()
            && u.username().is_empty()
            && u.password().is_none()
            && u.query().is_none()
            && u.fragment().is_none()
            && value.is_ascii()
            && !value.bytes().any(|b| b <= b' ' || b == 127)
            && !value.contains('\\'),
        "registry must be an HTTPS base URL without credentials"
    );
    let rest = &value[8..];
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    ensure!(
        !authority.contains('@'),
        "registry must be an HTTPS base URL without credentials"
    );
    let bytes = path.as_bytes();
    ensure!(
        bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~%/$&+,;=:@".contains(b))
            && bytes.iter().enumerate().all(|(i, b)| *b != b'%'
                || bytes
                    .get(i + 1..i + 3)
                    .is_some_and(|p| p.iter().all(u8::is_ascii_hexdigit)))
            && (path.is_empty() || u.path() == format!("/{path}")),
        "registry must be an HTTPS base URL without credentials"
    );
    Ok(format!(
        "https://{}{}",
        authority.to_lowercase(),
        if path.is_empty() {
            String::new()
        } else {
            format!("/{path}")
        }
    )
    .trim_end_matches('/')
    .to_owned())
}
impl Record {
    /// Validate and normalize a snapshot/delta record before hashing, like Go.
    pub fn validate(&mut self) -> Result<()> {
        if self.schema_version.is_empty() {
            self.schema_version = "1.0".to_owned();
        }
        ensure!(self.schema_version == "1.0", "unsupported schema version");
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 100
                && self.affected.as_ref().is_some_and(|v| !v.is_empty())
                && self.sources.as_ref().is_some_and(|v| !v.is_empty()),
            "id, affected packages and provenance are required"
        );
        ensure!(
            ["malicious", "suspicious"].contains(&self.classification.as_str()),
            "classification must be malicious or suspicious"
        );
        for a in self.affected.iter_mut().flatten() {
            a.package.normalize()?;
            if a.scope.is_empty() {
                a.scope = "unknown".to_owned();
            }
            ensure!(
                ["all", "versions", "unknown"].contains(&a.scope.as_str()),
                "invalid affected scope"
            );
            ensure!(
                a.scope != "all"
                    || (a.versions.omitted() && a.ranges.omitted() && a.package.version.is_empty()),
                "all scope cannot contain version selectors"
            );
        }
        for s in self.sources.iter().flatten() {
            ensure!(
                !s.source.is_empty()
                    && !s.id.is_empty()
                    && !s.license.is_empty()
                    && !s.revision.is_empty(),
                "complete source attribution is required"
            );
        }
        ensure!(
            self.evidence.as_ref().is_some_and(|v| !v.is_empty()),
            "evidence is required"
        );
        for e in self.evidence.iter().flatten() {
            ensure!(
                !e.explanation.trim().is_empty(),
                "evidence explanation is required"
            );
            ensure!(
                e.rule_id.is_empty() == e.rule_version.is_empty(),
                "rule id and version must be provided together"
            );
        }
        ensure!(
            self.go_json(Mode::Marshal)?.len() <= 1 << 20,
            "intelligence record exceeds size limit"
        );
        Ok(())
    }
}

/// SHA-256 over ordered Go hash-mode rows, including each final newline.
pub fn records_hash(records: &[Record]) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for r in records {
        hash.update(r.go_json(Mode::Hash)?);
        hash.update(b"\n");
    }
    Ok(hex::encode(hash.finalize()))
}
