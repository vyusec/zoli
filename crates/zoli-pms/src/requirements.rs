//! Non-executing inventory for a deliberately narrow, hash-pinned pip input.
//! This does not resolve transitive dependencies or authorize installation.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{collections::BTreeSet, path::Path, sync::OnceLock};
use zoli_intel::{feed::read_bounded, model::Identity, pypi};

/// Maximum UTF-8 input size, including comments and continuations.
pub const MAX_BYTES: usize = 1 << 20;
/// Maximum physical lines, including blank lines and comments.
pub const MAX_LINES: usize = 10_000;

// PyPA's version grammar, kept separate from the Go-compatible feed parser.
// Acceptance requires both: Go quirks such as `1..a1` must not become pip pins.
const PIN_VERSION: &str = concat!(
    r"(?ix)^v?(?:[0-9]+!)?[0-9]+(?:\.[0-9]+)*",
    r"(?:[-_.]?(?:alpha|beta|preview|pre|rc|a|b|c)[-_.]?[0-9]*)?",
    r"(?:(?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?",
    r"(?:[-_.]?dev[-_.]?[0-9]*)?",
    r"(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$",
);
static VERSION_GRAMMAR: OnceLock<Result<regex::Regex, regex::Error>> = OnceLock::new();
static ENCODING_DECLARATION: OnceLock<Result<regex::Regex, regex::Error>> = OnceLock::new();

/// One exact requirement and its allowed SHA-256 artifact digests.
#[derive(Debug, Serialize)]
pub struct Requirement {
    /// First physical line of this requirement.
    pub line: usize,
    /// Normalized PyPI identity; hashes are kept separately because there may be several.
    pub identity: Identity,
    /// Explicit allowed hashes; no digest is inferred from a URL or filename.
    pub sha256: Vec<String>,
}
/// Input that must not be silently omitted from a future guarded installation.
#[derive(Debug, Serialize)]
pub struct Gap {
    /// First physical line containing unsupported input.
    pub line: usize,
    /// Stable reason without source contents, credentials or URLs.
    pub reason: String,
}
/// Every supported pin and every unsupported line in the input.
#[derive(Debug, Serialize)]
pub struct Requirements {
    /// Exact named package pins with one or more SHA-256 hashes.
    pub packages: Vec<Requirement>,
    /// Unsupported or inconsistent declarations.
    pub gaps: Vec<Gap>,
}
impl Requirements {
    /// Read at most 1 MiB as UTF-8. The trusted registry is supplied by the caller;
    /// index options in the file cannot select or authorize a new destination.
    pub fn read(path: &Path, registry: &str) -> Result<Self> {
        ensure!(
            std::fs::symlink_metadata(path)?.file_type().is_file(),
            "requirements input must be a regular file, not a symlink or special file"
        );
        let bytes = read_bounded(path, MAX_BYTES)?;
        Self::parse(
            std::str::from_utf8(&bytes).context("requirements must be UTF-8")?,
            registry,
        )
    }
    /// Parse exact `name==version --hash=sha256:...` pins, comments and continuations.
    /// Extras, markers, includes, constraints, editable/URL paths and options are gaps.
    pub fn parse(text: &str, registry: &str) -> Result<Self> {
        ensure!(text.len() <= MAX_BYTES, "requirements byte limit exceeded");
        // Configuration errors are not per-line input gaps. Validate once even
        // for an empty file, and never return registry credentials in a report.
        let mut source = Identity {
            ecosystem: "PyPI".into(),
            name: "requirements".into(),
            registry: registry.into(),
            ..Default::default()
        };
        source.normalize()?;
        let registry = source.registry.as_str();
        let mut result = Self {
            packages: vec![],
            gaps: vec![],
        };
        let mut logical = String::new();
        let mut pending = false;
        let mut start = 1;
        let mut seen = BTreeSet::new();
        let encoding = ENCODING_DECLARATION
            .get_or_init(|| regex::Regex::new(r"^[ \t]*#.*coding[:=][ \t]*[-_.a-zA-Z0-9]+"))
            .as_ref()
            .map_err(|_| anyhow::anyhow!("invalid built-in encoding declaration grammar"))?;
        for (index, physical) in text.lines().enumerate() {
            ensure!(index < MAX_LINES, "requirements line limit exceeded");
            // PEP 263 headers can select a different decoder in pip. This
            // reader accepts already-decoded UTF-8 only; never hide a decoder
            // instruction among ordinary comments, even if it names UTF-8.
            if index < 2 && encoding.is_match(physical) {
                result.gaps.push(Gap {
                    line: index + 1,
                    reason: "unsupported_encoding_declaration".into(),
                });
            }
            if !pending {
                start = index + 1;
            }
            let continuation = physical.bytes().rev().take_while(|b| *b == b'\\').count() % 2 == 1;
            pending = continuation;
            logical.push_str(if continuation {
                &physical[..physical.len() - 1]
            } else {
                physical
            });
            if continuation {
                continue;
            }
            let line = strip_comment(&logical).trim_matches([' ', '\t']);
            if logical.bytes().any(|b| b.is_ascii_control() && b != b'\t') {
                result.gaps.push(Gap {
                    line: start,
                    reason: "unsupported_control_character".into(),
                });
            } else if !line.is_empty() {
                match pin(line, start, registry) {
                    Ok(package) => {
                        if !seen.insert(package.identity.name.clone()) {
                            result.gaps.push(Gap {
                                line: start,
                                reason: "duplicate_package_pin".into(),
                            });
                        }
                        result.packages.push(package);
                    }
                    Err(_) => result.gaps.push(Gap {
                        line: start,
                        reason: "unsupported_or_invalid_hash_pinned_requirement".into(),
                    }),
                }
            }
            logical.clear();
        }
        if pending {
            result.gaps.push(Gap {
                line: start,
                reason: "unterminated_line_continuation".into(),
            });
        }
        if result.packages.is_empty() && result.gaps.is_empty() {
            result.gaps.push(Gap {
                line: 1,
                reason: "no_package_pins".into(),
            });
        }
        Ok(result)
    }

    /// Return pins only when this file has no unsupported or ambiguous input.
    /// This proves input completeness, not transitive dependency completeness,
    /// artifact approval or permission to start an installer.
    pub fn complete_pins(&self) -> Result<&[Requirement]> {
        ensure!(
            self.gaps.is_empty() && !self.packages.is_empty(),
            "requirements contain gaps or no package pins"
        );
        Ok(&self.packages)
    }
}
fn strip_comment(line: &str) -> &str {
    for (i, c) in line.char_indices() {
        if c == '#' && (i == 0 || line[..i].ends_with(char::is_whitespace)) {
            return &line[..i];
        }
    }
    line
}
fn pin(line: &str, number: usize, registry: &str) -> Result<Requirement> {
    ensure!(
        line.is_ascii() && !line.bytes().any(|b| b.is_ascii_control() && b != b'\t'),
        "unsupported requirements character"
    );
    let (spec, hashes) = line.split_once("--hash=").context("missing SHA-256 pin")?;
    ensure!(
        spec.ends_with(char::is_whitespace),
        "hash option requires whitespace"
    );
    let (name, version) = spec
        .trim()
        .split_once("==")
        .context("requirement must be exactly pinned")?;
    ensure!(
        name.trim()
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric),
        "invalid pip package name"
    );
    let grammar = VERSION_GRAMMAR
        .get_or_init(|| regex::Regex::new(PIN_VERSION))
        .as_ref()
        .map_err(|_| anyhow::anyhow!("invalid built-in pin version grammar"))?;
    ensure!(grammar.is_match(version.trim()), "invalid pip version pin");
    let mut identity = Identity {
        ecosystem: "PyPI".into(),
        name: name.trim().into(),
        version: version.trim().into(),
        registry: registry.into(),
        ..Default::default()
    };
    identity.normalize()?;
    ensure!(
        pypi::concrete(&identity.version),
        "requirement version must be concrete"
    );
    let mut digests = BTreeSet::new();
    for (i, item) in hashes.split_whitespace().enumerate() {
        let item = if i == 0 {
            item
        } else {
            item.strip_prefix("--hash=")
                .context("unsupported requirement option")?
        };
        let digest = item
            .strip_prefix("sha256:")
            .context("only SHA-256 pins are supported")?;
        ensure!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid SHA-256 pin"
        );
        digests.insert(digest.to_ascii_lowercase());
    }
    ensure!(!digests.is_empty(), "missing SHA-256 pin");
    Ok(Requirement {
        line: number,
        identity,
        sha256: digests.into_iter().collect(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn pins_normalize_and_keep_every_artifact_hash() {
        let text = format!(
            "# test\nSome_Package.Name == 1!2.0rc1 \\\n    --hash=sha256:{} \\\n    --hash=sha256:{} # comment\n",
            "A".repeat(64),
            "b".repeat(64)
        );
        let inventory = Requirements::parse(&text, "https://pypi.org/simple/").unwrap();
        assert!(inventory.gaps.is_empty());
        let p = &inventory.packages[0];
        assert_eq!(p.line, 2);
        assert_eq!(p.identity.name, "some-package-name");
        assert_eq!(p.identity.registry, "https://pypi.org");
        assert_eq!(p.sha256, ["a".repeat(64), "b".repeat(64)]);
    }
    #[test]
    fn unsupported_lines_remain_visible_and_never_disclose_the_input() {
        for line in [
            "-r secrets.txt",
            "--index-url=https://user:secret@example.org",
            "-e .",
            "x @ https://user:secret@example.org/x.whl",
            "x>=1",
            "x==1.*",
            "x[extra]==1",
            "x==1; python_version>'3'",
            "x==1",
            "x==1 --hash=sha512:bad",
            "x==1 --hash=sha256:bad",
            "x===1",
            "${PRIVATE}",
        ] {
            let inv = Requirements::parse(line, "https://pypi.org").unwrap();
            assert!(inv.packages.is_empty(), "{line}");
            assert_eq!(inv.gaps.len(), 1, "{line}");
            assert!(!serde_json::to_string(&inv).unwrap().contains("secret"));
        }
    }
    #[test]
    fn duplicate_pins_continuations_and_bounds_refuse_completion() {
        let line = format!("some_pkg==1 --hash=sha256:{}\n", "a".repeat(64));
        let text = format!("{line}{}", line.replace("some_pkg", "Some-Pkg"));
        assert_eq!(
            Requirements::parse(&text, "https://pypi.org").unwrap().gaps[0].reason,
            "duplicate_package_pin"
        );
        assert_eq!(
            Requirements::parse("x==1 \\", "https://pypi.org")
                .unwrap()
                .gaps[0]
                .reason,
            "unterminated_line_continuation"
        );
        assert_eq!(
            Requirements::parse(&format!("{line}\\"), "https://pypi.org")
                .unwrap()
                .gaps[0]
                .reason,
            "unterminated_line_continuation"
        );
        assert!(Requirements::parse(&"x".repeat((1 << 20) + 1), "https://pypi.org").is_err());
        assert!(Requirements::parse(&"\n".repeat(10_001), "https://pypi.org").is_err());
    }
}
