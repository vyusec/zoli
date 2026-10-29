use crate::{Bundled, Finding, Limits, Report, analysis};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
};
use zoli_intel::{json, model::Identity};

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 1024
        && !name.starts_with('/')
        && !name.contains(['\\', ':'])
        && !name.chars().any(char::is_control)
        && name
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}
fn executable_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\0asm")
        || [
            &b"\xfe\xed\xfa\xce"[..],
            &b"\xce\xfa\xed\xfe"[..],
            &b"\xfe\xed\xfa\xcf"[..],
            &b"\xcf\xfa\xed\xfe"[..],
            &b"\xca\xfe\xba\xbe"[..],
            &b"\xbe\xba\xfe\xca"[..],
        ]
        .iter()
        .any(|m| bytes.starts_with(m))
}
fn script_kind(name: &str, bytes: &[u8]) -> Option<bool> {
    if bytes.starts_with(b"#!") {
        let header = bytes.split(|b| *b == b'\n').next().unwrap_or_default();
        let node = std::str::from_utf8(&header[2..])
            .ok()
            .and_then(shlex::split)
            .is_some_and(|tokens| {
                let Some(interpreter) = tokens
                    .first()
                    .and_then(|t| Path::new(t).file_name())
                    .and_then(|n| n.to_str())
                else {
                    return false;
                };
                matches!(interpreter, "node" | "nodejs")
                    || interpreter == "env"
                        && tokens
                            .iter()
                            .skip(1)
                            .find(|s| !s.starts_with('-'))
                            .is_some_and(|s| matches!(s.as_str(), "node" | "nodejs"))
            });
        return Some(node);
    }
    let extension = Path::new(name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ["js", "cjs", "mjs", "jsx", "ts", "cts", "mts", "tsx"].contains(&extension.as_str()) {
        return Some(true);
    }
    if [
        "sh", "bash", "zsh", "fish", "py", "rb", "ps1", "cmd", "bat", "vue", "svelte", "html",
        "htm", "cc", "cpp", "c", "h", "gyp", "node", "wasm", "exe", "dll", "so", "dylib", "bin",
        "a", "o", "obj", "lib", "zip", "7z", "rar", "tgz", "tar", "gz", "bz2", "xz", "zst", "gpg",
        "pgp", "age", "enc",
    ]
    .contains(&extension.as_str())
    {
        return Some(false);
    }
    None
}
pub(super) fn inspect(bytes: &[u8], limits: &Limits, report: &mut Report) -> Result<()> {
    ensure!(
        bytes.len() <= limits.max_artifact_bytes,
        "compressed byte limit exceeded"
    );
    let reader: Box<dyn Read + '_> = if bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::MultiGzDecoder::new(bytes))
    } else {
        Box::new(bytes)
    };
    let framing = limits
        .max_expanded_bytes
        .checked_add(
            limits
                .max_files
                .checked_mul(2048)
                .context("entry budget overflow")?,
        )
        .context("expansion budget overflow")?;
    let reader = reader.take(framing as u64 + 1);
    let mut archive = tar::Archive::new(reader);
    archive.set_ignore_zeros(true);
    let mut names = BTreeSet::new();
    let mut files = BTreeMap::new();
    // Raw iteration prevents extension headers from allocating or hiding entries
    // before our limits and special-file checks run.
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        report.entries += 1;
        ensure!(
            report.entries <= limits.max_files,
            "archive entry count limit exceeded"
        );
        let raw = entry.path_bytes();
        let raw = std::str::from_utf8(&raw).context("non-UTF-8 archive path")?;
        let name = raw.trim_end_matches('/').to_owned();
        ensure!(safe_name(&name), "unsafe archive path");
        ensure!(names.insert(name.clone()), "duplicate archive path");
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        ensure!(
            kind.is_file(),
            "archive links and special files are forbidden"
        );
        let size = entry.size();
        report.expanded_bytes = report
            .expanded_bytes
            .checked_add(size)
            .context("archive size overflow")?;
        ensure!(
            report.expanded_bytes <= limits.max_expanded_bytes as u64,
            "archive expansion limit exceeded"
        );
        let mut prefix = [0u8; 128];
        let mut n = 0;
        while n < prefix.len() {
            let read = entry.read(&mut prefix[n..])?;
            if read == 0 {
                break;
            }
            n += read;
        }
        let mode = entry.header().mode()?;
        let code = script_kind(&name, &prefix[..n]);
        if executable_magic(&prefix[..n])
            || code == Some(false)
            || (mode & 0o111 != 0 && code != Some(true))
        {
            report
                .gaps
                .push(format!("unsupported_executable_content:{name}"));
        }
        let retain =
            code == Some(true) || name.ends_with("/package.json") || name == "package.json";
        if retain {
            if size > limits.max_source_bytes as u64 {
                report
                    .gaps
                    .push(format!("source_file_limit_exceeded:{name}"));
                continue;
            }
            let mut data = prefix[..n].to_vec();
            entry
                .take(limits.max_source_bytes as u64 + 1)
                .read_to_end(&mut data)?;
            ensure!(
                data.len() <= limits.max_source_bytes,
                "source file exceeds byte limit"
            );
            files.insert(name, data);
        } else {
            report.data_files += 1;
        }
    }
    let mut reader = archive.into_inner();
    std::io::copy(&mut reader, &mut std::io::sink())?;
    ensure!(
        reader.limit() > 0,
        "archive framing/expansion limit exceeded"
    );
    let roots: Vec<_> = ["package/package.json", "package.json"]
        .iter()
        .filter(|p| files.contains_key(**p))
        .collect();
    ensure!(
        roots.len() == 1,
        "archive must have one unambiguous root package.json"
    );
    let root_manifest = *roots[0];
    let root_prefix = root_manifest.trim_end_matches("package.json");
    ensure!(
        names.iter().all(|n| root_prefix.is_empty()
            || n == root_prefix.trim_end_matches('/')
            || n.starts_with(root_prefix)),
        "entries outside npm package root"
    );
    let mut manifests = vec![];
    for (name, data) in &files {
        if name.ends_with("/package.json") || name == "package.json" {
            let manifest: Value = json::decode(data).context("invalid package manifest")?;
            if name == root_manifest {
                ensure!(
                    manifest["name"].as_str() == Some(&report.identity.name)
                        && manifest["version"].as_str() == Some(&report.identity.version),
                    "archive package identity mismatch"
                );
            } else if name.contains("/node_modules/") {
                let mut id = Identity {
                    ecosystem: "npm".into(),
                    name: manifest["name"].as_str().unwrap_or_default().into(),
                    version: manifest["version"].as_str().unwrap_or_default().into(),
                    registry: report.identity.registry.clone(),
                    ..Default::default()
                };
                if id.normalize().is_ok() {
                    report.bundled.push(Bundled {
                        path: name.trim_end_matches("/package.json").into(),
                        identity: id,
                    });
                } else {
                    report.gaps.push(format!("invalid_bundled_identity:{name}"));
                }
            }
            manifests.push((name, manifest));
        }
    }
    for (name, manifest) in manifests {
        inspect_manifest(name, &manifest, &files, &names, report)?;
    }
    for (name, data) in &files {
        if script_kind(name, data) == Some(true) {
            report.source_files += 1;
            match std::str::from_utf8(data) {
                Ok(text) => analysis::scan(name, text, 0, report),
                Err(_) => report.gaps.push(format!("source_is_not_utf8:{name}")),
            }
        }
    }
    Ok(())
}
fn inspect_manifest(
    name: &str,
    manifest: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    names: &BTreeSet<String>,
    report: &mut Report,
) -> Result<()> {
    let prefix = name.trim_end_matches("package.json");
    if let Some(exports) = manifest.get("exports") {
        inspect_exports(exports, prefix, names, 0, report);
    }
    let mut entrypoints = vec![];
    for key in ["main", "module"] {
        if let Some(v) = manifest[key].as_str() {
            entrypoints.push(v.to_owned());
        }
    }
    if let Some(bin) = manifest.get("bin") {
        if let Some(s) = bin.as_str() {
            entrypoints.push(s.into());
        } else if let Some(map) = bin.as_object() {
            for value in map.values() {
                if let Some(s) = value.as_str() {
                    entrypoints.push(s.into());
                }
            }
        }
    }
    for target in entrypoints {
        let target = target.strip_prefix("./").unwrap_or(&target);
        if !safe_name(target) {
            report
                .gaps
                .push(format!("unsafe_executable_entrypoint:{name}"));
            continue;
        }
        let path = format!("{prefix}{target}");
        if ![
            path.clone(),
            format!("{path}.js"),
            format!("{path}/index.js"),
        ]
        .iter()
        .any(|p| names.contains(p))
        {
            report
                .gaps
                .push(format!("missing_executable_entrypoint:{name}"));
        } else if !files
            .keys()
            .any(|p| p == &path || p == &format!("{path}.js") || p == &format!("{path}/index.js"))
        {
            report
                .gaps
                .push(format!("unsupported_executable_entrypoint:{name}"));
        }
    }
    let scripts = manifest.get("scripts").and_then(Value::as_object);
    for hook in ["preinstall", "install", "postinstall", "prepare"] {
        let Some(script) = scripts
            .and_then(|s| s.get(hook))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let original = files.get(name).context("manifest bytes missing")?;
        let label = format!("\"{hook}\"");
        let line = original
            .windows(label.len())
            .position(|w| w == label.as_bytes())
            .map_or(1, |p| {
                original[..p].iter().filter(|b| **b == b'\n').count() + 1
            });
        report.findings.push(Finding {
            rule_id: "ZOLI-LOCAL-101".into(),
            rule_version: "1.0.0".into(),
            severity: "informational".into(),
            confidence: "high".into(),
            file: name.into(),
            line,
            explanation: format!("Lifecycle hook present: {hook}; a hook alone is not malware"),
            observations: vec![],
        });
        let Some(tokens) = shlex::split(script) else {
            report
                .gaps
                .push(format!("unsupported_lifecycle_syntax:{name}:{hook}"));
            continue;
        };
        if shell_meta(script) || tokens.first().is_none_or(|s| s != "node" && s != "nodejs") {
            report
                .gaps
                .push(format!("unsupported_lifecycle_command:{name}:{hook}"));
            continue;
        }
        if let Some(i) = tokens.iter().position(|s| s == "-e" || s == "--eval") {
            if let Some(code) = tokens.get(i + 1) {
                report.source_files += 1;
                let first = report.findings.len();
                analysis::scan(name, code, line.saturating_sub(1), report);
                for finding in &mut report.findings[first..] {
                    finding.observations.push(format!(
                        "inline lifecycle source line {}",
                        finding.line.saturating_sub(line) + 1
                    ));
                    finding.line = line;
                }
            } else {
                report
                    .gaps
                    .push(format!("missing_inline_lifecycle_source:{name}:{hook}"));
            }
        } else if let Some(target) = tokens.iter().skip(1).find(|t| !t.starts_with('-')) {
            let target = target.strip_prefix("./").unwrap_or(target);
            if !safe_name(target) || !files.contains_key(&format!("{prefix}{target}")) {
                report
                    .gaps
                    .push(format!("unresolved_lifecycle_entrypoint:{name}:{hook}"));
            }
        } else {
            report
                .gaps
                .push(format!("unsupported_lifecycle_command:{name}:{hook}"));
        }
    }
    if names.contains(&format!("{prefix}binding.gyp"))
        && scripts.is_none_or(|s| !s.contains_key("install") && !s.contains_key("preinstall"))
    {
        report.gaps.push(format!("implicit_native_build:{name}"));
    }
    Ok(())
}
fn inspect_exports(
    value: &Value,
    prefix: &str,
    names: &BTreeSet<String>,
    depth: usize,
    report: &mut Report,
) {
    if depth > 32 {
        report.gaps.push("export_target_depth_exceeded".into());
        return;
    }
    match value {
        Value::String(target) => {
            let Some(target) = target.strip_prefix("./").filter(|s| safe_name(s)) else {
                report.gaps.push("unsafe_export_target".into());
                return;
            };
            let path = format!("{prefix}{target}");
            let exists = if target.matches('*').count() == 1 {
                let (before, after) = path.split_once('*').unwrap_or_default();
                names.iter().any(|n| {
                    n.starts_with(before)
                        && n.ends_with(after)
                        && n.len() >= before.len() + after.len()
                })
            } else if target.contains('*') {
                report.gaps.push("unsupported_export_pattern".into());
                return;
            } else {
                names.contains(&path)
            };
            if !exists {
                report.gaps.push("missing_export_target".into());
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                inspect_exports(child, prefix, names, depth + 1, report);
            }
        }
        Value::Array(list) => {
            for child in list {
                inspect_exports(child, prefix, names, depth + 1, report);
            }
        }
        Value::Null => {}
        _ => report.gaps.push("invalid_export_target".into()),
    }
}
fn shell_meta(script: &str) -> bool {
    let mut quote = '\0';
    let mut escaped = false;
    for c in script.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' && quote != '\'' {
            escaped = true;
            continue;
        }
        if quote != '\0' {
            if c == quote {
                quote = '\0';
            } else if quote == '"' && (c == '$' || c == '`') {
                return true;
            }
            continue;
        }
        if c == '\'' || c == '"' {
            quote = c;
        } else if "|&;<>$`\n\r".contains(c) {
            return true;
        }
    }
    false
}
