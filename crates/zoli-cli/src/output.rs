use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::Value;
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub fn emit(value: &impl Serialize, json: bool, home: &Path) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    audit(home, &bytes)?;
    let mut output = std::io::stdout().lock();
    if json {
        output.write_all(&bytes)?;
        output.write_all(b"\n")?;
    } else {
        let parsed: Value = serde_json::from_slice(&bytes)?;
        output.write_all(human(&parsed).as_bytes())?;
    }
    output.flush()?;
    Ok(())
}
pub(crate) fn guard_report(value: &impl Serialize, home: &Path) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    audit(home, &bytes)?;
    let parsed: Value = serde_json::from_slice(&bytes)?;
    let mut output = std::io::stderr().lock();
    output.write_all(human(&parsed).as_bytes())?;
    output.flush()?;
    Ok(())
}
pub(crate) fn audit(home: &Path, bytes: &[u8]) -> Result<()> {
    let directory = home.join("log");
    zoli_intel::feed::private_dir(&directory)?;
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(directory.join("audit.jsonl"))
        .context("cannot open audit log; assessment not released")?;
    file.lock()?;
    if file.metadata()?.len() > 0 {
        file.seek(SeekFrom::End(-1))?;
        let mut last = [0];
        file.read_exact(&mut last)?;
        ensure!(
            last[0] == b'\n',
            "audit log has an incomplete record; explicit recovery required"
        );
    }
    file.write_all(bytes)?;
    file.write_all(b"\n")?;
    file.sync_data()?;
    Ok(())
}
fn human(value: &Value) -> String {
    let scope = value["scope"].as_str().unwrap_or("operation");
    let mut out = format!("Zoli {scope}\n");
    if let Some(action) = value["decision"]["action"].as_str() {
        out.push_str(&format!(
            "Decision: {action}; complete: {}\n",
            value["decision"]["complete"]
        ));
    }
    if let Some(identity) = value.get("identity") {
        out.push_str(&format!(
            "Package: {}@{} ({})\n",
            identity["name"].as_str().unwrap_or_default(),
            identity["version"].as_str().unwrap_or_default(),
            identity["registry"].as_str().unwrap_or_default()
        ));
    }
    if let Some(v) = value.get("feed_verdict").filter(|v| !v.is_null()) {
        feed(v, &mut out);
    }
    if let Some(sequence) = value.get("sequence") {
        out.push_str(&format!(
            "Publication: {sequence}; records: {}; freshness: {}\n",
            value["record_count"],
            value["freshness"].as_str().unwrap_or_default()
        ));
    }
    for reason in value["decision"]["reasons"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(reason) = reason.as_str() {
            out.push_str(&format!("  {reason}\n"));
        }
    }
    if let Some(report) = value.get("local_analysis").filter(|v| !v.is_null()) {
        local(report, &mut out);
    }
    if let Some(inventory) = value.get("inventory") {
        out.push_str(&format!(
            "Dependencies: {} recorded packages\n",
            inventory["packages"].as_array().map_or(0, Vec::len)
        ));
        for gap in inventory["gaps"].as_array().into_iter().flatten() {
            out.push_str(&format!(
                "  Inventory gap: {} ({})\n",
                gap["reason"].as_str().unwrap_or_default(),
                gap["path"].as_str().unwrap_or_default()
            ));
        }
    }
    for package in value["packages"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "\n{}: {}@{} — {}\n",
            package["package"]["path"].as_str().unwrap_or_default(),
            package["package"]["identity"]["name"]
                .as_str()
                .unwrap_or_default(),
            package["package"]["identity"]["version"]
                .as_str()
                .unwrap_or_default(),
            package["decision"]["action"]
                .as_str()
                .unwrap_or("incomplete")
        ));
        if let Some(chain) = package["package"]["introduced_by"]
            .as_array()
            .filter(|p| !p.is_empty())
        {
            let path = chain
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" -> ");
            out.push_str(&format!("  Dependency path: root -> {path}\n"));
        }
        if let Some(verdict) = package.get("feed_verdict").filter(|v| !v.is_null()) {
            feed(verdict, &mut out);
        }
        if let Some(container) = package["analysis_container"].as_str() {
            out.push_str(&format!("  Inspected in archive for: {container}\n"));
        }
        if let Some(report) = package.get("local_analysis").filter(|v| !v.is_null()) {
            local(report, &mut out);
        }
        if let Some(error) = package["error"].as_str() {
            out.push_str(&format!("  Acquisition/inspection error: {error}\n"));
        }
    }
    out.push_str("Assessment is limited to the stated scope; no known match or static findings is not proof of safety.\n");
    out
}
fn feed(verdict: &Value, out: &mut String) {
    out.push_str(&format!(
        "Feed: {}; freshness: {}; publication: {}\n",
        verdict["status"].as_str().unwrap_or_default(),
        verdict["freshness"].as_str().unwrap_or_default(),
        verdict["sequence"]
    ));
    for matched in verdict["matches"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "  Feed match: {} [{}; certainty={}]\n",
            matched["record"]["id"]
                .as_str()
                .unwrap_or_default()
                .escape_default(),
            matched["record"]["classification"]
                .as_str()
                .unwrap_or_default(),
            matched["certainty"].as_str().unwrap_or_default()
        ));
    }
}
fn local(report: &Value, out: &mut String) {
    out.push_str(&format!(
        "Local inspection: complete={}; sources={}; archive={}\n",
        report["complete"],
        report["source_files"],
        report["artifact_sha256"].as_str().unwrap_or_default()
    ));
    for finding in report["findings"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "  {} [{}]: {}:{} — {}\n",
            finding["rule_id"].as_str().unwrap_or_default(),
            finding["severity"].as_str().unwrap_or_default(),
            finding["file"].as_str().unwrap_or_default(),
            finding["line"],
            finding["explanation"].as_str().unwrap_or_default()
        ));
    }
    for gap in report["gaps"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "  Coverage gap: {}\n",
            gap.as_str().unwrap_or_default()
        ));
    }
}
