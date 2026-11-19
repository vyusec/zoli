//! PyPI outcomes through signed cache, policy, CLI output and durable audit.
#![allow(clippy::unwrap_used)]
mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
use support::*;
use zoli_intel::{
    feed::{Snapshot, Store},
    model::*,
    net::Fetch,
};

fn report(constraint: &str) -> Record {
    let mut r = record("malicious", "https://pypi.org");
    let a = &mut r.affected.as_mut().unwrap()[0];
    a.package.ecosystem = "PyPI".into();
    a.package.name = "some-package".into();
    a.versions = None;
    a.ranges = Some(vec![Range {
        kind: "constraint".into(),
        constraint: constraint.into(),
        ..Default::default()
    }]);
    r
}
fn check(path: &Path, version: &str) -> std::process::Output {
    command(
        path,
        &[
            "check",
            "--eco",
            "pip",
            "--name",
            "Some_Package",
            "--ver",
            version,
            "--json",
        ],
    )
}
fn audit(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path.join("log/audit.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}
fn audited(path: &Path, version: &str, code: i32) -> Value {
    let value = result(check(path, version), code);
    assert_eq!(audit(path).last().unwrap(), &value);
    value
}

struct Memory(BTreeMap<String, Vec<u8>>);
impl Fetch for Memory {
    fn get(&self, url: &str, max: usize) -> anyhow::Result<Vec<u8>> {
        let bytes = self
            .0
            .get(url)
            .ok_or_else(|| anyhow::anyhow!("missing response"))?;
        anyhow::ensure!(bytes.len() <= max, "oversize fixture");
        Ok(bytes.clone())
    }
}
fn go_home(name: &str) -> (tempfile::TempDir, Snapshot) {
    let cases: Vec<Value> = serde_json::from_str(include_str!(
        "../../../testdata/conformance/feed-cases.json"
    ))
    .unwrap();
    let case = cases.iter().find(|c| c["name"] == name).unwrap();
    let key: [u8; 32] = STANDARD
        .decode(case["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let responses = case["responses"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(url, bytes)| (url.clone(), hex::decode(bytes.as_str().unwrap()).unwrap()))
        .collect();
    let h = tempfile::tempdir().unwrap();
    let snapshot = Store::new(h.path().into())
        .update(&Memory(responses), FEED, &key)
        .unwrap();
    let config = json!({"config_version":1,"feed":{"url":FEED,"public_key":case["public_key"]}});
    std::fs::write(
        h.path().join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    (h, snapshot)
}

#[test]
fn go_signed_pypi_range_reaches_cli_with_exact_provenance_and_audit() {
    let (h, snapshot) = go_home("pypi-range");
    let output = audited(h.path(), "1.2", 10);
    assert_eq!(output["feed_verdict"]["matches"][0]["certainty"], "range");
    assert_eq!(
        output["feed_provenance"]["manifest_sha256"],
        snapshot.envelope.digest()
    );
    assert_eq!(output["feed_provenance"]["sequence"], 2);
    assert_eq!(output["feed_provenance"]["record_count"], 1);
    assert_eq!(output["scope"], "feed_only");
    assert_eq!(output["decision"]["action"], "block");
    // The Go fixture deliberately has a fixed far-future publication time.
    assert_ne!(output["feed_verdict"]["freshness"], "current");
}
#[test]
fn go_signed_mixed_valid_and_invalid_records_preserve_both_findings() {
    let (h, _) = go_home("pypi-mixed");
    let output = audited(h.path(), "1.2", 10);
    let matches = output["feed_verdict"]["matches"].as_array().unwrap();
    assert_eq!(matches.len(), 2);
    assert!(matches.iter().any(|m| m["certainty"] == "range"));
    assert!(matches.iter().any(|m| m["certainty"] == "uncertain"));
}
#[test]
fn go_signed_withdrawal_removes_match_but_future_evidence_still_blocks() {
    let (h, _) = go_home("pypi-withdrawn");
    let output = audited(h.path(), "1.2", 10);
    assert_eq!(output["feed_verdict"]["status"], "insufficient_information");
    assert!(
        output["feed_verdict"]["matches"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
    assert_eq!(output["decision"]["action"], "block");
}
#[test]
fn go_signed_artifact_and_registry_selectors_remain_visible() {
    let (h, _) = go_home("pypi-artifact");
    let output = audited(h.path(), "1.2", 10);
    assert_eq!(
        output["feed_verdict"]["matches"][0]["certainty"],
        "uncertain"
    );
    let (h, _) = go_home("pypi-registry");
    let output = audited(h.path(), "1.2", 10);
    assert_eq!(output["feed_verdict"]["status"], "insufficient_information");
    assert!(
        output["feed_verdict"]["matches"]
            .as_array()
            .is_none_or(Vec::is_empty)
    );
}

#[test]
fn go_signed_snapshots_have_expected_policy_at_their_publication_clock() {
    use zoli_policy::{
        Mode,
        assessment::{Evidence, Suspicious, decide},
    };
    for (name, expected) in [
        ("pypi-range", 10),
        ("pypi-mixed", 10),
        ("pypi-withdrawn", 0),
        ("pypi-artifact", 10),
        ("pypi-registry", 0),
    ] {
        let (_, snapshot) = go_home(name);
        let key: [u8; 32] =
            ed25519_dalek::SigningKey::from_bytes(&std::array::from_fn(|i| i as u8))
                .verifying_key()
                .to_bytes();
        let manifest = snapshot.verify(&key).unwrap();
        let query = Identity {
            ecosystem: "PyPI".into(),
            name: "some-package".into(),
            version: "1.2".into(),
            registry: "https://pypi.org".into(),
            ..Default::default()
        };
        let verdict =
            zoli_intel::query::query(query, &manifest, &snapshot.records, &manifest.generated_at)
                .unwrap();
        let decision = decide(
            Evidence {
                verdict: Some(&verdict),
                manifest: Some(&manifest),
                require_feed: true,
                ..Default::default()
            },
            Mode::Interactive,
            Suspicious::Warn,
            &manifest.generated_at,
        );
        assert_eq!(decision.exit_code, expected, "{name}");
    }
}
#[test]
fn exact_match_does_not_hide_later_affected_entry_resource_failure() {
    let mut r = report("==1");
    let mut exhausted = r.affected.as_ref().unwrap()[0].clone();
    exhausted.ranges.as_mut().unwrap()[0].constraint = vec![">=0"; 129].join(",");
    r.affected.as_mut().unwrap().push(exhausted);
    let h = home(vec![r]);
    let output = audited(h.path(), "1", 1);
    assert!(output["feed_verdict"].is_null());
    assert!(output["error"].as_str().unwrap().contains("limit exceeded"));
}
#[test]
fn withdrawn_and_unrelated_records_do_not_consume_matching_budgets() {
    let mut withdrawn = report(&vec![">=0"; 129].join(","));
    withdrawn.status = "withdrawn".into();
    let mut unrelated = report(&vec![">=0"; 129].join(","));
    unrelated.id = "ZOLI-000000000000000000000002".into();
    unrelated.affected.as_mut().unwrap()[0].package.name = "other".into();
    let h = home(vec![withdrawn, unrelated]);
    assert_eq!(
        audited(h.path(), "1", 0)["feed_verdict"]["status"],
        "no_known_match"
    );
}
#[test]
fn tampered_signed_cache_never_releases_a_verdict() {
    let h = home(vec![report(">=1,<2")]);
    let path = h.path().join("cache/feed.json");
    let mut cache: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    cache["records"][0]["classification"] = json!("suspicious");
    std::fs::write(path, serde_json::to_vec(&cache).unwrap()).unwrap();
    let output = audited(h.path(), "1.2", 1);
    assert!(output["feed_verdict"].is_null());
}
#[test]
fn missing_and_future_sources_block_a_clean_query() {
    for mode in ["missing", "empty", "no-success", "future", "error"] {
        let h = home(vec![]);
        publish_adjusted(h.path(), vec![], 0, None, 2, |m| match mode {
            "missing" => m.sources = None,
            "empty" => m.sources = Some(vec![]),
            "no-success" => m.sources.as_mut().unwrap()[0].last_success = None,
            "future" => {
                m.sources.as_mut().unwrap()[0].last_success =
                    Some(GoTime::parse("9998-01-01T00:00:00Z").unwrap())
            }
            _ => m.sources.as_mut().unwrap()[0].error = "upstream unavailable".into(),
        });
        let output = audited(h.path(), "1.2", 10);
        assert_eq!(output["decision"]["action"], "block", "{mode}");
    }
}
#[test]
fn missing_pypi_coverage_never_inherits_npm_coverage() {
    let h = home(vec![]);
    publish_adjusted(h.path(), vec![], 0, None, 2, |m| {
        m.coverage
            .as_mut()
            .unwrap()
            .retain(|c| c.ecosystem == "npm");
    });
    assert_eq!(audited(h.path(), "1", 10)["decision"]["action"], "block");
}
#[test]
fn truncated_audit_refuses_success_and_is_not_overwritten() {
    let h = home(vec![]);
    std::fs::create_dir(h.path().join("log")).unwrap();
    let path = h.path().join("log/audit.jsonl");
    std::fs::write(&path, b"{\"unfinished\":").unwrap();
    let output = result(check(h.path(), "1"), 1);
    assert!(output["feed_verdict"].is_null());
    assert_eq!(output["audit_error"], "runtime_error_audit_unavailable");
    assert_eq!(std::fs::read(path).unwrap(), b"{\"unfinished\":");
}
#[test]
fn audit_parent_failure_cannot_emit_an_unaudited_clean_report() {
    let h = home(vec![]);
    std::fs::write(h.path().join("log"), "occupied").unwrap();
    let output = result(check(h.path(), "1"), 1);
    assert!(output["feed_verdict"].is_null());
    assert_eq!(output["audit_error"], "runtime_error_audit_unavailable");
}

#[cfg(target_os = "linux")]
#[test]
fn audit_write_failure_refuses_success_without_filling_the_disk() {
    let h = home(vec![]);
    std::fs::create_dir(h.path().join("log")).unwrap();
    // /dev/full fails writes with ENOSPC. This exercises write_all, not merely
    // path creation, without consuming disk or touching an existing user log.
    std::os::unix::fs::symlink("/dev/full", h.path().join("log/audit.jsonl")).unwrap();
    let output = result(check(h.path(), "1"), 1);
    assert!(output["feed_verdict"].is_null());
    assert_eq!(output["audit_error"], "runtime_error_audit_unavailable");
}
#[test]
fn concurrent_checks_and_publications_keep_reports_and_audits_consistent() {
    let h = home(vec![report(">=1,<2")]);
    // Deliberately small contention test; the enclosing test process still has
    // one worker and the entire subprocess tree shares the local CPU quota.
    let outputs = std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            for sequence in 2..=4 {
                publish_with_sequence(h.path(), vec![report(">=1,<2")], 0, None, sequence);
            }
        });
        let reader = scope.spawn(|| {
            (0..4)
                .map(|_| result(check(h.path(), "1.2"), 10))
                .collect::<Vec<_>>()
        });
        let second = (0..4)
            .map(|_| result(check(h.path(), "3"), 0))
            .collect::<Vec<_>>();
        writer.join().unwrap();
        [reader.join().unwrap(), second].concat()
    });
    let log = audit(h.path());
    assert_eq!(log.len(), outputs.len());
    let mut expected: Vec<_> = outputs
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    let mut actual: Vec<_> = log
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    expected.sort();
    actual.sort();
    assert_eq!(actual, expected);
    for output in &outputs {
        let sequence = output["feed_provenance"]["sequence"].as_i64().unwrap();
        assert!((1..=4).contains(&sequence));
        assert_eq!(output["feed_verdict"]["sequence"], sequence);
        assert_eq!(output["feed_provenance"]["record_count"], 1);
    }
    assert_eq!(audited(h.path(), "3", 0)["feed_provenance"]["sequence"], 4);
}
