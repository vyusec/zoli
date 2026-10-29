//! Phase 3 feed-only PyPI checks; no Python process or package code executes.
#![allow(clippy::unwrap_used)]
mod support;
use support::*;
use zoli_intel::model::{Event, Range, Record};

fn report() -> Record {
    let mut r = record("malicious", "https://pypi.org");
    let a = &mut r.affected.as_mut().unwrap()[0];
    a.package.ecosystem = "PyPI".into();
    a.package.name = "some-package".into();
    a.versions = Some(vec!["1.0".into()]);
    r.validate().unwrap();
    r
}
fn check(home: &std::path::Path, version: &str, extra: &[&str]) -> std::process::Output {
    let mut args = vec![
        "check",
        "--eco",
        "pip",
        "--name",
        "Some_Package",
        "--ver",
        version,
        "--json",
    ];
    args.extend_from_slice(extra);
    command(home, &args)
}

#[test]
fn pypi_normalization_event_ranges_and_withdrawal_use_existing_policy() {
    let mut r = report();
    let a = &mut r.affected.as_mut().unwrap()[0];
    a.versions = None;
    a.ranges = Some(vec![Range {
        kind: "ECOSYSTEM".into(),
        events: Some(vec![
            Event {
                introduced: "1.0rc1".into(),
                ..Default::default()
            },
            Event {
                fixed: "1.0".into(),
                ..Default::default()
            },
        ]),
        ..Default::default()
    }]);
    let h = home(vec![r.clone()]);
    let v = result(check(h.path(), "1.0preview2", &[]), 10);
    assert_eq!(v["identity"]["name"], "some-package");
    assert_eq!(v["identity"]["ecosystem"], "PyPI");
    assert_eq!(v["feed_verdict"]["matches"][0]["certainty"], "range");
    assert_eq!(
        result(check(h.path(), "1.0.0", &[]), 0)["scope"],
        "feed_only"
    );
    r.status = "withdrawn".into();
    publish_with_sequence(h.path(), vec![r], 0, None, 2);
    assert_eq!(
        result(check(h.path(), "1.0rc2", &[]), 0)["feed_verdict"]["status"],
        "no_known_match"
    );
}

#[test]
fn relisted_artifact_hashes_do_not_erase_package_wide_findings() {
    let old = "a".repeat(64);
    let new = "b".repeat(64);
    let mut r = report();
    r.affected.as_mut().unwrap()[0].package.sha256 = old.clone();
    let h = home(vec![r]);
    let missing = result(check(h.path(), "1.0.0", &[]), 10);
    assert_eq!(
        missing["feed_verdict"]["matches"][0]["certainty"],
        "uncertain"
    );
    result(check(h.path(), "1.0", &["--sha256", &old]), 10);
    let other = result(check(h.path(), "1.0", &["--sha256", &new]), 0);
    assert_eq!(other["feed_verdict"]["status"], "no_known_match");
    assert!(
        other["limitations"][0]
            .as_str()
            .unwrap()
            .contains("cannot grant installation approval")
    );
    publish_with_sequence(h.path(), vec![report()], 0, None, 2);
    result(check(h.path(), "1.0", &["--sha256", &new]), 10);
    result(check(h.path(), "1.0", &["--sha256", "bad"]), 2);
}

#[test]
fn unsupported_python_work_and_stale_evidence_never_release_success() {
    let mut r = report();
    r.affected.as_mut().unwrap()[0].ranges = Some(vec![Range {
        kind: "constraint".into(),
        constraint: ">=1.0".into(),
        ..Default::default()
    }]);
    let h = home(vec![r]);
    let v = result(check(h.path(), "1.0", &[]), 1);
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("constraint-string matching")
    );
    let mut invalid = report();
    invalid.affected.as_mut().unwrap()[0].ranges = Some(vec![Range {
        kind: "ECOSYSTEM".into(),
        events: Some(vec![Event {
            introduced: "not-a-version".into(),
            ..Default::default()
        }]),
        ..Default::default()
    }]);
    publish_with_sequence(h.path(), vec![invalid], 0, None, 2);
    assert!(
        result(check(h.path(), "1.0", &[]), 1)["error"]
            .as_str()
            .unwrap()
            .contains("event boundary")
    );
    publish_with_sequence(h.path(), vec![], 3601, None, 3);
    result(check(h.path(), "2.0", &[]), 10);
    result(check(h.path(), "1.*", &[]), 2);
    result(
        command(
            h.path(),
            &[
                "inspect",
                "not-a-wheel.whl",
                "--eco",
                "PyPI",
                "--name",
                "fixture",
                "--ver",
                "1",
                "--json",
            ],
        ),
        2,
    );
    assert!(!h.path().join("node_modules").exists());
}
