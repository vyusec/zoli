//! Decision table and exact clock-boundary tests, independent of Go verdicts.
#![allow(clippy::unwrap_used)]
use zoli_intel::model::*;
use zoli_policy::{
    Action, Mode,
    assessment::{Evidence, Suspicious, decide},
};
fn evidence() -> (GoTime, Manifest, QueryResponse) {
    let now = GoTime::parse("2026-10-18T10:00:00Z").unwrap();
    let coverage = Coverage {
        ecosystem: "npm".into(),
        mode: "reports_and_selective_analysis".into(),
        ..Default::default()
    };
    let manifest = Manifest {
        generated_at: now.clone(),
        coverage: Some(vec![coverage.clone()]),
        sources: Some(vec![SourceState {
            name: "fixture".into(),
            last_success: Some(now.clone()),
            ..Default::default()
        }]),
        ..Default::default()
    };
    let verdict = QueryResponse {
        status: "no_known_match".into(),
        freshness: "current".into(),
        coverage,
        ..Default::default()
    };
    (now, manifest, verdict)
}
fn code(now: &GoTime, m: &Manifest, v: &QueryResponse, mode: Mode) -> u8 {
    decide(
        Evidence {
            verdict: Some(v),
            manifest: Some(m),
            require_feed: true,
            ..Default::default()
        },
        mode,
        Suspicious::Warn,
        now,
    )
    .exit_code
}
#[test]
fn pypi_coverage_requires_a_supported_mode_and_fresh_sources() {
    let (now, mut m, mut v) = evidence();
    v.coverage.ecosystem = "PyPI".into();
    m.coverage = Some(vec![v.coverage.clone()]);
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 0);
    v.coverage.mode.clear();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
    v.coverage.mode = "reports_only".into();
    m.sources.as_mut().unwrap()[0].error = "source unavailable".into();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
    m.sources.as_mut().unwrap()[0].error.clear();
    v.coverage.ecosystem.clear();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
}

#[test]
fn suspicious_warns_interactively_but_ci_and_explicit_policy_block() {
    let (now, m, mut v) = evidence();
    v.matches = Some(vec![Match {
        record: Record {
            classification: "suspicious".into(),
            ..Default::default()
        },
        certainty: "uncertain".into(),
        ..Default::default()
    }]);
    let original = serde_json::to_vec(&v).unwrap();
    let d = decide(
        Evidence {
            verdict: Some(&v),
            manifest: Some(&m),
            require_feed: true,
            ..Default::default()
        },
        Mode::Interactive,
        Suspicious::Warn,
        &now,
    );
    assert_eq!(d.exit_code, 0);
    assert_eq!(d.action, Action::Warn);
    assert_eq!(code(&now, &m, &v, Mode::Ci), 10);
    assert_eq!(
        decide(
            Evidence {
                verdict: Some(&v),
                manifest: Some(&m),
                require_feed: true,
                ..Default::default()
            },
            Mode::Interactive,
            Suspicious::Block,
            &now
        )
        .exit_code,
        10
    );
    assert_eq!(serde_json::to_vec(&v).unwrap(), original);
    v.matches.as_mut().unwrap()[0].record.classification = "malicious".into();
    v.status = "insufficient_information".into();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
}
#[test]
fn one_hour_boundary_applies_to_publication_and_every_source() {
    let (now, mut m, v) = evidence();
    m.generated_at = GoTime::parse("2026-10-18T09:00:00Z").unwrap();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 0);
    m.generated_at = GoTime::parse("2026-10-18T08:59:59.999999999Z").unwrap();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
    m.generated_at = now.clone();
    m.sources.as_mut().unwrap()[0].last_success =
        Some(GoTime::parse("2026-10-18T08:59:59Z").unwrap());
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
    m.sources.as_mut().unwrap()[0].last_success = Some(now.clone());
    m.sources.as_mut().unwrap()[0].error = "upstream unavailable".into();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
    m.sources.as_mut().unwrap()[0].error.clear();
    m.sources.as_mut().unwrap()[0].last_success = None;
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
    m.sources = None;
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
}
#[test]
fn missing_analysis_or_inventory_is_incomplete_and_trust_failure_blocks() {
    let (now, m, mut v) = evidence();
    for e in [
        Evidence {
            require_local: true,
            ..Default::default()
        },
        Evidence {
            gaps: true,
            ..Default::default()
        },
    ] {
        assert_eq!(
            decide(e, Mode::Interactive, Suspicious::Warn, &now).exit_code,
            12
        );
    }
    assert_eq!(
        decide(
            Evidence {
                require_feed: true,
                ..Default::default()
            },
            Mode::Interactive,
            Suspicious::Warn,
            &now
        )
        .exit_code,
        10
    );
    v.status = "insufficient_information".into();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 12);
    v.freshness = "degraded".into();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
    let (now, m, mut v) = evidence();
    v.coverage.mode = "unexpected".into();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
    v.coverage.mode = "reports_only".into();
    v.status = "unexpected".into();
    assert_eq!(code(&now, &m, &v, Mode::Interactive), 10);
}

#[test]
fn final_clock_recheck_rejects_future_publication_and_source_times() {
    let (now, original, v) = evidence();
    for stamp in ["2026-10-18T10:05:00Z", "2026-10-18T10:05:00.000000001Z"] {
        for source in [false, true] {
            let mut m = original.clone();
            if source {
                m.sources.as_mut().unwrap()[0].last_success = Some(GoTime::parse(stamp).unwrap());
            } else {
                m.generated_at = GoTime::parse(stamp).unwrap();
            }
            assert_eq!(
                code(&now, &m, &v, Mode::Interactive),
                if stamp.contains(".000000001") { 10 } else { 0 }
            );
        }
    }
}

#[test]
fn a_healthy_source_never_masks_an_unhealthy_second_source() {
    let (now, original, v) = evidence();
    for state in ["stale", "missing", "future", "error"] {
        let mut m = original.clone();
        let mut source = m.sources.as_ref().unwrap()[0].clone();
        source.name = "second".into();
        match state {
            "stale" => source.last_success = Some(GoTime::parse("2026-10-18T08:59:59Z").unwrap()),
            "future" => {
                source.last_success = Some(GoTime::parse("2026-10-18T10:05:00.000000001Z").unwrap())
            }
            "missing" => source.last_success = None,
            _ => source.error = "unavailable".into(),
        }
        m.sources.as_mut().unwrap().push(source);
        assert_eq!(code(&now, &m, &v, Mode::Interactive), 10, "{state}");
        m.sources.as_mut().unwrap().reverse();
        assert_eq!(code(&now, &m, &v, Mode::Interactive), 10, "{state}");
    }
}

#[test]
fn exact_source_freshness_boundary_is_inclusive_to_the_nanosecond() {
    let (now, mut m, v) = evidence();
    for (stamp, expected) in [
        ("2026-10-18T08:59:59.999999999Z", 10),
        ("2026-10-18T09:00:00Z", 0),
        ("2026-10-18T09:00:00.000000001Z", 0),
    ] {
        m.sources.as_mut().unwrap()[0].last_success = Some(GoTime::parse(stamp).unwrap());
        assert_eq!(code(&now, &m, &v, Mode::Interactive), expected);
    }
}

#[test]
fn malicious_findings_dominate_suspicious_policy_and_record_order() {
    let (now, m, mut v) = evidence();
    v.matches = Some(
        ["suspicious", "malicious"]
            .map(|classification| Match {
                record: Record {
                    classification: classification.into(),
                    ..Default::default()
                },
                certainty: "uncertain".into(),
                ..Default::default()
            })
            .to_vec(),
    );
    for mode in [Mode::Interactive, Mode::Ci] {
        for _ in 0..2 {
            assert_eq!(code(&now, &m, &v, mode), 10);
            v.matches.as_mut().unwrap().reverse();
        }
    }
}
