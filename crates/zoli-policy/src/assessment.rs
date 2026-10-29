//! Conservative assessment decisions; feed verdicts are borrowed and unchanged.
use crate::{Action, Mode};
use serde::{Deserialize, Serialize};
use zoli_inspect::Report;
use zoli_intel::model::{GoTime, Manifest, QueryResponse};

/// Explicit user preference for unconfirmed suspicious findings.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Suspicious {
    /// Warn in interactive use; CI still blocks.
    #[default]
    Warn,
    /// Block in all modes.
    Block,
}
/// Policy output, independent of the immutable feed response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Decision {
    /// Allow, warn or block. Incomplete required work always refuses permission.
    pub action: Action,
    /// Required work and intelligence were available for this scope.
    pub complete: bool,
    /// Process-level assessment outcome.
    pub exit_code: u8,
    /// Stable explanations for the selected action.
    pub reasons: Vec<String>,
}
/// Assess a feed response and optional local inspection under the locked Phase 1
/// defaults. The caller supplies the final clock, after expensive inspection.
#[derive(Default)]
pub struct Evidence<'a> {
    /// Unmodified feed query result.
    pub verdict: Option<&'a QueryResponse>,
    /// Verified publication metadata.
    pub manifest: Option<&'a Manifest>,
    /// Optional bounded local report.
    pub local: Option<&'a Report>,
    /// This scope requires verified intelligence.
    pub require_feed: bool,
    /// This scope requires artifact inspection.
    pub require_local: bool,
    /// Inventory or required artifact coverage is incomplete.
    pub gaps: bool,
}
/// Decide from evidence without rewriting any feed response or local finding.
pub fn decide(
    evidence: Evidence<'_>,
    mode: Mode,
    suspicious: Suspicious,
    now: &GoTime,
) -> Decision {
    let Evidence {
        verdict,
        manifest,
        local,
        require_feed,
        require_local,
        gaps,
    } = evidence;
    let mut reasons = vec![];
    let mut blocked = false;
    let mut warning = false;
    let mut complete = !gaps;
    if gaps {
        reasons.push("dependency_inventory_incomplete".into());
    }
    if require_feed {
        match (verdict, manifest) {
            (Some(v), Some(m)) => {
                let sources: Vec<_> = m.sources.iter().flatten().collect();
                let missing =
                    sources.is_empty() || sources.iter().any(|s| s.last_success.is_none());
                let old = m.generated_at.age(now) > time::Duration::hours(1)
                    || sources.iter().any(|s| {
                        s.last_success
                            .as_ref()
                            .is_some_and(|t| t.age(now) > time::Duration::hours(1))
                    });
                let degraded =
                    v.freshness == "degraded" || sources.iter().any(|s| !s.error.is_empty());
                let future = m.generated_at.age(now) < -time::Duration::minutes(5)
                    || sources.iter().any(|s| {
                        s.last_success
                            .as_ref()
                            .is_some_and(|t| t.age(now) < -time::Duration::minutes(5))
                    });
                if missing || old || future || degraded || v.freshness != "current" {
                    blocked = true;
                    complete = false;
                    reasons.push(
                        if missing {
                            "feed_freshness_evidence_missing"
                        } else if old {
                            "feed_older_than_one_hour"
                        } else if future {
                            "feed_clock_skew_exceeds_five_minutes"
                        } else {
                            "feed_degraded"
                        }
                        .into(),
                    );
                }
                if !["npm", "PyPI"].contains(&v.coverage.ecosystem.as_str())
                    || !["reports_only", "reports_and_selective_analysis"]
                        .contains(&v.coverage.mode.as_str())
                {
                    blocked = true;
                    complete = false;
                    reasons.push("feed_coverage_missing".into());
                }
                if !["known_match", "no_known_match", "insufficient_information"]
                    .contains(&v.status.as_str())
                {
                    blocked = true;
                    complete = false;
                    reasons.push("feed_status_unknown".into());
                }
                for m in v.matches.iter().flatten() {
                    if m.record.classification == "malicious" {
                        blocked = true;
                        reasons.push("malicious_feed_match_including_uncertain".into());
                    } else if m.record.classification == "suspicious" {
                        warning = true;
                        reasons.push("suspicious_feed_match".into());
                    } else {
                        complete = false;
                        reasons.push("unknown_feed_classification".into());
                    }
                }
                if v.status == "insufficient_information"
                    && v.matches.as_ref().is_none_or(Vec::is_empty)
                {
                    complete = false;
                    reasons.push("feed_information_insufficient".into());
                }
            }
            _ => {
                blocked = true;
                complete = false;
                reasons.push("no_verified_feed".into());
            }
        }
    }
    if let Some(local) = local {
        if !local.complete {
            complete = false;
            reasons.push("local_inspection_incomplete".into());
        }
        if local.findings.iter().any(|f| f.severity != "informational") {
            warning = true;
            reasons.push("suspicious_local_finding".into());
        }
    } else if require_local {
        complete = false;
        reasons.push("local_inspection_not_performed".into());
    }
    if warning && (mode == Mode::Ci || matches!(suspicious, Suspicious::Block)) {
        blocked = true;
        reasons.push("suspicious_findings_blocked_by_policy".into());
    }
    reasons.sort();
    reasons.dedup();
    if blocked {
        Decision {
            action: Action::Block,
            complete,
            exit_code: 10,
            reasons,
        }
    } else if !complete {
        Decision {
            action: Action::Block,
            complete: false,
            exit_code: 12,
            reasons,
        }
    } else if warning {
        Decision {
            action: Action::Warn,
            complete: true,
            exit_code: 0,
            reasons,
        }
    } else {
        reasons.push("no_actionable_findings_within_declared_scope".into());
        Decision {
            action: Action::Allow,
            complete: true,
            exit_code: 0,
            reasons,
        }
    }
}
