//! Go-compatible affected matching and query responses, with an injected clock.
use crate::{model::*, npm, pypi};
use anyhow::{Result, bail, ensure};
use std::cmp::Ordering;

fn compare(ecosystem: &str, a: &str, b: &str) -> Result<Ordering> {
    match ecosystem {
        "npm" => npm::compare(a, b),
        "PyPI" => pypi::compare(a, b),
        _ => bail!("unsupported version comparison"),
    }
}
fn match_range(q: &Identity, range: &Range) -> Result<bool> {
    ensure!(
        ["npm", "PyPI"].contains(&q.ecosystem.as_str()),
        "unsupported version comparison"
    );
    ensure!(
        if q.ecosystem == "npm" {
            npm::concrete(&q.version)
        } else {
            pypi::concrete(&q.version)
        },
        "invalid query version"
    );
    if range.kind == "constraint" {
        ensure!(
            q.ecosystem == "npm",
            "PyPI constraint-string matching is not implemented"
        );
        return npm::matches(&range.constraint, &q.version)
            .map_err(|_| anyhow::anyhow!("unsupported version constraint: {}", range.constraint));
    }
    ensure!(
        ["ECOSYSTEM", "SEMVER"].contains(&range.kind.as_str()),
        "unsupported range type: {}",
        range.kind
    );
    let events = range.events.as_deref().unwrap_or_default();
    ensure!(!events.is_empty(), "empty range events");
    let (mut active, mut matched, mut open) = (false, false, false);
    for e in events {
        ensure!(
            [&e.introduced, &e.fixed, &e.last_affected, &e.limit]
                .iter()
                .filter(|s| !s.is_empty())
                .count()
                == 1,
            "invalid range event"
        );
        if !e.introduced.is_empty() {
            ensure!(!open, "nested introduced event");
            open = true;
            active = e.introduced == "0"
                || compare(&q.ecosystem, &q.version, &e.introduced)? != Ordering::Less;
            continue;
        }
        ensure!(open, "range end without introduced event");
        let (end, inclusive) = if !e.fixed.is_empty() {
            (&e.fixed, false)
        } else if !e.limit.is_empty() {
            (&e.limit, false)
        } else {
            (&e.last_affected, true)
        };
        let c = compare(&q.ecosystem, &q.version, end)?;
        if active && (c == Ordering::Less || (inclusive && c == Ordering::Equal)) {
            matched = true;
        }
        active = false;
        open = false;
    }
    Ok(matched || active)
}
/// Match one affected entry; missing selectors always preserve uncertainty.
pub fn match_affected(q: &Identity, a: &Affected) -> (String, Vec<String>) {
    let p = &a.package;
    if q.ecosystem != p.ecosystem || q.name != p.name {
        return ("none".into(), vec![]);
    }
    let mut reasons = vec![];
    for (label, p, q) in [
        ("registry", &p.registry, &q.registry),
        ("sha256", &p.sha256, &q.sha256),
        ("channel", &p.channel, &q.channel),
        ("subdir", &p.subdir, &q.subdir),
        ("build", &p.build, &q.build),
    ] {
        if !p.is_empty() && !q.is_empty() && p != q {
            return ("none".into(), vec![]);
        }
        if !p.is_empty() && q.is_empty() {
            reasons.push(format!("missing {label}"));
        }
    }
    if q.ecosystem == "Conda" && (p.channel.is_empty() || p.subdir.is_empty() || p.build.is_empty())
    {
        reasons.push("report lacks Conda artifact selectors".into());
    }
    if q.version.is_empty() {
        reasons.push("missing version".into());
        return ("uncertain".into(), reasons);
    }
    let mut certainty = if a.scope == "all" { "range" } else { "none" };
    let mut unknown = a.scope == "unknown";
    let mut versions: Vec<_> = a.versions.iter().flatten().map(String::as_str).collect();
    if !p.version.is_empty() {
        versions.push(&p.version);
    }
    for v in &versions {
        if q.version == *v {
            certainty = "exact";
            break;
        }
        match compare(&q.ecosystem, &q.version, v) {
            Ok(Ordering::Equal) => {
                certainty = "exact";
                break;
            }
            Err(_) => unknown = true,
            _ => {}
        }
    }
    for r in a.ranges.iter().flatten() {
        match match_range(q, r) {
            Ok(true) if certainty != "exact" => certainty = "range",
            Err(e) => {
                unknown = true;
                reasons.push(e.to_string());
            }
            _ => {}
        }
    }
    if versions.is_empty() && a.ranges.as_ref().is_none_or(Vec::is_empty) && a.scope != "all" {
        unknown = true;
    }
    if certainty == "none" && unknown {
        certainty = "uncertain";
    }
    if certainty != "none" && !reasons.is_empty() {
        certainty = "uncertain";
    }
    (certainty.into(), reasons)
}
/// Produce the Go query response for the same normalized records and clock.
/// PyPI currently supports exact identities and OSV event ranges only.
pub fn query(
    mut q: Identity,
    manifest: &Manifest,
    records: &[Record],
    now: &GoTime,
) -> Result<QueryResponse> {
    q.normalize()?;
    if !["npm", "PyPI"].contains(&q.ecosystem.as_str()) {
        bail!("only npm and PyPI feed assessment are implemented");
    }
    let mut out = QueryResponse {
        status: "no_known_match".into(),
        matches: Some(vec![]),
        sequence: manifest.sequence,
        generated_at: manifest.generated_at.clone(),
        freshness: "current".into(),
        ..Default::default()
    };
    for c in manifest.coverage.iter().flatten() {
        if c.ecosystem == q.ecosystem {
            out.coverage = c.clone();
        }
    }
    if manifest.generated_at.age(now) > time::Duration::hours(1) {
        out.freshness = "stale".into();
    }
    if manifest.generated_at.age(now) < -time::Duration::minutes(5)
        || manifest.sources.as_ref().is_none_or(Vec::is_empty)
    {
        out.freshness = "degraded".into();
    }
    for s in manifest.sources.iter().flatten() {
        if !s.error.is_empty()
            || s.last_success.as_ref().is_none_or(|t| {
                t.age(now) > time::Duration::hours(1) || t.age(now) < -time::Duration::minutes(5)
            })
        {
            out.freshness = "degraded".into();
        }
    }
    let mut matches = vec![];
    for record in records {
        if record.status != "published" || record.withdrawn_at.is_some() {
            continue;
        }
        // Do not turn a supported Go constraint into a different Rust verdict.
        // Until parity is implemented, refuse this query before emitting one.
        ensure!(
            q.ecosystem != "PyPI"
                || !record
                    .affected
                    .iter()
                    .flatten()
                    .any(|a| a.package.ecosystem == q.ecosystem
                        && a.package.name == q.name
                        && a.ranges.iter().flatten().any(|r| r.kind == "constraint")),
            "PyPI constraint-string matching is not implemented; required query refused"
        );
        ensure!(
            q.ecosystem != "PyPI"
                || !record.affected.iter().flatten().any(|a| {
                    a.package.ecosystem == q.ecosystem
                        && a.package.name == q.name
                        && a.ranges
                            .iter()
                            .flatten()
                            .flat_map(|r| r.events.iter().flatten())
                            .flat_map(|e| [&e.introduced, &e.fixed, &e.last_affected, &e.limit])
                            .any(|v| !v.is_empty() && !pypi::concrete(v))
                }),
            "unsupported PyPI event boundary; required query refused"
        );
        let mut best = "none".to_owned();
        let mut reasons = vec![];
        for a in record.affected.iter().flatten() {
            let (certainty, why) = match_affected(&q, a);
            if certainty == "exact" {
                best = certainty;
                reasons.clear();
                break;
            }
            if certainty == "range" {
                best = certainty;
                reasons.clear();
            } else if certainty == "uncertain" && best == "none" {
                best = certainty;
                reasons = why;
            }
        }
        if best != "none" {
            if best == "exact" || best == "range" {
                out.status = "known_match".into();
            } else if out.status != "known_match" {
                out.status = "insufficient_information".into();
            }
            matches.push(Match {
                record: record.clone(),
                certainty: best,
                reasons: if reasons.is_empty() {
                    None
                } else {
                    Some(reasons)
                },
            });
        }
    }
    out.matches = Some(matches);
    if out.status == "no_known_match" && (q.version.is_empty() || out.freshness != "current") {
        out.status = "insufficient_information".into();
    }
    Ok(out)
}
