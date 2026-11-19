// Copyright 2023 Google LLC; Rust adaptation copyright 2026 Zoli contributors.
// SPDX-License-Identifier: Apache-2.0
//! Interval construction/intersection and PyPI filters from deps.dev/util/semver.
//! Keep these separate from parsing concrete versions: a wildcard is a boundary
//! pattern, never a query version. Evaluate filters after intersection, as Go does.
use super::{Version, within_limit};
use anyhow::{Result, bail, ensure};
use std::cmp::Ordering;

const INFINITY: i64 = i64::MAX;
const WILDCARD: i64 = -1;
const MAX_CONSTRAINT_BYTES: usize = 8192;
const MAX_TERMS: usize = 128;

#[derive(Clone, Debug)]
struct Span {
    lo: Version,
    hi: Version,
    lo_open: bool,
    hi_open: bool,
}

impl Version {
    fn tail(&mut self, marker: i64, fill: i64) {
        let size = self.release.len().max(3);
        self.release.resize(size, 0);
        if let Some(i) = self.release.iter().position(|n| *n == marker) {
            self.release[i..].fill(fill);
        }
    }
    fn minimum() -> Self {
        Self {
            release: vec![0; 3],
            dev: Some(0),
            has_extension: true,
            ..Self::default()
        }
    }
    fn plain_boundary(value: i64) -> Self {
        Self {
            release: vec![value; 3],
            ..Self::default()
        }
    }
    fn clear_pre(&mut self) {
        // Go clears the suffix but retains its historical IsPrerelease flag.
        self.pre = None;
    }
    fn rebuild(&mut self) {
        // Go reconstructs boundaries through the canonical version string.
        // Overflowed negative suffixes are rendered with '-', which its parser
        // treats as an optional separator. Preserve that surprising round trip.
        for n in [
            self.pre.as_mut().map(|(_, n)| n),
            self.post.as_mut(),
            self.dev.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            if *n < 0 {
                *n = n.wrapping_neg();
            }
        }
    }
    fn increment(&mut self) {
        // Canonicalization uses Go's numeric successor, retaining suffixes.
        let marker = self
            .release
            .iter()
            .position(|n| [WILDCARD, INFINITY].contains(n));
        match marker {
            Some(0) => (),
            Some(i) => {
                self.release[i - 1] = self.release[i - 1].wrapping_add(1);
                self.release[i..].fill(0);
            }
            None => {
                if let Some(last) = self.release.last_mut() {
                    *last = last.wrapping_add(1);
                }
            }
        }
    }
}

impl Span {
    fn new(mut lo: Version, mut hi: Version, lo_open: bool, hi_open: bool) -> Result<Self> {
        lo.tail(WILDCARD, 0);
        hi.tail(WILDCARD, INFINITY);
        ensure!(lo.cmp(&hi) != Ordering::Greater, "inverted PyPI interval");
        // Go's unit span stores the lower endpoint in BOTH slots. Equality
        // with its plain != sentinel ignores epochs and suffixes, so retaining
        // the original upper endpoint changes later intersections.
        if lo.cmp(&hi) == Ordering::Equal {
            hi = lo.clone();
        }
        Ok(Self {
            lo,
            hi,
            lo_open,
            hi_open,
        })
    }
    fn contains(&self, query: &Version) -> bool {
        if self.lo.cmp(&self.hi) == Ordering::Equal {
            // The reference treats coincident endpoints as a point, including
            // open endpoints. This observable quirk is covered by the oracle.
            return self.lo.cmp(query) == Ordering::Equal;
        }
        if query.was_prerelease || query.dev.is_some() {
            let permits_pre = self.lo.was_prerelease
                || self.hi.was_prerelease
                || self.lo.dev.is_some()
                || self.hi.dev.is_some();
            if !permits_pre || self.lo_open {
                return false;
            }
        }
        if query.post.is_some()
            && self.lo.post.is_none()
            && self.lo_open
            && query.compare_release(&self.lo) == Ordering::Equal
        {
            return false;
        }
        // Go currently excludes local versions from vector ranges, even when
        // a boundary names a local version. Point equality remains supported.
        if !query.local.is_empty() {
            return false;
        }
        let lo = query.cmp(&self.lo);
        let hi = query.cmp(&self.hi);
        lo != Ordering::Less
            && !(lo == Ordering::Equal && self.lo_open)
            && hi != Ordering::Greater
            && !(hi == Ordering::Equal && self.hi_open)
    }
}

fn operator_spans(operator: &str, mut lo: Version) -> Result<Vec<Span>> {
    if operator == "!=" {
        ensure!(
            lo.release[..lo.release.len() - 1]
                .iter()
                .all(|n| *n >= 0 && *n != INFINITY),
            "unsupported PyPI exclusion wildcard"
        );
        let mut hi = lo.clone();
        if lo.release.last() == Some(&WILDCARD) {
            let mut equal = operator_spans("==", lo)?;
            let span = equal
                .pop()
                .ok_or_else(|| anyhow::anyhow!("empty wildcard exclusion"))?;
            lo = span.lo;
            hi = span.hi;
        }
        return Ok(vec![
            Span::new(Version::plain_boundary(0), lo, false, true)?,
            Span::new(hi, Version::plain_boundary(INFINITY), true, false)?,
        ]);
    }
    if lo.release.contains(&WILDCARD) {
        lo.clear_pre();
    }
    if operator == "==" && !lo.release.contains(&WILDCARD) {
        return Ok(vec![Span::new(lo.clone(), lo, false, false)?]);
    }
    let mut hi = lo.clone();
    let (mut lo_open, mut hi_open) = (false, false);
    match operator {
        "==" => return Ok(vec![Span::new(lo, hi, false, false)?]),
        ">" | ">=" => {
            lo_open = operator == ">";
            hi.release.fill(INFINITY);
            hi.clear_pre();
        }
        "<" => {
            if lo.release.iter().all(|n| *n == 0) {
                return Ok(vec![]);
            }
            for n in &mut hi.release {
                if *n == WILDCARD {
                    *n = 0;
                }
            }
            hi_open = true;
            lo = Version::minimum();
        }
        "<=" => {
            if hi.release.len() < 3 {
                hi.release.resize(3, INFINITY);
            }
            lo = Version::minimum();
        }
        "~=" => {
            ensure!(
                lo.user_components >= 2,
                "compatible release requires two components"
            );
            if lo.user_components == 2 {
                hi.release.resize(3, 0);
                hi.release[1..].fill(INFINITY);
                return Ok(vec![Span::new(lo, hi, false, false)?]);
            }
            if let Some(last) = hi.release.last_mut() {
                *last = INFINITY;
            }
        }
        _ => bail!("unsupported PyPI operator"),
    }
    lo.tail(INFINITY, INFINITY);
    hi.tail(INFINITY, INFINITY);
    lo.rebuild();
    hi.rebuild();
    Ok(vec![Span::new(lo, hi, lo_open, hi_open)?])
}

fn canonicalize(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| {
        a.lo.cmp(&b.lo)
            .then(a.lo_open.cmp(&b.lo_open))
            .then(a.hi.cmp(&b.hi))
            .then(b.hi_open.cmp(&a.hi_open))
    });
    let mut output = Vec::new();
    let mut i = 0;
    while i < spans.len() {
        let mut current = spans[i].clone();
        let mut j = i + 1;
        while j < spans.len() {
            let next = &spans[j];
            if current.hi.cmp(&next.lo) != Ordering::Equal {
                if current.hi.pre.is_none() {
                    let mut successor = current.hi.clone();
                    successor.increment();
                    if successor.cmp(&next.lo) == Ordering::Less {
                        break;
                    }
                } else {
                    j += 1;
                    continue;
                }
            }
            if (current.hi_open && next.lo_open)
                || [current.hi.pre, next.lo.pre, next.hi.pre]
                    .iter()
                    .any(|pre| *pre != current.lo.pre)
            {
                j += 1;
                continue;
            }
            i += 1;
            match next.hi.cmp(&current.hi) {
                Ordering::Equal => current.hi_open &= next.hi_open,
                Ordering::Greater => {
                    current.hi = next.hi.clone();
                    current.hi_open = next.hi_open;
                }
                Ordering::Less => (),
            }
            j += 1;
        }
        output.push(current);
        i += 1;
    }
    output
}

fn intersect(left: &[Span], right: &[Span]) -> Result<Vec<Span>> {
    let mut result = Vec::new();
    for a in left {
        for b in right {
            let before = b.hi.cmp(&a.lo);
            if before == Ordering::Less || (before == Ordering::Equal && b.hi_open) {
                continue;
            }
            if b.lo.cmp(&a.hi) == Ordering::Greater {
                break;
            }
            let lo = if b.lo.cmp(&a.lo) == Ordering::Greater
                || (b.lo.cmp(&a.lo) == Ordering::Equal && b.lo_open)
            {
                b
            } else {
                a
            };
            let hi = if b.hi.cmp(&a.hi) == Ordering::Less
                || (b.hi.cmp(&a.hi) == Ordering::Equal && b.hi_open)
            {
                b
            } else {
                a
            };
            result.push(Span::new(
                lo.lo.clone(),
                hi.hi.clone(),
                lo.lo_open,
                hi.hi_open,
            )?);
            within_limit(
                result.len() <= MAX_TERMS + 1,
                "PyPI interval limit exceeded",
            )?;
        }
    }
    Ok(canonicalize(result))
}

// The Go lexer accepts space/tab within constraints, and an epoch ! inside a
// version token. Underscores are valid in concrete versions but not its lexer.
fn version_token(rest: &str) -> (&str, &str) {
    let size = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || b".*+-!".contains(b))
        .count();
    (&rest[..size], &rest[size..])
}

/// Evaluate a concrete PyPI version using the pinned Go feed's interval rules.
/// Invalid or oversized input is an error, never a successful non-match.
/// Limits: 8 KiB per constraint, 128 terms and 129 intermediate intervals;
/// concrete-version limits are declared in the parent module.
pub fn matches(constraint: &str, raw: &str) -> Result<bool> {
    within_limit(
        constraint.len() <= MAX_CONSTRAINT_BYTES,
        "PyPI constraint byte limit exceeded",
    )?;
    let query = Version::parse(raw)?;
    let constraint = constraint.trim();
    let empty = constraint.is_empty();
    let mut rest = if empty { ">=0.0.0" } else { constraint };
    let mut spans = Vec::new();
    let mut terms = 0;
    while !rest.is_empty() {
        rest = rest.trim_start_matches([' ', '\t']);
        let operator = ["==", "!=", ">=", "<=", "~=", ">", "<"]
            .into_iter()
            .find(|op| rest.starts_with(op));
        let operator = match operator {
            Some(op) => {
                rest = rest[op.len()..].trim_start_matches([' ', '\t']);
                op
            }
            None => {
                ensure!(terms > 0, "missing PyPI constraint operator");
                "=="
            }
        };
        let (version, tail) = version_token(rest);
        ensure!(!version.is_empty(), "missing PyPI constraint version");
        terms += 1;
        within_limit(terms <= MAX_TERMS, "PyPI constraint term limit exceeded")?;
        let next = operator_spans(operator, Version::pattern(version)?)?;
        spans = if terms == 1 {
            next
        } else {
            intersect(&spans, &next)?
        };
        rest = tail.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            break;
        }
        // Unlike pip, the reference also accepts adjacent operators and
        // whitespace conjunctions. It requires a value after a literal comma.
        if let Some(tail) = rest.strip_prefix(',') {
            rest = tail.trim_start_matches([' ', '\t']);
            ensure!(!rest.is_empty(), "missing constraint after comma");
        }
    }
    Ok(!(empty && query.dev.is_some())
        && canonicalize(spans).iter().any(|span| span.contains(&query)))
}
