// Copyright 2023 Google LLC; Rust adaptation copyright 2026 Zoli contributors.
// SPDX-License-Identifier: Apache-2.0
// Port of the npm path in intel-feed/third_party/semver (deps.dev/util/semver).
//! npm version comparison and constraint intervals used by the Go matcher.
use anyhow::{Result, bail, ensure};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
struct Version {
    nums: [i64; 3],
    count: usize,
    pre: Vec<String>,
    explicit_pre: bool,
}
impl Version {
    fn minimum() -> Self {
        Self {
            nums: [0; 3],
            count: 3,
            pre: vec!["0".into()],
            explicit_pre: false,
        }
    }
    fn maximum() -> Self {
        Self {
            nums: [i64::MAX; 3],
            count: 3,
            pre: vec![],
            explicit_pre: false,
        }
    }
    fn wildcard(&self) -> bool {
        self.nums.contains(&-1)
    }
    fn parse(raw: &str) -> Result<Self> {
        let quoted = if raw.bytes().all(|b| (32..127).contains(&b) && b != b'`') {
            format!("`{raw}`")
        } else {
            serde_json::to_string(raw)?
        };
        let error = |message: &str| anyhow::anyhow!("{message} in {quoted}");
        if let Some(c) = raw
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && !".+-*".contains(*c))
        {
            bail!("invalid character {:?} in {quoted}", c);
        }
        let raw = raw.trim_start_matches('v');
        let (version, build) = raw
            .split_once('+')
            .map_or((raw, None), |(v, b)| (v, Some(b)));
        if let Some(build) = build {
            ensure!(
                !build.is_empty()
                    && build.split('.').all(|v| !v.is_empty()
                        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
                "empty or invalid build metadata in {quoted}"
            );
        }
        let (numbers, pre) = version
            .split_once('-')
            .map_or((version, None), |(v, p)| (v, Some(p)));
        let mut result = Self {
            nums: [0; 3],
            count: 0,
            pre: vec![],
            explicit_pre: pre.is_some(),
        };
        for (i, n) in numbers.split('.').enumerate() {
            ensure!(i < 3, "more than 3 numbers present in {quoted}");
            if n.is_empty()
                || (!n.bytes().all(|b| b.is_ascii_digit()) && !["x", "X", "*"].contains(&n))
            {
                return Err(error(if i == 0 {
                    "no number in version string"
                } else {
                    "non-numeric version"
                }));
            }
            result.nums[i] = if ["x", "X", "*"].contains(&n) {
                -1
            } else {
                let value: i64 = n
                    .parse()
                    .map_err(|_| anyhow::anyhow!("number out of range: {n}"))?;
                ensure!(value < i64::MAX, "number out of range: {n}");
                value
            };
            result.count += 1;
        }
        if let Some(pre) = pre {
            ensure!(!pre.is_empty(), "empty pre-release metadata in {quoted}");
            for p in pre.split('.') {
                ensure!(
                    !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                    "empty component in {quoted}"
                );
                result.pre.push(p.to_owned());
            }
        }
        Ok(result)
    }
    fn cmp(&self, other: &Self) -> Ordering {
        match self.nums.cmp(&other.nums) {
            Ordering::Equal => {}
            c => return c,
        }
        match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            _ => {}
        }
        for (a, b) in self.pre.iter().zip(&other.pre) {
            let numeric = |s: &str| {
                if s.bytes().all(|b| b.is_ascii_digit()) {
                    s.parse::<i64>().ok()
                } else {
                    None
                }
            };
            let order = match (numeric(a), numeric(b)) {
                (Some(a), Some(b)) => a.cmp(&b),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                _ => a.cmp(b),
            };
            if order != Ordering::Equal {
                return order;
            }
        }
        self.pre.len().cmp(&other.pre.len())
    }
    fn tail(&mut self, marker: i64, fill: i64) {
        if let Some(i) = self.nums.iter().position(|n| *n == marker) {
            self.nums[i..].fill(fill);
        }
        self.count = 3;
    }
    fn clear_pre(&mut self) {
        self.pre.clear();
        self.explicit_pre = false;
    }
    fn increment(&mut self) {
        let i = self
            .nums
            .iter()
            .position(|n| *n == -1)
            .map_or(self.count - 1, |i| i.saturating_sub(1));
        self.nums[i] = self.nums[i].saturating_add(1);
        for n in &mut self.nums[i + 1..] {
            *n = 0;
        }
        self.count = 3;
    }
}

#[derive(Clone)]
struct Span {
    lo: Version,
    hi: Version,
    lo_open: bool,
    hi_open: bool,
    empty: bool,
}
impl Span {
    fn all() -> Self {
        Self {
            lo: Version::minimum(),
            hi: Version::maximum(),
            lo_open: false,
            hi_open: false,
            empty: false,
        }
    }
    fn new(mut lo: Version, mut hi: Version, lo_open: bool, hi_open: bool) -> Self {
        if lo.nums[0] == -1 {
            lo = Version::minimum();
        } else {
            lo.tail(-1, 0);
        }
        hi.tail(-1, i64::MAX);
        let c = lo.cmp(&hi);
        Self {
            lo,
            hi,
            lo_open,
            hi_open,
            empty: c == Ordering::Greater || (c == Ordering::Equal && (lo_open || hi_open)),
        }
    }
    fn intersect(&mut self, other: Self) {
        self.empty |= other.empty;
        let lo = other.lo.cmp(&self.lo);
        if lo == Ordering::Greater || (lo == Ordering::Equal && other.lo_open) {
            self.lo = other.lo;
            self.lo_open = other.lo_open;
        }
        let hi = other.hi.cmp(&self.hi);
        if hi == Ordering::Less || (hi == Ordering::Equal && other.hi_open) {
            self.hi = other.hi;
            self.hi_open = other.hi_open;
        }
        let c = self.lo.cmp(&self.hi);
        self.empty |=
            c == Ordering::Greater || (c == Ordering::Equal && (self.lo_open || self.hi_open));
    }
    fn contains(&self, v: &Version) -> bool {
        if self.empty {
            return false;
        }
        let lo = v.cmp(&self.lo);
        let hi = v.cmp(&self.hi);
        if lo == Ordering::Less
            || (lo == Ordering::Equal && self.lo_open)
            || hi == Ordering::Greater
            || (hi == Ordering::Equal && self.hi_open)
        {
            return false;
        }
        if self.lo.cmp(&self.hi) == Ordering::Equal || v.pre.is_empty() {
            return true;
        }
        [&self.lo, &self.hi]
            .iter()
            .any(|b| b.explicit_pre && b.nums == v.nums && b.count == v.count)
    }
}

fn op_span(op: &str, mut v: Version) -> Result<Span> {
    if v.wildcard() {
        v.clear_pre();
    }
    ensure!(
        v.pre.is_empty() || v.count == 3,
        "prerelease requires 3 numbers"
    );
    let mut hi = v.clone();
    let mut lo = v;
    let mut lo_open = false;
    let mut hi_open = false;
    let mut empty = false;
    match op {
        "" | "=" => {
            if lo.count < 3 {
                hi.nums[lo.count..].fill(i64::MAX);
            }
        }
        ">" | ">=" => {
            if op == ">" {
                if lo.nums[0] == -1 {
                    empty = true;
                }
                if !lo.pre.is_empty() {
                    lo_open = true;
                } else {
                    lo.increment();
                }
            }
            hi = Version::maximum();
        }
        "<" => {
            empty = lo.nums[0] == -1 || lo.nums.iter().all(|n| *n == 0);
            hi.tail(-1, 0);
            hi_open = true;
            lo = Version::minimum();
        }
        "<=" => {
            if lo.count < 3 {
                hi.nums[lo.count..].fill(i64::MAX);
            }
            lo = Version::minimum();
        }
        "^" => {
            if lo.nums[0] == -1 {
                lo = Version::minimum();
                hi = Version::maximum();
            } else if lo.nums[0] == 0 && lo.count >= 2 {
                if lo.count == 2 || lo.nums[1] != 0 {
                    hi.nums[2] = i64::MAX;
                }
                hi.clear_pre();
            } else {
                hi.nums[1..].fill(i64::MAX);
                hi.clear_pre();
            }
        }
        "~" => {
            if lo.count == 1 {
                hi.nums[1..].fill(i64::MAX);
            } else {
                hi.nums[2] = i64::MAX;
            }
        }
        "~>" => {
            if lo.count == 1 {
                hi.nums[1..].fill(i64::MAX);
            } else {
                hi.nums[2] = i64::MAX;
            }
        }
        _ => bail!("unsupported operator"),
    }
    let mut result = Span::new(lo, hi, lo_open, hi_open);
    result.empty |= empty;
    Ok(result)
}
/// Compare concrete npm versions, including Go's leniency and prerelease rules.
pub fn compare(a: &str, b: &str) -> Result<Ordering> {
    let a = Version::parse(a)?;
    let b = Version::parse(b)?;
    ensure!(!a.wildcard() && !b.wildcard(), "expected concrete versions");
    Ok(a.cmp(&b))
}
/// Validate that a query version is a concrete npm version.
pub fn concrete(raw: &str) -> bool {
    Version::parse(raw).is_ok_and(|v| !v.wildcard())
}
/// Evaluate an npm constraint through the Go reference interval rules.
pub fn matches(constraint: &str, raw: &str) -> Result<bool> {
    let query = Version::parse(raw)?;
    ensure!(!query.wildcard(), "invalid query version");
    let constraint = constraint.trim();
    ensure!(
        constraint
            .bytes()
            .all(|b| b == b' ' || b == b'\t' || !b.is_ascii_whitespace()),
        "invalid constraint whitespace"
    );
    let mut matched = false;
    for alternative in constraint.split("||") {
        let text = alternative.trim();
        if text.is_empty() {
            ensure!(constraint.is_empty(), "empty alternative in npm constraint");
            matched |= query.pre.is_empty();
            continue;
        }
        let tokens: Vec<_> = text.split_ascii_whitespace().collect();
        if tokens.len() == 3 && tokens[1] == "-" {
            let lo = Version::parse(tokens[0])?;
            let mut hi = Version::parse(tokens[2])?;
            if hi.count < 3 {
                hi.nums[hi.count..].fill(i64::MAX);
            }
            ensure!(lo.cmp(&hi) != Ordering::Greater, "impossible constraint");
            matched |= Span::new(lo, hi, false, false).contains(&query);
            continue;
        }
        let mut rest = text;
        let mut combined = Span::all();
        while !rest.is_empty() {
            rest = rest.trim_start_matches([' ', '\t']);
            if rest.is_empty() {
                break;
            }
            let operator_len = rest.bytes().take_while(|b| b"<>=~^".contains(b)).count();
            let operator = &rest[..operator_len];
            rest = rest[operator_len..].trim_start_matches([' ', '\t']);
            let end = rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || b".+-*".contains(b))
                .count();
            ensure!(end > 0, "expected version after operator");
            let v = Version::parse(&rest[..end])?;
            combined.intersect(op_span(operator, v)?);
            rest = &rest[end..];
        }
        matched |= combined.contains(&query);
    }
    Ok(matched)
}
