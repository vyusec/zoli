// Copyright 2023 Google LLC; Rust adaptation copyright 2026 Zoli contributors.
// SPDX-License-Identifier: Apache-2.0
// Port of concrete comparison in intel-feed/third_party/semver/pep440.go.
//! Concrete PyPI version comparison against the Go feed's PEP 440 implementation.
//! Constraint-string evaluation is deliberately not implemented yet.
use anyhow::{Result, ensure};
use std::cmp::Ordering;

#[derive(Default)]
struct Version {
    epoch: u8,
    release: Vec<i64>,
    pre: Option<(u8, i64)>,
    post: Option<i64>,
    dev: Option<i64>,
    local: String,
}
fn separator(s: &str) -> &str {
    s.strip_prefix(['.', '_', '-']).unwrap_or(s)
}
fn number(s: &str) -> (i64, &str) {
    let s = separator(s);
    let n = s.bytes().take_while(u8::is_ascii_digit).count();
    // The Go implementation parses unsigned suffixes, saturates on overflow,
    // then casts to machine int. Keep that wire-matching behavior explicit.
    let value = if n == 0 {
        0
    } else {
        s[..n].parse::<u64>().unwrap_or(u64::MAX) as i64
    };
    (value, &s[n..])
}
fn possible(s: &str) -> bool {
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s);
    if s.is_empty() {
        return false;
    }
    for (i, b) in s.bytes().take(3).enumerate() {
        match b {
            b'.' | b'-' | b'+' => return i != 0,
            b'0'..=b'9' | b'*' | b'x' | b'X' | b'!' | b'_' => (),
            b if i > 0 && b"abcdehiloprstvw".contains(&b) => (),
            _ => return false,
        }
    }
    true
}
impl Version {
    fn parse(raw: &str) -> Result<Self> {
        ensure!(possible(raw), "invalid PyPI version");
        let mut s = raw.trim();
        ensure!(
            s.bytes().all(|b| (33..127).contains(&b)),
            "invalid PyPI version character"
        );
        let mut v = Self::default();
        if let Some((epoch, tail)) = s.split_once('!') {
            ensure!(
                !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()),
                "invalid PyPI epoch"
            );
            v.epoch = epoch.parse()?;
            s = tail;
        }
        s = s.strip_prefix(['v', 'V']).unwrap_or(s);
        loop {
            let n = s.bytes().take_while(u8::is_ascii_digit).count();
            if n == 0 {
                break;
            }
            let value: i64 = s[..n].parse()?;
            ensure!(value < i64::MAX, "PyPI release number out of range");
            v.release.push(value);
            s = &s[n..];
            if let Some(tail) = s.strip_prefix('.') {
                ensure!(!tail.is_empty(), "empty PyPI release component");
                s = tail;
            } else {
                break;
            }
        }
        ensure!(!v.release.is_empty(), "PyPI version has no release numbers");
        for (label, rank) in [
            ("alpha", 1),
            ("a", 1),
            ("beta", 2),
            ("b", 2),
            ("preview", 3),
            ("pre", 3),
            ("rc", 3),
            ("c", 3),
        ] {
            let tail = separator(s);
            if tail
                .get(..label.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(label))
            {
                let (num, tail) = number(&tail[label.len()..]);
                v.pre = Some((rank, num));
                s = tail;
                break;
            }
        }
        let tail = separator(s);
        let label = ["post", "rev", "r"].into_iter().find(|p| {
            tail.get(..p.len())
                .is_some_and(|t| t.eq_ignore_ascii_case(p))
        });
        if let Some(label) = label {
            let (num, tail) = number(&tail[label.len()..]);
            v.post = Some(num);
            s = tail;
        } else if s.starts_with('-') && tail.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            let (num, tail) = number(tail);
            v.post = Some(num);
            s = tail;
        }
        let tail = separator(s);
        if tail.get(..3).is_some_and(|t| t.eq_ignore_ascii_case("dev")) {
            let (num, tail) = number(&tail[3..]);
            v.dev = Some(num);
            s = tail;
        }
        if let Some(tail) = s.strip_prefix('+') {
            ensure!(
                tail.as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                    && tail
                        .as_bytes()
                        .last()
                        .is_some_and(u8::is_ascii_alphanumeric)
                    && tail
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "invalid PyPI local version"
            );
            v.local = tail.replace(['-', '_'], ".");
            s = "";
        }
        ensure!(s.is_empty(), "unsupported or nonconcrete PyPI version");
        Ok(v)
    }
    fn rank(&self) -> u8 {
        if let Some((rank, _)) = self.pre {
            rank
        } else if self.post.is_some() {
            6
        } else if self.dev.is_some() {
            0
        } else if !self.local.is_empty() {
            5
        } else {
            4
        }
    }
    fn cmp(&self, other: &Self) -> Ordering {
        let epoch = self.epoch.cmp(&other.epoch);
        if epoch != Ordering::Equal {
            return epoch;
        }
        for i in 0..self.release.len().max(other.release.len()) {
            let order = self
                .release
                .get(i)
                .unwrap_or(&0)
                .cmp(other.release.get(i).unwrap_or(&0));
            if order != Ordering::Equal {
                return order;
            }
        }
        let rank = self.rank().cmp(&other.rank());
        if rank != Ordering::Equal {
            return rank;
        }
        if (1..=3).contains(&self.rank()) {
            let pre = self.pre.cmp(&other.pre);
            if pre != Ordering::Equal {
                return pre;
            }
        }
        if (1..=3).contains(&self.rank()) || self.rank() == 5 {
            let local = compare_local(&self.local, &other.local);
            if local != Ordering::Equal {
                return local;
            }
        }
        if (1..=3).contains(&self.rank()) || [5, 6].contains(&self.rank()) {
            let post = self.post.unwrap_or(0).cmp(&other.post.unwrap_or(0));
            if post != Ordering::Equal {
                return post;
            }
        }
        match (self.dev, other.dev) {
            (Some(a), Some(b)) => a.cmp(&b),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            _ => Ordering::Equal,
        }
    }
}
fn compare_local(a: &str, b: &str) -> Ordering {
    let a: Vec<_> = a.split('.').collect();
    let b: Vec<_> = b.split('.').collect();
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    for (i, part) in a.iter().enumerate() {
        let other = b.get(i).copied().unwrap_or("");
        let order = match (numeric(part), numeric(other)) {
            (true, true) => part
                .parse::<u64>()
                .unwrap_or(u64::MAX)
                .cmp(&other.parse::<u64>().unwrap_or(u64::MAX)),
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            _ => part.cmp(&other),
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    a.len().cmp(&b.len())
}
/// Whether the Go-compatible parser accepts an exact version without wildcards.
pub fn concrete(version: &str) -> bool {
    Version::parse(version).is_ok()
}
/// Compare two concrete versions, preserving the Go feed's ordering semantics.
pub fn compare(a: &str, b: &str) -> Result<Ordering> {
    Ok(Version::parse(a)?.cmp(&Version::parse(b)?))
}
