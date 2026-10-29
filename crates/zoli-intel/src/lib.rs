//! Verified Zoli intel-feed client.
//!
//! This crate is a faithful Rust port of the Go reference client in
//! `intel-feed/pkg/client`. It has one job: produce the same verdict as Go's
//! `api.Query` for the same verified feed and query. It applies no Zoli
//! policy; `zoli-policy` turns verdicts into install decisions. See
//! `docs/decisions/ADR-004-feed-client-faithfulness.md`.
//!
//! Phase 0 established the shared vocabulary. Phase 1 starts with Go-generated
//! fixtures and string-encoding primitives in [`wire`]. The trust chain,
//! complete record serializer and version matching are still to be implemented.

pub mod feed;
pub mod json;
pub mod model;
pub mod net;
pub mod npm;
pub mod pypi;
pub mod query;
pub mod wire;

use std::fmt;
use std::str::FromStr;

/// Feed and record schema version this client understands (Go `model.Schema`).
pub const SCHEMA_VERSION: &str = "1.0";

/// A wire string that does not name a known value. Parsing is exact and
/// case-sensitive: these strings come from signed Go output, never from users.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownValue {
    /// Vocabulary the value was parsed as.
    pub kind: &'static str,
    /// The rejected input.
    pub value: String,
}

impl fmt::Display for UnknownValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {} value {:?}", self.kind, self.value)
    }
}

impl std::error::Error for UnknownValue {}

/// Declares an enum whose variants map one-to-one onto Go wire strings.
macro_rules! wire_enum {
    ($(#[$meta:meta])* $name:ident, $kind:literal { $($(#[$vmeta:meta])* $variant:ident => $wire:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            /// Every variant, in Go declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// The exact string Go emits for this value.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }
        }

        impl FromStr for $name {
            type Err = UnknownValue;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($wire => Ok(Self::$variant),)+
                    _ => Err(UnknownValue { kind: $kind, value: s.to_owned() }),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

wire_enum! {
    /// Outcome of one lookup (Go `api.QueryResponse.Status`).
    /// `NoKnownMatch` is never a safety verdict.
    QueryStatus, "query status" {
        /// A published record matches by exact version or range.
        KnownMatch => "known_match",
        /// No record matched, the version was given and the feed was current.
        NoKnownMatch => "no_known_match",
        /// An uncertain match, a missing version, missing Conda selectors,
        /// or stale/degraded intelligence.
        InsufficientInformation => "insufficient_information",
    }
}

wire_enum! {
    /// Finding classification (Go `model.Record.Classification`).
    Classification, "classification" {
        /// Confirmed malicious behaviour.
        Malicious => "malicious",
        /// Signals that need review; not confirmed malicious.
        Suspicious => "suspicious",
    }
}

wire_enum! {
    /// How a record matched a query (Go `model.Match.Certainty`). Go's
    /// internal `none` never reaches a response, so it has no variant here.
    Certainty, "certainty" {
        /// The query version is listed explicitly.
        Exact => "exact",
        /// The query version falls inside a range, or the scope is `all`.
        Range => "range",
        /// The record names the package but cannot confirm the version.
        Uncertain => "uncertain",
    }
}

wire_enum! {
    /// Feed freshness at query time (Go `api.QueryResponse.Freshness`).
    Freshness, "freshness" {
        /// Manifest and every source updated within the last hour.
        Current => "current",
        /// The manifest was generated more than an hour ago.
        Stale => "stale",
        /// A source has an error, or has not succeeded within the last hour.
        Degraded => "degraded",
    }
}

wire_enum! {
    /// Canonical ecosystem names (Go `model.Ecosystems`). Query-side aliases
    /// such as `pip` or `pnpm` are normalized in Phase 1, not parsed here.
    Ecosystem, "ecosystem" {
        /// Python Package Index.
        PyPi => "PyPI",
        /// npm registry.
        Npm => "npm",
        /// crates.io.
        Cargo => "Cargo",
        /// Maven Central.
        Maven => "Maven",
        /// Conda channels.
        Conda => "Conda",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trips<T>(all: &[T])
    where
        T: Copy + PartialEq + fmt::Debug + fmt::Display + FromStr<Err = UnknownValue>,
    {
        for &v in all {
            assert_eq!(v.to_string().parse::<T>(), Ok(v));
        }
    }

    #[test]
    fn wire_strings_round_trip() {
        round_trips(QueryStatus::ALL);
        round_trips(Classification::ALL);
        round_trips(Certainty::ALL);
        round_trips(Freshness::ALL);
        round_trips(Ecosystem::ALL);
    }

    #[test]
    fn wire_strings_match_go() {
        let statuses: Vec<_> = QueryStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            statuses,
            ["known_match", "no_known_match", "insufficient_information"]
        );
        let ecosystems: Vec<_> = Ecosystem::ALL.iter().map(|e| e.as_str()).collect();
        assert_eq!(ecosystems, ["PyPI", "npm", "Cargo", "Maven", "Conda"]);
    }

    #[test]
    fn parsing_is_exact() {
        for bad in ["Known_Match", "known_match ", "", "none", "pypi", "pnpm"] {
            assert!(bad.parse::<QueryStatus>().is_err(), "{bad:?}");
            assert!(bad.parse::<Ecosystem>().is_err(), "{bad:?}");
        }
        assert!("none".parse::<Certainty>().is_err());
        assert_eq!(
            "fresh".parse::<Freshness>().unwrap_err().to_string(),
            r#"unknown freshness value "fresh""#
        );
    }
}
