//! Strict wire parsing: retain raw signature bytes and reject ambiguous JSON.
use anyhow::Result;
use serde::{
    Deserialize,
    de::{MapAccess, SeqAccess, Visitor},
};
use std::collections::BTreeSet;

struct Checked;
impl<'de> Deserialize<'de> for Checked {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Check;
        impl<'de> Visitor<'de> for Check {
            type Value = Checked;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Checked, A::Error> {
                let mut seen = BTreeSet::new();
                while let Some(key) = a.next_key::<String>()? {
                    if !seen.insert(key.to_lowercase()) {
                        return Err(serde::de::Error::custom(
                            "duplicate or case-ambiguous JSON key",
                        ));
                    }
                    // All signed Go model keys are lower-case snake_case.
                    // Unknown fields remain ignored by the typed decoder.
                    if key.bytes().any(|b| b.is_ascii_uppercase())
                        && KNOWN.contains(&key.to_lowercase().as_str())
                    {
                        return Err(serde::de::Error::custom(
                            "case-insensitive wire field rejected",
                        ));
                    }
                    a.next_value::<Checked>()?;
                }
                Ok(Checked)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Checked, A::Error> {
                while a.next_element::<Checked>()?.is_some() {}
                Ok(Checked)
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<Checked, E> {
                Ok(Checked)
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Checked, E> {
                Ok(Checked)
            }
        }
        d.deserialize_any(Check)
    }
}
const KNOWN: &[&str] = &[
    "ecosystem",
    "name",
    "version",
    "registry",
    "sha256",
    "channel",
    "subdir",
    "build",
    "introduced",
    "fixed",
    "last_affected",
    "limit",
    "type",
    "constraint",
    "events",
    "package",
    "versions",
    "ranges",
    "scope",
    "source",
    "id",
    "url",
    "license",
    "revision",
    "retrieved_at",
    "rule_id",
    "rule_version",
    "artifact_sha256",
    "file",
    "line",
    "explanation",
    "observations",
    "reproduce",
    "limitations",
    "action",
    "reviewer",
    "rationale",
    "at",
    "schema_version",
    "aliases",
    "classification",
    "status",
    "summary",
    "affected",
    "evidence",
    "sources",
    "references",
    "published_at",
    "modified_at",
    "withdrawn_at",
    "reviews",
    "original_license",
    "cursor",
    "last_success",
    "last_attempt",
    "error",
    "coverage",
    "gaps",
    "mode",
    "path",
    "bytes",
    "kind",
    "from_sequence",
    "to_sequence",
    "created_at",
    "sequence",
    "generated_at",
    "record_count",
    "records_sha256",
    "rule_set_sha256",
    "files",
    "original_data_license",
    "imported_data_license",
    "operation",
    "record",
    "certainty",
    "reasons",
    "matches",
    "freshness",
    "manifest",
    "key_id",
    "signature",
    "envelope",
    "records",
];
/// Decode JSON after checking UTF-8, duplicate keys and wire-name casing.
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    std::str::from_utf8(bytes)?;
    let _: Checked = serde_json::from_slice(bytes)?;
    Ok(serde_json::from_slice(bytes)?)
}
