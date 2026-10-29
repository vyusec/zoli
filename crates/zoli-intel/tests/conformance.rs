//! Compare actual Rust behavior with generated Go output, not handwritten verdicts.
#![allow(clippy::expect_used, clippy::unwrap_used)]
use zoli_intel::{model::*, wire::Mode};

fn corpus(name: &str) -> Vec<serde_json::Value> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance")
        .join(name);
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}
#[test]
fn record_encoding_and_hashes_match_go() {
    let cases = corpus("record-encoding.json");
    assert!(!cases.is_empty());
    for case in cases {
        let r: Record = serde_json::from_value(case["record"].clone()).unwrap();
        assert_eq!(
            hex::encode(r.go_json(Mode::Marshal).unwrap()),
            case["marshal_json_hex"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            hex::encode(format!("{}\n", r.go_json(Mode::Hash).unwrap())),
            case["hash_json_hex"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            records_hash(&[r]).unwrap(),
            case["records_sha256"].as_str().unwrap()
        );
    }
}
#[test]
fn identity_normalization_matches_go() {
    for case in corpus("identities.json") {
        let mut p: Identity = serde_json::from_value(case["input"].clone()).unwrap();
        let result = p.normalize();
        if let Some(error) = case["error"].as_str() {
            assert_eq!(result.unwrap_err().to_string(), error, "{}", case["name"]);
        } else {
            result.unwrap();
            let expected: Identity = serde_json::from_value(case["normalized"].clone()).unwrap();
            assert_eq!(
                p.go_json(Mode::Marshal).unwrap(),
                expected.go_json(Mode::Marshal).unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
#[test]
fn query_bytes_match_go() {
    let now = GoTime::parse("2026-10-18T00:00:00Z").unwrap();
    for case in corpus("queries.json") {
        let q = serde_json::from_value(case["query"].clone()).unwrap();
        let m = serde_json::from_value(case["manifest"].clone()).unwrap();
        let records: Vec<Record> = serde_json::from_value(case["records"].clone()).unwrap();
        let result = zoli_intel::query::query(q, &m, &records, &now);
        if let Some(error) = case["error"].as_str() {
            assert_eq!(result.unwrap_err().to_string(), error);
        } else {
            assert_eq!(
                hex::encode(result.unwrap().go_json(Mode::Marshal).unwrap()),
                case["marshal_json_hex"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}
#[test]
fn ambiguous_json_is_rejected() {
    for bytes in [
        br#"{"name":"a","name":"b"}"#.as_slice(),
        br#"{"Name":"a"}"#,
        b"{\"name\":\"\xff\"}",
    ] {
        assert!(zoli_intel::json::decode::<Identity>(bytes).is_err());
    }
    assert!(zoli_intel::json::decode::<Identity>(br#"{"name":"a","future_field":1}"#).is_ok());
}

#[test]
fn npm_comparison_and_constraints_match_go() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/conformance/npm-matrix.json");
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut differences = vec![];
    for c in data["comparisons"].as_array().unwrap() {
        let a = c["a"].as_str().unwrap();
        let b = c["b"].as_str().unwrap();
        let actual = zoli_intel::npm::compare(a, b);
        if actual.is_err() != c["error"].as_bool().unwrap()
            || actual
                .as_ref()
                .is_ok_and(|v| (*v as i32).signum() != c["order"].as_i64().unwrap().signum() as i32)
        {
            differences.push(format!("compare {a:?} {b:?}: {actual:?}; {c}"));
        }
    }
    for c in data["matches"].as_array().unwrap() {
        let constraint = c["constraint"].as_str().unwrap();
        let version = c["version"].as_str().unwrap();
        let actual = zoli_intel::npm::matches(constraint, version);
        if actual.is_err() != c["error"].as_bool().unwrap()
            || actual
                .as_ref()
                .is_ok_and(|v| *v != c["match"].as_bool().unwrap())
        {
            differences.push(format!("match {constraint:?} {version:?}: {actual:?}; {c}"));
        }
    }
    assert!(
        differences.is_empty(),
        "{} differences:\n{}",
        differences.len(),
        differences
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn pypi_concrete_comparison_matches_go() {
    for case in corpus("pypi-matrix.json") {
        let a = case["a"].as_str().unwrap();
        let b = case["b"].as_str().unwrap();
        let actual = zoli_intel::pypi::compare(a, b);
        assert_eq!(
            actual.is_err(),
            case["error"].as_bool().unwrap(),
            "{a:?} {b:?}: {actual:?}"
        );
        if let Ok(order) = actual {
            assert_eq!(
                order as i32,
                case["order"].as_i64().unwrap().signum() as i32,
                "{a:?} {b:?}"
            );
        }
    }
}

#[test]
fn signed_snapshots_and_deltas_match_go() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    struct Memory(std::collections::BTreeMap<String, Vec<u8>>);
    impl zoli_intel::net::Fetch for Memory {
        fn get(&self, url: &str, max: usize) -> anyhow::Result<Vec<u8>> {
            let b = self
                .0
                .get(url)
                .ok_or_else(|| anyhow::anyhow!("missing fixture response"))?;
            anyhow::ensure!(b.len() <= max, "fixture response over limit");
            Ok(b.clone())
        }
    }
    for c in corpus("feed-cases.json") {
        let key: [u8; 32] = STANDARD
            .decode(c["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let responses = c["responses"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(u, b)| (u.clone(), hex::decode(b.as_str().unwrap()).unwrap()))
            .collect();
        let previous: Option<zoli_intel::feed::Snapshot> = c
            .get("previous_hex")
            .map(|v| serde_json::from_slice(&hex::decode(v.as_str().unwrap()).unwrap()).unwrap());
        let result = zoli_intel::feed::fetch_snapshot(
            &Memory(responses),
            "https://feed.example.invalid/feed",
            &key,
            previous.as_ref(),
            None,
        );
        if c.get("error").is_some() || c["rust_reject"].as_bool() == Some(true) {
            assert!(result.is_err(), "{} was accepted", c["name"]);
        } else {
            assert!(result.is_ok(), "{}: {result:?}", c["name"]);
            let actual = result.unwrap();
            let expected = hex::decode(c["expected_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                serde_json::to_vec(&actual).unwrap(),
                expected,
                "{}",
                c["name"]
            );
            actual.verify(&key).unwrap();
            if let Some(directory) = std::env::var_os("ZOLI_CONFORMANCE_CACHE_OUT") {
                let directory = std::path::PathBuf::from(directory);
                std::fs::create_dir_all(&directory).unwrap();
                let name = c["name"].as_str().unwrap();
                std::fs::write(
                    directory.join(format!("{name}.json")),
                    serde_json::to_vec(&actual).unwrap(),
                )
                .unwrap();
                std::fs::write(directory.join(format!("{name}.key")), STANDARD.encode(key))
                    .unwrap();
            }
        }
    }
}
