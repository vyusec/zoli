//! Crash/restart and concurrent-writer invariants for independently durable state.
#![allow(clippy::unwrap_used)]
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::BTreeMap;
use zoli_intel::{
    feed::{Snapshot, Store},
    net::Fetch,
};
const BASE: &str = "https://feed.example.invalid/feed";
struct Memory(BTreeMap<String, Vec<u8>>);
impl Fetch for Memory {
    fn get(&self, url: &str, max: usize) -> anyhow::Result<Vec<u8>> {
        let bytes = self
            .0
            .get(url)
            .ok_or_else(|| anyhow::anyhow!("missing fixture response"))?;
        anyhow::ensure!(bytes.len() <= max, "oversize");
        Ok(bytes.clone())
    }
}
fn fixture(name: &str) -> ([u8; 32], Memory, serde_json::Value) {
    let cases: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "../../../testdata/conformance/feed-cases.json"
    ))
    .unwrap();
    let case = cases.into_iter().find(|v| v["name"] == name).unwrap();
    let key = STANDARD
        .decode(case["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let memory = Memory(
        case["responses"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(u, b)| (u.clone(), hex::decode(b.as_str().unwrap()).unwrap()))
            .collect(),
    );
    (key, memory, case)
}
#[test]
fn failed_updates_preserve_cache_and_independent_high_water_mark() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().to_owned());
    let (key, good, _) = fixture("valid-snapshot");
    store.update(&good, BASE, &key).unwrap();
    let state = std::fs::read(dir.path().join("state.json")).unwrap();
    let cache = std::fs::read(dir.path().join("cache/feed.json")).unwrap();
    for name in [
        "bad-signature",
        "wrong-key",
        "rollback",
        "equal-sequence",
        "equivocation",
    ] {
        let (_, bad, _) = fixture(name);
        assert!(store.update(&bad, BASE, &key).is_err(), "{name}");
        assert_eq!(std::fs::read(dir.path().join("state.json")).unwrap(), state);
        assert_eq!(
            std::fs::read(dir.path().join("cache/feed.json")).unwrap(),
            cache
        );
        store.load(&key).unwrap();
    }
    assert!(store.load(&[7; 32]).is_err());
    // An authenticated identical publication can reuse the existing verified
    // cache; it must not depend on the availability of artifact mirrors.
    store
        .update(&fixture("artifact-byte").1, BASE, &key)
        .unwrap();
    for name in ["artifact-byte", "artifact-size"] {
        let fresh = tempfile::tempdir().unwrap();
        assert!(
            Store::new(fresh.path().into())
                .update(&fixture(name).1, BASE, &key)
                .is_err()
        );
        assert!(!fresh.path().join("state.json").exists());
        assert!(!fresh.path().join("cache/feed.json").exists());
    }
}
#[test]
fn missing_corrupt_or_interrupted_cache_recovers_only_above_known_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().to_owned());
    let (key, good, _) = fixture("valid-snapshot");
    store.update(&good, BASE, &key).unwrap();
    let cache = dir.path().join("cache/feed.json");
    for damaged in [
        b"corrupt".to_vec(),
        hex::decode(
            fixture("delta-correction").2["previous_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    ] {
        std::fs::write(&cache, damaged).unwrap();
        assert!(store.load(&key).is_err());
        assert!(store.update(&fixture("rollback").1, BASE, &key).is_err());
        store.update(&good, BASE, &key).unwrap();
        assert_eq!(store.load(&key).unwrap().verify(&key).unwrap().sequence, 2);
    }
    std::fs::remove_file(&cache).unwrap();
    assert!(store.load(&key).is_err());
    store.update(&good, BASE, &key).unwrap();
    std::fs::write(dir.path().join("state.json"), b"corrupt").unwrap();
    assert!(store.update(&good, BASE, &key).is_err());
    assert_eq!(
        std::fs::read(dir.path().join("state.json")).unwrap(),
        b"corrupt"
    );
}
#[test]
fn existing_cache_cannot_silently_bootstrap_a_lost_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().to_owned());
    let (key, good, _) = fixture("valid-snapshot");
    store.update(&good, BASE, &key).unwrap();
    std::fs::remove_file(dir.path().join("state.json")).unwrap();
    assert!(store.load(&key).is_err());
    assert!(store.update(&good, BASE, &key).is_err());
}
#[test]
fn concurrent_updates_and_readers_agree_on_one_verified_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (key, good, _) = fixture("valid-snapshot");
    Store::new(dir.path().into())
        .update(&good, BASE, &key)
        .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let path = dir.path();
            scope.spawn(move || {
                let (_, good, _) = fixture("valid-snapshot");
                let store = Store::new(path.into());
                for _ in 0..3 {
                    store.update(&good, BASE, &key).unwrap();
                    let snapshot: Snapshot = store.load(&key).unwrap();
                    assert_eq!(snapshot.verify(&key).unwrap().sequence, 2);
                }
            });
        }
    });
}

#[test]
fn failed_cache_rename_keeps_committed_high_water_and_can_be_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().into());
    let (key, good, _) = fixture("valid-snapshot");
    // Force persist to fail AFTER state was committed, without killing a process.
    std::fs::create_dir_all(dir.path().join("cache/feed.json")).unwrap();
    // A pre-existing cache without state correctly prevents initialization.
    assert!(store.update(&good, BASE, &key).is_err());
    std::fs::remove_dir(dir.path().join("cache/feed.json")).unwrap();
    store.update(&good, BASE, &key).unwrap();
    std::fs::remove_file(dir.path().join("cache/feed.json")).unwrap();
    std::fs::create_dir(dir.path().join("cache/feed.json")).unwrap();
    assert!(store.update(&good, BASE, &key).is_err());
    let state = std::fs::read(dir.path().join("state.json")).unwrap();
    assert!(store.load(&key).is_err());
    assert!(store.update(&fixture("rollback").1, BASE, &key).is_err());
    assert_eq!(std::fs::read(dir.path().join("state.json")).unwrap(), state);
    std::fs::remove_dir(dir.path().join("cache/feed.json")).unwrap();
    store.update(&good, BASE, &key).unwrap();
    assert_eq!(store.load(&key).unwrap().verify(&key).unwrap().sequence, 2);
}

#[test]
fn abandoned_temporary_files_never_become_trusted_state() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().into());
    let (key, good, _) = fixture("valid-snapshot");
    std::fs::create_dir(dir.path().join("cache")).unwrap();
    std::fs::write(dir.path().join("cache/.tmp-abandoned"), b"untrusted").unwrap();
    std::fs::write(dir.path().join(".tmp-abandoned"), b"untrusted").unwrap();
    assert!(store.load(&key).is_err());
    store.update(&good, BASE, &key).unwrap();
    assert_eq!(store.load(&key).unwrap().verify(&key).unwrap().sequence, 2);
}

#[test]
fn corrupt_independent_state_cannot_be_repaired_from_an_older_signed_cache() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().into());
    let (key, good, _) = fixture("valid-snapshot");
    store.update(&good, BASE, &key).unwrap();
    let path = dir.path().join("state.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for field in ["schema", "key_id", "manifest_sha256", "sequence"] {
        let mut state = original.clone();
        state[field] = match field {
            "schema" => serde_json::json!(99),
            "sequence" => serde_json::json!(-1),
            _ => serde_json::json!("invalid"),
        };
        let bytes = serde_json::to_vec(&state).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(store.load(&key).is_err(), "{field}");
        assert!(store.update(&good, BASE, &key).is_err(), "{field}");
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }
}

#[test]
fn duplicate_cache_keys_are_refused_before_signature_interpretation() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().into());
    let (key, good, _) = fixture("valid-snapshot");
    store.update(&good, BASE, &key).unwrap();
    let path = dir.path().join("cache/feed.json");
    let original = std::fs::read_to_string(&path).unwrap();
    let duplicate = original.replacen('{', "{\"records\":[],", 1);
    std::fs::write(path, duplicate).unwrap();
    assert!(store.load(&key).is_err());
    store.update(&good, BASE, &key).unwrap();
    assert_eq!(store.load(&key).unwrap().records.len(), 1);
}
