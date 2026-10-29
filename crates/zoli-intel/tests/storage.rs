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
