//! Fixed-seed differential cases from the actual pinned Go library.
#![allow(clippy::unwrap_used)]
use std::io::Read;
use zoli_intel::pypi;

#[test]
fn seeded_comparisons_and_long_intersections_match_go() {
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(
        &include_bytes!("../../../testdata/conformance/pypi-seeded.json.gz")[..],
    )
    .take(32 << 20)
    .read_to_end(&mut bytes)
    .unwrap();
    let corpus: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(corpus["seed"], 0x5a4f4c493033_u64);
    assert_eq!(corpus["comparisons"].as_array().unwrap().len(), 25_000);
    assert_eq!(corpus["matches"].as_array().unwrap().len(), 75_000);
    let mut differences = Vec::new();
    let mut failures = 0;
    for kind in ["comparisons", "matches"] {
        for (index, row) in corpus[kind].as_array().unwrap().iter().enumerate() {
            let a = row[0].as_str().unwrap();
            let b = row[1].as_str().unwrap();
            let actual = if kind == "comparisons" {
                pypi::compare(a, b).map(|order| serde_json::json!(order as i32))
            } else {
                pypi::matches(a, b).map(serde_json::Value::Bool)
            };
            if actual.as_ref().ok() != (!row[2].is_null()).then_some(&row[2]) {
                failures += 1;
                if differences.len() < 25 {
                    differences.push(format!(
                        "{kind}[{index}] {a:?} {b:?}: {actual:?}; expected {}",
                        row[2]
                    ));
                }
            }
        }
    }
    assert_eq!(failures, 0, "{}", differences.join("\n"));
}
