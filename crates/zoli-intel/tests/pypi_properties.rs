//! Small independent invariants supplement the Go differential oracle.
#![allow(clippy::unwrap_used)]
use std::cmp::Ordering::{Equal, Greater, Less};
use zoli_intel::pypi;

#[test]
fn zero_padding_and_leading_zeroes_preserve_release_equality() {
    for (a, b) in [
        ("1", "01.0.0.0"),
        ("0!1.2", "1.02.0"),
        ("v1.2.3", "1.2.3.0"),
    ] {
        assert_eq!(pypi::compare(a, b).unwrap(), Equal);
        assert_eq!(pypi::compare(b, a).unwrap(), Equal);
    }
}

#[test]
fn suffix_aliases_and_separators_preserve_equality() {
    for (a, b) in [
        ("1.0alpha1", "1.0a1"),
        ("1.0preview1", "1.0rc1"),
        ("1.0_post_1", "1.0-1"),
        ("1.0dev", "1.0.dev0"),
        ("1.0+abc-1", "1.0+abc.1"),
    ] {
        assert_eq!(pypi::compare(a, b).unwrap(), Equal, "{a} {b}");
    }
}

#[test]
fn ordinary_suffix_chain_is_antisymmetric_and_transitive() {
    let versions = [
        "1.0.dev0",
        "1.0a0",
        "1.0a1.dev0",
        "1.0a1",
        "1.0b0",
        "1.0rc1",
        "1.0",
        "1.0+abc",
        "1.0.post1.dev0",
        "1.0.post1",
        "1.1",
        "1!0",
    ];
    for (i, a) in versions.iter().enumerate() {
        assert_eq!(pypi::compare(a, a).unwrap(), Equal);
        for b in &versions[i + 1..] {
            assert_eq!(pypi::compare(a, b).unwrap(), Less, "{a} {b}");
            assert_eq!(pypi::compare(b, a).unwrap(), Greater, "{b} {a}");
            for c in &versions[i + 1..] {
                if pypi::compare(b, c).unwrap() == Less {
                    assert_eq!(pypi::compare(a, c).unwrap(), Less);
                }
            }
        }
    }
}

#[test]
fn epoch_and_release_integer_boundaries_are_explicit() {
    assert!(pypi::concrete("255!9223372036854775806"));
    for v in [
        "256!1",
        "-1!1",
        "1!!1",
        "9223372036854775807",
        "18446744073709551616",
    ] {
        assert!(pypi::compare(v, "1").is_err(), "{v}");
    }
    assert_eq!(pypi::compare("255!0", "254!999999999").unwrap(), Greater);
}

#[test]
fn suffix_overflow_remains_an_explicit_go_quirk() {
    assert_eq!(
        pypi::compare("1.0rc18446744073709551616", "1.0rc18446744073709551615").unwrap(),
        Equal
    );
    assert_eq!(
        pypi::compare("1.0rc9223372036854775808", "1.0rc0").unwrap(),
        Less
    );
}

#[test]
fn local_numeric_segments_compare_numerically() {
    assert_eq!(pypi::compare("1+abc.2", "1+abc.10").unwrap(), Less);
    assert_eq!(pypi::compare("1+01", "1+1").unwrap(), Equal);
    assert_eq!(pypi::compare("1+abc", "1+1").unwrap(), Less);
}

#[test]
fn all_ascii_controls_inside_versions_are_refused() {
    for byte in (0..=31).chain([127]) {
        let v = format!("1{}2", char::from(byte));
        assert!(!pypi::concrete(&v), "{byte}");
        assert!(pypi::matches("==1", &v).is_err());
    }
}

#[test]
fn unicode_digit_and_separator_lookalikes_are_refused() {
    for v in [
        "１.0",
        "١.0",
        "1。0",
        "1．0",
        "1!१",
        "1+é",
        "1\u{200d}0",
        "1\u{feff}0",
    ] {
        assert!(pypi::compare(v, "1").is_err(), "{v}");
    }
}

#[test]
fn four_term_reordering_preserves_ordinary_interval_membership() {
    let terms = [">=1", "<5", "!=2", "!=3"];
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let indices = [a, b, c, d];
                    if (0..4).all(|i| indices.contains(&i)) {
                        let constraint = indices.map(|i| terms[i]).join(",");
                        for (v, expected) in [
                            ("0", false),
                            ("1", true),
                            ("2", false),
                            ("3", false),
                            ("4", true),
                            ("5", false),
                        ] {
                            assert_eq!(
                                pypi::matches(&constraint, v).unwrap(),
                                expected,
                                "{constraint}: {v}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn repeated_exclusions_expose_pinned_go_non_idempotence() {
    // Confirmed against generated Go output, not a PEP 440 correctness claim.
    // Repeated terms unexpectedly restore excluded points in the reference.
    for repeats in [1, 2] {
        let constraint = vec!["!=1,!=2"; repeats].join(",");
        for v in ["1", "2"] {
            assert_eq!(pypi::matches(&constraint, v).unwrap(), repeats == 2);
        }
        assert!(pypi::matches(&constraint, "3").unwrap());
    }
}

#[test]
fn epoch_exclusion_unit_spans_keep_the_go_lower_endpoint() {
    for (c, v) in [
        ("<2,!=2!0", "1.0a1"),
        ("!=2!0.0.dev0,<=1", "1"),
        ("!=255!0-2,!=1!1", "1.0.0.1"),
    ] {
        assert!(!pypi::matches(c, v).unwrap(), "{c}: {v}");
    }
}

#[test]
fn contradictory_intersections_still_validate_later_terms() {
    assert!(!pypi::matches(">=3,<1,!=2,>=0", "2").unwrap());
    for tail in ["===1", "==💥", "!=*", "==1\0", "~=1"] {
        assert!(pypi::matches(&format!(">=3,<1,!=2,{tail}"), "2").is_err());
    }
}

#[test]
fn boundary_budget_counts_bytes_not_unicode_characters() {
    // Whitespace trimming must not bypass the raw input budget.
    let at = format!("==1{} ", "\u{2003}".repeat(2729));
    assert_eq!(at.len(), 8191);
    assert!(pypi::matches(&at, "1").unwrap());
    assert!(pypi::matches(&format!("{at} "), "1").unwrap());
    assert!(pypi::matches(&format!("{at}  "), "1").is_err());
}
