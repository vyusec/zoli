//! Resource refusal is distinct from an ordinary version/constraint non-match.
#![allow(clippy::unwrap_used)]
use zoli_intel::pypi::{self, MAX_RELEASE_COMPONENTS, MAX_VERSION_BYTES};

#[test]
fn version_limits_are_inclusive_and_apply_to_both_operands() {
    let maximum = format!("1+{}", "a".repeat(MAX_VERSION_BYTES - 2));
    assert!(pypi::concrete(&maximum));
    let too_long = format!("{maximum}a");
    assert!(!pypi::concrete(&too_long));
    assert!(pypi::compare(&too_long, "1").is_err());
    assert!(pypi::compare("1", &too_long).is_err());
    let components = vec!["1"; MAX_RELEASE_COMPONENTS].join(".");
    assert!(pypi::concrete(&components));
    assert!(!pypi::concrete(&format!("{components}.1")));
    assert!(pypi::matches(&format!("=={components}.1"), "1").is_err());
}

#[test]
fn constraint_limits_validate_the_entire_expression() {
    let maximum = format!("==1{}", " ".repeat(8192 - 3));
    assert!(pypi::matches(&maximum, "1").unwrap());
    assert!(pypi::matches(&format!("{maximum} "), "1").is_err());
    let terms = vec![">=0"; 128].join(",");
    assert!(pypi::matches(&terms, "1").unwrap());
    assert!(pypi::matches(&format!("{terms},>=0"), "1").is_err());
    // Neither an already-empty intersection nor a prior match hides bad input.
    for text in [">2,<1,broken", "==1,===1", "==1,", "!=1,!=2,!=3,,>=0"] {
        assert!(pypi::matches(text, "1").is_err(), "{text}");
    }
    let exclusions = (1..=128)
        .map(|n| format!("!={n}.0.0"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(!pypi::matches(&exclusions, "1").unwrap());
    assert!(pypi::matches(&exclusions, "129").unwrap());
}

#[test]
fn malformed_unicode_and_controls_never_panic_or_become_matches() {
    for invalid in [
        "💥",
        "1\0",
        "1\u{202e}",
        "1\u{200b}",
        "1..1",
        "1.*",
        "1.0+💥",
    ] {
        assert!(!pypi::concrete(invalid), "{invalid:?}");
        assert!(pypi::matches(">=0", invalid).is_err());
    }
    for invalid in ["==💥", "==1\0", "==1\u{202e}", ">=1\n<2", "==1,\u{200b}>=0"] {
        assert!(pypi::matches(invalid, "1").is_err(), "{invalid:?}");
    }
}
