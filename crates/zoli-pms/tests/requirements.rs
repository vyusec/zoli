//! Regression cases for the nonexecuting, exact/hash-pinned input contract.
#![allow(clippy::unwrap_used)]
use zoli_pms::requirements::{MAX_BYTES, MAX_LINES, Requirements};

const REGISTRY: &str = "https://pypi.org/simple/";
fn pin(spec: &str) -> String {
    format!("{spec} --hash=sha256:{}", "a".repeat(64))
}

#[test]
fn grammar_rejects_feed_only_quirks_and_ambiguous_package_names() {
    for spec in [
        "pkg==1..a1",
        "pkg==1.0+abc..x",
        "pkg==1!v1.0",
        "pkg-==1",
        "pkg_==1",
        "pkg.==1",
        "pkg==1.*",
        "pkg===1",
        "pkg[extra]==1",
        "pkg==1;python_version>'3'",
    ] {
        let input = Requirements::parse(&pin(spec), REGISTRY).unwrap();
        assert!(input.packages.is_empty(), "{spec}");
        assert!(input.complete_pins().is_err(), "{spec}");
    }
    for version in [
        "1",
        "01.0",
        "v1.0",
        "1!1.0",
        "1.0RC1",
        "1.0-2",
        "1.0_post_1",
        "1.0.dev1",
        "1.0+ABC-1",
    ] {
        let input =
            Requirements::parse(&pin(&format!("Some_Package=={version}")), REGISTRY).unwrap();
        let packages = input.complete_pins().unwrap();
        assert_eq!(packages[0].identity.name, "some-package");
        assert_eq!(packages[0].identity.version, version);
        assert_eq!(packages[0].identity.registry, "https://pypi.org");
    }
}

#[test]
fn unsupported_inputs_are_never_hidden_among_valid_pins() {
    for unsupported in [
        "-r private.txt",
        "-c constraints.txt",
        "--index-url=https://user:SECRET@example.org",
        "--extra-index-url https://example.org",
        "--trusted-host example.org",
        "-e .",
        "pkg @ https://user:SECRET@example.org/file.whl",
        "${SECRET}",
        "--require-hashes",
        "--no-deps",
        "./local.whl",
    ] {
        let text = format!("{}\n{unsupported}\n{}\n", pin("first==1"), pin("last==1"));
        let input = Requirements::parse(&text, REGISTRY).unwrap();
        assert_eq!(input.packages.len(), 2);
        assert_eq!(input.gaps.len(), 1);
        assert_eq!(input.gaps[0].line, 2);
        assert!(input.complete_pins().is_err());
        let report = serde_json::to_string(&input).unwrap();
        assert!(!report.contains("SECRET") && !report.contains("private.txt"));
    }
    for bad_hash in ["sha256:", "sha256:xyz", "sha512:abcdef", "SHA256:abcdef"] {
        let input = Requirements::parse(&format!("pkg==1 --hash={bad_hash}"), REGISTRY).unwrap();
        assert!(input.complete_pins().is_err());
    }
}

#[test]
fn comment_and_continuation_order_cannot_hide_extra_requirements() {
    let valid = pin("pkg==1");
    let input = Requirements::parse(&format!("# comment\r\n{valid}\r\n"), REGISTRY).unwrap();
    assert_eq!(input.complete_pins().unwrap()[0].line, 2);
    // Continuation happens before stripping comments. The next physical line
    // is part of this comment, and must not be falsely counted as an approved pin.
    let input = Requirements::parse(&format!("# comment \\\n{valid}\n"), REGISTRY).unwrap();
    assert!(input.packages.is_empty());
    assert!(input.complete_pins().is_err());
    let input = Requirements::parse(&format!("{valid} \\\n{}", pin("other==2")), REGISTRY).unwrap();
    assert!(input.packages.is_empty());
    assert!(input.complete_pins().is_err());
    for control in ['\0', '\r', '\u{000b}', '\u{001b}'] {
        let input = Requirements::parse(&format!("{control}{valid}"), REGISTRY).unwrap();
        assert_eq!(input.gaps[0].reason, "unsupported_control_character");
    }
}

#[test]
fn duplicate_normalization_and_hash_deduplication_preserve_completeness() {
    let text = format!("{} --hash=sha256:{}", pin("pkg==1"), "A".repeat(64));
    let input = Requirements::parse(&text, REGISTRY).unwrap();
    assert_eq!(input.complete_pins().unwrap()[0].sha256.len(), 1);
    let text = format!("{}\n{}", pin("Some_Package==1"), pin("some-package==2"));
    let input = Requirements::parse(&text, REGISTRY).unwrap();
    assert_eq!(input.packages.len(), 2);
    assert_eq!(input.gaps[0].reason, "duplicate_package_pin");
    assert!(input.complete_pins().is_err());
}

#[test]
fn file_and_parser_boundaries_refuse_invalid_or_unbounded_input() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("requirements.txt");
    std::fs::write(&file, pin("pkg==1")).unwrap();
    assert!(
        Requirements::read(&file, REGISTRY)
            .unwrap()
            .complete_pins()
            .is_ok()
    );
    assert!(Requirements::read(dir.path(), REGISTRY).is_err());
    std::fs::write(&file, [0xff, 0xfe]).unwrap();
    assert!(Requirements::read(&file, REGISTRY).is_err());
    let maximum = format!("#{}", "x".repeat(MAX_BYTES - 1));
    assert!(Requirements::parse(&maximum, REGISTRY).is_ok());
    assert!(Requirements::parse(&format!("{maximum}x"), REGISTRY).is_err());
    std::fs::write(&file, format!("{maximum}x")).unwrap();
    assert!(Requirements::read(&file, REGISTRY).is_err());
    assert!(Requirements::parse(&"\n".repeat(MAX_LINES), REGISTRY).is_ok());
    assert!(Requirements::parse(&"\n".repeat(MAX_LINES + 1), REGISTRY).is_err());
    assert!(Requirements::parse("", "https://user:SECRET@example.org").is_err());
    #[cfg(unix)]
    {
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(Requirements::read(&link, REGISTRY).is_err());
        let socket = dir.path().join("socket");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert!(Requirements::read(&socket, REGISTRY).is_err());
    }
}
