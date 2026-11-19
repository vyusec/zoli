//! Lossless refusal and input-boundary checks for future Python inventory use.
#![allow(clippy::unwrap_used)]
use zoli_pms::requirements::{MAX_BYTES, MAX_LINES, Requirements};
const REGISTRY: &str = "https://pypi.org";
fn pin(name: &str) -> String {
    format!("{name}==1 --hash=sha256:{}", "a".repeat(64))
}
fn parse(text: &str) -> Requirements {
    Requirements::parse(text, REGISTRY).unwrap()
}

#[test]
fn physical_lines_survive_crlf_and_multiline_hashes() {
    let text = format!(
        "# heading\r\n\r\npkg==1 \\\r\n --hash=sha256:{}\r\n{}\r\n",
        "b".repeat(64),
        pin("second")
    );
    let input = parse(&text);
    assert_eq!(
        input
            .complete_pins()
            .unwrap()
            .iter()
            .map(|p| p.line)
            .collect::<Vec<_>>(),
        [3, 5]
    );
}
#[test]
fn byte_order_mark_is_an_explicit_gap_even_with_later_valid_pins() {
    let input = parse(&format!("\u{feff}{}\n{}", pin("first"), pin("second")));
    assert_eq!(input.packages.len(), 1);
    assert_eq!(input.gaps[0].line, 1);
    assert!(input.complete_pins().is_err());
}
#[test]
fn encoding_directives_cannot_silently_change_interpretation() {
    for declaration in [
        "# coding: latin-1",
        "# -*- coding: unicode_escape -*-",
        "# coding=utf-16",
        "# coding: utf-8",
    ] {
        for prefix in ["", "# heading\n"] {
            let input = parse(&format!("{prefix}{declaration}\n{}", pin("pkg")));
            assert!(input.complete_pins().is_err(), "{declaration}");
            assert_eq!(input.gaps[0].reason, "unsupported_encoding_declaration");
        }
    }
}
#[test]
fn unicode_whitespace_does_not_disappear_around_a_pin() {
    for character in ['\u{a0}', '\u{2003}', '\u{202f}'] {
        for text in [
            format!("{character}{}", pin("pkg")),
            format!("{}{character}", pin("pkg")),
        ] {
            assert!(parse(&text).complete_pins().is_err(), "{text:?}");
        }
    }
}
#[test]
fn escaped_backslashes_do_not_consume_the_next_requirement() {
    let input = parse(&format!("{} \\\\\n{}", pin("bad"), pin("good")));
    assert_eq!(input.packages.len(), 1);
    assert_eq!(input.packages[0].identity.name, "good");
    assert_eq!(input.gaps[0].line, 1);
    assert!(input.complete_pins().is_err());
}
#[test]
fn unfinished_continuation_reports_the_first_physical_line() {
    let input = parse(&format!(
        "{}\nsecond==1 {slash}\n --hash=sha256:{} {slash}",
        pin("first"),
        "b".repeat(64),
        slash = char::from(92)
    ));
    assert_eq!(input.packages.len(), 1);
    assert_eq!(input.gaps[0].line, 2);
    assert_eq!(input.gaps[0].reason, "unterminated_line_continuation");
}
#[test]
fn hash_comment_needs_a_whitespace_delimiter() {
    assert!(
        parse(&format!("{} # explanation", pin("pkg")))
            .complete_pins()
            .is_ok()
    );
    assert!(
        parse(&format!("{}#explanation", pin("pkg")))
            .complete_pins()
            .is_err()
    );
}
#[test]
fn invalid_second_hash_cannot_be_hidden_by_a_valid_first_hash() {
    for suffix in [
        "--hash=sha256:bad",
        "--hash=sha512:bad",
        "--hash sha256:bad",
        "--hash=",
        "--index-url=https://SECRET.invalid",
    ] {
        let input = parse(&format!("{} {suffix}", pin("pkg")));
        assert!(input.packages.is_empty());
        assert!(input.complete_pins().is_err());
        assert!(!serde_json::to_string(&input).unwrap().contains("SECRET"));
    }
}
#[test]
fn multiple_hashes_are_preserved_sorted_and_deduplicated() {
    let input = parse(&format!(
        "{} --hash=sha256:{} --hash=sha256:{} --hash=sha256:{}",
        pin("pkg"),
        "b".repeat(64),
        "A".repeat(64),
        "0".repeat(64)
    ));
    assert_eq!(
        input.complete_pins().unwrap()[0].sha256,
        ["0".repeat(64), "a".repeat(64), "b".repeat(64)]
    );
}
#[test]
fn same_version_duplicate_is_still_an_ambiguous_input() {
    let input = parse(&format!(
        "{}\n{}",
        pin("Some..Package"),
        pin("some_package")
    ));
    assert_eq!(input.packages.len(), 2);
    assert_eq!(input.gaps[0].reason, "duplicate_package_pin");
    assert!(input.complete_pins().is_err());
}
#[test]
fn every_unsupported_physical_line_keeps_its_own_gap() {
    let input = parse(&format!(
        "-r hidden.txt\n{}\n-c constraints.txt\n--no-index\npkg[extra]==1\npkg==1; python_version>'3'",
        pin("valid")
    ));
    assert_eq!(input.packages.len(), 1);
    assert_eq!(
        input.gaps.iter().map(|g| g.line).collect::<Vec<_>>(),
        [1, 3, 4, 5, 6]
    );
    assert!(input.complete_pins().is_err());
}
#[test]
fn byte_and_line_limits_include_ignored_comments() {
    let base = pin("pkg");
    for size in [MAX_BYTES - 1, MAX_BYTES, MAX_BYTES + 1] {
        let text = format!("{base}\n#{}", "x".repeat(size - base.len() - 2));
        assert_eq!(
            Requirements::parse(&text, REGISTRY).is_ok(),
            size <= MAX_BYTES
        );
    }
    for lines in [MAX_LINES - 1, MAX_LINES, MAX_LINES + 1] {
        let text = format!("{}{}", "#\n".repeat(lines - 1), base);
        assert_eq!(
            Requirements::parse(&text, REGISTRY).is_ok(),
            lines <= MAX_LINES
        );
    }
}
#[test]
fn missing_files_and_parent_components_that_are_files_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("requirements.txt");
    assert!(Requirements::read(&file, REGISTRY).is_err());
    std::fs::write(&file, pin("pkg")).unwrap();
    assert!(Requirements::read(&file.join("child"), REGISTRY).is_err());
}
#[test]
fn truncation_and_replacement_are_reparsed_on_every_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("requirements.txt");
    std::fs::write(&path, pin("pkg")).unwrap();
    assert!(
        Requirements::read(&path, REGISTRY)
            .unwrap()
            .complete_pins()
            .is_ok()
    );
    std::fs::write(&path, "pkg==1 --hash=sha256:abc").unwrap();
    assert!(
        Requirements::read(&path, REGISTRY)
            .unwrap()
            .complete_pins()
            .is_err()
    );
    std::fs::write(&path, []).unwrap();
    assert!(
        Requirements::read(&path, REGISTRY)
            .unwrap()
            .complete_pins()
            .is_err()
    );
    // This is a between-read test, not a claim of TOCTOU protection.
}
#[cfg(target_os = "linux")]
#[test]
fn fifo_is_rejected_without_opening_or_waiting_for_a_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("requirements.fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tx.send(Requirements::read(&path, REGISTRY).is_err())
            .unwrap();
    });
    assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap());
}
#[cfg(unix)]
#[test]
fn unreadable_input_is_not_treated_as_an_empty_success() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("requirements.txt");
    std::fs::write(&path, pin("pkg")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Root can read mode-000 files; exercise the refusal on ordinary user/CI hosts.
    if std::fs::File::open(&path).is_ok() {
        eprintln!("mode-000 test unavailable with elevated filesystem access");
        return;
    }
    assert!(Requirements::read(&path, REGISTRY).is_err());
}
