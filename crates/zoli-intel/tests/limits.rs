//! Resource and destination rejection before untrusted input is acted on.
#![allow(clippy::unwrap_used)]
use std::io::Write;
use zoli_intel::{
    feed::*,
    model::Artifact,
    net::{Endpoint, public_ip},
};
#[test]
fn row_limits_blank_rows_and_broken_gzip_are_errors() {
    let mut large = vec![b' '; (2 << 20) + 1];
    large[0] = b'{';
    let end = large.len() - 1;
    large[end] = b'}';
    for bytes in [b"\n".to_vec(), large, b"{}\n\n".to_vec()] {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&bytes).unwrap();
        let mut bytes = encoder.finish().unwrap();
        assert!(decode_rows::<serde_json::Value>(&bytes).is_err());
        bytes.truncate(bytes.len() - 1);
        assert!(decode_rows::<serde_json::Value>(&bytes).is_err());
    }
    assert!(
        verify_artifact(
            b"small",
            &Artifact {
                bytes: MAX_ARTIFACT as i64 + 1,
                sha256: sha256(b"small"),
                ..Default::default()
            }
        )
        .is_err()
    );
}
#[test]
fn destination_policy_rejects_local_special_and_documentation_addresses() {
    for raw in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "198.19.0.1",
        "224.0.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(!public_ip(raw.parse().unwrap()), "{raw}");
    }
    for raw in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
        assert!(public_ip(raw.parse().unwrap()), "{raw}");
    }
    for url in [
        "http://example.invalid",
        "https://user:pass@example.invalid",
        "https://example.invalid?token=hidden",
        "https://example.invalid#fragment",
    ] {
        assert!(
            Endpoint {
                url: url.into(),
                allow_private_network: false,
                ca_file: None
            }
            .parsed()
            .is_err()
        );
    }
}
