//! Real HTTPS redirect, credential and TLS checks against controlled registries.
#![allow(clippy::unwrap_used)]
mod support;
use support::*;
use zoli_intel::{model::Identity, net::Endpoint};
use zoli_proxy::registry::{NpmConfig, Registry, RegistryClient};
fn client(
    server: &Server,
    artifacts: Vec<Endpoint>,
) -> (tempfile::TempDir, RegistryClient, Identity) {
    let home = tempfile::tempdir().unwrap();
    let npmrc = home.path().join("npmrc");
    std::fs::write(
        &npmrc,
        format!(
            "registry={}/npm/\n//{}/npm/:_authToken=REGISTRY_TEST_SECRET\n",
            server.origin,
            server.origin.trim_start_matches("https://")
        ),
    )
    .unwrap();
    let registry = Registry {
        url: format!("{}/npm", server.origin),
        allow_private_network: true,
        ca_file: Some(ca()),
        artifact_hosts: artifacts,
    };
    let identity = Identity {
        ecosystem: "npm".into(),
        name: "fixture".into(),
        version: "1.0.0".into(),
        registry: registry.url.clone(),
        ..Default::default()
    };
    (
        home,
        RegistryClient::new(vec![registry], NpmConfig::load(None, Some(&npmrc)).unwrap()).unwrap(),
        identity,
    )
}
#[test]
fn cross_origin_redirect_never_forwards_registry_credentials() {
    let bytes = package("module.exports=1;");
    let response = bytes.clone();
    let cdn = Server::new(move |_| (200, vec![], response.clone()));
    let destination = format!("{}/download?signature=HIDDEN_QUERY", cdn.origin);
    let registry =
        Server::new(move |_| (302, vec![("Location".into(), destination.clone())], vec![]));
    let (_home, client, id) = client(
        &registry,
        vec![Endpoint {
            url: cdn.origin.clone(),
            allow_private_network: true,
            ca_file: Some(ca()),
        }],
    );
    assert_eq!(
        client
            .acquire(
                &id,
                &format!("{}/npm/fixture.tgz", registry.origin),
                &integrity(&bytes)
            )
            .unwrap(),
        bytes
    );
    assert!(registry.requests.lock().unwrap()[0].contains("Bearer REGISTRY_TEST_SECRET"));
    assert!(
        !cdn.requests.lock().unwrap()[0]
            .to_ascii_lowercase()
            .contains("authorization:")
    );
}
#[test]
fn same_origin_redirect_outside_credential_path_gets_no_token() {
    let bytes = package("module.exports=1;");
    let response = bytes.clone();
    let registry = Server::new(move |request| {
        if request.starts_with("GET /npm/") {
            (
                302,
                vec![("Location".into(), "/other/fixture.tgz".into())],
                vec![],
            )
        } else {
            (200, vec![], response.clone())
        }
    });
    let (_home, client, id) = client(&registry, vec![]);
    client
        .acquire(
            &id,
            &format!("{}/npm/fixture.tgz", registry.origin),
            &integrity(&bytes),
        )
        .unwrap();
    let requests = registry.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].contains("Bearer REGISTRY_TEST_SECRET"));
    assert!(!requests[1].to_ascii_lowercase().contains("authorization:"));
}
#[test]
fn unapproved_or_http_redirect_and_redirect_loops_fail_closed() {
    for target in [
        "https://unapproved.example.invalid/pkg?secret=HIDDEN_QUERY",
        "http://127.0.0.1/pkg",
        "/npm/loop",
    ] {
        let registry =
            Server::new(move |_| (302, vec![("Location".into(), target.into())], vec![]));
        let (_home, client, id) = client(&registry, vec![]);
        let error = format!(
            "{:#}",
            client
                .acquire(
                    &id,
                    &format!("{}/npm/fixture.tgz", registry.origin),
                    &integrity(b"unused")
                )
                .unwrap_err()
        );
        assert!(!error.contains("HIDDEN_QUERY") && !error.contains("REGISTRY_TEST_SECRET"));
        assert!(registry.requests.lock().unwrap().len() <= 4);
    }
}
#[test]
fn private_endpoint_requires_both_operator_opt_in_and_trusted_certificate() {
    let bytes = package("module.exports=1;");
    let response = bytes.clone();
    let server = Server::new(move |_| (200, vec![], response.clone()));
    for (private, ca_file) in [(false, Some(ca())), (true, None)] {
        let registry = Registry {
            url: format!("{}/npm", server.origin),
            allow_private_network: private,
            ca_file,
            artifact_hosts: vec![],
        };
        let id = Identity {
            ecosystem: "npm".into(),
            name: "fixture".into(),
            version: "1.0.0".into(),
            registry: registry.url.clone(),
            ..Default::default()
        };
        let client = RegistryClient::new(vec![registry], NpmConfig::default()).unwrap();
        assert!(
            client
                .acquire(
                    &id,
                    &format!("{}/npm/fixture.tgz", server.origin),
                    &integrity(&bytes)
                )
                .is_err()
        );
    }
    assert!(server.requests.lock().unwrap().is_empty());
}
