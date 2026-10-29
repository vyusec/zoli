//! Inventory fixtures cover npm's installed-location graph rather than resolving.
#![allow(clippy::unwrap_used)]
use serde_json::{Value, json};
use zoli_pms::inventory::Inventory;
fn inventory(project: Value, packages: Value, version: u64) -> Inventory {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        serde_json::to_vec(&project).unwrap(),
    )
    .unwrap();
    std::fs::write(
        dir.path().join("package-lock.json"),
        serde_json::to_vec(&json!({"lockfileVersion":version,"packages":packages})).unwrap(),
    )
    .unwrap();
    Inventory::from_lock(&dir.path().join("package-lock.json"), |name| {
        Ok(if name.starts_with("@private/") {
            "https://private.example.invalid/npm"
        } else {
            "https://registry.npmjs.org"
        }
        .into())
    })
    .unwrap()
}
fn package(version: &str) -> Value {
    json!({"version":version,"resolved":"https://registry.npmjs.org/fixture/-/fixture.tgz","integrity":"sha512-test"})
}
#[test]
fn nested_versions_scopes_aliases_and_all_dependency_kinds_survive() {
    let root = json!({"dependencies":{"a":"^1.0.0","alias":"npm:actual@2.0.0","@private/pkg":"1.0.0"},"devDependencies":{"dev":"1.0.0"},"optionalDependencies":{"optional":"1.0.0"},"peerDependencies":{"peer":"1.0.0"}});
    let mut a = package("1.0.0");
    a["dependencies"] = json!({"child":"1.0.0"});
    a["devDependencies"] = json!({"not-installed":"1.0.0"});
    let mut alias = package("2.0.0");
    alias["name"] = json!("actual");
    let mut dev = package("1.0.0");
    dev["dev"] = json!(true);
    let mut optional = package("1.0.0");
    optional["optional"] = json!(true);
    let mut peer = package("1.0.0");
    peer["peer"] = json!(true);
    let packages = json!({"":root,"node_modules/a":a,"node_modules/a/node_modules/child":package("1.0.0"),"node_modules/child":package("2.0.0"),"node_modules/alias":alias,"node_modules/@private/pkg":package("1.0.0"),"node_modules/dev":dev,"node_modules/optional":optional,"node_modules/peer":peer});
    for version in [2, 3] {
        let inv = inventory(root.clone(), packages.clone(), version);
        assert!(inv.gaps.is_empty(), "{:?}", inv.gaps);
        let child = inv
            .packages
            .iter()
            .find(|p| p.path == "node_modules/a/node_modules/child")
            .unwrap();
        assert_eq!(
            child.introduced_by,
            ["node_modules/a", "node_modules/a/node_modules/child"]
        );
        assert_eq!(child.parents, ["node_modules/a"]);
        assert_eq!(
            inv.packages
                .iter()
                .filter(|p| p.identity.name == "child")
                .count(),
            2
        );
        assert_eq!(
            inv.packages
                .iter()
                .find(|p| p.path == "node_modules/alias")
                .unwrap()
                .identity
                .name,
            "actual"
        );
        assert_eq!(
            inv.packages
                .iter()
                .find(|p| p.identity.name == "@private/pkg")
                .unwrap()
                .identity
                .registry,
            "https://private.example.invalid/npm"
        );
        assert!(
            inv.packages.iter().any(|p| p.dev)
                && inv.packages.iter().any(|p| p.optional)
                && inv.packages.iter().any(|p| p.peer)
        );
    }
}
#[test]
fn absent_optional_dependencies_links_stale_locks_and_bundles_are_explicit() {
    let project = json!({"dependencies":{"linked":"file:../local","bundle":"1.0.0"},"optionalDependencies":{"absent":"1.0.0"}});
    let mut bundle = package("1.0.0");
    bundle["dependencies"] = json!({"child":"1.0.0"});
    let inv = inventory(
        project,
        json!({"":{},"node_modules/linked":{"link":true,"resolved":"../local"},"node_modules/bundle":bundle,"node_modules/bundle/node_modules/child":{"version":"1.0.0","inBundle":true}}),
        3,
    );
    assert!(
        inv.gaps
            .iter()
            .any(|g| g.reason == "project_manifest_and_lockfile_disagree")
    );
    assert!(
        inv.gaps
            .iter()
            .any(|g| g.reason == "unresolved_dependency:absent")
    );
    assert!(inv.gaps.iter().any(|g| g.path == "node_modules/linked"));
    let bundled = inv.packages.iter().find(|p| p.bundled).unwrap();
    assert!(bundled.resolved.is_none());
    assert!(!inv.gaps.iter().any(|g| g.path == bundled.path));
    assert!(!serde_json::to_string(&inv).unwrap().contains("fixture.tgz"));
}
#[test]
fn shrinkwrap_precedence_bad_versions_and_unsafe_paths_refuse() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("package.json"), "{}").unwrap();
    let lock = dir.path().join("package-lock.json");
    for value in [
        json!({"lockfileVersion":1,"packages":{"":{}}}),
        json!({"lockfileVersion":3,"packages":{"":{},"../outside":{}}}),
        json!({"lockfileVersion":3,"packages":{"":{},"node_modules/a\n":{}}}),
    ] {
        std::fs::write(&lock, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(Inventory::from_lock(&lock, |_| Ok("https://registry.npmjs.org".into())).is_err());
    }
    std::fs::write(&lock, b"{\"lockfileVersion\":3,\"packages\":{\"\":{}}}").unwrap();
    std::fs::write(
        dir.path().join("npm-shrinkwrap.json"),
        std::fs::read(&lock).unwrap(),
    )
    .unwrap();
    assert!(Inventory::from_lock(&lock, |_| Ok("https://registry.npmjs.org".into())).is_err());
    Inventory::from_lock(&dir.path().join("npm-shrinkwrap.json"), |_| {
        Ok("https://registry.npmjs.org".into())
    })
    .unwrap();
}

#[test]
fn malformed_dependency_declarations_cannot_become_an_empty_complete_inventory() {
    let dir = tempfile::tempdir().unwrap();
    let lock = dir.path().join("package-lock.json");
    for project in [
        json!([]),
        json!(null),
        json!({"dependencies": []}),
        json!({"dependencies": {"fixture": null}}),
        json!({"dependencies": {"fixture": " "}}),
        json!({"optionalDependencies": "fixture"}),
    ] {
        std::fs::write(
            dir.path().join("package.json"),
            serde_json::to_vec(&project).unwrap(),
        )
        .unwrap();
        std::fs::write(
            &lock,
            serde_json::to_vec(&json!({"lockfileVersion":3,"packages":{"":project}})).unwrap(),
        )
        .unwrap();
        assert!(Inventory::from_lock(&lock, |_| Ok("https://registry.npmjs.org".into())).is_err());
    }
    std::fs::write(dir.path().join("package.json"), "{}").unwrap();
    for entry in [
        json!([]),
        json!({"dependencies": []}),
        json!({"peerDependencies":{"missing":false}}),
    ] {
        std::fs::write(
            &lock,
            serde_json::to_vec(
                &json!({"lockfileVersion":3,"packages":{"":{},"node_modules/fixture":entry}}),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(Inventory::from_lock(&lock, |_| Ok("https://registry.npmjs.org".into())).is_err());
    }
}

#[test]
fn workspace_declarations_remain_incomplete_even_without_link_entries() {
    let project = json!({"workspaces":["packages/*"]});
    let inv = inventory(project.clone(), json!({"":project}), 3);
    assert!(
        inv.gaps
            .iter()
            .any(|g| g.reason == "unsupported_workspace_configuration")
    );
}
