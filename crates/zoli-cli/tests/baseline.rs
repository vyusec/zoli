//! Manual, reproducible first/repeated assessment measurements; no latency gate.
#![allow(clippy::unwrap_used)]
mod support;
use serde_json::json;
use std::{collections::BTreeMap, time::Instant};
use support::*;

#[test]
#[ignore = "manual timing baseline; run with --ignored --nocapture"]
fn first_and_repeated_dependency_assessments() {
    let definitions = [
        ("fixture", "1.0.0"),
        ("child", "1.0.0"),
        ("child", "2.0.0"),
        ("@scope/tool", "2.0.0"),
    ];
    let artifacts: BTreeMap<_,_>=definitions.iter().enumerate().map(|(i,(name,version))|{
        let manifest=serde_json::to_vec(&json!({"name":name,"version":version,"main":"index.js","scripts":{"postinstall":"node index.js"}})).unwrap();
        let source=format!("// Synthetic benign fixture\n{}\nmodule.exports = 42;", "function example(value) { return value + 1; }\n".repeat(1000));
        (format!("/npm/{i}.tgz"),archive(&[("package/package.json",&manifest),("package/index.js",source.as_bytes())]))
    }).collect();
    let response = artifacts.clone();
    let server = Server::new(move |request| {
        let path = request.split_whitespace().nth(1).unwrap();
        (200, vec![], response[path].clone())
    });
    let home = home(vec![]);
    configure(home.path(), |c| {
        c["registries"] = json!({"npm":[server.registry()]})
    });
    let project_dir = tempfile::tempdir().unwrap();
    let root = json!({"dependencies":{"fixture":"1.0.0","child":"1.0.0"},"devDependencies":{"@scope/tool":"2.0.0"}});
    let paths = [
        "node_modules/fixture",
        "node_modules/child",
        "node_modules/fixture/node_modules/child",
        "node_modules/@scope/tool",
    ];
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), root.clone());
    for (i, path) in paths.iter().enumerate() {
        packages.insert((*path).into(),json!({"version":definitions[i].1,"resolved":format!("{}/npm/{i}.tgz",server.origin),"integrity":integrity(&artifacts[&format!("/npm/{i}.tgz")]),"dev":i==3}));
    }
    packages.get_mut(paths[0]).unwrap()["dependencies"] = json!({"child":"2.0.0"});
    std::fs::write(
        project_dir.path().join("package.json"),
        serde_json::to_vec(&root).unwrap(),
    )
    .unwrap();
    let lock = project_dir.path().join("package-lock.json");
    std::fs::write(
        &lock,
        serde_json::to_vec(&json!({"lockfileVersion":3,"packages":packages})).unwrap(),
    )
    .unwrap();
    let npmrc = home.path().join("npmrc");
    std::fs::write(&npmrc, format!("registry={}/npm", server.origin)).unwrap();
    let args = [
        "--json",
        "scan",
        "--lockfile",
        lock.to_str().unwrap(),
        "--npmrc",
        npmrc.to_str().unwrap(),
    ];
    let mut runs = vec![];
    for index in 0..6 {
        let start = Instant::now();
        let report = result(command(home.path(), &args), 0);
        assert_eq!(report["decision"]["complete"], true);
        runs.push(json!({"kind":if index==0{"first"}else{"repeated"},"wall_ms":start.elapsed().as_millis(),"stages_ms":report["timings_ms"],"complete":true,"packages":report["packages"].as_array().unwrap().len()}));
    }
    let report = json!({"schema":1,"measured_at":zoli_intel::model::GoTime::now(),"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"profile":if cfg!(debug_assertions){"debug"}else{"release"},"fixture":{"packages":4,"source_files":4,"source_bytes_per_package_approx":44_000,"compressed_bytes":artifacts.values().map(Vec::len).sum::<usize>(),"first_run":"fresh Zoli state; no artifact or analysis-result cache","repeated_runs":5,"registry":"controlled local HTTPS with certificate verification","feed":"signed synthetic empty feed"},"runs":runs,"artifact_requests":server.requests.lock().unwrap().len(),"limitations":["OS caches were not flushed","Loopback registry timings do not represent internet downloads","Synthetic benign fixtures do not measure detection accuracy","No latency target or result-cache optimization"]});
    if let Some(path) = std::env::var_os("ZOLI_BASELINE_OUT") {
        let path = std::path::PathBuf::from(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
