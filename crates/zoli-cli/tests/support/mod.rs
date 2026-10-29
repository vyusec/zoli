#![allow(dead_code, clippy::unwrap_used)]
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha512};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use zoli_intel::{
    feed::{Envelope, Store, key_id, sha256},
    model::*,
    net::Fetch,
    wire::Mode,
};
pub const FEED: &str = "https://feed.example.invalid/feed";
pub fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes) in files {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(bytes.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, path, *bytes).unwrap();
    }
    gzip(&builder.into_inner().unwrap())
}
pub fn package(source: &str) -> Vec<u8> {
    archive(&[("package/package.json",br#"{"name":"fixture","version":"1.0.0","main":"index.js","scripts":{"postinstall":"node index.js"}}"#),("package/index.js",source.as_bytes())])
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut writer = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    writer.write_all(bytes).unwrap();
    writer.finish().unwrap()
}
pub fn integrity(bytes: &[u8]) -> String {
    format!("sha512-{}", STANDARD.encode(Sha512::digest(bytes)))
}
pub fn record(classification: &str, registry: &str) -> Record {
    let cases: Value = serde_json::from_str(include_str!(
        "../../../../testdata/conformance/record-encoding.json"
    ))
    .unwrap();
    let mut record: Record = serde_json::from_value(cases[0]["record"].clone()).unwrap();
    record.classification = classification.into();
    let affected = &mut record.affected.as_mut().unwrap()[0];
    affected.package.name = "fixture".into();
    affected.package.registry = registry.into();
    affected.versions = Some(vec!["1.0.0".into()]);
    record.validate().unwrap();
    record
}
pub fn home(records: Vec<Record>) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    publish(home.path(), records, 0, None);
    let key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    let config = json!({"config_version":1,"feed":{"url":FEED,"public_key":STANDARD.encode(key)}});
    std::fs::write(
        home.path().join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    home
}
pub fn publish(home: &Path, records: Vec<Record>, age_seconds: i64, source_error: Option<&str>) {
    publish_with_sequence(home, records, age_seconds, source_error, 1);
}
pub fn publish_with_sequence(
    home: &Path,
    records: Vec<Record>,
    age_seconds: i64,
    source_error: Option<&str>,
    sequence: i64,
) {
    let signing = SigningKey::from_bytes(&[7; 32]);
    let key = signing.verifying_key().to_bytes();
    let now = GoTime::now();
    let old = GoTime::parse(
        &time::OffsetDateTime::now_utc()
            .checked_sub(time::Duration::seconds(age_seconds))
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    )
    .unwrap();
    let rows = records
        .iter()
        .map(|r| format!("{}\n", r.go_json(Mode::Marshal).unwrap()))
        .collect::<String>();
    let compressed = gzip(rows.as_bytes());
    let manifest = Manifest {
        schema_version: "1.0".into(),
        sequence,
        generated_at: now.clone(),
        record_count: records.len() as i64,
        records_sha256: records_hash(&records).unwrap(),
        sources: Some(vec![SourceState {
            name: "fixture".into(),
            last_success: Some(old),
            error: source_error.unwrap_or_default().into(),
            coverage: "selective".into(),
            ..Default::default()
        }]),
        coverage: Some(
            ["npm", "PyPI"]
                .into_iter()
                .map(|ecosystem| Coverage {
                    ecosystem: ecosystem.into(),
                    mode: "reports_and_selective_analysis".into(),
                    limitations: Some(vec!["Synthetic fixture".into()]),
                })
                .collect(),
        ),
        files: Some(vec![Artifact {
            path: "snapshot.json.gz".into(),
            sha256: sha256(&compressed),
            bytes: compressed.len() as i64,
            kind: "snapshot".into(),
            created_at: now,
            ..Default::default()
        }]),
        ..Default::default()
    };
    let raw = serde_json::to_string(&manifest).unwrap();
    let signature = STANDARD.encode(signing.sign(raw.as_bytes()).to_bytes());
    let envelope = Envelope {
        manifest: serde_json::value::RawValue::from_string(raw).unwrap(),
        key_id: key_id(&key),
        signature,
    };
    struct Memory(BTreeMap<String, Vec<u8>>);
    impl Fetch for Memory {
        fn get(&self, u: &str, max: usize) -> anyhow::Result<Vec<u8>> {
            let bytes = self
                .0
                .get(u)
                .ok_or_else(|| anyhow::anyhow!("missing response"))?;
            anyhow::ensure!(bytes.len() <= max, "too large");
            Ok(bytes.clone())
        }
    }
    let responses = BTreeMap::from([
        (
            format!("{FEED}/latest.json"),
            serde_json::to_vec(&envelope).unwrap(),
        ),
        (format!("{FEED}/snapshot.json.gz"), compressed),
    ]);
    Store::new(home.into())
        .update(&Memory(responses), FEED, &key)
        .unwrap();
}
pub fn command(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zoli"))
        .env_clear()
        .env("HOME", home)
        .env("ZOLI_HOME", home)
        .args(args)
        .output()
        .unwrap()
}
pub fn result(output: Output, code: i32) -> Value {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
pub fn configure(home: &Path, change: impl FnOnce(&mut Value)) {
    let path = home.join("config.json");
    let mut config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    change(&mut config);
    std::fs::write(path, serde_json::to_vec(&config).unwrap()).unwrap();
}
pub fn project(dir: &Path, url: &str, bytes: &[u8]) -> PathBuf {
    let root = json!({"name":"fixture-project","dependencies":{"fixture":"1.0.0"}});
    let lock = json!({"lockfileVersion":3,"packages":{"":root,"node_modules/fixture":{"version":"1.0.0","resolved":url,"integrity":integrity(bytes)}}});
    std::fs::write(dir.join("package.json"), serde_json::to_vec(&root).unwrap()).unwrap();
    let path = dir.join("package-lock.json");
    std::fs::write(&path, serde_json::to_vec(&lock).unwrap()).unwrap();
    path
}
pub fn ca() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/mock-registry/tls/ca.pem")
}
pub type Requests = Arc<Mutex<Vec<String>>>;
pub struct Server {
    pub origin: String,
    pub requests: Requests,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Server {
    pub fn new(
        response: impl Fn(&str) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + 'static,
    ) -> Self {
        let cert = CertificateDer::from_pem_slice(include_bytes!(
            "../../../../testdata/mock-registry/tls/server.pem"
        ))
        .unwrap();
        let key = PrivateKeyDer::from_pem_slice(include_bytes!(
            "../../../../testdata/mock-registry/tls/server.key"
        ))
        .unwrap();
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("https://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let requests = Arc::new(Mutex::new(vec![]));
        let collected = requests.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                let (socket, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => return,
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut stream =
                    StreamOwned::new(ServerConnection::new(config.clone()).unwrap(), socket);
                let mut header = Vec::new();
                let mut byte = [0];
                while header.len() < 16_384 && !header.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => header.push(byte[0]),
                        _ => break,
                    }
                }
                if !header.ends_with(b"\r\n\r\n") {
                    continue;
                }
                let header = String::from_utf8(header).unwrap();
                collected.lock().unwrap().push(header.clone());
                let (status, headers, body) = response(&header);
                let mut out = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (name, value) in headers {
                    out.push_str(&format!("{name}: {value}\r\n"));
                }
                out.push_str("\r\n");
                let _ = stream.write_all(out.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        Self {
            origin,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    pub fn registry(&self) -> Value {
        json!({"url":format!("{}/npm",self.origin),"allow_private_network":true,"ca_file":ca()})
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
