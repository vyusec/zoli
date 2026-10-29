use anyhow::{Context, Result};
use std::{
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zoli_inspect::{Limits, Report};
use zoli_intel::{feed::read_bounded, model::Identity};

/// Run only this binary's parser worker; no package-provided executable is used.
pub fn inspect(bytes: &[u8], identity: Identity, limits: &Limits) -> Report {
    match run(bytes, &identity, limits) {
        Ok(report) => report,
        Err(_) => Report::failed(
            identity,
            bytes,
            limits,
            "inspection_worker_failed_or_exceeded_resource_budget",
        ),
    }
}
fn run(bytes: &[u8], identity: &Identity, limits: &Limits) -> Result<Report> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("artifact.tgz");
    let mut archive = tempfile::NamedTempFile::new_in(temporary.path())?;
    archive.write_all(bytes)?;
    archive.persist(&path).map_err(|e| e.error)?;
    let output = tempfile::NamedTempFile::new_in(temporary.path())?;
    let mut child = Command::new(std::env::current_exe()?)
        .arg("__inspect-worker")
        .arg(&path)
        .arg("--identity")
        .arg(serde_json::to_string(identity)?)
        .arg("--limits")
        .arg(serde_json::to_string(limits)?)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(output.reopen()?)
        .stderr(Stdio::null())
        .spawn()
        .context("cannot start isolated parser worker")?;
    let started = Instant::now();
    let pid = sysinfo::Pid::from_u32(child.id());
    let mut system = sysinfo::System::new();
    let status = loop {
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            true,
            sysinfo::ProcessRefreshKind::nothing().with_memory(),
        );
        let result = child.try_wait();
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(status) = result? {
            break status;
        }
        let memory = system.process(pid).map(|p| p.memory());
        if started.elapsed() > Duration::from_secs(limits.worker_seconds)
            || memory.is_none_or(|m| m > limits.worker_memory_bytes)
        {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("worker resource limit exceeded or unavailable");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    anyhow::ensure!(status.success(), "inspection worker failed");
    let bytes = read_bounded(output.path(), 16 << 20)?;
    let report: Report = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        report.schema == 1
            && report.limits == *limits
            && report.artifact_sha256
                == zoli_intel::feed::sha256(&read_bounded(&path, limits.max_artifact_bytes)?)
            && report.identity.name == identity.name
            && report.identity.version == identity.version
            && report.identity.registry == identity.registry,
        "worker report identity mismatch"
    );
    Ok(report)
}
