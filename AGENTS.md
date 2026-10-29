# Local resource preference

The user requested low CPU usage on 30 October 2026.

- Run builds and tests sequentially, with `CARGO_BUILD_JOBS=1`, `RUST_TEST_THREADS=1` and `GOMAXPROCS=1` as applicable.
- On this Linux desktop, run compute-heavy commands through `systemd-run --user --scope --quiet -p CPUQuota=50% -p CPUWeight=10 nice -n 15 ...`. This caps the whole command tree at half of one CPU core. If unavailable, retain one job and low priority; do not claim a hard cap.
- Prefer focused regression checks. Run Docker, full suites and expensive scans only when the change requires them; avoid concurrent validation jobs.
- Keep these local resource limits separate from hosted CI requirements.
