//! End-to-end CLI integration tests. These exercise the real `pulse` binary
//! against the committed sample snapshots under `examples/`.

use std::path::PathBuf;
use std::process::Command;

fn pulse_bin() -> PathBuf {
    // `CARGO_BIN_EXE_pulse` is set by Cargo for integration tests of the
    // package's binary target.
    PathBuf::from(env!("CARGO_BIN_EXE_pulse"))
}

fn examples_dir() -> PathBuf {
    // Integration tests run from the crate root's `tests/` dir; `CARGO_MANIFEST_DIR`
    // points at the crate root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples")
}

#[test]
fn cli_diff_integration() {
    let bin = pulse_bin();
    let base = examples_dir().join("baseline.json");
    let cur = examples_dir().join("current.json");

    let out = Command::new(&bin)
        .arg("diff")
        .arg(&base)
        .arg(&cur)
        .output()
        .expect("failed to spawn pulse");

    assert!(out.status.success(), "pulse diff should exit 0");
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");

    // Parse the emitted Diff JSON and assert key fields.
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("diff output must be valid JSON");
    assert_eq!(v["new_processes"].as_array().unwrap().len(), 1);
    assert_eq!(v["new_processes"][0]["pid"].as_u64().unwrap(), 31337);
    assert_eq!(v["new_external_connections"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["new_external_connections"][0]["remote_addr"]
            .as_str()
            .unwrap(),
        "203.0.113.66:443"
    );
}

#[test]
fn cli_verdict_alert_integration() {
    let bin = pulse_bin();
    let base = examples_dir().join("baseline.json");
    let cur = examples_dir().join("current.json");

    let out = Command::new(&bin)
        .arg("verdict")
        .arg(&base)
        .arg(&cur)
        .output()
        .expect("failed to spawn pulse");

    // A public external connection => ALERT, which exits with code 1.
    assert_eq!(
        out.status.code(),
        Some(1),
        "public C2 conn should be ALERT (exit 1)"
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("verdict output must be valid JSON");
    assert_eq!(v["verdict"].as_str().unwrap(), "ALERT");
    assert_eq!(v["public_external"].as_array().unwrap().len(), 1);
}

#[test]
fn cli_diff_roundtrip_is_stable() {
    // diffing a snapshot against itself must produce an empty drift.
    let bin = pulse_bin();
    let base = examples_dir().join("baseline.json");

    let out = Command::new(&bin)
        .arg("diff")
        .arg(&base)
        .arg(&base)
        .output()
        .expect("failed to spawn pulse");

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("stdout utf8");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["new_processes"].as_array().unwrap().len(), 0);
    assert_eq!(v["new_external_connections"].as_array().unwrap().len(), 0);
    assert_eq!(v["orphaned_parents"].as_array().unwrap().len(), 0);
}
