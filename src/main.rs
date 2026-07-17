//! Pulse CLI — a host telemetry tripwire.
//!
//! Usage:
//!   pulse snapshot              Capture a fresh host snapshot, print JSON.
//!   pulse diff A.json B.json    Compute drift (Diff) between two snapshots.
//!   pulse verdict A.json B.json [--watch PID ...]
//!                              Classify the drift as OK / WARN / ALERT.
//!
//! On non-Windows `snapshot` prints an honest empty snapshot (no fabrication).

use std::path::Path;
use std::process::exit;

use pulse::snapshot::{capture, is_public, Connection, Snapshot};
use pulse::verdict::{classify, Config, Verdict};
use pulse::watch::{diff, Diff};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        exit(2);
    }

    match args[0].as_str() {
        "snapshot" => cmd_snapshot(),
        "diff" => {
            if args.len() != 3 {
                eprintln!("error: `pulse diff` expects exactly 2 JSON file paths");
                print_usage();
                exit(2);
            }
            cmd_diff(&args[1], &args[2]);
        }
        "verdict" => cmd_verdict(&args[1..]),
        "help" | "--help" | "-h" => print_usage(),
        other => {
            eprintln!("error: unknown subcommand `{}`", other);
            print_usage();
            exit(2);
        }
    }
}

fn print_usage() {
    eprintln!(
        "pulse — blue-team host telemetry tripwire\n\n\
         USAGE:\n  \
         pulse snapshot\n  \
         pulse diff <a.json> <b.json>\n  \
         pulse verdict <baseline.json> <current.json> [--watch PID ...]\n"
    );
}

fn cmd_snapshot() {
    let snap = capture();
    let json = serde_json::to_string_pretty(&snap).expect("snapshot is serializable");
    println!("{}", json);
}

fn cmd_diff(a_path: &str, b_path: &str) {
    let baseline_snap = load_snapshot(a_path);
    let current_snap = load_snapshot(b_path);
    let d = diff(&baseline_snap, &current_snap);
    let json = serde_json::to_string_pretty(&d).expect("diff is serializable");
    println!("{}", json);
}

fn cmd_verdict(args: &[String]) {
    if args.len() < 2 {
        eprintln!(
            "error: `pulse verdict` expects <baseline.json> <current.json> [--watch PID ...]"
        );
        print_usage();
        exit(2);
    }
    let baseline_path = &args[0];
    let current_path = &args[1];

    let mut watched = Vec::new();
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--watch" | "-w" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("error: --watch requires a PID argument");
                    exit(2);
                }
                match args[i].parse::<u32>() {
                    Ok(pid) => watched.push(pid),
                    Err(_) => {
                        eprintln!("error: invalid PID `{}`", args[i]);
                        exit(2);
                    }
                }
            }
            other => {
                eprintln!("error: unexpected argument `{}`", other);
                exit(2);
            }
        }
        i += 1;
    }

    let base = load_snapshot(baseline_path);
    let cur = load_snapshot(current_path);
    let d = diff(&base, &cur);
    let config = Config {
        watched_pids: watched,
    };
    let v = classify(&d, &base, &cur, &config);

    let report = VerdictReport {
        verdict: v.tag(),
        diff: &d,
        public_external: d
            .new_external_connections
            .iter()
            .filter(|c| is_public(&c.remote_addr))
            .cloned()
            .collect::<Vec<Connection>>(),
        watched_pids: config.watched_pids.clone(),
    };
    let json = serde_json::to_string_pretty(&report).expect("report is serializable");
    println!("{}", json);
    if matches!(v, Verdict::Alert) {
        exit(1);
    }
}

/// Human + machine readable verdict report.
#[derive(serde::Serialize)]
struct VerdictReport<'a> {
    verdict: &'a str,
    #[serde(flatten)]
    diff: &'a Diff,
    public_external: Vec<Connection>,
    watched_pids: Vec<u32>,
}

fn load_snapshot(path: &str) -> Snapshot {
    let text = std::fs::read_to_string(Path::new(path)).unwrap_or_else(|e| {
        eprintln!("error: cannot read `{}`: {}", path, e);
        exit(2);
    });
    serde_json::from_str(&text).unwrap_or_else(|e| {
        eprintln!("error: `{}` is not a valid snapshot JSON: {}", path, e);
        exit(2);
    })
}
