//! Verdict — classify a [`crate::watch::Diff`] into `OK` / `WARN` / `ALERT`.
//!
//! Rules (deliberately simple and auditable):
//!   * ALERT — any connection in `new_external_connections` whose remote peer
//!     is a *public* (globally-routable, non-RFC1918) address. That is the
//!     exfiltration / C2 signature.
//!   * WARN  — otherwise, if there is any new process that is a child of a
//!     watched PID, or any orphaned (reparented / reparented-to-absent) parent.
//!   * OK    — no notable drift.

use crate::snapshot::{is_public, ProcessInfo, Snapshot};
use crate::watch::Diff;
use serde::{Deserialize, Serialize};

/// The severity verdict for a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Ok,
    Warn,
    Alert,
}

impl Verdict {
    /// Single-letter / short tag for compact logging.
    pub fn tag(self) -> &'static str {
        match self {
            Verdict::Ok => "OK",
            Verdict::Warn => "WARN",
            Verdict::Alert => "ALERT",
        }
    }
}

/// Configuration that tunes the verdict.
#[derive(Debug, Clone)]
pub struct Config {
    /// PIDs whose newly-spawned children warrant a WARN.
    pub watched_pids: Vec<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            watched_pids: Vec::new(),
        }
    }
}

/// Classify `diff` against `baseline` using `config`.
///
/// Pure: no I/O. The `current` snapshot is used to resolve the parent PID of
/// new processes (so we can ask "is this new process a child of a watched
/// PID?"). `baseline` feeds orphan detection (already computed in the diff).
pub fn classify(diff: &Diff, baseline: &Snapshot, current: &Snapshot, config: &Config) -> Verdict {
    // ALERT: any new external connection to a public (non-private) address.
    if diff.new_external_connections.iter().any(|c| is_public(&c.remote_addr)) {
        return Verdict::Alert;
    }

    // WARN: a new process that is a child of a watched PID.
    let watched: std::collections::HashSet<u32> = config.watched_pids.iter().copied().collect();
    let is_watched_child = |proc: &ProcessInfo| watched.contains(&proc.parent_pid);

    if diff.new_processes.iter().any(is_watched_child) {
        return Verdict::Warn;
    }

    // WARN: any reparented / orphaned parent.
    let _ = (baseline, current);
    if !diff.orphaned_parents.is_empty() {
        return Verdict::Warn;
    }

    Verdict::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{Connection, ProcessInfo, Snapshot};
    use crate::watch::OrphanedParent;

    fn p(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: ppid,
            name: name.to_string(),
        }
    }

    fn c(pid: u32, remote: &str) -> Connection {
        Connection {
            pid,
            local_addr: "0.0.0.0:0".to_string(),
            remote_addr: remote.to_string(),
            state: "ESTABLISHED".to_string(),
        }
    }

    fn diff_with_external(ext: &[Connection]) -> Diff {
        Diff {
            new_processes: vec![],
            new_external_connections: ext.to_vec(),
            orphaned_parents: vec![],
        }
    }

    #[test]
    fn public_external_is_alert() {
        let d = diff_with_external(&[c(1, "8.8.8.8:443")]);
        let v = classify(&d, &Snapshot::default(), &Snapshot::default(), &Config::default());
        assert_eq!(v, Verdict::Alert);
    }

    #[test]
    fn private_external_is_not_alert_alone() {
        // An external (off-host) but RFC1918 connection is not public, so no
        // ALERT by itself. With nothing else it is OK.
        let d = diff_with_external(&[c(1, "10.0.0.5:80")]);
        let v = classify(&d, &Snapshot::default(), &Snapshot::default(), &Config::default());
        assert_eq!(v, Verdict::Ok);
    }

    #[test]
    fn watched_child_is_warn() {
        let d = Diff {
            new_processes: vec![p(9, 4, "child")],
            new_external_connections: vec![],
            orphaned_parents: vec![],
        };
        let v = classify(
            &d,
            &Snapshot::default(),
            &Snapshot::default(),
            &Config {
                watched_pids: vec![4],
            },
        );
        assert_eq!(v, Verdict::Warn);
    }

    #[test]
    fn orphaned_parent_is_warn() {
        let d = Diff {
            new_processes: vec![],
            new_external_connections: vec![],
            orphaned_parents: vec![OrphanedParent {
                pid: 3,
                current_parent_pid: 4,
                baseline_parent_pid: 2,
                name: "child".to_string(),
            }],
        };
        let v = classify(&d, &Snapshot::default(), &Snapshot::default(), &Config::default());
        assert_eq!(v, Verdict::Warn);
    }

    #[test]
    fn clean_diff_is_ok() {
        let d = Diff {
            new_processes: vec![],
            new_external_connections: vec![],
            orphaned_parents: vec![],
        };
        let v = classify(&d, &Snapshot::default(), &Snapshot::default(), &Config::default());
        assert_eq!(v, Verdict::Ok);
    }

    #[test]
    fn alert_takes_precedence_over_warn() {
        // Public external connection AND a watched child: ALERT wins.
        let d = Diff {
            new_processes: vec![p(9, 4, "child")],
            new_external_connections: vec![c(1, "8.8.8.8:443")],
            orphaned_parents: vec![],
        };
        let v = classify(
            &d,
            &Snapshot::default(),
            &Snapshot::default(),
            &Config {
                watched_pids: vec![4],
            },
        );
        assert_eq!(v, Verdict::Alert);
    }
}
