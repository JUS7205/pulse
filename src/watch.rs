//! Baseline capture + drift computation.
//!
//! A `Diff` compares a *current* snapshot against a *baseline* and reports the
//! interesting deltas a tripwire cares about:
//!   * `new_processes`         — processes present now but not at baseline,
//!   * `new_external_connections` — external (off-host) connections that have
//!                                 appeared since baseline,
//!   * `orphaned_parents`      — processes whose parent changed / disappeared.

use crate::snapshot::{is_external, Connection, ProcessInfo, Snapshot};

/// The delta between a baseline and a current snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Diff {
    /// Processes present in `current` but absent from `baseline`, by PID.
    pub new_processes: Vec<ProcessInfo>,
    /// External (off-host) connections present in `current` but not baseline.
    pub new_external_connections: Vec<Connection>,
    /// Processes whose parent PID differs from baseline, or whose baseline
    /// parent no longer exists. Each entry pairs the process with the
    /// (now-stale) baseline parent PID.
    pub orphaned_parents: Vec<OrphanedParent>,
}

/// A process whose parent changed / disappeared between baseline and current.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OrphanedParent {
    pub pid: u32,
    pub current_parent_pid: u32,
    pub baseline_parent_pid: u32,
    pub name: String,
}

/// Capture a fresh baseline snapshot of the host.
pub fn baseline() -> Snapshot {
    crate::snapshot::capture()
}

/// Compute the drift from `baseline` to `current`.
///
/// Pure: no I/O, no host access. Identity of a process is its PID; identity of
/// a connection is the whole record (pid + local + remote + state).
pub fn diff(baseline: &Snapshot, current: &Snapshot) -> Diff {
    let base_pids: std::collections::HashSet<u32> =
        baseline.processes.iter().map(|p| p.pid).collect();
    let base_parents: std::collections::HashMap<u32, u32> = baseline
        .processes
        .iter()
        .map(|p| (p.pid, p.parent_pid))
        .collect();

    let new_processes = current
        .processes
        .iter()
        .filter(|p| !base_pids.contains(&p.pid))
        .cloned()
        .collect();

    let base_conn_set: std::collections::HashSet<&Connection> =
        baseline.connections.iter().collect();
    let new_external_connections = current
        .connections
        .iter()
        .filter(|c| {
            is_external(&c.remote_addr) && !base_conn_set.contains(c)
        })
        .cloned()
        .collect();

    // Orphan detection. A process is "orphaned" (its parent relationship
    // changed / disappeared) in one of two honest cases:
    //   1. It existed in the baseline but its PARENT changed between baseline
    //      and current (it was reparented), or its baseline parent no longer
    //      exists in the current snapshot.
    //   2. It is a NEW process whose recorded parent is absent from the
    //      CURRENT snapshot (the parent died before the new process spawned,
    //      or was never observed) — a classic spawn-after-parent-exit pattern.
    let cur_pids: std::collections::HashSet<u32> =
        current.processes.iter().map(|p| p.pid).collect();

    let mut orphaned_parents = Vec::new();
    for p in &current.processes {
        if let Some(&base_ppid) = base_parents.get(&p.pid) {
            // Known pid from baseline. A parent of 0 is the system root, which
            // is never enumerated; don't treat it as "missing".
            if (p.parent_pid != base_ppid && !(p.parent_pid == 0 && base_ppid == 0))
                || (base_ppid != 0 && !cur_pids.contains(&base_ppid))
            {
                orphaned_parents.push(OrphanedParent {
                    pid: p.pid,
                    current_parent_pid: p.parent_pid,
                    baseline_parent_pid: base_ppid,
                    name: p.name.clone(),
                });
            }
        } else if !base_pids.contains(&p.pid) {
            // Brand-new process. A parent of 0 is root; only flag when the
            // parent is a non-root PID that is absent from the current snapshot.
            if p.parent_pid != 0 && !cur_pids.contains(&p.parent_pid) {
                orphaned_parents.push(OrphanedParent {
                    pid: p.pid,
                    current_parent_pid: p.parent_pid,
                    baseline_parent_pid: 0,
                    name: p.name.clone(),
                });
            }
        }
    }

    Diff {
        new_processes,
        new_external_connections,
        orphaned_parents,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{Connection, ProcessInfo, Snapshot};

    fn snap(ts: u64, procs: &[ProcessInfo], conns: &[Connection]) -> Snapshot {
        Snapshot {
            timestamp: ts,
            processes: procs.to_vec(),
            connections: conns.to_vec(),
        }
    }

    fn p(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: ppid,
            name: name.to_string(),
        }
    }

    fn c(pid: u32, local: &str, remote: &str, state: &str) -> Connection {
        Connection {
            pid,
            local_addr: local.to_string(),
            remote_addr: remote.to_string(),
            state: state.to_string(),
        }
    }

    #[test]
    fn new_process_detected() {
        let base = snap(1, &[p(1, 0, "init"), p(2, 1, "shell")], &[]);
        let cur = snap(
            2,
            &[p(1, 0, "init"), p(2, 1, "shell"), p(3, 2, "payload")],
            &[],
        );
        let d = diff(&base, &cur);
        assert_eq!(d.new_processes.len(), 1);
        assert_eq!(d.new_processes[0].pid, 3);
        assert!(d.new_external_connections.is_empty());
        assert!(d.orphaned_parents.is_empty());
    }

    #[test]
    fn existing_process_not_flagged_as_new() {
        let base = snap(1, &[p(1, 0, "init")], &[]);
        let cur = snap(2, &[p(1, 0, "init")], &[]);
        let d = diff(&base, &cur);
        assert!(d.new_processes.is_empty());
    }

    #[test]
    fn new_external_connection_detected() {
        let base = snap(1, &[p(1, 0, "init")], &[c(1, "127.0.0.1:5000", "127.0.0.1:5001", "ESTABLISHED")]);
        let cur = snap(
            2,
            &[p(1, 0, "init")],
            &[
                c(1, "127.0.0.1:5000", "127.0.0.1:5001", "ESTABLISHED"),
                c(1, "192.168.1.7:4444", "8.8.8.8:443", "ESTABLISHED"),
            ],
        );
        let d = diff(&base, &cur);
        assert_eq!(d.new_external_connections.len(), 1);
        assert_eq!(d.new_external_connections[0].remote_addr, "8.8.8.8:443");
    }

    #[test]
    fn local_connection_not_external() {
        let base = snap(1, &[p(1, 0, "init")], &[]);
        let cur = snap(
            2,
            &[p(1, 0, "init")],
            &[c(1, "127.0.0.1:5000", "127.0.0.1:5001", "ESTABLISHED")],
        );
        let d = diff(&base, &cur);
        assert!(d.new_external_connections.is_empty());
    }

    #[test]
    fn listening_socket_not_external() {
        let base = snap(1, &[p(1, 0, "init")], &[]);
        let cur = snap(
            2,
            &[p(1, 0, "init")],
            &[c(1, "0.0.0.0:0", "0.0.0.0:0", "LISTEN")],
        );
        let d = diff(&base, &cur);
        assert!(d.new_external_connections.is_empty());
    }

    #[test]
    fn orphaned_parent_reparent_detected() {
        // PID 3 exists in both snapshots but its parent changed 2 -> 4.
        let base = snap(1, &[p(1, 0, "init"), p(2, 1, "shell"), p(3, 2, "child")], &[]);
        let cur = snap(
            2,
            &[p(1, 0, "init"), p(4, 1, "shell2"), p(3, 4, "child")],
            &[],
        );
        let d = diff(&base, &cur);
        assert_eq!(d.orphaned_parents.len(), 1);
        assert_eq!(d.orphaned_parents[0].pid, 3);
        assert_eq!(d.orphaned_parents[0].baseline_parent_pid, 2);
        assert_eq!(d.orphaned_parents[0].current_parent_pid, 4);
    }

    #[test]
    fn orphaned_parent_parent_gone() {
        // PID 5 is new and its parent (404) does not exist in baseline at all.
        let base = snap(1, &[p(1, 0, "init")], &[]);
        let cur = snap(2, &[p(1, 0, "init"), p(5, 404, "spawn")], &[]);
        let d = diff(&base, &cur);
        assert_eq!(d.orphaned_parents.len(), 1);
        assert_eq!(d.orphaned_parents[0].pid, 5);
        assert_eq!(d.orphaned_parents[0].baseline_parent_pid, 0);
    }

    #[test]
    fn unchanged_no_orphans() {
        let base = snap(1, &[p(1, 0, "init"), p(2, 1, "shell")], &[]);
        let cur = snap(2, &[p(1, 0, "init"), p(2, 1, "shell")], &[]);
        let d = diff(&base, &cur);
        assert!(d.orphaned_parents.is_empty());
    }
}
