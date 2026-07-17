//! Host snapshot: process tree + TCP connection table.
//!
//! On Windows we use the same user-mode Win32 primitives an EDR / anti-cheat
//! engine uses — `CreateToolhelp32Snapshot` for the process tree and
//! `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)` for PID-attributed sockets.
//! On non-Windows we return an honest empty snapshot (no process / connection
//! data is fabricated). The diff + verdict logic is platform-independent.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
mod windows;

/// One process discovered on the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
}

/// One IPv4 TCP connection attributed to its owning process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Connection {
    pub pid: u32,
    /// `local_ip:port`
    pub local_addr: String,
    /// `remote_ip:port`
    pub remote_addr: String,
    /// TCP state name (ESTABLISHED, LISTEN, TIME_WAIT, ...).
    pub state: String,
}

/// A point-in-time host snapshot: process tree + connection table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Snapshot {
    /// Unix epoch seconds at capture time.
    pub timestamp: u64,
    pub processes: Vec<ProcessInfo>,
    pub connections: Vec<Connection>,
}

/// Capture a fresh snapshot of the host.
///
/// On non-Windows this returns an honest empty snapshot (no process or
/// connection data is fabricated). On Windows it enumerates the live process
/// tree and IPv4 TCP table via Win32.
pub fn capture() -> Snapshot {
    let (processes, connections) = collect();
    Snapshot {
        timestamp: now_secs(),
        processes,
        connections,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(windows)]
fn collect() -> (Vec<ProcessInfo>, Vec<Connection>) {
    (windows::processes(), windows::connections())
}

#[cfg(not(windows))]
fn collect() -> (Vec<ProcessInfo>, Vec<Connection>) {
    (Vec::new(), Vec::new())
}

/// Parse the IPv4 address portion of an `ip:port` string.
pub fn parse_ipv4(addr: &str) -> Option<std::net::Ipv4Addr> {
    let ip_part = addr.rsplit_once(':').map(|(ip, _)| ip).unwrap_or(addr);
    ip_part.parse().ok()
}

/// A connection is "external" if it has a real remote peer — i.e. its remote
/// address is neither loopback (127/8), the unspecified `0.0.0.0`, nor
/// multicast. A `LISTEN` socket with `0.0.0.0:0` is therefore *not* external.
pub fn is_external(addr: &str) -> bool {
    match parse_ipv4(addr) {
        Some(ip) => !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast()),
        None => false,
    }
}

/// A remote address is "public" (globally routable / off your private LAN) —
/// the interesting case for exfiltration detection. Per the tripwire rule a
/// *non-private* external connection is the ALERT trigger, so public means:
/// has a real peer (not loopback / unspecified / multicast), is not RFC1918
/// private, and is not link-local. Documentation/reserved ranges (e.g.
/// 203.0.113.0/24) are not private and therefore count as public here.
pub fn is_public(addr: &str) -> bool {
    match parse_ipv4(addr) {
        Some(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_private()
                && !ip.is_link_local()
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_detection() {
        assert!(is_external("8.8.8.8:443"));
        assert!(is_external("192.168.1.5:80"));
        assert!(!is_external("127.0.0.1:5432"));
        assert!(!is_external("0.0.0.0:0"));
        assert!(!is_external("224.0.0.1:1"));
    }

    #[test]
    fn public_detection() {
        assert!(is_public("8.8.8.8:443"));
        assert!(!is_public("192.168.1.5:80"));
        assert!(!is_public("127.0.0.1:5432"));
        assert!(!is_public("0.0.0.0:0"));
        assert!(!is_public("169.254.1.1:1"));
    }

    #[test]
    fn sample_snapshot_deserializes() {
        let json = include_str!("../../examples/sample.snapshot.json");
        let s: Snapshot = serde_json::from_str(json).expect("sample snapshot must parse as JSON");
        assert!(s.timestamp > 0, "timestamp should be non-zero");
        assert!(!s.processes.is_empty(), "sample must contain processes");
        assert!(
            s.connections
                .iter()
                .all(|c| parse_ipv4(&c.remote_addr).is_some()),
            "every connection remote_addr must be a parseable ip:port"
        );
    }
}
