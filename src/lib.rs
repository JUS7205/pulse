//! Pulse — a blue-team host telemetry tripwire.
//!
//! The crate captures a point-in-time snapshot of a host's process tree and
//! IPv4 TCP connection table, then diffs a later snapshot against a baseline
//! to surface drift: new processes, new external connections, and unexpected
//! (reparented) parents. A pure `verdict` classifier turns that drift into
//! `OK` / `WARN` / `ALERT`.
//!
//! This is the blue-team continuous-monitoring facet of the *runtime defense
//! of autonomous systems* project spine.

pub mod snapshot;
pub mod verdict;
pub mod watch;
