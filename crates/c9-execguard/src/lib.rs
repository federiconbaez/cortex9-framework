// SPDX-License-Identifier: Apache-2.0
//! `c9-execguard`: block untrusted binaries at exec time.
//!
//! Two backends share one decision engine ([`scan::Engine`]):
//! * [`fanotify`] — `FAN_OPEN_EXEC_PERM`, no TOCTOU, needs CAP_SYS_ADMIN.
//! * [`seccomp`] — `SECCOMP_RET_USER_NOTIF`, works unprivileged, has a
//!   path-based race the README documents.
//!
//! The engine scans the opened file with an Aho-Corasick DFA built from the
//! policy signatures, then (only on a match) checks a SHA-256 allowlist so a
//! known-good binary that happens to contain a signature string is not blocked.

pub mod fanotify;
pub mod scan;
pub mod seccomp;

pub use scan::{Decision, Engine, Why};

/// One interception event, produced by either backend.
#[derive(Clone, Debug)]
pub struct Event {
    pub backend: &'static str,
    pub path: String,
    pub pid: i32,
    pub decision: Decision,
    pub latency_ns: u64,
}

/// Percentile of a sorted sample (nearest-rank).
pub fn percentile(sorted_ns: &[u64], p: f64) -> Option<u64> {
    if sorted_ns.is_empty() {
        return None;
    }
    let i = ((p / 100.0) * (sorted_ns.len() as f64 - 1.0)).round() as usize;
    Some(sorted_ns[i.min(sorted_ns.len() - 1)])
}
