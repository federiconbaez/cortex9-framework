// SPDX-License-Identifier: Apache-2.0
//! The decision engine shared by both interception backends.
use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use anyhow::{Context, Result};
use c9_policy::{ExecMode, ExecPlan, ScanErrorAction};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Why {
    /// No signature matched.
    Clean,
    /// A signature matched but the file hash is on the trust list.
    Trusted { signature: String },
    /// A signature matched; `offset` is where in the file.
    Matched { signature: String, offset: u64 },
    /// The file could not be scanned (too large, unreadable).
    ScanError(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub allow: bool,
    pub why: Why,
    /// True if this came from the cache.
    pub cached: bool,
    pub scanned_bytes: u64,
}

/// Identity of a file version: any write or chmod changes ctime, so a
/// modified binary is always rescanned.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct FileKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i64,
    ctime_ns: i64,
}

const CACHE_CAP: usize = 4096;

pub struct Engine {
    ac: AhoCorasick,
    ids: Vec<String>,
    plan: ExecPlan,
    cache: HashMap<FileKey, Decision>,
}

impl Engine {
    pub fn new(plan: &ExecPlan) -> Result<Engine> {
        let ac = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .match_kind(MatchKind::LeftmostFirst)
            .build(plan.signatures.iter().map(|s| s.bytes.as_slice()))
            .context("build Aho-Corasick automaton")?;
        Ok(Engine {
            ac,
            ids: plan.signatures.iter().map(|s| s.id.clone()).collect(),
            plan: plan.clone(),
            cache: HashMap::new(),
        })
    }

    pub fn plan(&self) -> &ExecPlan {
        &self.plan
    }

    fn finish(&self, allow: bool) -> bool {
        allow || self.plan.mode == ExecMode::Audit
    }

    /// Decide for an open file. Never panics on hostile input.
    pub fn decide(&mut self, file: &File) -> Decision {
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(e) => return self.scan_error(format!("fstat: {e}")),
        };
        let key = FileKey {
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            mtime_ns: meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
            ctime_ns: meta.ctime() * 1_000_000_000 + meta.ctime_nsec(),
        };
        if let Some(d) = self.cache.get(&key) {
            return Decision {
                cached: true,
                ..d.clone()
            };
        }
        let d = self.scan(file, meta.size());
        if self.cache.len() >= CACHE_CAP {
            self.cache.clear();
        }
        self.cache.insert(key, d.clone());
        d
    }

    fn scan_error(&self, msg: String) -> Decision {
        let allow = self.plan.on_scan_error == ScanErrorAction::Allow;
        Decision {
            allow: self.finish(allow),
            why: Why::ScanError(msg),
            cached: false,
            scanned_bytes: 0,
        }
    }

    fn scan(&self, file: &File, size: u64) -> Decision {
        if size > self.plan.max_scan_bytes {
            return self.scan_error(format!("{size} bytes exceeds max_scan_bytes"));
        }
        if size == 0 {
            return Decision {
                allow: true,
                why: Why::Clean,
                cached: false,
                scanned_bytes: 0,
            };
        }
        // SAFETY: read-only private mapping of a file we hold open. A
        // concurrent truncation could raise SIGBUS; exec'd files are
        // write-protected (ETXTBSY) while running, and fanotify hands us
        // the exact file being executed.
        let map = match unsafe { memmap2::Mmap::map(file) } {
            Ok(m) => m,
            Err(e) => return self.scan_error(format!("mmap: {e}")),
        };
        match self.ac.find(&map[..]) {
            None => Decision {
                allow: true,
                why: Why::Clean,
                cached: false,
                scanned_bytes: size,
            },
            Some(m) => {
                let signature = self.ids[m.pattern().as_usize()].clone();
                // Only matching files pay for a hash.
                let digest = hex::encode(Sha256::digest(&map[..]));
                if self.plan.is_trusted(&digest) {
                    Decision {
                        allow: true,
                        why: Why::Trusted { signature },
                        cached: false,
                        scanned_bytes: size,
                    }
                } else {
                    Decision {
                        allow: self.finish(false),
                        why: Why::Matched {
                            signature,
                            offset: m.start() as u64,
                        },
                        cached: false,
                        scanned_bytes: size,
                    }
                }
            }
        }
    }

    /// Scan without caching, for the false-positive sweep.
    pub fn scan_path(&self, path: &std::path::Path) -> Result<Decision> {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let size = f.metadata()?.size();
        Ok(self.scan(&f, size))
    }
}

/// Wall-clock helper for latency samples.
pub fn elapsed_ns(t0: Instant) -> u64 {
    t0.elapsed().as_nanos() as u64
}
