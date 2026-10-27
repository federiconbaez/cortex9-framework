// SPDX-License-Identifier: Apache-2.0
//! `c9-classify`: the packet classifier at the heart of cortex9.
//!
//! The same source (`engine.rs`) runs inside the Linux kernel as a
//! Rust-for-Linux module, in userspace as the oracle that the XDP program is
//! checked against, and under Miri. It is `no_std`, allocation-free and total.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

mod engine;
pub use engine::*;

#[cfg(feature = "std")]
pub mod packet;
