//! cfprobe: measure what an HTTP/TLS client sends and what Cloudflare answers, on a zone you own.
//!
//! Every report separates three kinds of value:
//! - **configured**: what this engine was asked to do (`None` means the library default),
//! - **measured by the client**: what this engine's own TLS and HTTP stack observed,
//! - **measured by a receiver**: what the lab TrackMe server or the zone Worker saw
//!   (`fingerprint`).
//!
//! The engine does not ship browser profiles and does not solve challenges.

pub mod core;
pub mod fingerprint;
pub mod http;
pub mod networking;
pub mod reporting;
pub mod tls;

pub use crate::core::{Config, Error, Result, Stage, Target};
pub use crate::networking::{CFProbe, Exchange};
