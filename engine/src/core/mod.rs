//! Configuration, request targets and the error type shared by every module.

mod config;
mod error;

pub use config::{Config, Target};
pub use error::{Error, Result, Stage};
