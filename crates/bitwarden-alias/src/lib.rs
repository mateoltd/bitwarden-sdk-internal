#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

mod client;
mod error;
mod models;
mod reconciliation;

#[cfg(test)]
mod tests;

pub use client::{AliasClient, AliasClientExt, AliasClientSettings, SIMPLELOGIN_DEFAULT_BASE_URL};
pub use error::AliasError;
pub use models::*;
pub use reconciliation::*;
