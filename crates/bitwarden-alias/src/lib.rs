#![doc = include_str!("../README.md")]

mod client;
mod error;
mod models;

pub use client::{AliasClient, AliasClientExt, AliasClientSettings, SIMPLELOGIN_DEFAULT_BASE_URL};
pub use error::AliasError;
pub use models::*;
