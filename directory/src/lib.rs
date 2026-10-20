//! The AgentConnect directory (ADR-006, discovery): an index of signed
//! listings (A2A Agent Cards with the `e2e` extension) and their owner and
//! door state.
//!
//! It holds no keys and no secrets, never talks to the relay, never learns
//! mailbox ids and stores nothing about readers. Every signature and
//! canonical-form check goes through a [`verify::Verifier`]; the directory itself
//! applies policy (its host, its relays, its clock, the `seq` rules).
//!
//! - [`directory`]: publish, withdraw, revoke, lookup, search, owner checks
//! - [`verify`]: the seam to `agentconnect_core` for every crypto check
//! - [`store`]: the storage seam, with [`memory`] and [`postgres`] backends
//! - [`owner`]: the owner-file fetch and its SSRF guard, and owner states
//! - [`http`], [`render`], [`mcp`]: the site, its Markdown copies and MCP
#![warn(clippy::pedantic, missing_docs)]

pub mod api;
pub mod card;
pub mod config;
pub mod directory;
pub mod http;
pub mod logging;
pub mod mcp;
pub mod memory;
pub mod metrics;
pub mod owner;
pub mod postgres;
pub mod ratelimit;
pub mod render;
pub mod store;
pub mod verify;

pub use directory::{Directory, Settings};

pub use http::{HttpConfig, app};
pub use memory::MemoryStore;
pub use postgres::PgStore;
pub use store::Store;
