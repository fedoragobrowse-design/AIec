//! A local-only MCP server for AIec sandboxes.
//!
//! This crate is an adapter: it exposes AIec's sandbox lifecycle, exec and file
//! operations as Model Context Protocol tools so that any MCP-capable agent can
//! ask for a disposable machine. It deliberately knows nothing about OMP or any
//! other particular agent, and AIec itself has no dependency on it.

pub mod auth;
pub mod config;
pub mod error;
pub mod eval;
pub mod guard;
pub mod sandbox;
pub mod server;
