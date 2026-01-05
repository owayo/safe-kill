//! safe-kill: Safe process termination tool for AI agents
//!
//! This library provides ancestry-based access control for process termination,
//! allowing AI agents to safely kill only their descendant processes.

pub mod ancestry;
pub mod cli;
pub mod config;
pub mod error;
pub mod killer;
pub mod policy;
pub mod process_info;
pub mod signal;
