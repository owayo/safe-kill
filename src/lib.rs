//! safe-kill: AI エージェント向けの安全なプロセス終了ツール
//!
//! ancestry ベースのアクセス制御によるプロセス終了機能を提供し、
//! AI エージェントが自身の子孫プロセスのみを安全に kill できるようにする。

pub mod ancestry;
pub mod cli;
pub mod config;
pub mod error;
pub mod init;
pub mod killer;
pub mod policy;
pub mod port;
pub mod process_info;
pub mod signal;
