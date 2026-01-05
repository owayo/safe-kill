//! CLI argument parser for safe-kill
//!
//! Provides type-safe argument parsing using clap derive.

use clap::Parser;

use crate::error::SafeKillError;
use crate::signal::{Signal, SignalSender};

/// Execution mode determined from CLI arguments
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Kill a process by PID
    KillByPid(u32),
    /// Kill processes by name (pkill-style)
    KillByName(String),
    /// List killable processes
    ListKillable,
}

/// CLI arguments for safe-kill
#[derive(Parser, Debug)]
#[command(
    name = "safe-kill",
    version,
    about = "Safe process termination tool for AI agents",
    long_about = "A CLI tool that provides ancestry-based access control for process termination.\n\
                  It allows killing only descendant processes of the current session,\n\
                  preventing accidental termination of system or unrelated processes."
)]
pub struct CliArgs {
    /// Target PID to kill
    #[arg(value_name = "PID")]
    pub pid: Option<u32>,

    /// Kill processes by name (pkill-style)
    #[arg(short = 'N', long, value_name = "NAME")]
    pub name: Option<String>,

    /// Signal to send (name or number)
    #[arg(short, long, default_value = "SIGTERM", value_name = "SIGNAL")]
    pub signal: String,

    /// List killable processes
    #[arg(short, long)]
    pub list: bool,

    /// Dry run mode (don't actually send signals)
    #[arg(short = 'n', long)]
    pub dry_run: bool,
}

impl CliArgs {
    /// Parse CLI arguments from command line
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Validate arguments and determine execution mode
    ///
    /// Returns an error if:
    /// - No target is specified (neither PID, --name, nor --list)
    /// - Multiple targets are specified (PID and --name, or --list with others)
    pub fn validate(&self) -> Result<ExecutionMode, SafeKillError> {
        // Count how many target options are specified
        let has_pid = self.pid.is_some();
        let has_name = self.name.is_some();
        let has_list = self.list;

        // Check for mutual exclusivity
        let target_count = [has_pid, has_name, has_list].iter().filter(|&&b| b).count();

        match target_count {
            0 => Err(SafeKillError::NoTarget),
            1 => {
                if has_list {
                    Ok(ExecutionMode::ListKillable)
                } else if let Some(pid) = self.pid {
                    Ok(ExecutionMode::KillByPid(pid))
                } else if let Some(ref name) = self.name {
                    Ok(ExecutionMode::KillByName(name.clone()))
                } else {
                    // This should never happen given the logic above
                    Err(SafeKillError::NoTarget)
                }
            }
            _ => {
                // Multiple targets specified - this is an error
                if has_list {
                    Err(SafeKillError::InvalidPid(
                        "--list cannot be combined with PID or --name".to_string(),
                    ))
                } else {
                    Err(SafeKillError::InvalidPid(
                        "Cannot specify both PID and --name".to_string(),
                    ))
                }
            }
        }
    }

    /// Parse the signal argument into a Signal enum
    pub fn parse_signal(&self) -> Result<Signal, SafeKillError> {
        SignalSender::parse_signal(&self.signal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create CliArgs for testing
    fn make_args(
        pid: Option<u32>,
        name: Option<String>,
        signal: &str,
        list: bool,
        dry_run: bool,
    ) -> CliArgs {
        CliArgs {
            pid,
            name,
            signal: signal.to_string(),
            list,
            dry_run,
        }
    }

    // ExecutionMode tests
    #[test]
    fn test_execution_mode_debug() {
        let mode = ExecutionMode::KillByPid(1234);
        let debug_str = format!("{:?}", mode);
        assert!(debug_str.contains("KillByPid"));
        assert!(debug_str.contains("1234"));
    }

    #[test]
    fn test_execution_mode_clone() {
        let mode = ExecutionMode::KillByName("test".to_string());
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_execution_mode_eq() {
        assert_eq!(ExecutionMode::ListKillable, ExecutionMode::ListKillable);
        assert_eq!(ExecutionMode::KillByPid(100), ExecutionMode::KillByPid(100));
        assert_ne!(ExecutionMode::KillByPid(100), ExecutionMode::KillByPid(200));
    }

    // CliArgs validation tests
    #[test]
    fn test_validate_no_target() {
        let args = make_args(None, None, "SIGTERM", false, false);
        let result = args.validate();
        assert!(matches!(result, Err(SafeKillError::NoTarget)));
    }

    #[test]
    fn test_validate_pid_only() {
        let args = make_args(Some(1234), None, "SIGTERM", false, false);
        let result = args.validate();
        assert!(matches!(result, Ok(ExecutionMode::KillByPid(1234))));
    }

    #[test]
    fn test_validate_name_only() {
        let args = make_args(None, Some("node".to_string()), "SIGTERM", false, false);
        let result = args.validate();
        match result {
            Ok(ExecutionMode::KillByName(name)) => assert_eq!(name, "node"),
            _ => panic!("Expected KillByName"),
        }
    }

    #[test]
    fn test_validate_list_only() {
        let args = make_args(None, None, "SIGTERM", true, false);
        let result = args.validate();
        assert!(matches!(result, Ok(ExecutionMode::ListKillable)));
    }

    #[test]
    fn test_validate_pid_and_name_conflict() {
        let args = make_args(
            Some(1234),
            Some("node".to_string()),
            "SIGTERM",
            false,
            false,
        );
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Cannot specify both"));
        }
    }

    #[test]
    fn test_validate_list_and_pid_conflict() {
        let args = make_args(Some(1234), None, "SIGTERM", true, false);
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("--list cannot be combined"));
        }
    }

    #[test]
    fn test_validate_list_and_name_conflict() {
        let args = make_args(None, Some("node".to_string()), "SIGTERM", true, false);
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("--list cannot be combined"));
        }
    }

    #[test]
    fn test_validate_all_targets_conflict() {
        let args = make_args(Some(1234), Some("node".to_string()), "SIGTERM", true, false);
        let result = args.validate();
        assert!(result.is_err());
    }

    // parse_signal tests
    #[test]
    fn test_parse_signal_default() {
        let args = make_args(Some(1234), None, "SIGTERM", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_sigkill() {
        let args = make_args(Some(1234), None, "SIGKILL", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_number() {
        let args = make_args(Some(1234), None, "9", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_without_prefix() {
        let args = make_args(Some(1234), None, "TERM", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_lowercase() {
        let args = make_args(Some(1234), None, "sigterm", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_invalid() {
        let args = make_args(Some(1234), None, "INVALID", false, false);
        let result = args.parse_signal();
        assert!(result.is_err());
    }

    // dry_run tests
    #[test]
    fn test_dry_run_flag() {
        let args = make_args(Some(1234), None, "SIGTERM", false, true);
        assert!(args.dry_run);
    }

    #[test]
    fn test_dry_run_default() {
        let args = make_args(Some(1234), None, "SIGTERM", false, false);
        assert!(!args.dry_run);
    }

    // CliArgs struct tests
    #[test]
    fn test_cli_args_debug() {
        let args = make_args(Some(1234), None, "SIGTERM", false, false);
        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("CliArgs"));
        assert!(debug_str.contains("1234"));
    }

    #[test]
    fn test_cli_args_fields() {
        let args = make_args(Some(100), Some("test".to_string()), "SIGKILL", true, true);
        assert_eq!(args.pid, Some(100));
        assert_eq!(args.name, Some("test".to_string()));
        assert_eq!(args.signal, "SIGKILL");
        assert!(args.list);
        assert!(args.dry_run);
    }

    // Integration-like tests
    #[test]
    fn test_workflow_pid_kill() {
        let args = make_args(Some(1234), None, "SIGTERM", false, false);

        // Validate
        let mode = args.validate().unwrap();
        assert!(matches!(mode, ExecutionMode::KillByPid(1234)));

        // Parse signal
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);

        // Check dry_run
        assert!(!args.dry_run);
    }

    #[test]
    fn test_workflow_name_kill_dry_run() {
        let args = make_args(None, Some("node".to_string()), "SIGKILL", false, true);

        // Validate
        let mode = args.validate().unwrap();
        match mode {
            ExecutionMode::KillByName(name) => assert_eq!(name, "node"),
            _ => panic!("Expected KillByName"),
        }

        // Parse signal
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGKILL);

        // Check dry_run
        assert!(args.dry_run);
    }

    #[test]
    fn test_workflow_list() {
        let args = make_args(None, None, "SIGTERM", true, false);

        // Validate
        let mode = args.validate().unwrap();
        assert!(matches!(mode, ExecutionMode::ListKillable));
    }
}
