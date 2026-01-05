//! Error types and exit codes for safe-kill
//!
//! Provides user-friendly error messages and standardized exit codes.

use std::process::ExitCode;
use thiserror::Error;

/// Exit codes for safe-kill command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeKillExitCode {
    /// Successful execution
    Success = 0,
    /// No target process found or specified
    NoTarget = 1,
    /// Permission denied
    PermissionDenied = 2,
    /// Configuration file error
    ConfigError = 3,
    /// General/other error
    GeneralError = 255,
}

impl From<SafeKillExitCode> for ExitCode {
    fn from(code: SafeKillExitCode) -> Self {
        ExitCode::from(code as u8)
    }
}

/// Error types for safe-kill operations
#[derive(Error, Debug)]
pub enum SafeKillError {
    // User input errors
    /// Invalid PID format
    #[error("Invalid PID: {0}")]
    InvalidPid(String),

    /// Invalid signal specification
    #[error("Invalid signal: {0}")]
    InvalidSignal(String),

    /// No target specified
    #[error("No target specified. Use --help for usage.")]
    NoTarget,

    // Business logic errors
    /// Target is not a descendant of current session
    #[error("Process {0} ({1}) is not a descendant of the current session")]
    NotDescendant(u32, String),

    /// Process is in denylist
    #[error("Process {0} is in denylist and cannot be killed")]
    Denylisted(String),

    /// Attempted to kill self or parent (suicide prevention)
    #[error("Cannot kill self or parent process (PID: {0})")]
    SuicidePrevention(u32),

    /// Process not found
    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    // System errors
    /// Permission denied for operation
    #[error("Permission denied for PID {0}")]
    PermissionDenied(u32),

    /// Configuration file parse error
    #[error("Config parse error: {0}")]
    ConfigError(String),

    /// Generic system error
    #[error("System error: {0}")]
    SystemError(String),
}

impl SafeKillError {
    /// Get the appropriate exit code for this error
    pub fn exit_code(&self) -> SafeKillExitCode {
        match self {
            SafeKillError::NoTarget | SafeKillError::ProcessNotFound(_) => {
                SafeKillExitCode::NoTarget
            }
            SafeKillError::PermissionDenied(_) => SafeKillExitCode::PermissionDenied,
            SafeKillError::ConfigError(_) => SafeKillExitCode::ConfigError,
            _ => SafeKillExitCode::GeneralError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_values() {
        assert_eq!(SafeKillExitCode::Success as u8, 0);
        assert_eq!(SafeKillExitCode::NoTarget as u8, 1);
        assert_eq!(SafeKillExitCode::PermissionDenied as u8, 2);
        assert_eq!(SafeKillExitCode::ConfigError as u8, 3);
        assert_eq!(SafeKillExitCode::GeneralError as u8, 255);
    }

    #[test]
    fn test_exit_code_conversion() {
        let code: ExitCode = SafeKillExitCode::Success.into();
        // ExitCode doesn't expose its value, but we verify it compiles and runs
        let _ = code;
    }

    #[test]
    fn test_invalid_pid_error_message() {
        let err = SafeKillError::InvalidPid("abc".to_string());
        assert_eq!(err.to_string(), "Invalid PID: abc");
    }

    #[test]
    fn test_invalid_signal_error_message() {
        let err = SafeKillError::InvalidSignal("SIGFOO".to_string());
        assert_eq!(err.to_string(), "Invalid signal: SIGFOO");
    }

    #[test]
    fn test_no_target_error_message() {
        let err = SafeKillError::NoTarget;
        assert_eq!(
            err.to_string(),
            "No target specified. Use --help for usage."
        );
    }

    #[test]
    fn test_not_descendant_error_message() {
        let err = SafeKillError::NotDescendant(1234, "nginx".to_string());
        assert_eq!(
            err.to_string(),
            "Process 1234 (nginx) is not a descendant of the current session"
        );
    }

    #[test]
    fn test_denylisted_error_message() {
        let err = SafeKillError::Denylisted("systemd".to_string());
        assert_eq!(
            err.to_string(),
            "Process systemd is in denylist and cannot be killed"
        );
    }

    #[test]
    fn test_suicide_prevention_error_message() {
        let err = SafeKillError::SuicidePrevention(5678);
        assert_eq!(
            err.to_string(),
            "Cannot kill self or parent process (PID: 5678)"
        );
    }

    #[test]
    fn test_process_not_found_error_message() {
        let err = SafeKillError::ProcessNotFound(9999);
        assert_eq!(err.to_string(), "Process 9999 not found");
    }

    #[test]
    fn test_permission_denied_error_message() {
        let err = SafeKillError::PermissionDenied(1);
        assert_eq!(err.to_string(), "Permission denied for PID 1");
    }

    #[test]
    fn test_config_error_message() {
        let err = SafeKillError::ConfigError("invalid TOML".to_string());
        assert_eq!(err.to_string(), "Config parse error: invalid TOML");
    }

    #[test]
    fn test_system_error_message() {
        let err = SafeKillError::SystemError("IO error".to_string());
        assert_eq!(err.to_string(), "System error: IO error");
    }

    #[test]
    fn test_error_to_exit_code_no_target() {
        assert_eq!(
            SafeKillError::NoTarget.exit_code(),
            SafeKillExitCode::NoTarget
        );
    }

    #[test]
    fn test_error_to_exit_code_process_not_found() {
        assert_eq!(
            SafeKillError::ProcessNotFound(123).exit_code(),
            SafeKillExitCode::NoTarget
        );
    }

    #[test]
    fn test_error_to_exit_code_permission_denied() {
        assert_eq!(
            SafeKillError::PermissionDenied(1).exit_code(),
            SafeKillExitCode::PermissionDenied
        );
    }

    #[test]
    fn test_error_to_exit_code_config_error() {
        assert_eq!(
            SafeKillError::ConfigError("error".to_string()).exit_code(),
            SafeKillExitCode::ConfigError
        );
    }

    #[test]
    fn test_error_to_exit_code_general_errors() {
        assert_eq!(
            SafeKillError::InvalidPid("x".to_string()).exit_code(),
            SafeKillExitCode::GeneralError
        );
        assert_eq!(
            SafeKillError::InvalidSignal("x".to_string()).exit_code(),
            SafeKillExitCode::GeneralError
        );
        assert_eq!(
            SafeKillError::NotDescendant(1, "x".to_string()).exit_code(),
            SafeKillExitCode::GeneralError
        );
        assert_eq!(
            SafeKillError::Denylisted("x".to_string()).exit_code(),
            SafeKillExitCode::GeneralError
        );
        assert_eq!(
            SafeKillError::SuicidePrevention(1).exit_code(),
            SafeKillExitCode::GeneralError
        );
        assert_eq!(
            SafeKillError::SystemError("x".to_string()).exit_code(),
            SafeKillExitCode::GeneralError
        );
    }
}
