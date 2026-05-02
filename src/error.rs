//! safe-kill のエラー型と終了コード定義
//!
//! 利用者向けのエラーメッセージと標準化した終了コードを提供する。

use std::process::ExitCode;
use thiserror::Error;

/// `safe-kill` コマンドの終了コード
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeKillExitCode {
    /// 正常終了
    Success = 0,
    /// 対象未指定または対象プロセスなし
    NoTarget = 1,
    /// 権限不足
    PermissionDenied = 2,
    /// 設定ファイルエラー
    ConfigError = 3,
    /// 設定上許可されていないポート
    PortNotAllowed = 4,
    /// その他の一般エラー
    GeneralError = 255,
}

impl From<SafeKillExitCode> for ExitCode {
    fn from(code: SafeKillExitCode) -> Self {
        ExitCode::from(code as u8)
    }
}

/// `safe-kill` のエラー型
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SafeKillError {
    // 入力値エラー
    /// PID の形式が不正
    #[error("Invalid PID: {0}")]
    InvalidPid(String),

    /// CLI オプションの組み合わせが不正
    #[error("{0}")]
    InvalidUsage(String),

    /// シグナル指定が不正
    #[error("Invalid signal: {0}")]
    InvalidSignal(String),

    /// ポート番号が不正
    #[error("Invalid port: {0}")]
    InvalidPort(String),

    /// 対象未指定
    #[error("No target specified. Use --help for usage.")]
    NoTarget,

    // ポリシー判定エラー
    /// 対象が現在セッションの子孫ではない
    #[error("Process {0} ({1}) is not a descendant of the current session")]
    NotDescendant(u32, String),

    /// denylist に含まれている
    #[error("Process {0} is in denylist and cannot be killed")]
    Denylisted(String),

    /// 自分または親を kill しようとした
    #[error("Cannot kill self or parent process (PID: {0})")]
    SuicidePrevention(u32),

    /// プロセスが見つからない
    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    /// 指定名のプロセスが見つからない
    #[error("No process found with name: {0}")]
    ProcessNameNotFound(String),

    /// 一致はしたがポリシー上 kill できる対象がなかった
    #[error("No killable process found for {0}")]
    NoKillableTarget(String),

    // ポート関連エラー
    /// 指定ポートで待ち受けるプロセスが見つからない
    #[error("No process found on port {0}")]
    NoProcessOnPort(u16),

    /// 設定上許可されていないポート
    #[error("Port {port} is not allowed. {hint}")]
    PortNotAllowed { port: u16, hint: String },

    /// ポート使用プロセスの検出に失敗
    #[error("Failed to detect process on port {port}: {reason}")]
    PortDetectionError { port: u16, reason: String },

    /// ポート範囲指定の形式が不正
    #[error("Invalid port range format: {0}")]
    InvalidPortRange(String),

    /// 設定ファイル作成に失敗
    #[error("Failed to create config file: {0}")]
    ConfigCreationError(String),

    // システムエラー
    /// OS レベルで権限不足
    #[error("Permission denied for PID {0}")]
    PermissionDenied(u32),

    /// 設定ファイルの解析エラー
    #[error("Config parse error: {0}")]
    ConfigError(String),

    /// その他のシステムエラー
    #[error("System error: {0}")]
    SystemError(String),
}

impl SafeKillError {
    /// このエラーに対応する終了コードを返す
    pub fn exit_code(&self) -> SafeKillExitCode {
        match self {
            SafeKillError::NoTarget
            | SafeKillError::ProcessNotFound(_)
            | SafeKillError::ProcessNameNotFound(_)
            | SafeKillError::NoKillableTarget(_)
            | SafeKillError::NoProcessOnPort(_) => SafeKillExitCode::NoTarget,
            SafeKillError::PermissionDenied(_) => SafeKillExitCode::PermissionDenied,
            SafeKillError::ConfigError(_) | SafeKillError::ConfigCreationError(_) => {
                SafeKillExitCode::ConfigError
            }
            SafeKillError::PortNotAllowed { .. } => SafeKillExitCode::PortNotAllowed,
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
        assert_eq!(SafeKillExitCode::PortNotAllowed as u8, 4);
        assert_eq!(SafeKillExitCode::GeneralError as u8, 255);
    }

    #[test]
    fn test_exit_code_conversion() {
        let code: ExitCode = SafeKillExitCode::Success.into();
        // `ExitCode` は数値を直接取り出せないため、生成できることだけ確認する
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
    fn test_invalid_port_error_message() {
        let err = SafeKillError::InvalidPort("0".to_string());
        assert_eq!(err.to_string(), "Invalid port: 0");
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
    fn test_process_name_not_found_error_message() {
        let err = SafeKillError::ProcessNameNotFound("node-dev".to_string());
        assert_eq!(err.to_string(), "No process found with name: node-dev");
    }

    #[test]
    fn test_no_killable_target_error_message() {
        let err = SafeKillError::NoKillableTarget("name 'launchd'".to_string());
        assert_eq!(
            err.to_string(),
            "No killable process found for name 'launchd'"
        );
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

    // ポート関連エラーのテスト
    #[test]
    fn test_no_process_on_port_error_message() {
        let err = SafeKillError::NoProcessOnPort(8080);
        assert_eq!(err.to_string(), "No process found on port 8080");
    }

    #[test]
    fn test_port_not_allowed_error_message() {
        let err = SafeKillError::PortNotAllowed {
            port: 22,
            hint: "Add 22 to [allowed_ports] in config.toml".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Port 22 is not allowed. Add 22 to [allowed_ports] in config.toml"
        );
    }

    #[test]
    fn test_port_detection_error_message() {
        let err = SafeKillError::PortDetectionError {
            port: 3000,
            reason: "permission denied".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Failed to detect process on port 3000: permission denied"
        );
    }

    #[test]
    fn test_invalid_port_range_error_message() {
        let err = SafeKillError::InvalidPortRange("abc-def".to_string());
        assert_eq!(err.to_string(), "Invalid port range format: abc-def");
    }

    #[test]
    fn test_config_creation_error_message() {
        let err = SafeKillError::ConfigCreationError("directory not found".to_string());
        assert_eq!(
            err.to_string(),
            "Failed to create config file: directory not found"
        );
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
    fn test_error_to_exit_code_process_name_not_found() {
        assert_eq!(
            SafeKillError::ProcessNameNotFound("node".to_string()).exit_code(),
            SafeKillExitCode::NoTarget
        );
    }

    #[test]
    fn test_error_to_exit_code_no_killable_target() {
        assert_eq!(
            SafeKillError::NoKillableTarget("name 'launchd'".to_string()).exit_code(),
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
    fn test_error_to_exit_code_no_process_on_port() {
        assert_eq!(
            SafeKillError::NoProcessOnPort(8080).exit_code(),
            SafeKillExitCode::NoTarget
        );
    }

    #[test]
    fn test_error_to_exit_code_port_not_allowed() {
        assert_eq!(
            SafeKillError::PortNotAllowed {
                port: 22,
                hint: "hint".to_string()
            }
            .exit_code(),
            SafeKillExitCode::PortNotAllowed
        );
    }

    #[test]
    fn test_error_to_exit_code_config_creation_error() {
        assert_eq!(
            SafeKillError::ConfigCreationError("error".to_string()).exit_code(),
            SafeKillExitCode::ConfigError
        );
    }

    #[test]
    fn test_error_to_exit_code_port_detection_error() {
        assert_eq!(
            SafeKillError::PortDetectionError {
                port: 3000,
                reason: "error".to_string()
            }
            .exit_code(),
            SafeKillExitCode::GeneralError
        );
    }

    #[test]
    fn test_error_to_exit_code_invalid_port_range() {
        assert_eq!(
            SafeKillError::InvalidPortRange("bad".to_string()).exit_code(),
            SafeKillExitCode::GeneralError
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
            SafeKillError::InvalidPort("0".to_string()).exit_code(),
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
