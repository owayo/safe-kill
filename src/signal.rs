//! safe-kill のシグナル処理
//!
//! nix クレートを使用した Unix シグナルの解析と送信機能を提供する。

use crate::error::SafeKillError;
use nix::sys::signal::{self, Signal as NixSignal};
use nix::unistd::Pid;

/// プロセス終了に使用するサポート対象シグナル
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Signal {
    /// SIGHUP (1) - ハングアップ
    SIGHUP,
    /// SIGINT (2) - 割り込み
    SIGINT,
    /// SIGQUIT (3) - 終了
    SIGQUIT,
    /// SIGKILL (9) - 強制終了（捕捉不可）
    SIGKILL,
    /// SIGTERM (15) - 終了要求
    #[default]
    SIGTERM,
    /// SIGUSR1 (10/30) - ユーザー定義シグナル 1
    SIGUSR1,
    /// SIGUSR2 (12/31) - ユーザー定義シグナル 2
    SIGUSR2,
}

impl Signal {
    /// nix の Signal 型に変換する
    fn to_nix(self) -> NixSignal {
        match self {
            Signal::SIGHUP => NixSignal::SIGHUP,
            Signal::SIGINT => NixSignal::SIGINT,
            Signal::SIGQUIT => NixSignal::SIGQUIT,
            Signal::SIGKILL => NixSignal::SIGKILL,
            Signal::SIGTERM => NixSignal::SIGTERM,
            Signal::SIGUSR1 => NixSignal::SIGUSR1,
            Signal::SIGUSR2 => NixSignal::SIGUSR2,
        }
    }

    /// シグナル番号を取得する
    pub fn number(&self) -> i32 {
        self.to_nix() as i32
    }

    /// シグナル名を取得する
    pub fn name(&self) -> &'static str {
        match self {
            Signal::SIGHUP => "SIGHUP",
            Signal::SIGINT => "SIGINT",
            Signal::SIGQUIT => "SIGQUIT",
            Signal::SIGKILL => "SIGKILL",
            Signal::SIGTERM => "SIGTERM",
            Signal::SIGUSR1 => "SIGUSR1",
            Signal::SIGUSR2 => "SIGUSR2",
        }
    }
}

/// Unix プロセス向けシグナル送信器
pub struct SignalSender;

impl SignalSender {
    /// 文字列からシグナルを解析する（名前または番号）
    ///
    /// 受け付ける形式:
    /// - シグナル名: "SIGTERM", "SIGKILL", "TERM", "KILL" など
    /// - シグナル番号: "15", "9" など
    pub fn parse_signal(s: &str) -> Result<Signal, SafeKillError> {
        let s = s.trim().to_uppercase();

        // まず番号として解析を試みる
        if let Ok(num) = s.parse::<i32>() {
            return Self::from_number(num);
        }

        // 名前として解析を試みる
        Self::from_name(&s)
    }

    /// 番号からシグナルを解析する
    fn from_number(num: i32) -> Result<Signal, SafeKillError> {
        match num {
            1 => Ok(Signal::SIGHUP),
            2 => Ok(Signal::SIGINT),
            3 => Ok(Signal::SIGQUIT),
            9 => Ok(Signal::SIGKILL),
            15 => Ok(Signal::SIGTERM),
            10 | 30 => Ok(Signal::SIGUSR1), // Linux: 10, macOS: 30
            12 | 31 => Ok(Signal::SIGUSR2), // Linux: 12, macOS: 31
            _ => Err(SafeKillError::InvalidSignal(num.to_string())),
        }
    }

    /// 名前からシグナルを解析する
    fn from_name(s: &str) -> Result<Signal, SafeKillError> {
        // SIG プレフィックスがあれば除去
        let name = s.strip_prefix("SIG").unwrap_or(s);

        match name {
            "HUP" => Ok(Signal::SIGHUP),
            "INT" => Ok(Signal::SIGINT),
            "QUIT" => Ok(Signal::SIGQUIT),
            "KILL" => Ok(Signal::SIGKILL),
            "TERM" => Ok(Signal::SIGTERM),
            "USR1" => Ok(Signal::SIGUSR1),
            "USR2" => Ok(Signal::SIGUSR2),
            _ => Err(SafeKillError::InvalidSignal(s.to_string())),
        }
    }

    /// プロセスにシグナルを送信する
    pub fn send(pid: u32, signal: Signal) -> Result<(), SafeKillError> {
        // PID 0 および i32 を超える値は nix::Pid::from_raw で安全に扱えない。
        // PID 0 は特殊な意味（プロセスグループ）を持つため明示的に拒否する。
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(SafeKillError::InvalidPid(pid.to_string()));
        }

        let nix_pid = Pid::from_raw(pid as i32);
        let nix_signal = signal.to_nix();

        signal::kill(nix_pid, nix_signal).map_err(|e| match e {
            nix::errno::Errno::ESRCH => SafeKillError::ProcessNotFound(pid),
            nix::errno::Errno::EPERM => SafeKillError::PermissionDenied(pid),
            _ => SafeKillError::SystemError(format!("Failed to send signal: {}", e)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signal enum のテスト
    #[test]
    fn test_signal_default() {
        assert_eq!(Signal::default(), Signal::SIGTERM);
    }

    #[test]
    fn test_signal_name() {
        assert_eq!(Signal::SIGHUP.name(), "SIGHUP");
        assert_eq!(Signal::SIGINT.name(), "SIGINT");
        assert_eq!(Signal::SIGQUIT.name(), "SIGQUIT");
        assert_eq!(Signal::SIGKILL.name(), "SIGKILL");
        assert_eq!(Signal::SIGTERM.name(), "SIGTERM");
        assert_eq!(Signal::SIGUSR1.name(), "SIGUSR1");
        assert_eq!(Signal::SIGUSR2.name(), "SIGUSR2");
    }

    #[test]
    fn test_signal_number() {
        assert_eq!(Signal::SIGHUP.number(), 1);
        assert_eq!(Signal::SIGINT.number(), 2);
        assert_eq!(Signal::SIGQUIT.number(), 3);
        assert_eq!(Signal::SIGKILL.number(), 9);
        assert_eq!(Signal::SIGTERM.number(), 15);
    }

    // 番号からの解析テスト
    #[test]
    fn test_parse_signal_from_number() {
        assert_eq!(SignalSender::parse_signal("1").unwrap(), Signal::SIGHUP);
        assert_eq!(SignalSender::parse_signal("2").unwrap(), Signal::SIGINT);
        assert_eq!(SignalSender::parse_signal("3").unwrap(), Signal::SIGQUIT);
        assert_eq!(SignalSender::parse_signal("9").unwrap(), Signal::SIGKILL);
        assert_eq!(SignalSender::parse_signal("15").unwrap(), Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_usr1_linux() {
        assert_eq!(SignalSender::parse_signal("10").unwrap(), Signal::SIGUSR1);
    }

    #[test]
    fn test_parse_signal_usr1_macos() {
        assert_eq!(SignalSender::parse_signal("30").unwrap(), Signal::SIGUSR1);
    }

    #[test]
    fn test_parse_signal_usr2_linux() {
        assert_eq!(SignalSender::parse_signal("12").unwrap(), Signal::SIGUSR2);
    }

    #[test]
    fn test_parse_signal_usr2_macos() {
        assert_eq!(SignalSender::parse_signal("31").unwrap(), Signal::SIGUSR2);
    }

    // 名前からの解析テスト
    #[test]
    fn test_parse_signal_from_name_with_prefix() {
        assert_eq!(
            SignalSender::parse_signal("SIGTERM").unwrap(),
            Signal::SIGTERM
        );
        assert_eq!(
            SignalSender::parse_signal("SIGKILL").unwrap(),
            Signal::SIGKILL
        );
        assert_eq!(
            SignalSender::parse_signal("SIGHUP").unwrap(),
            Signal::SIGHUP
        );
        assert_eq!(
            SignalSender::parse_signal("SIGINT").unwrap(),
            Signal::SIGINT
        );
        assert_eq!(
            SignalSender::parse_signal("SIGQUIT").unwrap(),
            Signal::SIGQUIT
        );
        assert_eq!(
            SignalSender::parse_signal("SIGUSR1").unwrap(),
            Signal::SIGUSR1
        );
        assert_eq!(
            SignalSender::parse_signal("SIGUSR2").unwrap(),
            Signal::SIGUSR2
        );
    }

    #[test]
    fn test_parse_signal_from_name_without_prefix() {
        assert_eq!(SignalSender::parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(SignalSender::parse_signal("KILL").unwrap(), Signal::SIGKILL);
        assert_eq!(SignalSender::parse_signal("HUP").unwrap(), Signal::SIGHUP);
        assert_eq!(SignalSender::parse_signal("INT").unwrap(), Signal::SIGINT);
        assert_eq!(SignalSender::parse_signal("QUIT").unwrap(), Signal::SIGQUIT);
        assert_eq!(SignalSender::parse_signal("USR1").unwrap(), Signal::SIGUSR1);
        assert_eq!(SignalSender::parse_signal("USR2").unwrap(), Signal::SIGUSR2);
    }

    #[test]
    fn test_parse_signal_case_insensitive() {
        assert_eq!(
            SignalSender::parse_signal("sigterm").unwrap(),
            Signal::SIGTERM
        );
        assert_eq!(
            SignalSender::parse_signal("Sigkill").unwrap(),
            Signal::SIGKILL
        );
        assert_eq!(SignalSender::parse_signal("term").unwrap(), Signal::SIGTERM);
        assert_eq!(SignalSender::parse_signal("kill").unwrap(), Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_with_whitespace() {
        assert_eq!(
            SignalSender::parse_signal("  SIGTERM  ").unwrap(),
            Signal::SIGTERM
        );
        assert_eq!(SignalSender::parse_signal(" 15 ").unwrap(), Signal::SIGTERM);
    }

    // 無効なシグナルのテスト
    #[test]
    fn test_parse_invalid_signal_number() {
        let result = SignalSender::parse_signal("99");
        assert!(result.is_err());
        match result {
            Err(SafeKillError::InvalidSignal(s)) => assert_eq!(s, "99"),
            _ => panic!("Expected InvalidSignal error"),
        }
    }

    #[test]
    fn test_parse_invalid_signal_name() {
        let result = SignalSender::parse_signal("SIGFOO");
        assert!(result.is_err());
        match result {
            Err(SafeKillError::InvalidSignal(s)) => assert_eq!(s, "SIGFOO"),
            _ => panic!("Expected InvalidSignal error"),
        }
    }

    #[test]
    fn test_parse_empty_signal() {
        let result = SignalSender::parse_signal("");
        assert!(result.is_err());
    }

    // =============================================================================
    // 異常入力テスト（Codex分析により追加）
    // =============================================================================

    #[test]
    fn test_parse_signal_only_sig_prefix() {
        // "SIG"のみの場合はエラー
        let result = SignalSender::parse_signal("SIG");
        assert!(result.is_err());
        match result {
            Err(SafeKillError::InvalidSignal(s)) => assert_eq!(s, "SIG"),
            _ => panic!("Expected InvalidSignal error"),
        }
    }

    #[test]
    fn test_parse_signal_whitespace_only() {
        // 空白のみの場合はエラー
        let result = SignalSender::parse_signal("   ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signal_negative_number() {
        // 負の数はエラー
        let result = SignalSender::parse_signal("-1");
        assert!(result.is_err());

        let result = SignalSender::parse_signal("-15");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signal_zero() {
        // シグナル番号0はサポートされていない
        let result = SignalSender::parse_signal("0");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signal_very_large_number() {
        // 非常に大きな数はエラー
        let result = SignalSender::parse_signal("999999");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signal_special_characters() {
        // 特殊文字を含む場合はエラー
        assert!(SignalSender::parse_signal("SIGTERM!").is_err());
        assert!(SignalSender::parse_signal("SIG@TERM").is_err());
        assert!(SignalSender::parse_signal("15#").is_err());
    }

    #[test]
    fn test_parse_signal_mixed_number_and_name() {
        // 数字と名前の混合はエラー
        assert!(SignalSender::parse_signal("SIG15").is_err());
        assert!(SignalSender::parse_signal("15TERM").is_err());
    }

    // シグナル送信テスト
    #[test]
    fn test_send_to_nonexistent_process() {
        // 存在する可能性が極めて低い大きな PID を使用
        let result = SignalSender::send(999999999, Signal::SIGTERM);
        assert!(result.is_err());
        match result {
            Err(SafeKillError::ProcessNotFound(pid)) => assert_eq!(pid, 999999999),
            Err(SafeKillError::PermissionDenied(_)) => {
                // 一部のシステムでは代わりに permission denied を返す場合がある
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(_) => panic!("Expected error for nonexistent process"),
        }
    }

    #[test]
    fn test_send_rejects_pid_zero() {
        let result = SignalSender::send(0, Signal::SIGTERM);
        assert!(matches!(result, Err(SafeKillError::InvalidPid(_))));
    }

    #[test]
    fn test_send_rejects_pid_over_i32_max() {
        let overflow_pid = i32::MAX as u32 + 1;
        let result = SignalSender::send(overflow_pid, Signal::SIGTERM);
        assert!(matches!(result, Err(SafeKillError::InvalidPid(_))));
    }

    #[test]
    fn test_signal_number_all_variants() {
        // すべてのシグナルが有効な番号を持つことを検証
        let signals = [
            (Signal::SIGHUP, 1),
            (Signal::SIGINT, 2),
            (Signal::SIGQUIT, 3),
            (Signal::SIGKILL, 9),
            (Signal::SIGTERM, 15),
        ];
        for (sig, expected_num) in &signals {
            assert_eq!(sig.number(), *expected_num);
        }
        // SIGUSR1 と SIGUSR2 はプラットフォーム固有の番号を持つ
        assert!(Signal::SIGUSR1.number() > 0);
        assert!(Signal::SIGUSR2.number() > 0);
    }

    // Clone と Copy のテスト
    #[test]
    fn test_signal_clone() {
        let sig = Signal::SIGTERM;
        let cloned = sig;
        assert_eq!(sig, cloned);
    }

    #[test]
    fn test_signal_debug() {
        let sig = Signal::SIGTERM;
        let debug_str = format!("{:?}", sig);
        assert_eq!(debug_str, "SIGTERM");
    }

    #[test]
    fn test_send_pid_i32_max_boundary() {
        // i32::MAX はギリギリ有効な PID 値（プロセスは存在しないが InvalidPid にはならない）
        let result = SignalSender::send(i32::MAX as u32, Signal::SIGTERM);
        assert!(
            matches!(
                result,
                Err(SafeKillError::ProcessNotFound(_)) | Err(SafeKillError::PermissionDenied(_))
            ),
            "i32::MAX は有効な PID 範囲だが、プロセスが存在しないためエラーになる"
        );
    }

    #[test]
    fn test_send_pid_1_permission_denied_or_ok() {
        // PID 1 (init/launchd) への送信は PermissionDenied になることが多い
        let result = SignalSender::send(1, Signal::SIGTERM);
        // 環境依存のためエラー型は限定しないが、InvalidPid にはならないことを確認
        assert!(
            !matches!(result, Err(SafeKillError::InvalidPid(_))),
            "PID 1 は有効な PID なので InvalidPid にはならない"
        );
    }
}
