//! safe-kill のシグナル処理
//!
//! nix クレートを使用した Unix シグナルの解析と送信機能を提供する。

use crate::error::SafeKillError;
use nix::errno::Errno;
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
    /// - シグナル名: "SIGTERM", "SIGKILL", "TERM", "KILL" など（ASCII の大文字・小文字は区別しない）
    /// - シグナル番号: "15", "9" など
    ///
    /// 照合は ASCII だけで行う。以前の `str::to_uppercase` は Unicode の大文字化なので、
    /// `ſ`（U+017F）が `S` に、`ı`（U+0131）が `I` になり、`ſigterm` や `sıgkıll` が
    /// SIGTERM / SIGKILL として通っていた。前後の空白も ASCII の空白
    /// （`char::is_ascii_whitespace`: SP / HT / LF / FF / CR）だけを除く。`str::trim` は
    /// Unicode の White_Space（U+0085 / U+00A0 / U+2028 / U+3000 など）まで除くため、
    /// 端末では見分けにくい文字を前置した値まで受理していた（VT も ASCII だが
    /// `is_ascii_whitespace` に含まれないので除かない）。
    ///
    /// エラー（`InvalidSignal`）には入力をそのまま入れる。大文字化した値を入れると
    /// `foo` が `FOO` と表示され、`ß` と `ss` がどちらも `SS` になって区別できない。
    /// 制御文字は表示するときに `terminal.rs` のサニタイズがエスケープする。
    pub fn parse_signal(s: &str) -> Result<Signal, SafeKillError> {
        let trimmed = s.trim_matches(|c: char| c.is_ascii_whitespace());

        // まず番号として解析を試み、番号でなければ名前として解析する。
        // `i32` の `FromStr` は先頭の符号と ASCII の数字だけを受け付ける。
        let signal = match trimmed.parse::<i32>() {
            Ok(num) => Self::from_number(num),
            Err(_) => Self::from_name(trimmed),
        };
        signal.ok_or_else(|| SafeKillError::InvalidSignal(s.to_string()))
    }

    /// 番号からシグナルを解析する
    ///
    /// USR1/USR2 のシグナル番号はプラットフォームごとに異なるため、
    /// 各 OS のネイティブな番号のみ受け付ける:
    /// - Linux: USR1=10, USR2=12
    /// - macOS: USR1=30, USR2=31
    fn from_number(num: i32) -> Option<Signal> {
        match num {
            1 => Some(Signal::SIGHUP),
            2 => Some(Signal::SIGINT),
            3 => Some(Signal::SIGQUIT),
            9 => Some(Signal::SIGKILL),
            15 => Some(Signal::SIGTERM),
            #[cfg(target_os = "linux")]
            10 => Some(Signal::SIGUSR1),
            #[cfg(target_os = "linux")]
            12 => Some(Signal::SIGUSR2),
            #[cfg(target_os = "macos")]
            30 => Some(Signal::SIGUSR1),
            #[cfg(target_os = "macos")]
            31 => Some(Signal::SIGUSR2),
            _ => None,
        }
    }

    /// 名前からシグナルを解析する（ASCII の大文字・小文字は区別しない）
    fn from_name(s: &str) -> Option<Signal> {
        // ASCII の英字だけを大文字にする。非 ASCII の文字はそのまま残るので、
        // どの名前とも一致しない。
        let upper = s.to_ascii_uppercase();
        // SIG プレフィックスがあれば除去
        let name = upper.strip_prefix("SIG").unwrap_or(&upper);

        match name {
            "HUP" => Some(Signal::SIGHUP),
            "INT" => Some(Signal::SIGINT),
            "QUIT" => Some(Signal::SIGQUIT),
            "KILL" => Some(Signal::SIGKILL),
            "TERM" => Some(Signal::SIGTERM),
            "USR1" => Some(Signal::SIGUSR1),
            "USR2" => Some(Signal::SIGUSR2),
            _ => None,
        }
    }

    /// プロセスにシグナルを送信する
    pub fn send(pid: u32, signal: Signal) -> Result<(), SafeKillError> {
        Self::send_with(pid, signal, signal::kill)
    }

    /// `send` の本体。シグナルを実際に送る関数を引数で受け取る
    ///
    /// PID の検証が送信より先に行われることと、送信の失敗の対応付けを、実際の
    /// `kill(2)` を呼ばずに単体テストで確かめるために分けている。検証が退行したときに
    /// テスト自身が PID 0（自分のプロセスグループ）や -1（送れる全プロセス）へ
    /// 送ってしまう形のテストを書かずに済む。
    fn send_with(
        pid: u32,
        signal: Signal,
        kill: impl FnOnce(Pid, NixSignal) -> nix::Result<()>,
    ) -> Result<(), SafeKillError> {
        let nix_pid = to_nix_pid(pid)?;
        kill(nix_pid, signal.to_nix()).map_err(|errno| kill_error(pid, errno))
    }
}

/// シグナルの送信先として安全に渡せる PID へ変換する
///
/// `kill(2)` は PID の値で送り先の意味が変わる。0 は自分のプロセスグループ、-1 は
/// 送れる全プロセス、-1 未満は -pid のプロセスグループ全体になる。`u32` を `as i32` で
/// 変換すると `i32::MAX` を超える値が負数へ折り返す（`u32::MAX` は -1 になる）ので、
/// 1..=`i32::MAX` 以外は `InvalidPid` として送る前に拒否する。
fn to_nix_pid(pid: u32) -> Result<Pid, SafeKillError> {
    match i32::try_from(pid) {
        Ok(raw) if raw > 0 => Ok(Pid::from_raw(raw)),
        _ => Err(SafeKillError::InvalidPid(pid.to_string())),
    }
}

/// `kill(2)` の失敗を `SafeKillError` に対応付ける
///
/// ESRCH（対象が居ない）は `ProcessNotFound`、EPERM（送る権限が無い）は `PermissionDenied`、
/// それ以外は `SystemError` にする。
fn kill_error(pid: u32, errno: Errno) -> SafeKillError {
    match errno {
        Errno::ESRCH => SafeKillError::ProcessNotFound(pid),
        Errno::EPERM => SafeKillError::PermissionDenied(pid),
        _ => SafeKillError::SystemError(format!("Failed to send signal: {}", errno)),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_signal_usr1_linux() {
        assert_eq!(SignalSender::parse_signal("10").unwrap(), Signal::SIGUSR1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_signal_usr1_macos() {
        assert_eq!(SignalSender::parse_signal("30").unwrap(), Signal::SIGUSR1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_signal_usr2_linux() {
        assert_eq!(SignalSender::parse_signal("12").unwrap(), Signal::SIGUSR2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_signal_usr2_macos() {
        assert_eq!(SignalSender::parse_signal("31").unwrap(), Signal::SIGUSR2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_signal_linux_number_rejected_on_macos() {
        // macOS ではシグナル番号 10 は SIGBUS であり SIGUSR1 ではない
        assert!(
            SignalSender::parse_signal("10").is_err(),
            "macOS ではシグナル番号 10 は拒否されるべき"
        );
        // macOS ではシグナル番号 12 は SIGSYS であり SIGUSR2 ではない（SIGPIPE は 13）
        assert!(
            SignalSender::parse_signal("12").is_err(),
            "macOS ではシグナル番号 12 は拒否されるべき"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_signal_macos_number_rejected_on_linux() {
        // Linux ではシグナル番号 30 は SIGPWR であり SIGUSR1 ではない
        assert!(
            SignalSender::parse_signal("30").is_err(),
            "Linux ではシグナル番号 30 は拒否されるべき"
        );
        // Linux ではシグナル番号 31 は SIGSYS であり SIGUSR2 ではない
        assert!(
            SignalSender::parse_signal("31").is_err(),
            "Linux ではシグナル番号 31 は拒否されるべき"
        );
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
        // 前後から除くのは ASCII の空白（SP / HT / LF / FF / CR）すべて
        assert_eq!(
            SignalSender::parse_signal("\t\n\x0c\r sigKill \r\x0c\n\t").unwrap(),
            Signal::SIGKILL
        );
        assert_eq!(
            SignalSender::parse_signal("\t9\n").unwrap(),
            Signal::SIGKILL
        );
    }

    /// 以前の正規化（`str::trim` + `str::to_uppercase`）で受理されていたかを返す
    ///
    /// 拒否を確かめるテストの入力が、実際に修正前の実装をすり抜けていた値であることを
    /// 先に確認するために使う（そうでなければ、何も検証しないテストになる）。
    fn accepted_by_legacy_normalization(s: &str) -> bool {
        SignalSender::parse_signal(&s.trim().to_uppercase()).is_ok()
    }

    #[test]
    fn test_parse_signal_rejects_non_ascii_letters_that_uppercase_to_ascii() {
        // `ſ`（U+017F）と `ı`（U+0131）は Unicode の大文字化で ASCII の `S` / `I` になる。
        // 照合を ASCII だけで行うので、どのシグナル名とも一致しない。
        for input in ["ſigterm", "sıgkıll", "SIGKıLL", "uſr1", "ſıgınt"] {
            assert!(
                accepted_by_legacy_normalization(input),
                "前提: {input:?} は以前の正規化では受理されていた"
            );
            assert_eq!(
                SignalSender::parse_signal(input),
                Err(SafeKillError::InvalidSignal(input.to_string())),
                "{input:?}"
            );
        }
    }

    #[test]
    fn test_parse_signal_rejects_non_ascii_whitespace_around_value() {
        // U+2028 LINE SEPARATOR / U+0085 NEL / U+00A0 NO-BREAK SPACE / U+3000 IDEOGRAPHIC SPACE は
        // Unicode の White_Space なので `str::trim` なら除かれるが、ASCII の空白ではない。
        for space in ['\u{2028}', '\u{0085}', '\u{00A0}', '\u{3000}'] {
            for input in [
                format!("{space}SIGTERM"),
                format!("SIGTERM{space}"),
                format!("{space}15"),
                format!("15{space}"),
            ] {
                assert!(
                    accepted_by_legacy_normalization(&input),
                    "前提: {input:?} は以前の正規化では受理されていた"
                );
                assert_eq!(
                    SignalSender::parse_signal(&input),
                    Err(SafeKillError::InvalidSignal(input.clone())),
                    "{input:?}"
                );
            }
        }
    }

    #[test]
    fn test_parse_signal_error_keeps_input_as_is() {
        // エラーには大文字化した値ではなく入力そのものを入れる
        assert_eq!(
            SignalSender::parse_signal("foo"),
            Err(SafeKillError::InvalidSignal("foo".to_string()))
        );
        assert_eq!(
            SignalSender::parse_signal(" sigfoo\t"),
            Err(SafeKillError::InvalidSignal(" sigfoo\t".to_string()))
        );
        // 番号の経路でも入力をそのまま入れる（`i32` へ変換した値に正規化しない）
        assert_eq!(
            SignalSender::parse_signal("+099"),
            Err(SafeKillError::InvalidSignal("+099".to_string()))
        );

        // `ß` は Unicode の大文字化で `SS` になる。以前は `ß` と `ss` のエラーが
        // どちらも `Invalid signal: SS` になり、何を渡したのか区別できなかった。
        assert_eq!("ß".to_uppercase(), "ss".to_uppercase());
        let eszett = SignalSender::parse_signal("ß").unwrap_err();
        let double_s = SignalSender::parse_signal("ss").unwrap_err();
        assert_eq!(eszett, SafeKillError::InvalidSignal("ß".to_string()));
        assert_eq!(double_s, SafeKillError::InvalidSignal("ss".to_string()));
        assert_ne!(eszett.to_string(), double_s.to_string());
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
    // 異常入力テスト
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

    // 危険な PID の拒否は `send_with` に偽の送信関数を渡して確かめる。`send` を直接呼ぶと、
    // 検証が退行したときに PID 0（自分のプロセスグループ = テストの実行そのもの）や
    // -1（`u32::MAX` が折り返した値。送れる全プロセス）へ本物のシグナルが届く。

    /// 呼ばれたら失敗する送信関数（検証で拒否されるべき PID に使う）
    fn kill_must_not_be_called(pid: Pid, _signal: NixSignal) -> nix::Result<()> {
        panic!("検証で拒否されるべき PID {pid} にシグナルを送ろうとした");
    }

    #[test]
    fn test_send_rejects_dangerous_pids_before_kill() {
        for pid in [0, i32::MAX as u32 + 1, u32::MAX] {
            let result = SignalSender::send_with(pid, Signal::SIGTERM, kill_must_not_be_called);
            assert_eq!(
                result,
                Err(SafeKillError::InvalidPid(pid.to_string())),
                "PID {pid}"
            );
        }
    }

    #[test]
    fn test_to_nix_pid_boundaries() {
        // 1..=i32::MAX だけを受理する。0 は自分のプロセスグループ、`as i32` で負数へ
        // 折り返す値は送れる全プロセス（-1）やプロセスグループ（-1 未満）を意味する
        assert_eq!(to_nix_pid(1), Ok(Pid::from_raw(1)));
        assert_eq!(to_nix_pid(i32::MAX as u32), Ok(Pid::from_raw(i32::MAX)));
        for pid in [0, i32::MAX as u32 + 1, u32::MAX] {
            assert_eq!(
                to_nix_pid(pid),
                Err(SafeKillError::InvalidPid(pid.to_string())),
                "PID {pid}"
            );
        }
    }

    #[test]
    fn test_send_passes_validated_pid_and_signal_to_kill() {
        // PID 1 は有効な PID として送信まで進む（実際には送らない）
        let mut sent = None;
        let result = SignalSender::send_with(1, Signal::SIGKILL, |pid, signal| {
            sent = Some((pid, signal));
            Ok(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(sent, Some((Pid::from_raw(1), NixSignal::SIGKILL)));
    }

    #[test]
    fn test_send_maps_kill_errors() {
        // ESRCH は対象が居ない、EPERM は権限が無い、それ以外は SystemError
        let cases = [
            (Errno::ESRCH, SafeKillError::ProcessNotFound(42)),
            (Errno::EPERM, SafeKillError::PermissionDenied(42)),
        ];
        for (errno, expected) in cases {
            let result = SignalSender::send_with(42, Signal::SIGTERM, |_, _| Err(errno));
            assert_eq!(result, Err(expected), "{errno:?}");
        }
        let result = SignalSender::send_with(42, Signal::SIGTERM, |_, _| Err(Errno::EINVAL));
        assert!(
            matches!(result, Err(SafeKillError::SystemError(ref message)) if message.contains("Failed to send signal")),
            "{result:?}"
        );
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

    // サポート外のシグナル番号テスト
    #[test]
    fn test_parse_signal_unsupported_numbers_in_range() {
        // 1-31 の範囲内だがサポート対象外のシグナル番号
        for num in [4, 5, 6, 7, 8, 11, 13, 14, 16, 17, 18, 19, 20, 21] {
            let result = SignalSender::parse_signal(&num.to_string());
            assert!(
                result.is_err(),
                "シグナル番号 {} はサポート外のためエラーになるべき",
                num
            );
        }
    }

    #[test]
    fn test_signal_usr1_usr2_platform_number() {
        // プラットフォーム固有の番号が正しいことを検証
        #[cfg(target_os = "macos")]
        {
            assert_eq!(Signal::SIGUSR1.number(), 30);
            assert_eq!(Signal::SIGUSR2.number(), 31);
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(Signal::SIGUSR1.number(), 10);
            assert_eq!(Signal::SIGUSR2.number(), 12);
        }
    }

    #[test]
    fn test_signal_name_number_roundtrip() {
        // 名前 → シグナル → 番号 → シグナル のラウンドトリップ
        let signals = ["HUP", "INT", "QUIT", "KILL", "TERM", "USR1", "USR2"];
        for name in signals {
            let sig = SignalSender::parse_signal(name).unwrap();
            let num = sig.number();
            let sig2 = SignalSender::parse_signal(&num.to_string()).unwrap();
            assert_eq!(sig, sig2, "{} のラウンドトリップが一致するべき", name);
        }
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

    // 実プロセスへのシグナル送信成功テスト
    #[test]
    fn test_send_success_to_child_process() {
        use std::process::Command;

        // 子プロセスを生成
        let child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("sleep プロセスの起動に失敗");
        let pid = child.id();

        // SIGTERM を送信し、成功を確認
        let result = SignalSender::send(pid, Signal::SIGTERM);
        assert!(result.is_ok(), "子プロセスへの SIGTERM 送信は成功するべき");

        // 終了を待つ
        let mut child = child;
        let _ = child.wait();
    }

    // 子プロセスに各種シグナルを送信できることを確認
    #[test]
    fn test_send_various_signals_to_child() {
        use std::process::Command;

        for signal in [
            Signal::SIGHUP,
            Signal::SIGINT,
            Signal::SIGQUIT,
            Signal::SIGKILL,
        ] {
            let child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("sleep プロセスの起動に失敗");
            let pid = child.id();

            let result = SignalSender::send(pid, signal);
            assert!(result.is_ok(), "{} の送信が失敗した", signal.name());

            let mut child = child;
            let _ = child.wait();
        }
    }
}
