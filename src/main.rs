//! safe-kill: AI エージェント向け安全プロセス終了ツール
//!
//! ancestry ベースのアクセス制御で、現在セッションの子孫プロセスのみを
//! 安全に終了できるようにする。

use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use safe_kill::cli::{CliArgs, ExecutionMode};
use safe_kill::error::{SafeKillError, SafeKillExitCode};
use safe_kill::init::{InitCommand, InitOutcome};
use safe_kill::killer::{BatchKillResult, KillResult};
use safe_kill::policy::PolicyEngine;
use safe_kill::process_info;
use safe_kill::terminal::{sanitize_path, sanitize_terminal};

/// 表示の書き込み先
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputStream {
    Stdout,
    Stderr,
}

impl fmt::Display for OutputStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputStream::Stdout => write!(f, "stdout"),
            OutputStream::Stderr => write!(f, "stderr"),
        }
    }
}

/// `run()` の失敗理由
///
/// 「操作そのものの失敗（ドメインエラー）」と「操作結果を表示できなかった失敗」を
/// 分けて扱う。両者を混ぜると、表示の失敗が kill の成否を上書きしてしまう。
#[derive(Debug)]
enum RunError {
    /// kill 判定・設定読み込みなど、操作自体の失敗
    Domain(SafeKillError),
    /// 操作は確定したが、その結果を書き出せなかった
    Output {
        stream: OutputStream,
        source: io::Error,
    },
}

impl From<SafeKillError> for RunError {
    fn from(e: SafeKillError) -> Self {
        RunError::Domain(e)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(RunError::Domain(e)) => {
            // エラーメッセージには `NotDescendant(pid, name)` や `Denylisted(name)` のように
            // OS から取得したプロセス名が含まれることがある。攻撃者が `\x1b[2J` 等の
            // ANSI escape を含む引数でプロセスを起動した場合に、エラー経路でも表示偽装や
            // 端末状態改ざんが起きないよう、表示前に必ずサニタイズする。
            //
            // 診断の書き込み失敗で終了コードを変えてはいけない。呼び出し側が分岐に使う
            // のは「なぜ失敗したか」であって「その説明が届いたか」ではないため、
            // ここでは書き込み結果を捨てて元の終了コードを維持する。
            let _ = writeln!(
                io::stderr(),
                "safe-kill: {}",
                sanitize_terminal(&e.to_string())
            );
            e.exit_code().into()
        }
        Err(RunError::Output { stream, source }) => {
            // BrokenPipe は `finish_output` が成功として処理済みなので、ここへ来るのは
            // ディスク満杯（ENOSPC）や I/O エラーなど「出力が本当に失われた」場合だけ。
            let _ = writeln!(
                io::stderr(),
                "safe-kill: failed to write to {}: {}",
                stream,
                sanitize_terminal(&source.to_string())
            );
            SafeKillExitCode::GeneralError.into()
        }
    }
}

/// 操作結果と表示結果を突き合わせて最終的な実行結果を決める
///
/// 優先順位は「操作の結果 > 表示の結果」。
///
/// * ドメインエラーが出ていれば、表示が成功していようと失敗していようとそれを返す
///   （終了コードは操作の意味を表すという契約を守る）
/// * 表示が `BrokenPipe` で失敗した場合は、読み手がパイプを閉じただけであり操作は
///   完了しているので成功として扱う。`safe-kill --list | head -1` のような通常の
///   シェル利用で、Rust の `println!` が panic して終了コード 101 になるのを防ぐ
///   （Rust ランタイムは起動時に SIGPIPE を無視するため、EPIPE が panic に化ける）
/// * それ以外の I/O エラーは出力が本当に失われているので `Output` として報告する
fn finish_output(
    outcome: Result<(), SafeKillError>,
    printed: io::Result<()>,
    stream: OutputStream,
) -> Result<(), RunError> {
    if let Err(e) = outcome {
        return Err(RunError::Domain(e));
    }

    match printed {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(source) => Err(RunError::Output { stream, source }),
    }
}

/// メインの実行ロジック
fn run() -> Result<(), RunError> {
    // CLI 引数を解析する
    let args = CliArgs::parse_args();

    // 実行モードを検証して確定する
    let mode = args.validate()?;

    // 実行モードごとに処理する
    match mode {
        ExecutionMode::KillByPid(pid) => {
            let engine = PolicyEngine::try_with_defaults()?;
            let signal = args.parse_signal()?;
            let result = engine.kill_by_pid(pid, signal, args.dry_run)?;
            let printed =
                print_kill_result(&result.name, result.pid, result.success, &result.message);
            let outcome = if result.success {
                Ok(())
            } else {
                Err(single_result_error(&result))
            };
            finish_output(outcome, printed, OutputStream::Stdout)
        }
        ExecutionMode::KillByName(name) => {
            let engine = PolicyEngine::try_with_defaults()?;
            let signal = args.parse_signal()?;
            let batch_result = engine.kill_by_name(&name, signal, args.dry_run)?;
            let printed = print_batch_result(&batch_result, args.dry_run);
            let outcome = if batch_result.any_success() {
                Ok(())
            } else {
                Err(batch_result_error(
                    format!("name '{}'", name),
                    &batch_result,
                ))
            };
            finish_output(outcome, printed, OutputStream::Stdout)
        }
        ExecutionMode::ListKillable => {
            let engine = PolicyEngine::try_with_defaults()?;
            let processes = engine.list_killable();
            let printed = print_killable_list(&processes);
            finish_output(Ok(()), printed, OutputStream::Stdout)
        }
        ExecutionMode::KillByPort(port) => {
            let engine = PolicyEngine::try_with_defaults()?;
            let signal = args.parse_signal()?;
            let batch_result = engine.kill_by_port(port, signal, args.dry_run)?;
            let printed = print_port_kill_result(port, &batch_result, args.dry_run);
            let outcome = if batch_result.any_success() {
                Ok(())
            } else if batch_result.results.is_empty() {
                Err(SafeKillError::NoProcessOnPort(port))
            } else {
                Err(batch_result_error(format!("port {}", port), &batch_result))
            };
            finish_output(outcome, printed, OutputStream::Stdout)
        }
        ExecutionMode::InitConfig { force } => match InitCommand::execute(force)? {
            InitOutcome::Created {
                config_path,
                written_path,
                via_symlink,
            } => {
                let printed = print_init_created(&config_path, &written_path, via_symlink);
                finish_output(Ok(()), printed, OutputStream::Stdout)
            }
            InitOutcome::SkippedExisting {
                config_path,
                target_path,
                via_symlink,
            } => {
                let printed = print_init_skipped(&config_path, &target_path, via_symlink);
                finish_output(Ok(()), printed, OutputStream::Stderr)
            }
        },
    }
}

/// `safe-kill init` の生成結果を表示する
fn print_init_created(
    config_path: &Path,
    written_path: &Path,
    via_symlink: bool,
) -> io::Result<()> {
    let mut out = io::stdout().lock();
    // config.toml が symlink のときは実際に書き込んだ実体パスも示す。
    // 「Created: .../config.toml」とだけ表示すると、dotfiles 等の
    // リンク先ファイルを上書きした事実が利用者に伝わらない。
    if !via_symlink {
        writeln!(out, "Created: {}", sanitize_path(config_path))?;
    } else {
        writeln!(
            out,
            "Created: {} (written via symlink {})",
            sanitize_path(written_path),
            sanitize_path(config_path)
        )?;
    }
    writeln!(out)?;
    writeln!(
        out,
        "Hint: Edit the config file to customize allowed ports and process lists."
    )?;
    writeln!(
        out,
        "      Then use `safe-kill --port <PORT>` to kill processes by port."
    )
}

/// `safe-kill init` で既存設定を残した結果を表示する
fn print_init_skipped(config_path: &Path, target_path: &Path, via_symlink: bool) -> io::Result<()> {
    let mut out = io::stderr().lock();
    // ユーザーが上書きを拒否した場合は正常な no-op として扱う（終了コード 0）。
    if !via_symlink {
        writeln!(
            out,
            "Skipped. Existing config left unchanged: {}",
            sanitize_path(config_path)
        )
    } else {
        writeln!(
            out,
            "Skipped. Existing config left unchanged: {} (symlink to {})",
            sanitize_path(config_path),
            sanitize_path(target_path)
        )
    }
}

/// 1 件分の実行結果から返却用エラーを復元する
fn single_result_error(result: &KillResult) -> SafeKillError {
    result
        .error
        .clone()
        .unwrap_or_else(|| SafeKillError::SystemError(result.message.clone()))
}

/// 複数件の実行結果から返却用エラーを選ぶ
fn batch_result_error(target: String, result: &BatchKillResult) -> SafeKillError {
    result
        .first_operational_error()
        .cloned()
        .unwrap_or(SafeKillError::NoKillableTarget(target))
}

/// 1 件の結果を表示する
fn print_kill_result(name: &str, pid: u32, success: bool, message: &str) -> io::Result<()> {
    write_kill_result(&mut io::stdout().lock(), name, pid, success, message)
}

/// 1 件の結果を任意の書き込み先へ出力する
fn write_kill_result(
    out: &mut impl Write,
    name: &str,
    pid: u32,
    success: bool,
    message: &str,
) -> io::Result<()> {
    let status = if success { "✓" } else { "✗" };
    // `message` は失敗時に `SafeKillError::to_string()` を保持しており、エラー型によっては
    // OS から取得したプロセス名がそのまま含まれる（例: `NotDescendant(pid, name)`、
    // `Denylisted(name)`）。攻撃者が ANSI escape を含む引数でプロセスを起動した場合に
    // 表示偽装や端末状態改ざんが起きないよう、`name` と `message` の両方をサニタイズする。
    writeln!(
        out,
        "{} {} (PID {}): {}",
        status,
        sanitize_terminal(name),
        pid,
        sanitize_terminal(message)
    )
}

/// 複数件実行時の要約行を組み立てる
fn batch_result_summary(result: &BatchKillResult, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Matched {} process(es), would kill {}:",
            result.total_matched, result.total_killed
        )
    } else {
        format!(
            "Matched {} process(es), killed {}:",
            result.total_matched, result.total_killed
        )
    }
}

/// 複数件の結果を表示する
fn print_batch_result(result: &BatchKillResult, dry_run: bool) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{}", batch_result_summary(result, dry_run))?;
    for r in &result.results {
        write_kill_result(&mut out, &r.name, r.pid, r.success, &r.message)?;
    }
    Ok(())
}

/// ポート指定実行時の要約行を組み立てる
fn port_result_summary(port: u16, result: &BatchKillResult, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Port {}: Found {} process(es), would kill {}:",
            port, result.total_matched, result.total_killed
        )
    } else {
        format!(
            "Port {}: Found {} process(es), killed {}:",
            port, result.total_matched, result.total_killed
        )
    }
}

/// ポート指定の結果を表示する
fn print_port_kill_result(port: u16, result: &BatchKillResult, dry_run: bool) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{}", port_result_summary(port, result, dry_run))?;
    for r in &result.results {
        write_kill_result(&mut out, &r.name, r.pid, r.success, &r.message)?;
    }
    Ok(())
}

/// 終了可能なプロセス一覧を表示する
fn print_killable_list(processes: &[process_info::ProcessInfo]) -> io::Result<()> {
    let mut out = io::stdout().lock();

    if processes.is_empty() {
        return writeln!(out, "No killable processes found.");
    }

    writeln!(out, "Killable processes ({}):", processes.len())?;
    writeln!(out, "{:>8}  {:<20}  COMMAND", "PID", "NAME")?;
    writeln!(out, "{}", "-".repeat(60))?;

    for p in processes {
        let cmd = if p.cmd.is_empty() {
            String::new()
        } else {
            p.cmd.join(" ")
        };
        // 端末制御文字（ANSI escape、改行、OSC など）はサニタイズしてから
        // truncate する。サニタイズせずに truncate すると、escape sequence の
        // 途中で切られて意図しない端末状態が残る可能性がある。
        let cmd_display = truncate(&sanitize_terminal(&cmd), 30);
        let name_display = truncate(&sanitize_terminal(&p.name), 20);
        writeln!(out, "{:>8}  {:<20}  {}", p.pid, name_display, cmd_display)?;
    }

    Ok(())
}

/// 文字数上限で文字列を切り詰める
fn truncate(s: &str, max_len: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_len {
        return s.to_string();
    }

    if max_len <= 3 {
        return s.chars().take(max_len).collect();
    }

    let prefix: String = s.chars().take(max_len - 3).collect();
    format!("{}...", prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_project_compiles() {
        // このテストが動く時点でコンパイルは通っている
    }

    #[test]
    fn test_version_available() {
        // Cargo からバージョンを取得できることを確認する
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
        // バージョン形式は YY.M.COUNTER
        assert!(version.contains('.'), "Version should contain dots");
    }

    #[test]
    fn test_truncate_short_string() {
        let result = truncate("hello", 10);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_truncate_exact_length() {
        let result = truncate("hello", 5);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let result = truncate("hello world", 8);
        assert_eq!(result, "hello...");
    }

    #[test]
    fn test_truncate_empty_string() {
        let result = truncate("", 10);
        assert_eq!(result, "");
    }

    #[test]
    fn test_truncate_boundary_just_over() {
        let result = truncate("abcde", 4);
        assert_eq!(result, "a...");
    }

    #[test]
    fn test_truncate_boundary_exact_no_truncation() {
        let result = truncate("abcd", 4);
        assert_eq!(result, "abcd");
    }

    #[test]
    fn test_truncate_single_char() {
        let result = truncate("x", 1);
        assert_eq!(result, "x");
    }

    #[test]
    fn test_truncate_unicode_safe() {
        let result = truncate("あいうえお", 4);
        assert_eq!(result, "あ...");
    }

    #[test]
    fn test_truncate_after_sanitize_never_emits_raw_escape() {
        // `print_killable_list` は `truncate(&sanitize_terminal(&cmd), 30)` の順で処理する。
        // 逆順（truncate → sanitize）だと escape sequence の途中で切られた断片が
        // そのまま端末へ流れ、端末状態が壊れたまま残る。長い argv を持つプロセスでも
        // ESC が生で残らないこと、切り詰め後も文字数上限を守ることを固定する。
        // 既存テストは truncate と sanitize_terminal を個別にしか検証していなかった。
        let hostile_cmd = format!("node {}--inspect", "\x1b[2J\u{202E}".repeat(10));
        let displayed = truncate(&sanitize_terminal(&hostile_cmd), 30);

        assert!(
            !displayed.contains('\x1b'),
            "切り詰め後も生の ESC が残ってはいけない: {displayed}"
        );
        assert!(
            !displayed.contains('\u{202E}'),
            "切り詰め後も双方向制御文字が残ってはいけない: {displayed}"
        );
        assert!(
            displayed.chars().count() <= 30,
            "表示幅の上限を超えてはいけない: {}",
            displayed.chars().count()
        );
    }

    #[test]
    fn test_truncate_small_limit_without_ellipsis() {
        let result = truncate("abcdef", 2);
        assert_eq!(result, "ab");
    }

    #[test]
    fn test_truncate_zero_limit() {
        let result = truncate("abcdef", 0);
        assert_eq!(result, "");
    }

    #[test]
    fn test_truncate_three_limit_without_ellipsis() {
        let result = truncate("abcdef", 3);
        assert_eq!(result, "abc");
    }

    #[test]
    fn test_truncate_multibyte_boundary() {
        // マルチバイト文字のみで構成された文字列の切り詰め
        let result = truncate("日本語テスト", 5);
        assert_eq!(result, "日本...");
    }

    #[test]
    fn test_truncate_mixed_ascii_unicode() {
        // ASCII とマルチバイト文字の混在
        let result = truncate("abc日本語", 5);
        assert_eq!(result, "ab...");
    }

    #[test]
    fn test_truncate_emoji() {
        // 絵文字を含む文字列
        let result = truncate("🎉🎊🎋🎌🎍", 4);
        assert_eq!(result, "🎉...");
    }

    #[test]
    fn test_version_format_parts() {
        let version = env!("CARGO_PKG_VERSION");
        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(parts.len(), 3, "Version should have 3 parts: YY.M.COUNTER");
        for part in &parts {
            assert!(
                part.parse::<u32>().is_ok(),
                "Each version part should be numeric"
            );
        }
    }

    #[test]
    fn test_single_result_error_preserves_original_error() {
        let result = KillResult::failure(42, "worker", &SafeKillError::PermissionDenied(42));
        assert_eq!(
            single_result_error(&result),
            SafeKillError::PermissionDenied(42)
        );
    }

    #[test]
    fn test_batch_result_error_prefers_operational_error() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::failure(
            10,
            "parent",
            &SafeKillError::SuicidePrevention(10),
        ));
        batch.add(KillResult::failure(
            20,
            "worker",
            &SafeKillError::ProcessNotFound(20),
        ));

        assert_eq!(
            batch_result_error("name 'worker'".to_string(), &batch),
            SafeKillError::ProcessNotFound(20)
        );
    }

    #[test]
    fn test_batch_result_error_falls_back_to_no_killable_target() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::failure(
            10,
            "parent",
            &SafeKillError::SuicidePrevention(10),
        ));

        assert_eq!(
            batch_result_error("port 8080".to_string(), &batch),
            SafeKillError::NoKillableTarget("port 8080".to_string())
        );
    }

    #[test]
    fn test_batch_result_summary_uses_killed_for_normal_run() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::success(
            10,
            "worker",
            safe_kill::signal::Signal::SIGTERM,
        ));

        assert_eq!(
            batch_result_summary(&batch, false),
            "Matched 1 process(es), killed 1:"
        );
    }

    #[test]
    fn test_batch_result_summary_uses_would_kill_for_dry_run() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::dry_run(
            10,
            "worker",
            safe_kill::signal::Signal::SIGTERM,
        ));

        assert_eq!(
            batch_result_summary(&batch, true),
            "Matched 1 process(es), would kill 1:"
        );
    }

    #[test]
    fn test_port_result_summary_uses_would_kill_for_dry_run() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::dry_run(
            20,
            "server",
            safe_kill::signal::Signal::SIGTERM,
        ));

        assert_eq!(
            port_result_summary(3000, &batch, true),
            "Port 3000: Found 1 process(es), would kill 1:"
        );
    }

    #[test]
    fn test_single_result_error_fallback_when_no_error_field() {
        // error フィールドが None の場合、message から SystemError にフォールバックする
        let result = KillResult {
            pid: 42,
            name: "test".to_string(),
            success: false,
            message: "unexpected failure".to_string(),
            error: None,
        };
        assert_eq!(
            single_result_error(&result),
            SafeKillError::SystemError("unexpected failure".to_string())
        );
    }

    #[test]
    fn test_batch_result_error_empty_batch() {
        let batch = BatchKillResult::new();
        assert_eq!(
            batch_result_error("name 'test'".to_string(), &batch),
            SafeKillError::NoKillableTarget("name 'test'".to_string())
        );
    }

    #[test]
    fn test_port_result_summary_uses_killed_for_normal_run() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::success(
            20,
            "server",
            safe_kill::signal::Signal::SIGTERM,
        ));

        assert_eq!(
            port_result_summary(3000, &batch, false),
            "Port 3000: Found 1 process(es), killed 1:"
        );
    }

    // =========================================================================
    // 端末制御文字サニタイズの回帰テスト
    //
    // OS から取得したプロセス名・コマンドライン引数に ANSI escape や改行が
    // 含まれていても、表示行を上書きする偽装や端末状態の改ざんが起きないこと
    // を保証する。
    // =========================================================================

    #[test]
    fn test_sanitize_terminal_passes_printable_ascii() {
        assert_eq!(sanitize_terminal("hello world"), "hello world");
        assert_eq!(sanitize_terminal("safe-kill"), "safe-kill");
        assert_eq!(sanitize_terminal(""), "");
    }

    #[test]
    fn test_sanitize_terminal_escapes_newline_carriage_return_tab() {
        // 改行・復帰・タブはそれぞれリテラルなエスケープ表記に置き換える。
        assert_eq!(sanitize_terminal("a\nb"), "a\\nb");
        assert_eq!(sanitize_terminal("a\rb"), "a\\rb");
        assert_eq!(sanitize_terminal("a\tb"), "a\\tb");
    }

    #[test]
    fn test_sanitize_terminal_escapes_ansi_escape_sequence() {
        // 画面消去（ESC[2J）のような ANSI escape は出力に残してはならない。
        // ESC（U+001B）は `\x1B` 表記に置き換える。
        let raw = "ok\x1b[2Jspoofed";
        let sanitized = sanitize_terminal(raw);
        assert!(
            !sanitized.contains('\x1b'),
            "ESC 文字（U+001B）はサニタイズで除去されるべき: {sanitized}"
        );
        assert!(
            sanitized.contains("\\x1B"),
            "ESC は `\\x1B` 形式のエスケープ表記に置き換わるべき: {sanitized}"
        );
        assert!(sanitized.contains("spoofed"));
    }

    #[test]
    fn test_sanitize_terminal_preserves_unicode_printable_chars() {
        // マルチバイトの印字可能文字（日本語・絵文字）はそのまま残す。
        assert_eq!(sanitize_terminal("日本語"), "日本語");
        assert_eq!(sanitize_terminal("safe🛡️kill"), "safe🛡️kill");
    }

    #[test]
    fn test_sanitize_terminal_escapes_other_control_chars() {
        // 一般の制御文字（NUL、BEL、DEL など）も `\xHH` 表記に置き換える。
        let raw = "a\x00b\x07c\x7fd";
        let sanitized = sanitize_terminal(raw);
        for forbidden in ['\x00', '\x07', '\x7f'] {
            assert!(
                !sanitized.contains(forbidden),
                "制御文字 {:?} はサニタイズで除去されるべき: {sanitized}",
                forbidden
            );
        }
        assert!(sanitized.contains("\\x00"));
        assert!(sanitized.contains("\\x07"));
        assert!(sanitized.contains("\\x7F"));
    }

    // =========================================================================
    // エラー表示経路のサニタイズ回帰テスト
    //
    // `SafeKillError::NotDescendant(pid, name)` や `Denylisted(name)` のように、
    // エラーメッセージに OS から取得したプロセス名が含まれるケースで、攻撃者の
    // 制御文字が端末へ出ないことを保証する。
    // =========================================================================

    #[test]
    fn test_sanitize_terminal_neutralizes_not_descendant_error_display() {
        // 攻撃者が `\x1b[2J`（画面消去）を含む名前で起動したプロセスを kill しようとして
        // 拒否されると、`SafeKillError::NotDescendant(pid, name)` の Display 結果に
        // そのまま制御文字が含まれる。`sanitize_terminal` がそれを安全な表記に置き換える。
        let err = SafeKillError::NotDescendant(42, "evil\x1b[2Jname".to_string());
        let rendered = sanitize_terminal(&err.to_string());
        assert!(
            !rendered.contains('\x1b'),
            "エラー表示の ESC 文字はサニタイズで除去されるべき: {rendered}"
        );
        assert!(
            rendered.contains("\\x1B[2J"),
            "ESC は `\\x1B` 形式へエスケープされて表示されるべき: {rendered}"
        );
    }

    #[test]
    fn test_sanitize_terminal_neutralizes_denylisted_error_display() {
        // `Denylisted(name)` 経路でも同様にプロセス名が含まれる。
        let err = SafeKillError::Denylisted("rogue\nproc".to_string());
        let rendered = sanitize_terminal(&err.to_string());
        assert!(
            !rendered.contains('\n'),
            "エラー表示の改行はサニタイズで除去されるべき: {rendered}"
        );
        assert!(
            rendered.contains("\\n"),
            "改行は `\\n` リテラル表記に置き換わるべき: {rendered}"
        );
    }

    #[test]
    fn test_print_kill_result_sanitizes_message_field() {
        // `KillResult::failure` は `message: error.to_string()` でエラー文を保持するため、
        // 表示経路の `message` 引数にも制御文字が混入し得る。`sanitize_terminal` を通す
        // ことで、攻撃者が拒否される側でも端末状態改ざんを防ぐ。
        let err = SafeKillError::NotDescendant(7, "boom\x1b[31m".to_string());
        let result = KillResult::failure(7, "boom\x1b[31m", &err);
        let sanitized_message = sanitize_terminal(&result.message);
        assert!(
            !sanitized_message.contains('\x1b'),
            "message 経由でも ESC 文字は表示されないべき: {sanitized_message}"
        );
    }

    /// 常に指定した種類の I/O エラーを返す書き込み先
    struct FailingWriter {
        kind: io::ErrorKind,
    }

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.kind))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.kind))
        }
    }

    #[test]
    fn test_finish_output_broken_pipe_keeps_success() {
        // 読み手がパイプを閉じただけで操作は完了している。
        // ここを失敗にすると `safe-kill --list | head -1` が異常終了する。
        let result = finish_output(
            Ok(()),
            Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            OutputStream::Stdout,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_finish_output_reports_other_io_errors() {
        // ディスク満杯などは出力が本当に失われているので隠さない。
        let result = finish_output(
            Ok(()),
            Err(io::Error::from(io::ErrorKind::StorageFull)),
            OutputStream::Stdout,
        );
        assert!(matches!(
            result,
            Err(RunError::Output {
                stream: OutputStream::Stdout,
                ..
            })
        ));
    }

    #[test]
    fn test_finish_output_domain_error_takes_precedence() {
        // 終了コードは「操作の結果」を表す契約なので、表示の失敗で塗り替えない。
        let result = finish_output(
            Err(SafeKillError::PermissionDenied(123)),
            Err(io::Error::from(io::ErrorKind::StorageFull)),
            OutputStream::Stdout,
        );
        assert!(matches!(
            result,
            Err(RunError::Domain(SafeKillError::PermissionDenied(123)))
        ));
    }

    #[test]
    fn test_finish_output_domain_error_survives_broken_pipe() {
        let result = finish_output(
            Err(SafeKillError::NoProcessOnPort(3000)),
            Err(io::Error::from(io::ErrorKind::BrokenPipe)),
            OutputStream::Stderr,
        );
        assert!(matches!(
            result,
            Err(RunError::Domain(SafeKillError::NoProcessOnPort(3000)))
        ));
    }

    #[test]
    fn test_write_kill_result_propagates_io_error() {
        // 表示関数が I/O エラーを握りつぶしていないことを確認する。
        // 握りつぶすと `finish_output` が判断できず、BrokenPipe の扱いが崩れる。
        let mut writer = FailingWriter {
            kind: io::ErrorKind::BrokenPipe,
        };
        let err = write_kill_result(&mut writer, "node", 42, true, "Sent SIGTERM").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn test_output_stream_display() {
        assert_eq!(OutputStream::Stdout.to_string(), "stdout");
        assert_eq!(OutputStream::Stderr.to_string(), "stderr");
    }
}
