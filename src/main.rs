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

/// 表示が操作の中で担う役割
///
/// 書き込みに失敗したときの終了コードは、表示が「済んだ操作の報告」なのか
/// 「表示そのものが成果物」なのかで変わる。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputRole {
    /// 操作は既に完了しており、表示はその報告に過ぎない
    /// （dry-run でない PID / 名前 / ポート指定の kill、`init` の生成とスキップ）。
    ///
    /// シグナルは送信済み（設定ファイルは書き込み済み）で取り消せない。ここで失敗の
    /// 終了コードを返すと、呼び出し側は「kill に失敗した」と誤解して再試行したり
    /// SIGKILL などの別手段へ進んだりする。終了コードは操作の結果を表す契約なので、
    /// 報告を書けなくても成功を返し、報告が失われたことは stderr の警告で伝える。
    Informational,
    /// 表示そのものが成果物（`--list` と、すべての dry-run）
    ///
    /// 呼び出し側が欲しいのは出力そのものなので、書き出せなければ何も得られていない。
    /// 失敗として報告する（`RunError::Output`、終了コード 255）。
    Required,
}

impl OutputRole {
    /// kill 系の実行モードにおける表示の役割
    ///
    /// dry-run はシグナルを送らず「何が kill されるか」を見せるだけなので、表示が成果物。
    /// 実際の kill は送信を終えた後の報告なので、表示は補助的なものになる。
    fn for_kill(dry_run: bool) -> Self {
        if dry_run {
            OutputRole::Required
        } else {
            OutputRole::Informational
        }
    }
}

/// `run()` が成功したときの内訳
#[derive(Debug)]
enum RunOutcome {
    /// 操作も表示も完了した（読み手がパイプを閉じただけの場合を含む）
    Completed,
    /// 操作は完了したが、その報告（`OutputRole::Informational` の表示）を書き出せなかった
    ReportLost {
        stream: OutputStream,
        source: io::Error,
    },
}

/// `run()` の失敗理由
///
/// 「操作そのものの失敗（ドメインエラー）」と「操作結果を表示できなかった失敗」を
/// 分けて扱う。両者を混ぜると、表示の失敗が kill の成否を上書きしてしまう。
#[derive(Debug)]
enum RunError {
    /// kill 判定・設定読み込みなど、操作自体の失敗
    Domain(SafeKillError),
    /// 成果物である表示（`OutputRole::Required`）を書き出せなかった
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
        Ok(RunOutcome::Completed) => ExitCode::SUCCESS,
        Ok(RunOutcome::ReportLost { stream, source }) => {
            // 操作は完了しているので終了コードは成功のまま（`OutputRole::Informational`
            // を参照）。警告すら書けない状況（stderr も失われている）でも結果は変えない。
            let _ = write_report_lost_warning(&mut io::stderr(), stream, &source);
            ExitCode::SUCCESS
        }
        Err(RunError::Domain(e)) => {
            // 診断の書き込み失敗で終了コードを変えてはいけない。呼び出し側が分岐に使う
            // のは「なぜ失敗したか」であって「その説明が届いたか」ではないため、
            // ここでは書き込み結果を捨てて元の終了コードを維持する。
            let _ = write_domain_error(&mut io::stderr(), &e);
            e.exit_code().into()
        }
        Err(RunError::Output { stream, source }) => {
            // BrokenPipe は `finish_output` が成功として処理済みで、Informational な表示の
            // 失敗は `RunOutcome::ReportLost` になる。ここへ来るのは、成果物である表示
            // （`--list` / dry-run）がディスク満杯（ENOSPC）や I/O エラーで本当に
            // 失われた場合だけ。
            let _ = write_output_failure(&mut io::stderr(), stream, &source);
            SafeKillExitCode::GeneralError.into()
        }
    }
}

// `main()` の診断 3 種は、書き込み先を引数に取る関数へ切り出してある。
// `io::stderr()` へ直接書くと、テストは `sanitize_terminal` 単体しか検証できず、
// 表示経路からサニタイズ呼び出しを外す退行（変異）を検出できないため。

/// ドメインエラーの診断を 1 行書く
///
/// エラーメッセージには `NotDescendant(pid, name)` や `Denylisted(name)` のように
/// OS から取得したプロセス名が含まれることがある。攻撃者が `\x1b[2J` 等の
/// ANSI escape を含む引数でプロセスを起動した場合に、エラー経路でも表示偽装や
/// 端末状態改ざんが起きないよう、表示前に必ずサニタイズする。
fn write_domain_error(out: &mut impl Write, error: &SafeKillError) -> io::Result<()> {
    writeln!(out, "safe-kill: {}", sanitize_terminal(&error.to_string()))
}

/// 成果物である表示（`--list` / dry-run）を書き出せなかった診断を 1 行書く
///
/// I/O エラーの本文は OS 由来の文字列なので、他の診断と同じくサニタイズしてから出す。
fn write_output_failure(
    out: &mut impl Write,
    stream: OutputStream,
    source: &io::Error,
) -> io::Result<()> {
    writeln!(
        out,
        "safe-kill: failed to write to {}: {}",
        stream,
        sanitize_terminal(&source.to_string())
    )
}

/// 操作は完了したのに報告を書き出せなかったときの警告を 1 行書く
///
/// 終了コードが 0 のままである理由（操作は完了済み）と、失われた出力先を明示する。
/// I/O エラーの本文は他の診断と同じくサニタイズしてから出す。
fn write_report_lost_warning(
    out: &mut impl Write,
    stream: OutputStream,
    source: &io::Error,
) -> io::Result<()> {
    writeln!(
        out,
        "safe-kill: warning: operation completed, but failed to write to {}: {}",
        stream,
        sanitize_terminal(&source.to_string())
    )
}

/// 操作結果と表示結果を突き合わせて最終的な実行結果を決める
///
/// 優先順位は「操作の結果 > 表示の結果」。
///
/// * ドメインエラーが出ていれば、表示が成功していようと失敗していようとそれを返す
///   （終了コードは操作の意味を表すという契約を守る）
/// * 表示が `BrokenPipe` で失敗した場合は、読み手がパイプを閉じただけであり操作は
///   完了しているので、役割を問わず成功として扱う（警告も出さない）。
///   `safe-kill --list | head -1` のような通常のシェル利用で、Rust の `println!` が
///   panic して終了コード 101 になるのを防ぐ
///   （Rust ランタイムは起動時に SIGPIPE を無視するため、EPIPE が panic に化ける）
/// * それ以外の I/O エラーは出力が本当に失われている。扱いは表示の役割で分かれる
///   * `Informational`: 操作は取り消せない形で完了済みなので成功のまま、
///     `RunOutcome::ReportLost` で「報告が失われた」ことだけを伝える
///   * `Required`: 表示が成果物なので `RunError::Output` として失敗を報告する
fn finish_output(
    outcome: Result<(), SafeKillError>,
    printed: io::Result<()>,
    stream: OutputStream,
    role: OutputRole,
) -> Result<RunOutcome, RunError> {
    if let Err(e) = outcome {
        return Err(RunError::Domain(e));
    }

    match printed {
        Ok(()) => Ok(RunOutcome::Completed),
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(RunOutcome::Completed),
        Err(source) => match role {
            OutputRole::Informational => Ok(RunOutcome::ReportLost { stream, source }),
            OutputRole::Required => Err(RunError::Output { stream, source }),
        },
    }
}

/// メインの実行ロジック
fn run() -> Result<RunOutcome, RunError> {
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
            finish_output(
                outcome,
                printed,
                OutputStream::Stdout,
                OutputRole::for_kill(args.dry_run),
            )
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
            finish_output(
                outcome,
                printed,
                OutputStream::Stdout,
                OutputRole::for_kill(args.dry_run),
            )
        }
        ExecutionMode::ListKillable => {
            let engine = PolicyEngine::try_with_defaults()?;
            let processes = engine.list_killable();
            let printed = print_killable_list(&processes);
            // 一覧は表示そのものが成果物
            finish_output(Ok(()), printed, OutputStream::Stdout, OutputRole::Required)
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
            finish_output(
                outcome,
                printed,
                OutputStream::Stdout,
                OutputRole::for_kill(args.dry_run),
            )
        }
        // init はファイルの書き込み（またはスキップの確定）を終えてから表示するので、
        // どちらの結果でも表示は報告に過ぎない。
        ExecutionMode::InitConfig { force } => match InitCommand::execute(force)? {
            InitOutcome::Created {
                config_path,
                written_path,
                via_symlink,
            } => {
                let printed = print_init_created(&config_path, &written_path, via_symlink);
                finish_output(
                    Ok(()),
                    printed,
                    OutputStream::Stdout,
                    OutputRole::Informational,
                )
            }
            InitOutcome::SkippedExisting {
                config_path,
                target_path,
                via_symlink,
            } => {
                let printed = print_init_skipped(&config_path, &target_path, via_symlink);
                finish_output(
                    Ok(()),
                    printed,
                    OutputStream::Stderr,
                    OutputRole::Informational,
                )
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
    write_killable_list(&mut io::stdout().lock(), processes)
}

/// 終了可能なプロセス一覧を任意の書き込み先へ出力する
///
/// 書き込み先を引数に取るのは、サニタイズと切り詰めの順序を実際の表示経路で
/// テストするため（`write_kill_result` と同じ構成）。
fn write_killable_list(
    out: &mut impl Write,
    processes: &[process_info::ProcessInfo],
) -> io::Result<()> {
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

    const ALL_ROLES: [OutputRole; 2] = [OutputRole::Informational, OutputRole::Required];

    #[test]
    fn test_finish_output_success_is_completed_for_every_role() {
        for role in ALL_ROLES {
            let result = finish_output(Ok(()), Ok(()), OutputStream::Stdout, role);
            assert!(
                matches!(result, Ok(RunOutcome::Completed)),
                "{role:?}: {result:?}"
            );
        }
    }

    #[test]
    fn test_finish_output_broken_pipe_keeps_success() {
        // 読み手がパイプを閉じただけで操作は完了している。役割を問わず成功で、警告も出さない
        // （ReportLost にしない）。ここを失敗にすると `safe-kill --list | head -1` が
        // 異常終了し、`--name x | head -1` のような実 kill では余計な警告が出る。
        for role in ALL_ROLES {
            let result = finish_output(
                Ok(()),
                Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                OutputStream::Stdout,
                role,
            );
            assert!(
                matches!(result, Ok(RunOutcome::Completed)),
                "{role:?}: {result:?}"
            );
        }
    }

    #[test]
    fn test_finish_output_required_output_loss_is_failure() {
        // `--list` や dry-run は表示そのものが成果物。ディスク満杯などで出力が
        // 本当に失われたら、呼び出し側は何も受け取れていないので隠さない（255）。
        let result = finish_output(
            Ok(()),
            Err(io::Error::from(io::ErrorKind::StorageFull)),
            OutputStream::Stdout,
            OutputRole::Required,
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
    fn test_finish_output_informational_output_loss_keeps_success() {
        // 実際の kill は送信済みで取り消せない。結果行を書けなかっただけで失敗を返すと、
        // 呼び出し側は kill に失敗したと誤解して再試行や SIGKILL へ進む。
        // 成功のまま、報告が失われたことだけを ReportLost で伝える。
        let result = finish_output(
            Ok(()),
            Err(io::Error::from(io::ErrorKind::StorageFull)),
            OutputStream::Stdout,
            OutputRole::Informational,
        );
        match result {
            Ok(RunOutcome::ReportLost { stream, source }) => {
                assert_eq!(stream, OutputStream::Stdout);
                assert_eq!(source.kind(), io::ErrorKind::StorageFull);
            }
            other => panic!("ReportLost になるべき: {other:?}"),
        }
    }

    #[test]
    fn test_finish_output_informational_keeps_failing_stream() {
        // `init` のスキップ表示は stderr へ書く。警告文に正しい出力先が載るよう、
        // 失敗した stream を取り違えずに運ぶこと。
        let result = finish_output(
            Ok(()),
            Err(io::Error::from(io::ErrorKind::FileTooLarge)),
            OutputStream::Stderr,
            OutputRole::Informational,
        );
        assert!(matches!(
            result,
            Ok(RunOutcome::ReportLost {
                stream: OutputStream::Stderr,
                ..
            })
        ));
    }

    #[test]
    fn test_finish_output_informational_with_failing_writer() {
        // 実際の表示関数が返すエラーをそのまま渡す経路で確かめる。
        // `ulimit -f` 超過（EFBIG）で結果行を書けなかった実 kill を想定する。
        let mut writer = FailingWriter {
            kind: io::ErrorKind::FileTooLarge,
        };
        let printed = write_kill_result(&mut writer, "node", 42, true, "Sent SIGTERM");
        let result = finish_output(
            Ok(()),
            printed,
            OutputStream::Stdout,
            OutputRole::for_kill(false),
        );
        assert!(matches!(result, Ok(RunOutcome::ReportLost { .. })));
    }

    #[test]
    fn test_finish_output_dry_run_with_failing_writer_is_failure() {
        // dry-run は「何が kill されるか」の表示が成果物なので、書けなければ失敗。
        let mut writer = FailingWriter {
            kind: io::ErrorKind::FileTooLarge,
        };
        let printed = write_kill_result(&mut writer, "node", 42, true, "Would send SIGTERM");
        let result = finish_output(
            Ok(()),
            printed,
            OutputStream::Stdout,
            OutputRole::for_kill(true),
        );
        assert!(matches!(result, Err(RunError::Output { .. })));
    }

    #[test]
    fn test_finish_output_domain_error_takes_precedence() {
        // 終了コードは「操作の結果」を表す契約なので、表示の失敗で塗り替えない。
        // 役割が Informational でも、操作自体が失敗していれば成功にはしない。
        for role in ALL_ROLES {
            let result = finish_output(
                Err(SafeKillError::PermissionDenied(123)),
                Err(io::Error::from(io::ErrorKind::StorageFull)),
                OutputStream::Stdout,
                role,
            );
            assert!(
                matches!(
                    result,
                    Err(RunError::Domain(SafeKillError::PermissionDenied(123)))
                ),
                "{role:?}: {result:?}"
            );
        }
    }

    #[test]
    fn test_finish_output_domain_error_survives_broken_pipe() {
        for role in ALL_ROLES {
            let result = finish_output(
                Err(SafeKillError::NoProcessOnPort(3000)),
                Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                OutputStream::Stderr,
                role,
            );
            assert!(
                matches!(
                    result,
                    Err(RunError::Domain(SafeKillError::NoProcessOnPort(3000)))
                ),
                "{role:?}: {result:?}"
            );
        }
    }

    #[test]
    fn test_output_role_for_kill() {
        // dry-run の表示は成果物、実際の kill の表示は送信後の報告。
        assert_eq!(OutputRole::for_kill(true), OutputRole::Required);
        assert_eq!(OutputRole::for_kill(false), OutputRole::Informational);
    }

    // =========================================================================
    // 実際の表示関数を通したサニタイズの回帰テスト
    //
    // `sanitize_terminal` 単体のテストだけでは、表示経路からサニタイズ呼び出しを
    // 外す退行を検出できない（変異テストで確認済み）。ここでは書き込み先に Vec<u8> を
    // 渡して、表示関数が実際に書いたバイト列を検査する。
    // =========================================================================

    /// 表示関数の出力を `Vec<u8>` に受けて文字列として取り出す
    fn capture(write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> String {
        let mut buf = Vec::new();
        write(&mut buf).expect("Vec<u8> への書き込みは失敗しない");
        String::from_utf8(buf).expect("出力は UTF-8 のはず")
    }

    /// 生の制御文字・Unicode の行区切り・双方向制御が 1 つも残っていないこと
    /// （行末の改行は表示関数自身が付けるものなので除いて検査する）
    fn assert_no_raw_controls(output: &str) {
        let raw: Vec<char> = output
            .split('\n')
            .flat_map(str::chars)
            .filter(|&c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202E}'))
            .collect();
        assert!(
            raw.is_empty(),
            "生の制御文字 {raw:?} が残っている: {output:?}"
        );
    }

    #[test]
    fn test_write_domain_error_sanitizes_process_name() {
        // `NotDescendant(pid, name)` は OS から取得したプロセス名をそのまま含む。
        // 改行で偽の行を作ったり、ESC で画面を消したりできないこと。
        let err = SafeKillError::NotDescendant(42, "evil\x1b[2J\nname".to_string());
        let output = capture(|out| write_domain_error(out, &err));
        assert_eq!(
            output,
            "safe-kill: Process 42 (evil\\x1B[2J\\nname) is not a descendant of the current session\n"
        );
        assert_eq!(output.lines().count(), 1, "{output:?}");
        assert_no_raw_controls(&output);
    }

    #[test]
    fn test_write_domain_error_escapes_cr_and_unicode_line_separator() {
        let err = SafeKillError::Denylisted("rogue\r\u{2028}proc".to_string());
        let output = capture(|out| write_domain_error(out, &err));
        assert_eq!(
            output,
            "safe-kill: Process rogue\\r\\u{2028}proc is in denylist and cannot be killed\n"
        );
        assert_no_raw_controls(&output);
    }

    #[test]
    fn test_write_output_failure_sanitizes_error_text() {
        // I/O エラーの本文は外部由来になり得るので、制御文字はエスケープして出す。
        let output = capture(|out| {
            write_output_failure(
                out,
                OutputStream::Stdout,
                &io::Error::other("disk\x1b[2J\nerror: forged"),
            )
        });
        assert_eq!(
            output,
            "safe-kill: failed to write to stdout: disk\\x1B[2J\\nerror: forged\n"
        );
        assert_no_raw_controls(&output);
    }

    #[test]
    fn test_write_report_lost_warning_format() {
        // 警告は他の診断と同じ `safe-kill: ` 接頭辞の 1 行で、操作が完了したこと
        // （＝終了コードが 0 である理由）と、失われた出力先を明示する。
        let output = capture(|out| {
            write_report_lost_warning(
                out,
                OutputStream::Stdout,
                &io::Error::from(io::ErrorKind::FileTooLarge),
            )
        });
        assert!(
            output.starts_with(
                "safe-kill: warning: operation completed, but failed to write to stdout: "
            ),
            "{output}"
        );
        assert_eq!(output.lines().count(), 1, "{output:?}");
    }

    #[test]
    fn test_write_report_lost_warning_sanitizes_error_text() {
        let output = capture(|out| {
            write_report_lost_warning(
                out,
                OutputStream::Stderr,
                &io::Error::other("disk\x1b[2J\nerror: forged"),
            )
        });
        assert_eq!(
            output,
            "safe-kill: warning: operation completed, but failed to write to stderr: \
             disk\\x1B[2J\\nerror: forged\n"
        );
        assert_no_raw_controls(&output);
    }

    #[test]
    fn test_write_kill_result_sanitizes_name_and_message() {
        // 失敗時の `message` は `SafeKillError::to_string()` で、プロセス名を含む。
        // `name` 列と `message` 列のどちらからサニタイズを外しても検出できるよう、
        // 両方に ESC・CR・LF・U+2028 を混ぜて、出力全体を完全一致で固定する。
        let name = "evil\x1b[2J\r\nname\u{2028}x";
        let result = KillResult::failure(42, name, &SafeKillError::NotDescendant(42, name.into()));
        let output = capture(|out| {
            write_kill_result(
                out,
                &result.name,
                result.pid,
                result.success,
                &result.message,
            )
        });
        assert_eq!(
            output,
            "✗ evil\\x1B[2J\\r\\nname\\u{2028}x (PID 42): \
             Process 42 (evil\\x1B[2J\\r\\nname\\u{2028}x) is not a descendant of the current session\n"
        );
        assert_eq!(output.lines().count(), 1, "{output:?}");
        assert_no_raw_controls(&output);
    }

    #[test]
    fn test_write_kill_result_sanitizes_message_only_hostility() {
        // 名前は無害でも、message 側だけに制御文字が入る経路（OS 由来のエラー本文など）
        let output = capture(|out| {
            write_kill_result(out, "node", 7, false, "boom\x1b]0;title\x07\nerror: forged")
        });
        assert_eq!(
            output,
            "✗ node (PID 7): boom\\x1B]0;title\\x07\\nerror: forged\n"
        );
        assert_no_raw_controls(&output);
    }

    #[test]
    fn test_write_kill_result_success_line_unchanged() {
        let output = capture(|out| write_kill_result(out, "evil\x1b[2J", 7, true, "Sent SIGTERM"));
        assert_eq!(output, "✓ evil\\x1B[2J (PID 7): Sent SIGTERM\n");
    }

    /// 一覧表示用の `ProcessInfo` を組み立てる
    fn listed_process(pid: u32, name: &str, cmd: &[&str]) -> process_info::ProcessInfo {
        process_info::ProcessInfo {
            pid,
            parent_pid: Some(1),
            name: name.to_string(),
            cmd: cmd.iter().map(|s| s.to_string()).collect(),
            start_time: 0,
        }
    }

    #[test]
    fn test_write_killable_list_empty_output_unchanged() {
        let output = capture(|out| write_killable_list(out, &[]));
        assert_eq!(output, "No killable processes found.\n");
    }

    #[test]
    fn test_write_killable_list_header_and_rows_unchanged() {
        // 列幅（PID 右寄せ 8、NAME 左寄せ 20）と区切り線の体裁を固定する
        let processes = [
            listed_process(4242, "node", &["node", "server.js"]),
            listed_process(7, "sleep", &[]),
        ];
        let output = capture(|out| write_killable_list(out, &processes));
        let expected = [
            "Killable processes (2):".to_string(),
            format!("     PID  NAME{}  COMMAND", " ".repeat(16)),
            "-".repeat(60),
            format!("    4242  node{}  node server.js", " ".repeat(16)),
            format!("       7  sleep{}  ", " ".repeat(15)),
        ]
        .map(|line| line + "\n")
        .concat();
        assert_eq!(output, expected);
    }

    #[test]
    fn test_write_killable_list_sanitizes_before_truncating() {
        // サニタイズより先に切り詰めると、エスケープ表記への展開で列幅（30）を超え、
        // 途中で切られた ESC シーケンスが端末に残る。名前と COMMAND の両方を
        // 「サニタイズ → 切り詰め」の順で処理していることを、実際の出力で確かめる。
        let processes = [listed_process(
            4242,
            "evil\x1b[2J\u{2028}name-that-is-long",
            &[
                "node",
                "\x1b]52;c;ZXZpbA==\x07",
                "--inspect\r\nerror: forged",
            ],
        )];
        let output = capture(|out| write_killable_list(out, &processes));
        assert_no_raw_controls(&output);

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 4, "見出し 3 行 + 1 行のはず: {output:?}");
        let row = lines[3];
        // 名前はエスケープ表記へ展開してから 20 文字に、COMMAND は 30 文字に切り詰める
        assert_eq!(
            row,
            "    4242  evil\\x1B[2J\\u{202...  node \\x1B]52;c;ZXZpbA==\\x07..."
        );
        // 出力はすべて ASCII なのでバイト位置で列を切り出せる
        assert!(row.is_ascii(), "{row:?}");
        assert_eq!(&row[..10], "    4242  ");
        assert_eq!(row[10..30].chars().count(), 20, "NAME 列の幅: {row:?}");
        assert_eq!(
            &row[30..32],
            "  ",
            "NAME 列が幅を超えてはみ出している: {row:?}"
        );
        assert!(
            row[32..].chars().count() <= 30,
            "COMMAND 列が 30 文字を超えている: {row:?}"
        );
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
