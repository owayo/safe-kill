//! safe-kill: AI エージェント向け安全プロセス終了ツール
//!
//! ancestry ベースのアクセス制御で、現在セッションの子孫プロセスのみを
//! 安全に終了できるようにする。

use std::process::ExitCode;

use safe_kill::cli::{CliArgs, ExecutionMode};
use safe_kill::error::SafeKillError;
use safe_kill::init::{InitCommand, InitOutcome};
use safe_kill::killer::{BatchKillResult, KillResult};
use safe_kill::policy::PolicyEngine;
use safe_kill::process_info;
use safe_kill::terminal::{sanitize_path, sanitize_terminal};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // エラーメッセージには `NotDescendant(pid, name)` や `Denylisted(name)` のように
            // OS から取得したプロセス名が含まれることがある。攻撃者が `\x1b[2J` 等の
            // ANSI escape を含む引数でプロセスを起動した場合に、エラー経路でも表示偽装や
            // 端末状態改ざんが起きないよう、表示前に必ずサニタイズする。
            eprintln!("safe-kill: {}", sanitize_terminal(&e.to_string()));
            e.exit_code().into()
        }
    }
}

/// メインの実行ロジック
fn run() -> Result<(), SafeKillError> {
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
            print_kill_result(&result.name, result.pid, result.success, &result.message);
            if result.success {
                Ok(())
            } else {
                Err(single_result_error(&result))
            }
        }
        ExecutionMode::KillByName(name) => {
            let engine = PolicyEngine::try_with_defaults()?;
            let signal = args.parse_signal()?;
            let batch_result = engine.kill_by_name(&name, signal, args.dry_run)?;
            print_batch_result(&batch_result, args.dry_run);
            if batch_result.any_success() {
                Ok(())
            } else {
                Err(batch_result_error(
                    format!("name '{}'", name),
                    &batch_result,
                ))
            }
        }
        ExecutionMode::ListKillable => {
            let engine = PolicyEngine::try_with_defaults()?;
            let processes = engine.list_killable();
            print_killable_list(&processes);
            Ok(())
        }
        ExecutionMode::KillByPort(port) => {
            let engine = PolicyEngine::try_with_defaults()?;
            let signal = args.parse_signal()?;
            let batch_result = engine.kill_by_port(port, signal, args.dry_run)?;
            print_port_kill_result(port, &batch_result, args.dry_run);
            if batch_result.any_success() {
                Ok(())
            } else if batch_result.results.is_empty() {
                Err(SafeKillError::NoProcessOnPort(port))
            } else {
                Err(batch_result_error(format!("port {}", port), &batch_result))
            }
        }
        ExecutionMode::InitConfig { force } => {
            match InitCommand::execute(force)? {
                InitOutcome::Created {
                    config_path,
                    written_path,
                } => {
                    // config.toml が symlink のときは実際に書き込んだ実体パスも示す。
                    // 「Created: .../config.toml」とだけ表示すると、dotfiles 等の
                    // リンク先ファイルを上書きした事実が利用者に伝わらない。
                    if written_path == config_path {
                        println!("Created: {}", sanitize_path(&written_path));
                    } else {
                        println!(
                            "Created: {} (written via symlink {})",
                            sanitize_path(&written_path),
                            sanitize_path(&config_path)
                        );
                    }
                    println!();
                    println!(
                        "Hint: Edit the config file to customize allowed ports and process lists."
                    );
                    println!("      Then use `safe-kill --port <PORT>` to kill processes by port.");
                }
                InitOutcome::SkippedExisting {
                    config_path,
                    target_path,
                } => {
                    // ユーザーが上書きを拒否した場合は正常な no-op として扱う（終了コード 0）。
                    if target_path == config_path {
                        eprintln!(
                            "Skipped. Existing config left unchanged: {}",
                            sanitize_path(&config_path)
                        );
                    } else {
                        eprintln!(
                            "Skipped. Existing config left unchanged: {} (symlink to {})",
                            sanitize_path(&config_path),
                            sanitize_path(&target_path)
                        );
                    }
                }
            }
            Ok(())
        }
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
fn print_kill_result(name: &str, pid: u32, success: bool, message: &str) {
    let status = if success { "✓" } else { "✗" };
    // `message` は失敗時に `SafeKillError::to_string()` を保持しており、エラー型によっては
    // OS から取得したプロセス名がそのまま含まれる（例: `NotDescendant(pid, name)`、
    // `Denylisted(name)`）。攻撃者が ANSI escape を含む引数でプロセスを起動した場合に
    // 表示偽装や端末状態改ざんが起きないよう、`name` と `message` の両方をサニタイズする。
    println!(
        "{} {} (PID {}): {}",
        status,
        sanitize_terminal(name),
        pid,
        sanitize_terminal(message)
    );
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
fn print_batch_result(result: &BatchKillResult, dry_run: bool) {
    println!("{}", batch_result_summary(result, dry_run));
    for r in &result.results {
        print_kill_result(&r.name, r.pid, r.success, &r.message);
    }
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
fn print_port_kill_result(port: u16, result: &BatchKillResult, dry_run: bool) {
    println!("{}", port_result_summary(port, result, dry_run));
    for r in &result.results {
        print_kill_result(&r.name, r.pid, r.success, &r.message);
    }
}

/// 終了可能なプロセス一覧を表示する
fn print_killable_list(processes: &[process_info::ProcessInfo]) {
    if processes.is_empty() {
        println!("No killable processes found.");
        return;
    }

    println!("Killable processes ({}):", processes.len());
    println!("{:>8}  {:<20}  COMMAND", "PID", "NAME");
    println!("{}", "-".repeat(60));

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
        println!("{:>8}  {:<20}  {}", p.pid, name_display, cmd_display);
    }
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
}
