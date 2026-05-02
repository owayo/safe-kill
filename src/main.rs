//! safe-kill: AI エージェント向け安全プロセス終了ツール
//!
//! ancestry ベースのアクセス制御で、現在セッションの子孫プロセスのみを
//! 安全に終了できるようにする。

use std::process::ExitCode;

use safe_kill::cli::{CliArgs, ExecutionMode};
use safe_kill::error::SafeKillError;
use safe_kill::init::InitCommand;
use safe_kill::killer::{BatchKillResult, KillResult};
use safe_kill::policy::PolicyEngine;
use safe_kill::process_info;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("safe-kill: {}", e);
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
            let path = InitCommand::execute(force)?;
            println!("Created: {}", path.display());
            println!();
            println!("Hint: Edit the config file to customize allowed ports and process lists.");
            println!("      Then use `safe-kill --port <PORT>` to kill processes by port.");
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
    println!("{} {} (PID {}): {}", status, name, pid, message);
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
        // Unicode を壊さないように切り詰める
        let cmd_display = truncate(&cmd, 30);
        println!(
            "{:>8}  {:<20}  {}",
            p.pid,
            truncate(&p.name, 20),
            cmd_display
        );
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
}
