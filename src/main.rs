//! safe-kill: Safe process termination tool for AI agents
//!
//! This tool provides ancestry-based access control for process termination,
//! allowing AI agents to safely kill only their descendant processes.

use std::process::ExitCode;

use safe_kill::cli::{CliArgs, ExecutionMode};
use safe_kill::error::SafeKillError;
use safe_kill::init::InitCommand;
use safe_kill::killer::BatchKillResult;
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

/// Main execution logic
fn run() -> Result<(), SafeKillError> {
    // Parse CLI arguments
    let args = CliArgs::parse_args();

    // Validate and determine execution mode
    let mode = args.validate()?;

    // Parse signal
    let signal = args.parse_signal()?;

    // Create policy engine
    let engine = PolicyEngine::with_defaults();

    // Execute based on mode
    match mode {
        ExecutionMode::KillByPid(pid) => {
            let result = engine.kill_by_pid(pid, signal, args.dry_run)?;
            print_kill_result(&result.name, result.pid, result.success, &result.message);
            if result.success {
                Ok(())
            } else {
                Err(SafeKillError::SystemError(result.message))
            }
        }
        ExecutionMode::KillByName(name) => {
            let batch_result = engine.kill_by_name(&name, signal, args.dry_run)?;
            print_batch_result(&batch_result);
            if batch_result.any_success() {
                Ok(())
            } else {
                Err(SafeKillError::NoKillableTarget(format!("name '{}'", name)))
            }
        }
        ExecutionMode::ListKillable => {
            let processes = engine.list_killable();
            print_killable_list(&processes);
            Ok(())
        }
        ExecutionMode::KillByPort(port) => {
            let batch_result = engine.kill_by_port(port, signal, args.dry_run)?;
            print_port_kill_result(port, &batch_result);
            if batch_result.any_success() {
                Ok(())
            } else if batch_result.results.is_empty() {
                Err(SafeKillError::NoProcessOnPort(port))
            } else {
                Err(SafeKillError::NoKillableTarget(format!("port {}", port)))
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

/// Print a single kill result
fn print_kill_result(name: &str, pid: u32, success: bool, message: &str) {
    let status = if success { "✓" } else { "✗" };
    println!("{} {} (PID {}): {}", status, name, pid, message);
}

/// Print batch kill results
fn print_batch_result(result: &BatchKillResult) {
    println!(
        "Matched {} process(es), killed {}:",
        result.total_matched, result.total_killed
    );
    for r in &result.results {
        print_kill_result(&r.name, r.pid, r.success, &r.message);
    }
}

/// Print port kill results
fn print_port_kill_result(port: u16, result: &BatchKillResult) {
    println!(
        "Port {}: Found {} process(es), killed {}:",
        port, result.total_matched, result.total_killed
    );
    for r in &result.results {
        print_kill_result(&r.name, r.pid, r.success, &r.message);
    }
}

/// Print list of killable processes
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
        // Truncate command safely for Unicode
        let cmd_display = truncate(&cmd, 30);
        println!(
            "{:>8}  {:<20}  {}",
            p.pid,
            truncate(&p.name, 20),
            cmd_display
        );
    }
}

/// Truncate a string to max length
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
        // Basic smoke test to verify the project compiles correctly
        // The fact that this test runs means the project compiles
    }

    #[test]
    fn test_version_available() {
        // Verify that cargo version is accessible
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
        // Version format: YY.M.COUNTER (e.g., 26.1.100)
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
        // len 5 > max_len 4, so truncated: s[..1] + "..." = "a..."
        let result = truncate("abcde", 4);
        assert_eq!(result, "a...");
    }

    #[test]
    fn test_truncate_boundary_exact_no_truncation() {
        // len 4 == max_len 4, no truncation
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
}
