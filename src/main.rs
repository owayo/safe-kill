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
                Err(SafeKillError::NoTarget)
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
                Err(SafeKillError::NoTarget)
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
        // Truncate command if too long
        let cmd_display = if cmd.len() > 30 {
            format!("{}...", &cmd[..27])
        } else {
            cmd
        };
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
    if s.len() > max_len {
        format!("{}...", &s[..max_len - 3])
    } else {
        s.to_string()
    }
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
}
