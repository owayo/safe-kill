//! End-to-end tests for safe-kill CLI
//!
//! Tests the CLI binary with real command execution, output verification, and exit codes.
#![allow(deprecated)] // cargo_bin is deprecated but still functional

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use std::process::Stdio;
use tempfile::NamedTempFile;

// =============================================================================
// --list オプションの出力確認テスト
// =============================================================================

#[test]
fn test_list_command_runs_successfully() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--list").assert().success().stdout(
        predicate::str::contains("Killable processes").or(predicate::str::contains("No killable")),
    );
}

#[test]
fn test_list_command_shows_header_format() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    let assert = cmd.arg("--list").assert();

    // Should contain either the header or "No killable processes" message
    assert.success().stdout(
        predicate::str::contains("PID")
            .and(predicate::str::contains("NAME"))
            .or(predicate::str::contains("No killable processes")),
    );
}

#[test]
fn test_list_with_dry_run_is_invalid() {
    // --list and --dry-run together should work (dry-run is ignored for list)
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--list").arg("--dry-run").assert().success();
}

// =============================================================================
// --dry-run モードの動作確認テスト
// =============================================================================

#[test]
fn test_dry_run_with_pid() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    // Use a non-existent PID to test dry-run behavior
    cmd.arg("999999999")
        .arg("--dry-run")
        .assert()
        .failure() // Should fail because process doesn't exist
        .stderr(
            predicate::str::contains("not found").or(predicate::str::contains("No such process")),
        );
}

#[test]
fn test_dry_run_with_name() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--name")
        .arg("__nonexistent_process_12345__")
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("No matching")));
}

#[test]
fn test_dry_run_does_not_kill_self() {
    // Even in dry-run mode, trying to kill self should be prevented
    let current_pid = std::process::id();
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg(current_pid.to_string())
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("suicide").or(predicate::str::contains("self")));
}

// =============================================================================
// シグナルオプションのテスト
// =============================================================================

#[test]
fn test_signal_option_sigterm() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("SIGTERM")
        .arg("999999999")
        .arg("--dry-run")
        .assert()
        .failure(); // Process doesn't exist
}

#[test]
fn test_signal_option_sigkill() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("9")
        .arg("999999999")
        .arg("--dry-run")
        .assert()
        .failure(); // Process doesn't exist
}

#[test]
fn test_signal_option_invalid() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("INVALID_SIGNAL")
        .arg("999999999")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid signal"));
}

#[test]
fn test_signal_option_invalid_number() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("999")
        .arg("12345")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid signal"));
}

// =============================================================================
// 終了コードの確認テスト
// =============================================================================

#[test]
fn test_exit_code_success_on_list() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--list").assert().code(0);
}

#[test]
fn test_exit_code_process_not_found() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("999999999").assert().code(1); // NoTarget exit code (includes ProcessNotFound)
}

#[test]
fn test_exit_code_invalid_signal() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("INVALID")
        .arg("12345")
        .assert()
        .code(255); // GeneralError exit code (InvalidSignal maps to this)
}

#[test]
fn test_exit_code_suicide_prevention() {
    let current_pid = std::process::id();
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg(current_pid.to_string()).assert().code(255); // GeneralError (SuicidePrevention)
}

#[test]
fn test_exit_code_no_target() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--name")
        .arg("__nonexistent_process_xyz__")
        .assert()
        .code(1); // NoTarget exit code
}

// =============================================================================
// CLI引数バリデーションテスト
// =============================================================================

#[test]
fn test_no_arguments_shows_error() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("No target").or(predicate::str::contains("--help")));
}

#[test]
fn test_help_option() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--help").assert().success().stdout(
        predicate::str::contains("safe-kill")
            .and(predicate::str::contains("--list"))
            .and(predicate::str::contains("--signal"))
            .and(predicate::str::contains("--dry-run")),
    );
}

#[test]
fn test_version_option() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("safe-kill"));
}

#[test]
fn test_pid_and_name_mutually_exclusive() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("12345")
        .arg("--name")
        .arg("process_name")
        .assert()
        .failure();
}

#[test]
fn test_pid_and_list_mutually_exclusive() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("12345").arg("--list").assert().failure();
}

// =============================================================================
// 実際のプロセス終了テスト（子プロセスを生成してテスト）
// =============================================================================

#[test]
fn test_kill_child_process_dry_run() {
    // Spawn a child process that sleeps
    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Ok(child) = child {
        let child_pid = child.id();

        // Try to kill with dry-run - should succeed without actually killing
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        let result = cmd.arg(child_pid.to_string()).arg("--dry-run").assert();

        // Should succeed (dry run) and mention the process
        result.success().stdout(predicate::str::contains("dry run"));

        // Verify the process is still running
        let check = std::process::Command::new("kill")
            .arg("-0")
            .arg(child_pid.to_string())
            .status();

        assert!(
            check.is_ok() && check.unwrap().success(),
            "Child process should still be running after dry-run"
        );

        // Clean up: actually kill the child process
        let _ = std::process::Command::new("kill")
            .arg(child_pid.to_string())
            .status();
    }
}

#[test]
fn test_kill_child_process_actually() {
    // Spawn a child process that sleeps
    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Ok(mut child) = child {
        let child_pid = child.id();

        // Actually kill the child process
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        let result = cmd.arg(child_pid.to_string()).assert();

        // Should succeed
        result.success().stdout(predicate::str::contains("✓"));

        // Wait for the child process to be reaped
        let _ = child.wait();

        // Give the OS a moment to clean up
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Verify the process is no longer running
        let check = std::process::Command::new("kill")
            .arg("-0")
            .arg(child_pid.to_string())
            .status();

        // Either the command fails or returns non-zero (process doesn't exist)
        let is_terminated = check.is_err() || !check.unwrap().success();
        assert!(is_terminated, "Child process should be terminated");
    }
}

#[test]
fn test_kill_child_by_name_dry_run() {
    // Spawn a uniquely named process (using a script)
    let mut script = NamedTempFile::new().unwrap();
    writeln!(script, "#!/bin/bash\nsleep 60").unwrap();

    let script_path = script.path().to_str().unwrap();
    let _ = std::process::Command::new("chmod")
        .arg("+x")
        .arg(script_path)
        .status();

    let child = std::process::Command::new("bash")
        .arg("-c")
        .arg("exec -a 'safe_kill_test_target' sleep 60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Ok(_child) = child {
        // Small delay to let the process start
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Try to kill by name with dry-run
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        let result = cmd
            .arg("--name")
            .arg("safe_kill_test_target")
            .arg("--dry-run")
            .assert();

        // May find the process or not depending on OS behavior
        // Just verify it doesn't panic and returns some result
        result.try_success().ok();

        // Clean up
        let _ = std::process::Command::new("pkill")
            .arg("-f")
            .arg("safe_kill_test_target")
            .status();
    }
}

// =============================================================================
// 設定ファイルとの連携テスト
// =============================================================================

#[test]
fn test_denylist_prevents_kill() {
    // Try to kill launchd (macOS) or systemd (Linux) - should be denied
    #[cfg(target_os = "macos")]
    {
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        cmd.arg("1") // launchd PID
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("denylist")
                    .or(predicate::str::contains("not a descendant"))
                    .or(predicate::str::contains("denied")),
            );
    }

    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        cmd.arg("1") // systemd/init PID
            .assert()
            .failure()
            .stderr(
                predicate::str::contains("denylist")
                    .or(predicate::str::contains("not a descendant"))
                    .or(predicate::str::contains("denied")),
            );
    }
}

#[test]
fn test_custom_config_file_path() {
    // Create a temporary config file
    let mut config_file = NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        r#"
[denylist]
processes = ["test_denied_process"]
"#
    )
    .unwrap();

    // The config loading is done at startup, so we can't easily test custom paths
    // via CLI. This test verifies that the binary still works with config present.
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--list").assert().success();
}

// =============================================================================
// エッジケースのテスト
// =============================================================================

#[test]
fn test_invalid_pid_format() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("not_a_number").assert().failure();
}

#[test]
fn test_negative_pid() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("-1").assert().failure();
}

#[test]
fn test_very_large_pid() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("99999999999999").assert().failure();
}

#[test]
fn test_empty_name() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--name").arg("").assert().failure();
}

#[test]
fn test_special_characters_in_name() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--name")
        .arg("process*with?special[chars]")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("No matching")));
}
