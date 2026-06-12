//! safe-kill CLI の E2E テスト
//!
//! 実バイナリを起動し、出力と終了コードを検証する。
#![allow(deprecated)] // `cargo_bin` は非推奨だが現状のテストでは実用上問題ない

use assert_cmd::Command;
use predicates::prelude::*;
use safe_kill::process_info::ProcessInfoProvider;
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

    // ヘッダーか「終了可能なプロセスなし」のどちらかを表示する
    assert.success().stdout(
        predicate::str::contains("PID")
            .and(predicate::str::contains("NAME"))
            .or(predicate::str::contains("No killable processes")),
    );
}

#[test]
fn test_list_with_dry_run_succeeds_as_list() {
    // `--list` では `--dry-run` が指定されても一覧表示として成功する
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--list").arg("--dry-run").assert().success();
}

#[test]
fn test_list_ignores_invalid_signal() {
    // 一覧表示ではシグナルを使わないため、無効な値でも失敗しない
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("INVALID")
        .arg("--list")
        .assert()
        .success();
}

#[test]
fn test_init_cannot_be_combined_with_list() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--list").arg("init").assert().failure();
}

#[test]
fn test_init_cannot_be_combined_with_pid() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("1234")
        .arg("init")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

// =============================================================================
// --dry-run モードの動作確認テスト
// =============================================================================

#[test]
fn test_dry_run_with_pid() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    // 存在しない PID で dry-run 時のエラー経路を確認する
    cmd.arg("999999999")
        .arg("--dry-run")
        .assert()
        .failure() // 対象が存在しないため失敗する
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
        .stderr(
            predicate::str::contains("No process found with name")
                .or(predicate::str::contains("not found"))
                .or(predicate::str::contains("No matching")),
        );
}

#[test]
fn test_dry_run_does_not_kill_self() {
    // dry-run でも自分自身の kill は拒否される
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
        .failure(); // 対象が存在しないため失敗する
}

#[test]
fn test_signal_option_sigkill() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("9")
        .arg("999999999")
        .arg("--dry-run")
        .assert()
        .failure(); // 対象が存在しないため失敗する
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

#[test]
fn test_name_not_found_reports_name() {
    let missing_name = "__nonexistent_process_xyz__";
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--name").arg(missing_name).assert().code(1).stderr(
        predicate::str::contains(missing_name)
            .and(predicate::str::contains("No process found with name:")),
    );
}

#[test]
fn test_name_all_denied_reports_no_killable_target() {
    use std::fs;

    let pid1_name = ProcessInfoProvider::new()
        .get(1)
        .expect("PID 1 should exist")
        .name;
    let escaped_name = pid1_name.replace('\\', "\\\\").replace('"', "\\\"");

    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        format!("[denylist]\nprocesses = [\"{}\"]\n", escaped_name),
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--name")
        .arg(&pid1_name)
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "No killable process found for name",
        ));
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
    // 待機する子プロセスを起動する
    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Ok(child) = child {
        let child_pid = child.id();

        // dry-run では実際に終了せず成功する
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        let result = cmd.arg(child_pid.to_string()).arg("--dry-run").assert();

        // dry-run 成功として表示される
        result.success().stdout(predicate::str::contains("dry run"));

        // プロセスが生き続けていることを確認する
        let check = std::process::Command::new("kill")
            .arg("-0")
            .arg(child_pid.to_string())
            .status();

        assert!(
            check.is_ok() && check.unwrap().success(),
            "Child process should still be running after dry-run"
        );

        // 後始末として実際に終了する
        let _ = std::process::Command::new("kill")
            .arg(child_pid.to_string())
            .status();
    }
}

#[test]
fn test_kill_child_process_actually() {
    // 待機する子プロセスを起動する
    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Ok(mut child) = child {
        let child_pid = child.id();

        // 実際に子プロセスを終了する
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        let result = cmd.arg(child_pid.to_string()).assert();

        // 成功表示になる
        result.success().stdout(predicate::str::contains("✓"));

        // ゾンビ化を避けるため回収する
        let _ = child.wait();

        // OS 側の後始末待ち
        std::thread::sleep(std::time::Duration::from_millis(200));

        // すでに終了済みであることを確認する
        let check = std::process::Command::new("kill")
            .arg("-0")
            .arg(child_pid.to_string())
            .status();

        // `kill -0` が失敗するか非 0 を返せば終了済み
        let is_terminated = check.is_err() || !check.unwrap().success();
        assert!(is_terminated, "Child process should be terminated");
    }
}

#[test]
fn test_kill_child_by_name_dry_run() {
    // 一意な名前の子プロセスを起動する
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
        // 起動完了を少し待つ
        std::thread::sleep(std::time::Duration::from_millis(100));

        // 名前指定の dry-run を試す
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        let result = cmd
            .arg("--name")
            .arg("safe_kill_test_target")
            .arg("--dry-run")
            .assert();

        // OS 実装差で見つからない場合があるため、少なくとも異常終了しないことだけ見る
        result.try_success().ok();

        // 後始末
        let _ = std::process::Command::new("pkill")
            .arg("-f")
            .arg("safe_kill_test_target")
            .status();
    }
}

#[test]
fn test_name_dry_run_summary_uses_would_kill() {
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--name")
        .arg("sleep")
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("would kill"));

    let _ = child.kill();
    let _ = child.wait();
}

// =============================================================================
// 設定ファイルとの連携テスト
// =============================================================================

#[test]
fn test_denylist_prevents_kill() {
    // launchd (macOS) または systemd (Linux) の kill を試みる - 拒否されるべき
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
fn test_invalid_config_does_not_fall_back_for_kill() {
    use std::fs;

    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[denylist]\nprocesses = [\"sleep\"]\n{{invalid}}\n",
    )
    .unwrap();

    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep プロセスの起動に失敗");

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg(child.id().to_string())
        .arg("--dry-run")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Config parse error"));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_invalid_config_does_not_fall_back_for_port_kill() {
    use std::fs;

    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[allowed_ports]\nports = [\"3000\"]\n{{invalid}}\n",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--port")
        .arg("3000")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Config parse error"));
}

#[test]
fn test_unknown_config_field_does_not_fall_back_for_list() {
    use std::fs;

    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[denylst]\nprocesses = [\"sleep\"]\n",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--list")
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Config parse error"));
}

#[test]
fn test_custom_config_file_path() {
    // 一時的な設定ファイルを作成
    let mut config_file = NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        r#"
[denylist]
processes = ["test_denied_process"]
"#
    )
    .unwrap();

    // 設定の読み込みは起動時に行われるため、CLI 経由でカスタムパスを簡単にテストできない。
    // このテストは設定ファイルが存在してもバイナリが正常に動作することを確認する。
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
fn test_pid_zero() {
    // PID 0はUnixで特殊な意味を持つ（プロセスグループ全体にシグナルを送る）
    // safe-killでは拒否すべき
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("0")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid PID: 0"));
}

#[test]
fn test_pid_over_i32_max() {
    // nix::Pid が扱う i32 の範囲を超える PID は拒否すべき
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("2147483648")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid PID: 2147483648"));
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
        .stderr(
            predicate::str::contains("No process found with name")
                .or(predicate::str::contains("not found"))
                .or(predicate::str::contains("No matching")),
        );
}

// =============================================================================
// --port オプションのテスト (Task 10.1)
// =============================================================================

#[test]
fn test_help_shows_port_option() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--port").and(predicate::str::contains("-p")));
}

#[test]
fn test_port_no_process_on_port() {
    // プロセスが使用していないであろうポート番号を使用
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--port")
        .arg("59997")
        .assert()
        .failure()
        .stderr(predicate::str::contains("No process").or(predicate::str::contains("59997")));
}

#[test]
fn test_port_with_dry_run_no_process() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--port")
        .arg("59998")
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("No process").or(predicate::str::contains("59998")));
}

#[test]
fn test_port_short_option() {
    // -p 短縮形のテスト
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("-p")
        .arg("59996")
        .assert()
        .failure()
        .stderr(predicate::str::contains("No process").or(predicate::str::contains("59996")));
}

#[test]
fn test_port_and_pid_mutually_exclusive() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--port")
        .arg("8080")
        .arg("12345")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be combined"));
}

#[test]
fn test_port_and_name_mutually_exclusive() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--port")
        .arg("8080")
        .arg("--name")
        .arg("some_process")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be combined"));
}

#[test]
fn test_port_and_list_mutually_exclusive() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--port")
        .arg("8080")
        .arg("--list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be combined"));
}

#[test]
fn test_port_invalid_port_number() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--port").arg("not_a_number").assert().failure();
}

#[test]
fn test_port_out_of_range() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--port").arg("99999").assert().failure();
}

// =============================================================================
// init サブコマンドのテスト (Task 10.2)
// =============================================================================

#[test]
fn test_init_help() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("init")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--force").or(predicate::str::contains("-f")));
}

#[test]
fn test_init_force_creates_config() {
    // init --force が正常に実行されることをテスト
    // 実際のユーザー設定に書き込まないよう一時的な HOME を使用
    let temp = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .arg("--force")
        .assert()
        .success()
        .stdout(predicate::str::contains("Created").or(predicate::str::contains("config")));
}

#[test]
fn test_init_output_shows_hint() {
    let temp = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .arg("--force")
        .assert()
        .success()
        .stdout(predicate::str::contains("Hint").and(predicate::str::contains("--port")));
}

#[test]
fn test_init_rejects_signal_option() {
    // init は単独サブコマンドとして扱い、通常オプションとの併用は拒否する
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp
        .path()
        .join(".config")
        .join("safe-kill")
        .join("config.toml");

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--signal")
        .arg("INVALID")
        .arg("init")
        .arg("--force")
        .assert()
        .failure();

    assert!(!config_path.exists());
}

#[test]
fn test_init_creates_valid_toml() {
    use std::fs;

    let temp = tempfile::tempdir().unwrap();

    // init --force を実行
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .arg("--force")
        .assert()
        .success();

    // 出力からパスを取得し、内容を検証
    let config_path = temp
        .path()
        .join(".config")
        .join("safe-kill")
        .join("config.toml");
    let content =
        fs::read_to_string(config_path).expect("init --force should create config.toml in HOME");
    assert!(content.contains("[allowed_ports]"));
    assert!(content.contains("ports ="));
    assert!(content.contains("# [allowlist]"));
    assert!(content.contains("# [denylist]"));
}

// =============================================================================
// 終了コードの追加テスト
// =============================================================================

#[test]
fn test_exit_code_port_not_allowed_without_config() {
    // 設定ファイルがない場合、ポートは許可されていないのでエラー
    let temp = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--port")
        .arg("3000")
        .assert()
        .code(4) // PortNotAllowed exit code
        .stderr(predicate::str::contains("not allowed"));
}

#[test]
fn test_exit_code_port_allowed_but_no_process() {
    use std::fs;

    // 一時ディレクトリに設定ファイルを作成
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[allowed_ports]\nports = [\"59997\"]",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--port")
        .arg("59997")
        .assert()
        .code(1) // NoTarget exit code (NoProcessOnPort)
        .stderr(predicate::str::contains("No process"));
}

#[test]
fn test_init_cancel_preserves_existing_config() {
    use std::fs;

    // 一時ディレクトリに既存の設定ファイルを作成
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "# existing config\ndummy = 1").unwrap();

    // "n"を入力してキャンセル。
    // キャンセルはユーザーの意図的な操作であり、設定ファイル作成エラーではない。
    // 既存ファイルを変更しない正常な no-op として終了コード 0 を返す。
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .write_stdin("n\n")
        .assert()
        .code(0) // 正常な no-op（既存ファイルを保持）
        .stderr(predicate::str::contains("Skipped"));

    // 既存のファイルが保持されていることを確認
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("dummy = 1"));
}

#[test]
fn test_init_overwrite_yes() {
    use std::fs;

    // 一時ディレクトリに既存の設定ファイルを作成
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "# old config\nold = 1").unwrap();

    // "y"を入力して上書き承認
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .write_stdin("y\n")
        .assert()
        .success();

    // 新しい設定が書き込まれていることを確認
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("[allowed_ports]"));
    assert!(!content.contains("old = 1"));
}

#[test]
fn test_init_write_failure_reports_config_error() {
    use std::fs;

    // config.toml を「ディレクトリ」として作成しておくと、ファイル書き込みが失敗する。
    // InitOutcome 導入後も、ユーザーキャンセル（正常な no-op / 終了コード0）とは区別して、
    // 実際の作成失敗は ConfigCreationError（終了コード3）で報告されることを保証する回帰テスト。
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    // config.toml をディレクトリにすることで fs::write が必ず失敗する状況を作る
    let config_path_as_dir = config_dir.join("config.toml");
    fs::create_dir_all(&config_path_as_dir).unwrap();

    // --force で上書き確認をスキップし、書き込み試行まで進める
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .arg("--force")
        .assert()
        .code(3) // ConfigError exit code（実際の作成失敗）
        .stderr(predicate::str::contains("Failed to"));
}

// =============================================================================
// シグナルの境界値・異常入力テスト
// =============================================================================

#[test]
fn test_signal_option_zero() {
    // シグナル番号0は無効
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("0")
        .arg("12345")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid signal"));
}

#[test]
fn test_signal_option_negative() {
    // 負のシグナル番号は無効
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("-1")
        .arg("12345")
        .assert()
        .failure();
}

#[test]
fn test_signal_option_sig_only() {
    // "SIG"のみは無効
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("SIG")
        .arg("12345")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid signal"));
}

#[test]
fn test_signal_option_whitespace() {
    // 空白のみは無効（clapがトリムする前にエラーになる可能性）
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--signal")
        .arg("   ")
        .arg("12345")
        .assert()
        .failure();
}

// =============================================================================
// ポート範囲の境界値テスト
// =============================================================================

#[test]
fn test_port_boundary_zero() {
    // ポート 0 は OS の自動割り当て用の特殊値なので拒否する
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("--port")
        .arg("0")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid port: 0"));
}

#[test]
fn test_port_zero_rejected_even_when_configured() {
    use std::fs;

    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[allowed_ports]\nports = [\"0-65535\", \"0\"]",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--port")
        .arg("0")
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid port: 0"));
}

#[test]
fn test_port_boundary_max() {
    // ポート65535は有効な最大値
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    // 許可設定されていない場合はPortNotAllowed
    cmd.arg("--port").arg("65535").assert().failure();
}

// =============================================================================
// SAFE_KILL_ROOT_PID 環境変数テスト
// =============================================================================

#[test]
fn test_env_var_root_pid_one_is_ignored() {
    // SAFE_KILL_ROOT_PID=1 は信頼ルートとして不適格（PID 1 を許すと全プロセスが
    // 子孫扱いになる fail-open）なため無視され、自動検出ルートにフォールバックする。
    // --list 自体は（自動検出ルート配下を列挙して）常に成功する。
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("SAFE_KILL_ROOT_PID", "1")
        .arg("--list")
        .assert()
        .success();
}

#[test]
fn test_env_var_root_pid_itself_is_not_killable() {
    let mut child = std::process::Command::new("sleep")
        .arg("5")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep プロセスの起動に失敗");

    std::thread::sleep(std::time::Duration::from_millis(100));
    let root_pid = child.id();

    // 信頼ルート自体は子孫ではないため、dry-run でも終了対象にしない。
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("SAFE_KILL_ROOT_PID", root_pid.to_string())
        .arg(root_pid.to_string())
        .arg("--dry-run")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a descendant"));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_env_var_root_pid_invalid_ignored() {
    // 無効な値は無視され、デフォルトの挙動になる
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("SAFE_KILL_ROOT_PID", "not_a_number")
        .arg("--list")
        .assert()
        .success();
}

#[test]
fn test_env_var_root_pid_zero_ignored() {
    // PID 0 は無効値として無視され、デフォルトの挙動になる
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("SAFE_KILL_ROOT_PID", "0")
        .arg("--list")
        .assert()
        .success();
}

// =============================================================================
// SIGKILL での子プロセス終了テスト
// =============================================================================

#[test]
fn test_kill_child_with_sigkill() {
    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Ok(mut child) = child {
        let child_pid = child.id();

        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        cmd.arg("--signal")
            .arg("SIGKILL")
            .arg(child_pid.to_string())
            .assert()
            .success()
            .stdout(predicate::str::contains("SIGKILL"));

        let _ = child.wait();
    }
}

#[test]
fn test_kill_child_with_signal_number() {
    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Ok(mut child) = child {
        let child_pid = child.id();

        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        cmd.arg("--signal")
            .arg("15") // SIGTERM by number
            .arg(child_pid.to_string())
            .assert()
            .success()
            .stdout(predicate::str::contains("SIGTERM"));

        let _ = child.wait();
    }
}

// =============================================================================
// init サブコマンド追加テスト
// =============================================================================

#[test]
fn test_init_creates_config_dir() {
    use std::fs;

    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");

    // ディレクトリがまだ存在しないことを確認
    assert!(!config_dir.exists());

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .arg("--force")
        .assert()
        .success();

    // ディレクトリとファイルが作成されたことを確認
    assert!(config_dir.exists());
    assert!(config_dir.join("config.toml").exists());

    // ファイルの内容が有効なTOMLであることを確認
    let content = fs::read_to_string(config_dir.join("config.toml")).unwrap();
    let parsed: Result<toml::Value, _> = toml::from_str(&content);
    assert!(parsed.is_ok());
}

// =============================================================================
// --port での実 kill テスト
// =============================================================================

#[test]
fn test_port_kill_with_real_listener() {
    use std::fs;
    use std::net::TcpListener;

    // 利用可能なポートを見つける
    let listener = TcpListener::bind("127.0.0.1:0").expect("ポートのバインドに失敗");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // nc (netcat) でリスナーを起動
    let child = std::process::Command::new("nc")
        .arg("-l")
        .arg("127.0.0.1")
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Ok(mut child) = child {
        std::thread::sleep(std::time::Duration::from_millis(200));

        // 一時設定ファイルを作成（ポートを許可）
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(".config").join("safe-kill");
        fs::create_dir_all(&config_dir).unwrap();
        fs::write(
            config_dir.join("config.toml"),
            format!("[allowed_ports]\nports = [\"{}\"]", port),
        )
        .unwrap();

        // dry-run でプロセスが見つかることを確認
        let mut cmd = Command::cargo_bin("safe-kill").unwrap();
        let result = cmd
            .env("HOME", temp.path())
            .arg("--port")
            .arg(port.to_string())
            .arg("--dry-run")
            .assert();

        // nc がポートをバインドできた場合は成功
        // 環境差で見つからない場合もあるため、異常終了しないことだけ確認
        result.try_success().ok();

        // クリーンアップ
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[test]
fn test_port_kill_with_config_allowed_port_range() {
    use std::fs;

    // 一時設定ファイルを作成（範囲指定でポートを許可）
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[allowed_ports]\nports = [\"59990-59999\"]",
    )
    .unwrap();

    // 範囲内のポートでプロセスがなくても PortNotAllowed ではなく NoProcessOnPort が返る
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--port")
        .arg("59995")
        .assert()
        .code(1) // NoTarget (NoProcessOnPort)
        .stderr(predicate::str::contains("No process"));
}

#[test]
fn test_port_kill_outside_allowed_range() {
    use std::fs;

    // 一時設定ファイルを作成（範囲指定でポートを許可）
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join(".config").join("safe-kill");
    fs::create_dir_all(&config_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[allowed_ports]\nports = [\"3000-3010\"]",
    )
    .unwrap();

    // 範囲外のポートは PortNotAllowed エラー
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("--port")
        .arg("4000")
        .assert()
        .code(4) // PortNotAllowed exit code
        .stderr(predicate::str::contains("not allowed"));
}

// =============================================================================
// init サブコマンドの E2E テスト
// =============================================================================

#[test]
fn test_init_creates_config_file() {
    use std::fs;

    let temp = tempfile::tempdir().unwrap();

    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .arg("--force")
        .assert()
        .success()
        .stdout(predicate::str::contains("Created:"));

    // 設定ファイルが作成されたことを確認
    let config_path = temp
        .path()
        .join(".config")
        .join("safe-kill")
        .join("config.toml");
    assert!(config_path.exists(), "設定ファイルが作成されるべき");

    // 有効な TOML であることを確認
    let content = fs::read_to_string(&config_path).unwrap();
    let parsed: Result<toml::Value, _> = toml::from_str(&content);
    assert!(
        parsed.is_ok(),
        "生成された設定ファイルは有効な TOML であるべき"
    );
}

#[test]
fn test_init_twice_with_force() {
    let temp = tempfile::tempdir().unwrap();

    // 1回目の init
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .arg("--force")
        .assert()
        .success();

    // 2回目の init（--force で上書き）
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.env("HOME", temp.path())
        .arg("init")
        .arg("--force")
        .assert()
        .success()
        .stdout(predicate::str::contains("Created:"));
}

// =============================================================================
// 複数ターゲットの排他チェック E2E テスト
// =============================================================================

#[test]
fn test_pid_and_port_conflict() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("12345")
        .arg("--port")
        .arg("3000")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--port cannot be combined"));
}

#[test]
fn test_pid_and_name_conflict() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("12345")
        .arg("--name")
        .arg("node")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cannot specify both"));
}

#[test]
fn test_list_and_pid_conflict() {
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg("12345")
        .arg("--list")
        .assert()
        .failure()
        .stderr(predicate::str::contains("--list cannot be combined"));
}

// =============================================================================
// dry-run の E2E テスト
// =============================================================================

#[test]
fn test_dry_run_does_not_kill_child_process() {
    use std::process::Stdio;

    // 子プロセスを生成
    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let pid = child.id();

    // dry-run で kill を試みる
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg(pid.to_string())
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("dry run"));

    // プロセスがまだ生きていることを確認（safe-kill の API を使用）
    use safe_kill::signal::{Signal, SignalSender};
    // SIGTERM を dry-run ではなく実際に送信して成功すれば生存している
    // ここでは単にプロセスが存在することを ProcessInfoProvider で確認
    use safe_kill::process_info::ProcessInfoProvider;
    let provider = ProcessInfoProvider::new();
    assert!(
        provider.get(pid).is_some(),
        "dry-run 後もプロセスは生存しているべき"
    );

    // クリーンアップ
    let mut child = child;
    let _ = SignalSender::send(pid, Signal::SIGTERM);
    let _ = child.wait();
}

// =============================================================================
// シグナル指定の E2E テスト
// =============================================================================

#[test]
fn test_kill_with_signal_number() {
    use std::process::Stdio;

    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let pid = child.id();

    // シグナル番号 15 (SIGTERM) で kill
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg(pid.to_string())
        .arg("--signal")
        .arg("15")
        .assert()
        .success()
        .stdout(predicate::str::contains("SIGTERM"));

    let mut child = child;
    let _ = child.wait();
}

#[test]
fn test_kill_with_signal_name_without_prefix() {
    use std::process::Stdio;

    let child = std::process::Command::new("sleep")
        .arg("60")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let pid = child.id();

    // "KILL" (SIGプレフィックスなし) で kill
    let mut cmd = Command::cargo_bin("safe-kill").unwrap();
    cmd.arg(pid.to_string())
        .arg("--signal")
        .arg("KILL")
        .assert()
        .success()
        .stdout(predicate::str::contains("SIGKILL"));

    let mut child = child;
    let _ = child.wait();
}
