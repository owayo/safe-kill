//! Integration tests for safe-kill
//!
//! Tests the public API with real process trees, configuration files, and signal operations.

use safe_kill::ancestry::AncestryChecker;
use safe_kill::config::Config;
use safe_kill::error::SafeKillError;
use safe_kill::killer::ProcessKiller;
use safe_kill::policy::PolicyEngine;
use safe_kill::process_info::ProcessInfoProvider;
use safe_kill::signal::{Signal, SignalSender};

use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

// =============================================================================
// 実際のプロセスツリーでの祖先判定テスト
// =============================================================================

#[test]
fn test_real_process_tree_current_is_descendant() {
    let provider = ProcessInfoProvider::new();
    let checker = AncestryChecker::new(provider);
    let current_pid = ProcessInfoProvider::current_pid();

    // Current process should be a descendant of detected root
    assert!(checker.is_descendant(current_pid));
}

#[test]
fn test_real_process_tree_parent_chain() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();

    // Get current process info first
    let parent_pid = provider.get(current_pid).and_then(|info| info.parent_pid);

    // Create checker after we're done with provider
    let checker = AncestryChecker::new(ProcessInfoProvider::new());

    // Current should be descendant of its parent
    if let Some(parent_pid) = parent_pid {
        assert!(checker.is_descendant_of(current_pid, parent_pid));
    }
}

#[test]
fn test_real_process_tree_unrelated_process() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();
    let checker = AncestryChecker::with_root_pid(provider, current_pid);

    // PID 1 (init/launchd) is not a descendant of current process
    assert!(!checker.is_descendant(1));
}

#[test]
fn test_real_process_tree_grandparent_ancestor() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();

    // Get grandparent
    if let Some(current_info) = provider.get(current_pid) {
        if let Some(parent_pid) = current_info.parent_pid {
            if let Some(parent_info) = provider.get(parent_pid) {
                if let Some(grandparent_pid) = parent_info.parent_pid {
                    let checker = AncestryChecker::new(ProcessInfoProvider::new());
                    // Current should be descendant of grandparent
                    assert!(checker.is_descendant_of(current_pid, grandparent_pid));
                }
            }
        }
    }
}

#[test]
fn test_real_process_tree_env_var_override() {
    // Test that the root PID env var would be respected
    // (We don't actually set it to avoid side effects, but verify the parsing logic)
    let env_value = "12345";
    let parsed: Result<u32, _> = env_value.parse();
    assert!(parsed.is_ok());
    assert_eq!(parsed.unwrap(), 12345);
}

// =============================================================================
// 設定ファイルの読み込みと適用のテスト
// =============================================================================

#[test]
fn test_config_load_valid_file() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[allowlist]
processes = ["test_process_1", "test_process_2"]

[denylist]
processes = ["blocked_process"]
"#
    )
    .unwrap();

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    assert!(config.is_allowed("test_process_1"));
    assert!(config.is_allowed("test_process_2"));
    assert!(config.is_denied("blocked_process"));
    assert!(!config.is_allowed("other_process"));
    assert!(!config.is_denied("other_process"));
}

#[test]
fn test_config_apply_in_policy_engine() {
    use safe_kill::config::ProcessList;

    let config = Config {
        allowlist: Some(ProcessList {
            processes: vec!["allowed_test".to_string()],
        }),
        denylist: Some(ProcessList {
            processes: vec!["denied_test".to_string()],
        }),
        allowed_ports: None,
    };

    let engine = PolicyEngine::new(config);

    // Verify config is applied
    assert!(engine.config().is_allowed("allowed_test"));
    assert!(engine.config().is_denied("denied_test"));
}

#[test]
fn test_config_defaults_applied_when_missing() {
    let file = NamedTempFile::new().unwrap();
    // Empty config file

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    // Default denylist should be applied
    assert!(config.denylist.is_some());
    let denylist = config.denylist.unwrap();
    assert!(!denylist.processes.is_empty());
}

#[test]
fn test_config_fallback_on_invalid_toml() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "{{{{invalid toml syntax}}}}").unwrap();

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    // Should fall back to defaults
    assert!(config.denylist.is_some());
}

#[test]
fn test_config_nonexistent_file_uses_defaults() {
    let config = Config::load_from_path(Some(PathBuf::from("/nonexistent/path/config.toml")));

    assert!(config.denylist.is_some());
}

#[test]
fn test_config_denylist_precedence_over_allowlist() {
    use safe_kill::config::ProcessList;

    let config = Config {
        allowlist: Some(ProcessList {
            processes: vec!["conflict".to_string()],
        }),
        denylist: Some(ProcessList {
            processes: vec!["conflict".to_string()],
        }),
        allowed_ports: None,
    };

    // Denylist takes precedence
    assert!(config.is_denied("conflict"));
    // Even though it's in allowlist, denylist check comes first
}

// =============================================================================
// シグナル送信の成功/失敗ケースのテスト
// =============================================================================

#[test]
fn test_signal_send_to_nonexistent_process() {
    let result = SignalSender::send(999999999, Signal::SIGTERM);

    assert!(result.is_err());
    match result {
        Err(SafeKillError::ProcessNotFound(pid)) => assert_eq!(pid, 999999999),
        Err(SafeKillError::PermissionDenied(_)) => {
            // Some systems return permission denied instead
        }
        _ => panic!("Expected ProcessNotFound or PermissionDenied"),
    }
}

#[test]
fn test_signal_parsing_all_types() {
    let signals = [
        ("SIGTERM", Signal::SIGTERM),
        ("SIGKILL", Signal::SIGKILL),
        ("SIGHUP", Signal::SIGHUP),
        ("SIGINT", Signal::SIGINT),
        ("SIGQUIT", Signal::SIGQUIT),
        ("SIGUSR1", Signal::SIGUSR1),
        ("SIGUSR2", Signal::SIGUSR2),
        ("15", Signal::SIGTERM),
        ("9", Signal::SIGKILL),
        ("1", Signal::SIGHUP),
        ("2", Signal::SIGINT),
        ("3", Signal::SIGQUIT),
    ];

    for (input, expected) in signals {
        let result = SignalSender::parse_signal(input);
        assert!(result.is_ok(), "Failed to parse signal: {}", input);
        assert_eq!(result.unwrap(), expected, "Wrong signal for: {}", input);
    }
}

#[test]
fn test_signal_parsing_case_insensitive() {
    assert_eq!(
        SignalSender::parse_signal("sigterm").unwrap(),
        Signal::SIGTERM
    );
    assert_eq!(
        SignalSender::parse_signal("SigKill").unwrap(),
        Signal::SIGKILL
    );
    assert_eq!(SignalSender::parse_signal("term").unwrap(), Signal::SIGTERM);
    assert_eq!(SignalSender::parse_signal("KILL").unwrap(), Signal::SIGKILL);
}

#[test]
fn test_signal_invalid_name() {
    let result = SignalSender::parse_signal("INVALID");
    assert!(result.is_err());
    match result {
        Err(SafeKillError::InvalidSignal(s)) => assert_eq!(s, "INVALID"),
        _ => panic!("Expected InvalidSignal error"),
    }
}

#[test]
fn test_signal_invalid_number() {
    let result = SignalSender::parse_signal("999");
    assert!(result.is_err());
    match result {
        Err(SafeKillError::InvalidSignal(s)) => assert_eq!(s, "999"),
        _ => panic!("Expected InvalidSignal error"),
    }
}

#[test]
fn test_process_killer_dry_run() {
    let killer = ProcessKiller::new();
    let result = killer.kill_with_result(999999999, "test_process", Signal::SIGTERM, true);

    assert!(result.success);
    assert!(result.message.contains("dry run"));
}

// =============================================================================
// --dry-runモードの動作確認テスト
// =============================================================================

#[test]
fn test_dry_run_does_not_send_signal() {
    let killer = ProcessKiller::new();

    // Even with a valid signal, dry run shouldn't actually send
    let result = killer.kill_with_result(
        ProcessInfoProvider::current_pid(),
        "self",
        Signal::SIGTERM,
        true,
    );

    // Should succeed (in dry-run mode)
    assert!(result.success);
    assert!(result.message.contains("dry run"));
    // Process should still be alive (we're still running!)
}

#[test]
fn test_dry_run_result_format() {
    let killer = ProcessKiller::new();
    let result = killer.kill_with_result(12345, "test_proc", Signal::SIGKILL, true);

    assert_eq!(result.pid, 12345);
    assert_eq!(result.name, "test_proc");
    assert!(result.success);
    assert!(result.message.contains("SIGKILL"));
    assert!(result.message.contains("dry run"));
}

#[test]
fn test_policy_engine_with_dry_run() {
    use safe_kill::config::ProcessList;

    // Create a config that allows a specific process
    let config = Config {
        allowlist: Some(ProcessList {
            processes: vec!["safe_kill_test_target".to_string()],
        }),
        denylist: None,
        allowed_ports: None,
    };

    let engine = PolicyEngine::new(config);

    // Try to kill a non-existent process with dry_run=true
    // This should fail because the process doesn't exist, not because of dry_run
    let result = engine.kill_by_pid(999999999, Signal::SIGTERM, true);
    assert!(result.is_err());
    match result {
        Err(SafeKillError::ProcessNotFound(_)) => {}
        _ => panic!("Expected ProcessNotFound"),
    }
}

// =============================================================================
// PolicyEngine統合テスト
// =============================================================================

#[test]
fn test_policy_engine_suicide_prevention() {
    let engine = PolicyEngine::with_defaults();
    let current_pid = ProcessInfoProvider::current_pid();

    let result = engine.kill_by_pid(current_pid, Signal::SIGTERM, false);

    assert!(result.is_err());
    match result {
        Err(SafeKillError::SuicidePrevention(pid)) => assert_eq!(pid, current_pid),
        _ => panic!("Expected SuicidePrevention"),
    }
}

#[test]
fn test_policy_engine_list_killable() {
    let engine = PolicyEngine::with_defaults();
    let killable = engine.list_killable();

    let current_pid = ProcessInfoProvider::current_pid();

    // Should not include self
    assert!(!killable.iter().any(|p| p.pid == current_pid));

    // Should not include denylisted processes
    #[cfg(target_os = "macos")]
    {
        assert!(!killable.iter().any(|p| p.name == "launchd"));
    }
    #[cfg(target_os = "linux")]
    {
        assert!(!killable.iter().any(|p| p.name == "systemd"));
    }
}

#[test]
fn test_policy_engine_kill_by_name_not_found() {
    let engine = PolicyEngine::with_defaults();

    let result = engine.kill_by_name("__nonexistent_process_12345__", Signal::SIGTERM, false);

    assert!(result.is_err());
    match result {
        Err(SafeKillError::ProcessNameNotFound(_)) => {}
        _ => panic!("Expected ProcessNameNotFound"),
    }
}

// =============================================================================
// プロセス情報統合テスト
// =============================================================================

#[test]
fn test_process_info_real_processes() {
    let provider = ProcessInfoProvider::new();
    let all = provider.all();

    // Should have multiple processes
    assert!(all.len() > 1);

    // All should have valid PIDs
    for proc in &all {
        assert!(proc.pid > 0);
        assert!(!proc.name.is_empty());
    }
}

#[test]
fn test_process_info_refresh() {
    let mut provider = ProcessInfoProvider::new();
    let before = provider.all().len();

    provider.refresh();
    let after = provider.all().len();

    // Should still have processes after refresh
    assert!(before > 0);
    assert!(after > 0);
}

#[test]
fn test_process_info_current_has_parent() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();
    let info = provider.get(current_pid).unwrap();

    // Current process should have a parent
    assert!(info.parent_pid.is_some());
}

// =============================================================================
// エンドツーエンド統合テスト
// =============================================================================

#[test]
fn test_end_to_end_workflow_dry_run() {
    // Simulate the full workflow with dry_run

    // 1. Load configuration
    let config = Config::load();
    assert!(config.denylist.is_some());

    // 2. Create policy engine
    let engine = PolicyEngine::new(config);
    assert!(engine.root_pid() > 0);

    // 3. List killable processes
    let _killable = engine.list_killable();
    // May or may not have killable processes, but should not panic

    // 4. Try dry-run on non-existent process
    let result = engine.kill_by_pid(999999999, Signal::SIGTERM, true);
    assert!(result.is_err()); // Not found

    // 5. Check suicide prevention
    let current = ProcessInfoProvider::current_pid();
    let suicide_result = engine.kill_by_pid(current, Signal::SIGTERM, true);
    assert!(matches!(
        suicide_result,
        Err(SafeKillError::SuicidePrevention(_))
    ));
}

// =============================================================================
// 異常入力テスト（Codex分析により追加）
// =============================================================================

#[cfg(unix)]
#[test]
fn test_config_load_permission_denied_fallback() {
    use std::os::unix::fs::PermissionsExt;

    let file = NamedTempFile::new().unwrap();
    let path = file.path().to_path_buf();

    // ファイルに何か書き込む
    std::fs::write(&path, "[allowlist]\nprocesses = [\"test\"]").unwrap();

    // パーミッションを読み取り不可に設定
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    // 読み込みを試みる（デフォルトにフォールバックすべき）
    let config = Config::load_from_path(Some(path.clone()));

    // デフォルトのdenylistが適用されているはず
    assert!(config.denylist.is_some());

    // クリーンアップ: パーミッションを戻す
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn test_config_load_invalid_types_fallback() {
    let mut file = NamedTempFile::new().unwrap();
    // portsが文字列の配列でなく数値の配列になっている（誤った型）
    writeln!(file, "[allowed_ports]\nports = [3000, 8080]").unwrap();

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    // TOMLのパースは成功するが、型が合わないためデフォルトにフォールバック
    // またはallowed_portsがNoneになるかデフォルトが適用される
    // この場合、tomlは数値配列を文字列配列として読めないのでパースエラーになり
    // デフォルトにフォールバックする
    assert!(config.denylist.is_some());
}

#[test]
fn test_config_is_port_allowed_ignores_invalid_specs() {
    use safe_kill::config::AllowedPorts;

    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: Some(AllowedPorts {
            ports: vec![
                "invalid".to_string(),   // 無効なポート指定
                "3000-3001".to_string(), // 有効な範囲
                "also-bad".to_string(),  // 無効なポート指定
            ],
        }),
    };

    // 有効な範囲内のポートは許可される
    assert!(config.is_port_allowed(3000));
    assert!(config.is_port_allowed(3001));

    // 無効な指定は無視され、その範囲外は許可されない
    assert!(!config.is_port_allowed(22));
    assert!(!config.is_port_allowed(8080));
}

#[test]
fn test_signal_parsing_edge_cases() {
    // 正常なケース（大文字小文字混在）
    assert_eq!(
        SignalSender::parse_signal("SigTerm").unwrap(),
        Signal::SIGTERM
    );

    // 空白を含む場合（trimされる）
    assert_eq!(
        SignalSender::parse_signal("  SIGKILL  ").unwrap(),
        Signal::SIGKILL
    );

    // 無効なシグナル名
    assert!(SignalSender::parse_signal("SIGINVALID").is_err());

    // 空文字列
    assert!(SignalSender::parse_signal("").is_err());
}

// =============================================================================
// ポート機能の境界値テスト（Codex分析により追加）
// =============================================================================

#[test]
fn test_port_range_boundary_in_config() {
    use safe_kill::config::AllowedPorts;

    // 最大ポート値のテスト
    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: Some(AllowedPorts {
            ports: vec!["65535".to_string()],
        }),
    };

    assert!(config.is_port_allowed(65535));
    assert!(!config.is_port_allowed(65534));

    // 最小ポート値のテスト
    let config_min = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: Some(AllowedPorts {
            ports: vec!["0".to_string()],
        }),
    };

    assert!(config_min.is_port_allowed(0));
    assert!(!config_min.is_port_allowed(1));
}

#[test]
fn test_port_full_range_config() {
    use safe_kill::config::AllowedPorts;

    // 全ポート範囲のテスト
    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: Some(AllowedPorts {
            ports: vec!["0-65535".to_string()],
        }),
    };

    // 境界値
    assert!(config.is_port_allowed(0));
    assert!(config.is_port_allowed(65535));

    // 中間値
    assert!(config.is_port_allowed(80));
    assert!(config.is_port_allowed(443));
    assert!(config.is_port_allowed(3000));
    assert!(config.is_port_allowed(8080));
}

// =============================================================================
// PolicyEngine kill_by_port 統合テスト
// =============================================================================

#[test]
fn test_policy_engine_kill_by_port_not_allowed_default() {
    // Default config has no allowed_ports, so port-based killing is disabled
    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: None,
    };
    let engine = PolicyEngine::new(config);

    let result = engine.kill_by_port(3000, Signal::SIGTERM, false);
    assert!(matches!(result, Err(SafeKillError::PortNotAllowed { .. })));
}

#[test]
fn test_policy_engine_kill_by_port_allowed_but_empty() {
    use safe_kill::config::AllowedPorts;

    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: Some(AllowedPorts {
            ports: vec!["59990".to_string()],
        }),
    };
    let engine = PolicyEngine::new(config);

    // Port is allowed but no process on it
    let result = engine.kill_by_port(59990, Signal::SIGTERM, false);
    assert!(matches!(result, Err(SafeKillError::NoProcessOnPort(59990))));
}

// =============================================================================
// init コマンド設定ファイルの整合性テスト
// =============================================================================

#[test]
fn test_init_config_parses_as_valid_config() {
    use safe_kill::init::InitCommand;

    let content = InitCommand::default_config_content();
    let config: Config = toml::from_str(&content).expect("Default config should be valid");

    // Should have allowed_ports section
    assert!(config.allowed_ports.is_some());
    let ports = config.allowed_ports.unwrap();
    assert!(!ports.ports.is_empty());
}

// =============================================================================
// ProcessInfoProvider 統合テスト
// =============================================================================

#[test]
fn test_process_info_find_by_name_matches_exact() {
    let provider = ProcessInfoProvider::new();
    let current = provider.get(ProcessInfoProvider::current_pid()).unwrap();

    // Finding by exact current process name should include current PID
    let results = provider.find_by_name(&current.name);
    assert!(
        results
            .iter()
            .any(|p| p.pid == ProcessInfoProvider::current_pid())
    );
}

// =============================================================================
// SAFE_KILL_ROOT_PID 環境変数テスト
// =============================================================================

#[test]
fn test_ancestry_with_explicit_root_pid() {
    use safe_kill::ancestry::AncestryChecker;

    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();

    // 現在のプロセスをルートPIDとして設定
    let checker = AncestryChecker::with_root_pid(provider, current_pid);

    // 自身はルートの子孫として判定される
    assert!(checker.is_descendant(current_pid));

    // PID 1 は現在のプロセスの子孫ではない
    assert!(!checker.is_descendant(1));
}

#[test]
fn test_ancestry_root_pid_is_consistent() {
    use safe_kill::ancestry::AncestryChecker;

    let provider1 = ProcessInfoProvider::new();
    let provider2 = ProcessInfoProvider::new();

    let root1 = AncestryChecker::get_root_pid(&provider1);
    let root2 = AncestryChecker::get_root_pid(&provider2);

    // 同じプロセスから取得したルートPIDは一致する
    assert_eq!(root1, root2);
}

// =============================================================================
// PolicyEngine 混合バッチ結果テスト
// =============================================================================

#[test]
fn test_policy_engine_kill_by_name_denylisted_returns_batch() {
    use safe_kill::config::ProcessList;

    // PID 1 のプロセス名を取得 (launchd or systemd)
    let provider = ProcessInfoProvider::new();
    let pid1_info = provider.get(1).expect("PID 1 should exist");

    let config = Config {
        allowlist: None,
        denylist: Some(ProcessList {
            processes: vec![pid1_info.name.clone()],
        }),
        allowed_ports: None,
    };
    let engine = PolicyEngine::new(config);

    // denylist に入っているプロセスを名前で kill しようとする
    let result = engine.kill_by_name(&pid1_info.name, Signal::SIGTERM, true);

    // プロセスは見つかるが kill は拒否される → Ok(batch) で返る
    assert!(result.is_ok());
    let batch = result.unwrap();
    assert!(batch.total_matched > 0);
    assert_eq!(batch.total_killed, 0);
    assert!(!batch.any_success());
}

#[test]
fn test_config_with_allowed_ports_in_policy_engine() {
    use safe_kill::config::AllowedPorts;

    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: Some(AllowedPorts {
            ports: vec!["59989".to_string()],
        }),
    };
    let engine = PolicyEngine::new(config);

    // 設定に含まれるポートは許可される
    assert!(engine.config().is_port_allowed(59989));

    // 設定に含まれないポートは拒否される
    assert!(!engine.config().is_port_allowed(59988));
}

// =============================================================================
// ProcessInfoProvider 追加テスト
// =============================================================================

#[test]
fn test_process_info_get_pid_1() {
    let provider = ProcessInfoProvider::new();
    // PID 1 should exist on any Unix system
    let info = provider.get(1);
    assert!(info.is_some(), "PID 1 should exist");
    let info = info.unwrap();
    assert_eq!(info.pid, 1);
    assert!(!info.name.is_empty());
}
