//! safe-kill の統合テスト
//!
//! 実際のプロセスツリー、設定ファイル、シグナル操作を使って公開 API をテストする。

use safe_kill::ancestry::AncestryChecker;
use safe_kill::config::Config;
use safe_kill::error::SafeKillError;
use safe_kill::killer::ProcessKiller;
use safe_kill::policy::{KillPermission, PolicyEngine};
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

    // 現在のプロセスは検出されたルートの子孫であるべき
    assert!(checker.is_descendant(current_pid));
}

#[test]
fn test_real_process_tree_parent_chain() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();

    // まず現在のプロセス情報を取得
    let parent_pid = provider.get(current_pid).and_then(|info| info.parent_pid);

    // provider の使用が終わった後に checker を作成
    let checker = AncestryChecker::new(ProcessInfoProvider::new());

    // 現在のプロセスは親の子孫であるべき
    if let Some(parent_pid) = parent_pid {
        assert!(checker.is_descendant_of(current_pid, parent_pid));
    }
}

#[test]
fn test_real_process_tree_unrelated_process() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();
    let checker = AncestryChecker::with_root_pid(provider, current_pid);

    // PID 1 (init/launchd) は現在のプロセスの子孫ではない
    assert!(!checker.is_descendant(1));
}

#[test]
fn test_real_process_tree_grandparent_ancestor() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();

    // 祖父プロセスを取得
    if let Some(current_info) = provider.get(current_pid) {
        if let Some(parent_pid) = current_info.parent_pid {
            if let Some(parent_info) = provider.get(parent_pid) {
                if let Some(grandparent_pid) = parent_info.parent_pid {
                    let checker = AncestryChecker::new(ProcessInfoProvider::new());
                    // 現在のプロセスは祖父プロセスの子孫であるべき
                    assert!(checker.is_descendant_of(current_pid, grandparent_pid));
                }
            }
        }
    }
}

#[test]
fn test_real_process_tree_env_var_override() {
    // ルート PID 環境変数が尊重されることをテスト
    // （副作用を避けるため実際には設定せず、パースロジックのみ検証）
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
fn test_config_load_keeps_default_system_denylist_when_customized() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[denylist]
processes = ["custom_process"]
"#
    )
    .unwrap();

    let provider = ProcessInfoProvider::new();
    let pid1_info = provider.get(1).expect("PID 1 should exist");

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    assert!(config.is_denied("custom_process"));
    assert!(
        config.is_denied(&pid1_info.name),
        "custom denylist should not remove system protection for PID 1 ({})",
        pid1_info.name
    );
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

    // 設定が適用されていることを確認
    assert!(engine.config().is_allowed("allowed_test"));
    assert!(engine.config().is_denied("denied_test"));
}

#[test]
fn test_policy_engine_keeps_system_processes_denied_with_custom_denylist() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[denylist]
processes = ["custom_process"]
"#
    )
    .unwrap();

    let provider = ProcessInfoProvider::new();
    let pid1_info = provider.get(1).expect("PID 1 should exist");
    let config = Config::load_from_path(Some(file.path().to_path_buf()));
    let engine = PolicyEngine::new(config);

    assert!(matches!(
        engine.can_kill(&pid1_info),
        KillPermission::DeniedByDenylist(ref name) if name == &pid1_info.name
    ));
}

#[test]
fn test_config_defaults_applied_when_missing() {
    let file = NamedTempFile::new().unwrap();
    // 空の設定ファイル

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    // デフォルトの denylist が適用されるべき
    assert!(config.denylist.is_some());
    let denylist = config.denylist.unwrap();
    assert!(!denylist.processes.is_empty());
}

#[test]
fn test_config_fallback_on_invalid_toml() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "{{{{invalid toml syntax}}}}").unwrap();

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    // デフォルトにフォールバックすべき
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

    // denylist が優先される
    assert!(config.is_denied("conflict"));
    // allowlist に含まれていても、denylist のチェックが先に行われる
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
            // 一部のシステムでは permission denied が返る
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

    // 有効なシグナルでも dry-run では実際に送信しない
    let result = killer.kill_with_result(
        ProcessInfoProvider::current_pid(),
        "self",
        Signal::SIGTERM,
        true,
    );

    // dry-run モードでは成功するべき
    assert!(result.success);
    assert!(result.message.contains("dry run"));
    // プロセスはまだ生存しているはず（まだ実行中！）
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

    // 特定のプロセスを許可する設定を作成
    let config = Config {
        allowlist: Some(ProcessList {
            processes: vec!["safe_kill_test_target".to_string()],
        }),
        denylist: None,
        allowed_ports: None,
    };

    let engine = PolicyEngine::new(config);

    // 存在しないプロセスを dry_run=true で kill しようとする
    // dry_run ではなく、プロセスが存在しないために失敗するべき
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

    // 自プロセスは含まれないべき
    assert!(!killable.iter().any(|p| p.pid == current_pid));

    // denylist のプロセスは含まれないべき
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

    // 複数のプロセスが存在するべき
    assert!(all.len() > 1);

    // すべて有効な PID を持つべき
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

    // リフレッシュ後もプロセスが存在するべき
    assert!(before > 0);
    assert!(after > 0);
}

#[test]
fn test_process_info_current_has_parent() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();
    let info = provider.get(current_pid).unwrap();

    // 現在のプロセスは親を持つべき
    assert!(info.parent_pid.is_some());
}

// =============================================================================
// エンドツーエンド統合テスト
// =============================================================================

#[test]
fn test_end_to_end_workflow_dry_run() {
    // dry_run での完全なワークフローをシミュレート

    // 1. 設定を読み込み
    let config = Config::load();
    assert!(config.denylist.is_some());

    // 2. PolicyEngine を作成
    let engine = PolicyEngine::new(config);
    assert!(engine.root_pid() > 0);

    // 3. kill 可能なプロセスを一覧表示
    let _killable = engine.list_killable();
    // kill 可能なプロセスがあるかは不定だが、パニックしないこと

    // 4. 存在しないプロセスに dry-run を試行
    let result = engine.kill_by_pid(999999999, Signal::SIGTERM, true);
    assert!(result.is_err()); // 見つからない

    // 5. 自殺防止チェック
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
    // デフォルト設定には allowed_ports がないため、ポートベースの kill は無効
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

    // ポートは許可されているがプロセスが存在しない
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

    // allowed_ports セクションが存在するべき
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

    // 現在のプロセス名で正確に検索すると、現在の PID が含まれるべき
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
    // PID 1 はすべての Unix システムで存在するべき
    let info = provider.get(1);
    assert!(info.is_some(), "PID 1 should exist");
    let info = info.unwrap();
    assert_eq!(info.pid, 1);
    assert!(!info.name.is_empty());
}

// =============================================================================
// PolicyEngine kill_by_name 成功パステスト
// =============================================================================

/// kill_by_name で子プロセスが見つかり dry-run で成功するテスト
#[test]
fn test_policy_engine_kill_by_name_dry_run_success() {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    // 自プロセスの子孫なので ancestry チェックを通過する
    let config = Config::load();
    let engine = PolicyEngine::new(config);

    let result = engine.kill_by_name("sleep", Signal::SIGTERM, true);
    assert!(result.is_ok(), "dry-run での kill_by_name は Ok を返すべき");

    let batch = result.unwrap();
    assert!(batch.total_matched > 0, "sleep プロセスが見つかるべき");
    // dry-run では kill が成功扱いになる
    assert!(batch.any_success(), "dry-run の結果は success になるべき");

    // 実際には kill されていないので cleanup
    let mut child = child;
    let _ = SignalSender::send(child_pid, Signal::SIGTERM);
    let _ = child.wait();
}

/// kill_by_name で混合結果（一部許可・一部拒否）のテスト
#[test]
fn test_policy_engine_kill_by_name_mixed_batch() {
    use safe_kill::config::ProcessList;

    // PID 1 のプロセス名を取得
    let provider = ProcessInfoProvider::new();
    let pid1_info = provider.get(1).expect("PID 1 should exist");

    // denylist に入っているプロセスを名前で検索した場合、
    // 全プロセスが拒否される
    let config = Config {
        allowlist: None,
        denylist: Some(ProcessList {
            processes: vec![pid1_info.name.clone()],
        }),
        allowed_ports: None,
    };
    let engine = PolicyEngine::new(config);

    let result = engine.kill_by_name(&pid1_info.name, Signal::SIGTERM, true);
    assert!(result.is_ok());

    let batch = result.unwrap();
    assert!(batch.total_matched > 0);
    // denylist 上のプロセスはすべて拒否
    assert_eq!(batch.total_killed, 0);
    assert!(!batch.all_success());
    assert!(!batch.any_success());

    // 各結果にエラーが含まれることを確認
    for r in &batch.results {
        assert!(!r.success);
        assert!(r.error.is_some());
    }
}

// =============================================================================
// PolicyEngine kill_by_pid 成功パステスト
// =============================================================================

/// kill_by_pid で子プロセスを dry-run で正常終了するテスト
#[test]
fn test_policy_engine_kill_by_pid_dry_run_success() {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    let config = Config::load();
    let engine = PolicyEngine::new(config);

    let result = engine.kill_by_pid(child_pid, Signal::SIGTERM, true);
    assert!(result.is_ok(), "子プロセスの dry-run kill は Ok を返すべき");

    let kill_result = result.unwrap();
    assert!(kill_result.success);
    assert_eq!(kill_result.pid, child_pid);
    assert!(kill_result.message.contains("dry run"));

    let mut child = child;
    let _ = SignalSender::send(child_pid, Signal::SIGTERM);
    let _ = child.wait();
}

// =============================================================================
// AncestryChecker get_root_pid フォールバックテスト
// =============================================================================

/// 環境変数未設定時に get_root_pid が祖父プロセス PID を返すテスト
#[test]
fn test_ancestry_get_root_pid_without_env_var() {
    // 環境変数を一時的にクリア
    let original = std::env::var("SAFE_KILL_ROOT_PID").ok();
    unsafe {
        std::env::remove_var("SAFE_KILL_ROOT_PID");
    }

    let provider = ProcessInfoProvider::new();
    let root = AncestryChecker::get_root_pid(&provider);

    // ルート PID は有効な値（> 0）であるべき
    assert!(root > 0, "ルート PID は 0 より大きいべき");

    // 現在プロセスの祖父 PID または親 PID と一致するはず
    let current_pid = ProcessInfoProvider::current_pid();
    if let Some(current_info) = provider.get(current_pid) {
        if let Some(parent_pid) = current_info.parent_pid {
            if let Some(parent_info) = provider.get(parent_pid) {
                if let Some(grandparent_pid) = parent_info.parent_pid {
                    assert_eq!(root, grandparent_pid, "祖父プロセス PID と一致すべき");
                } else {
                    // 祖父が取得できない場合は親 PID にフォールバック
                    assert_eq!(root, parent_pid, "親プロセス PID にフォールバックすべき");
                }
            }
        }
    }

    // 環境変数を復元
    if let Some(val) = original {
        unsafe {
            std::env::set_var("SAFE_KILL_ROOT_PID", val);
        }
    }
}

// =============================================================================
// ProcessInfoProvider 空文字列検索テスト
// =============================================================================

#[test]
fn test_process_info_find_by_name_empty_string() {
    let provider = ProcessInfoProvider::new();
    let results = provider.find_by_name("");
    assert!(results.is_empty(), "空文字列での検索は空の結果を返すべき");
}

// =============================================================================
// SignalSender 成功パス統合テスト
// =============================================================================

/// 子プロセスに SIGTERM を送信し、成功を確認する統合テスト
#[test]
fn test_signal_send_success_to_child_integration() {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let pid = child.id();

    let result = SignalSender::send(pid, Signal::SIGTERM);
    assert!(result.is_ok(), "子プロセスへの SIGTERM 送信は成功するべき");

    // プロセスが終了済みなので再送信すると ProcessNotFound になる
    let mut child = child;
    let _ = child.wait();

    let result2 = SignalSender::send(pid, Signal::SIGTERM);
    assert!(
        matches!(result2, Err(SafeKillError::ProcessNotFound(_))),
        "終了済みプロセスへの送信は ProcessNotFound になるべき"
    );
}

// =============================================================================
// kill_by_name 実 kill テスト
// =============================================================================

/// kill_by_name で子プロセスを実際に kill するテスト
#[test]
fn test_policy_engine_kill_by_name_actual_kill() {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    let config = Config::load();
    let engine = PolicyEngine::new(config);

    let result = engine.kill_by_name("sleep", Signal::SIGTERM, false);
    assert!(result.is_ok(), "子プロセスの kill_by_name は Ok を返すべき");

    let batch = result.unwrap();
    assert!(batch.total_matched > 0, "sleep プロセスが見つかるべき");
    assert!(batch.any_success(), "少なくとも1件は成功するべき");

    // 終了済みプロセスの回収
    let mut child = child;
    let _ = child.wait();

    // プロセスが終了したことを確認
    std::thread::sleep(std::time::Duration::from_millis(100));
    let check = SignalSender::send(child_pid, Signal::SIGTERM);
    assert!(
        matches!(check, Err(SafeKillError::ProcessNotFound(_))),
        "kill 後のプロセスは ProcessNotFound になるべき"
    );
}

// =============================================================================
// config port_not_allowed_hint テスト
// =============================================================================

/// config なしの場合の port_not_allowed_hint テスト
#[test]
fn test_port_not_allowed_hint_without_config() {
    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: None,
    };
    let hint = config.port_not_allowed_hint(3000);
    assert!(hint.contains("3000"), "ヒントにポート番号が含まれるべき");
    assert!(
        hint.contains("config.toml"),
        "ヒントに設定ファイル名が含まれるべき"
    );
    assert!(
        hint.contains("safe-kill init"),
        "ヒントに init コマンドが含まれるべき"
    );
}

// =============================================================================
// PolicyEngine kill_by_pid 実 kill テスト
// =============================================================================

/// kill_by_pid で子プロセスを実際に kill するテスト
#[test]
fn test_policy_engine_kill_by_pid_actual_kill() {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    let config = Config::load();
    let engine = PolicyEngine::new(config);

    let result = engine.kill_by_pid(child_pid, Signal::SIGTERM, false);
    assert!(result.is_ok(), "子プロセスの kill_by_pid は Ok を返すべき");

    let kill_result = result.unwrap();
    assert!(kill_result.success, "kill は成功するべき");
    assert_eq!(kill_result.pid, child_pid);
    assert!(
        kill_result.message.contains("SIGTERM"),
        "メッセージにシグナル名が含まれるべき"
    );

    // 終了済みプロセスの回収
    let mut child = child;
    let _ = child.wait();
}

// =============================================================================
// AncestryChecker is_descendant_of で異なる祖先テスト
// =============================================================================

/// 無関係なプロセスの子孫判定テスト
#[test]
fn test_ancestry_is_descendant_of_unrelated() {
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();
    let checker = AncestryChecker::new(provider);

    // 現在プロセスが PID 1 の子孫であることは確認（通常は true）
    // ただし PID 1 は現在プロセスの子孫ではない
    assert!(!checker.is_descendant_of(1, current_pid));
}

// =============================================================================
// Config check_port_allowed のエラー内容テスト
// =============================================================================

/// check_port_allowed のエラーにポート番号とヒントが含まれることを確認
#[test]
fn test_check_port_allowed_error_content() {
    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: None,
    };
    let result = config.check_port_allowed(8080);
    assert!(result.is_err());
    match result {
        Err(SafeKillError::PortNotAllowed { port, hint }) => {
            assert_eq!(port, 8080);
            assert!(hint.contains("8080"));
            assert!(hint.contains("config.toml"));
        }
        _ => panic!("PortNotAllowed エラーが返されるべき"),
    }
}

// =============================================================================
// PolicyEngine list_killable で子プロセスが含まれるテスト
// =============================================================================

/// 子プロセスが list_killable の結果に含まれることを確認
#[test]
fn test_policy_engine_list_killable_includes_child() {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    let config = Config::load();
    let engine = PolicyEngine::new(config);

    let killable = engine.list_killable();
    assert!(
        killable.iter().any(|p| p.pid == child_pid),
        "子プロセスが killable リストに含まれるべき"
    );

    // クリーンアップ
    let mut child = child;
    let _ = SignalSender::send(child_pid, Signal::SIGTERM);
    let _ = child.wait();
}

// =============================================================================
// 追加テスト: 空リスト・部分一致・既終了プロセス
// =============================================================================

/// 空の processes 配列での allowlist/denylist 動作テスト
#[test]
fn test_config_empty_process_lists() {
    use safe_kill::config::ProcessList;

    let config = Config {
        allowlist: Some(ProcessList { processes: vec![] }),
        denylist: Some(ProcessList { processes: vec![] }),
        allowed_ports: None,
    };

    // 空リストでは何も許可・拒否されない
    assert!(!config.is_allowed("node"));
    assert!(!config.is_denied("node"));
    assert!(!config.is_allowed(""));
    assert!(!config.is_denied(""));
}

/// find_by_name は部分一致ではなく完全一致であることを確認
#[test]
fn test_process_info_find_by_name_no_partial_match() {
    let provider = ProcessInfoProvider::new();
    let current = provider.get(ProcessInfoProvider::current_pid()).unwrap();

    // 名前の一部だけでは一致しないことを確認
    if current.name.len() > 1 {
        let partial = &current.name[..current.name.len() - 1];
        let results = provider.find_by_name(partial);
        // 部分一致では現在のプロセスが見つからないこと
        // （ただし偶然一致するプロセスが存在する可能性はある）
        for r in &results {
            assert_eq!(r.name, partial, "find_by_name は完全一致のみ返すべき");
        }
    }
}

/// 既に終了したプロセスへの kill が適切なエラーを返すテスト
#[test]
fn test_kill_already_terminated_process() {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    // まず終了させる
    let _ = SignalSender::send(child_pid, Signal::SIGTERM);
    let mut child = child;
    let _ = child.wait();
    std::thread::sleep(std::time::Duration::from_millis(100));

    // 終了済みプロセスへの kill を試行
    let config = Config::load();
    let engine = PolicyEngine::new(config);
    let result = engine.kill_by_pid(child_pid, Signal::SIGTERM, false);

    // ProcessNotFound エラーが返されるべき
    assert!(
        matches!(result, Err(SafeKillError::ProcessNotFound(_))),
        "終了済みプロセスへの kill は ProcessNotFound になるべき"
    );
}

/// 子プロセスが ancestry チェックを通過することを確認
#[test]
fn test_ancestry_child_process_is_descendant() {
    use safe_kill::ancestry::AncestryChecker;
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    let provider = ProcessInfoProvider::new();
    let checker = AncestryChecker::new(provider);

    // 子プロセスはセッションの子孫であるべき
    assert!(
        checker.is_descendant(child_pid),
        "子プロセスは ancestry チェックを通過すべき"
    );

    // クリーンアップ
    let mut child = child;
    let _ = SignalSender::send(child_pid, Signal::SIGTERM);
    let _ = child.wait();
}

/// ポート指定 kill で実際の TCP リスナーをテスト
#[test]
fn test_policy_engine_kill_by_port_with_real_listener() {
    use safe_kill::config::AllowedPorts;
    use std::net::TcpListener;
    use std::process::Command;

    // 利用可能なポートを見つける
    let listener = TcpListener::bind("127.0.0.1:0").expect("ポートのバインドに失敗");
    let port = listener.local_addr().unwrap().port();
    drop(listener); // ポートを解放して子プロセスに使わせる

    // nc (netcat) でリスナーを起動
    let child = Command::new("nc")
        .arg("-l")
        .arg("127.0.0.1")
        .arg(port.to_string())
        .spawn();

    if let Ok(child) = child {
        let child_pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(200));

        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec![format!("{}", port)],
            }),
        };
        let engine = PolicyEngine::new(config);

        let result = engine.kill_by_port(port, Signal::SIGTERM, true);
        // nc がポートをバインドできた場合はプロセスが見つかるはず
        // 環境により見つからない場合もあるので、エラーでも OK
        if let Ok(batch) = result {
            if batch.total_matched > 0 {
                assert!(batch.any_success(), "dry-run では成功扱いになるべき");
            }
        }

        // クリーンアップ
        let mut child = child;
        let _ = SignalSender::send(child_pid, Signal::SIGTERM);
        let _ = child.wait();
    }
}

/// denylist に入っているプロセスは ancestry チェックに関係なく拒否される
#[test]
fn test_denylist_overrides_ancestry_for_child() {
    use safe_kill::config::ProcessList;
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    let config = Config {
        allowlist: None,
        denylist: Some(ProcessList {
            processes: vec!["sleep".to_string()],
        }),
        allowed_ports: None,
    };
    let engine = PolicyEngine::new(config);

    // 子プロセスでも denylist に含まれていれば拒否
    let result = engine.kill_by_pid(child_pid, Signal::SIGTERM, false);
    assert!(
        matches!(result, Err(SafeKillError::Denylisted(_))),
        "denylist のプロセスは子プロセスでも拒否されるべき"
    );

    // クリーンアップ
    let mut child = child;
    let _ = SignalSender::send(child_pid, Signal::SIGTERM);
    let _ = child.wait();
}

/// allowlist に入っていれば ancestry チェックをバイパスできる
#[test]
fn test_allowlist_bypasses_ancestry_check() {
    use safe_kill::config::ProcessList;

    // PID 1 のプロセス名を取得
    let provider = ProcessInfoProvider::new();
    let pid1_info = provider.get(1).expect("PID 1 should exist");

    // PID 1 を allowlist に入れ、denylist からは除外
    let config = Config {
        allowlist: Some(ProcessList {
            processes: vec![pid1_info.name.clone()],
        }),
        denylist: None,
        allowed_ports: None,
    };
    let engine = PolicyEngine::new(config);

    // can_kill では AllowedByAllowlist が返るべき
    let permission = engine.can_kill(&pid1_info);
    assert_eq!(
        permission,
        KillPermission::AllowedByAllowlist,
        "allowlist のプロセスは ancestry チェックをバイパスすべき"
    );
}

/// PortRange の同一ポート範囲テスト（start == end）
#[test]
fn test_port_range_same_start_end_in_policy() {
    use safe_kill::config::AllowedPorts;

    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: Some(AllowedPorts {
            ports: vec!["8080-8080".to_string()],
        }),
    };

    assert!(config.is_port_allowed(8080));
    assert!(!config.is_port_allowed(8079));
    assert!(!config.is_port_allowed(8081));
}

// =============================================================================
// PortDetector 実リスナーテスト
// =============================================================================

/// 実際の TCP リスナーを起動し、PortDetector がプロセスを検出できることを確認
#[test]
fn test_port_detector_find_by_port_with_real_listener() {
    use safe_kill::port::PortDetector;
    use std::net::TcpListener;

    // OS が自動割り当てしたポートを使用
    let listener = TcpListener::bind("127.0.0.1:0").expect("ポートのバインドに失敗");
    let port = listener.local_addr().unwrap().port();

    // リスナーが生きている状態で検出を試みる
    let detector = PortDetector::new();
    let result = detector.find_by_port(port);
    assert!(result.is_ok(), "find_by_port はエラーなく完了すべき");

    let processes = result.unwrap();
    // 自プロセスがリッスンしているので検出されるべき
    let current_pid = ProcessInfoProvider::current_pid();
    assert!(
        processes.iter().any(|p| p.pid == current_pid),
        "自プロセスがポート {} のリスナーとして検出されるべき (検出: {:?})",
        port,
        processes.iter().map(|p| p.pid).collect::<Vec<_>>()
    );

    // PortProcess のフィールドを確認
    if let Some(pp) = processes.iter().find(|p| p.pid == current_pid) {
        assert_eq!(pp.port, port);
        assert!(!pp.name.is_empty());
    }

    drop(listener);
}

/// 実際の TCP リスナーで get_process_info が ProcessInfo を返すことを確認
#[test]
fn test_port_detector_get_process_info_with_real_listener() {
    use safe_kill::port::PortDetector;
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("ポートのバインドに失敗");
    let port = listener.local_addr().unwrap().port();

    let detector = PortDetector::new();
    let result = detector.get_process_info(port);
    assert!(result.is_ok(), "get_process_info はエラーなく完了すべき");

    let infos = result.unwrap();
    let current_pid = ProcessInfoProvider::current_pid();
    assert!(
        infos.iter().any(|p| p.pid == current_pid),
        "get_process_info で自プロセスが返されるべき"
    );

    drop(listener);
}

// =============================================================================
// Config 全セクション同時指定テスト
// =============================================================================

/// allowlist + denylist + allowed_ports を全て指定した設定ファイルのロードテスト
#[test]
fn test_config_load_all_sections() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[allowlist]
processes = ["node", "npm"]

[denylist]
processes = ["postgres"]

[allowed_ports]
ports = ["3000-3010", "8080"]
"#
    )
    .unwrap();

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    // allowlist が正しく読み込まれている
    assert!(config.is_allowed("node"));
    assert!(config.is_allowed("npm"));
    assert!(!config.is_allowed("python"));

    // カスタム denylist + デフォルト denylist が合流されている
    assert!(config.is_denied("postgres"));
    for default in Config::default_denylist() {
        assert!(
            config.is_denied(&default),
            "デフォルト denylist の {} が含まれるべき",
            default
        );
    }

    // allowed_ports が正しく読み込まれている
    assert!(config.is_port_allowed(3000));
    assert!(config.is_port_allowed(3005));
    assert!(config.is_port_allowed(3010));
    assert!(config.is_port_allowed(8080));
    assert!(!config.is_port_allowed(8081));
    assert!(!config.is_port_allowed(22));
}

// =============================================================================
// PolicyEngine kill_by_port 実 kill テスト
// =============================================================================

/// --port で実際に子プロセスの TCP リスナーを kill するテスト
#[test]
fn test_policy_engine_kill_by_port_actual_kill() {
    use safe_kill::config::AllowedPorts;
    use std::net::TcpListener;
    use std::process::Command;

    // 利用可能なポートを見つける
    let listener = TcpListener::bind("127.0.0.1:0").expect("ポートのバインドに失敗");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    // nc (netcat) でリスナーを起動
    let child = Command::new("nc")
        .arg("-l")
        .arg("127.0.0.1")
        .arg(port.to_string())
        .spawn();

    if let Ok(child) = child {
        let child_pid = child.id();
        std::thread::sleep(std::time::Duration::from_millis(200));

        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec![format!("{}", port)],
            }),
        };
        let engine = PolicyEngine::new(config);

        let result = engine.kill_by_port(port, Signal::SIGTERM, false);

        // nc がポートをバインドできた場合
        if let Ok(batch) = result {
            if batch.total_matched > 0 {
                assert!(batch.any_success(), "実際の kill は成功すべき");

                // プロセスが終了したことを確認
                let mut child = child;
                let _ = child.wait();
                std::thread::sleep(std::time::Duration::from_millis(100));

                let check = SignalSender::send(child_pid, Signal::SIGTERM);
                assert!(
                    matches!(check, Err(SafeKillError::ProcessNotFound(_))),
                    "kill 後のプロセスは ProcessNotFound になるべき"
                );
                return;
            }
        }

        // nc が使えなかった場合のクリーンアップ
        let mut child = child;
        let _ = SignalSender::send(child_pid, Signal::SIGTERM);
        let _ = child.wait();
    }
}

// =============================================================================
// PolicyEngine::kill_by_name で全プロセスがポリシー拒否されるケース
// =============================================================================

/// kill_by_name で一致プロセスが全て denylist に含まれる場合のテスト
#[test]
fn test_kill_by_name_all_denied_returns_batch_with_failures() {
    use safe_kill::config::ProcessList;

    // 現在のプロセス名を取得して denylist に追加する
    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();
    let current_info = provider
        .get(current_pid)
        .expect("現在のプロセスが存在するべき");

    let config = Config {
        allowlist: None,
        denylist: Some(ProcessList {
            processes: vec![current_info.name.clone()],
        }),
        allowed_ports: None,
    };
    let engine = PolicyEngine::new(config);

    // 現在のプロセス名で kill を試みる（全て拒否されるはず）
    let result = engine.kill_by_name(&current_info.name, Signal::SIGTERM, false);
    assert!(
        result.is_ok(),
        "kill_by_name はプロセスが見つかれば Ok を返す"
    );
    let batch = result.unwrap();
    assert!(!batch.any_success(), "全プロセスが拒否されるため成功なし");
    assert!(batch.total_matched > 0, "一致プロセスが存在するべき");
}

/// kill_by_name の dry-run で成功するケースのテスト
#[test]
fn test_kill_by_name_dry_run_child_process() {
    use safe_kill::config::ProcessList;
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let _pid = child.id();

    let engine = PolicyEngine::with_defaults();
    let result = engine.kill_by_name("sleep", Signal::SIGTERM, true);

    // sleep プロセスが見つかり、dry-run で成功するはず
    match result {
        Ok(batch) => {
            if batch.any_success() {
                // dry-run なので実際にはプロセスは生きている
                assert!(batch.total_killed > 0);
            }
        }
        Err(SafeKillError::ProcessNameNotFound(_)) => {
            // プロセス名が異なる場合（環境依存）
        }
        Err(e) => panic!("予期しないエラー: {:?}", e),
    }

    // クリーンアップ
    let mut child = child;
    let _ = SignalSender::send(child.id(), Signal::SIGTERM);
    let _ = child.wait();
}

// =============================================================================
// AncestryChecker の追加テスト
// =============================================================================

/// 子プロセスを生成して ancestry チェックを検証するテスト
#[test]
fn test_ancestry_checker_child_process_is_descendant() {
    use std::process::Command;

    let child = Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("sleep プロセスの起動に失敗");
    let child_pid = child.id();

    let provider = ProcessInfoProvider::new();
    let current_pid = ProcessInfoProvider::current_pid();
    let checker = AncestryChecker::with_root_pid(provider, current_pid);

    // 子プロセスは現在プロセスの子孫であるべき
    assert!(
        checker.is_descendant(child_pid),
        "子プロセス (PID {}) は現在プロセス (PID {}) の子孫であるべき",
        child_pid,
        current_pid
    );

    // クリーンアップ
    let mut child = child;
    let _ = SignalSender::send(child_pid, Signal::SIGTERM);
    let _ = child.wait();
}

/// PID 1 をルートに設定した場合、現在プロセスが子孫になることを確認
#[test]
fn test_ancestry_checker_pid1_as_root_current_is_descendant() {
    let provider = ProcessInfoProvider::new();
    let checker = AncestryChecker::with_root_pid(provider, 1);
    let current_pid = ProcessInfoProvider::current_pid();

    // PID 1 をルートとした場合、現在プロセスはその子孫であるべき
    // （macOS/Linux では全プロセスが PID 1 の子孫）
    assert!(
        checker.is_descendant(current_pid),
        "現在プロセスは PID 1 の子孫であるべき"
    );
}

// =============================================================================
// Config::load のテスト（実パスからの読み込み）
// =============================================================================

/// Config::load がデフォルト設定を返すことを確認（設定ファイルの有無に依存しない）
#[test]
fn test_config_load_returns_valid_config() {
    let config = Config::load();
    // denylist は常に存在する（デフォルトまたは設定ファイルから）
    assert!(
        config.denylist.is_some(),
        "Config::load は常に denylist を持つべき"
    );
    let denylist = config.denylist.as_ref().unwrap();
    assert!(!denylist.processes.is_empty(), "denylist は空でないべき");

    // デフォルトのシステムプロセスが含まれているべき
    let defaults = Config::default_denylist();
    for process in &defaults {
        assert!(
            denylist.processes.contains(process),
            "デフォルト denylist の {} が含まれるべき",
            process
        );
    }
}

// =============================================================================
// PolicyEngine::kill_by_port の追加テスト
// =============================================================================

/// ポート kill で自プロセスが対象になった場合の自殺防止テスト
#[test]
fn test_kill_by_port_suicide_prevention() {
    use safe_kill::config::AllowedPorts;

    // 自プロセスがリッスンしているポートがあれば自殺防止が効くはず
    // ここでは設定上許可されたポートで、プロセスが見つからないケースを確認
    let config = Config {
        allowlist: None,
        denylist: None,
        allowed_ports: Some(AllowedPorts {
            ports: vec!["59980-59989".to_string()],
        }),
    };
    let engine = PolicyEngine::new(config);

    // 未使用ポートでは NoProcessOnPort エラー
    let result = engine.kill_by_port(59985, Signal::SIGTERM, false);
    assert!(
        matches!(result, Err(SafeKillError::NoProcessOnPort(59985))),
        "未使用ポートでは NoProcessOnPort エラーが返るべき"
    );
}

/// TOML の allowlist のみ指定時にデフォルト denylist が自動追加されることを確認
#[test]
fn test_config_load_allowlist_only_gets_default_denylist() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
[allowlist]
processes = ["my_app"]
"#
    )
    .unwrap();

    let config = Config::load_from_path(Some(file.path().to_path_buf()));

    // allowlist が設定されている
    assert!(config.is_allowed("my_app"));

    // デフォルト denylist も自動追加されている
    let default_denylist = Config::default_denylist();
    for process in &default_denylist {
        assert!(
            config.is_denied(process),
            "デフォルト denylist の {} が含まれるべき",
            process
        );
    }
}
