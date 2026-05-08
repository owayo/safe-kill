//! safe-kill のポリシーエンジン
//!
//! ancestry、config、自殺防止を組み合わせた kill 許可判定を統括する。

use crate::ancestry::AncestryChecker;
use crate::config::Config;
use crate::error::SafeKillError;
use crate::killer::{BatchKillResult, KillResult, ProcessKiller};
use crate::port::PortDetector;
use crate::process_info::{ProcessInfo, ProcessInfoProvider};
use crate::signal::Signal;

/// kill 許可判定の結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillPermission {
    /// kill 許可（ancestry チェックによる）
    Allowed,
    /// kill 許可（allowlist に含まれるプロセス）
    AllowedByAllowlist,
    /// kill 拒否（denylist に含まれるプロセス）
    DeniedByDenylist(String),
    /// kill 拒否（root の子孫ではない）
    DeniedNotDescendant,
    /// kill 拒否（自プロセスまたは親プロセスの kill）
    DeniedSuicidePrevention,
}

impl KillPermission {
    /// kill が許可されているかを確認する
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            KillPermission::Allowed | KillPermission::AllowedByAllowlist
        )
    }

    /// kill が拒否されているかを確認する
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }
}

/// kill 許可判定を統括するポリシーエンジン
pub struct PolicyEngine {
    config: Config,
    ancestry: AncestryChecker,
    killer: ProcessKiller,
    provider: ProcessInfoProvider,
    port_detector: PortDetector,
}

impl PolicyEngine {
    /// 指定された設定で PolicyEngine を生成する
    pub fn new(mut config: Config) -> Self {
        config.merge_defaults();

        let provider = ProcessInfoProvider::new();
        let ancestry = AncestryChecker::new(ProcessInfoProvider::new());
        let killer = ProcessKiller::new();
        let port_detector = PortDetector::new();

        Self {
            config,
            ancestry,
            killer,
            provider,
            port_detector,
        }
    }

    /// デフォルト設定で PolicyEngine を生成する
    pub fn with_defaults() -> Self {
        Self::new(Config::load())
    }

    /// 設定ファイルエラーを呼び出し元へ返して PolicyEngine を生成する
    pub fn try_with_defaults() -> Result<Self, SafeKillError> {
        Ok(Self::new(Config::try_load()?))
    }

    /// プロセス情報を更新する
    pub fn refresh(&mut self) {
        self.provider.refresh();
        self.ancestry.refresh();
        self.port_detector.refresh();
    }

    /// プロセスを kill 可能か判定する
    pub fn can_kill(&self, process: &ProcessInfo) -> KillPermission {
        // 1. 自殺防止チェック（最優先）
        if self.ancestry.is_suicide(process.pid) {
            return KillPermission::DeniedSuicidePrevention;
        }

        // 2. denylist チェック（2番目の優先度）
        if self.config.is_denied(&process.name) {
            return KillPermission::DeniedByDenylist(process.name.clone());
        }

        // 3. 信頼ルート自体は子孫プロセスではないため保護する
        if process.pid == self.ancestry.root_pid() {
            return KillPermission::DeniedNotDescendant;
        }

        // 4. allowlist チェック（ancestry チェックをバイパス）
        if self.config.is_allowed(&process.name) {
            return KillPermission::AllowedByAllowlist;
        }

        // 5. ancestry チェック（デフォルトのチェック）
        if self.ancestry.is_descendant(process.pid) {
            return KillPermission::Allowed;
        }

        KillPermission::DeniedNotDescendant
    }

    /// PID を指定してプロセスを kill する
    pub fn kill_by_pid(
        &self,
        pid: u32,
        signal: Signal,
        dry_run: bool,
    ) -> Result<KillResult, SafeKillError> {
        // PID 0 はプロセスグループを表し、i32 超過値は nix::Pid に安全に渡せない。
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(SafeKillError::InvalidPid(pid.to_string()));
        }

        // プロセス情報を取得
        let process = self
            .provider
            .get(pid)
            .ok_or(SafeKillError::ProcessNotFound(pid))?;

        // 許可判定
        match self.can_kill(&process) {
            KillPermission::Allowed | KillPermission::AllowedByAllowlist => Ok(self
                .killer
                .kill_with_result(pid, &process.name, signal, dry_run)),
            KillPermission::DeniedByDenylist(name) => Err(SafeKillError::Denylisted(name)),
            KillPermission::DeniedNotDescendant => {
                Err(SafeKillError::NotDescendant(pid, process.name))
            }
            KillPermission::DeniedSuicidePrevention => Err(SafeKillError::SuicidePrevention(pid)),
        }
    }

    /// プロセス名を指定して kill する
    pub fn kill_by_name(
        &self,
        name: &str,
        signal: Signal,
        dry_run: bool,
    ) -> Result<BatchKillResult, SafeKillError> {
        let processes = self.provider.find_by_name(name);

        if processes.is_empty() {
            return Err(SafeKillError::ProcessNameNotFound(name.to_string()));
        }

        let mut batch_result = BatchKillResult::new();

        for process in processes {
            let permission = self.can_kill(&process);

            let result = if permission.is_allowed() {
                self.killer
                    .kill_with_result(process.pid, &process.name, signal, dry_run)
            } else {
                // 拒否されたプロセスの失敗結果を生成
                let error = match permission {
                    KillPermission::DeniedByDenylist(ref name) => {
                        SafeKillError::Denylisted(name.clone())
                    }
                    KillPermission::DeniedNotDescendant => {
                        SafeKillError::NotDescendant(process.pid, process.name.clone())
                    }
                    KillPermission::DeniedSuicidePrevention => {
                        SafeKillError::SuicidePrevention(process.pid)
                    }
                    _ => SafeKillError::SystemError("Unexpected permission".to_string()),
                };
                KillResult::failure(process.pid, &process.name, &error)
            };

            batch_result.add(result);
        }

        Ok(batch_result)
    }

    /// ポートを指定してプロセスを kill する
    ///
    /// 注意: ancestry チェックは適用しない。denylist のみ適用される。
    /// ポート指定の kill はプロセスの ancestry に関係なく
    /// 特定のサービスを対象とするため。
    pub fn kill_by_port(
        &self,
        port: u16,
        signal: Signal,
        dry_run: bool,
    ) -> Result<BatchKillResult, SafeKillError> {
        // 1. config でポートが許可されているか確認
        self.config.check_port_allowed(port)?;

        // 2. ポート上のプロセスを検索
        let port_processes = self.port_detector.find_by_port(port)?;

        if port_processes.is_empty() {
            return Err(SafeKillError::NoProcessOnPort(port));
        }

        Ok(self.kill_port_processes(port_processes, signal, dry_run))
    }

    /// 検出済みの `PortProcess` 一覧から kill を実行する内部ヘルパー
    ///
    /// `kill_by_port` の中身を切り出してテスト容易性を高めるために存在する。
    /// 名前解決失敗時の fail-closed 挙動を直接検証できるようにする目的。
    fn kill_port_processes(
        &self,
        port_processes: Vec<crate::port::PortProcess>,
        signal: Signal,
        dry_run: bool,
    ) -> BatchKillResult {
        let mut batch_result = BatchKillResult::new();

        // 各プロセスに対して自殺防止と denylist チェックのみ適用
        for pp in port_processes {
            // プロセス情報が取得できない PID は denylist 名前一致を回避するために
            // 即座に失敗扱いにする（fail-closed）。
            // PortDetector のフォールバック名（"pid:<pid>"）で denylist 判定すると
            // 名前不明なプロセスがバイパスされてしまうため。
            let Some(process) = self.provider.get(pp.pid) else {
                let error = SafeKillError::ProcessNotFound(pp.pid);
                batch_result.add(KillResult::failure(pp.pid, &pp.name, &error));
                continue;
            };
            let process_name = process.name;

            // 許可判定（自殺防止と denylist のみ）
            let permission = self.can_kill_for_port(pp.pid, &process_name);

            let result = if permission.is_allowed() {
                self.killer
                    .kill_with_result(pp.pid, &process_name, signal, dry_run)
            } else {
                let error = match permission {
                    KillPermission::DeniedByDenylist(ref name) => {
                        SafeKillError::Denylisted(name.clone())
                    }
                    KillPermission::DeniedSuicidePrevention => {
                        SafeKillError::SuicidePrevention(pp.pid)
                    }
                    KillPermission::DeniedNotDescendant => {
                        SafeKillError::NotDescendant(pp.pid, process_name.clone())
                    }
                    _ => SafeKillError::SystemError("Unexpected permission".to_string()),
                };
                KillResult::failure(pp.pid, &process_name, &error)
            };

            batch_result.add(result);
        }

        batch_result
    }

    /// ポート指定 kill 用のプロセス kill 可否判定
    ///
    /// 以下の簡略化されたチェックのみ適用:
    /// 1. 自殺防止（自プロセス・親プロセスの kill 不可）
    /// 2. denylist チェック
    /// 3. root PID 保護（信頼ルート自体の kill 不可）
    ///
    /// ancestry 走査や allowlist は適用しない（ポート指定 kill 用）。
    fn can_kill_for_port(&self, pid: u32, name: &str) -> KillPermission {
        // 1. 自殺防止チェック（最優先）
        if self.ancestry.is_suicide(pid) {
            return KillPermission::DeniedSuicidePrevention;
        }

        // 2. denylist チェック
        if self.config.is_denied(name) {
            return KillPermission::DeniedByDenylist(name.to_string());
        }

        // 3. 信頼ルート自体はポート指定でも終了対象にしない
        if pid == self.ancestry.root_pid() {
            return KillPermission::DeniedNotDescendant;
        }

        // 拒否されなければポート指定 kill は許可
        KillPermission::Allowed
    }

    /// kill 可能な全プロセスを一覧する
    pub fn list_killable(&self) -> Vec<ProcessInfo> {
        self.provider
            .all()
            .into_iter()
            .filter(|p| self.can_kill(p).is_allowed())
            .collect()
    }

    /// 現在の root PID を取得する
    pub fn root_pid(&self) -> u32 {
        self.ancestry.root_pid()
    }

    /// 設定への参照を取得する
    pub fn config(&self) -> &Config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProcessList;

    // KillPermission のテスト
    #[test]
    fn test_kill_permission_allowed() {
        assert!(KillPermission::Allowed.is_allowed());
        assert!(!KillPermission::Allowed.is_denied());
    }

    #[test]
    fn test_kill_permission_allowed_by_allowlist() {
        assert!(KillPermission::AllowedByAllowlist.is_allowed());
        assert!(!KillPermission::AllowedByAllowlist.is_denied());
    }

    #[test]
    fn test_kill_permission_denied_by_denylist() {
        let perm = KillPermission::DeniedByDenylist("systemd".to_string());
        assert!(!perm.is_allowed());
        assert!(perm.is_denied());
    }

    #[test]
    fn test_kill_permission_denied_not_descendant() {
        assert!(!KillPermission::DeniedNotDescendant.is_allowed());
        assert!(KillPermission::DeniedNotDescendant.is_denied());
    }

    #[test]
    fn test_kill_permission_denied_suicide() {
        assert!(!KillPermission::DeniedSuicidePrevention.is_allowed());
        assert!(KillPermission::DeniedSuicidePrevention.is_denied());
    }

    #[test]
    fn test_kill_permission_clone() {
        let perm = KillPermission::Allowed;
        let cloned = perm.clone();
        assert_eq!(perm, cloned);
    }

    #[test]
    fn test_kill_permission_debug() {
        let perm = KillPermission::Allowed;
        let debug_str = format!("{:?}", perm);
        assert!(debug_str.contains("Allowed"));
    }

    // PolicyEngine 構築テスト
    #[test]
    fn test_policy_engine_new() {
        let config = Config::default();
        let engine = PolicyEngine::new(config);
        assert!(engine.root_pid() > 0);
    }

    #[test]
    fn test_policy_engine_with_defaults() {
        let engine = PolicyEngine::with_defaults();
        assert!(engine.root_pid() > 0);
    }

    #[test]
    fn test_policy_engine_refresh() {
        let config = Config::default();
        let mut engine = PolicyEngine::new(config);
        engine.refresh();
        // パニックしないことを確認
    }

    #[test]
    fn test_policy_engine_config() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["node".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.config().is_allowed("node"));
    }

    #[test]
    fn test_policy_engine_new_merges_default_denylist() {
        let engine = PolicyEngine::new(Config::default());

        for process in Config::default_denylist() {
            assert!(
                engine.config().is_denied(&process),
                "デフォルト denylist の {process} が PolicyEngine::new で合流されるべき"
            );
        }
    }

    fn engine_with_root_pid(mut config: Config, root_pid: u32) -> PolicyEngine {
        config.merge_defaults();

        PolicyEngine {
            config,
            ancestry: AncestryChecker::with_root_pid(ProcessInfoProvider::new(), root_pid),
            killer: ProcessKiller::new(),
            provider: ProcessInfoProvider::new(),
            port_detector: PortDetector::new(),
        }
    }

    // can_kill のテスト
    #[test]
    fn test_can_kill_self_denied() {
        let engine = PolicyEngine::with_defaults();
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(process) = engine.provider.get(current_pid) {
            let permission = engine.can_kill(&process);
            assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
        }
    }

    #[test]
    fn test_can_kill_parent_denied() {
        let engine = PolicyEngine::with_defaults();
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(current) = engine.provider.get(current_pid) {
            if let Some(parent_pid) = current.parent_pid {
                if let Some(parent) = engine.provider.get(parent_pid) {
                    let permission = engine.can_kill(&parent);
                    assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
                }
            }
        }
    }

    #[test]
    fn test_can_kill_denylisted() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["test_denied_process".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "test_denied_process".to_string(),
            cmd: vec![],
        };

        match engine.can_kill(&process) {
            KillPermission::DeniedByDenylist(name) => {
                assert_eq!(name, "test_denied_process");
            }
            _ => panic!("Expected DeniedByDenylist"),
        }
    }

    #[test]
    fn test_can_kill_allowlisted() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["test_allowed_process".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "test_allowed_process".to_string(),
            cmd: vec![],
        };

        // 自プロセスの PID だと自殺防止チェックに引っかかるため
        // 確実に自プロセスではない偽の PID を使用
        let permission = engine.can_kill(&process);
        assert_eq!(permission, KillPermission::AllowedByAllowlist);
    }

    #[test]
    fn test_can_kill_root_pid_denied_before_allowlist() {
        let root_pid = ProcessInfoProvider::current_pid().saturating_add(100_000);
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["trusted_root".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = engine_with_root_pid(config, root_pid);

        let process = ProcessInfo {
            pid: root_pid,
            parent_pid: None,
            name: "trusted_root".to_string(),
            cmd: vec![],
        };

        // root PID は信頼境界であり、allowlist でも終了対象にしない。
        let permission = engine.can_kill(&process);
        assert_eq!(permission, KillPermission::DeniedNotDescendant);
    }

    #[test]
    fn test_denylist_takes_precedence_over_allowlist() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["conflicted_process".to_string()],
            }),
            denylist: Some(ProcessList {
                processes: vec!["conflicted_process".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "conflicted_process".to_string(),
            cmd: vec![],
        };

        match engine.can_kill(&process) {
            KillPermission::DeniedByDenylist(_) => {}
            other => panic!("Expected DeniedByDenylist, got {:?}", other),
        }
    }

    // kill_by_pid のテスト
    #[test]
    fn test_kill_by_pid_not_found() {
        let engine = PolicyEngine::with_defaults();
        let result = engine.kill_by_pid(999999999, Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::ProcessNotFound(_))));
    }

    #[test]
    fn test_kill_by_pid_zero_rejected_as_invalid() {
        let engine = PolicyEngine::with_defaults();
        let result = engine.kill_by_pid(0, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::InvalidPid(_))));
    }

    #[test]
    fn test_kill_by_pid_over_i32_max_rejected_as_invalid() {
        let engine = PolicyEngine::with_defaults();
        let result = engine.kill_by_pid(i32::MAX as u32 + 1, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::InvalidPid(_))));
    }

    #[test]
    fn test_kill_by_pid_self_prevented() {
        let engine = PolicyEngine::with_defaults();
        let current_pid = ProcessInfoProvider::current_pid();
        let result = engine.kill_by_pid(current_pid, Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::SuicidePrevention(_))));
    }

    #[test]
    fn test_kill_by_pid_dry_run() {
        let engine = PolicyEngine::with_defaults();
        // 存在しないプロセスに dry_run を使用 - プロセス未検出で失敗するはず
        let result = engine.kill_by_pid(999999999, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::ProcessNotFound(_))));
    }

    // kill_by_name のテスト
    #[test]
    fn test_kill_by_name_not_found() {
        let engine = PolicyEngine::with_defaults();
        let result = engine.kill_by_name("__nonexistent_process__", Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::ProcessNameNotFound(_))));
    }

    // list_killable のテスト
    #[test]
    fn test_list_killable() {
        let engine = PolicyEngine::with_defaults();
        let killable = engine.list_killable();

        // 自プロセスを含まないこと
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(!killable.iter().any(|p| p.pid == current_pid));

        // 親プロセスを含まないこと
        if let Some(current) = engine.provider.get(current_pid) {
            if let Some(parent_pid) = current.parent_pid {
                assert!(!killable.iter().any(|p| p.pid == parent_pid));
            }
        }
    }

    #[test]
    fn test_list_killable_excludes_denylisted() {
        #[cfg(target_os = "macos")]
        {
            let engine = PolicyEngine::with_defaults();
            let killable = engine.list_killable();

            // launchd を含まないこと（macOS のデフォルト denylist に含まれる）
            assert!(!killable.iter().any(|p| p.name == "launchd"));
        }

        #[cfg(target_os = "linux")]
        {
            let engine = PolicyEngine::with_defaults();
            let killable = engine.list_killable();

            // systemd を含まないこと（Linux のデフォルト denylist に含まれる）
            assert!(!killable.iter().any(|p| p.name == "systemd"));
        }
    }

    // root PID のテスト
    #[test]
    fn test_root_pid() {
        let engine = PolicyEngine::with_defaults();
        let root_pid = engine.root_pid();
        assert!(root_pid > 0);
    }

    // 許可優先順位のテスト
    #[test]
    fn test_permission_priority_suicide_over_denylist() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["safe-kill".to_string()], // 自プロセスを denylist に追加
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(process) = engine.provider.get(current_pid) {
            let permission = engine.can_kill(&process);
            // 自殺防止が優先されるべき
            assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
        }
    }

    #[test]
    fn test_permission_priority_denylist_over_allowlist() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["both_listed".to_string()],
            }),
            denylist: Some(ProcessList {
                processes: vec!["both_listed".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "both_listed".to_string(),
            cmd: vec![],
        };

        match engine.can_kill(&process) {
            KillPermission::DeniedByDenylist(_) => {}
            other => panic!("Expected DeniedByDenylist, got {:?}", other),
        }
    }

    // kill_by_port のテスト
    #[test]
    fn test_kill_by_port_no_process() {
        use crate::config::AllowedPorts;

        // 明示的な allowed_ports 設定（None はポート kill 無効を意味する）
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3010".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);
        // ポート 3009 は許可されているがプロセスが存在しない
        let result = engine.kill_by_port(3009, Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::NoProcessOnPort(3009))));
    }

    #[test]
    fn test_kill_by_port_no_config_disabled() {
        // allowed_ports が None の場合、ポート kill は完全に無効
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        // config が None の場合、すべてのポートで PortNotAllowed を返す
        let result = engine.kill_by_port(3000, Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::PortNotAllowed { .. })));
    }

    #[test]
    fn test_kill_by_port_port_not_allowed() {
        use crate::config::AllowedPorts;

        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000".to_string(), "8080".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);

        // ポート 59996 は許可リストに含まれていない
        let result = engine.kill_by_port(59996, Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::PortNotAllowed { .. })));
    }

    #[test]
    fn test_kill_by_port_with_allowed_config() {
        use crate::config::AllowedPorts;

        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["59995".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);

        // ポート 59995 は許可されているがプロセスが存在しない
        let result = engine.kill_by_port(59995, Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::NoProcessOnPort(59995))));
    }

    #[test]
    fn test_kill_by_port_dry_run_no_process() {
        use crate::config::AllowedPorts;

        // 明示的な allowed_ports 設定（None はポート kill 無効を意味する）
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3010".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);
        // dry_run でもプロセスの存在チェックは行われる
        let result = engine.kill_by_port(3008, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::NoProcessOnPort(3008))));
    }

    // can_kill_for_port のテスト
    #[test]
    fn test_can_kill_for_port_allowed() {
        let engine = PolicyEngine::with_defaults();
        // 自プロセスでも denylist にも含まれないランダムな PID
        let permission = engine.can_kill_for_port(99999, "random_process");
        assert_eq!(permission, KillPermission::Allowed);
    }

    #[test]
    fn test_can_kill_for_port_suicide_prevention() {
        let engine = PolicyEngine::with_defaults();
        let current_pid = ProcessInfoProvider::current_pid();
        let permission = engine.can_kill_for_port(current_pid, "safe-kill");
        assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
    }

    #[test]
    fn test_can_kill_for_port_denylisted() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["denylisted_server".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let permission = engine.can_kill_for_port(99999, "denylisted_server");
        match permission {
            KillPermission::DeniedByDenylist(name) => {
                assert_eq!(name, "denylisted_server");
            }
            other => panic!("Expected DeniedByDenylist, got {:?}", other),
        }
    }

    #[test]
    fn test_can_kill_for_port_root_pid_denied() {
        let root_pid = ProcessInfoProvider::current_pid().saturating_add(100_000);
        let engine = engine_with_root_pid(Config::default(), root_pid);

        let permission = engine.can_kill_for_port(root_pid, "trusted_root");
        assert_eq!(permission, KillPermission::DeniedNotDescendant);
    }

    #[test]
    fn test_can_kill_for_port_no_ancestor_check() {
        // can_kill_for_port が ancestry チェックを行わないことを検証
        // 設計上の意図: ポート指定 kill は ancestry 走査を適用しない
        let engine = PolicyEngine::with_defaults();

        // 確実に子孫ではないランダムなプロセス
        // denylist に含まれていなければ許可されるべき
        // 注意: macOS では "launchd" がデフォルト denylist に含まれる可能性がある
        // そのためこのテストでは汎用的な名前を使用
        let permission = engine.can_kill_for_port(99999, "some_random_server");
        assert_eq!(permission, KillPermission::Allowed);
    }

    #[test]
    fn test_can_kill_non_descendant_process() {
        let engine = PolicyEngine::with_defaults();
        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "unrelated_process".to_string(),
            cmd: vec![],
        };
        let permission = engine.can_kill(&process);
        // allowlist に含まれず、子孫でもない -> DeniedNotDescendant
        assert_eq!(permission, KillPermission::DeniedNotDescendant);
    }

    #[test]
    fn test_kill_by_pid_not_descendant() {
        // PID 1 は通常のセッションの子孫にはなり得ない
        let engine = PolicyEngine::with_defaults();
        let result = engine.kill_by_pid(1, Signal::SIGTERM, false);
        assert!(result.is_err());
        // DeniedByDenylist（launchd/systemd が denylist に含まれる）または SuicidePrevention の可能性
        match result {
            Err(SafeKillError::Denylisted(_))
            | Err(SafeKillError::SuicidePrevention(_))
            | Err(SafeKillError::NotDescendant(_, _)) => {}
            other => panic!("Expected denial error, got {:?}", other),
        }
    }

    #[test]
    fn test_can_kill_for_port_suicide_prevention_parent() {
        let engine = PolicyEngine::with_defaults();
        let current_pid = ProcessInfoProvider::current_pid();
        if let Some(current) = engine.provider.get(current_pid) {
            if let Some(parent_pid) = current.parent_pid {
                let permission = engine.can_kill_for_port(parent_pid, "parent_process");
                assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
            }
        }
    }

    #[test]
    fn test_can_kill_for_port_ignores_allowlist() {
        // allowlist に含まれていても、can_kill_for_port は AllowedByAllowlist を返さない
        // （ポート kill では allowlist バイパスは適用しない設計）
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["allowlisted_server".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        // allowlist に含まれるプロセスでも、Allowed（AllowedByAllowlist ではない）が返る
        let permission = engine.can_kill_for_port(99999, "allowlisted_server");
        assert_eq!(
            permission,
            KillPermission::Allowed,
            "can_kill_for_port は AllowedByAllowlist ではなく Allowed を返すべき"
        );
    }

    #[test]
    fn test_batch_result_error_multiple_policy_errors_only() {
        // 全てポリシーエラー（NotDescendant）のみの場合、NoKillableTarget にフォールバック
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::failure(
            100,
            "proc_a",
            &SafeKillError::NotDescendant(100, "proc_a".to_string()),
        ));
        batch.add(KillResult::failure(
            200,
            "proc_b",
            &SafeKillError::NotDescendant(200, "proc_b".to_string()),
        ));

        // first_operational_error は NotDescendant をスキップするため None
        assert!(batch.first_operational_error().is_none());
    }

    #[test]
    fn test_kill_permission_eq_variants() {
        // 異なる DeniedByDenylist インスタンス間の等値性を検証
        let a = KillPermission::DeniedByDenylist("proc_a".to_string());
        let b = KillPermission::DeniedByDenylist("proc_a".to_string());
        let c = KillPermission::DeniedByDenylist("proc_b".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_list_killable_excludes_root_pid() {
        // 信頼ルート PID 自体は子孫扱いされず、kill 可能リストに含まれてはならない。
        let engine = PolicyEngine::with_defaults();
        let root_pid = engine.root_pid();
        let killable = engine.list_killable();
        assert!(
            !killable.iter().any(|p| p.pid == root_pid),
            "root PID ({}) は kill 可能リストから除外されるべき",
            root_pid
        );
    }

    #[test]
    fn test_can_kill_root_pid_with_default_engine() {
        // デフォルト設定のエンジンでも、root PID 自体への kill は拒否される。
        let engine = PolicyEngine::with_defaults();
        let root_pid = engine.root_pid();

        // root PID のプロセス情報が取得できる場合のみ検証（環境依存）
        if let Some(process) = engine.provider.get(root_pid) {
            let permission = engine.can_kill(&process);
            assert!(
                permission.is_denied(),
                "root PID ({}) は kill 拒否されるべき",
                root_pid
            );
        }
    }

    #[test]
    fn test_kill_by_pid_i32_max_boundary() {
        // i32::MAX は有効な PID 範囲だが、対応するプロセスが存在しないため
        // InvalidPid ではなく ProcessNotFound が返るべき。
        let engine = PolicyEngine::with_defaults();
        let result = engine.kill_by_pid(i32::MAX as u32, Signal::SIGTERM, true);
        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(_))),
            "i32::MAX は有効な PID 値だが対応プロセスが存在しないため ProcessNotFound になるべき"
        );
    }

    // ポート指定 kill の名前解決失敗時 fail-closed 回帰テスト
    //
    // 過去のバグ: PortDetector のフォールバック名 "pid:<pid>" を denylist
    // 判定に使うと、名前不明なプロセスが denylist 保護をバイパスしていた。
    // 今後のリグレッションを防ぐため、フォールバック名のままでは絶対に
    // 許可判定に到達しないことを検証する。
    #[test]
    fn test_kill_port_processes_unknown_pid_fails_closed() {
        use crate::port::{PortProcess, PortProtocol};

        // 存在しない可能性が極めて高い PID
        let unknown_pid = 999_999_999u32;
        let placeholder_name = format!("pid:{}", unknown_pid);

        // この placeholder を denylist に登録しても、ロジック上 denylist チェックに
        // 到達せず ProcessNotFound として失敗するべき。
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec![placeholder_name.clone()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let port_processes = vec![PortProcess {
            pid: unknown_pid,
            name: placeholder_name.clone(),
            port: 3000,
            protocol: PortProtocol::Tcp,
        }];

        let batch = engine.kill_port_processes(port_processes, Signal::SIGTERM, true);

        assert_eq!(batch.results.len(), 1);
        assert!(!batch.results[0].success);
        assert_eq!(
            batch.results[0].error,
            Some(SafeKillError::ProcessNotFound(unknown_pid)),
            "名前解決できない PID は ProcessNotFound で fail-closed されるべき (denylist バイパス防止)"
        );
        assert_eq!(
            batch.results[0].name, placeholder_name,
            "表示名としてはフォールバック名がそのまま残るべき"
        );
    }

    #[test]
    fn test_kill_port_processes_unknown_pid_does_not_match_real_denylist() {
        use crate::port::{PortProcess, PortProtocol};

        // フォールバック名で denylist 一致した場合に Denylisted エラーが返る
        // 経路を完全に塞いだことを検証する。
        let unknown_pid = 999_999_998u32;
        let placeholder_name = format!("pid:{}", unknown_pid);

        // フォールバック名と「実プロセス名らしき名前」両方を denylist に入れる
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec![placeholder_name.clone(), "denied_proc".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let port_processes = vec![PortProcess {
            pid: unknown_pid,
            name: placeholder_name.clone(),
            port: 3000,
            protocol: PortProtocol::Tcp,
        }];

        let batch = engine.kill_port_processes(port_processes, Signal::SIGTERM, true);

        // ProcessNotFound で fail-closed されるため、Denylisted エラーには
        // ならないことを確認（denylist 判定そのものに到達してはならない）。
        assert!(
            !matches!(batch.results[0].error, Some(SafeKillError::Denylisted(_))),
            "プレースホルダ名で denylist 判定に到達してはならない"
        );
        assert_eq!(
            batch.results[0].error,
            Some(SafeKillError::ProcessNotFound(unknown_pid))
        );
    }
}
