//! Policy engine for safe-kill
//!
//! Coordinates kill permission checks using ancestry, config, and suicide prevention.

use crate::ancestry::AncestryChecker;
use crate::config::Config;
use crate::error::SafeKillError;
use crate::killer::{BatchKillResult, KillResult, ProcessKiller};
use crate::process_info::{ProcessInfo, ProcessInfoProvider};
use crate::signal::Signal;

/// Result of a kill permission check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillPermission {
    /// Kill is allowed (by ancestry check)
    Allowed,
    /// Kill is allowed (process is in allowlist)
    AllowedByAllowlist,
    /// Kill is denied (process is in denylist)
    DeniedByDenylist(String),
    /// Kill is denied (not a descendant of root)
    DeniedNotDescendant,
    /// Kill is denied (would kill self or parent)
    DeniedSuicidePrevention,
}

impl KillPermission {
    /// Check if the permission allows killing
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            KillPermission::Allowed | KillPermission::AllowedByAllowlist
        )
    }

    /// Check if the permission denies killing
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }
}

/// Policy engine that orchestrates kill permission checks
pub struct PolicyEngine {
    config: Config,
    ancestry: AncestryChecker,
    killer: ProcessKiller,
    provider: ProcessInfoProvider,
}

impl PolicyEngine {
    /// Create a new PolicyEngine with the given configuration
    pub fn new(config: Config) -> Self {
        let provider = ProcessInfoProvider::new();
        let ancestry = AncestryChecker::new(ProcessInfoProvider::new());
        let killer = ProcessKiller::new();

        Self {
            config,
            ancestry,
            killer,
            provider,
        }
    }

    /// Create a new PolicyEngine with default configuration
    pub fn with_defaults() -> Self {
        Self::new(Config::load())
    }

    /// Refresh process information
    pub fn refresh(&mut self) {
        self.provider.refresh();
        self.ancestry.refresh();
    }

    /// Check if a process can be killed
    pub fn can_kill(&self, process: &ProcessInfo) -> KillPermission {
        // 1. Check suicide prevention first (highest priority)
        if self.ancestry.is_suicide(process.pid) {
            return KillPermission::DeniedSuicidePrevention;
        }

        // 2. Check denylist (second highest priority)
        if self.config.is_denied(&process.name) {
            return KillPermission::DeniedByDenylist(process.name.clone());
        }

        // 3. Check allowlist (bypasses ancestry check)
        if self.config.is_allowed(&process.name) {
            return KillPermission::AllowedByAllowlist;
        }

        // 4. Check ancestry (default check)
        if self.ancestry.is_descendant(process.pid) {
            return KillPermission::Allowed;
        }

        KillPermission::DeniedNotDescendant
    }

    /// Kill a process by PID
    pub fn kill_by_pid(
        &self,
        pid: u32,
        signal: Signal,
        dry_run: bool,
    ) -> Result<KillResult, SafeKillError> {
        // Get process info
        let process = self
            .provider
            .get(pid)
            .ok_or(SafeKillError::ProcessNotFound(pid))?;

        // Check permission
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

    /// Kill processes by name
    pub fn kill_by_name(
        &self,
        name: &str,
        signal: Signal,
        dry_run: bool,
    ) -> Result<BatchKillResult, SafeKillError> {
        let processes = self.provider.find_by_name(name);

        if processes.is_empty() {
            return Err(SafeKillError::ProcessNotFound(0));
        }

        let mut batch_result = BatchKillResult::new();

        for process in processes {
            let permission = self.can_kill(&process);

            let result = if permission.is_allowed() {
                self.killer
                    .kill_with_result(process.pid, &process.name, signal, dry_run)
            } else {
                // Create a failure result for denied processes
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

    /// List all processes that can be killed
    pub fn list_killable(&self) -> Vec<ProcessInfo> {
        self.provider
            .all()
            .into_iter()
            .filter(|p| self.can_kill(p).is_allowed())
            .collect()
    }

    /// Get the current root PID
    pub fn root_pid(&self) -> u32 {
        self.ancestry.root_pid()
    }

    /// Get a reference to the configuration
    pub fn config(&self) -> &Config {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProcessList;

    // KillPermission tests
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

    // PolicyEngine construction tests
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
        // Should not panic
    }

    #[test]
    fn test_policy_engine_config() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["node".to_string()],
            }),
            denylist: None,
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.config().is_allowed("node"));
    }

    // can_kill tests
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
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "test_allowed_process".to_string(),
            cmd: vec![],
        };

        // Note: This will fail suicide check if it happens to be our PID
        // So we use a fake PID that's definitely not ours
        let permission = engine.can_kill(&process);
        assert_eq!(permission, KillPermission::AllowedByAllowlist);
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

    // kill_by_pid tests
    #[test]
    fn test_kill_by_pid_not_found() {
        let engine = PolicyEngine::with_defaults();
        let result = engine.kill_by_pid(999999999, Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::ProcessNotFound(_))));
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
        // Use dry_run on a non-existent process - should still fail because process not found
        let result = engine.kill_by_pid(999999999, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::ProcessNotFound(_))));
    }

    // kill_by_name tests
    #[test]
    fn test_kill_by_name_not_found() {
        let engine = PolicyEngine::with_defaults();
        let result = engine.kill_by_name("__nonexistent_process__", Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::ProcessNotFound(_))));
    }

    // list_killable tests
    #[test]
    fn test_list_killable() {
        let engine = PolicyEngine::with_defaults();
        let killable = engine.list_killable();

        // Should not contain current process
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(!killable.iter().any(|p| p.pid == current_pid));

        // Should not contain parent process
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

            // Should not contain launchd (in default denylist on macOS)
            assert!(!killable.iter().any(|p| p.name == "launchd"));
        }

        #[cfg(target_os = "linux")]
        {
            let engine = PolicyEngine::with_defaults();
            let killable = engine.list_killable();

            // Should not contain systemd (in default denylist on Linux)
            assert!(!killable.iter().any(|p| p.name == "systemd"));
        }
    }

    // Root PID tests
    #[test]
    fn test_root_pid() {
        let engine = PolicyEngine::with_defaults();
        let root_pid = engine.root_pid();
        assert!(root_pid > 0);
    }

    // Permission priority tests
    #[test]
    fn test_permission_priority_suicide_over_denylist() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["safe-kill".to_string()], // Add self to denylist
            }),
        };
        let engine = PolicyEngine::new(config);
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(process) = engine.provider.get(current_pid) {
            let permission = engine.can_kill(&process);
            // Suicide prevention should take precedence
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
}
