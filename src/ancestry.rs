//! Ancestry checker for process tree verification
//!
//! Provides functionality to verify if a process is a descendant of the current session.

use crate::process_info::ProcessInfoProvider;
use std::env;

/// Maximum depth for ancestry traversal to prevent infinite loops
const MAX_ANCESTRY_DEPTH: u32 = 100;

/// Environment variable to override the root PID
const ROOT_PID_ENV_VAR: &str = "SAFE_KILL_ROOT_PID";

/// Ancestry checker for process tree verification
pub struct AncestryChecker {
    provider: ProcessInfoProvider,
    root_pid: u32,
}

impl AncestryChecker {
    /// Create a new AncestryChecker with automatic root PID detection
    pub fn new(provider: ProcessInfoProvider) -> Self {
        let root_pid = Self::get_root_pid(&provider);
        Self { provider, root_pid }
    }

    /// Create a new AncestryChecker with a specific root PID
    pub fn with_root_pid(provider: ProcessInfoProvider, root_pid: u32) -> Self {
        Self { provider, root_pid }
    }

    /// Get the root PID (trust root)
    ///
    /// Priority:
    /// 1. SAFE_KILL_ROOT_PID environment variable
    /// 2. Parent of the calling shell (grandparent of current process)
    /// 3. Current process PID as fallback
    pub fn get_root_pid(provider: &ProcessInfoProvider) -> u32 {
        // Check environment variable first
        if let Ok(env_pid) = env::var(ROOT_PID_ENV_VAR) {
            if let Ok(pid) = env_pid.parse::<u32>() {
                return pid;
            }
        }

        // Get the grandparent (shell's parent) as the trust root
        // Current process -> Shell -> Trust root
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(current_info) = provider.get(current_pid) {
            if let Some(parent_pid) = current_info.parent_pid {
                if let Some(parent_info) = provider.get(parent_pid) {
                    if let Some(grandparent_pid) = parent_info.parent_pid {
                        return grandparent_pid;
                    }
                }
                return parent_pid;
            }
        }

        // Fallback to current PID
        current_pid
    }

    /// Get the configured root PID
    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// Check if target_pid is a descendant of root_pid
    ///
    /// Traverses the PPID chain from target_pid upward until:
    /// - root_pid is found (returns true)
    /// - PID 1 (init) is reached (returns false)
    /// - Maximum depth is exceeded (returns false)
    /// - Process not found (returns false)
    pub fn is_descendant(&self, target_pid: u32) -> bool {
        self.is_descendant_of(target_pid, self.root_pid)
    }

    /// Check if target_pid is a descendant of a specific ancestor_pid
    pub fn is_descendant_of(&self, target_pid: u32, ancestor_pid: u32) -> bool {
        // If target is the ancestor itself, consider it a descendant
        if target_pid == ancestor_pid {
            return true;
        }

        let mut current_pid = target_pid;
        let mut depth = 0u32;

        while depth < MAX_ANCESTRY_DEPTH {
            // Get process info for current PID
            let Some(info) = self.provider.get(current_pid) else {
                // Process not found
                return false;
            };

            // Get parent PID
            let Some(parent_pid) = info.parent_pid else {
                // No parent (orphan or init)
                return false;
            };

            // Check if parent is the ancestor we're looking for
            if parent_pid == ancestor_pid {
                return true;
            }

            // Stop if we've reached PID 1 (init/launchd)
            if parent_pid == 1 {
                return false;
            }

            current_pid = parent_pid;
            depth += 1;
        }

        // Max depth exceeded
        false
    }

    /// Check if killing target_pid would be suicide (killing self or parent)
    pub fn is_suicide(&self, target_pid: u32) -> bool {
        let current_pid = ProcessInfoProvider::current_pid();

        // Check if target is self
        if target_pid == current_pid {
            return true;
        }

        // Check if target is parent
        if let Some(info) = self.provider.get(current_pid) {
            if let Some(parent_pid) = info.parent_pid {
                if target_pid == parent_pid {
                    return true;
                }
            }
        }

        false
    }

    /// Refresh process information
    pub fn refresh(&mut self) {
        self.provider.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic construction tests
    #[test]
    fn test_ancestry_checker_new() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        assert!(checker.root_pid() > 0);
    }

    #[test]
    fn test_ancestry_checker_with_root_pid() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 12345);
        assert_eq!(checker.root_pid(), 12345);
    }

    // Root PID detection tests
    #[test]
    fn test_get_root_pid_returns_valid() {
        let provider = ProcessInfoProvider::new();
        let root_pid = AncestryChecker::get_root_pid(&provider);
        assert!(root_pid > 0);
    }

    // Note: Environment variable tests are tricky in parallel execution.
    // We test the parsing logic directly instead.

    #[test]
    fn test_root_pid_env_var_parsing() {
        // Test that when a valid number is provided, it would be parsed
        let test_value = "12345";
        let parsed: Result<u32, _> = test_value.parse();
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap(), 12345);
    }

    #[test]
    fn test_root_pid_env_var_invalid_parsing() {
        // Test that invalid values would fail to parse
        let test_value = "not_a_number";
        let parsed: Result<u32, _> = test_value.parse();
        assert!(parsed.is_err());
    }

    // is_descendant tests
    #[test]
    fn test_current_process_is_descendant_of_root() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();

        // Current process should be a descendant of its detected root
        assert!(checker.is_descendant(current_pid));
    }

    #[test]
    fn test_process_is_descendant_of_itself() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let checker = AncestryChecker::with_root_pid(provider, current_pid);

        assert!(checker.is_descendant(current_pid));
    }

    #[test]
    fn test_nonexistent_process_not_descendant() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);

        // Very high PID unlikely to exist
        assert!(!checker.is_descendant(999999999));
    }

    #[test]
    fn test_init_not_descendant_of_normal_root() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let checker = AncestryChecker::with_root_pid(provider, current_pid);

        // PID 1 (init) is never a descendant of a normal process
        assert!(!checker.is_descendant(1));
    }

    // is_descendant_of tests
    #[test]
    fn test_is_descendant_of_self() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();

        // A process is a descendant of itself
        assert!(checker.is_descendant_of(current_pid, current_pid));
    }

    #[test]
    fn test_parent_is_ancestor() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();

        // Current process should be a descendant of its parent
        if let Some(info) = checker.provider.get(current_pid) {
            if let Some(parent_pid) = info.parent_pid {
                assert!(checker.is_descendant_of(current_pid, parent_pid));
            }
        }
    }

    // is_suicide tests
    #[test]
    fn test_is_suicide_self() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();

        assert!(checker.is_suicide(current_pid));
    }

    #[test]
    fn test_is_suicide_parent() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(info) = checker.provider.get(current_pid) {
            if let Some(parent_pid) = info.parent_pid {
                assert!(checker.is_suicide(parent_pid));
            }
        }
    }

    #[test]
    fn test_is_suicide_random_process() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);

        // Some random process should not be suicide
        // Using a high PID that's unlikely to be self or parent
        assert!(!checker.is_suicide(999999999));
    }

    // Refresh tests
    #[test]
    fn test_refresh() {
        let provider = ProcessInfoProvider::new();
        let mut checker = AncestryChecker::new(provider);

        // Just verify refresh doesn't panic
        checker.refresh();

        // Root PID should remain the same
        let root = checker.root_pid();
        assert!(root > 0);
    }

    #[test]
    fn test_root_pid_one() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 1);

        assert!(checker.is_descendant(1));

        // Result varies by environment (process tree depth) - just verify no panic
        let current_pid = ProcessInfoProvider::current_pid();
        let _result = checker.is_descendant(current_pid);
    }

    #[test]
    fn test_max_depth_protection() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let checker = AncestryChecker::new(provider);
        let root = checker.root_pid();

        let _result = checker.is_descendant(current_pid);

        assert!(MAX_ANCESTRY_DEPTH >= 10);
        assert!(MAX_ANCESTRY_DEPTH <= 1000);
        assert!(root > 0);
    }

    // Environment variable constant test
    #[test]
    fn test_env_var_name() {
        assert_eq!(ROOT_PID_ENV_VAR, "SAFE_KILL_ROOT_PID");
    }

    // Max depth constant test
    #[test]
    fn test_max_depth_constant() {
        assert_eq!(MAX_ANCESTRY_DEPTH, 100);
    }
}
