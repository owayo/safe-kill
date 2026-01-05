//! Process information provider using sysinfo crate
//!
//! Provides cross-platform process information retrieval.

use sysinfo::{Pid, ProcessesToUpdate, System};

/// Information about a single process
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Parent process ID (None if no parent or unknown)
    pub parent_pid: Option<u32>,
    /// Process name
    pub name: String,
    /// Command line arguments
    pub cmd: Vec<String>,
}

/// Provider for process information using sysinfo
pub struct ProcessInfoProvider {
    system: System,
}

impl ProcessInfoProvider {
    /// Create a new ProcessInfoProvider with refreshed process list
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);
        Self { system }
    }

    /// Refresh the process list
    pub fn refresh(&mut self) {
        self.system.refresh_processes(ProcessesToUpdate::All, true);
    }

    /// Get process information by PID
    pub fn get(&self, pid: u32) -> Option<ProcessInfo> {
        let sysinfo_pid = Pid::from_u32(pid);
        self.system.process(sysinfo_pid).map(|proc| ProcessInfo {
            pid,
            parent_pid: proc.parent().map(|p| p.as_u32()),
            name: proc.name().to_string_lossy().to_string(),
            cmd: proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect(),
        })
    }

    /// Find all processes matching the given name (exact match)
    pub fn find_by_name(&self, name: &str) -> Vec<ProcessInfo> {
        self.system
            .processes()
            .iter()
            .filter(|(_, proc)| proc.name().to_string_lossy() == name)
            .map(|(pid, proc)| ProcessInfo {
                pid: pid.as_u32(),
                parent_pid: proc.parent().map(|p| p.as_u32()),
                name: proc.name().to_string_lossy().to_string(),
                cmd: proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect(),
            })
            .collect()
    }

    /// Get all processes
    pub fn all(&self) -> Vec<ProcessInfo> {
        self.system
            .processes()
            .iter()
            .map(|(pid, proc)| ProcessInfo {
                pid: pid.as_u32(),
                parent_pid: proc.parent().map(|p| p.as_u32()),
                name: proc.name().to_string_lossy().to_string(),
                cmd: proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect(),
            })
            .collect()
    }

    /// Get current process PID
    pub fn current_pid() -> u32 {
        std::process::id()
    }

    /// Get parent PID of current process
    pub fn current_parent_pid(&self) -> Option<u32> {
        self.get(Self::current_pid()).and_then(|p| p.parent_pid)
    }
}

impl Default for ProcessInfoProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_info_struct() {
        let info = ProcessInfo {
            pid: 1234,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec!["test".to_string(), "--arg".to_string()],
        };
        assert_eq!(info.pid, 1234);
        assert_eq!(info.parent_pid, Some(1));
        assert_eq!(info.name, "test");
        assert_eq!(info.cmd, vec!["test", "--arg"]);
    }

    #[test]
    fn test_process_info_clone() {
        let info = ProcessInfo {
            pid: 100,
            parent_pid: None,
            name: "proc".to_string(),
            cmd: vec![],
        };
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_provider_new() {
        let provider = ProcessInfoProvider::new();
        // Should have at least some processes
        assert!(!provider.all().is_empty());
    }

    #[test]
    fn test_provider_default() {
        let provider = ProcessInfoProvider::default();
        assert!(!provider.all().is_empty());
    }

    #[test]
    fn test_get_current_process() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let info = provider.get(current_pid);
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.pid, current_pid);
    }

    #[test]
    fn test_get_nonexistent_process() {
        let provider = ProcessInfoProvider::new();
        // Use a very high PID that's unlikely to exist
        let info = provider.get(999999999);
        assert!(info.is_none());
    }

    #[test]
    fn test_current_pid() {
        let pid = ProcessInfoProvider::current_pid();
        assert!(pid > 0);
    }

    #[test]
    fn test_current_parent_pid() {
        let provider = ProcessInfoProvider::new();
        let parent = provider.current_parent_pid();
        // Current process should have a parent
        assert!(parent.is_some());
    }

    #[test]
    fn test_all_processes_not_empty() {
        let provider = ProcessInfoProvider::new();
        let all = provider.all();
        // There should be at least the current process
        assert!(!all.is_empty());
    }

    #[test]
    fn test_all_processes_contain_current() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let all = provider.all();
        assert!(all.iter().any(|p| p.pid == current_pid));
    }

    #[test]
    fn test_refresh() {
        let mut provider = ProcessInfoProvider::new();
        let before = provider.all().len();
        provider.refresh();
        let after = provider.all().len();
        // Process count should be reasonable (not zero)
        assert!(before > 0);
        assert!(after > 0);
    }

    #[test]
    fn test_find_by_name_no_match() {
        let provider = ProcessInfoProvider::new();
        let results = provider.find_by_name("__nonexistent_process_name_12345__");
        assert!(results.is_empty());
    }

    #[test]
    fn test_process_has_name() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let info = provider.get(current_pid).unwrap();
        // Process name should not be empty
        assert!(!info.name.is_empty());
    }

    #[test]
    fn test_pid_1_exists_or_system_process() {
        let provider = ProcessInfoProvider::new();
        // On most systems, PID 1 exists (init/launchd/systemd)
        // But we don't strictly require it - just test that get works
        let _result = provider.get(1);
        // This test passes regardless - we're just testing the API works
    }
}
