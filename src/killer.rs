//! Process killer for safe-kill
//!
//! Handles the actual process termination after safety checks have passed.

use crate::error::SafeKillError;
use crate::signal::{Signal, SignalSender};

/// Result of a kill operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillResult {
    /// Target process ID
    pub pid: u32,
    /// Process name (if known)
    pub name: String,
    /// Whether the operation succeeded
    pub success: bool,
    /// Detailed message about the result
    pub message: String,
}

impl KillResult {
    /// Create a successful kill result
    pub fn success(pid: u32, name: impl Into<String>, signal: Signal) -> Self {
        Self {
            pid,
            name: name.into(),
            success: true,
            message: format!("Sent {} to process", signal.name()),
        }
    }

    /// Create a failed kill result
    pub fn failure(pid: u32, name: impl Into<String>, error: &SafeKillError) -> Self {
        Self {
            pid,
            name: name.into(),
            success: false,
            message: error.to_string(),
        }
    }

    /// Create a dry-run result
    pub fn dry_run(pid: u32, name: impl Into<String>, signal: Signal) -> Self {
        Self {
            pid,
            name: name.into(),
            success: true,
            message: format!("Would send {} to process (dry run)", signal.name()),
        }
    }
}

/// Result of a batch kill operation
#[derive(Debug, Clone, Default)]
pub struct BatchKillResult {
    /// Individual results for each process
    pub results: Vec<KillResult>,
    /// Total number of processes matched
    pub total_matched: usize,
    /// Total number of processes successfully killed
    pub total_killed: usize,
}

impl BatchKillResult {
    /// Create a new empty batch result
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a result to the batch
    pub fn add(&mut self, result: KillResult) {
        if result.success {
            self.total_killed += 1;
        }
        self.total_matched += 1;
        self.results.push(result);
    }

    /// Check if all operations succeeded
    pub fn all_success(&self) -> bool {
        self.total_matched > 0 && self.total_killed == self.total_matched
    }

    /// Check if any operations succeeded
    pub fn any_success(&self) -> bool {
        self.total_killed > 0
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

/// Process killer that sends signals to processes
pub struct ProcessKiller;

impl ProcessKiller {
    /// Create a new ProcessKiller
    pub fn new() -> Self {
        Self
    }

    /// Kill a process with the specified signal
    ///
    /// This function only handles the signal sending.
    /// Safety checks should be performed by the caller (PolicyEngine).
    pub fn kill(&self, pid: u32, signal: Signal) -> Result<(), SafeKillError> {
        SignalSender::send(pid, signal)
    }

    /// Kill a process with result tracking
    pub fn kill_with_result(
        &self,
        pid: u32,
        name: impl Into<String>,
        signal: Signal,
        dry_run: bool,
    ) -> KillResult {
        let name = name.into();

        if dry_run {
            return KillResult::dry_run(pid, name, signal);
        }

        match self.kill(pid, signal) {
            Ok(()) => KillResult::success(pid, name, signal),
            Err(e) => KillResult::failure(pid, name, &e),
        }
    }
}

impl Default for ProcessKiller {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // KillResult tests
    #[test]
    fn test_kill_result_success() {
        let result = KillResult::success(1234, "test", Signal::SIGTERM);
        assert_eq!(result.pid, 1234);
        assert_eq!(result.name, "test");
        assert!(result.success);
        assert!(result.message.contains("SIGTERM"));
    }

    #[test]
    fn test_kill_result_failure() {
        let error = SafeKillError::ProcessNotFound(1234);
        let result = KillResult::failure(1234, "test", &error);
        assert_eq!(result.pid, 1234);
        assert_eq!(result.name, "test");
        assert!(!result.success);
        assert!(result.message.contains("not found"));
    }

    #[test]
    fn test_kill_result_dry_run() {
        let result = KillResult::dry_run(1234, "test", Signal::SIGKILL);
        assert_eq!(result.pid, 1234);
        assert_eq!(result.name, "test");
        assert!(result.success);
        assert!(result.message.contains("dry run"));
        assert!(result.message.contains("SIGKILL"));
    }

    #[test]
    fn test_kill_result_clone() {
        let result = KillResult::success(100, "proc", Signal::SIGTERM);
        let cloned = result.clone();
        assert_eq!(result, cloned);
    }

    #[test]
    fn test_kill_result_debug() {
        let result = KillResult::success(100, "proc", Signal::SIGTERM);
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("KillResult"));
        assert!(debug_str.contains("100"));
    }

    // BatchKillResult tests
    #[test]
    fn test_batch_kill_result_new() {
        let batch = BatchKillResult::new();
        assert!(batch.is_empty());
        assert_eq!(batch.total_matched, 0);
        assert_eq!(batch.total_killed, 0);
    }

    #[test]
    fn test_batch_kill_result_default() {
        let batch = BatchKillResult::default();
        assert!(batch.is_empty());
    }

    #[test]
    fn test_batch_kill_result_add_success() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::success(100, "a", Signal::SIGTERM));
        batch.add(KillResult::success(200, "b", Signal::SIGTERM));

        assert_eq!(batch.total_matched, 2);
        assert_eq!(batch.total_killed, 2);
        assert!(batch.all_success());
        assert!(batch.any_success());
    }

    #[test]
    fn test_batch_kill_result_add_failure() {
        let mut batch = BatchKillResult::new();
        let error = SafeKillError::ProcessNotFound(100);
        batch.add(KillResult::failure(100, "a", &error));

        assert_eq!(batch.total_matched, 1);
        assert_eq!(batch.total_killed, 0);
        assert!(!batch.all_success());
        assert!(!batch.any_success());
    }

    #[test]
    fn test_batch_kill_result_mixed() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::success(100, "a", Signal::SIGTERM));
        let error = SafeKillError::ProcessNotFound(200);
        batch.add(KillResult::failure(200, "b", &error));

        assert_eq!(batch.total_matched, 2);
        assert_eq!(batch.total_killed, 1);
        assert!(!batch.all_success());
        assert!(batch.any_success());
    }

    #[test]
    fn test_batch_kill_result_is_empty() {
        let batch = BatchKillResult::new();
        assert!(batch.is_empty());

        let mut batch_with_item = BatchKillResult::new();
        batch_with_item.add(KillResult::success(100, "a", Signal::SIGTERM));
        assert!(!batch_with_item.is_empty());
    }

    #[test]
    fn test_batch_kill_result_all_success_empty() {
        let batch = BatchKillResult::new();
        // Empty batch should not be considered "all success"
        assert!(!batch.all_success());
    }

    // ProcessKiller tests
    #[test]
    fn test_process_killer_new() {
        let killer = ProcessKiller::new();
        // Just verify it can be created
        let _ = killer;
    }

    #[test]
    fn test_process_killer_default() {
        let killer = ProcessKiller;
        let _ = killer;
    }

    #[test]
    fn test_kill_nonexistent_process() {
        let killer = ProcessKiller::new();
        let result = killer.kill(999999999, Signal::SIGTERM);
        assert!(result.is_err());
    }

    #[test]
    fn test_kill_with_result_dry_run() {
        let killer = ProcessKiller::new();
        let result = killer.kill_with_result(999999999, "test", Signal::SIGTERM, true);

        assert!(result.success);
        assert!(result.message.contains("dry run"));
    }

    #[test]
    fn test_kill_with_result_failure() {
        let killer = ProcessKiller::new();
        let result = killer.kill_with_result(999999999, "test", Signal::SIGTERM, false);

        // Should fail because process doesn't exist
        assert!(!result.success);
    }

    #[test]
    fn test_kill_with_result_tracks_pid_and_name() {
        let killer = ProcessKiller::new();
        let result = killer.kill_with_result(12345, "myprocess", Signal::SIGKILL, true);

        assert_eq!(result.pid, 12345);
        assert_eq!(result.name, "myprocess");
    }
}
