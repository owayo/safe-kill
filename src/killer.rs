//! safe-kill のプロセス終了処理
//!
//! 安全性チェック通過後の実際のシグナル送信を担当する。

use crate::error::SafeKillError;
use crate::signal::{Signal, SignalSender};

/// 1 件の kill 実行結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillResult {
    /// 対象プロセス ID
    pub pid: u32,
    /// プロセス名（取得できた場合）
    pub name: String,
    /// 実行成否
    pub success: bool,
    /// 表示用メッセージ
    pub message: String,
    /// エラー本体。成功時と dry-run 時は `None`
    pub error: Option<SafeKillError>,
}

impl KillResult {
    /// 成功結果を生成する
    pub fn success(pid: u32, name: impl Into<String>, signal: Signal) -> Self {
        Self {
            pid,
            name: name.into(),
            success: true,
            message: format!("Sent {} to process", signal.name()),
            error: None,
        }
    }

    /// 失敗結果を生成する
    pub fn failure(pid: u32, name: impl Into<String>, error: &SafeKillError) -> Self {
        Self {
            pid,
            name: name.into(),
            success: false,
            message: error.to_string(),
            error: Some(error.clone()),
        }
    }

    /// dry-run 結果を生成する
    pub fn dry_run(pid: u32, name: impl Into<String>, signal: Signal) -> Self {
        Self {
            pid,
            name: name.into(),
            success: true,
            message: format!("Would send {} to process (dry run)", signal.name()),
            error: None,
        }
    }
}

/// 複数件の kill 実行結果
#[derive(Debug, Clone, Default)]
pub struct BatchKillResult {
    /// 各プロセスの結果
    pub results: Vec<KillResult>,
    /// 一致したプロセス総数
    pub total_matched: usize,
    /// 成功したプロセス総数
    pub total_killed: usize,
}

impl BatchKillResult {
    /// 空の結果を生成する
    pub fn new() -> Self {
        Self::default()
    }

    /// 結果を追加する
    pub fn add(&mut self, result: KillResult) {
        if result.success {
            self.total_killed += 1;
        }
        self.total_matched += 1;
        self.results.push(result);
    }

    /// 全件成功か判定する
    pub fn all_success(&self) -> bool {
        self.total_matched > 0 && self.total_killed == self.total_matched
    }

    /// 1 件でも成功したか判定する
    pub fn any_success(&self) -> bool {
        self.total_killed > 0
    }

    /// 結果が空か判定する
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// ポリシー拒否ではない最初の実行時エラーを返す
    pub fn first_operational_error(&self) -> Option<&SafeKillError> {
        self.results
            .iter()
            .filter_map(|result| result.error.as_ref())
            .find(|error| {
                !matches!(
                    error,
                    SafeKillError::Denylisted(_)
                        | SafeKillError::NotDescendant(_, _)
                        | SafeKillError::SuicidePrevention(_)
                )
            })
    }
}

/// プロセスへシグナルを送る実行器
pub struct ProcessKiller;

impl ProcessKiller {
    /// `ProcessKiller` を生成する
    pub fn new() -> Self {
        Self
    }

    /// 指定シグナルを送る
    ///
    /// 安全性チェックは呼び出し側（`PolicyEngine`）で行う。
    pub fn kill(&self, pid: u32, signal: Signal) -> Result<(), SafeKillError> {
        SignalSender::send(pid, signal)
    }

    /// 表示用結果を伴って kill を実行する
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

    // KillResult のテスト
    #[test]
    fn test_kill_result_success() {
        let result = KillResult::success(1234, "test", Signal::SIGTERM);
        assert_eq!(result.pid, 1234);
        assert_eq!(result.name, "test");
        assert!(result.success);
        assert!(result.message.contains("SIGTERM"));
        assert!(result.error.is_none());
    }

    #[test]
    fn test_kill_result_failure() {
        let error = SafeKillError::ProcessNotFound(1234);
        let result = KillResult::failure(1234, "test", &error);
        assert_eq!(result.pid, 1234);
        assert_eq!(result.name, "test");
        assert!(!result.success);
        assert!(result.message.contains("not found"));
        assert_eq!(result.error, Some(error));
    }

    #[test]
    fn test_kill_result_dry_run() {
        let result = KillResult::dry_run(1234, "test", Signal::SIGKILL);
        assert_eq!(result.pid, 1234);
        assert_eq!(result.name, "test");
        assert!(result.success);
        assert!(result.message.contains("dry run"));
        assert!(result.message.contains("SIGKILL"));
        assert!(result.error.is_none());
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

    // BatchKillResult のテスト
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
    fn test_batch_kill_result_first_operational_error() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::failure(
            100,
            "denylisted",
            &SafeKillError::Denylisted("denylisted".to_string()),
        ));
        batch.add(KillResult::failure(
            200,
            "worker",
            &SafeKillError::PermissionDenied(200),
        ));

        assert_eq!(
            batch.first_operational_error(),
            Some(&SafeKillError::PermissionDenied(200))
        );
    }

    #[test]
    fn test_batch_kill_result_first_operational_error_none_for_policy_only() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::failure(
            100,
            "denylisted",
            &SafeKillError::Denylisted("denylisted".to_string()),
        ));
        batch.add(KillResult::failure(
            200,
            "parent",
            &SafeKillError::SuicidePrevention(200),
        ));

        assert_eq!(batch.first_operational_error(), None);
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
        // 空の結果は「全件成功」とはみなさない
        assert!(!batch.all_success());
    }

    // ProcessKiller のテスト
    #[test]
    fn test_process_killer_new() {
        let killer = ProcessKiller::new();
        // 生成できることだけ確認する
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
        assert!(result.error.is_none());
    }

    #[test]
    fn test_kill_with_result_failure() {
        let killer = ProcessKiller::new();
        let result = killer.kill_with_result(999999999, "test", Signal::SIGTERM, false);

        // プロセスが存在しないため失敗する
        assert!(!result.success);
        assert_eq!(
            result.error,
            Some(SafeKillError::ProcessNotFound(999999999))
        );
    }

    #[test]
    fn test_kill_with_result_tracks_pid_and_name() {
        let killer = ProcessKiller::new();
        let result = killer.kill_with_result(12345, "myprocess", Signal::SIGKILL, true);

        assert_eq!(result.pid, 12345);
        assert_eq!(result.name, "myprocess");
    }

    #[test]
    fn test_kill_result_success_all_signals() {
        let signals = [
            (Signal::SIGHUP, "SIGHUP"),
            (Signal::SIGINT, "SIGINT"),
            (Signal::SIGQUIT, "SIGQUIT"),
            (Signal::SIGKILL, "SIGKILL"),
            (Signal::SIGTERM, "SIGTERM"),
            (Signal::SIGUSR1, "SIGUSR1"),
            (Signal::SIGUSR2, "SIGUSR2"),
        ];
        for (signal, name) in &signals {
            let result = KillResult::success(100, "proc", *signal);
            assert!(result.success);
            assert!(
                result.message.contains(name),
                "Message should contain signal name {}",
                name
            );
        }
    }

    #[test]
    fn test_kill_result_dry_run_all_signals() {
        let signals = [
            Signal::SIGHUP,
            Signal::SIGINT,
            Signal::SIGQUIT,
            Signal::SIGKILL,
            Signal::SIGTERM,
            Signal::SIGUSR1,
            Signal::SIGUSR2,
        ];
        for signal in &signals {
            let result = KillResult::dry_run(100, "proc", *signal);
            assert!(result.success);
            assert!(result.message.contains("dry run"));
            assert!(result.message.contains(signal.name()));
        }
    }

    #[test]
    fn test_kill_result_failure_various_errors() {
        let errors = [
            SafeKillError::ProcessNotFound(100),
            SafeKillError::PermissionDenied(100),
            SafeKillError::Denylisted("test".to_string()),
            SafeKillError::SuicidePrevention(100),
            SafeKillError::NotDescendant(100, "test".to_string()),
        ];
        for error in &errors {
            let result = KillResult::failure(100, "proc", error);
            assert!(!result.success);
            assert!(!result.message.is_empty());
        }
    }

    #[test]
    fn test_batch_kill_result_clone() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::success(100, "a", Signal::SIGTERM));
        batch.add(KillResult::dry_run(200, "b", Signal::SIGKILL));
        let cloned = batch.clone();
        assert_eq!(cloned.total_matched, 2);
        assert_eq!(cloned.total_killed, 2);
        assert_eq!(cloned.results.len(), 2);
    }

    #[test]
    fn test_batch_kill_result_multiple_failures() {
        let mut batch = BatchKillResult::new();
        let err = SafeKillError::ProcessNotFound(1);
        batch.add(KillResult::failure(1, "a", &err));
        let err2 = SafeKillError::PermissionDenied(2);
        batch.add(KillResult::failure(2, "b", &err2));

        assert_eq!(batch.total_matched, 2);
        assert_eq!(batch.total_killed, 0);
        assert!(!batch.all_success());
        assert!(!batch.any_success());
    }

    #[test]
    fn test_first_operational_error_empty_batch() {
        let batch = BatchKillResult::new();
        assert_eq!(batch.first_operational_error(), None);
    }

    #[test]
    fn test_first_operational_error_skips_not_descendant() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::failure(
            1,
            "a",
            &SafeKillError::NotDescendant(1, "a".to_string()),
        ));
        batch.add(KillResult::failure(
            2,
            "b",
            &SafeKillError::ProcessNotFound(2),
        ));
        assert_eq!(
            batch.first_operational_error(),
            Some(&SafeKillError::ProcessNotFound(2))
        );
    }

    #[test]
    fn test_first_operational_error_returns_first_among_multiple() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::failure(
            1,
            "a",
            &SafeKillError::Denylisted("a".to_string()),
        ));
        batch.add(KillResult::failure(
            2,
            "b",
            &SafeKillError::PermissionDenied(2),
        ));
        batch.add(KillResult::failure(
            3,
            "c",
            &SafeKillError::ProcessNotFound(3),
        ));
        // ポリシーエラー以外の最初 = PermissionDenied(2)
        assert_eq!(
            batch.first_operational_error(),
            Some(&SafeKillError::PermissionDenied(2))
        );
    }

    #[test]
    fn test_first_operational_error_success_results_ignored() {
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::success(1, "a", Signal::SIGTERM));
        batch.add(KillResult::failure(
            2,
            "b",
            &SafeKillError::Denylisted("b".to_string()),
        ));
        // 成功結果には error がなく、Denylisted はポリシーエラー → None
        assert_eq!(batch.first_operational_error(), None);
    }

    // 実プロセスに対する kill_with_result の成功パステスト
    #[test]
    fn test_kill_with_result_success_real_process() {
        use std::process::Command;

        let child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("sleep プロセスの起動に失敗");
        let pid = child.id();

        let killer = ProcessKiller::new();
        let result = killer.kill_with_result(pid, "sleep", Signal::SIGTERM, false);

        assert!(result.success, "実プロセスへの kill は成功するべき");
        assert_eq!(result.pid, pid);
        assert_eq!(result.name, "sleep");
        assert!(result.error.is_none());
        assert!(result.message.contains("Sent SIGTERM"));

        let mut child = child;
        let _ = child.wait();
    }

    // kill() メソッドの成功パステスト
    #[test]
    fn test_kill_success_real_process() {
        use std::process::Command;

        let child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("sleep プロセスの起動に失敗");
        let pid = child.id();

        let killer = ProcessKiller::new();
        let result = killer.kill(pid, Signal::SIGTERM);

        assert!(result.is_ok(), "実プロセスへの kill() は Ok を返すべき");

        let mut child = child;
        let _ = child.wait();
    }

    // BatchKillResult の any_success テスト
    #[test]
    fn test_batch_kill_result_any_success() {
        let mut batch = BatchKillResult::new();
        assert!(!batch.any_success(), "空のバッチは any_success = false");

        batch.add(KillResult::failure(
            1,
            "a",
            &SafeKillError::ProcessNotFound(1),
        ));
        assert!(!batch.any_success(), "全失敗のバッチは any_success = false");

        batch.add(KillResult::success(2, "b", Signal::SIGTERM));
        assert!(
            batch.any_success(),
            "1件でも成功があれば any_success = true"
        );
    }
}
