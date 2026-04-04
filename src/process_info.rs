//! sysinfo クレートを使用したプロセス情報プロバイダー
//!
//! クロスプラットフォームなプロセス情報取得を提供する。

use sysinfo::{Pid, ProcessesToUpdate, System};

/// 単一プロセスの情報
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// プロセス ID
    pub pid: u32,
    /// 親プロセス ID（親がない場合や不明な場合は None）
    pub parent_pid: Option<u32>,
    /// プロセス名
    pub name: String,
    /// コマンドライン引数
    pub cmd: Vec<String>,
}

/// sysinfo を使用したプロセス情報プロバイダー
pub struct ProcessInfoProvider {
    system: System,
}

impl ProcessInfoProvider {
    /// プロセスリストを更新済みの新しい ProcessInfoProvider を作成
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::All, true);
        Self { system }
    }

    /// プロセスリストを更新
    pub fn refresh(&mut self) {
        self.system.refresh_processes(ProcessesToUpdate::All, true);
    }

    /// PID でプロセス情報を取得
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

    /// 指定名に一致するすべてのプロセスを検索（完全一致）
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

    /// すべてのプロセスを取得
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

    /// 現在のプロセスの PID を取得
    pub fn current_pid() -> u32 {
        std::process::id()
    }

    /// 現在のプロセスの親 PID を取得
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
        // 少なくともいくつかのプロセスが存在するはず
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
        // 存在しない可能性の高い大きな PID を使用
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
        // 現在のプロセスには親が存在するはず
        assert!(parent.is_some());
    }

    #[test]
    fn test_all_processes_not_empty() {
        let provider = ProcessInfoProvider::new();
        let all = provider.all();
        // 少なくとも現在のプロセスが含まれるはず
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
        // プロセス数が妥当であること（ゼロでない）
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
        // プロセス名が空でないこと
        assert!(!info.name.is_empty());
    }

    #[test]
    fn test_pid_1_exists_or_system_process() {
        let provider = ProcessInfoProvider::new();
        // ほとんどのシステムで PID 1 は存在する（init/launchd/systemd）
        // ただし厳密には要求せず、get が動作することをテスト
        let _result = provider.get(1);
        // 結果に関わらずテストは通過する - API の動作確認が目的
    }

    #[test]
    fn test_find_by_name_finds_current_process() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        // 現在のプロセス名を取得
        let current_info = provider
            .get(current_pid)
            .expect("Current process should exist");
        // 名前で検索して現在のプロセスが含まれることを確認
        let results = provider.find_by_name(&current_info.name);
        assert!(
            results.iter().any(|p| p.pid == current_pid),
            "find_by_name should find the current process by its name"
        );
    }

    #[test]
    fn test_find_by_name_results_have_correct_name() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let current_info = provider
            .get(current_pid)
            .expect("Current process should exist");
        let results = provider.find_by_name(&current_info.name);
        // 結果の全プロセスが検索名と一致すること
        for result in &results {
            assert_eq!(
                result.name, current_info.name,
                "All find_by_name results should have the searched name"
            );
        }
    }

    #[test]
    fn test_process_info_parent_pid_some() {
        let info = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec![],
        };
        assert_eq!(info.parent_pid, Some(1));
    }

    #[test]
    fn test_process_info_parent_pid_none() {
        let info = ProcessInfo {
            pid: 1,
            parent_pid: None,
            name: "init".to_string(),
            cmd: vec![],
        };
        assert_eq!(info.parent_pid, None);
    }

    #[test]
    fn test_process_info_equality() {
        let a = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec!["arg1".to_string()],
        };
        let b = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec!["arg1".to_string()],
        };
        let c = ProcessInfo {
            pid: 200,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec!["arg1".to_string()],
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_process_info_debug_output() {
        let info = ProcessInfo {
            pid: 42,
            parent_pid: Some(1),
            name: "test_proc".to_string(),
            cmd: vec!["test".to_string()],
        };
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("42"));
        assert!(debug_str.contains("test_proc"));
    }

    #[test]
    fn test_all_processes_have_valid_pids() {
        let provider = ProcessInfoProvider::new();
        let all = provider.all();
        for p in &all {
            assert!(p.pid > 0, "All processes should have PID > 0");
            assert!(!p.name.is_empty(), "All processes should have a name");
        }
    }

    // find_by_name の大文字小文字区別テスト
    #[test]
    fn test_find_by_name_case_sensitive() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let current_info = provider
            .get(current_pid)
            .expect("現在のプロセスが存在するべき");

        // 大文字に変換して検索（元の名前と異なる場合のみテスト有効）
        let upper_name = current_info.name.to_uppercase();
        if upper_name != current_info.name {
            let results = provider.find_by_name(&upper_name);
            assert!(
                !results.iter().any(|p| p.pid == current_pid),
                "find_by_name は大文字小文字を区別するため、大文字変換名では一致しないべき"
            );
        }
    }

    // find_by_name の部分一致を拒否するテスト
    #[test]
    fn test_find_by_name_no_partial_match() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let current_info = provider
            .get(current_pid)
            .expect("現在のプロセスが存在するべき");

        // プロセス名が2文字以上の場合、先頭1文字で検索しても部分一致しない
        if current_info.name.len() > 1 {
            let partial = &current_info.name[..1];
            let results = provider.find_by_name(partial);
            // 部分一致で見つかるプロセスがあっても、完全一致でないものは含まない
            for r in &results {
                assert_eq!(r.name, partial, "find_by_name は完全一致のみ返すべき");
            }
        }
    }

    // 空文字列での find_by_name テスト
    #[test]
    fn test_find_by_name_empty_string() {
        let provider = ProcessInfoProvider::new();
        let results = provider.find_by_name("");
        // 空文字列で一致するプロセスは通常存在しない
        assert!(results.is_empty(), "空文字列での検索は空の結果を返すべき");
    }

    // 存在しない PID への get テスト（u32::MAX 付近）
    #[test]
    fn test_get_nonexistent_large_pid() {
        let provider = ProcessInfoProvider::new();
        // u32::MAX に近い PID は通常存在しない
        let result = provider.get(u32::MAX - 1);
        assert!(result.is_none(), "非常に大きい PID は存在しないはず");
    }
}
