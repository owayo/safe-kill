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
    /// プロセスの起動時刻（UNIXエポック秒）。
    /// PID 再利用検出に使用する。同じ PID でも異なるプロセスは別の起動時刻を持つ。
    pub start_time: u64,
}

impl ProcessInfo {
    /// 同一プロセスかを判定する（PID 再利用検出用）
    ///
    /// PID と `start_time` の両方が一致していれば同一プロセスとみなす。
    /// `start_time` は同一秒内に再利用された場合に区別できないため、
    /// 名前も補助的に検証する。これにより、ポリシー判定後に kill 直前で
    /// PID 再利用を検出できる。
    pub fn is_same_process(&self, other: &ProcessInfo) -> bool {
        self.pid == other.pid && self.start_time == other.start_time && self.name == other.name
    }
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

    /// `sysinfo::Process` から `ProcessInfo` を構築する内部ヘルパー
    fn build_info(pid: u32, proc: &sysinfo::Process) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid: proc.parent().map(|p| p.as_u32()),
            name: proc.name().to_string_lossy().to_string(),
            cmd: proc
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect(),
            start_time: proc.start_time(),
        }
    }

    /// PID でプロセス情報を取得
    pub fn get(&self, pid: u32) -> Option<ProcessInfo> {
        let sysinfo_pid = Pid::from_u32(pid);
        self.system
            .process(sysinfo_pid)
            .map(|proc| Self::build_info(pid, proc))
    }

    /// 指定 PID の最新プロセス情報を OS から直接取得する
    ///
    /// kill 直前の TOCTOU 検証用。新しい `System` インスタンスを生成して
    /// 指定 PID のみ refresh するため、`ProcessInfoProvider` の保持する
    /// スナップショットに依存しない。PID 再利用が発生した場合は新しい
    /// プロセスの `start_time` が返るため、判定時の `start_time` と比較
    /// することで再利用を検出できる。
    pub fn fetch_fresh(pid: u32) -> Option<ProcessInfo> {
        let mut sys = System::new();
        let sysinfo_pid = Pid::from_u32(pid);
        sys.refresh_processes(ProcessesToUpdate::Some(&[sysinfo_pid]), true);
        sys.process(sysinfo_pid)
            .map(|proc| Self::build_info(pid, proc))
    }

    /// 指定名に一致するすべてのプロセスを検索（完全一致）
    pub fn find_by_name(&self, name: &str) -> Vec<ProcessInfo> {
        let mut processes: Vec<_> = self
            .system
            .processes()
            .iter()
            .filter(|(_, proc)| proc.name().to_string_lossy() == name)
            .map(|(pid, proc)| Self::build_info(pid.as_u32(), proc))
            .collect();

        // `sysinfo` の内部マップ順に依存させず、複数一致時の処理順を安定させる。
        processes.sort_by_key(|process| process.pid);
        processes
    }

    /// すべてのプロセスを取得
    pub fn all(&self) -> Vec<ProcessInfo> {
        let mut processes: Vec<_> = self
            .system
            .processes()
            .iter()
            .map(|(pid, proc)| Self::build_info(pid.as_u32(), proc))
            .collect();

        // 一覧表示の出力順が毎回ぶれないよう PID 昇順にそろえる。
        processes.sort_by_key(|process| process.pid);
        processes
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
            start_time: 0,
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
            start_time: 0,
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
            .expect("現在のプロセスが存在するべき");
        // 名前で検索して現在のプロセスが含まれることを確認
        let results = provider.find_by_name(&current_info.name);
        assert!(
            results.iter().any(|p| p.pid == current_pid),
            "find_by_name は現在のプロセス名で検索した結果に現在の PID を含むべき"
        );
    }

    #[test]
    fn test_find_by_name_results_have_correct_name() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let current_info = provider
            .get(current_pid)
            .expect("現在のプロセスが存在するべき");
        let results = provider.find_by_name(&current_info.name);
        // 結果の全プロセスが検索名と一致すること
        for result in &results {
            assert_eq!(
                result.name, current_info.name,
                "find_by_name の結果はすべて検索した名前と一致するべき"
            );
        }
    }

    #[test]
    fn test_find_by_name_results_are_sorted_by_pid() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let current_info = provider
            .get(current_pid)
            .expect("現在のプロセスが存在するべき");
        let results = provider.find_by_name(&current_info.name);

        assert!(
            results.windows(2).all(|pair| pair[0].pid <= pair[1].pid),
            "find_by_name の結果は PID 昇順であるべき"
        );
    }

    #[test]
    fn test_process_info_parent_pid_some() {
        let info = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec![],
            start_time: 0,
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
            start_time: 0,
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
            start_time: 0,
        };
        let b = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec!["arg1".to_string()],
            start_time: 0,
        };
        let c = ProcessInfo {
            pid: 200,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec!["arg1".to_string()],
            start_time: 0,
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
            start_time: 0,
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
            assert!(p.pid > 0, "すべてのプロセスは PID > 0 であるべき");
            assert!(!p.name.is_empty(), "すべてのプロセスは名前を持つべき");
        }
    }

    #[test]
    fn test_all_processes_are_sorted_by_pid() {
        let provider = ProcessInfoProvider::new();
        let all = provider.all();

        assert!(
            all.windows(2).all(|pair| pair[0].pid <= pair[1].pid),
            "all の結果は PID 昇順であるべき"
        );
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

    // start_time 関連テスト

    #[test]
    fn test_get_includes_start_time() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let info = provider
            .get(current_pid)
            .expect("現在のプロセスが取得できるべき");
        // start_time は通常 0 ではない（プロセス起動後の epoch 秒）
        assert!(
            info.start_time > 0,
            "現在プロセスの start_time は 0 以外であるべき"
        );
    }

    #[test]
    fn test_fetch_fresh_returns_current_process() {
        let current_pid = ProcessInfoProvider::current_pid();
        let info = ProcessInfoProvider::fetch_fresh(current_pid)
            .expect("現在プロセスは fetch_fresh で取得できるべき");
        assert_eq!(info.pid, current_pid);
        assert!(!info.name.is_empty());
        assert!(info.start_time > 0);
    }

    #[test]
    fn test_fetch_fresh_returns_none_for_nonexistent_pid() {
        // 存在しない可能性が極めて高い PID
        let info = ProcessInfoProvider::fetch_fresh(999_999_999);
        assert!(
            info.is_none(),
            "存在しない PID は fetch_fresh で None を返すべき"
        );
    }

    #[test]
    fn test_fetch_fresh_consistent_with_get() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let from_get = provider.get(current_pid).expect("get できるべき");
        let from_fresh =
            ProcessInfoProvider::fetch_fresh(current_pid).expect("fetch_fresh できるべき");

        // PID と name と start_time は必ず一致するべき
        // （cmd や parent_pid はタイミングや表示形式の差で揺れる可能性がある）
        assert_eq!(from_get.pid, from_fresh.pid);
        assert_eq!(from_get.name, from_fresh.name);
        assert_eq!(from_get.start_time, from_fresh.start_time);
    }

    #[test]
    fn test_is_same_process_identical() {
        let info = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec!["arg".to_string()],
            start_time: 12345,
        };
        let cloned = info.clone();
        assert!(info.is_same_process(&cloned));
    }

    #[test]
    fn test_is_same_process_different_pid() {
        let a = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec![],
            start_time: 12345,
        };
        let b = ProcessInfo {
            pid: 101,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec![],
            start_time: 12345,
        };
        assert!(!a.is_same_process(&b), "PID 不一致は別プロセス");
    }

    #[test]
    fn test_is_same_process_different_start_time() {
        // PID 再利用ケース: 同じ PID/同じ名前でも起動時刻が違えば別プロセス
        let original = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec![],
            start_time: 12345,
        };
        let reused = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec![],
            start_time: 99999,
        };
        assert!(
            !original.is_same_process(&reused),
            "start_time が異なれば PID 再利用とみなして別プロセスと判定するべき"
        );
    }

    #[test]
    fn test_is_same_process_different_name() {
        // 同じ秒に PID 再利用された場合に名前で識別する補助検証
        let a = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "process_a".to_string(),
            cmd: vec![],
            start_time: 12345,
        };
        let b = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "process_b".to_string(),
            cmd: vec![],
            start_time: 12345,
        };
        assert!(
            !a.is_same_process(&b),
            "プロセス名が異なれば別プロセスと判定するべき"
        );
    }

    #[test]
    fn test_is_same_process_ignores_parent_and_cmd() {
        // parent_pid と cmd は同一性判定に使わない（プロセスの状態として変動し得るため）
        let a = ProcessInfo {
            pid: 100,
            parent_pid: Some(1),
            name: "test".to_string(),
            cmd: vec!["arg1".to_string()],
            start_time: 12345,
        };
        let b = ProcessInfo {
            pid: 100,
            parent_pid: Some(2),
            name: "test".to_string(),
            cmd: vec!["arg2".to_string()],
            start_time: 12345,
        };
        assert!(
            a.is_same_process(&b),
            "parent_pid と cmd の差異は同一性判定に影響しないべき"
        );
    }
}
