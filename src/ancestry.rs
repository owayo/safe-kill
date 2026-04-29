//! プロセスツリー検証用の ancestry チェッカー
//!
//! プロセスが現在セッションの子孫かどうかを判定する。

use crate::process_info::ProcessInfoProvider;
use std::env;

/// 無限ループを防ぐための ancestry 走査最大深度
const MAX_ANCESTRY_DEPTH: u32 = 100;

/// ルート PID を上書きする環境変数名
const ROOT_PID_ENV_VAR: &str = "SAFE_KILL_ROOT_PID";

/// プロセスツリー検証用 ancestry チェッカー
pub struct AncestryChecker {
    provider: ProcessInfoProvider,
    root_pid: u32,
}

impl AncestryChecker {
    /// ルート PID を自動検出して `AncestryChecker` を生成する
    pub fn new(provider: ProcessInfoProvider) -> Self {
        let root_pid = Self::get_root_pid(&provider);
        Self { provider, root_pid }
    }

    /// ルート PID を明示指定して `AncestryChecker` を生成する
    pub fn with_root_pid(provider: ProcessInfoProvider, root_pid: u32) -> Self {
        Self { provider, root_pid }
    }

    /// 環境変数からルート PID を解析する
    fn parse_root_pid(value: &str) -> Option<u32> {
        let pid = value.trim().parse::<u32>().ok()?;
        if pid == 0 {
            return None;
        }
        Some(pid)
    }

    /// ルート PID（信頼ルート）を取得する
    ///
    /// 優先順位:
    /// 1. `SAFE_KILL_ROOT_PID` 環境変数
    /// 2. 呼び出しシェルの親（現在プロセスの祖父）
    /// 3. 現在プロセス PID（フォールバック）
    pub fn get_root_pid(provider: &ProcessInfoProvider) -> u32 {
        // まず環境変数を確認する
        if let Ok(env_pid) = env::var(ROOT_PID_ENV_VAR) {
            if let Some(pid) = Self::parse_root_pid(&env_pid) {
                return pid;
            }
        }

        // 祖父プロセス（シェルの親）を信頼ルートとして採用する
        // 現在プロセス -> シェル -> 信頼ルート
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

        // フォールバックとして現在 PID を使用する
        current_pid
    }

    /// 設定済みルート PID を返す
    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// `target_pid` が `root_pid` の子孫か判定する
    ///
    /// `target_pid` から親 PID チェーンをたどり、以下の条件で停止する:
    /// - `root_pid` に到達した（`true`）
    /// - PID 1（init/launchd）に到達した（`false`）
    /// - 最大深度を超えた（`false`）
    /// - プロセス情報が取得できない（`false`）
    pub fn is_descendant(&self, target_pid: u32) -> bool {
        self.is_descendant_of(target_pid, self.root_pid)
    }

    /// `target_pid` が特定の `ancestor_pid` の子孫か判定する
    pub fn is_descendant_of(&self, target_pid: u32, ancestor_pid: u32) -> bool {
        // 同一 PID の場合は子孫とみなす
        if target_pid == ancestor_pid {
            return true;
        }

        let mut current_pid = target_pid;
        let mut depth = 0u32;

        while depth < MAX_ANCESTRY_DEPTH {
            // 現在 PID のプロセス情報を取得
            let Some(info) = self.provider.get(current_pid) else {
                // プロセスが見つからない
                return false;
            };

            // 親 PID を取得
            let Some(parent_pid) = info.parent_pid else {
                // 親なし（孤立プロセスまたは init）
                return false;
            };

            // 親が目的の祖先か確認
            if parent_pid == ancestor_pid {
                return true;
            }

            // PID 1（init/launchd）到達時は探索終了
            if parent_pid == 1 {
                return false;
            }

            current_pid = parent_pid;
            depth += 1;
        }

        // 最大深度超過
        false
    }

    /// `target_pid` の kill が自殺行為（自分または親の kill）か判定する
    pub fn is_suicide(&self, target_pid: u32) -> bool {
        let current_pid = ProcessInfoProvider::current_pid();

        // 自分自身か確認
        if target_pid == current_pid {
            return true;
        }

        // 親プロセスか確認
        if let Some(info) = self.provider.get(current_pid) {
            if let Some(parent_pid) = info.parent_pid {
                if target_pid == parent_pid {
                    return true;
                }
            }
        }

        false
    }

    /// プロセス情報を再取得する
    pub fn refresh(&mut self) {
        self.provider.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 基本的な生成テスト
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

    // ルート PID 検出テスト
    #[test]
    fn test_get_root_pid_returns_valid() {
        let provider = ProcessInfoProvider::new();
        let root_pid = AncestryChecker::get_root_pid(&provider);
        assert!(root_pid > 0);
    }

    // 補足: 環境変数の直接テストは並列実行時に競合しやすいため、
    // ここではパース関数を直接検証する。

    #[test]
    fn test_parse_root_pid_valid() {
        assert_eq!(AncestryChecker::parse_root_pid("12345"), Some(12345));
    }

    #[test]
    fn test_parse_root_pid_invalid() {
        assert_eq!(AncestryChecker::parse_root_pid("not_a_number"), None);
    }

    #[test]
    fn test_parse_root_pid_zero_rejected() {
        assert_eq!(AncestryChecker::parse_root_pid("0"), None);
    }

    #[test]
    fn test_parse_root_pid_trimmed() {
        assert_eq!(AncestryChecker::parse_root_pid("  42  "), Some(42));
    }

    #[test]
    fn test_parse_root_pid_negative_rejected() {
        // 負数は u32 として解析できないため None になる。
        assert_eq!(AncestryChecker::parse_root_pid("-1"), None);
        assert_eq!(AncestryChecker::parse_root_pid("-12345"), None);
    }

    #[test]
    fn test_parse_root_pid_overflow_rejected() {
        // u32::MAX を超える値は解析できないため None になる。
        let overflow = format!("{}", u64::from(u32::MAX) + 1);
        assert_eq!(AncestryChecker::parse_root_pid(&overflow), None);
    }

    #[test]
    fn test_parse_root_pid_empty_rejected() {
        assert_eq!(AncestryChecker::parse_root_pid(""), None);
        assert_eq!(AncestryChecker::parse_root_pid("   "), None);
    }

    // is_descendant テスト
    #[test]
    fn test_current_process_is_descendant_of_root() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();

        // 現在プロセスは検出されたルートの子孫であるはず
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

        // 存在しない可能性が高い PID
        assert!(!checker.is_descendant(999999999));
    }

    #[test]
    fn test_init_not_descendant_of_normal_root() {
        let provider = ProcessInfoProvider::new();
        let current_pid = ProcessInfoProvider::current_pid();
        let checker = AncestryChecker::with_root_pid(provider, current_pid);

        // PID 1（init）は通常プロセスの子孫にならない
        assert!(!checker.is_descendant(1));
    }

    // is_descendant_of テスト
    #[test]
    fn test_is_descendant_of_self() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();

        // プロセスは自分自身の子孫とみなす
        assert!(checker.is_descendant_of(current_pid, current_pid));
    }

    #[test]
    fn test_parent_is_ancestor() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();

        // 現在プロセスは親プロセスの子孫であるはず
        if let Some(info) = checker.provider.get(current_pid) {
            if let Some(parent_pid) = info.parent_pid {
                assert!(checker.is_descendant_of(current_pid, parent_pid));
            }
        }
    }

    // is_suicide テスト
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

        // 自分や親でない可能性が高い PID は自殺判定にならない
        assert!(!checker.is_suicide(999999999));
    }

    // refresh テスト
    #[test]
    fn test_refresh() {
        let provider = ProcessInfoProvider::new();
        let mut checker = AncestryChecker::new(provider);

        // panic しないことのみ確認
        checker.refresh();

        // ルート PID が有効値であることを確認
        let root = checker.root_pid();
        assert!(root > 0);
    }

    #[test]
    fn test_root_pid_one() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 1);

        assert!(checker.is_descendant(1));

        // 結果は実行環境に依存するため、panic しないことのみ確認
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

        let depth = MAX_ANCESTRY_DEPTH;
        assert!(depth >= 10);
        assert!(depth <= 1000);
        assert!(root > 0);
    }

    // 環境変数定数テスト
    #[test]
    fn test_env_var_name() {
        assert_eq!(ROOT_PID_ENV_VAR, "SAFE_KILL_ROOT_PID");
    }

    // 最大深度定数テスト
    #[test]
    fn test_max_depth_constant() {
        assert_eq!(MAX_ANCESTRY_DEPTH, 100);
    }
}
