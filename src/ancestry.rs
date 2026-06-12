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

    /// 信頼ルートとして妥当な PID か判定する
    ///
    /// PID 0（無効値）と PID 1（init/launchd）は信頼ルートにできない。
    /// PID 1 を信頼ルートにすると、親チェーンをたどれば事実上すべての
    /// プロセスが init に到達するため、ほぼ全プロセスが「子孫」と誤判定され、
    /// ancestry による安全境界が消失してしまう（fail-open）。
    /// コンテナ・systemd サービス・直接 spawn されたシェル配下など、
    /// 祖父/親が PID 1 になり得る環境を考慮し、1 以下は常に拒否する。
    fn is_valid_root_pid(pid: u32) -> bool {
        pid > 1
    }

    /// 環境変数からルート PID を解析する
    fn parse_root_pid(value: &str) -> Option<u32> {
        let pid = value.trim().parse::<u32>().ok()?;
        if !Self::is_valid_root_pid(pid) {
            return None;
        }
        Some(pid)
    }

    /// ルート PID（信頼ルート）を取得する
    ///
    /// 優先順位:
    /// 1. `SAFE_KILL_ROOT_PID` 環境変数
    /// 2. 呼び出しシェルの親（現在プロセスの祖父）
    /// 3. 呼び出しシェル（現在プロセスの親）
    /// 4. 現在プロセス PID（フォールバック）
    ///
    /// 祖父・親が PID 1（init/launchd）等で信頼ルートに不適格な場合は、
    /// より内側（親→現在プロセス）へフォールバックして fail-closed に倒す。
    /// これにより、コンテナや systemd サービス配下で親が PID 1 になる場合でも
    /// 「全プロセスが子孫」と誤判定せず、自プロセスの子孫のみを kill 対象とする。
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
                // 祖父が妥当な信頼ルートであれば採用する
                if let Some(parent_info) = provider.get(parent_pid) {
                    if let Some(grandparent_pid) = parent_info.parent_pid {
                        if Self::is_valid_root_pid(grandparent_pid) {
                            return grandparent_pid;
                        }
                    }
                }
                // 祖父が不適格（PID 1 等）な場合は親へフォールバックする
                if Self::is_valid_root_pid(parent_pid) {
                    return parent_pid;
                }
            }
        }

        // 最終フォールバックは現在 PID（自プロセスの子孫のみ kill 可能=fail-closed）
        current_pid
    }

    /// 設定済みルート PID を返す
    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// `target_pid` が `root_pid` の子孫か判定する
    pub fn is_descendant(&self, target_pid: u32) -> bool {
        self.is_descendant_of(target_pid, self.root_pid)
    }

    /// `target_pid` が特定の `ancestor_pid` の子孫か判定する
    ///
    /// `ancestor_pid` が信頼ルートに不適格（PID 0/1）な場合は、誰も子孫とみなさず
    /// `false` を返す（fail-closed）。PID 1（init/launchd）を祖先とみなすと、親チェーンを
    /// たどれば事実上すべてのプロセスが子孫扱いになり ancestry の安全境界が崩れるため、
    /// 公開 API 境界でガードする（ライブラリ利用者が直接呼んでも安全）。
    pub fn is_descendant_of(&self, target_pid: u32, ancestor_pid: u32) -> bool {
        if !Self::is_valid_root_pid(ancestor_pid) {
            return false;
        }
        self.is_descendant_of_unchecked(target_pid, ancestor_pid)
    }

    /// 親チェーンをたどる木探索の本体（`ancestor_pid` の妥当性は確認済み前提）
    ///
    /// `target_pid` から親 PID チェーンをたどり、以下の条件で停止する:
    /// - `ancestor_pid` に到達した（`true`）
    /// - PID 1（init/launchd）に到達した（`false`）
    /// - 最大深度を超えた（`false`）
    /// - プロセス情報が取得できない（`false`）
    fn is_descendant_of_unchecked(&self, target_pid: u32, ancestor_pid: u32) -> bool {
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
        // get_root_pid は信頼ルートとして PID 1 以下（init/launchd・無効値）を返さない。
        // 祖父/親が PID 1 でもより内側へフォールバックするため、常に 1 より大きい。
        assert!(
            root_pid > 1,
            "get_root_pid は PID 1 以下を返すべきでない: {root_pid}"
        );
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
    fn test_parse_root_pid_one_rejected() {
        // PID 1（init/launchd）を信頼ルートにすると全プロセスが子孫扱いになるため拒否する。
        assert_eq!(AncestryChecker::parse_root_pid("1"), None);
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
    fn test_root_pid_one_is_fail_closed() {
        // PID 1（init/launchd）を信頼ルートにすると全プロセスが子孫扱いになり
        // ancestry の安全境界が消失する（fail-open）。そのため root_pid が 1 の
        // 場合は誰も子孫とみなさず fail-closed に倒すことを検証する。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 1);

        // PID 1 自身も子孫扱いしない（root PID 自体は policy 側で別途保護される）
        assert!(
            !checker.is_descendant(1),
            "root_pid=1 では PID 1 も子孫扱いしないべき"
        );

        // 現在プロセスも子孫扱いしない（全プロセス kill 可能化を防ぐ）
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(
            !checker.is_descendant(current_pid),
            "root_pid=1 では現在プロセスも子孫扱いしないべき（fail-closed）"
        );
    }

    #[test]
    fn test_root_pid_zero_is_fail_closed() {
        // 信頼ルートが 0（無効値）の場合も誰も子孫扱いしない（fail-closed）。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 0);
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(!checker.is_descendant(current_pid));
        assert!(!checker.is_descendant(0));
    }

    #[test]
    fn test_is_descendant_of_rejects_init_ancestor() {
        // 公開 API の is_descendant_of は ancestor=0/1 を直接渡されても fail-closed
        // （false）に倒す。ライブラリ利用者が PID 1 経由の旧 fail-open を踏めないことを保証。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(
            !checker.is_descendant_of(current_pid, 1),
            "ancestor=1 は子孫判定を fail-closed にすべき"
        );
        assert!(
            !checker.is_descendant_of(current_pid, 0),
            "ancestor=0 は子孫判定を fail-closed にすべき"
        );
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
