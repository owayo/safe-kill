//! プロセスツリー検証用の ancestry チェッカー
//!
//! プロセスが現在セッションの子孫かどうかを判定する。

use crate::process_info::{ProcessInfo, ProcessInfoProvider};
use std::env;

/// 無限ループを防ぐための ancestry 走査最大深度
const MAX_ANCESTRY_DEPTH: u32 = 100;

/// ルート PID を上書きする環境変数名
const ROOT_PID_ENV_VAR: &str = "SAFE_KILL_ROOT_PID";

/// プロセスツリー検証用 ancestry チェッカー
pub struct AncestryChecker {
    provider: ProcessInfoProvider,
    root_pid: u32,
    /// 信頼ルートの初期取得時 identity（PID 再利用検出の基準点）。
    ///
    /// `pid + start_time + name` の同一性を後続の判定で検証することで、
    /// 長寿命の `AncestryChecker`（ライブラリ利用シナリオ）で信頼ルートの
    /// PID が再利用された場合に認可境界が別プロセスへ移ることを防ぐ。
    ///
    /// `None` の場合は信頼ルートが妥当でない（PID 0/1）か、初期取得に
    /// 失敗した状態を表し、以後の子孫判定はすべて `false`（fail-closed）になる。
    root_identity: Option<ProcessInfo>,
}

impl AncestryChecker {
    /// ルート PID を自動検出して `AncestryChecker` を生成する
    pub fn new(provider: ProcessInfoProvider) -> Self {
        let root_pid = Self::get_root_pid(&provider);
        let root_identity = Self::capture_root_identity(root_pid);
        Self {
            provider,
            root_pid,
            root_identity,
        }
    }

    /// ルート PID を明示指定して `AncestryChecker` を生成する
    pub fn with_root_pid(provider: ProcessInfoProvider, root_pid: u32) -> Self {
        let root_identity = Self::capture_root_identity(root_pid);
        Self {
            provider,
            root_pid,
            root_identity,
        }
    }

    /// 信頼ルートの初期 identity を OS から取得する。
    ///
    /// PID 0/1 や OS から情報が取れない PID では `None` を返し、
    /// 以後の子孫判定が fail-closed に倒れるようにする。
    fn capture_root_identity(root_pid: u32) -> Option<ProcessInfo> {
        if !Self::is_valid_root_pid(root_pid) {
            return None;
        }
        ProcessInfoProvider::fetch_fresh(root_pid)
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

    /// 指定された `provider` snapshot 内で信頼ルートの identity 同一性を検証する内部ヘルパー。
    ///
    /// 以下のいずれかが成立しなければ `false`（fail-closed）を返す:
    /// - 信頼ルート PID が妥当（PID 0/1 は不可）
    /// - 初期 identity を保持している
    /// - 渡された provider snapshot から取得した identity と `pid + start_time + name` が一致
    ///
    /// 識別子検証と子孫判定を同一 snapshot 上で行えるようにすることで、両者の間に
    /// 発生し得る微小な TOCTOU 窓を最小化する（例えば `is_descendant_fresh` 内で
    /// 別タイミング snapshot を 2 つ使うと、その間隔で信頼ルート PID が再利用された場合に
    /// identity 検証は通過したが子孫判定は別プロセスの親子関係を見ている、という不整合が起こりうる）。
    fn root_identity_matches_in_provider(&self, provider: &ProcessInfoProvider) -> bool {
        if !Self::is_valid_root_pid(self.root_pid) {
            return false;
        }
        let Some(expected) = &self.root_identity else {
            return false;
        };
        provider
            .get(self.root_pid)
            .is_some_and(|fresh| fresh.is_same_process(expected))
    }

    /// 信頼ルートの identity が初期取得時から変わっていないかを fresh に検証する。
    ///
    /// 新しい `ProcessInfoProvider` snapshot を生成して identity 同一性を確認する。
    /// 長寿命の `AncestryChecker`（ライブラリ利用シナリオ）で、信頼ルートの祖父
    /// シェルが終了して同じ PID が別プロセスに割り当てられた場合に、認可境界が
    /// 別プロセス配下へ移るのを防ぐ。
    pub fn verify_root_identity_unchanged(&self) -> bool {
        let fresh = ProcessInfoProvider::new();
        self.root_identity_matches_in_provider(&fresh)
    }

    /// `target_pid` が `root_pid` の子孫か判定する
    ///
    /// 自身の snapshot (`self.provider`) 内で信頼ルートの identity 同一性を確認した上で、
    /// 同じ snapshot から子孫判定を行う。snapshot 一貫性を維持しつつ
    /// PID 再利用を検出する。
    pub fn is_descendant(&self, target_pid: u32) -> bool {
        if !self.root_identity_matches_in_provider(&self.provider) {
            return false;
        }
        self.is_descendant_of_unchecked(target_pid, self.root_pid)
    }

    /// `target_pid` が特定の `ancestor_pid` の子孫か判定する
    ///
    /// `ancestor_pid` が信頼ルートに不適格（PID 0/1）な場合は、誰も子孫とみなさず
    /// `false` を返す（fail-closed）。PID 1（init/launchd）を祖先とみなすと、親チェーンを
    /// たどれば事実上すべてのプロセスが子孫扱いになり ancestry の安全境界が崩れるため、
    /// 公開 API 境界でガードする（ライブラリ利用者が直接呼んでも安全）。
    ///
    /// `ancestor_pid` が自身の `root_pid` と一致する場合は、自身の snapshot 内で
    /// root identity の同一性も検証する（信頼ルートの PID 再利用を検出するため）。
    pub fn is_descendant_of(&self, target_pid: u32, ancestor_pid: u32) -> bool {
        if !Self::is_valid_root_pid(ancestor_pid) {
            return false;
        }
        if ancestor_pid == self.root_pid && !self.root_identity_matches_in_provider(&self.provider)
        {
            return false;
        }
        self.is_descendant_of_unchecked(target_pid, ancestor_pid)
    }

    /// fresh な OS 情報で子孫判定する（kill 直前の TOCTOU 緩和用）
    ///
    /// 信頼ルートの identity 整合性に加え、新しい `ProcessInfoProvider` snapshot で
    /// 子孫判定をやり直す。`AncestryChecker` 構築時の親子関係 snapshot に依存しないため、
    /// 判定〜kill の間に対象プロセスが再ペアレントされて信頼ルート外に出たケースを
    /// 捕捉できる。
    ///
    /// **重要**: identity 同一性検証と子孫判定は同一 snapshot で行う。
    /// 別タイミング snapshot を使うと、その間隔で信頼ルート PID が再利用された場合に
    /// identity 検証は通過したが子孫判定は別プロセスの親子関係を見ている、という
    /// 不整合が起き得るため。
    ///
    /// `ProcessInfoProvider::new()` で都度 fresh 取得するため、頻繁な呼び出しは
    /// オーバーヘッドが大きい。kill 直前の最終ガード用途に限定する。
    pub fn is_descendant_fresh(&self, target_pid: u32) -> bool {
        let fresh = ProcessInfoProvider::new();
        if !self.root_identity_matches_in_provider(&fresh) {
            return false;
        }
        Self::is_descendant_of_with_provider(&fresh, target_pid, self.root_pid)
    }

    /// 親チェーンをたどる木探索の本体（`ancestor_pid` の妥当性は確認済み前提）
    ///
    /// 内部 provider を使った既存挙動を維持するためのシム。
    fn is_descendant_of_unchecked(&self, target_pid: u32, ancestor_pid: u32) -> bool {
        Self::is_descendant_of_with_provider(&self.provider, target_pid, ancestor_pid)
    }

    /// 任意の `provider` を使った木探索本体
    ///
    /// `target_pid` から親 PID チェーンをたどり、以下の条件で停止する:
    /// - `ancestor_pid` に到達した（`true`）
    /// - PID 1（init/launchd）に到達した（`false`）
    /// - 最大深度を超えた（`false`）
    /// - プロセス情報が取得できない（`false`）
    fn is_descendant_of_with_provider(
        provider: &ProcessInfoProvider,
        target_pid: u32,
        ancestor_pid: u32,
    ) -> bool {
        // 存在しない PID を「自分自身の子孫」と誤判定しないよう、同一 PID 判定より
        // 前に対象プロセスが snapshot 内に存在することを確認する。
        if provider.get(target_pid).is_none() {
            return false;
        }

        // 同一 PID の場合は子孫とみなす
        if target_pid == ancestor_pid {
            return true;
        }

        let mut current_pid = target_pid;
        let mut depth = 0u32;

        while depth < MAX_ANCESTRY_DEPTH {
            // 現在 PID のプロセス情報を取得
            let Some(info) = provider.get(current_pid) else {
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
    ///
    /// 内部 provider を最新化する。信頼ルートの identity が初期取得時から変わって
    /// いれば `root_identity` を `None` にして以後の子孫判定を fail-closed に倒す。
    /// 初期取得した identity 自体は再取得しない（新しい identity を信頼すると
    /// PID 再利用後のプロセスを信頼ルートとして受け入れてしまうため）。
    ///
    /// identity 検証は最新化した自身の snapshot 上で行う（snapshot 一貫性維持）。
    pub fn refresh(&mut self) {
        self.provider.refresh();
        if self.root_identity.is_some() && !self.root_identity_matches_in_provider(&self.provider) {
            self.root_identity = None;
        }
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

    // is_valid_root_pid（信頼ルート妥当性判定）の直接テスト。
    // PID 1 fail-open 修正の安全境界を回帰テストとして固定する。
    #[test]
    fn test_is_valid_root_pid_rejects_zero_and_one() {
        // PID 0（無効値）と PID 1（init/launchd）は信頼ルートにできない。
        // これを許すと親チェーンが init に到達する全プロセスが子孫扱いになる（fail-open）。
        assert!(!AncestryChecker::is_valid_root_pid(0));
        assert!(!AncestryChecker::is_valid_root_pid(1));
    }

    #[test]
    fn test_is_valid_root_pid_accepts_two_and_above() {
        // 2 以上は信頼ルートとして妥当。境界値 2・通常値・u32 最大値で確認する。
        assert!(AncestryChecker::is_valid_root_pid(2));
        assert!(AncestryChecker::is_valid_root_pid(12345));
        assert!(AncestryChecker::is_valid_root_pid(u32::MAX));
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
    fn test_is_descendant_of_nonexistent_self_fails_closed() {
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let nonexistent_pid = u32::MAX;

        assert!(
            !checker.is_descendant_of(nonexistent_pid, nonexistent_pid),
            "存在しない PID は同一 PID 指定でも子孫として扱わない"
        );
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
    fn test_is_descendant_of_rejects_huge_nonexistent_ancestor() {
        // is_valid_root_pid は pid > 1 のみで弾くため、u32::MAX や i32::MAX+1 の
        // ような巨大で実在しない PID を ancestor に渡しても 0/1 ガードは通過する。
        // しかし木探索は現在プロセスの親チェーンにその PID を見つけられないため
        // false を返すべき。公開 API が巨大な偽 ancestor を「子孫」と誤判定しない
        // ことを安全境界として固定する。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::new(provider);
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(
            !checker.is_descendant_of(current_pid, u32::MAX),
            "巨大で実在しない ancestor は子孫判定を false にすべき"
        );
        assert!(
            !checker.is_descendant_of(current_pid, (i32::MAX as u32) + 1),
            "i32::MAX を超える ancestor も子孫判定を false にすべき"
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

    // =====================================================================
    // 信頼ルート identity 検証の回帰テスト
    //
    // 長寿命の AncestryChecker（ライブラリ利用シナリオ）で、信頼ルートの
    // 祖父シェルが終了して同じ PID が別プロセスに割り当てられた場合に、
    // 認可境界が別プロセス配下へ移らないよう fail-closed する。
    // =====================================================================

    #[test]
    fn test_verify_root_identity_unchanged_for_current_process() {
        // 現在プロセスを信頼ルートとして指定した直後は、identity 取得が成功し
        // 同一性検証も通過する（生きているプロセスへの指定）。
        let current_pid = ProcessInfoProvider::current_pid();
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, current_pid);
        assert!(
            checker.verify_root_identity_unchanged(),
            "現在プロセスを root とした直後は identity 検証が成功すべき"
        );
    }

    #[test]
    fn test_verify_root_identity_unchanged_fails_for_nonexistent_pid() {
        // 存在しない可能性が極めて高い PID を root に指定すると、初期 identity が
        // 取得できないため verify_root_identity_unchanged は false（fail-closed）。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 999_999_998);
        assert!(
            !checker.verify_root_identity_unchanged(),
            "初期 identity が取れない root では検証は fail-closed すべき"
        );
    }

    #[test]
    fn test_verify_root_identity_unchanged_fails_for_pid_zero() {
        // PID 0 は信頼ルートに不適格。capture_root_identity も None になる。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 0);
        assert!(!checker.verify_root_identity_unchanged());
    }

    #[test]
    fn test_verify_root_identity_unchanged_fails_for_pid_one() {
        // PID 1 は信頼ルートに不適格。capture_root_identity も None になる。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 1);
        assert!(!checker.verify_root_identity_unchanged());
    }

    #[test]
    fn test_is_descendant_fails_closed_when_root_identity_missing() {
        // 信頼ルートの identity を取得できない場合、is_descendant は誰も子孫
        // としない（fail-closed）。これは PID 再利用検出を兼ねる安全境界。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 999_999_997);
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(
            !checker.is_descendant(current_pid),
            "root identity が未取得なら is_descendant は false（fail-closed）"
        );
    }

    #[test]
    fn test_is_descendant_of_fails_closed_when_targeted_root_identity_missing() {
        // is_descendant_of の ancestor が自身の root_pid と一致するときも、
        // identity 検証を経由するため fail-closed する。
        let provider = ProcessInfoProvider::new();
        let root_pid = 999_999_996;
        let checker = AncestryChecker::with_root_pid(provider, root_pid);
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(
            !checker.is_descendant_of(current_pid, root_pid),
            "ancestor が root_pid と一致するときは identity 検証で fail-closed すべき"
        );
    }

    #[test]
    fn test_is_descendant_fresh_succeeds_for_current_process_as_root() {
        // 現在プロセスを root にすれば、新しい provider snapshot でも自分自身が
        // 子孫として true になる（target == ancestor は常に true）。
        let current_pid = ProcessInfoProvider::current_pid();
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, current_pid);
        assert!(
            checker.is_descendant_fresh(current_pid),
            "現在プロセスは fresh 判定でも自身の子孫として認識されるべき"
        );
    }

    #[test]
    fn test_is_descendant_fresh_fails_closed_when_root_identity_missing() {
        // 信頼ルートが取得不能な状態では、fresh 判定でも fail-closed。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 999_999_995);
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(
            !checker.is_descendant_fresh(current_pid),
            "root identity が未取得なら is_descendant_fresh は false（fail-closed）"
        );
    }

    #[test]
    fn test_refresh_invalidates_root_identity_when_mismatched() {
        // 信頼ルートが取得不能な状態で refresh を呼んでも、それまで保持していた
        // root_identity （ここでは元から None）が None のままで、is_descendant は
        // fail-closed のままであることを確認する。
        let provider = ProcessInfoProvider::new();
        let mut checker = AncestryChecker::with_root_pid(provider, 999_999_994);
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(!checker.is_descendant(current_pid));
        checker.refresh();
        assert!(
            !checker.is_descendant(current_pid),
            "refresh 後も root identity が未取得なら fail-closed のまま"
        );
    }

    #[test]
    fn test_refresh_keeps_validity_when_root_identity_stable() {
        // 現在プロセスを root にしてから refresh しても、identity は安定で
        // is_descendant が true を返し続ける（既存挙動の維持を保証）。
        let current_pid = ProcessInfoProvider::current_pid();
        let provider = ProcessInfoProvider::new();
        let mut checker = AncestryChecker::with_root_pid(provider, current_pid);
        assert!(checker.is_descendant(current_pid));
        checker.refresh();
        assert!(
            checker.is_descendant(current_pid),
            "現在プロセスを root にしている限り refresh 後も is_descendant は維持されるべき"
        );
        assert!(checker.verify_root_identity_unchanged());
    }

    #[test]
    fn test_capture_root_identity_returns_none_for_invalid_root() {
        // capture_root_identity は内部関数だが、is_valid_root_pid と組み合わせ
        // PID 0/1 では即 None を返す。これは構築直後の挙動として外から観測できる。
        let provider = ProcessInfoProvider::new();
        let checker = AncestryChecker::with_root_pid(provider, 0);
        // root_identity が None なら verify_root_identity_unchanged が false
        assert!(!checker.verify_root_identity_unchanged());
    }
}
