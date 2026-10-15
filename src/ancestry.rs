//! プロセスツリー検証用の ancestry チェッカー
//!
//! プロセスが現在セッションの子孫かどうかを判定する。

use crate::config::{Config, denylist_entry_matches};
use crate::process_info::{ProcessInfo, ProcessInfoProvider};
use std::env;

/// 無限ループを防ぐための ancestry 走査最大深度
const MAX_ANCESTRY_DEPTH: u32 = 100;

/// ルート PID を上書きする環境変数名
const ROOT_PID_ENV_VAR: &str = "SAFE_KILL_ROOT_PID";

/// 信頼ルートの自動検出で「エージェントと safe-kill の間に挟まったシェル」とみなす名前
///
/// ここに無いシェルは内側（親）を信頼ルートにする側へ倒れる。範囲が狭まるだけで
/// 広がらないので、未知のシェルは `SAFE_KILL_ROOT_PID` で明示してもらう。
/// `busybox` は多数のコマンドを兼ねるため、名前だけではシェルと断定できず含めない。
const SHELL_NAMES: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ash", "ksh", "ksh93", "mksh", "pdksh", "yash", "fish", "tcsh",
    "csh",
];

/// プロセス名がシェルか判定する
///
/// ログインシェルの argv[0] は `-zsh` のように先頭に `-` が付くが、sysinfo のプロセス名は
/// macOS では exec したパスの basename、Linux では comm（実行ファイル名）なので、通常 `-` は
/// 付かない。comm を `-zsh` に書き換えたプロセスもシェルとして扱えるよう、判定のときだけ
/// 防御的に 1 つ外す（保持しているプロセス名や identity は変えない）。
fn is_shell_process_name(name: &str) -> bool {
    let name = name.strip_prefix('-').unwrap_or(name);
    SHELL_NAMES.contains(&name)
}

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
    ///
    /// 前後の空白を除いて `u32` として読めない値と、0・1 は `None`（無視して自動検出）。
    /// `2..=u32::MAX` は明示されたルートとして採用する。`i32::MAX` を超える値や生きて
    /// いない PID では identity が取れないので、親子関係による許可は成立しない（fail-closed）。
    /// 明示された値を黙って自動検出へ置き換えると、意図より広い範囲を子孫扱いしかねないため。
    /// allowlist と許可ポートによる ancestry の迂回までは止めない。
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
    /// 2. 自動検出（[`Self::detect_root_pid`]）: 親がシェルならシェルの親（エージェント）、
    ///    そうでなければ親、どちらも不適格なら現在プロセス
    pub fn get_root_pid(provider: &ProcessInfoProvider) -> u32 {
        // まず環境変数を確認する
        if let Ok(env_pid) = env::var(ROOT_PID_ENV_VAR)
            && let Some(pid) = Self::parse_root_pid(&env_pid)
        {
            return pid;
        }

        Self::detect_root_pid(|pid| provider.get(pid), ProcessInfoProvider::current_pid())
    }

    /// 信頼ルートを自動検出する（参照関数を注入できる本体）
    ///
    /// 想定する呼び出し構造は「エージェント → ツール用シェル → safe-kill」で、
    /// エージェントを信頼ルートにする。ただし祖父を無条件には採らない。
    /// `sh -c 'safe-kill …'` のように最後の単一コマンドを渡すと、sh / bash / zsh は
    /// fork せず exec するため間のシェルが消え、親がエージェント、祖父が
    /// エージェントを起動したもの（端末のシェルや IDE のプロセス）になる。
    /// そこで祖父を採ると、エージェントの兄弟プロセスまで「子孫」として kill できて
    /// しまう。祖父を採るのは親がシェルのときだけにし、それ以外は親を信頼ルートにする。
    ///
    /// 候補は [`Self::is_eligible_auto_root`] を満たす必要があり、不適格なら
    /// より内側（親 → 現在プロセス）へ倒す。外側へは決して探索しない。
    fn detect_root_pid(lookup: impl Fn(u32) -> Option<ProcessInfo>, current_pid: u32) -> u32 {
        let parent = lookup(current_pid)
            .and_then(|current| current.parent_pid)
            .and_then(&lookup);

        if let Some(parent) = parent {
            if is_shell_process_name(&parent.name)
                && let Some(grandparent) = parent.parent_pid.and_then(&lookup)
                && Self::is_eligible_auto_root(&grandparent)
            {
                return grandparent.pid;
            }
            if Self::is_eligible_auto_root(&parent) {
                return parent.pid;
            }
        }

        // 最終フォールバックは現在 PID（自プロセスの子孫のみ kill 可能=fail-closed）
        current_pid
    }

    /// 自動検出の候補として信頼ルートにできるプロセスか判定する
    ///
    /// - PID 0/1 は不可（[`Self::is_valid_root_pid`]）
    /// - 既定 denylist に載るシステムプロセス（`systemd` / `init` / `launchd` など）は不可。
    ///   Linux では孤児が最寄りの subreaper（`systemd --user` など、PID 1 ではない）へ
    ///   付け替えられるため、PID だけを見ると、それが信頼ルートになってユーザーセッション
    ///   全体が子孫扱いになる。PID 1 を拒否しているのと同じ理由で除外する。
    ///   利用者が追加した denylist は保護対象の指定であって信頼ルートの適格性とは別なので
    ///   含めない（`node` を保護しただけで Node 製エージェントがルートになれなくなるため）。
    fn is_eligible_auto_root(process: &ProcessInfo) -> bool {
        Self::is_valid_root_pid(process.pid)
            && !Config::default_denylist()
                .iter()
                .any(|entry| denylist_entry_matches(entry, &process.name))
    }

    /// 設定済みルート PID を返す
    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// 子孫判定に使っているプロセスの snapshot を返す
    ///
    /// `PolicyEngine` は対象の取得と ancestry の判定にこの同じ snapshot を使う。
    /// 別々に取ると、その間に終了した子孫が ancestry 側の snapshot にだけ居なくなり、
    /// 消えただけの対象を「セッション外」(`NotDescendant`) と誤って報告してしまう。
    pub(crate) fn provider(&self) -> &ProcessInfoProvider {
        &self.provider
    }

    /// 指定された `provider` snapshot 内で信頼ルートの identity 同一性を検証する内部ヘルパー。
    ///
    /// 以下のいずれかが成立しなければ `false`（fail-closed）を返す:
    /// - 信頼ルート PID が妥当（PID 0/1 は不可）
    /// - 初期 identity を保持している
    /// - 渡された provider snapshot から取得した identity と `pid + start_time + name` が一致
    ///
    /// 識別子検証と子孫判定を同一 snapshot 上で行えるようにすることで、両者の間に
    /// 発生し得る微小な TOCTOU 窓を最小化する（別タイミングの snapshot を 2 つ使うと、
    /// その間隔で信頼ルート PID が再利用された場合に、identity 検証は通過したが
    /// 子孫判定は別プロセスの親子関係を見ている、という不整合が起こりうる）。
    /// kill 直前の `is_descendant_fresh` は snapshot ではなくチェーンの往復検証で同じ
    /// 不整合を防ぐ（[`Self::verify_fresh_chain`]）。
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
    /// 長寿命の `AncestryChecker`（ライブラリ利用シナリオ）で、信頼ルート（エージェント）が
    /// 終了して同じ PID が別プロセスに割り当てられた場合に、認可境界が別プロセス配下へ
    /// 移るのを防ぐ。
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
    /// `AncestryChecker` 構築時の親子関係 snapshot に依存せず、対象から信頼ルートまでの
    /// 親チェーンを OS から 1 プロセスずつ取り直して検証する（[`Self::verify_fresh_chain`]）。
    /// 判定〜kill の間に対象プロセスが再ペアレントされて信頼ルート外に出たケースや、
    /// 信頼ルート・途中の祖先の PID が別プロセスへ再利用されたケースを捕捉できる。
    ///
    /// 以前は呼び出しのたびに全プロセスの snapshot を作り直していた（macOS の約 900
    /// プロセスで 1 回約 30ms）。`--name` は許可された一致ごとにこれを呼ぶため、
    /// 一致 200 件で約 6 秒かかっていた。チェーンだけを取り直せば対象ごとの
    /// コストは親チェーンの深さに比例する。全プロセスの snapshot も OS 全体を
    /// 一時点で固めたものではなく、各プロセスを順に読んだ結果なので、チェーンを
    /// 往復で検証する方が「途中で何かが変わった」ことを明示的に検出できる。
    ///
    /// 信頼ルートの初期 identity を持たない（PID 0/1、初期取得失敗、`refresh` で
    /// 不一致を検出済み）場合は常に `false`（fail-closed）。
    pub fn is_descendant_fresh(&self, target_pid: u32) -> bool {
        if !Self::is_valid_root_pid(self.root_pid) {
            return false;
        }
        let Some(root) = &self.root_identity else {
            return false;
        };
        Self::verify_fresh_chain(ProcessInfoProvider::fetch_fresh, target_pid, root)
    }

    /// 対象から信頼ルートまでの親チェーンを取り直して検証する本体
    ///
    /// 1. 対象から親をたどり、各ノードの identity（`pid + start_time + name`）と親 PID を
    ///    記録する。PID 0/1 への到達・循環・深度上限超過・取得失敗はその時点で拒否する。
    /// 2. 到達したルートの identity が、構築時に固定した信頼ルートと一致することを確かめる。
    /// 3. ルートから対象へ逆順に取り直し、各ノードの identity と親子関係が 1 の記録から
    ///    変わっていないことを確かめる（対象を最後に確かめるので kill までの窓が短い）。
    ///
    /// 2 回の観測の間に変化して元へ戻った場合や、検証後の変化は検出できない。
    /// 呼び出し側（`PolicyEngine`）は、この後に対象の identity を判定時の値とも照合する。
    ///
    /// 取得関数を引数で受け取るのは、取得のたびに結果が変わる状況（途中の祖先の
    /// PID 再利用や再ペアレント）を固定のシナリオで検証できるようにするため。
    fn verify_fresh_chain(
        mut fetch: impl FnMut(u32) -> Option<ProcessInfo>,
        target_pid: u32,
        root: &ProcessInfo,
    ) -> bool {
        let mut chain: Vec<ProcessInfo> = Vec::new();
        let mut pid = target_pid;

        // 対象自身に加えて最大 MAX_ANCESTRY_DEPTH ホップ先まで（`is_descendant_of_with_lookup` と同じ上限）
        for _ in 0..=MAX_ANCESTRY_DEPTH {
            // PID 1（init/launchd）より外へは進まない。PID 0 は実プロセスではない。
            if !Self::is_valid_root_pid(pid) || chain.iter().any(|node| node.pid == pid) {
                return false;
            }
            let Some(node) = fetch(pid).filter(|node| node.pid == pid) else {
                return false;
            };

            if pid == root.pid {
                if !node.is_same_process(root) {
                    return false;
                }
                chain.push(node);
                return Self::chain_is_unchanged(&mut fetch, &chain, root.pid);
            }

            let Some(parent_pid) = node.parent_pid else {
                return false;
            };
            chain.push(node);
            pid = parent_pid;
        }

        // 最大深度超過
        false
    }

    /// 記録したチェーンをルート側から取り直し、identity と親子関係が変わっていないか確かめる
    ///
    /// ルート自身の親は認可の条件ではない（ルートより外は見ない）ので比べない。
    fn chain_is_unchanged(
        fetch: &mut impl FnMut(u32) -> Option<ProcessInfo>,
        chain: &[ProcessInfo],
        root_pid: u32,
    ) -> bool {
        chain.iter().rev().all(|recorded| {
            fetch(recorded.pid).is_some_and(|fresh| {
                recorded.is_same_process(&fresh)
                    && (recorded.pid == root_pid || recorded.parent_pid == fresh.parent_pid)
            })
        })
    }

    /// 親チェーンをたどる木探索の本体（`ancestor_pid` の妥当性は確認済み前提）
    ///
    /// 内部 provider を使った既存挙動を維持するためのシム。
    fn is_descendant_of_unchecked(&self, target_pid: u32, ancestor_pid: u32) -> bool {
        Self::is_descendant_of_with_provider(&self.provider, target_pid, ancestor_pid)
    }

    /// 任意の `provider` を使った木探索本体
    fn is_descendant_of_with_provider(
        provider: &ProcessInfoProvider,
        target_pid: u32,
        ancestor_pid: u32,
    ) -> bool {
        Self::is_descendant_of_with_lookup(|pid| provider.get(pid), target_pid, ancestor_pid)
    }

    /// PID からプロセス情報を引く関数に対する木探索本体
    ///
    /// `target_pid` から親 PID チェーンをたどり、以下の条件で停止する:
    /// - `ancestor_pid` に到達した（`true`）
    /// - PID 1（init/launchd）に到達した（`false`）
    /// - 最大深度を超えた（`false`）
    /// - プロセス情報が取得できない（`false`）
    ///
    /// `ProcessInfoProvider` ではなく参照関数を受け取るのは、停止条件そのものを
    /// 検証できるようにするため。深度上限・親 PID の循環・PID 1 到達はいずれも
    /// 実プロセスツリーでは意図的に作れず、provider 直結のままだと
    /// 「ループ条件を壊してもテストが通る」状態になる。
    fn is_descendant_of_with_lookup(
        lookup: impl Fn(u32) -> Option<ProcessInfo>,
        target_pid: u32,
        ancestor_pid: u32,
    ) -> bool {
        // 存在しない PID を「自分自身の子孫」と誤判定しないよう、同一 PID 判定より
        // 前に対象プロセスが snapshot 内に存在することを確認する。
        if lookup(target_pid).is_none() {
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
            let Some(info) = lookup(current_pid) else {
                // プロセスが見つからない
                return false;
            };

            // 親 PID を取得
            let Some(parent_pid) = info.parent_pid else {
                // 親なし（孤立プロセスまたは init）
                return false;
            };

            // 親が目的の祖先でも、その PID が snapshot から消えていれば拒否する。
            // 親 PID の値だけでは、祖先プロセスの実在を証明できない。
            if parent_pid == ancestor_pid {
                return lookup(ancestor_pid).is_some();
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
        if let Some(info) = self.provider.get(current_pid)
            && let Some(parent_pid) = info.parent_pid
            && target_pid == parent_pid
        {
            return true;
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
    use std::collections::HashMap;

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
        if let Some(info) = checker.provider.get(current_pid)
            && let Some(parent_pid) = info.parent_pid
        {
            assert!(checker.is_descendant_of(current_pid, parent_pid));
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

        if let Some(info) = checker.provider.get(current_pid)
            && let Some(parent_pid) = info.parent_pid
        {
            assert!(checker.is_suicide(parent_pid));
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

    // =====================================================================
    // 木探索の停止条件テスト
    //
    // 深度上限・親 PID の循環・PID 1 到達は、実プロセスツリーでは意図的に
    // 作れない。固定ツリーを `is_descendant_of_with_lookup` へ注入して、
    // 停止条件そのものが効いていることを固定する。
    // =====================================================================

    /// `(pid, parent_pid)` の組からテスト用のプロセスツリーを組み立てる
    fn build_tree(entries: &[(u32, Option<u32>)]) -> HashMap<u32, ProcessInfo> {
        entries
            .iter()
            .map(|&(pid, parent_pid)| {
                (
                    pid,
                    ProcessInfo {
                        pid,
                        parent_pid,
                        name: format!("proc{pid}"),
                        cmd: Vec::new(),
                        start_time: 0,
                    },
                )
            })
            .collect()
    }

    /// 一直線の親子チェーンを構築する
    ///
    /// `base` が末端（探索の起点）で、そこから `hops` 段だけ親方向へ連なる。
    /// 最上位（`base + hops`）の親は `top_parent`。
    fn linear_chain(base: u32, hops: u32, top_parent: Option<u32>) -> HashMap<u32, ProcessInfo> {
        let mut entries: Vec<(u32, Option<u32>)> =
            (0..hops).map(|i| (base + i, Some(base + i + 1))).collect();
        entries.push((base + hops, top_parent));
        build_tree(&entries)
    }

    #[test]
    fn test_is_descendant_detects_ancestor_at_max_depth() {
        // 深度上限ちょうど（末端から MAX_ANCESTRY_DEPTH ホップ上）の祖先は検出できる。
        // 上限を下げる変更が入れば、正当な子孫が kill できなくなる形で検出される。
        let tree = linear_chain(1000, MAX_ANCESTRY_DEPTH, None);
        assert!(AncestryChecker::is_descendant_of_with_lookup(
            |pid| tree.get(&pid).cloned(),
            1000,
            1000 + MAX_ANCESTRY_DEPTH
        ));
    }

    #[test]
    fn test_is_descendant_stops_beyond_max_depth() {
        // 1 ホップ超えたら実在する祖先でも探索を打ち切る（fail-closed）。
        let hops = MAX_ANCESTRY_DEPTH + 1;
        let tree = linear_chain(1000, hops, None);
        assert!(!AncestryChecker::is_descendant_of_with_lookup(
            |pid| tree.get(&pid).cloned(),
            1000,
            1000 + hops
        ));
    }

    #[test]
    fn test_is_descendant_terminates_on_parent_cycle() {
        // 親 PID が循環していても無限ループしない。PID 再利用が起きた直後の
        // snapshot では、親子関係が循環して見えることがある。
        let tree = build_tree(&[(10, Some(11)), (11, Some(10))]);
        assert!(!AncestryChecker::is_descendant_of_with_lookup(
            |pid| tree.get(&pid).cloned(),
            10,
            9999
        ));
    }

    #[test]
    fn test_is_descendant_stops_at_pid_one() {
        // 親チェーンが PID 1（init/launchd）へ到達したら、その先は追わない。
        // ここを外すと「init に到達する全プロセス」が子孫扱いになり、
        // ancestry の安全境界が消える（fail-open）。
        let tree = build_tree(&[(10, Some(1)), (1, Some(999)), (999, None)]);
        assert!(!AncestryChecker::is_descendant_of_with_lookup(
            |pid| tree.get(&pid).cloned(),
            10,
            999
        ));
    }

    #[test]
    fn test_is_descendant_false_when_chain_is_broken() {
        // 途中の親が snapshot から消えていたら子孫扱いしない。
        let tree = build_tree(&[(10, Some(11))]);
        assert!(!AncestryChecker::is_descendant_of_with_lookup(
            |pid| tree.get(&pid).cloned(),
            10,
            12
        ));
    }

    #[test]
    fn test_is_descendant_false_when_direct_ancestor_disappeared() {
        // 親 PID が一致しても、祖先そのものが snapshot に存在しなければ拒否する。
        let tree = build_tree(&[(10, Some(11))]);
        assert!(!AncestryChecker::is_descendant_of_with_lookup(
            |pid| tree.get(&pid).cloned(),
            10,
            11
        ));
    }

    #[test]
    fn test_is_descendant_false_when_parent_is_unknown() {
        // 親 PID が不明なプロセスは、どの祖先の子孫とも判定しない。
        let tree = build_tree(&[(10, None)]);
        assert!(!AncestryChecker::is_descendant_of_with_lookup(
            |pid| tree.get(&pid).cloned(),
            10,
            11
        ));
    }

    // =====================================================================
    // 信頼ルート自動検出（detect_root_pid）のテスト
    //
    // 実プロセスツリーでは「親がシェルか」「祖父が PID 1 / subreaper か」を
    // 選べないため、名前付きの固定ツリーを注入して規則そのものを固定する。
    // =====================================================================

    /// テスト用のプロセス情報を作る
    fn process(pid: u32, parent_pid: Option<u32>, name: &str, start_time: u64) -> ProcessInfo {
        ProcessInfo {
            pid,
            parent_pid,
            name: name.to_string(),
            cmd: Vec::new(),
            start_time,
        }
    }

    /// `(pid, parent_pid, name)` の組から名前付きのプロセスツリーを組み立てる
    fn named_tree(entries: &[(u32, Option<u32>, &str)]) -> HashMap<u32, ProcessInfo> {
        entries
            .iter()
            .map(|&(pid, parent_pid, name)| (pid, process(pid, parent_pid, name, 1)))
            .collect()
    }

    fn detect_root(tree: &HashMap<u32, ProcessInfo>, current_pid: u32) -> u32 {
        AncestryChecker::detect_root_pid(|pid| tree.get(&pid).cloned(), current_pid)
    }

    /// プラットフォームの既定 denylist に載る（システムプロセス扱いの）名前
    fn system_process_name() -> String {
        Config::default_denylist()
            .into_iter()
            .next()
            .expect("既定 denylist は空ではない")
    }

    #[test]
    fn test_detect_root_pid_uses_agent_above_tool_shell() {
        // エージェント(20) → ツール用シェル(50) → safe-kill(100) の通常の構造。
        let tree = named_tree(&[
            (100, Some(50), "safe-kill"),
            (50, Some(20), "zsh"),
            (20, Some(5), "claude"),
            (5, Some(1), "zsh"),
        ]);
        assert_eq!(detect_root(&tree, 100), 20);
    }

    #[test]
    fn test_detect_root_pid_keeps_agent_when_shell_execed_into_safe_kill() {
        // `sh -c 'safe-kill …'` はシェルが safe-kill を exec するので、親がエージェント自身になる。
        // ここで祖父（エージェントを起動した端末のシェル 5）を採ると、エージェントの
        // 兄弟プロセスまで子孫扱いになる。親を信頼ルートにするべき。
        let tree = named_tree(&[
            (100, Some(20), "safe-kill"),
            (20, Some(5), "codex"),
            (5, Some(1), "zsh"),
        ]);
        assert_eq!(detect_root(&tree, 100), 20);
    }

    #[test]
    fn test_detect_root_pid_accepts_login_shell_name() {
        // sysinfo の名前に `-` は通常付かないが、comm を `-zsh` に書き換えた場合もシェルとして扱う
        let tree = named_tree(&[
            (100, Some(50), "safe-kill"),
            (50, Some(20), "-zsh"),
            (20, Some(5), "agent"),
        ]);
        assert_eq!(detect_root(&tree, 100), 20);
    }

    #[test]
    fn test_detect_root_pid_falls_back_to_shell_when_grandparent_is_pid_one() {
        // 祖父が PID 1（init/launchd）なら信頼ルートにせず、シェル自身へ倒す。
        let tree = named_tree(&[
            (100, Some(50), "safe-kill"),
            (50, Some(1), "bash"),
            (1, None, "init"),
        ]);
        assert_eq!(detect_root(&tree, 100), 50);
    }

    #[test]
    fn test_detect_root_pid_rejects_system_process_as_grandparent() {
        // Linux の孤児は PID 1 ではない subreaper（`systemd --user` など）へ付け替えられる。
        // PID だけで判定するとそれが信頼ルートになり、ユーザーセッション全体が子孫扱いになる。
        let system = system_process_name();
        let tree = named_tree(&[
            (100, Some(50), "safe-kill"),
            (50, Some(900), "sh"),
            (900, Some(1), &system),
        ]);
        assert_eq!(detect_root(&tree, 100), 50);
    }

    #[test]
    fn test_detect_root_pid_falls_back_to_current_when_parent_is_ineligible() {
        // 親がシステムプロセス（シェルではない）なら、親も祖父も採らず自プロセスへ倒す。
        let system = system_process_name();
        let tree = named_tree(&[(100, Some(900), "safe-kill"), (900, Some(1), &system)]);
        assert_eq!(detect_root(&tree, 100), 100);

        // 親が PID 1 の場合も同じ（コンテナで直接起動された場合など）
        let tree = named_tree(&[(100, Some(1), "safe-kill"), (1, None, "node")]);
        assert_eq!(detect_root(&tree, 100), 100);
    }

    #[test]
    fn test_detect_root_pid_falls_back_to_current_when_parent_is_unknown() {
        // 親の情報を取得できなければ、外側へ広げずに自プロセスへ倒す。
        let tree = named_tree(&[(100, Some(50), "safe-kill")]);
        assert_eq!(detect_root(&tree, 100), 100);
        let tree = named_tree(&[(100, None, "safe-kill")]);
        assert_eq!(detect_root(&tree, 100), 100);
    }

    #[test]
    fn test_is_shell_process_name() {
        for name in ["sh", "bash", "zsh", "dash", "fish", "-bash", "-zsh"] {
            assert!(is_shell_process_name(name), "{name} はシェル扱いするべき");
        }
        for name in ["node", "python3", "codex", "busybox", "--zsh", "zsh5", ""] {
            assert!(!is_shell_process_name(name), "{name} はシェル扱いしない");
        }
    }

    // =====================================================================
    // kill 直前の親チェーン検証（verify_fresh_chain）のテスト
    //
    // 取得のたびに結果が変わる状況（途中の祖先の PID 再利用・再ペアレント・消失）は
    // 実プロセスでは意図的に作れない。呼び出し回数で返す内容を切り替える取得関数を
    // 注入して、往復の再確認が変化を検出することを固定する。
    // =====================================================================

    /// 対象(10) → 中間(11) → 信頼ルート(12) のチェーン
    fn stable_chain() -> HashMap<u32, ProcessInfo> {
        [
            process(10, Some(11), "worker", 30),
            process(11, Some(12), "npm", 20),
            process(12, Some(5), "agent", 10),
        ]
        .into_iter()
        .map(|p| (p.pid, p))
        .collect()
    }

    /// 最初の `first_calls` 回は `first` を、以降は `second` を返す取得関数
    fn changing_fetch(
        first: HashMap<u32, ProcessInfo>,
        first_calls: usize,
        second: HashMap<u32, ProcessInfo>,
    ) -> impl FnMut(u32) -> Option<ProcessInfo> {
        let mut calls = 0;
        move |pid| {
            calls += 1;
            if calls <= first_calls {
                first.get(&pid).cloned()
            } else {
                second.get(&pid).cloned()
            }
        }
    }

    #[test]
    fn test_verify_fresh_chain_accepts_stable_chain() {
        let tree = stable_chain();
        let root = tree[&12].clone();
        assert!(AncestryChecker::verify_fresh_chain(
            |pid| tree.get(&pid).cloned(),
            10,
            &root
        ));
        // 対象が信頼ルート自身でも、identity が一致すれば子孫とみなす
        assert!(AncestryChecker::verify_fresh_chain(
            |pid| tree.get(&pid).cloned(),
            12,
            &root
        ));
    }

    #[test]
    fn test_verify_fresh_chain_rejects_reused_root_pid() {
        // 信頼ルートの PID が別プロセス（起動時刻が違う）に再利用されていたら拒否する
        let tree = stable_chain();
        let original_root = process(12, Some(5), "agent", 9);
        assert!(!AncestryChecker::verify_fresh_chain(
            |pid| tree.get(&pid).cloned(),
            10,
            &original_root
        ));
    }

    #[test]
    fn test_verify_fresh_chain_rejects_ancestor_replaced_between_passes() {
        // 往路（3 回の取得）の後に中間の祖先 11 が終了し、同じ PID が別プロセスになった
        let first = stable_chain();
        let mut second = stable_chain();
        second.insert(11, process(11, Some(12), "npm", 21));
        let root = first[&12].clone();
        assert!(!AncestryChecker::verify_fresh_chain(
            changing_fetch(first, 3, second),
            10,
            &root
        ));
    }

    #[test]
    fn test_verify_fresh_chain_rejects_target_reparented_between_passes() {
        // 往路の後に対象が信頼ルートの外へ付け替えられた（親が PID 1 になった）
        let first = stable_chain();
        let mut second = stable_chain();
        second.insert(10, process(10, Some(1), "worker", 30));
        let root = first[&12].clone();
        assert!(!AncestryChecker::verify_fresh_chain(
            changing_fetch(first, 3, second),
            10,
            &root
        ));
    }

    #[test]
    fn test_verify_fresh_chain_rejects_target_vanished_before_recheck() {
        // 往路の後に対象が終了した
        let first = stable_chain();
        let mut second = stable_chain();
        second.remove(&10);
        let root = first[&12].clone();
        assert!(!AncestryChecker::verify_fresh_chain(
            changing_fetch(first, 3, second),
            10,
            &root
        ));
    }

    #[test]
    fn test_verify_fresh_chain_rejects_cycle_pid_one_and_missing_parent() {
        let root = process(12, Some(5), "agent", 10);

        // 親 PID が循環している（PID 再利用直後に起こり得る）
        let cycle: HashMap<u32, ProcessInfo> =
            [process(10, Some(11), "a", 1), process(11, Some(10), "b", 1)]
                .into_iter()
                .map(|p| (p.pid, p))
                .collect();
        assert!(!AncestryChecker::verify_fresh_chain(
            |pid| cycle.get(&pid).cloned(),
            10,
            &root
        ));

        // チェーンが PID 1 に到達したら、その先は追わない
        let via_init: HashMap<u32, ProcessInfo> = [
            process(10, Some(1), "a", 1),
            process(1, Some(12), "init", 1),
            root.clone(),
        ]
        .into_iter()
        .map(|p| (p.pid, p))
        .collect();
        assert!(!AncestryChecker::verify_fresh_chain(
            |pid| via_init.get(&pid).cloned(),
            10,
            &root
        ));

        // 親 PID が不明・途中の祖先が取得できない
        let orphan: HashMap<u32, ProcessInfo> = [process(10, None, "a", 1)]
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        assert!(!AncestryChecker::verify_fresh_chain(
            |pid| orphan.get(&pid).cloned(),
            10,
            &root
        ));
        let broken: HashMap<u32, ProcessInfo> = [process(10, Some(11), "a", 1), root.clone()]
            .into_iter()
            .map(|p| (p.pid, p))
            .collect();
        assert!(!AncestryChecker::verify_fresh_chain(
            |pid| broken.get(&pid).cloned(),
            10,
            &root
        ));
    }

    #[test]
    fn test_verify_fresh_chain_respects_max_depth() {
        // `is_descendant_of_with_lookup` と同じく、上限ちょうどの祖先は検出し、1 ホップ超えたら拒否する
        let tree = linear_chain(1000, MAX_ANCESTRY_DEPTH, None);
        let root = tree[&(1000 + MAX_ANCESTRY_DEPTH)].clone();
        assert!(AncestryChecker::verify_fresh_chain(
            |pid| tree.get(&pid).cloned(),
            1000,
            &root
        ));

        let hops = MAX_ANCESTRY_DEPTH + 1;
        let tree = linear_chain(1000, hops, None);
        let root = tree[&(1000 + hops)].clone();
        assert!(!AncestryChecker::verify_fresh_chain(
            |pid| tree.get(&pid).cloned(),
            1000,
            &root
        ));
    }

    #[test]
    fn test_is_descendant_fresh_follows_real_child() {
        // 実プロセスでも、子は自プロセスを信頼ルートにした fresh 判定で子孫になり、
        // 逆向き（子を信頼ルートにして自プロセスを判定）は子孫にならない。
        let mut child = std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("sleep の起動に失敗");
        let current_pid = ProcessInfoProvider::current_pid();

        let from_current = AncestryChecker::with_root_pid(ProcessInfoProvider::new(), current_pid);
        let child_is_descendant = from_current.is_descendant_fresh(child.id());
        let from_child = AncestryChecker::with_root_pid(ProcessInfoProvider::new(), child.id());
        let current_is_descendant = from_child.is_descendant_fresh(current_pid);

        let _ = child.kill();
        let _ = child.wait();
        assert!(child_is_descendant, "自プロセスの子は子孫であるべき");
        assert!(!current_is_descendant, "親は子の子孫ではない");
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
    // 長寿命の AncestryChecker（ライブラリ利用シナリオ）で、信頼ルート
    // （エージェント）が終了して同じ PID が別プロセスに割り当てられた場合に、
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
        // 現在プロセスを root にすれば、kill 直前の親チェーンの往復検証でも自分自身が
        // 子孫として true になる（target == ancestor でも、取り直した identity が
        // 構築時の identity と一致する必要がある）。
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

    // =====================================================================
    // SAFE_KILL_ROOT_PID の解釈の境界
    //
    // u32 として読めない値・0・1 は無視して自動検出に倒す。読める値は、生きた
    // プロセスを指さなくても明示されたルートとして採用し、identity が取れないので
    // 親子関係では何も kill できない（自動検出に置き換えて範囲を広げない）。
    // =====================================================================

    #[test]
    fn test_parse_root_pid_fixes_current_interpretation_at_the_edges() {
        // `u32::from_str` は先頭の `+` を受け付ける
        assert_eq!(AncestryChecker::parse_root_pid("+42"), Some(42));
        assert_eq!(AncestryChecker::parse_root_pid("+1"), None);
        // u32 の上限ちょうどは読める（PID にはなり得ないが、明示されたルートとして扱う）
        assert_eq!(
            AncestryChecker::parse_root_pid("4294967295"),
            Some(u32::MAX)
        );
        assert_eq!(AncestryChecker::parse_root_pid("4294967296"), None);
        // 全角数字や桁区切りは数字として読まない
        assert_eq!(AncestryChecker::parse_root_pid("４２"), None);
        assert_eq!(AncestryChecker::parse_root_pid("1_000"), None);
    }

    #[test]
    fn test_unusable_explicit_root_allows_no_descendants() {
        // PID になり得ない値・生きていない PID を明示されたルートにすると、identity が
        // 取れず、現在のプロセスさえ子孫として扱わない（fail-closed）
        let current_pid = ProcessInfoProvider::current_pid();
        for root_pid in [u32::MAX, i32::MAX as u32 + 1, 999_999_999] {
            let checker = AncestryChecker::with_root_pid(ProcessInfoProvider::new(), root_pid);
            assert!(
                !checker.is_descendant(current_pid),
                "ルート {root_pid} では子孫を認めないべき"
            );
            assert!(!checker.is_descendant_fresh(current_pid), "{root_pid}");
            assert!(!checker.verify_root_identity_unchanged(), "{root_pid}");
        }
    }

    // =====================================================================
    // 信頼ルートの自動検出の追加の形
    // =====================================================================

    #[test]
    fn test_detect_root_pid_uses_shell_when_grandparent_is_missing() {
        // 親はシェルだが、祖父が snapshot に無い（取得の間に終了した等）。外側へは探さず、
        // 適格な親（シェル）をルートにする
        let tree = named_tree(&[(100, Some(50), "safe-kill"), (50, Some(20), "zsh")]);
        assert_eq!(detect_root(&tree, 100), 50);
    }

    #[test]
    fn test_detect_root_pid_climbs_only_one_shell() {
        // シェルが 2 段続いても、さかのぼるのは祖父までの 1 段だけ（外側のシェルがルート）
        let tree = named_tree(&[
            (100, Some(50), "safe-kill"),
            (50, Some(40), "bash"),
            (40, Some(20), "sh"),
            (20, Some(5), "agent"),
        ]);
        assert_eq!(detect_root(&tree, 100), 40);
    }

    #[test]
    fn test_detect_root_pid_falls_back_to_current_when_pid_one_is_a_shell() {
        // コンテナで PID 1 が sh のとき、親（PID 1）はシェルでも信頼ルートにできない。
        // 祖父も無いので、現在のプロセスに倒す
        let tree = named_tree(&[(100, Some(1), "safe-kill"), (1, None, "sh")]);
        assert_eq!(detect_root(&tree, 100), 100);
    }

    // =====================================================================
    // kill 直前の親チェーンの往復検証の追加の形
    // =====================================================================

    #[test]
    fn test_verify_fresh_chain_fetches_up_then_back_down() {
        // 往路で対象から信頼ルートへ、復路で信頼ルートから対象へ取り直す
        let tree = stable_chain();
        let root = tree[&12].clone();
        let mut fetched = Vec::new();
        assert!(AncestryChecker::verify_fresh_chain(
            |pid| {
                fetched.push(pid);
                tree.get(&pid).cloned()
            },
            10,
            &root
        ));
        assert_eq!(fetched, vec![10, 11, 12, 12, 11, 10]);
    }

    #[test]
    fn test_verify_fresh_chain_ignores_change_of_roots_own_parent() {
        // 信頼ルート自身の親は比べない（エージェントの起動元が終了して付け替えられても、
        // ルートの identity が同じなら認可の境界は変わらない）
        let mut reparented_root = stable_chain();
        reparented_root.insert(12, process(12, Some(1), "agent", 10));
        let root = stable_chain()[&12].clone();
        assert!(AncestryChecker::verify_fresh_chain(
            changing_fetch(stable_chain(), 3, reparented_root),
            10,
            &root
        ));
    }

    #[test]
    fn test_verify_fresh_chain_rejects_root_changed_or_gone_on_way_back() {
        let root = stable_chain()[&12].clone();

        // 往路の後で信頼ルートの PID が別プロセスに再利用された
        let mut replaced_root = stable_chain();
        replaced_root.insert(12, process(12, Some(5), "agent", 99));
        assert!(!AncestryChecker::verify_fresh_chain(
            changing_fetch(stable_chain(), 3, replaced_root),
            10,
            &root
        ));

        // 往路の後で信頼ルートが終了した
        let mut root_gone = stable_chain();
        root_gone.remove(&12);
        assert!(!AncestryChecker::verify_fresh_chain(
            changing_fetch(stable_chain(), 3, root_gone),
            10,
            &root
        ));
    }

    #[test]
    fn test_verify_fresh_chain_rejects_answer_for_another_pid() {
        // 取得関数が別の PID の情報を返したら、その情報で親子関係をたどらない
        let tree = stable_chain();
        let root = tree[&12].clone();
        assert!(!AncestryChecker::verify_fresh_chain(
            |pid| {
                if pid == 11 {
                    tree.get(&12).cloned()
                } else {
                    tree.get(&pid).cloned()
                }
            },
            10,
            &root
        ));
    }
}
