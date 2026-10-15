//! safe-kill のポリシーエンジン
//!
//! ancestry、config、自殺防止を組み合わせた kill 許可判定を統括する。

use std::cmp::Reverse;
use std::collections::HashSet;

use crate::ancestry::AncestryChecker;
use crate::config::Config;
use crate::error::SafeKillError;
use crate::killer::{BatchKillResult, KillResult, ProcessKiller};
use crate::port::PortDetector;
use crate::process_info::{ProcessInfo, ProcessInfoProvider};
use crate::signal::Signal;

/// kill 許可判定の結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillPermission {
    /// kill 許可（ancestry チェックによる）
    Allowed,
    /// kill 許可（allowlist に含まれるプロセス）
    AllowedByAllowlist,
    /// kill 拒否（denylist に含まれるプロセス）
    DeniedByDenylist(String),
    /// kill 拒否（root の子孫ではない）
    DeniedNotDescendant,
    /// kill 拒否（自プロセスまたは親プロセスの kill）
    DeniedSuicidePrevention,
}

/// kill 直前の最終安全検証における ancestry 再評価の要否
///
/// boolean ではなく enum とすることで、呼び出し側が「ancestry をバイパス」する
/// 意図を明示的に表現できるようにする（安全側に倒すデフォルトを取り違えにくくする）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalAncestryCheck {
    /// 信頼ルート配下に「今も」あるかを再評価する。対象から信頼ルートまでの親チェーンを
    /// `fetch_fresh` で 1 プロセスずつ往復して取り直す（`AncestryChecker::is_descendant_fresh`。
    /// 全プロセスの snapshot は作らない）。
    /// PID/名前指定で `KillPermission::Allowed`（ancestry 経由）で許可された場合に使う。
    Required,
    /// ancestry 再評価をバイパスする。設計上 ancestry を適用しない経路で使う:
    /// - `KillPermission::AllowedByAllowlist`（allowlist は ancestry バイパス）
    /// - ポート指定 kill（明示的に ancestry をバイパス）
    Bypassed,
}

impl FinalAncestryCheck {
    /// 許可判定結果から ancestry 再評価の要否を決定する。
    ///
    /// 拒否系の値が渡された場合は `Err(SystemError)` を返す（呼び出し側は
    /// `is_allowed()` で分岐済みなので通常は到達しないが、将来の呼び出し漏れを
    /// 早期検出するため fail-loud にする）。`Bypassed` フォールバックにすると
    /// 拒否系を弱い最終検証にすり抜けさせる経路が残るため避ける。
    fn try_from_permission(permission: &KillPermission) -> Result<Self, SafeKillError> {
        match permission {
            KillPermission::Allowed => Ok(Self::Required),
            KillPermission::AllowedByAllowlist => Ok(Self::Bypassed),
            _ => Err(SafeKillError::SystemError(
                "unexpected denied permission reached final ancestry check".to_string(),
            )),
        }
    }
}

impl KillPermission {
    /// kill が許可されているかを確認する
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            KillPermission::Allowed | KillPermission::AllowedByAllowlist
        )
    }

    /// kill が拒否されているかを確認する
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }

    /// 拒否系の判定結果を、対応する `SafeKillError` に変換する
    ///
    /// `pid` は対象 PID、`name` は対象プロセスの表示名。
    /// 許可系（`Allowed` / `AllowedByAllowlist`）には対応するエラーがないため、
    /// 呼び出し側で `is_allowed()` による分岐を済ませてから使うこと。
    /// 万一許可系が渡された場合は防御的に `SystemError` を返す（fail-closed）。
    fn to_error(&self, pid: u32, name: &str) -> SafeKillError {
        match self {
            KillPermission::DeniedByDenylist(denied_name) => {
                SafeKillError::Denylisted(denied_name.clone())
            }
            KillPermission::DeniedNotDescendant => {
                SafeKillError::NotDescendant(pid, name.to_string())
            }
            KillPermission::DeniedSuicidePrevention => SafeKillError::SuicidePrevention(pid),
            KillPermission::Allowed | KillPermission::AllowedByAllowlist => {
                SafeKillError::SystemError("Unexpected permission".to_string())
            }
        }
    }
}

/// kill 許可判定を統括するポリシーエンジン
pub struct PolicyEngine {
    config: Config,
    /// 子孫判定と、対象の取得・一覧・名前検索に共用するプロセスの snapshot を持つ
    /// （[`PolicyEngine::provider`] を参照）
    ancestry: AncestryChecker,
    killer: ProcessKiller,
    port_detector: PortDetector,
}

impl PolicyEngine {
    /// 指定された設定で PolicyEngine を生成する
    pub fn new(mut config: Config) -> Self {
        config.merge_defaults();

        let ancestry = AncestryChecker::new(ProcessInfoProvider::new());
        let killer = ProcessKiller::new();
        let port_detector = PortDetector::new();

        Self {
            config,
            ancestry,
            killer,
            port_detector,
        }
    }

    /// 対象の取得・一覧・名前検索に使うプロセスの snapshot
    ///
    /// 子孫判定 (`AncestryChecker`) と同じ snapshot を使う。以前は対象の取得用に別の
    /// snapshot を取っていたため、2 回の取得の間に終了した子孫が「取得用には居るが
    /// 子孫判定用には居ない」状態になり、消えただけの対象を `NotDescendant`
    /// （終了コード 255、セッション外）と報告していた。正しくは `ProcessNotFound`（1）。
    fn provider(&self) -> &ProcessInfoProvider {
        self.ancestry.provider()
    }

    /// デフォルト設定で PolicyEngine を生成する
    pub fn with_defaults() -> Self {
        Self::new(Config::load())
    }

    /// 設定ファイルエラーを呼び出し元へ返して PolicyEngine を生成する
    pub fn try_with_defaults() -> Result<Self, SafeKillError> {
        Ok(Self::new(Config::try_load()?))
    }

    /// プロセス情報を更新する
    ///
    /// 対象の取得にも子孫判定の snapshot を使うので、snapshot の取り直しは ancestry 側の
    /// `refresh()` だけで済む（信頼ルートの identity が変わっていれば以後は fail-closed）。
    pub fn refresh(&mut self) {
        self.ancestry.refresh();
        self.port_detector.refresh();
    }

    /// プロセスを kill 可能か判定する
    pub fn can_kill(&self, process: &ProcessInfo) -> KillPermission {
        // 1. 自殺防止チェック（最優先）
        if self.ancestry.is_suicide(process.pid) {
            return KillPermission::DeniedSuicidePrevention;
        }

        // 2. denylist チェック（2番目の優先度）
        if self.config.is_denied(&process.name) {
            return KillPermission::DeniedByDenylist(process.name.clone());
        }

        // 3. PID 1（init/launchd 相当）は常に保護する
        //    コンテナ環境では PID 1 が `node` / `python` などの非標準プロセスになり
        //    既定 denylist に入らないことがある。その場合でも allowlist 経由や
        //    ポート kill 経路で PID 1 を kill するとコンテナ全体を巻き添えにする
        //    ため、ancestry / allowlist 判定より手前で fail-closed する。
        if process.pid <= 1 {
            return KillPermission::DeniedNotDescendant;
        }

        // 4. 信頼ルート自体は子孫プロセスではないため保護する
        if process.pid == self.ancestry.root_pid() {
            return KillPermission::DeniedNotDescendant;
        }

        // 5. allowlist チェック（ancestry チェックをバイパス）
        if self.config.is_allowed(&process.name) {
            return KillPermission::AllowedByAllowlist;
        }

        // 6. ancestry チェック（デフォルトのチェック）
        if self.ancestry.is_descendant(process.pid) {
            return KillPermission::Allowed;
        }

        KillPermission::DeniedNotDescendant
    }

    /// PID を指定してプロセスを kill する
    pub fn kill_by_pid(
        &self,
        pid: u32,
        signal: Signal,
        dry_run: bool,
    ) -> Result<KillResult, SafeKillError> {
        // PID 0 はプロセスグループを表し、i32 超過値は nix::Pid に安全に渡せない。
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(SafeKillError::InvalidPid(pid.to_string()));
        }

        // プロセス情報を取得
        let process = self
            .provider()
            .get(pid)
            .ok_or(SafeKillError::ProcessNotFound(pid))?;

        // 許可判定
        let permission = self.can_kill(&process);
        if permission.is_allowed() {
            // 判定後・kill 前に、自殺防止（最新の親 PID 解決）、ancestry 再評価
            // （Allowed の場合のみ）、PID 再利用検出を最終ガードとしてまとめて再検証する。
            // dry-run でも、ユーザーへの誤った成功表示を避けるために検証する。
            let ancestry_check = FinalAncestryCheck::try_from_permission(&permission)?;
            self.verify_final_safety_before_kill(&process, ancestry_check)?;
            Ok(self
                .killer
                .kill_with_result(pid, &process.name, signal, dry_run))
        } else {
            Err(self.denial_error(&process, &permission))
        }
    }

    /// PID 指定・名前指定の経路で、拒否系の判定結果を返すエラーに変える
    ///
    /// `DeniedNotDescendant` のときだけ、先に対象の同一性（`pid + start_time + name`）を
    /// OS から取り直して確かめ、判定に使った snapshot の後で対象が終了した（または PID が
    /// 別プロセスへ再利用された）なら `ProcessNotFound`（終了コード 1）を返す。消えただけの
    /// 対象を `NotDescendant`（終了コード 255、セッション外）と報告すると、呼び出し側が
    /// 権限の問題と誤解する。kill 直前の ancestry 再評価（`verify_final_safety_before_kill`）
    /// と同じ分類にそろえる。
    ///
    /// この確認で拒否を許可に変えたりシグナルを送ったりはしない。denylist と自殺防止の
    /// 拒否は対象の生死に関係なく保護の理由なので、分類し直さない。
    fn denial_error(&self, process: &ProcessInfo, permission: &KillPermission) -> SafeKillError {
        if *permission == KillPermission::DeniedNotDescendant
            && let Err(e) = self.verify_identity_before_kill(process)
        {
            return e;
        }
        permission.to_error(process.pid, &process.name)
    }

    /// kill 直前のプロセス同一性検証
    ///
    /// ポリシー判定に使った `expected` と、OS から取得した最新情報を比較する。
    /// PID 再利用や対象プロセスの消失を検出した場合は `ProcessNotFound` を返し、
    /// fail-closed（誤って別プロセスへシグナルを送らない）を保証する。
    ///
    /// 注意（残るレース）:
    ///
    /// - 検証から実際の `kill(2)` までの間（マイクロ秒オーダー）に PID が再利用
    ///   された場合は検出できない。完全に閉じるには Linux の `pidfd_open` +
    ///   `pidfd_send_signal` のような、PID ではなくプロセス実体に結びついた
    ///   識別子が必要。
    /// - `start_time` は秒精度のため、同一秒内に同名プロセスへ PID が再利用
    ///   された場合は検出できない。実用上は極めて稀。
    fn verify_identity_before_kill(&self, expected: &ProcessInfo) -> Result<(), SafeKillError> {
        let fresh = ProcessInfoProvider::fetch_fresh(expected.pid)
            .ok_or(SafeKillError::ProcessNotFound(expected.pid))?;
        if !fresh.is_same_process(expected) {
            return Err(SafeKillError::ProcessNotFound(expected.pid));
        }
        Ok(())
    }

    /// kill 直前の自殺防止最終ガード
    ///
    /// `can_kill` / `can_kill_for_port` の `is_suicide` 判定は PolicyEngine 構築時の
    /// スナップショットに基づく早期拒否であり、判定～kill の間に現在プロセスの親が
    /// 変化（元の親の終了に伴う再ペアレント）した場合を捕捉できない。
    /// この関数は signal 送信直前に現在プロセスと「最新の」親 PID を OS から取得し直し、
    /// 対象が自プロセスまたは現在の親であれば `SuicidePrevention` として fail-closed する。
    ///
    /// 現在プロセス情報の取得に失敗した場合も、安全側に倒して `SystemError` で拒否する。
    fn verify_not_suicide_before_kill(target_pid: u32) -> Result<(), SafeKillError> {
        let current_pid = ProcessInfoProvider::current_pid();

        // 自分自身は現在プロセス情報の取得成否に関わらず、必ず拒否する（最も確実な保護）。
        if target_pid == current_pid {
            return Err(SafeKillError::SuicidePrevention(target_pid));
        }

        // 現在プロセスの最新情報を取得し、親 PID を fresh に確認する。
        // 取得できない場合は安全側に倒して fail-closed する。
        let current = ProcessInfoProvider::fetch_fresh(current_pid).ok_or_else(|| {
            SafeKillError::SystemError(
                "failed to resolve current process during suicide prevention".to_string(),
            )
        })?;

        Self::check_parent_not_suicide(target_pid, current.parent_pid)
    }

    /// 自殺防止の親判定（純粋関数）
    ///
    /// 対象が現在の親プロセスであれば `SuicidePrevention` を返す。
    /// 親 PID が不明（`None`）な場合は「対象が現在の親ではない」と証明できないため、
    /// fail-closed の原則に従い `SystemError` で拒否する（親なしと取得失敗を区別できないため）。
    fn check_parent_not_suicide(
        target_pid: u32,
        current_parent_pid: Option<u32>,
    ) -> Result<(), SafeKillError> {
        // 親 PID が不明な場合は安全側に倒して fail-closed する。
        let parent_pid = current_parent_pid.ok_or_else(|| {
            SafeKillError::SystemError(
                "failed to resolve current parent process during suicide prevention".to_string(),
            )
        })?;

        // 最新の親 PID が対象と一致すれば自殺行為として拒否
        if parent_pid == target_pid {
            return Err(SafeKillError::SuicidePrevention(target_pid));
        }

        Ok(())
    }

    /// kill 直前の最終安全検証（自殺防止 + ancestry 再評価 + プロセス同一性）
    ///
    /// signal 送信直前の最終ガードとして、以下を fresh な OS 情報で再検証し
    /// fail-closed を保証する:
    /// 1. 自殺防止（最新の親 PID 解決による自プロセス・親プロセス保護）
    /// 2. ancestry 再評価（`ancestry_check == Required` のときのみ）
    ///    対象から信頼ルートまでの親チェーンを `fetch_fresh` で往復して取り直し、各ノードの
    ///    identity と親子関係、到達した信頼ルートの identity を確かめる
    ///    （`AncestryChecker::is_descendant_fresh`）。`PolicyEngine` 構築時の snapshot に
    ///    依存しないため、判定〜kill 間の対象プロセス再ペアレントを捕捉できる。
    /// 3. PID 再利用検出（`pid + start_time + name` の同一性）
    ///
    /// 順序は「自殺防止 → ancestry 再評価 → 同一性」とし、もっとも重要な保護を
    /// 先に実行する。ancestry 再評価で拒否するときだけは、同一性を先に確かめて
    /// 「対象が消えた」と「子孫ではない」を区別する。
    fn verify_final_safety_before_kill(
        &self,
        expected: &ProcessInfo,
        ancestry_check: FinalAncestryCheck,
    ) -> Result<(), SafeKillError> {
        Self::verify_not_suicide_before_kill(expected.pid)?;

        if ancestry_check == FinalAncestryCheck::Required
            && !self.ancestry.is_descendant_fresh(expected.pid)
        {
            // 判定後に対象が終了した（または PID が別プロセスへ再利用された）場合も、
            // fresh な子孫判定は false になる。そのまま `NotDescendant` を返すと、
            // 消えただけの対象を「セッション外のプロセス」と報告して終了コードも 255 になり、
            // 呼び出し側が権限の問題と誤解する。同一性を先に確かめ、消えた対象は
            // `ProcessNotFound` として返す。同一性が一致してもシグナルは送らない。
            self.verify_identity_before_kill(expected)?;
            return Err(SafeKillError::NotDescendant(
                expected.pid,
                expected.name.clone(),
            ));
        }

        self.verify_identity_before_kill(expected)
    }

    /// プロセス名を指定して kill する
    pub fn kill_by_name(
        &self,
        name: &str,
        signal: Signal,
        dry_run: bool,
    ) -> Result<BatchKillResult, SafeKillError> {
        let processes = self.provider().find_by_name(name);

        if processes.is_empty() {
            return Err(SafeKillError::ProcessNameNotFound(name.to_string()));
        }

        // 同名の親子が一致したときに子を孤児として残さないよう、子孫から先に処理する
        // （理由と限界は `order_descendants_first` を参照）
        let provider = self.provider();
        let order = order_descendants_first(&processes, |pid| {
            provider.get(pid).and_then(|process| process.parent_pid)
        });

        let mut results = Vec::with_capacity(processes.len());
        for index in order {
            let process = &processes[index];
            let permission = self.can_kill(process);

            let result = if permission.is_allowed() {
                // kill 直前の最終ガード（自殺防止の再確認 + ancestry 再評価 +
                // PID 再利用検出）。`Allowed` の場合のみ ancestry を再評価する。
                // 拒否系の permission が紛れ込んでも try_from_permission が
                // SystemError として失敗扱いにするため、バッチ全体は壊れない。
                match FinalAncestryCheck::try_from_permission(&permission)
                    .and_then(|check| self.verify_final_safety_before_kill(process, check))
                {
                    Ok(()) => {
                        self.killer
                            .kill_with_result(process.pid, &process.name, signal, dry_run)
                    }
                    Err(err) => KillResult::failure(process.pid, &process.name, &err),
                }
            } else {
                // 拒否されたプロセスの失敗結果を生成
                let error = self.denial_error(process, &permission);
                KillResult::failure(process.pid, &process.name, &error)
            };

            results.push(result);
        }

        // 処理は子孫からでも、表示は従来どおり PID 昇順にする（繰り返し実行しても同じ並び）
        results.sort_by_key(|result| result.pid);
        let mut batch_result = BatchKillResult::new();
        for result in results {
            batch_result.add(result);
        }

        Ok(batch_result)
    }

    /// ポートを指定してプロセスを kill する
    ///
    /// 注意: ancestry チェックと allowlist は適用しない。ポート指定の kill はプロセスの
    /// ancestry に関係なく特定のサービスを対象とするため。自殺防止・denylist・PID 1 の保護・
    /// 信頼ルートの保護（`can_kill_for_port`）と、kill 直前のポート保持の再確認・同一性の
    /// 検証は適用する。
    pub fn kill_by_port(
        &self,
        port: u16,
        signal: Signal,
        dry_run: bool,
    ) -> Result<BatchKillResult, SafeKillError> {
        // 1. config でポートが許可されているか確認
        self.config.check_port_allowed(port)?;

        // 2. ポート上のプロセスを検索
        let port_processes = self.port_detector.find_by_port(port)?;

        if port_processes.is_empty() {
            return Err(SafeKillError::NoProcessOnPort(port));
        }

        Ok(self.kill_port_processes(port, port_processes, signal, dry_run))
    }

    /// 検出済みの `PortProcess` 一覧から kill を実行する内部ヘルパー
    ///
    /// `kill_by_port` の中身を切り出してテスト容易性を高めるために存在する。
    /// 名前解決失敗時の fail-closed 挙動と、各 PID の kill 直前のポート保持再検証を担う。
    fn kill_port_processes(
        &self,
        port: u16,
        port_processes: Vec<crate::port::PortProcess>,
        signal: Signal,
        dry_run: bool,
    ) -> BatchKillResult {
        let mut batch_result = BatchKillResult::new();

        // 各プロセスに対して、ancestry と allowlist を除いた保護（自殺防止・denylist・
        // PID 1・信頼ルート）を適用する
        for pp in port_processes {
            // プロセス情報が取得できない PID は denylist 名前一致を回避するために
            // 即座に失敗扱いにする（fail-closed）。
            // PortDetector のフォールバック名（"pid:<pid>"）で denylist 判定すると
            // 名前不明なプロセスがバイパスされてしまうため。
            let Some(process) = self.provider().get(pp.pid) else {
                let error = SafeKillError::ProcessNotFound(pp.pid);
                batch_result.add(KillResult::failure(pp.pid, &pp.name, &error));
                continue;
            };

            // 許可判定（自殺防止・denylist・PID 1・信頼ルート。ancestry と allowlist は見ない）
            let permission = self.can_kill_for_port(pp.pid, &process.name);

            let result = if permission.is_allowed() {
                // ポート kill 固有の TOCTOU 緩和は「保持確認 → 同一性確認 → kill」の順で行う。
                // 1. ポート保持確認 (pid_holds_port): バッチ実行中に対象がポートを離した場合は kill しない。
                //    取得失敗時は安全側に倒して fail-closed（NoProcessOnPort）。
                // 2. 最終安全検証 (verify_final_safety_before_kill): 自殺防止（最新の親 PID 解決）と
                //    `pid + start_time + name` の同一性を OS から取り直して再検証する。順序を最後に
                //    することで、ポート確認に要する時間内に起きた再ペアレントや PID 再利用も検出できる。
                // ポート指定 kill は ancestry をバイパスするため、PID/名前指定より TOCTOU リスクが高い。
                if !self.port_detector.pid_holds_port(pp.pid, port, pp.protocol) {
                    let err = SafeKillError::NoProcessOnPort(port);
                    KillResult::failure(pp.pid, &process.name, &err)
                } else {
                    // ポート kill は ancestry を意図的にバイパスする設計のため、
                    // 最終ガードでも ancestry 再評価は行わない（Bypassed）。
                    match self
                        .verify_final_safety_before_kill(&process, FinalAncestryCheck::Bypassed)
                    {
                        Ok(()) => {
                            self.killer
                                .kill_with_result(pp.pid, &process.name, signal, dry_run)
                        }
                        Err(err) => KillResult::failure(pp.pid, &process.name, &err),
                    }
                }
            } else {
                let error = permission.to_error(pp.pid, &process.name);
                KillResult::failure(pp.pid, &process.name, &error)
            };

            batch_result.add(result);
        }

        batch_result
    }

    /// ポート指定 kill 用のプロセス kill 可否判定
    ///
    /// 以下の簡略化されたチェックのみ適用:
    /// 1. 自殺防止（自プロセス・親プロセスの kill 不可）
    /// 2. denylist チェック
    /// 3. PID 1 保護（コンテナ環境での巻き添え防止）
    /// 4. root PID 保護（信頼ルート自体の kill 不可）
    ///
    /// ancestry 走査や allowlist は適用しない（ポート指定 kill 用）。
    fn can_kill_for_port(&self, pid: u32, name: &str) -> KillPermission {
        // 1. 自殺防止チェック（最優先）
        if self.ancestry.is_suicide(pid) {
            return KillPermission::DeniedSuicidePrevention;
        }

        // 2. denylist チェック
        if self.config.is_denied(name) {
            return KillPermission::DeniedByDenylist(name.to_string());
        }

        // 3. PID 1（init/launchd 相当）は常に保護する
        //    コンテナ環境では PID 1 が非標準プロセスとして denylist 外になる
        //    ことがある。ポート kill は ancestry をバイパスするため、ここで
        //    明示的に PID 1 を拒否しないとコンテナ全体を巻き添えにする。
        if pid <= 1 {
            return KillPermission::DeniedNotDescendant;
        }

        // 4. 信頼ルート自体はポート指定でも終了対象にしない
        if pid == self.ancestry.root_pid() {
            return KillPermission::DeniedNotDescendant;
        }

        // 拒否されなければポート指定 kill は許可
        KillPermission::Allowed
    }

    /// kill 可能な全プロセスを一覧する
    pub fn list_killable(&self) -> Vec<ProcessInfo> {
        self.provider()
            .all()
            .into_iter()
            .filter(|p| self.can_kill(p).is_allowed())
            .collect()
    }

    /// 現在の root PID を取得する
    pub fn root_pid(&self) -> u32 {
        self.ancestry.root_pid()
    }

    /// 設定への参照を取得する
    pub fn config(&self) -> &Config {
        &self.config
    }
}

/// 名前指定の kill で一致したプロセスを、子孫から先に処理する順に並べる（`processes` の添字を返す）
///
/// 同名の親子が一致したとき、親を先に kill すると子が init（や subreaper）に付け替えられ、
/// 子は kill 直前の ancestry 再評価で「セッション外」として拒否されて孤児のまま残る
/// （npm → node、jest のワーカーなど。実測で SIGKILL では毎回起きた）。判定時の snapshot の
/// 親チェーン（`parent_of`）から各対象の深さを求め、深い順に、同じ深さは PID 昇順に処理する。
/// 一致しない中間の祖先がいてもチェーンをたどる。循環は訪問済みの PID で止め、親が分からない
/// ところで止める。深さは並べ替えにだけ使い、認可の根拠にはしない（認可は各対象の kill 直前の
/// `can_kill` と `verify_final_safety_before_kill` が行う）。
///
/// 子を再起動するスーパーバイザーの完全停止までは保証しない。最初の snapshot に無い新しい子は
/// 対象にならず、再走査や再試行もしない（対象を広げ、再起動との競争が終わらなくなるため）。
fn order_descendants_first(
    processes: &[ProcessInfo],
    parent_of: impl Fn(u32) -> Option<u32>,
) -> Vec<usize> {
    let depth = |pid: u32| {
        let mut visited = HashSet::new();
        let mut current = pid;
        while visited.insert(current) {
            match parent_of(current) {
                Some(parent) => current = parent,
                None => break,
            }
        }
        // 訪問したのは自分と祖先なので、祖先の数が深さになる
        visited.len() - 1
    };

    let mut keyed: Vec<(usize, usize)> = processes
        .iter()
        .enumerate()
        .map(|(index, process)| (index, depth(process.pid)))
        .collect();
    keyed.sort_by_key(|&(index, depth)| (Reverse(depth), processes[index].pid));
    keyed.into_iter().map(|(index, _)| index).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProcessList;

    // KillPermission のテスト
    #[test]
    fn test_kill_permission_allowed() {
        assert!(KillPermission::Allowed.is_allowed());
        assert!(!KillPermission::Allowed.is_denied());
    }

    #[test]
    fn test_kill_permission_allowed_by_allowlist() {
        assert!(KillPermission::AllowedByAllowlist.is_allowed());
        assert!(!KillPermission::AllowedByAllowlist.is_denied());
    }

    #[test]
    fn test_kill_permission_denied_by_denylist() {
        let perm = KillPermission::DeniedByDenylist("systemd".to_string());
        assert!(!perm.is_allowed());
        assert!(perm.is_denied());
    }

    #[test]
    fn test_kill_permission_denied_not_descendant() {
        assert!(!KillPermission::DeniedNotDescendant.is_allowed());
        assert!(KillPermission::DeniedNotDescendant.is_denied());
    }

    #[test]
    fn test_kill_permission_denied_suicide() {
        assert!(!KillPermission::DeniedSuicidePrevention.is_allowed());
        assert!(KillPermission::DeniedSuicidePrevention.is_denied());
    }

    // KillPermission::to_error 変換テスト
    // 拒否系の判定結果が、対応する SafeKillError に正しく変換されることを検証する。
    // kill_by_pid / kill_by_name / kill_port_processes が共有する変換ロジックのため、
    // 各バリアントの変換結果をここで一元的に保証する。
    #[test]
    fn test_kill_permission_to_error_denylist() {
        let perm = KillPermission::DeniedByDenylist("systemd".to_string());
        assert_eq!(
            perm.to_error(1234, "systemd"),
            SafeKillError::Denylisted("systemd".to_string())
        );
    }

    #[test]
    fn test_kill_permission_to_error_not_descendant() {
        // NotDescendant には対象 PID と表示名の両方が含まれるべき
        let perm = KillPermission::DeniedNotDescendant;
        assert_eq!(
            perm.to_error(1234, "nginx"),
            SafeKillError::NotDescendant(1234, "nginx".to_string())
        );
    }

    #[test]
    fn test_kill_permission_to_error_suicide() {
        let perm = KillPermission::DeniedSuicidePrevention;
        assert_eq!(
            perm.to_error(5678, "bash"),
            SafeKillError::SuicidePrevention(5678)
        );
    }

    #[test]
    fn test_kill_permission_to_error_allowed_falls_back_to_system_error() {
        // 許可系が渡された場合は防御的に SystemError を返す（fail-closed）。
        // 通常は is_allowed() で分岐済みのため、この経路には到達しない。
        assert!(matches!(
            KillPermission::Allowed.to_error(1, "x"),
            SafeKillError::SystemError(_)
        ));
        assert!(matches!(
            KillPermission::AllowedByAllowlist.to_error(1, "x"),
            SafeKillError::SystemError(_)
        ));
    }

    #[test]
    fn test_kill_permission_clone() {
        let perm = KillPermission::Allowed;
        let cloned = perm.clone();
        assert_eq!(perm, cloned);
    }

    #[test]
    fn test_kill_permission_debug() {
        let perm = KillPermission::Allowed;
        let debug_str = format!("{:?}", perm);
        assert!(debug_str.contains("Allowed"));
    }

    // PolicyEngine 構築テスト
    #[test]
    fn test_policy_engine_new() {
        let config = Config::default();
        let engine = PolicyEngine::new(config);
        assert!(engine.root_pid() > 0);
    }

    #[test]
    fn test_policy_engine_with_defaults() {
        let engine = PolicyEngine::with_defaults();
        assert!(engine.root_pid() > 0);
    }

    #[test]
    fn test_policy_engine_refresh() {
        let config = Config::default();
        let mut engine = PolicyEngine::new(config);
        engine.refresh();
        // パニックしないことを確認
    }

    #[test]
    fn test_policy_engine_config() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["node".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);
        assert!(engine.config().is_allowed("node"));
    }

    #[test]
    fn test_policy_engine_new_merges_default_denylist() {
        let engine = PolicyEngine::new(Config::default());

        for process in Config::default_denylist() {
            assert!(
                engine.config().is_denied(&process),
                "デフォルト denylist の {process} が PolicyEngine::new で合流されるべき"
            );
        }
    }

    fn engine_with_root_pid(mut config: Config, root_pid: u32) -> PolicyEngine {
        config.merge_defaults();

        PolicyEngine {
            config,
            ancestry: AncestryChecker::with_root_pid(ProcessInfoProvider::new(), root_pid),
            killer: ProcessKiller::new(),
            port_detector: PortDetector::new(),
        }
    }

    // can_kill のテスト
    #[test]
    fn test_can_kill_self_denied() {
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(process) = engine.provider().get(current_pid) {
            let permission = engine.can_kill(&process);
            assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
        }
    }

    #[test]
    fn test_can_kill_parent_denied() {
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(current) = engine.provider().get(current_pid)
            && let Some(parent_pid) = current.parent_pid
            && let Some(parent) = engine.provider().get(parent_pid)
        {
            let permission = engine.can_kill(&parent);
            assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
        }
    }

    #[test]
    fn test_can_kill_denylisted() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["test_denied_process".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "test_denied_process".to_string(),
            cmd: vec![],
            start_time: 0,
        };

        match engine.can_kill(&process) {
            KillPermission::DeniedByDenylist(name) => {
                assert_eq!(name, "test_denied_process");
            }
            _ => panic!("Expected DeniedByDenylist"),
        }
    }

    #[test]
    fn test_can_kill_allowlisted() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["test_allowed_process".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "test_allowed_process".to_string(),
            cmd: vec![],
            start_time: 0,
        };

        // 自プロセスの PID だと自殺防止チェックに引っかかるため
        // 確実に自プロセスではない偽の PID を使用
        let permission = engine.can_kill(&process);
        assert_eq!(permission, KillPermission::AllowedByAllowlist);
    }

    #[test]
    fn test_can_kill_root_pid_denied_before_allowlist() {
        let root_pid = ProcessInfoProvider::current_pid().saturating_add(100_000);
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["trusted_root".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = engine_with_root_pid(config, root_pid);

        let process = ProcessInfo {
            pid: root_pid,
            parent_pid: None,
            name: "trusted_root".to_string(),
            cmd: vec![],
            start_time: 0,
        };

        // root PID は信頼境界であり、allowlist でも終了対象にしない。
        let permission = engine.can_kill(&process);
        assert_eq!(permission, KillPermission::DeniedNotDescendant);
    }

    #[test]
    fn test_denylist_takes_precedence_over_allowlist() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["conflicted_process".to_string()],
            }),
            denylist: Some(ProcessList {
                processes: vec!["conflicted_process".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "conflicted_process".to_string(),
            cmd: vec![],
            start_time: 0,
        };

        match engine.can_kill(&process) {
            KillPermission::DeniedByDenylist(_) => {}
            other => panic!("Expected DeniedByDenylist, got {:?}", other),
        }
    }

    // kill_by_pid のテスト
    #[test]
    fn test_kill_by_pid_not_found() {
        let engine = PolicyEngine::new(Config::default());
        let result = engine.kill_by_pid(999999999, Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::ProcessNotFound(_))));
    }

    #[test]
    fn test_kill_by_pid_zero_rejected_as_invalid() {
        let engine = PolicyEngine::new(Config::default());
        let result = engine.kill_by_pid(0, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::InvalidPid(_))));
    }

    #[test]
    fn test_kill_by_pid_over_i32_max_rejected_as_invalid() {
        let engine = PolicyEngine::new(Config::default());
        let result = engine.kill_by_pid(i32::MAX as u32 + 1, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::InvalidPid(_))));
    }

    #[test]
    fn test_kill_by_pid_self_prevented() {
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();
        // 自殺防止の判定はシグナル送信の前に行われるので dry-run でも同じ結果になる。
        // dry-run でなければ、自殺防止が退行したときにテストランナー自身が SIGTERM で落ちる。
        let result = engine.kill_by_pid(current_pid, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::SuicidePrevention(_))));
    }

    #[test]
    fn test_kill_by_pid_dry_run() {
        let engine = PolicyEngine::new(Config::default());
        // 存在しないプロセスに dry_run を使用 - プロセス未検出で失敗するはず
        let result = engine.kill_by_pid(999999999, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::ProcessNotFound(_))));
    }

    // kill_by_name のテスト
    #[test]
    fn test_kill_by_name_not_found() {
        let engine = PolicyEngine::new(Config::default());
        let result = engine.kill_by_name("__nonexistent_process__", Signal::SIGTERM, false);
        assert!(matches!(result, Err(SafeKillError::ProcessNameNotFound(_))));
    }

    // list_killable のテスト
    #[test]
    fn test_list_killable() {
        let engine = PolicyEngine::new(Config::default());
        let killable = engine.list_killable();

        // 自プロセスを含まないこと
        let current_pid = ProcessInfoProvider::current_pid();
        assert!(!killable.iter().any(|p| p.pid == current_pid));

        // 親プロセスを含まないこと
        if let Some(current) = engine.provider().get(current_pid)
            && let Some(parent_pid) = current.parent_pid
        {
            assert!(!killable.iter().any(|p| p.pid == parent_pid));
        }
    }

    #[test]
    fn test_list_killable_excludes_denylisted() {
        #[cfg(target_os = "macos")]
        {
            let engine = PolicyEngine::new(Config::default());
            let killable = engine.list_killable();

            // launchd を含まないこと（macOS のデフォルト denylist に含まれる）
            assert!(!killable.iter().any(|p| p.name == "launchd"));
        }

        #[cfg(target_os = "linux")]
        {
            let engine = PolicyEngine::new(Config::default());
            let killable = engine.list_killable();

            // systemd を含まないこと（Linux のデフォルト denylist に含まれる）
            assert!(!killable.iter().any(|p| p.name == "systemd"));
        }
    }

    // root PID のテスト
    #[test]
    fn test_root_pid() {
        let engine = PolicyEngine::new(Config::default());
        let root_pid = engine.root_pid();
        assert!(root_pid > 0);
    }

    // 許可優先順位のテスト
    #[test]
    fn test_permission_priority_suicide_over_denylist() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["safe-kill".to_string()], // 自プロセスを denylist に追加
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);
        let current_pid = ProcessInfoProvider::current_pid();

        if let Some(process) = engine.provider().get(current_pid) {
            let permission = engine.can_kill(&process);
            // 自殺防止が優先されるべき
            assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
        }
    }

    #[test]
    fn test_permission_priority_denylist_over_allowlist() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["both_listed".to_string()],
            }),
            denylist: Some(ProcessList {
                processes: vec!["both_listed".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "both_listed".to_string(),
            cmd: vec![],
            start_time: 0,
        };

        match engine.can_kill(&process) {
            KillPermission::DeniedByDenylist(_) => {}
            other => panic!("Expected DeniedByDenylist, got {:?}", other),
        }
    }

    // kill_by_port のテスト
    #[test]
    fn test_kill_by_port_no_process() {
        use crate::config::AllowedPorts;

        // 明示的な allowed_ports 設定（None はポート kill 無効を意味する）
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3010".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);
        // ポート 3009 は許可されているがプロセスが存在しない想定。
        // `--port` は ancestry を通らないため、開発者がこのポートでサーバーを動かして
        // いれば実 kill になってしまう。dry-run でも NoProcessOnPort の判定は同じ。
        let result = engine.kill_by_port(3009, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::NoProcessOnPort(3009))));
    }

    #[test]
    fn test_kill_by_port_no_config_disabled() {
        // allowed_ports が None の場合、ポート kill は完全に無効
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        // config が None の場合、すべてのポートで PortNotAllowed を返す。
        // 許可判定が退行しても 3000 番の開発サーバーを落とさないよう dry-run で検証する。
        let result = engine.kill_by_port(3000, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::PortNotAllowed { .. })));
    }

    #[test]
    fn test_kill_by_port_port_not_allowed() {
        use crate::config::AllowedPorts;

        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000".to_string(), "8080".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);

        // ポート 59996 は許可リストに含まれていない（退行しても実 kill しないよう dry-run）
        let result = engine.kill_by_port(59996, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::PortNotAllowed { .. })));
    }

    #[test]
    fn test_kill_by_port_with_allowed_config() {
        use crate::config::AllowedPorts;

        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["59995".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);

        // ポート 59995 は許可されているがプロセスが存在しない想定。
        // 一時ポートの範囲なので他アプリの UDP ソケットと重なり得る。実 kill にしない。
        let result = engine.kill_by_port(59995, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::NoProcessOnPort(59995))));
    }

    #[test]
    fn test_kill_by_port_dry_run_no_process() {
        use crate::config::AllowedPorts;

        // 明示的な allowed_ports 設定（None はポート kill 無効を意味する）
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3010".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);
        // dry_run でもプロセスの存在チェックは行われる
        let result = engine.kill_by_port(3008, Signal::SIGTERM, true);
        assert!(matches!(result, Err(SafeKillError::NoProcessOnPort(3008))));
    }

    // can_kill_for_port のテスト
    #[test]
    fn test_can_kill_for_port_allowed() {
        let engine = PolicyEngine::new(Config::default());
        // 自プロセスでも denylist にも含まれないランダムな PID
        let permission = engine.can_kill_for_port(99999, "random_process");
        assert_eq!(permission, KillPermission::Allowed);
    }

    #[test]
    fn test_can_kill_for_port_suicide_prevention() {
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();
        let permission = engine.can_kill_for_port(current_pid, "safe-kill");
        assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
    }

    #[test]
    fn test_can_kill_for_port_denylisted() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["denylisted_server".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let permission = engine.can_kill_for_port(99999, "denylisted_server");
        match permission {
            KillPermission::DeniedByDenylist(name) => {
                assert_eq!(name, "denylisted_server");
            }
            other => panic!("Expected DeniedByDenylist, got {:?}", other),
        }
    }

    #[test]
    fn test_can_kill_for_port_root_pid_denied() {
        let root_pid = ProcessInfoProvider::current_pid().saturating_add(100_000);
        let engine = engine_with_root_pid(Config::default(), root_pid);

        let permission = engine.can_kill_for_port(root_pid, "trusted_root");
        assert_eq!(permission, KillPermission::DeniedNotDescendant);
    }

    #[test]
    fn test_can_kill_for_port_no_ancestor_check() {
        // can_kill_for_port が ancestry チェックを行わないことを検証
        // 設計上の意図: ポート指定 kill は ancestry 走査を適用しない
        let engine = PolicyEngine::new(Config::default());

        // 確実に子孫ではないランダムなプロセス
        // denylist に含まれていなければ許可されるべき
        // 注意: macOS では "launchd" がデフォルト denylist に含まれる可能性がある
        // そのためこのテストでは汎用的な名前を使用
        let permission = engine.can_kill_for_port(99999, "some_random_server");
        assert_eq!(permission, KillPermission::Allowed);
    }

    #[test]
    fn test_can_kill_non_descendant_process() {
        let engine = PolicyEngine::new(Config::default());
        let process = ProcessInfo {
            pid: 99999,
            parent_pid: Some(1),
            name: "unrelated_process".to_string(),
            cmd: vec![],
            start_time: 0,
        };
        let permission = engine.can_kill(&process);
        // allowlist に含まれず、子孫でもない -> DeniedNotDescendant
        assert_eq!(permission, KillPermission::DeniedNotDescendant);
    }

    #[test]
    fn test_kill_by_pid_not_descendant() {
        // PID 1 は通常のセッションの子孫にはなり得ない。
        // 保護が退行しても PID 1 へシグナルを送らないよう dry-run で検証する。
        let engine = PolicyEngine::new(Config::default());
        let result = engine.kill_by_pid(1, Signal::SIGTERM, true);
        assert!(result.is_err());
        // DeniedByDenylist（launchd/systemd が denylist に含まれる）または SuicidePrevention の可能性
        match result {
            Err(SafeKillError::Denylisted(_))
            | Err(SafeKillError::SuicidePrevention(_))
            | Err(SafeKillError::NotDescendant(_, _)) => {}
            other => panic!("Expected denial error, got {:?}", other),
        }
    }

    #[test]
    fn test_can_kill_for_port_suicide_prevention_parent() {
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();
        if let Some(current) = engine.provider().get(current_pid)
            && let Some(parent_pid) = current.parent_pid
        {
            let permission = engine.can_kill_for_port(parent_pid, "parent_process");
            assert_eq!(permission, KillPermission::DeniedSuicidePrevention);
        }
    }

    #[test]
    fn test_can_kill_for_port_ignores_allowlist() {
        // allowlist に含まれていても、can_kill_for_port は AllowedByAllowlist を返さない
        // （ポート kill では allowlist バイパスは適用しない設計）
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["allowlisted_server".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        // allowlist に含まれるプロセスでも、Allowed（AllowedByAllowlist ではない）が返る
        let permission = engine.can_kill_for_port(99999, "allowlisted_server");
        assert_eq!(
            permission,
            KillPermission::Allowed,
            "can_kill_for_port は AllowedByAllowlist ではなく Allowed を返すべき"
        );
    }

    #[test]
    fn test_batch_result_error_multiple_policy_errors_only() {
        // 全てポリシーエラー（NotDescendant）のみの場合、NoKillableTarget にフォールバック
        let mut batch = BatchKillResult::new();
        batch.add(KillResult::failure(
            100,
            "proc_a",
            &SafeKillError::NotDescendant(100, "proc_a".to_string()),
        ));
        batch.add(KillResult::failure(
            200,
            "proc_b",
            &SafeKillError::NotDescendant(200, "proc_b".to_string()),
        ));

        // first_operational_error は NotDescendant をスキップするため None
        assert!(batch.first_operational_error().is_none());
    }

    #[test]
    fn test_kill_permission_eq_variants() {
        // 異なる DeniedByDenylist インスタンス間の等値性を検証
        let a = KillPermission::DeniedByDenylist("proc_a".to_string());
        let b = KillPermission::DeniedByDenylist("proc_a".to_string());
        let c = KillPermission::DeniedByDenylist("proc_b".to_string());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_list_killable_excludes_root_pid() {
        // 信頼ルート PID 自体は子孫扱いされず、kill 可能リストに含まれてはならない。
        let engine = PolicyEngine::new(Config::default());
        let root_pid = engine.root_pid();
        let killable = engine.list_killable();
        assert!(
            !killable.iter().any(|p| p.pid == root_pid),
            "root PID ({}) は kill 可能リストから除外されるべき",
            root_pid
        );
    }

    #[test]
    fn test_can_kill_root_pid_with_default_engine() {
        // デフォルト設定のエンジンでも、root PID 自体への kill は拒否される。
        let engine = PolicyEngine::new(Config::default());
        let root_pid = engine.root_pid();

        // root PID のプロセス情報が取得できる場合のみ検証（環境依存）
        if let Some(process) = engine.provider().get(root_pid) {
            let permission = engine.can_kill(&process);
            assert!(
                permission.is_denied(),
                "root PID ({}) は kill 拒否されるべき",
                root_pid
            );
        }
    }

    #[test]
    fn test_kill_by_pid_i32_max_boundary() {
        // i32::MAX は有効な PID 範囲だが、対応するプロセスが存在しないため
        // InvalidPid ではなく ProcessNotFound が返るべき。
        let engine = PolicyEngine::new(Config::default());
        let result = engine.kill_by_pid(i32::MAX as u32, Signal::SIGTERM, true);
        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(_))),
            "i32::MAX は有効な PID 値だが対応プロセスが存在しないため ProcessNotFound になるべき"
        );
    }

    // ポート指定 kill の名前解決失敗時 fail-closed 回帰テスト
    //
    // 過去のバグ: PortDetector のフォールバック名 "pid:<pid>" を denylist
    // 判定に使うと、名前不明なプロセスが denylist 保護をバイパスしていた。
    // 今後のリグレッションを防ぐため、フォールバック名のままでは絶対に
    // 許可判定に到達しないことを検証する。
    #[test]
    fn test_kill_port_processes_unknown_pid_fails_closed() {
        use crate::port::{PortProcess, PortProtocol};

        // 存在しない可能性が極めて高い PID
        let unknown_pid = 999_999_999u32;
        let placeholder_name = format!("pid:{}", unknown_pid);

        // この placeholder を denylist に登録しても、ロジック上 denylist チェックに
        // 到達せず ProcessNotFound として失敗するべき。
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec![placeholder_name.clone()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let port_processes = vec![PortProcess {
            pid: unknown_pid,
            name: placeholder_name.clone(),
            port: 3000,
            protocol: PortProtocol::Tcp,
        }];

        let batch = engine.kill_port_processes(3000, port_processes, Signal::SIGTERM, true);

        assert_eq!(batch.results.len(), 1);
        assert!(!batch.results[0].success);
        assert_eq!(
            batch.results[0].error,
            Some(SafeKillError::ProcessNotFound(unknown_pid)),
            "名前解決できない PID は ProcessNotFound で fail-closed されるべき (denylist バイパス防止)"
        );
        assert_eq!(
            batch.results[0].name, placeholder_name,
            "表示名としてはフォールバック名がそのまま残るべき"
        );
    }

    #[test]
    fn test_kill_port_processes_unknown_pid_does_not_match_real_denylist() {
        use crate::port::{PortProcess, PortProtocol};

        // フォールバック名で denylist 一致した場合に Denylisted エラーが返る
        // 経路を完全に塞いだことを検証する。
        let unknown_pid = 999_999_998u32;
        let placeholder_name = format!("pid:{}", unknown_pid);

        // フォールバック名と「実プロセス名らしき名前」両方を denylist に入れる
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec![placeholder_name.clone(), "denied_proc".to_string()],
            }),
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let port_processes = vec![PortProcess {
            pid: unknown_pid,
            name: placeholder_name.clone(),
            port: 3000,
            protocol: PortProtocol::Tcp,
        }];

        let batch = engine.kill_port_processes(3000, port_processes, Signal::SIGTERM, true);

        // ProcessNotFound で fail-closed されるため、Denylisted エラーには
        // ならないことを確認（denylist 判定そのものに到達してはならない）。
        assert!(
            !matches!(batch.results[0].error, Some(SafeKillError::Denylisted(_))),
            "プレースホルダ名で denylist 判定に到達してはならない"
        );
        assert_eq!(
            batch.results[0].error,
            Some(SafeKillError::ProcessNotFound(unknown_pid))
        );
    }

    /// kill 直前にポートを保持していない PID は kill されないことを保証する
    ///
    /// シナリオ: ポリシー判定の対象に渡された PID が、判定～kill の間に
    /// 対象ポートを離した（あるいは別の理由で対象ポートを持っていない）場合、
    /// ユーザーの意図（そのポートを解放したい）は既に達成されているため、
    /// 該当 PID は kill せず NoProcessOnPort として fail-closed する。
    #[test]
    fn test_kill_port_processes_skips_pid_not_holding_port() {
        use crate::port::{PortProcess, PortProtocol};
        use std::process::Command;

        // sleep プロセスを起動し、その PID をポート保持者として偽装する。
        // 実際にはポートを開いていないため、fresh_holders には含まれない。
        let mut child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("sleep プロセスの起動に失敗");
        let pid = child.id();

        // ポート 59990 は未使用想定（fresh_holders は空になるはず）。
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(crate::config::AllowedPorts {
                ports: vec!["59990".to_string()],
            }),
        };
        let engine = PolicyEngine::new(config);

        let port_processes = vec![PortProcess {
            pid,
            name: "sleep".to_string(),
            port: 59990,
            protocol: PortProtocol::Tcp,
        }];

        // dry_run=true で副作用なく検証する
        let batch = engine.kill_port_processes(59990, port_processes, Signal::SIGTERM, true);

        assert_eq!(batch.results.len(), 1);
        assert!(
            !batch.results[0].success,
            "ポートを保持していない PID は kill されないべき"
        );
        assert_eq!(
            batch.results[0].error,
            Some(SafeKillError::NoProcessOnPort(59990)),
            "kill 直前にポートを保持していなければ NoProcessOnPort で fail-closed されるべき"
        );

        // クリーンアップ
        let _ = child.kill();
        let _ = child.wait();
    }

    // =============================================================================
    // TOCTOU 検証（PID 再利用）の回帰テスト
    //
    // ポリシー判定後、kill 直前に対象プロセスが消えた・別プロセスに再利用された
    // ケースで、誤って認可外プロセスにシグナルが送られないことを保証する。
    // =============================================================================

    #[test]
    fn test_verify_identity_before_kill_succeeds_for_current_process() {
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();
        let process = engine
            .provider()
            .get(current_pid)
            .expect("現在プロセスが取得できるべき");

        // 直後に検証すれば必ず一致する
        let result = engine.verify_identity_before_kill(&process);
        assert!(
            result.is_ok(),
            "現在プロセスの直近スナップショットは同一性検証を通過すべき"
        );
    }

    #[test]
    fn test_verify_identity_before_kill_fails_when_pid_disappeared() {
        let engine = PolicyEngine::new(Config::default());
        // 存在しない可能性が極めて高い PID を使った擬似 ProcessInfo
        let stale = ProcessInfo {
            pid: 999_999_999,
            parent_pid: Some(1),
            name: "ghost_process".to_string(),
            cmd: vec![],
            start_time: 1,
        };
        let result = engine.verify_identity_before_kill(&stale);
        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(p)) if p == 999_999_999),
            "fetch_fresh で None になる PID は ProcessNotFound として失敗するべき"
        );
    }

    #[test]
    fn test_verify_identity_before_kill_fails_on_start_time_mismatch() {
        // PID 再利用シミュレーション: 現在プロセスの PID で、start_time だけ
        // 改ざんした擬似スナップショットを渡す。OS から取得し直した start_time
        // とは一致しないため、ProcessNotFound として fail-closed されるべき。
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();
        let mut tampered = engine
            .provider()
            .get(current_pid)
            .expect("現在プロセスが取得できるべき");
        tampered.start_time = tampered.start_time.wrapping_add(1);

        let result = engine.verify_identity_before_kill(&tampered);
        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(p)) if p == current_pid),
            "start_time が一致しなければ PID 再利用とみなして fail-closed すべき"
        );
    }

    #[test]
    fn test_verify_identity_before_kill_fails_on_name_mismatch() {
        // 同じ秒に PID 再利用された場合の補助検証として、名前が異なれば
        // 別プロセスと判定する。
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();
        let mut tampered = engine
            .provider()
            .get(current_pid)
            .expect("現在プロセスが取得できるべき");
        tampered.name = format!("{}_pretender", tampered.name);

        let result = engine.verify_identity_before_kill(&tampered);
        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(p)) if p == current_pid),
            "プロセス名が一致しなければ fail-closed すべき"
        );
    }

    // verify_not_suicide_before_kill / verify_final_safety_before_kill テスト
    // kill 直前の自殺防止最終ガードが、最新の親 PID をもとに自プロセス・親プロセスを
    // 拒否することを検証する（判定～kill 間の再ペアレントに対する fail-closed）。

    #[test]
    fn test_verify_not_suicide_before_kill_fails_for_self() {
        // 自分自身の PID は常に自殺防止で拒否される
        let current_pid = ProcessInfoProvider::current_pid();
        let result = PolicyEngine::verify_not_suicide_before_kill(current_pid);
        assert!(
            matches!(result, Err(SafeKillError::SuicidePrevention(pid)) if pid == current_pid),
            "自プロセスの kill は SuicidePrevention で拒否すべき"
        );
    }

    #[test]
    fn test_verify_not_suicide_before_kill_fails_for_current_parent() {
        // kill 直前に OS から取得した最新の親 PID は自殺防止で拒否される
        let current_pid = ProcessInfoProvider::current_pid();
        let parent_pid = ProcessInfoProvider::fetch_fresh(current_pid)
            .and_then(|p| p.parent_pid)
            .expect("現在プロセスには親が存在するべき");

        let result = PolicyEngine::verify_not_suicide_before_kill(parent_pid);
        assert!(
            matches!(result, Err(SafeKillError::SuicidePrevention(pid)) if pid == parent_pid),
            "現在の親プロセスの kill は SuicidePrevention で拒否すべき"
        );
    }

    #[test]
    fn test_verify_not_suicide_before_kill_allows_unrelated_pid() {
        // 自分でも親でもない PID は自殺防止を通過する（許可可否は別レイヤーで判定）。
        // 999_999_998 は通常の pid_max を超えるため、実在の自/親プロセス PID とは一致しない。
        let result = PolicyEngine::verify_not_suicide_before_kill(999_999_998);
        assert!(
            result.is_ok(),
            "自分でも親でもない PID は自殺防止を通過すべき"
        );
    }

    #[test]
    fn test_verify_final_safety_rejects_current_parent() {
        // 最終安全検証は、自殺防止（親）と同一性検証の複合ガードとして機能する。
        // 現在の親プロセスを対象にすると SuicidePrevention で拒否される。
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();
        let parent_pid = ProcessInfoProvider::fetch_fresh(current_pid)
            .and_then(|p| p.parent_pid)
            .expect("現在プロセスには親が存在するべき");

        // 親のスナップショット情報が取得できる場合のみ検証する
        if let Some(parent_info) = engine.provider().get(parent_pid) {
            let result =
                engine.verify_final_safety_before_kill(&parent_info, FinalAncestryCheck::Required);
            assert!(
                matches!(result, Err(SafeKillError::SuicidePrevention(pid)) if pid == parent_pid),
                "最終安全検証は現在の親プロセスを SuicidePrevention で拒否すべき"
            );
        }
    }

    // check_parent_not_suicide（純粋関数）テスト
    // 親 PID の一致・不一致・不明（None）の各分岐を OS 非依存で検証する。

    #[test]
    fn test_check_parent_not_suicide_rejects_matching_parent() {
        // 対象が現在の親 PID と一致すれば SuicidePrevention で拒否する
        let result = PolicyEngine::check_parent_not_suicide(100, Some(100));
        assert!(
            matches!(result, Err(SafeKillError::SuicidePrevention(pid)) if pid == 100),
            "対象が現在の親 PID と一致すれば自殺防止で拒否すべき"
        );
    }

    #[test]
    fn test_check_parent_not_suicide_allows_different_parent() {
        // 対象が現在の親 PID と異なれば通過する
        let result = PolicyEngine::check_parent_not_suicide(100, Some(200));
        assert!(
            result.is_ok(),
            "対象が現在の親と異なれば自殺防止を通過すべき"
        );
    }

    #[test]
    fn test_check_parent_not_suicide_fails_closed_on_unknown_parent() {
        // 親 PID が不明（None）な場合は fail-closed（SystemError）で拒否する。
        // 「親なし」と「取得失敗」を区別できないため、安全側に倒す。
        let result = PolicyEngine::check_parent_not_suicide(100, None);
        assert!(
            matches!(result, Err(SafeKillError::SystemError(_))),
            "親 PID 不明時は fail-closed（SystemError）すべき"
        );
    }

    // =========================================================================
    // FinalAncestryCheck / verify_final_safety_before_kill の回帰テスト
    //
    // ancestry の fresh 再評価が「ancestry 経由の許可（KillPermission::Allowed）」
    // でのみ Required になり、allowlist / port 経路では Bypassed になる仕様を保証する。
    // =========================================================================

    #[test]
    fn test_final_ancestry_check_try_from_allowed_is_required() {
        let result = FinalAncestryCheck::try_from_permission(&KillPermission::Allowed);
        assert_eq!(result, Ok(FinalAncestryCheck::Required));
    }

    #[test]
    fn test_final_ancestry_check_try_from_allowlist_is_bypassed() {
        // allowlist は設計上 ancestry をバイパスするため、最終ガードでも Bypassed。
        let result = FinalAncestryCheck::try_from_permission(&KillPermission::AllowedByAllowlist);
        assert_eq!(result, Ok(FinalAncestryCheck::Bypassed));
    }

    #[test]
    fn test_final_ancestry_check_try_from_denied_returns_error() {
        // 拒否系の permission は本来 verify_final_safety_before_kill へ到達しないが、
        // 将来の呼び出し漏れを早期検出するため Err(SystemError) で fail-loud にする。
        // Bypassed フォールバックにすると拒否系が弱い最終検証をすり抜ける経路が残るため避ける。
        let cases = [
            KillPermission::DeniedNotDescendant,
            KillPermission::DeniedSuicidePrevention,
            KillPermission::DeniedByDenylist("x".to_string()),
        ];
        for permission in cases {
            let result = FinalAncestryCheck::try_from_permission(&permission);
            assert!(
                matches!(result, Err(SafeKillError::SystemError(_))),
                "拒否系 permission {:?} は SystemError で fail-loud すべき",
                permission
            );
        }
    }

    /// テスト用に待機するだけの子プロセスを起動する
    ///
    /// `Command::spawn` は exec の成否を確認してから戻るので、戻った時点で
    /// プロセス名は `sleep` になっている。
    fn spawn_sleeper() -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("sleep の起動に失敗")
    }

    /// 自分で起動した子プロセスを終了させて回収する
    fn reap(mut child: std::process::Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn test_verify_final_safety_required_rejects_non_descendant_with_exact_error() {
        // ancestry_check=Required で、生きているが信頼ルートの子孫ではないプロセスを
        // 渡すと NotDescendant で拒否される。兄弟プロセスの一方を信頼ルートにし、
        // もう一方を対象にすることで、実在する非子孫を環境に依存せず作る。
        // （存在しない PID を使うと、それは「消えた対象」として ProcessNotFound になる）
        let root = spawn_sleeper();
        let sibling = spawn_sleeper();
        let engine = engine_with_root_pid(Config::default(), root.id());
        let target = engine
            .provider()
            .get(sibling.id())
            .expect("起動直後の兄弟プロセスは snapshot に含まれるはず");

        let result = engine.verify_final_safety_before_kill(&target, FinalAncestryCheck::Required);

        reap(root);
        reap(sibling);
        assert!(
            matches!(result, Err(SafeKillError::NotDescendant(pid, ref name))
                if pid == target.pid && name == &target.name),
            "生存中の非子孫は ancestry 段で NotDescendant に倒れるべき、実際: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_final_safety_reports_vanished_descendant_as_process_not_found() {
        // 許可判定の後に対象が終了すると、fresh な子孫判定も false になる。
        // それを NotDescendant（終了コード 255、「セッション外」）と報告せず、
        // ProcessNotFound（終了コード 1）として返すことを固定する。
        let child = spawn_sleeper();
        let engine = engine_with_root_pid(Config::default(), ProcessInfoProvider::current_pid());
        let target = engine
            .provider()
            .get(child.id())
            .expect("起動直後の子プロセスは snapshot に含まれるはず");
        reap(child);

        let result = engine.verify_final_safety_before_kill(&target, FinalAncestryCheck::Required);

        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(pid)) if pid == target.pid),
            "判定後に終了した対象は ProcessNotFound になるべき、実際: {:?}",
            result
        );
    }

    #[test]
    fn test_kill_by_pid_reports_target_exited_after_snapshot_as_not_found() {
        // PolicyEngine の snapshot には対象が残っているが、OS 上ではもう終了している状況。
        // can_kill は古い snapshot で Allowed を返し、kill 直前の再検証で不在に気付く。
        // dry-run なので、万一 PID が再利用されていてもシグナルは送らない。
        let child = spawn_sleeper();
        let pid = child.id();
        let engine = engine_with_root_pid(Config::default(), ProcessInfoProvider::current_pid());
        assert!(engine.provider().get(pid).is_some());
        reap(child);

        let result = engine.kill_by_pid(pid, Signal::SIGTERM, true);

        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(p)) if p == pid),
            "判定後に終了した対象は ProcessNotFound になるべき、実際: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_final_safety_bypassed_skips_ancestry_for_non_descendant() {
        // ancestry_check=Bypassed では、ancestry 経由の NotDescendant では拒否されない。
        // 順序: 自殺防止 → ancestry(skip) → 同一性 のため、ダミー PID は
        // 同一性検証段の ProcessNotFound で fail-closed される（NotDescendant ではない）。
        let engine = PolicyEngine::new(Config::default());
        let dummy = ProcessInfo {
            pid: 999_999_998,
            parent_pid: Some(1),
            name: "unrelated".to_string(),
            cmd: vec![],
            start_time: 0,
        };
        let result = engine.verify_final_safety_before_kill(&dummy, FinalAncestryCheck::Bypassed);
        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(pid)) if pid == dummy.pid),
            "Bypassed では ancestry 段をスキップして同一性段の ProcessNotFound で落ちるべき、実際: {:?}",
            result
        );
    }

    #[test]
    fn test_verify_final_safety_bypassed_still_rejects_self_kill() {
        // ancestry_check=Bypassed でも自殺防止は引き続き適用される。
        let engine = PolicyEngine::new(Config::default());
        let current_pid = ProcessInfoProvider::current_pid();
        if let Some(process) = engine.provider().get(current_pid) {
            let result =
                engine.verify_final_safety_before_kill(&process, FinalAncestryCheck::Bypassed);
            assert!(
                matches!(result, Err(SafeKillError::SuicidePrevention(pid)) if pid == current_pid),
                "Bypassed でも自殺防止は通過させてはならない"
            );
        }
    }

    // =========================================================================
    // PID 1（init/launchd 相当）保護の回帰テスト
    //
    // コンテナ環境では PID 1 が `node` / `python` などの非標準プロセスとなり、
    // 既定 denylist に入らないケースがある。その場合でも:
    //  - PID/名前指定の allowlist 経路（ancestry バイパス）
    //  - ポート kill 経路（設計上 ancestry バイパス）
    // で PID 1 を kill するとコンテナ全体が落ちるため、ancestry / allowlist 判定の
    // 手前で常に fail-closed する。安全境界の回帰として固定する。
    // =========================================================================

    #[test]
    fn test_can_kill_rejects_pid_one_even_when_allowlisted() {
        // PID 1 が allowlist 名と一致しても、ancestry / allowlist より手前で
        // NotDescendant として拒否されることを検証する。
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["node".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        let engine = PolicyEngine::new(config);

        let process = ProcessInfo {
            pid: 1,
            parent_pid: None,
            name: "node".to_string(),
            cmd: vec![],
            start_time: 0,
        };

        let permission = engine.can_kill(&process);
        assert_eq!(
            permission,
            KillPermission::DeniedNotDescendant,
            "PID 1 は allowlist 一致でも常に保護されるべき"
        );
    }

    #[test]
    fn test_can_kill_rejects_pid_one_even_when_not_in_default_denylist() {
        // 既定 denylist に含まれない名前（コンテナ環境の PID 1 を想定）の
        // PID 1 でも拒否されることを検証する。
        let engine = PolicyEngine::new(Config::default());

        let process = ProcessInfo {
            pid: 1,
            parent_pid: None,
            name: "custom_container_init".to_string(),
            cmd: vec![],
            start_time: 0,
        };

        let permission = engine.can_kill(&process);
        assert_eq!(
            permission,
            KillPermission::DeniedNotDescendant,
            "PID 1 は denylist 非該当の名前でも常に保護されるべき"
        );
    }

    #[test]
    fn test_can_kill_for_port_rejects_pid_one() {
        // ポート kill は ancestry をバイパスする設計のため、PID 1 を明示的に
        // 拒否する経路がないと、PID 1 が許可ポートを listen しているケースで
        // コンテナ全体が落ちる。常に NotDescendant で拒否されるべき。
        let engine = PolicyEngine::new(Config::default());
        let permission = engine.can_kill_for_port(1, "custom_init");
        assert_eq!(
            permission,
            KillPermission::DeniedNotDescendant,
            "PID 1 はポート kill 経路でも常に保護されるべき"
        );
    }

    #[test]
    fn test_can_kill_for_port_rejects_pid_zero() {
        // PID 0 はプロセスグループ用の特殊値であり、通常の kill 対象にできない。
        // ポート kill の fail-closed として PID 1 と同じ扱いにする。
        let engine = PolicyEngine::new(Config::default());
        let permission = engine.can_kill_for_port(0, "anything");
        assert_eq!(permission, KillPermission::DeniedNotDescendant);
    }

    #[test]
    fn test_can_kill_pid_one_protection_precedes_root_pid() {
        // root PID を明示的に 1 ではない値にしても、PID 1 への kill は
        // root_pid 判定より手前で拒否される（順序の回帰）。
        let root_pid = ProcessInfoProvider::current_pid().saturating_add(100_000);
        let engine = engine_with_root_pid(Config::default(), root_pid);

        let process = ProcessInfo {
            pid: 1,
            parent_pid: None,
            name: "totally_custom_name".to_string(),
            cmd: vec![],
            start_time: 0,
        };

        let permission = engine.can_kill(&process);
        assert_eq!(permission, KillPermission::DeniedNotDescendant);
    }

    // =========================================================================
    // 名前指定 kill の処理順（子孫から先に処理する）のテスト
    //
    // 親を先に kill すると子が init に付け替えられ、kill 直前の ancestry 再評価で
    // 拒否されて孤児として残る。実プロセスでは PID の大小や付け替えの時機を作れないので、
    // 固定のツリーで並べ方そのものを確かめる。
    // =========================================================================

    /// 一致した PID と (子, 親) の組から、`order_descendants_first` の処理順を PID で返す
    fn order_of(matches: &[u32], parent_links: &[(u32, u32)]) -> Vec<u32> {
        let parents: std::collections::HashMap<u32, u32> = parent_links.iter().copied().collect();
        let processes: Vec<ProcessInfo> = matches
            .iter()
            .map(|&pid| ProcessInfo {
                pid,
                parent_pid: parents.get(&pid).copied(),
                name: "node".to_string(),
                cmd: vec![],
                start_time: 0,
            })
            .collect();
        order_descendants_first(&processes, |pid| parents.get(&pid).copied())
            .into_iter()
            .map(|index| processes[index].pid)
            .collect()
    }

    #[test]
    fn test_order_descendants_first_processes_children_before_parents() {
        // 親 100 → 子 200 → 孫 300 がすべて一致する。PID 昇順のままだと親から処理してしまう
        assert_eq!(
            order_of(&[100, 200, 300], &[(300, 200), (200, 100), (100, 1)]),
            vec![300, 200, 100]
        );
    }

    #[test]
    fn test_order_descendants_first_ignores_pid_magnitude() {
        // PID が周回すると、子の PID が親より小さくなる
        assert_eq!(order_of(&[900, 50], &[(50, 900), (900, 1)]), vec![50, 900]);
    }

    #[test]
    fn test_order_descendants_first_follows_non_matching_ancestors() {
        // 親 100（一致）→ 中間 150（別名で一致しない）→ 子 200（一致）。
        // 中間の祖先が一致しなくても、チェーンをたどって子を先にする
        assert_eq!(
            order_of(&[100, 200], &[(200, 150), (150, 100), (100, 1)]),
            vec![200, 100]
        );
    }

    #[test]
    fn test_order_descendants_first_breaks_ties_by_pid() {
        // 同じ深さの兄弟と、別のツリーの一致は PID 昇順
        assert_eq!(
            order_of(&[30, 10, 20], &[(30, 5), (10, 5), (20, 7), (5, 1), (7, 1)]),
            vec![10, 20, 30]
        );
    }

    #[test]
    fn test_order_descendants_first_terminates_on_cycle_and_unknown_parent() {
        // 親 PID の循環（壊れた snapshot）と、親が分からないプロセスが混ざっても止まり、
        // すべての一致を 1 回ずつ返す
        assert_eq!(
            order_of(&[30, 10, 20], &[(10, 20), (20, 10)]),
            vec![10, 20, 30]
        );
        assert_eq!(order_of(&[7], &[(7, 7)]), vec![7]);
        assert!(order_of(&[], &[]).is_empty());
    }

    // =========================================================================
    // 拒否をエラーに変えるときの分類（denial_error）のテスト
    // =========================================================================

    /// 存在しない PID を持つプロセス情報（判定の後で終了した対象の代わり）
    fn vanished_process() -> ProcessInfo {
        ProcessInfo {
            pid: 999_999_999,
            parent_pid: Some(1),
            name: "vanished".to_string(),
            cmd: vec![],
            start_time: 1,
        }
    }

    #[test]
    fn test_denial_error_reports_vanished_target_as_process_not_found() {
        // セッション外という判定の後で対象が消えていれば、ProcessNotFound（終了コード 1）
        let engine = PolicyEngine::new(Config::default());
        assert_eq!(
            engine.denial_error(&vanished_process(), &KillPermission::DeniedNotDescendant),
            SafeKillError::ProcessNotFound(999_999_999)
        );
    }

    #[test]
    fn test_denial_error_keeps_not_descendant_for_live_target() {
        // 兄弟プロセスの一方を信頼ルートにし、生きている非子孫を作る
        let root = spawn_sleeper();
        let sibling = spawn_sleeper();
        let engine = engine_with_root_pid(Config::default(), root.id());
        let target = engine
            .provider()
            .get(sibling.id())
            .expect("起動直後の兄弟プロセスは snapshot に含まれるはず");

        let error = engine.denial_error(&target, &KillPermission::DeniedNotDescendant);

        reap(root);
        reap(sibling);
        assert_eq!(
            error,
            SafeKillError::NotDescendant(target.pid, target.name.clone())
        );
    }

    #[test]
    fn test_denial_error_does_not_reclassify_denylist_or_suicide() {
        // denylist と自殺防止は対象の生死に関係なく保護の理由なので、消えた対象でも変えない
        let engine = PolicyEngine::new(Config::default());
        assert_eq!(
            engine.denial_error(
                &vanished_process(),
                &KillPermission::DeniedByDenylist("vanished".to_string())
            ),
            SafeKillError::Denylisted("vanished".to_string())
        );
        assert_eq!(
            engine.denial_error(
                &vanished_process(),
                &KillPermission::DeniedSuicidePrevention
            ),
            SafeKillError::SuicidePrevention(999_999_999)
        );
    }

    #[test]
    fn test_kill_by_pid_reports_non_descendant_that_exited_as_not_found() {
        // snapshot の時点では生きていたセッション外の対象が、判定の前に終了した状況。
        // can_kill は snapshot で DeniedNotDescendant を返すが、消えただけの対象を
        // NotDescendant（255）と報告せず ProcessNotFound（1）にする。dry-run なので、
        // 万一 PID が再利用されていてもシグナルは送らない。
        let root = spawn_sleeper();
        let sibling = spawn_sleeper();
        let pid = sibling.id();
        let engine = engine_with_root_pid(Config::default(), root.id());
        assert!(engine.provider().get(pid).is_some());
        reap(sibling);

        let result = engine.kill_by_pid(pid, Signal::SIGTERM, true);

        reap(root);
        assert!(
            matches!(result, Err(SafeKillError::ProcessNotFound(p)) if p == pid),
            "判定の前に終了したセッション外の対象は ProcessNotFound になるべき、実際: {:?}",
            result
        );
    }

    #[test]
    fn test_target_lookup_and_ancestry_share_one_snapshot() {
        // 対象の取得と子孫判定が同じ snapshot を見ていること。別々に取ると、
        // その間に終了した子孫が NotDescendant（255）と誤って報告される。
        let engine = PolicyEngine::new(Config::default());
        assert!(std::ptr::eq(engine.provider(), engine.ancestry.provider()));
    }

    // =========================================================================
    // ポート指定 kill でポリシーが実際に適用されることのテスト
    //
    // 現状のポート経路のテストは、自殺防止以外の拒否を実際にポートを持つプロセスで
    // 確かめていない（`can_kill_for_port` を常に許可にしても通ってしまう）。
    // リスナーを継承した子プロセスを作り、dry-run で判定だけを確かめる。
    // =========================================================================

    /// TCP リスナーを FD 3 として継承させた `sleep 60` を起動する
    ///
    /// 子は exec 後もソケットを保持するので、ポート保持の再確認に通る。テスト側の
    /// リスナーは返り値で保持し続ける（同じポートの保持者にテスト自身も加わるが、
    /// `kill_port_processes` には子の PID だけを渡す）。
    fn spawn_listener_holder() -> (std::process::Child, std::net::TcpListener, u16) {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;

        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let fd = listener.as_raw_fd();
        let mut command = std::process::Command::new("sleep");
        command.arg("60");
        // SAFETY: pre_exec のクロージャは fork 後・exec 前の子で動く。呼ぶのは
        // async-signal-safe な dup2(2) / fcntl(2) だけで、メモリの確保もロックの取得もしない。
        unsafe {
            command.pre_exec(move || {
                // dup2 は複製先の FD_CLOEXEC を外すので、FD 3 は exec 後も残る。ただし複製元と
                // 複製先が同じ番号だと dup2 は何もせずフラグも外れない。リスナーがたまたま
                // FD 3 のときは、exec で閉じられないようフラグを直接外す。
                let result = if fd == 3 {
                    let flags = nix::libc::fcntl(3, nix::libc::F_GETFD);
                    if flags == -1 {
                        -1
                    } else {
                        nix::libc::fcntl(3, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC)
                    }
                } else {
                    nix::libc::dup2(fd, 3)
                };
                if result == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("sleep の起動に失敗");
        (child, listener, port)
    }

    /// ポートを持つ子プロセスに対して、ポート指定 kill を dry-run で実行した結果
    fn dry_run_port_kill_on_holder(
        engine: &PolicyEngine,
        child: &std::process::Child,
        port: u16,
    ) -> KillResult {
        assert!(
            engine
                .port_detector
                .pid_holds_port(child.id(), port, crate::port::PortProtocol::Tcp),
            "前提: 子プロセスがポート {port} を保持している"
        );
        let holder = crate::port::PortProcess {
            pid: child.id(),
            name: "sleep".to_string(),
            port,
            protocol: crate::port::PortProtocol::Tcp,
        };
        let mut batch = engine.kill_port_processes(port, vec![holder], Signal::SIGTERM, true);
        assert_eq!(batch.results.len(), 1);
        batch.results.remove(0)
    }

    #[test]
    fn test_kill_port_processes_dry_run_reaches_holder() {
        // 対照: 拒否する理由が無ければ、ポートを持つ子は dry-run で対象になる。
        // 下の 2 つのテストが「ポート保持の再確認で落ちただけ」で通らないための確認。
        let (child, _listener, port) = spawn_listener_holder();
        let engine = engine_with_root_pid(Config::default(), ProcessInfoProvider::current_pid());

        let result = dry_run_port_kill_on_holder(&engine, &child, port);

        reap(child);
        assert!(result.success, "{result:?}");
        assert_eq!(result.error, None);
    }

    #[test]
    fn test_kill_port_processes_applies_denylist_to_real_holder() {
        let (child, _listener, port) = spawn_listener_holder();
        let config = Config {
            denylist: Some(ProcessList {
                processes: vec!["sleep".to_string()],
            }),
            ..Default::default()
        };
        let engine = engine_with_root_pid(config, ProcessInfoProvider::current_pid());

        let result = dry_run_port_kill_on_holder(&engine, &child, port);

        reap(child);
        assert!(!result.success);
        assert_eq!(
            result.error,
            Some(SafeKillError::Denylisted("sleep".to_string()))
        );
    }

    #[test]
    fn test_kill_port_processes_protects_trust_root_holding_port() {
        // ポートを持つプロセスが信頼ルートそのものなら、ancestry を迂回する `--port` でも拒否する
        let (child, _listener, port) = spawn_listener_holder();
        let engine = engine_with_root_pid(Config::default(), child.id());

        let result = dry_run_port_kill_on_holder(&engine, &child, port);

        let pid = child.id();
        reap(child);
        assert!(!result.success);
        assert_eq!(
            result.error,
            Some(SafeKillError::NotDescendant(pid, "sleep".to_string()))
        );
    }
}
