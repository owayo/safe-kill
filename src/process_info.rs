//! sysinfo クレートを使用したプロセス情報プロバイダー
//!
//! クロスプラットフォームなプロセス情報取得を提供する。

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

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
    /// safe-kill が必要とする情報だけを取得する refresh 指定
    ///
    /// `System::refresh_processes` の既定値は `with_tasks()` を含むため、Linux では
    /// `/proc/<pid>/task/<tid>` のスレッドが独立したプロセスとして一覧に載る
    /// （sysinfo 側のコメントも "tasks are considered processes on their own in linux"）。
    /// スレッドは `prctl(PR_SET_NAME)` / `pthread_setname_np` で自分の comm を自由に
    /// 変更できるので、これを許すと denylist に載せたプロセスでも「スレッド名」を
    /// 指定すれば名前一致を回避でき、しかも TID への `kill(2)` はスレッドグループ全体へ
    /// 配送されるため、denylist を迂回して本体を落とせてしまう。
    /// `without_tasks()` を明示してスレッドを一覧から除外する。
    ///
    /// あわせて memory / cpu / disk_usage は取得しない（safe-kill はどれも参照しない）。
    /// `cmd` は `--list` の COMMAND 列で使うため明示的に取得する。
    fn refresh_kind() -> ProcessRefreshKind {
        // `exe` は要求しない。`ProcessInfo` は parent / name / cmd / start_time しか
        // 持たず実行ファイルパスを使わない一方、Linux ではこれを要求すると sysinfo が
        // プロセスごとに `realpath("/proc/<pid>/exe")` を実行する。1 回の kill で
        // スナップショットを複数作るため、その分だけ無駄が積み上がる。
        //
        // `name` の解決には影響しない。Linux の `name` は `/proc/<pid>/stat` の comm 由来、
        // macOS は `KERN_PROCARGS2`（失敗時は `proc_pidpath`）から basename を取り、
        // どちらも `exe` の要求有無と独立している（`Process::exe` フィールドを保持するか
        // だけが変わる）。`name` は `--name` 検索と denylist 判定に使うため、
        // ここが壊れていないことは `test_refresh_kind_does_not_request_exe` 以下の
        // テストで固定する。
        ProcessRefreshKind::nothing()
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .without_tasks()
    }

    /// プロセスリストを更新済みの新しい ProcessInfoProvider を作成
    pub fn new() -> Self {
        // `System::new_all()` は内部で tasks 付きの refresh を行うため使わない。
        // 空の System から `without_tasks()` の refresh だけを行い、スレッドを
        // 一度もスナップショットへ入れない。
        let mut system = System::new();
        system.refresh_processes_specifics(ProcessesToUpdate::All, true, Self::refresh_kind());
        Self { system }
    }

    /// プロセスリストを取り直す
    ///
    /// 保持している `System` を差分更新せず、snapshot を作り直す。sysinfo の差分更新は、
    /// 起動時刻が変わらない（同じプロセスとみなした）PID の名前を読み直さない。Linux は
    /// comm を新しいエントリを作るときにしか読まず、macOS も名前が空のときだけ設定する。
    /// `cmd` も `UpdateKind::OnlyIfNotSet` なので読み直されない。exec は PID と起動時刻を
    /// 変えないため、差分更新のままだと exec した後も `get` / `find_by_name` / `all` が
    /// exec 前の名前と cmd を返し続け、`--name` の検索や denylist の判定が古い名前で行われる。
    pub fn refresh(&mut self) {
        *self = Self::new();
    }

    /// スレッド（Linux の TID エントリ）でない実プロセスかを判定する
    ///
    /// `thread_kind()` は実プロセスなら `None`、スレッドなら `Some(_)` を返す。
    /// `refresh_kind()` の `without_tasks()` で一覧には入らないはずだが、
    /// `ProcessesToUpdate::Some` 指定の取得経路（`fetch_fresh`）は tasks 指定に
    /// 関わらず TID を返すため、参照側でも一律に fail-closed で弾く。
    fn is_real_process(proc: &sysinfo::Process) -> bool {
        proc.thread_kind().is_none()
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
            .filter(|proc| Self::is_real_process(proc))
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
        // PID 0 は Unix ではシグナル送信時にプロセスグループを表す特殊値。
        // i32::MAX を超える値も kill(2) へ渡せないため、OS や sysinfo の
        // 解釈に委ねず公開 API の境界で拒否する。
        if pid == 0 || pid > i32::MAX as u32 {
            return None;
        }

        let mut sys = System::new();
        let sysinfo_pid = Pid::from_u32(pid);
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[sysinfo_pid]),
            true,
            Self::refresh_kind(),
        );
        // `ProcessesToUpdate::Some` は tasks 指定に関わらず TID を返すため、
        // ここでスレッドを弾かないと kill 直前の同一性検証をスレッドが通過してしまう。
        sys.process(sysinfo_pid)
            .filter(|proc| Self::is_real_process(proc))
            .map(|proc| Self::build_info(pid, proc))
    }

    /// 指定名に一致するすべてのプロセスを検索（完全一致）
    pub fn find_by_name(&self, name: &str) -> Vec<ProcessInfo> {
        let mut processes: Vec<_> = self
            .system
            .processes()
            .iter()
            .filter(|(_, proc)| Self::is_real_process(proc))
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
            .filter(|(_, proc)| Self::is_real_process(proc))
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
    fn test_refresh_kind_does_not_request_exe() {
        // exe を要求すると Linux では sysinfo がプロセスごとに
        // `realpath("/proc/<pid>/exe")` を実行する。`ProcessInfo` は exe を持たないので
        // 不要な負荷であり、うっかり戻すと 1 実行あたり複数スナップショット分の
        // 無駄が復活する。設定そのものをテストで固定する。
        let kind = ProcessInfoProvider::refresh_kind();
        assert_eq!(kind.exe(), UpdateKind::Never);
        assert_eq!(kind.cmd(), UpdateKind::OnlyIfNotSet);
        assert!(!kind.tasks(), "スレッド（TID）を一覧に入れてはいけない");
    }

    #[test]
    fn test_name_resolves_without_exe_refresh() {
        // `name` は `--name` 検索と denylist 判定の入力なので、空になると
        // 「denylist に載せたプロセスが名前一致しない」形で安全性が壊れる。
        // exe を要求しない設定でも name が解決できることを固定する。
        let provider = ProcessInfoProvider::new();
        let info = provider
            .get(ProcessInfoProvider::current_pid())
            .expect("自プロセスは一覧に含まれるはず");
        assert!(
            !info.name.is_empty(),
            "exe を要求しない設定でプロセス名が解決できていない"
        );
    }

    #[test]
    fn test_fetch_fresh_resolves_name_without_exe_refresh() {
        // TOCTOU 検証で使う `fetch_fresh` は `pid + start_time + name` を突き合わせる。
        // name が空になると同一性検証が常に失敗し、正当な kill まで拒否される。
        let info = ProcessInfoProvider::fetch_fresh(ProcessInfoProvider::current_pid())
            .expect("自プロセスを取得できるはず");
        assert!(
            !info.name.is_empty(),
            "exe を要求しない設定で fetch_fresh のプロセス名が解決できていない"
        );
    }

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
    fn test_refresh_rereads_name_and_cmd_after_exec() {
        // exec は PID と起動時刻を変えずに名前と cmd だけを変える。refresh 後に古い名前が
        // 残ると、`--name` の検索・denylist の判定・identity の照合が exec 前の名前で行われる。
        // exec の時機は標準入力で渡し、snapshot を取る前に exec してしまわないようにする。
        use std::io::Write;
        use std::time::{Duration, Instant};

        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "read _; exec sleep 30"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("sh を起動できるべき");
        let pid = child.id();
        let mut provider = ProcessInfoProvider::new();
        let before = provider.get(pid).map(|info| info.name);

        let exec_requested = child
            .stdin
            .take()
            .expect("sh の標準入力を取れるべき")
            .write_all(b"\n");
        // exec が終わるまで待つ（fresh な取得は名前を毎回読み直す）
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut execed = false;
        while !execed && Instant::now() < deadline {
            execed = ProcessInfoProvider::fetch_fresh(pid).is_some_and(|info| info.name == "sleep");
            if !execed {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        provider.refresh();
        let after = provider.get(pid);

        let _ = child.kill();
        let _ = child.wait();
        exec_requested.expect("sh へ exec の合図を書けるべき");
        assert!(execed, "10 秒以内に sleep へ exec しなかった");
        assert!(
            before.is_some_and(|name| name != "sleep"),
            "exec 前の名前を取れていない"
        );
        let after = after.expect("refresh 後も子プロセスを取得できるべき");
        assert_eq!(
            after.name, "sleep",
            "refresh 後も exec 前の名前が残っている"
        );
        assert_eq!(
            after.cmd,
            ["sleep", "30"],
            "refresh 後も exec 前のコマンドラインが残っている"
        );
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
    fn test_fetch_fresh_rejects_pid_zero() {
        // PID 0 はプロセスグループを表す特殊値で、実プロセスとしては存在しない。
        // sysinfo もこれを有効として扱わないため、fetch_fresh は None を返すべき。
        // policy 層は事前に PID=0 を拒否しているが、TOCTOU 検証経路で誤って
        // Some(...) を返さないことを公開 API の境界として固定する。
        assert!(
            ProcessInfoProvider::fetch_fresh(0).is_none(),
            "PID 0 は fetch_fresh で None を返すべき"
        );
    }

    #[test]
    fn test_fetch_fresh_rejects_u32_max_pid() {
        // u32::MAX は i32::MAX を超えており、実プロセスに割り当てられない。
        // sysinfo が Some を返してしまうと PID 再利用検証の同一性チェックを
        // 通過させてしまう可能性があるため、None を返すことを回帰として固定する。
        assert!(
            ProcessInfoProvider::fetch_fresh(u32::MAX).is_none(),
            "u32::MAX は fetch_fresh で None を返すべき"
        );
    }

    #[test]
    fn test_fetch_fresh_rejects_i32_max_plus_one_pid() {
        let pid = i32::MAX as u32 + 1;

        assert!(
            ProcessInfoProvider::fetch_fresh(pid).is_none(),
            "i32::MAX を超える PID は fetch_fresh で None を返すべき"
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

    #[test]
    fn test_all_excludes_threads_of_current_process() {
        // sysinfo の既定 refresh は `with_tasks()` を含み、Linux では
        // `/proc/<pid>/task/<tid>` のスレッドが独立したプロセスとして一覧に現れる。
        // スレッドは自分の comm を自由に変えられるうえ、TID への kill(2) はスレッド
        // グループ全体へ配送されるため、これを一覧に含めると denylist をスレッド名で
        // 迂回できてしまう。
        //
        // 固有の名前を付けたスレッドを生かしたまま、各スレッドの TID（Linux）とスレッド名が
        // どの参照経路（all / get / fetch_fresh / find_by_name）にも現れないことを確かめる。
        // 「親が自 PID のエントリ」をスレッドとみなす判定は使わない。同じテストバイナリの
        // ほかのテストが並行して起動する子プロセス（`sleep` など）まで誤検出して、
        // テストが不定期に失敗していた。macOS はスレッドを列挙しないので TID は集めず、
        // 名前の経路だけを確かめる。
        use std::sync::mpsc;

        let current = ProcessInfoProvider::current_pid();
        // Linux の comm の上限（15 バイト）に収まる名前
        let thread_name = format!("skthr{current:08x}");
        let (ready_tx, ready_rx) = mpsc::channel::<Option<u32>>();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let stop_rx = std::sync::Arc::new(std::sync::Mutex::new(stop_rx));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let ready_tx = ready_tx.clone();
                let stop_rx = std::sync::Arc::clone(&stop_rx);
                std::thread::Builder::new()
                    .name(thread_name.clone())
                    .spawn(move || {
                        #[cfg(target_os = "linux")]
                        let tid = u32::try_from(nix::unistd::gettid().as_raw()).ok();
                        #[cfg(not(target_os = "linux"))]
                        let tid = None;
                        ready_tx.send(tid).ok();
                        // 検証が終わるまでスレッドを生かしておく。
                        let _ = stop_rx.lock().unwrap().recv();
                    })
                    .expect("スレッドを起動できるべき")
            })
            .collect();
        drop(ready_tx);
        let tids: Vec<u32> = (0..4)
            .filter_map(|_| ready_rx.recv().expect("スレッドの起動を待てるべき"))
            .collect();

        let provider = ProcessInfoProvider::new();
        let all = provider.all();
        let leaked_tids: Vec<u32> = tids
            .iter()
            .copied()
            .filter(|&tid| {
                tid != current
                    && (all.iter().any(|p| p.pid == tid)
                        || provider.get(tid).is_some()
                        || ProcessInfoProvider::fetch_fresh(tid).is_some())
            })
            .collect();
        let leaked_by_name = provider.find_by_name(&thread_name);

        // スレッドを解放してから assert する（失敗時もハングしないように）。
        drop(stop_tx);
        for handle in handles {
            handle.join().ok();
        }

        #[cfg(target_os = "linux")]
        assert_eq!(tids.len(), 4, "スレッドの TID を集められるべき: {tids:?}");
        assert!(
            leaked_tids.is_empty(),
            "スレッドの TID が独立したプロセスとして取得できてしまう: {leaked_tids:?}"
        );
        assert!(
            leaked_by_name.is_empty(),
            "スレッド名でプロセスとして一致してしまう: {leaked_by_name:?}"
        );

        // 自プロセス自身は当然一覧に載る（フィルタが効きすぎていないことの確認）。
        assert!(
            all.iter().any(|p| p.pid == current),
            "自プロセスは一覧に含まれるべき"
        );
    }
}
