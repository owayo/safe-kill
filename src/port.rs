//! safe-kill のポート検出モジュール
//!
//! 特定ポートを使用するプロセスを検出する。OS ごとの実装は次のとおり。
//!
//! - Linux: netstat2（netlink の sock_diag と `/proc/<pid>/fd`）。`linux.rs`
//! - macOS: libproc（`proc_listallpids` / `proc_pidinfo` / `proc_pidfdinfo`）を直接呼ぶ自前の実装。
//!   `macos.rs`。netstat2 の macOS 実装は失敗した問い合わせのバッファを別 PID の結果として
//!   返すため使わない（詳細は `macos.rs` の冒頭）
//!
//! どちらも「TCP は LISTEN のみ、UDP はローカルポートの一致、IPv4 と IPv6 の両方」を対象にする。

use std::cell::OnceCell;

use crate::error::SafeKillError;
use crate::process_info::{ProcessInfo, ProcessInfoProvider};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as backend;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as backend;

/// ポート検出に対応していない OS の実装（`--port` は常に検出エラー、再検証は常に不成立）
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod backend {
    use super::PortProtocol;
    use crate::error::SafeKillError;

    pub(super) fn find_port_holders(port: u16) -> Result<Vec<(u32, PortProtocol)>, SafeKillError> {
        Err(SafeKillError::PortDetectionError {
            port,
            reason: "port detection is not supported on this platform".to_string(),
        })
    }

    pub(super) fn pid_holds_port(_pid: u32, _port: u16, _protocol: PortProtocol) -> bool {
        false
    }

    #[cfg(test)]
    pub(super) fn count_raw_socket_entries(_pid: u32, _port: u16) -> usize {
        0
    }
}

/// 特定ポートを使用するプロセスの情報
#[derive(Debug, Clone)]
pub struct PortProcess {
    /// プロセス ID
    pub pid: u32,
    /// プロセス名
    pub name: String,
    /// ポート番号
    pub port: u16,
    /// プロトコル（TCP または UDP）
    pub protocol: PortProtocol,
}

/// ポートバインディングのプロトコル種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProtocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortProtocol::Tcp => write!(f, "TCP"),
            PortProtocol::Udp => write!(f, "UDP"),
        }
    }
}

/// 特定ポートを使用するプロセスを検出するポート検出器
pub struct PortDetector {
    /// 表示名の解決に使うプロセス一覧（初回参照時に構築する）
    ///
    /// `PolicyEngine` は実行モードに関わらず `PortDetector` を持つが、この provider が
    /// 要るのは `--port` 経路だけである。構築は全プロセスの列挙（Linux なら `/proc` の
    /// 全走査）を伴うため、`safe-kill <PID>` / `--name` / `--list` では丸ごと無駄になる。
    /// 遅延生成にして、ポート検索で実際に名前を引くときだけ払うようにする。
    provider: OnceCell<ProcessInfoProvider>,
}

impl PortDetector {
    /// 新しい PortDetector を作成
    pub fn new() -> Self {
        Self {
            provider: OnceCell::new(),
        }
    }

    /// 表示名解決用のプロセス一覧を取得する（初回のみ構築）
    fn provider(&self) -> &ProcessInfoProvider {
        self.provider.get_or_init(ProcessInfoProvider::new)
    }

    /// 指定ポートを使用するすべてのプロセスを検索
    ///
    /// ポートでリッスンしているプロセスを返す（TCP と UDP の両方）。
    /// ポートを共有している場合、複数のプロセスが返される可能性がある。
    pub fn find_by_port(&self, port: u16) -> Result<Vec<PortProcess>, SafeKillError> {
        if port == 0 {
            return Err(SafeKillError::InvalidPort(port.to_string()));
        }

        let holders = dedup_holders(backend::find_port_holders(port)?);

        let results = holders
            .into_iter()
            .map(|(pid, protocol)| {
                // プロセス情報が取れない場合は表示用のプレースホルダ名を入れる。
                // この名前はあくまで UI 出力用であり、denylist 等のポリシー判定には
                // 使ってはならない（呼び出し側で fresh なプロセス情報を再取得すること）。
                let name = self
                    .provider()
                    .get(pid)
                    .map(|p| p.name)
                    .unwrap_or_else(|| format!("pid:{}", pid));

                PortProcess {
                    pid,
                    name,
                    port,
                    protocol,
                }
            })
            .collect();

        Ok(results)
    }

    /// 指定 PID が指定ポート/プロトコルをいま保持しているかを再確認する
    ///
    /// kill 直前の TOCTOU 緩和用。判定〜kill の窓を最小化するため、対象 PID ごとに
    /// その都度 OS へ問い合わせ直す。
    ///
    /// 呼び出しコストは OS で異なる。macOS は対象 PID の FD だけを `proc_pidfdinfo` で
    /// 問い合わせ直す（システム全体は走査しない）。Linux は netstat2 の `get_sockets_info` が
    /// 1 回ごとにシステム全体のソケット表を走査する（netlink dump に加えて `/proc/*/fd` 全体の
    /// `read_link`）ため、同一ポートを N 個のプロセスが保持していれば、その N 回ぶん全体走査が
    /// 走る。窓を狭めるためにこの重さを受け入れている、というのが意図した設計上のトレードオフである。
    ///
    /// 取得に失敗した場合や調べ切れなかった場合は安全側に倒して `false` を返す（fail-closed）。
    pub fn pid_holds_port(&self, pid: u32, port: u16, protocol: PortProtocol) -> bool {
        backend::pid_holds_port(pid, port, protocol)
    }

    /// 指定ポートを使用するすべてのプロセスのプロセス情報を取得
    pub fn get_process_info(&self, port: u16) -> Result<Vec<ProcessInfo>, SafeKillError> {
        let port_processes = self.find_by_port(port)?;

        let mut process_infos = Vec::new();
        for pp in port_processes {
            if let Some(info) = self.provider().get(pp.pid) {
                process_infos.push(info);
            }
        }

        Ok(process_infos)
    }

    /// 内部のプロセス情報を更新
    ///
    /// まだ一度も名前解決していなければ何もしない（遅延生成を維持する）。
    pub fn refresh(&mut self) {
        if let Some(provider) = self.provider.get_mut() {
            provider.refresh();
        }
    }
}

impl Default for PortDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// ポートの保持者の一覧から同じ PID の重複を除き、PID 昇順に並べる
///
/// 同じ PID が複数のソケット（TCP と UDP、IPv4 と IPv6）で現れることがある。`dedup_by_key` は
/// 隣り合う要素しか見ないので、先に PID で並べる。macOS の実装は PID ごとに走査するので同じ
/// PID は隣り合うが、Linux の netstat2 は TCPv4 → UDPv4 → TCPv6 → UDPv6 の順に返すので、
/// 同じ PID が離れて現れる（例: `[A/TCP, B/TCP, A/UDP]`）。安定ソートなので、同じ PID では
/// 最初に見つかったソケットのプロトコルが残る。
fn dedup_holders(mut holders: Vec<(u32, PortProtocol)>) -> Vec<(u32, PortProtocol)> {
    holders.sort_by_key(|&(pid, _)| pid);
    holders.dedup_by_key(|&mut (pid, _)| pid);
    holders
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_dedup_holders_merges_non_adjacent_duplicates() {
        // Linux の netstat2 のように、同じ PID がプロトコルごとに離れて現れる並び
        let holders = vec![
            (30, PortProtocol::Udp),
            (10, PortProtocol::Tcp),
            (30, PortProtocol::Tcp),
            (20, PortProtocol::Udp),
            (10, PortProtocol::Udp),
        ];
        assert_eq!(
            dedup_holders(holders),
            vec![
                (10, PortProtocol::Tcp),
                (20, PortProtocol::Udp),
                (30, PortProtocol::Udp),
            ]
        );
        assert!(dedup_holders(Vec::new()).is_empty());
    }

    #[test]
    fn test_port_detector_new() {
        let detector = PortDetector::new();
        // パニックしないことを確認
        let _ = detector;
    }

    #[test]
    fn test_new_does_not_build_process_snapshot() {
        // `PolicyEngine` は実行モードに関わらず `PortDetector` を持つ。ここで
        // 全プロセス列挙を走らせると `--port` を使わない実行でも毎回無駄になる。
        let detector = PortDetector::new();
        assert!(detector.provider.get().is_none());
    }

    #[test]
    fn test_refresh_before_first_use_keeps_provider_uninitialized() {
        // refresh は「まだ作っていないものを作る」きっかけにしてはいけない。
        let mut detector = PortDetector::new();
        detector.refresh();
        assert!(detector.provider.get().is_none());
    }

    #[test]
    fn test_pid_holds_port_does_not_build_process_snapshot() {
        // kill 直前の再検証はソケット表しか見ない。表示名の解決は不要。
        let detector = PortDetector::new();
        let _ =
            detector.pid_holds_port(ProcessInfoProvider::current_pid(), 65535, PortProtocol::Tcp);
        assert!(detector.provider.get().is_none());
    }

    #[test]
    fn test_find_by_port_builds_process_snapshot_on_demand() {
        // 表示名が要るのはこの経路だけ。ここでは実際に構築されることを確認する。
        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let detector = PortDetector::new();
        assert!(detector.provider.get().is_none());

        // OS のソケット一覧へ反映されるまで短く待つ。通常は初回で成功する。
        let found = (0..10).any(|_| {
            let detected = detector
                .find_by_port(port)
                .map(|processes| !processes.is_empty())
                .unwrap_or(false);
            if !detected {
                thread::sleep(Duration::from_millis(50));
            }
            detected
        });

        assert!(found, "自プロセスの TCP リスナーを検出できなかった");
        assert!(detector.provider.get().is_some());
    }

    #[test]
    fn test_port_detector_default() {
        let detector = PortDetector::default();
        // パニックしないことを確認
        let _ = detector;
    }

    #[test]
    fn test_port_protocol_display() {
        assert_eq!(format!("{}", PortProtocol::Tcp), "TCP");
        assert_eq!(format!("{}", PortProtocol::Udp), "UDP");
    }

    #[test]
    fn test_port_protocol_eq() {
        assert_eq!(PortProtocol::Tcp, PortProtocol::Tcp);
        assert_eq!(PortProtocol::Udp, PortProtocol::Udp);
        assert_ne!(PortProtocol::Tcp, PortProtocol::Udp);
    }

    #[test]
    fn test_port_protocol_clone() {
        let protocol = PortProtocol::Tcp;
        let cloned = protocol;
        assert_eq!(protocol, cloned);
    }

    #[test]
    fn test_port_protocol_copy() {
        let protocol = PortProtocol::Tcp;
        let copied: PortProtocol = protocol;
        assert_eq!(protocol, copied);
    }

    #[test]
    fn test_port_process_clone() {
        let pp = PortProcess {
            pid: 1234,
            name: "test".to_string(),
            port: 8080,
            protocol: PortProtocol::Tcp,
        };
        let cloned = pp.clone();
        assert_eq!(cloned.pid, 1234);
        assert_eq!(cloned.name, "test");
        assert_eq!(cloned.port, 8080);
        assert_eq!(cloned.protocol, PortProtocol::Tcp);
    }

    #[test]
    fn test_port_process_debug() {
        let pp = PortProcess {
            pid: 1234,
            name: "test".to_string(),
            port: 8080,
            protocol: PortProtocol::Tcp,
        };
        let debug_str = format!("{:?}", pp);
        assert!(debug_str.contains("1234"));
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("8080"));
    }

    #[test]
    fn test_find_by_port_unused_port() {
        let detector = PortDetector::new();
        // 使用されていない可能性の高い高ポートを使用
        let result = detector.find_by_port(59999);
        assert!(result.is_ok());
        // プロセスがあるかは不定だが、エラーにはならないはず
    }

    #[test]
    fn test_find_by_port_returns_vec() {
        let detector = PortDetector::new();
        let result = detector.find_by_port(80);
        assert!(result.is_ok());
        // 結果は Vec で、空の場合もある
        let _processes: Vec<PortProcess> = result.unwrap();
    }

    #[test]
    fn test_get_process_info_unused_port() {
        let detector = PortDetector::new();
        let result = detector.get_process_info(59998);
        assert!(result.is_ok());
    }

    #[test]
    fn test_port_detector_refresh() {
        let mut detector = PortDetector::new();
        detector.refresh();
        // パニックしないことを確認
    }

    // =============================================================================
    // 境界値テスト
    // =============================================================================

    #[test]
    fn test_find_by_port_zero() {
        let detector = PortDetector::new();
        // ポート 0 は OS の自動割り当て用の特殊値なので終了対象にしない
        let result = detector.find_by_port(0);
        assert!(matches!(result, Err(SafeKillError::InvalidPort(_))));
    }

    #[test]
    fn test_find_by_port_max() {
        let detector = PortDetector::new();
        // ポート65535は最大有効値
        let result = detector.find_by_port(65535);
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_by_port_common_ports() {
        let detector = PortDetector::new();

        // 一般的なポート番号でテスト（プロセスがあるかは環境依存）
        // エラーにならないことを確認
        assert!(detector.find_by_port(22).is_ok()); // SSH
        assert!(detector.find_by_port(80).is_ok()); // HTTP
        assert!(detector.find_by_port(443).is_ok()); // HTTPS
        assert!(detector.find_by_port(3000).is_ok()); // 開発用
        assert!(detector.find_by_port(8080).is_ok()); // 代替HTTP
    }

    #[test]
    fn test_port_protocol_debug() {
        let tcp = PortProtocol::Tcp;
        let udp = PortProtocol::Udp;
        assert!(format!("{:?}", tcp).contains("Tcp"));
        assert!(format!("{:?}", udp).contains("Udp"));
    }

    #[test]
    fn test_port_process_fields() {
        let pp = PortProcess {
            pid: 12345,
            name: "test_process".to_string(),
            port: 8080,
            protocol: PortProtocol::Tcp,
        };

        assert_eq!(pp.pid, 12345);
        assert_eq!(pp.name, "test_process");
        assert_eq!(pp.port, 8080);
        assert_eq!(pp.protocol, PortProtocol::Tcp);
    }

    #[test]
    fn test_get_process_info_returns_empty_for_unused_port() {
        let detector = PortDetector::new();
        let result = detector.get_process_info(59991).unwrap();
        // 使用されていないポートではプロセス情報は空
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_process_info_returns_process_info_type() {
        let detector = PortDetector::new();
        let result = detector.get_process_info(59992);
        assert!(result.is_ok());
        // 返り値はVec<ProcessInfo>であること
        let infos: Vec<ProcessInfo> = result.unwrap();
        for info in &infos {
            assert!(info.pid > 0);
            assert!(!info.name.is_empty());
        }
    }

    /// 同一ポート番号を TCP と UDP の両方で確保する
    ///
    /// TCP の自動割り当てポートが UDP 側で使用中の場合があるため、確保できるまで
    /// ポートを取り直す。両ソケットは呼び出し側で保持し続ける必要がある
    /// （drop するとソケット表から消えて検証にならない）。
    fn bind_same_port_tcp_and_udp() -> (TcpListener, UdpSocket, u16) {
        for _ in 0..20 {
            let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
            let port = listener.local_addr().unwrap().port();
            if let Ok(udp) = UdpSocket::bind(("127.0.0.1", port)) {
                return (listener, udp, port);
            }
        }
        panic!("同一ポート番号で TCP と UDP を確保できなかった");
    }

    /// 重複排除する前の、OS のソケット表に載っているエントリ数を数える
    ///
    /// `find_by_port` は排除後の結果しか返さないため、これを併せて確認しないと
    /// 「そもそも重複が発生していないので assert が素通りしている」状態に
    /// 気付けない（この関数を足す前のテストがまさにその状態だった）。
    fn count_raw_socket_entries(pid: u32, port: u16) -> usize {
        backend::count_raw_socket_entries(pid, port)
    }

    /// 指定ポートの検出結果が得られるまで短く待って取得する
    fn find_by_port_with_retry(detector: &PortDetector, port: u16) -> Vec<PortProcess> {
        for _ in 0..10 {
            let found = detector.find_by_port(port).expect("ポート検索に失敗");
            if !found.is_empty() {
                return found;
            }
            thread::sleep(Duration::from_millis(50));
        }
        panic!("自プロセスのソケットを検出できなかった (port {port})");
    }

    #[test]
    fn test_find_by_port_deduplicates_pid_holding_tcp_and_udp() {
        // 同一 PID が同じポート番号で TCP と UDP を持つと、OS のソケット表には
        // 2 エントリ載る。重複排除が効いていないと同じ PID へ 2 回シグナルを送り、
        // 2 回目が ProcessNotFound になって「成功したのに失敗が混ざった」結果に
        // なる。実際に重複が発生する状況を作って検証する
        // （未使用ポートを検索すると結果が空で、何も検証しないテストになる）。
        let (_listener, _udp, port) = bind_same_port_tcp_and_udp();
        let detector = PortDetector::new();
        let processes = find_by_port_with_retry(&detector, port);
        let current_pid = ProcessInfoProvider::current_pid();

        // 排除前に重複していたことを先に確認する。ここが 1 件なら、後続の
        // assert は「元から重複が無い」だけで通ってしまい検証にならない。
        let raw_entries = count_raw_socket_entries(current_pid, port);
        assert!(
            raw_entries >= 2,
            "TCP/UDP の両方を確保したのにソケット表のエントリが {raw_entries} 件しかなく、\
             重複排除を検証できていない (port {port})"
        );

        let own_entries: Vec<&PortProcess> =
            processes.iter().filter(|p| p.pid == current_pid).collect();
        assert_eq!(
            own_entries.len(),
            1,
            "同一 PID が TCP/UDP で重複して列挙されている: {processes:?}"
        );
    }

    // 補足: 上のテストは TCP と UDP を同じテストプロセスが保持するので、重複排除後は
    // 1 件しか残らず、並べ替えの検証にはならない（macOS では同じ PID が隣り合って現れるので、
    // ソートを消しても通る）。並べ替えが要ることは、Linux の並びを模した
    // `test_dedup_holders_merges_non_adjacent_duplicates` で確かめる。

    #[test]
    fn test_pid_holds_port_detects_current_tcp_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let detector = PortDetector::new();
        let current_pid = ProcessInfoProvider::current_pid();

        // OS のソケット一覧へ反映されるまで短く待つ。通常は初回で成功する。
        let holds_port = (0..10).any(|_| {
            let detected = detector.pid_holds_port(current_pid, port, PortProtocol::Tcp);
            if !detected {
                thread::sleep(Duration::from_millis(50));
            }
            detected
        });

        assert!(
            holds_port,
            "自プロセスが TCP ポート {} を保持していることを検出できるべき",
            port
        );

        drop(listener);
    }

    #[test]
    fn test_find_by_port_detects_ipv6_tcp_listener() {
        // find_by_port / pid_holds_port は IPv4 と IPv6 の両方を対象にする（Linux は netstat2 の
        // AddressFamilyFlags::IPV4 | IPV6、macOS は `macos.rs` の `listening_endpoint` が
        // AF_INET / AF_INET6 を受理する）。既存テストは 127.0.0.1 (IPv4) 束縛しか検証しておらず、
        // IPv6 のみで待ち受ける開発サーバー（Node.js が既定で [::] に bind する構成など）を
        // 検出できるかが固定されていなかった。IPv6 が落ちると --port kill が黙って対象なしに
        // なるため、IPv6 を外す回帰を検出できるようにする。
        let Ok(listener) = TcpListener::bind("[::1]:0") else {
            // IPv6 ループバックが無効な環境（一部のコンテナ）ではスキップする。
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let detector = PortDetector::new();
        let current_pid = ProcessInfoProvider::current_pid();

        // OS のソケット一覧へ反映されるまで短く待つ。通常は初回で成功する。
        let detected = (0..10).any(|_| {
            let matched = detector
                .find_by_port(port)
                .map(|processes| {
                    processes
                        .into_iter()
                        .any(|p| p.pid == current_pid && p.protocol == PortProtocol::Tcp)
                })
                .unwrap_or(false);
            if !matched {
                thread::sleep(Duration::from_millis(50));
            }
            matched
        });

        assert!(
            detected,
            "IPv6 で待ち受ける TCP ポート {} を find_by_port が検出できるべき",
            port
        );

        assert!(
            detector.pid_holds_port(current_pid, port, PortProtocol::Tcp),
            "IPv6 リスナーでも kill 直前のポート保持再検証を通過できるべき"
        );

        drop(listener);
    }

    #[test]
    fn test_pid_holds_port_rejects_released_tcp_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let detector = PortDetector::new();
        let current_pid = ProcessInfoProvider::current_pid();

        let detected_before_drop = (0..10).any(|_| {
            let detected = detector.pid_holds_port(current_pid, port, PortProtocol::Tcp);
            if !detected {
                thread::sleep(Duration::from_millis(50));
            }
            detected
        });
        assert!(
            detected_before_drop,
            "テスト前提として TCP ポート {} の保持を検出できるべき",
            port
        );

        drop(listener);

        // ソケット一覧から閉じたリスナーが消えるまで短く待つ。
        let released = (0..10).any(|_| {
            let released = !detector.pid_holds_port(current_pid, port, PortProtocol::Tcp);
            if !released {
                thread::sleep(Duration::from_millis(50));
            }
            released
        });

        assert!(
            released,
            "解放済み TCP ポート {} は保持中として扱われるべきではない",
            port
        );
    }

    #[test]
    fn test_find_by_port_detects_current_udp_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("UDP ソケットの作成に失敗");
        let port = socket.local_addr().unwrap().port();
        let detector = PortDetector::new();
        let current_pid = ProcessInfoProvider::current_pid();

        // UDP ソケットも OS のソケット一覧へ反映されるまで短く待つ。
        let detected = (0..10).find_map(|_| {
            let processes = detector.find_by_port(port).ok()?;
            let matched = processes
                .into_iter()
                .any(|process| process.pid == current_pid && process.protocol == PortProtocol::Udp);
            if !matched {
                thread::sleep(Duration::from_millis(50));
                return None;
            }
            Some(())
        });

        assert!(
            detected.is_some(),
            "自プロセスが UDP ポート {} を保持していることを検出できるべき",
            port
        );

        assert!(
            detector.pid_holds_port(current_pid, port, PortProtocol::Udp),
            "UDP ポート保持の再検証でも現在プロセスを検出できるべき"
        );

        drop(socket);
    }

    #[test]
    fn test_pid_holds_port_rejects_protocol_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let detector = PortDetector::new();
        let current_pid = ProcessInfoProvider::current_pid();

        assert!(
            !detector.pid_holds_port(current_pid, port, PortProtocol::Udp),
            "TCP で保持しているポートは UDP 保持として扱わない"
        );

        drop(listener);
    }

    #[test]
    fn test_find_by_port_ignores_connected_tcp_client() {
        // TCP は LISTEN のみが対象。接続先ポートを共有するだけの接続済みソケット
        // （サーバー側の accept 済みソケットとクライアント）は保持者に数えない。
        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let client =
            std::net::TcpStream::connect(("127.0.0.1", port)).expect("リスナーへの接続に失敗");
        let (_accepted, _) = listener.accept().expect("接続の受け入れに失敗");
        let current_pid = ProcessInfoProvider::current_pid();

        // 接続済みソケットまで数えていれば、同一 PID でも LISTEN との 2 件以上になる。
        assert_eq!(
            count_raw_socket_entries(current_pid, port),
            1,
            "LISTEN 以外の TCP ソケットを保持者として数えている (port {port})"
        );

        // 接続側のローカルポート（エフェメラルポート）では保持者にならない。
        let client_port = client.local_addr().unwrap().port();
        assert!(!PortDetector::new().pid_holds_port(current_pid, client_port, PortProtocol::Tcp));
    }

    // =========================================================================
    // pid_holds_port の境界値・無効値テスト
    //
    // policy 層が呼び出す前に通常 fail-closed されるが、公開 API として直接
    // 呼ばれても誤って true を返さないことを回帰として固定する。
    // =========================================================================

    #[test]
    fn test_pid_holds_port_rejects_pid_zero() {
        // PID=0 は実プロセスに対応しない。OS のソケット一覧に紐づく PID として
        // 現れないことを期待し、保持なし（false）を返す。
        let detector = PortDetector::new();
        assert!(!detector.pid_holds_port(0, 8080, PortProtocol::Tcp));
        assert!(!detector.pid_holds_port(0, 8080, PortProtocol::Udp));
    }

    #[test]
    fn test_pid_holds_port_rejects_u32_max_pid() {
        // 巨大 PID（u32::MAX 付近）は実プロセスに対応しない。
        let detector = PortDetector::new();
        assert!(!detector.pid_holds_port(u32::MAX, 8080, PortProtocol::Tcp));
        assert!(!detector.pid_holds_port(u32::MAX, 8080, PortProtocol::Udp));
    }

    #[test]
    fn test_pid_holds_port_returns_false_for_unused_port_even_with_real_pid() {
        // 存在する PID（自プロセス）でも、保持していないポート/プロトコルでは false。
        let detector = PortDetector::new();
        let current_pid = ProcessInfoProvider::current_pid();
        // 高位ポートで TCP/UDP を保持していないことを前提に false を期待する。
        assert!(!detector.pid_holds_port(current_pid, 59997, PortProtocol::Tcp));
        assert!(!detector.pid_holds_port(current_pid, 59997, PortProtocol::Udp));
    }
}
