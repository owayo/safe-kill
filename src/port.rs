//! safe-kill のポート検出モジュール
//!
//! netstat2 を使用して特定ポートを使用するプロセスを検出する。

use std::cell::OnceCell;

use crate::error::SafeKillError;
use crate::process_info::{ProcessInfo, ProcessInfoProvider};
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};

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

/// netstat2 が参照するソケット情報源が読める状態かを確認する
///
/// netstat2 の Linux 実装は `/proc` を `read_dir("/proc/").expect("Can't read /proc/")` で
/// 読むため、`/proc` が未マウント・読み取り不可の環境ではライブラリ内部で panic する。
/// panic の終了コード 101 は公開している終了コード契約（0/1/2/3/4/255）に存在せず、
/// panic メッセージは `terminal.rs` のサニタイズも通らない。呼び出す前に可読性を
/// 確認して、通常の `PortDetectionError` へ落とす。
///
/// macOS の実装は `proc_listallpids` を使い `/proc` を参照しないため確認は不要。
#[cfg(target_os = "linux")]
fn ensure_socket_source_readable(port: u16) -> Result<(), SafeKillError> {
    std::fs::read_dir("/proc")
        .map(|_| ())
        .map_err(|e| SafeKillError::PortDetectionError {
            port,
            reason: format!("Cannot read /proc: {}", e),
        })
}

#[cfg(not(target_os = "linux"))]
fn ensure_socket_source_readable(_port: u16) -> Result<(), SafeKillError> {
    Ok(())
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

        ensure_socket_source_readable(port)?;

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        let sockets_info = get_sockets_info(af_flags, proto_flags).map_err(|e| {
            SafeKillError::PortDetectionError {
                port,
                reason: e.to_string(),
            }
        })?;

        let mut results = Vec::new();

        for si in sockets_info {
            let Some(protocol) = socket_matches_port(&si.protocol_socket_info, port) else {
                continue;
            };

            for pid in &si.associated_pids {
                let pid = *pid;
                // プロセス情報が取れない場合は表示用のプレースホルダ名を入れる。
                // この名前はあくまで UI 出力用であり、denylist 等のポリシー判定には
                // 使ってはならない（呼び出し側で fresh なプロセス情報を再取得すること）。
                let name = self
                    .provider()
                    .get(pid)
                    .map(|p| p.name)
                    .unwrap_or_else(|| format!("pid:{}", pid));

                results.push(PortProcess {
                    pid,
                    name,
                    port,
                    protocol,
                });
            }
        }

        // 重複を除去（同一 PID が異なるソケットで複数回出現する場合がある）
        results.sort_by_key(|p| p.pid);
        results.dedup_by_key(|p| p.pid);

        Ok(results)
    }

    /// 指定 PID が指定ポート/プロトコルをいま保持しているかを再確認する
    ///
    /// kill 直前の TOCTOU 緩和用。判定〜kill の窓を最小化するため、対象 PID ごとに
    /// その都度 OS へ問い合わせ直す。
    ///
    /// 呼び出しコストは軽くない。`get_sockets_info` は 1 回ごとにシステム全体の
    /// ソケット表を走査する（macOS は全 PID × 全 FD に `proc_pidfdinfo`、Linux は
    /// netlink dump に加えて `/proc/*/fd` 全体の `read_link`）。同一ポートを N 個の
    /// プロセスが保持していれば、その N 回ぶん全体走査が走る。窓を狭めるために
    /// この重さを受け入れている、というのが意図した設計上のトレードオフである。
    ///
    /// 取得に失敗した場合は安全側に倒して `false` を返す（fail-closed）。
    pub fn pid_holds_port(&self, pid: u32, port: u16, protocol: PortProtocol) -> bool {
        // 情報源が読めない場合は「保持していない」と断定できないので fail-closed。
        if ensure_socket_source_readable(port).is_err() {
            return false;
        }

        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = match protocol {
            PortProtocol::Tcp => ProtocolFlags::TCP,
            PortProtocol::Udp => ProtocolFlags::UDP,
        };

        let Ok(sockets_info) = get_sockets_info(af_flags, proto_flags) else {
            return false;
        };

        for si in sockets_info {
            if !si.associated_pids.contains(&pid) {
                continue;
            }
            let Some(matched_protocol) = socket_matches_port(&si.protocol_socket_info, port) else {
                continue;
            };
            if matched_protocol == protocol {
                return true;
            }
        }

        false
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

/// 指定ポートの待ち受けソケットか判定する
///
/// TCP は LISTEN 状態のみを対象にする。ESTABLISHED などの接続済みソケットまで
/// kill 対象に含めると、同じローカルポートを持つクライアントプロセスを誤って
/// 終了する可能性がある。UDP は状態を持たないため、ローカルポート一致で対象にする。
fn socket_matches_port(socket: &ProtocolSocketInfo, port: u16) -> Option<PortProtocol> {
    match socket {
        ProtocolSocketInfo::Tcp(tcp_si)
            if tcp_si.local_port == port && tcp_si.state == TcpState::Listen =>
        {
            Some(PortProtocol::Tcp)
        }
        ProtocolSocketInfo::Udp(udp_si) if udp_si.local_port == port => Some(PortProtocol::Udp),
        _ => None,
    }
}

impl Default for PortDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, UdpSocket};
    use std::thread;
    use std::time::Duration;

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
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
        get_sockets_info(af_flags, proto_flags)
            .expect("ソケット一覧の取得に失敗")
            .iter()
            .filter(|si| {
                socket_matches_port(&si.protocol_socket_info, port).is_some()
                    && si.associated_pids.contains(&pid)
            })
            .count()
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

    // 補足: PID 昇順を直接検証するテストは置いていない。TCP と UDP を保持するのは
    // どちらも同じテストプロセスなので、重複排除後は 1 件しか残らず、ソートを削除
    // しても降順へ変えても assert が通ってしまう（検証にならない）。意味のある検証には
    // 同一ポートを別プロセスで保持させる必要があり、テストの複雑さに見合わない。
    // ソート自体は `dedup_by_key` が隣接要素しか見ないことで間接的に要求されており、
    // 上の重複排除テストが壊れれば気付ける。

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
        // find_by_port / pid_holds_port は AddressFamilyFlags::IPV4 | IPV6 を指定するが、
        // 既存テストは 127.0.0.1 (IPv4) 束縛しか検証しておらず、IPv6 のみで待ち受ける
        // 開発サーバー（Node.js が既定で [::] に bind する構成など）を検出できるかが
        // 固定されていなかった。IPv6 が落ちると --port kill が黙って対象なしになるため、
        // AddressFamilyFlags から IPV6 が外れる回帰を検出できるようにする。
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
    fn test_socket_matches_port_accepts_tcp_listen_only() {
        let tcp_listen = ProtocolSocketInfo::Tcp(netstat2::TcpSocketInfo {
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 3000,
            remote_addr: "0.0.0.0".parse().unwrap(),
            remote_port: 0,
            state: TcpState::Listen,
        });
        let tcp_established = ProtocolSocketInfo::Tcp(netstat2::TcpSocketInfo {
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 3000,
            remote_addr: "127.0.0.1".parse().unwrap(),
            remote_port: 4000,
            state: TcpState::Established,
        });

        assert_eq!(
            socket_matches_port(&tcp_listen, 3000),
            Some(PortProtocol::Tcp)
        );
        assert_eq!(socket_matches_port(&tcp_established, 3000), None);
    }

    #[test]
    fn test_socket_matches_port_rejects_tcp_listen_on_other_port() {
        // LISTEN 状態でもローカルポートが一致しなければ対象外（None）。
        // 別ポートで待ち受けるサービスを誤って巻き込まないことを保証する。
        let tcp_listen = ProtocolSocketInfo::Tcp(netstat2::TcpSocketInfo {
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 3000,
            remote_addr: "0.0.0.0".parse().unwrap(),
            remote_port: 0,
            state: TcpState::Listen,
        });

        assert_eq!(socket_matches_port(&tcp_listen, 9999), None);
    }

    #[test]
    fn test_socket_matches_port_accepts_udp_by_local_port() {
        let udp = ProtocolSocketInfo::Udp(netstat2::UdpSocketInfo {
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 5353,
        });

        assert_eq!(socket_matches_port(&udp, 5353), Some(PortProtocol::Udp));
        assert_eq!(socket_matches_port(&udp, 5354), None);
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
