//! safe-kill のポート検出モジュール
//!
//! netstat2 を使用して特定ポートを使用するプロセスを検出する。

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

/// 特定ポートを使用するプロセスを検出するポート検出器
pub struct PortDetector {
    provider: ProcessInfoProvider,
}

impl PortDetector {
    /// 新しい PortDetector を作成
    pub fn new() -> Self {
        Self {
            provider: ProcessInfoProvider::new(),
        }
    }

    /// 指定ポートを使用するすべてのプロセスを検索
    ///
    /// ポートでリッスンしているプロセスを返す（TCP と UDP の両方）。
    /// ポートを共有している場合、複数のプロセスが返される可能性がある。
    pub fn find_by_port(&self, port: u16) -> Result<Vec<PortProcess>, SafeKillError> {
        if port == 0 {
            return Err(SafeKillError::InvalidPort(port.to_string()));
        }

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
                    .provider
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
    /// kill 直前の TOCTOU 緩和用。`find_by_port` と同様の OS 問い合わせを行うが、
    /// 1 PID あたりの軽量チェックとして使うことを想定する。
    /// 取得に失敗した場合は安全側に倒して `false` を返す（fail-closed）。
    pub fn pid_holds_port(&self, pid: u32, port: u16, protocol: PortProtocol) -> bool {
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
            if let Some(info) = self.provider.get(pp.pid) {
                process_infos.push(info);
            }
        }

        Ok(process_infos)
    }

    /// 内部のプロセス情報を更新
    pub fn refresh(&mut self) {
        self.provider.refresh();
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

    #[test]
    fn test_find_by_port_deduplicates_by_pid() {
        let detector = PortDetector::new();
        // 使用されていないポートでは重複が発生しないが、
        // 重複排除ロジック自体が正しく動作することを確認
        let result = detector.find_by_port(59993).unwrap();
        // PIDがソートされていること
        let pids: Vec<u32> = result.iter().map(|p| p.pid).collect();
        let mut sorted_pids = pids.clone();
        sorted_pids.sort();
        assert_eq!(pids, sorted_pids);
        // PIDの重複がないこと
        sorted_pids.dedup();
        assert_eq!(pids.len(), sorted_pids.len());
    }

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
    fn test_socket_matches_port_accepts_udp_by_local_port() {
        let udp = ProtocolSocketInfo::Udp(netstat2::UdpSocketInfo {
            local_addr: "127.0.0.1".parse().unwrap(),
            local_port: 5353,
        });

        assert_eq!(socket_matches_port(&udp, 5353), Some(PortProtocol::Udp));
        assert_eq!(socket_matches_port(&udp, 5354), None);
    }
}
