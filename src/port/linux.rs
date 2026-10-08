//! Linux のポート検出: netstat2 を使う実装
//!
//! netstat2 の Linux 実装は netlink の sock_diag でソケット表を取り、`/proc/<pid>/fd` の
//! リンク先 (`socket:[inode]`) と突き合わせて PID を引く。macOS の実装 (`macos.rs`) が
//! 避けている「失敗した問い合わせのバッファを別の PID の結果として返す」欠陥は Linux の経路には無い。

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};

use super::PortProtocol;
use crate::error::SafeKillError;

/// netstat2 が参照するソケット情報源が読める状態かを確認する
///
/// netstat2 の Linux 実装は `/proc` を `read_dir("/proc/").expect("Can't read /proc/")` で
/// 読むため、`/proc` が未マウント・読み取り不可の環境ではライブラリ内部で panic する。
/// panic の終了コード 101 は公開している終了コード契約（0/1/2/3/4/255）に存在せず、
/// panic メッセージは `terminal.rs` のサニタイズも通らない。呼び出す前に可読性を
/// 確認して、通常の `PortDetectionError` へ落とす。
fn ensure_socket_source_readable(port: u16) -> Result<(), SafeKillError> {
    std::fs::read_dir("/proc")
        .map(|_| ())
        .map_err(|e| SafeKillError::PortDetectionError {
            port,
            reason: format!("Cannot read /proc: {}", e),
        })
}

/// 指定ポートを保持している (PID, プロトコル) を、ソケット表の順に列挙する
///
/// 同一 PID が複数のソケットで重複して現れることがある（重複排除は呼び出し側で行う）。
pub(super) fn find_port_holders(port: u16) -> Result<Vec<(u32, PortProtocol)>, SafeKillError> {
    ensure_socket_source_readable(port)?;

    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets_info =
        get_sockets_info(af_flags, proto_flags).map_err(|e| SafeKillError::PortDetectionError {
            port,
            reason: e.to_string(),
        })?;

    let mut holders = Vec::new();
    for si in sockets_info {
        let Some(protocol) = socket_matches_port(&si.protocol_socket_info, port) else {
            continue;
        };
        holders.extend(si.associated_pids.iter().map(|&pid| (pid, protocol)));
    }

    Ok(holders)
}

/// 指定 PID が指定ポート/プロトコルをいま保持しているかを再確認する
///
/// `get_sockets_info` は 1 回ごとにシステム全体のソケット表を走査する（netlink dump に
/// 加えて `/proc/*/fd` 全体の `read_link`）。同一ポートを N 個のプロセスが保持していれば、
/// その N 回ぶん全体走査が走る。判定〜kill の窓を狭めるためにこの重さを受け入れている。
///
/// 取得に失敗した場合は安全側に倒して `false` を返す（fail-closed）。
pub(super) fn pid_holds_port(pid: u32, port: u16, protocol: PortProtocol) -> bool {
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

    sockets_info.iter().any(|si| {
        si.associated_pids.contains(&pid)
            && socket_matches_port(&si.protocol_socket_info, port) == Some(protocol)
    })
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

/// 重複排除する前の、OS のソケット表に載っているエントリ数を数える（テスト用）
#[cfg(test)]
pub(super) fn count_raw_socket_entries(pid: u32, port: u16) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
