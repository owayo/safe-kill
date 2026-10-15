//! macOS のポート検出: libproc を直接呼ぶ実装
//!
//! 以前は netstat2 0.11.2 を使っていたが、その macOS 実装には次の欠陥があった。
//!
//! - `proc_pidfdinfo` は失敗すると -1 ではなく 0 を返し、バッファには何も書かない。netstat2 は
//!   `戻り値 < 0` だけを失敗として扱い、書き込まれていないバッファに `MaybeUninit::assume_init` を
//!   呼んでいた（未定義動作。実際には直前の問い合わせ結果が残る）。列挙した FD が問い合わせ前に
//!   閉じられると、直前に調べたソケット（別プロセスの LISTEN を含む）が次の PID のものとして
//!   報告され、ancestry を迂回する `--port` が無関係なプロセスを kill 対象に選んでいた
//! - ソケットの種別をカーネルのデータに対する `assert!` で確かめており、
//!   SOCK_RAW + IPPROTO_TCP のソケットがあると panic した
//! - 失敗した FD の問い合わせを `Err` として結果に積むため、比較だけを直すと
//!   `get_sockets_info` 全体が失敗するようになる
//!
//! この実装は次の不変条件を守る。
//!
//! 1. 問い合わせのたびに 0 で初期化した新しいバッファを使い、カーネルが書いたと確かめた範囲しか読まない
//! 2. `proc_pidfdinfo` は戻り値が `size_of::<socket_fdinfo>()` と一致したときだけ成功とみなす。
//!    0 以下は OS エラー（errno は直後に読む）、それ以外の正の値は大きさの食い違いとして扱い、
//!    どちらの場合もバッファを解釈しない
//! 3. family / type / protocol / kind / TCP の状態がそろったソケットだけを解釈する。RAW ソケットや
//!    未知の kind、組み合わせの食い違いは無視し、カーネルのデータで panic しない
//! 4. 列挙した後に FD やプロセスが消えたための失敗（EBADF / ENOTSOCK / ESRCH）は、その FD を
//!    読み飛ばす（証拠に数えない）。それ以外の失敗が出たプロセスは候補にしない
//! 5. kill 直前の再検証 (`pid_holds_port`) は対象 PID の FD だけを問い合わせ直す。
//!    システム全体を走査しないので軽く、別の PID のソケット情報が混ざる余地もない

use std::ffi::c_int;
use std::fmt;
use std::io;
use std::ptr;

use nix::errno::Errno;

use super::PortProtocol;
use crate::error::SafeKillError;

/// bindgen が macOS SDK のヘッダから生成した libproc の定義（`build.rs` を参照）
#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
mod sys {
    include!(concat!(env!("OUT_DIR"), "/libproc_sys.rs"));
}

/// u32 の定数を c_int として使う（収まらなければコンパイルエラーにする）
const fn to_c_int(value: u32) -> c_int {
    assert!(value <= c_int::MAX as u32, "c_int に収まらない定数");
    value as c_int
}

const AF_INET: c_int = to_c_int(sys::AF_INET);
const AF_INET6: c_int = to_c_int(sys::AF_INET6);
const SOCK_STREAM: c_int = to_c_int(sys::SOCK_STREAM);
const SOCK_DGRAM: c_int = to_c_int(sys::SOCK_DGRAM);
const IPPROTO_TCP: c_int = to_c_int(sys::IPPROTO_TCP);
const IPPROTO_UDP: c_int = to_c_int(sys::IPPROTO_UDP);
const SOCKINFO_IN: c_int = to_c_int(sys::SOCKINFO_IN);
const SOCKINFO_TCP: c_int = to_c_int(sys::SOCKINFO_TCP);
const TSI_S_LISTEN: c_int = to_c_int(sys::TSI_S_LISTEN);
const PROC_PIDLISTFDS: c_int = to_c_int(sys::PROC_PIDLISTFDS);
const PROC_PIDFDSOCKETINFO: c_int = to_c_int(sys::PROC_PIDFDSOCKETINFO);

/// `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` が成功したときに返すバイト数
const SOCKET_FDINFO_SIZE: c_int = {
    let size = size_of::<sys::socket_fdinfo>();
    assert!(size <= c_int::MAX as usize);
    size as c_int
};

/// `PROC_PIDLISTFDS` が返す 1 件あたりのバイト数
const PROC_FDINFO_SIZE: usize = size_of::<sys::proc_fdinfo>();

/// PID 一覧の初期の件数（`kern.maxproc` の既定値は数千なので、通常は 1 回で収まる）
const PID_LIST_INITIAL_CAPACITY: usize = 4096;
/// PID 一覧の件数の上限。macOS の PID は 99999 (PID_MAX) を超えないので、これが埋まり切ることはない
const PID_LIST_MAX_CAPACITY: usize = 1 << 17;
/// FD 一覧の初期の件数
const FD_LIST_INITIAL_CAPACITY: usize = 1024;
/// FD 一覧の件数の上限（`kern.maxfilesperproc` は数万〜 50 万程度）。超えたプロセスは候補にしない
const FD_LIST_MAX_CAPACITY: usize = 1 << 22;

// 上限まで広げたバッファの大きさも c_int で渡せること
const _: () = assert!(PID_LIST_MAX_CAPACITY * size_of::<c_int>() <= c_int::MAX as usize);
const _: () = assert!(FD_LIST_MAX_CAPACITY * PROC_FDINFO_SIZE <= c_int::MAX as usize);

/// libproc を 1 回呼んだ生の結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawCall {
    /// 関数の戻り値
    ret: c_int,
    /// 呼び出しの直後に読んだ errno（呼び出しの前に 0 へ戻している）
    errno: i32,
}

impl RawCall {
    /// バッファの大きさを c_int で表せないため、呼び出さずに失敗させるときの結果
    const INVALID_SIZE: Self = Self {
        ret: 0,
        errno: Errno::EINVAL as i32,
    };

    /// 戻り値と、その直後の errno をまとめる（errno が他の呼び出しで上書きされる前に読む）
    fn capture(ret: c_int) -> Self {
        Self {
            ret,
            errno: Errno::last_raw(),
        }
    }
}

/// libproc の呼び出し口
///
/// 実際の libproc は `SystemLibproc`。テストでは失敗・大きさの食い違い・前回の内容が残った
/// バッファ・列挙と問い合わせの間の FD の消失を注入するために差し替える。
trait Libproc {
    /// `proc_listallpids(buf, buf のバイト数)`。戻り値はバイト数ではなく PID の「件数」
    fn list_all_pids(&self, buf: &mut [c_int]) -> RawCall;

    /// `proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf, buf のバイト数)`。戻り値は書き込んだ「バイト数」
    fn list_fds(&self, pid: c_int, buf: &mut [sys::proc_fdinfo]) -> RawCall;

    /// `proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, buf, socket_fdinfo のバイト数)`。
    /// 戻り値は書き込んだ「バイト数」
    fn socket_info(&self, pid: c_int, fd: c_int, buf: &mut sys::socket_fdinfo) -> RawCall;
}

/// 実際の libproc を呼ぶ実装
struct SystemLibproc;

impl Libproc for SystemLibproc {
    fn list_all_pids(&self, buf: &mut [c_int]) -> RawCall {
        let Some(size) = byte_size(buf) else {
            return RawCall::INVALID_SIZE;
        };
        Errno::clear();
        // SAFETY: buf は size バイトの書き込み可能な領域。libproc は渡した大きさを超えて書かない
        let ret = unsafe { sys::proc_listallpids(buf.as_mut_ptr().cast(), size) };
        RawCall::capture(ret)
    }

    fn list_fds(&self, pid: c_int, buf: &mut [sys::proc_fdinfo]) -> RawCall {
        let Some(size) = byte_size(buf) else {
            return RawCall::INVALID_SIZE;
        };
        Errno::clear();
        // SAFETY: buf は size バイトの書き込み可能な領域。libproc は渡した大きさを超えて書かない
        let ret =
            unsafe { sys::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf.as_mut_ptr().cast(), size) };
        RawCall::capture(ret)
    }

    fn socket_info(&self, pid: c_int, fd: c_int, buf: &mut sys::socket_fdinfo) -> RawCall {
        Errno::clear();
        // SAFETY: buf は socket_fdinfo 1 つ分 (SOCKET_FDINFO_SIZE バイト) の書き込み可能な領域
        let ret = unsafe {
            sys::proc_pidfdinfo(
                pid,
                fd,
                PROC_PIDFDSOCKETINFO,
                ptr::from_mut(buf).cast(),
                SOCKET_FDINFO_SIZE,
            )
        };
        RawCall::capture(ret)
    }
}

/// スライスのバイト数を c_int で表す（収まらなければ None。実際より大きい値は決して渡さない）
fn byte_size<T>(buf: &[T]) -> Option<c_int> {
    c_int::try_from(size_of_val(buf)).ok()
}

/// libproc の問い合わせの失敗
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryError {
    /// 列挙した後に対象が消えた（FD が閉じられた: EBADF、FD がソケット以外に置き換わった:
    /// ENOTSOCK、プロセスが終了した: ESRCH）。その FD は証拠に数えず読み飛ばす
    Gone(Errno),
    /// それ以外の OS エラー（他ユーザーのプロセスに対する EPERM など）。生の errno を持つ
    Os(i32),
    /// 戻り値が想定した大きさと合わない（バッファを解釈できない）
    UnexpectedSize(c_int),
    /// 上限まで広げても一覧が埋まり切った（全件を取れたと言えない）
    Truncated,
}

impl QueryError {
    /// 失敗した呼び出し（戻り値が 0 以下）を分類する
    fn from_failed_call(raw: RawCall) -> Self {
        // errno を立てない失敗は、戻り値が想定外だったものとして扱う
        if raw.errno == 0 {
            return Self::UnexpectedSize(raw.ret);
        }
        match Errno::from_raw(raw.errno) {
            errno @ (Errno::EBADF | Errno::ENOTSOCK | Errno::ESRCH) => Self::Gone(errno),
            _ => Self::Os(raw.errno),
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gone(errno) => write!(f, "{}", io::Error::from_raw_os_error(*errno as i32)),
            Self::Os(errno) => write!(f, "{}", io::Error::from_raw_os_error(*errno)),
            Self::UnexpectedSize(ret) => write!(f, "unexpected return value {ret}"),
            Self::Truncated => write!(f, "the list did not fit within the size limit"),
        }
    }
}

/// 一覧を取得する。バッファが埋まり切ったら（取りこぼしの可能性がある）倍に広げて取り直す
///
/// 呼び出しのたびに `zero` で埋めた新しいバッファを `call` へ渡し、`count_of` が戻り値から求めた
/// 件数の範囲だけを返す。件数がバッファの長さを超えていたら解釈せずに失敗させる。
fn fetch_growing<T: Copy>(
    zero: T,
    (initial, max): (usize, usize),
    mut call: impl FnMut(&mut [T]) -> RawCall,
    count_of: impl Fn(RawCall) -> Result<usize, QueryError>,
) -> Result<Vec<T>, QueryError> {
    let mut capacity = initial;
    loop {
        let mut buf = vec![zero; capacity];
        let raw = call(&mut buf);
        let count = count_of(raw)?;
        if count > capacity {
            return Err(QueryError::UnexpectedSize(raw.ret));
        }
        if count < capacity {
            buf.truncate(count);
            return Ok(buf);
        }
        if capacity >= max {
            return Err(QueryError::Truncated);
        }
        capacity = capacity.saturating_mul(2).min(max);
    }
}

/// `proc_listallpids` の戻り値を件数に変換する
///
/// 戻り値はバイト数ではなく PID の件数で、失敗すると -1 ではなく 0 を返す（errno は立つ）。
/// 自プロセスが必ず含まれるので、成功して 0 件ということはない。0 以下はすべて失敗とする。
fn pid_count(raw: RawCall) -> Result<usize, QueryError> {
    if raw.ret <= 0 {
        return Err(QueryError::from_failed_call(raw));
    }
    usize::try_from(raw.ret).map_err(|_| QueryError::UnexpectedSize(raw.ret))
}

/// `proc_pidinfo(PROC_PIDLISTFDS)` の戻り値（バイト数）を件数に変換する
///
/// FD を 1 つも開いていないプロセスは、errno を立てずに 0 を返す（失敗も 0 を返すので errno で見分ける）。
/// 要素の大きさで割り切れないバイト数は解釈しない。
fn fd_count(raw: RawCall) -> Result<usize, QueryError> {
    if raw.ret == 0 && raw.errno == 0 {
        return Ok(0);
    }
    if raw.ret <= 0 {
        return Err(QueryError::from_failed_call(raw));
    }
    let bytes = usize::try_from(raw.ret).map_err(|_| QueryError::UnexpectedSize(raw.ret))?;
    if bytes % PROC_FDINFO_SIZE != 0 {
        return Err(QueryError::UnexpectedSize(raw.ret));
    }
    Ok(bytes / PROC_FDINFO_SIZE)
}

/// すべてのプロセスの PID を列挙する（PID 0 の kernel_task と 0 埋めは除く）
fn list_all_pids(api: &impl Libproc) -> Result<Vec<c_int>, QueryError> {
    let pids = fetch_growing(
        0,
        (PID_LIST_INITIAL_CAPACITY, PID_LIST_MAX_CAPACITY),
        |buf| api.list_all_pids(buf),
        pid_count,
    )?;
    Ok(pids.into_iter().filter(|&pid| pid > 0).collect())
}

/// 1 プロセスが開いているソケットの FD 番号を列挙する
fn list_socket_fds(api: &impl Libproc, pid: c_int) -> Result<Vec<c_int>, QueryError> {
    let empty = sys::proc_fdinfo {
        proc_fd: 0,
        proc_fdtype: 0,
    };
    let entries = fetch_growing(
        empty,
        (FD_LIST_INITIAL_CAPACITY, FD_LIST_MAX_CAPACITY),
        |buf| api.list_fds(pid, buf),
        fd_count,
    )?;
    Ok(entries
        .into_iter()
        .filter(|entry| entry.proc_fdtype == sys::PROX_FDTYPE_SOCKET)
        .map(|entry| entry.proc_fd)
        .collect())
}

/// 全バイトが 0 の `socket_fdinfo` を作る
fn zeroed_socket_fdinfo() -> sys::socket_fdinfo {
    // SAFETY: socket_fdinfo は bindgen が C の構造体から生成した型で、整数・整数の配列と、
    // それらから成る構造体・共用体だけでできている（ポインタ・参照・enum・bool を含まない）。
    // 全ビット 0 はどのフィールドにとっても正当な値である。
    unsafe { std::mem::zeroed() }
}

/// 1 つの FD のソケット情報を問い合わせる
///
/// 戻り値が `size_of::<socket_fdinfo>()` と一致したときだけ成功とする。それ以外ではバッファを一切読まない。
fn query_socket(
    api: &impl Libproc,
    pid: c_int,
    fd: c_int,
) -> Result<sys::socket_fdinfo, QueryError> {
    // 問い合わせのたびに 0 で初期化した新しいバッファを使い、前回の内容が残る余地を作らない
    let mut info = zeroed_socket_fdinfo();
    let raw = api.socket_info(pid, fd, &mut info);
    if raw.ret == SOCKET_FDINFO_SIZE {
        Ok(info)
    } else if raw.ret <= 0 {
        Err(QueryError::from_failed_call(raw))
    } else {
        Err(QueryError::UnexpectedSize(raw.ret))
    }
}

/// ソケットがポートを待ち受けているなら、そのプロトコルとポート番号を返す
///
/// - TCP: family が IPv4/IPv6、type が SOCK_STREAM、protocol が IPPROTO_TCP、kind が SOCKINFO_TCP で、
///   状態が LISTEN のものだけ。ESTABLISHED などの接続済みソケットまで含めると、同じローカルポートを
///   持つクライアントプロセスを誤って終了しかねない
/// - UDP: family が IPv4/IPv6、type が SOCK_DGRAM、protocol が IPPROTO_UDP、kind が SOCKINFO_IN のもの。
///   状態を持たないので、ローカルポートの一致で対象にする
/// - それ以外（RAW ソケット、ICMP、UNIX ドメイン、未知の kind、組み合わせの食い違い）は無視する
fn listening_endpoint(info: &sys::socket_fdinfo) -> Option<(PortProtocol, u16)> {
    let si = &info.psi;
    if si.soi_family != AF_INET && si.soi_family != AF_INET6 {
        return None;
    }

    if si.soi_kind == SOCKINFO_TCP && si.soi_type == SOCK_STREAM && si.soi_protocol == IPPROTO_TCP {
        // SAFETY: 共用体 soi_proto のどのフィールドも整数だけから成り、バッファは 0 で初期化した
        // うえでカーネルが書いたもの。どのフィールドを読んでも未定義動作にはならない。
        // kind が SOCKINFO_TCP のとき、カーネルは pri_tcp を埋める
        let tcp = unsafe { si.soi_proto.pri_tcp };
        if tcp.tcpsi_state != TSI_S_LISTEN {
            return None;
        }
        return decode_port(tcp.tcpsi_ini.insi_lport).map(|port| (PortProtocol::Tcp, port));
    }

    if si.soi_kind == SOCKINFO_IN && si.soi_type == SOCK_DGRAM && si.soi_protocol == IPPROTO_UDP {
        // SAFETY: 上と同じ。kind が SOCKINFO_IN のとき、カーネルは pri_in を埋める
        let udp = unsafe { si.soi_proto.pri_in };
        return decode_port(udp.insi_lport).map(|port| (PortProtocol::Udp, port));
    }

    None
}

/// `in_sockinfo::insi_lport` からポート番号を取り出す
///
/// カーネルはネットワークバイトオーダの `u_short` をそのまま int へ代入している
/// （符号拡張は無く、上位 16 ビットは 0）。16 ビットに収まらない値（負数を含む）は解釈せず、
/// ポート 0（未割り当て）とともに「ポートなし」とする。panic はしない。
fn decode_port(insi_lport: c_int) -> Option<u16> {
    let network_order = u16::try_from(insi_lport).ok()?;
    let port = u16::from_be(network_order);
    (port != 0).then_some(port)
}

/// 1 プロセスのソケットを調べ、指定ポートを待ち受けているもののプロトコルを FD の順に返す
///
/// 列挙した後に消えた FD は読み飛ばす（証拠に数えない）。それ以外の失敗が 1 つでもあれば
/// `Err` を返す。呼び出し側はそのプロセスを候補にしない（一部しか見えていないプロセスを信用しない）。
fn scan_process(
    api: &impl Libproc,
    pid: c_int,
    port: u16,
) -> Result<Vec<PortProtocol>, QueryError> {
    let mut found = Vec::new();
    for fd in list_socket_fds(api, pid)? {
        let info = match query_socket(api, pid, fd) {
            Ok(info) => info,
            Err(QueryError::Gone(_)) => continue,
            Err(e) => return Err(e),
        };
        if let Some((protocol, bound_port)) = listening_endpoint(&info)
            && bound_port == port
        {
            found.push(protocol);
        }
    }
    Ok(found)
}

/// 指定ポートを保持している (PID, プロトコル) を列挙する
///
/// PID の列挙順に並び、同じ PID の中では FD の順に並ぶ（重複排除は呼び出し側で行う）。
/// PID の一覧そのものを取れないときだけエラーにする。個々のプロセスを調べ切れないとき
/// （他ユーザーのプロセスへの EPERM、走査中の終了、想定外の失敗）は、そのプロセスを
/// 候補にしないだけで走査を続ける。
pub(super) fn find_port_holders(port: u16) -> Result<Vec<(u32, PortProtocol)>, SafeKillError> {
    find_port_holders_with(&SystemLibproc, port)
}

fn find_port_holders_with(
    api: &impl Libproc,
    port: u16,
) -> Result<Vec<(u32, PortProtocol)>, SafeKillError> {
    let pids = list_all_pids(api).map_err(|e| SafeKillError::PortDetectionError {
        port,
        reason: format!("Cannot list processes: {e}"),
    })?;

    let mut holders = Vec::new();
    for pid in pids {
        // list_all_pids は正の PID だけを返すので、変換は失敗しない
        let Ok(holder) = u32::try_from(pid) else {
            continue;
        };
        let Ok(protocols) = scan_process(api, pid, port) else {
            continue;
        };
        holders.extend(protocols.into_iter().map(|protocol| (holder, protocol)));
    }
    Ok(holders)
}

/// 指定 PID が指定ポート/プロトコルをいま保持しているかを確かめる（kill 直前の再検証）
///
/// 対象 PID の FD だけを問い合わせ直す。調べ切れなかったとき（想定外の失敗）は、保持して
/// いないものとして `false` を返す（fail-closed）。
pub(super) fn pid_holds_port(pid: u32, port: u16, protocol: PortProtocol) -> bool {
    pid_holds_port_with(&SystemLibproc, pid, port, protocol)
}

fn pid_holds_port_with(api: &impl Libproc, pid: u32, port: u16, protocol: PortProtocol) -> bool {
    // PID 0 (kernel_task) と c_int に収まらない値は、問い合わせる前に弾く
    let Ok(pid) = c_int::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    scan_process(api, pid, port).is_ok_and(|found| found.contains(&protocol))
}

/// 重複排除する前の、指定 PID が指定ポートで保持しているソケットの件数（テスト用）
#[cfg(test)]
pub(super) fn count_raw_socket_entries(pid: u32, port: u16) -> usize {
    let pid = c_int::try_from(pid).expect("PID が c_int に収まらない");
    scan_process(&SystemLibproc, pid, port)
        .expect("ソケットの走査に失敗")
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::fs::File;
    use std::net::{TcpListener, UdpSocket};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
    use std::sync::{Mutex, PoisonError};

    use nix::fcntl::{FcntlArg, fcntl};

    // =========================================================================
    // テスト用の部品
    // =========================================================================

    /// TCP ソケットの情報を組み立てる
    fn tcp_socket(family: c_int, state: c_int, port: u16) -> sys::socket_fdinfo {
        let mut info = zeroed_socket_fdinfo();
        info.psi.soi_family = family;
        info.psi.soi_type = SOCK_STREAM;
        info.psi.soi_protocol = IPPROTO_TCP;
        info.psi.soi_kind = SOCKINFO_TCP;
        // SAFETY: 共用体のフィールドは整数だけから成る。0 初期化したものを読み、書き換えて戻す
        let mut tcp = unsafe { info.psi.soi_proto.pri_tcp };
        tcp.tcpsi_state = state;
        tcp.tcpsi_ini.insi_lport = c_int::from(port.to_be());
        info.psi.soi_proto.pri_tcp = tcp;
        info
    }

    /// TCP の LISTEN ソケットの情報を組み立てる
    fn tcp_listen(port: u16) -> sys::socket_fdinfo {
        tcp_socket(AF_INET, TSI_S_LISTEN, port)
    }

    /// UDP ソケットの情報を組み立てる
    fn udp_socket(family: c_int, port: u16) -> sys::socket_fdinfo {
        let mut info = zeroed_socket_fdinfo();
        info.psi.soi_family = family;
        info.psi.soi_type = SOCK_DGRAM;
        info.psi.soi_protocol = IPPROTO_UDP;
        info.psi.soi_kind = SOCKINFO_IN;
        // SAFETY: tcp_socket と同じ
        let mut udp = unsafe { info.psi.soi_proto.pri_in };
        udp.insi_lport = c_int::from(port.to_be());
        info.psi.soi_proto.pri_in = udp;
        info
    }

    /// ソケットの FD 一覧の 1 件を組み立てる
    fn socket_fd(fd: c_int) -> sys::proc_fdinfo {
        sys::proc_fdinfo {
            proc_fd: fd,
            proc_fdtype: sys::PROX_FDTYPE_SOCKET,
        }
    }

    fn raw(ret: c_int, errno: Errno) -> RawCall {
        RawCall {
            ret,
            errno: errno as i32,
        }
    }

    /// errno を立てない結果
    fn raw_no_errno(ret: c_int) -> RawCall {
        RawCall { ret, errno: 0 }
    }

    /// ソケット情報の問い合わせへの応答
    #[derive(Clone, Copy)]
    enum SocketReply {
        /// 成功: 内容を書き込み、socket_fdinfo の大きさを返す
        Success(sys::socket_fdinfo),
        /// 失敗: `prefill` をバッファへ書き込んだうえで、指定の戻り値と errno を返す
        Failure {
            raw: RawCall,
            prefill: sys::socket_fdinfo,
        },
        /// 失敗: 直前に成功した問い合わせの内容をバッファへ書き戻してから返す
        /// （netstat2 で起きた「書き込まれていないバッファに前回の結果が残る」状況の再現）
        FailureWithStaleBuffer(RawCall),
    }

    /// 台本どおりに応答するテスト用の libproc
    ///
    /// 載っていない PID の FD 一覧は ESRCH、載っていない (PID, FD) の問い合わせは EBADF で失敗する。
    #[derive(Default)]
    struct FakeLibproc {
        /// proc_listallpids が返す PID（バッファに収まる分だけ書き、書いた件数を返す）
        pids: Vec<c_int>,
        /// proc_listallpids の応答を差し替える
        pid_list_override: Option<RawCall>,
        /// PID ごとの FD 一覧（バッファに収まる分だけ書き、書いたバイト数を返す）
        fds: HashMap<c_int, Vec<sys::proc_fdinfo>>,
        /// PID ごとの FD 一覧の応答の差し替え
        fd_list_override: HashMap<c_int, RawCall>,
        /// (PID, FD) ごとのソケット情報の応答
        sockets: HashMap<(c_int, c_int), SocketReply>,
        /// 直前に成功として書き込んだソケット情報
        last_written: Cell<Option<sys::socket_fdinfo>>,
        /// proc_listallpids に渡されたバッファの長さ（呼び出し順）
        pid_list_capacities: RefCell<Vec<usize>>,
        /// PROC_PIDLISTFDS に渡されたバッファの長さ（呼び出し順）
        fd_list_capacities: RefCell<Vec<usize>>,
    }

    impl FakeLibproc {
        /// 1 プロセスが 1 つのソケット FD を持つ台本
        fn single_socket(pid: c_int, fd: c_int, reply: SocketReply) -> Self {
            let mut fake = Self {
                pids: vec![pid],
                ..Self::default()
            };
            fake.fds.insert(pid, vec![socket_fd(fd)]);
            fake.sockets.insert((pid, fd), reply);
            fake
        }
    }

    impl Libproc for FakeLibproc {
        fn list_all_pids(&self, buf: &mut [c_int]) -> RawCall {
            self.pid_list_capacities.borrow_mut().push(buf.len());
            if let Some(raw) = self.pid_list_override {
                return raw;
            }
            let count = self.pids.len().min(buf.len());
            buf[..count].copy_from_slice(&self.pids[..count]);
            raw_no_errno(c_int::try_from(count).unwrap())
        }

        fn list_fds(&self, pid: c_int, buf: &mut [sys::proc_fdinfo]) -> RawCall {
            self.fd_list_capacities.borrow_mut().push(buf.len());
            if let Some(raw) = self.fd_list_override.get(&pid) {
                return *raw;
            }
            let Some(entries) = self.fds.get(&pid) else {
                return raw(0, Errno::ESRCH);
            };
            let count = entries.len().min(buf.len());
            buf[..count].copy_from_slice(&entries[..count]);
            raw_no_errno(c_int::try_from(count * PROC_FDINFO_SIZE).unwrap())
        }

        fn socket_info(&self, pid: c_int, fd: c_int, buf: &mut sys::socket_fdinfo) -> RawCall {
            match self.sockets.get(&(pid, fd)).copied() {
                Some(SocketReply::Success(info)) => {
                    *buf = info;
                    self.last_written.set(Some(info));
                    raw_no_errno(SOCKET_FDINFO_SIZE)
                }
                Some(SocketReply::Failure { raw, prefill }) => {
                    *buf = prefill;
                    raw
                }
                Some(SocketReply::FailureWithStaleBuffer(raw)) => {
                    if let Some(previous) = self.last_written.get() {
                        *buf = previous;
                    }
                    raw
                }
                None => raw(0, Errno::EBADF),
            }
        }
    }

    // =========================================================================
    // (a) 失敗した問い合わせのバッファは、中身が LISTEN に見えても決して受け入れない
    // =========================================================================

    /// 失敗とみなすべき戻り値の組（大きさが一致しない正の値を含む）
    fn failed_calls() -> Vec<RawCall> {
        vec![
            raw(0, Errno::EBADF),
            raw(0, Errno::ENOTSOCK),
            raw(0, Errno::ESRCH),
            raw(0, Errno::EPERM),
            raw(0, Errno::EINVAL),
            raw_no_errno(0),
            raw(-1, Errno::EPERM),
            raw_no_errno(-1),
            raw_no_errno(c_int::MIN),
            raw_no_errno(1),
            raw_no_errno(16),
            raw_no_errno(SOCKET_FDINFO_SIZE - 1),
            raw_no_errno(SOCKET_FDINFO_SIZE + 1),
            raw_no_errno(c_int::MAX),
        ]
    }

    #[test]
    fn test_failed_query_with_listen_shaped_buffer_is_never_accepted() {
        // libproc の proc_pidfdinfo は失敗すると 0 を返し、バッファには書かない。netstat2 は
        // これを成功と誤認し、前回の内容が残ったバッファを解釈していた。ここではバッファを
        // 「対象ポートの LISTEN」そのものの形に埋めたうえで失敗を返し、どの経路でも
        // 証拠として扱われないことを確かめる。
        let pid = 4242;
        let fd = 7;
        let port = 3998;
        for prefill in [tcp_listen(port), udp_socket(AF_INET, port)] {
            for raw in failed_calls() {
                let fake =
                    FakeLibproc::single_socket(pid, fd, SocketReply::Failure { raw, prefill });

                assert!(
                    query_socket(&fake, pid, fd).is_err(),
                    "失敗した問い合わせ {raw:?} を成功として扱った"
                );
                let holders = find_port_holders_with(&fake, port).expect("PID 一覧は取れる");
                assert!(
                    holders.is_empty(),
                    "失敗した問い合わせ {raw:?} のバッファからポート保持者を作った: {holders:?}"
                );
                for protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
                    assert!(
                        !pid_holds_port_with(&fake, 4242, port, protocol),
                        "失敗した問い合わせ {raw:?} で kill 直前の再検証を通した"
                    );
                }
            }
        }
    }

    #[test]
    fn test_failed_query_classification() {
        // 列挙後に消えた FD / プロセスだけが Gone（読み飛ばす）。errno の無い失敗と大きさの
        // 食い違いは UnexpectedSize、それ以外は Os として、そのプロセスを候補から外す。
        let pid = 1;
        let fd = 3;
        let cases = [
            (raw(0, Errno::EBADF), QueryError::Gone(Errno::EBADF)),
            (raw(0, Errno::ENOTSOCK), QueryError::Gone(Errno::ENOTSOCK)),
            (raw(0, Errno::ESRCH), QueryError::Gone(Errno::ESRCH)),
            (raw(0, Errno::EPERM), QueryError::Os(Errno::EPERM as i32)),
            (raw_no_errno(0), QueryError::UnexpectedSize(0)),
            (raw_no_errno(-1), QueryError::UnexpectedSize(-1)),
            (
                raw_no_errno(SOCKET_FDINFO_SIZE - 1),
                QueryError::UnexpectedSize(SOCKET_FDINFO_SIZE - 1),
            ),
            (
                raw_no_errno(SOCKET_FDINFO_SIZE + 1),
                QueryError::UnexpectedSize(SOCKET_FDINFO_SIZE + 1),
            ),
        ];
        for (raw, expected) in cases {
            let fake = FakeLibproc::single_socket(
                pid,
                fd,
                SocketReply::Failure {
                    raw,
                    prefill: tcp_listen(80),
                },
            );
            assert_eq!(
                query_socket(&fake, pid, fd).err(),
                Some(expected),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn test_query_socket_starts_from_zeroed_buffer() {
        // 前の問い合わせの内容が次の問い合わせのバッファへ持ち越されないこと。
        // 成功した応答の直後に「バッファへ何も書かずに成功の大きさを返す」応答を置き、
        // 2 回目の結果が 0 埋めのまま（= 何も解釈できない）であることを確かめる。
        struct WritesNothing;
        impl Libproc for WritesNothing {
            fn list_all_pids(&self, _: &mut [c_int]) -> RawCall {
                unreachable!()
            }
            fn list_fds(&self, _: c_int, _: &mut [sys::proc_fdinfo]) -> RawCall {
                unreachable!()
            }
            fn socket_info(&self, _: c_int, _: c_int, _: &mut sys::socket_fdinfo) -> RawCall {
                raw_no_errno(SOCKET_FDINFO_SIZE)
            }
        }

        let fake = FakeLibproc::single_socket(1, 3, SocketReply::Success(tcp_listen(3998)));
        assert!(query_socket(&fake, 1, 3).is_ok());

        let info = query_socket(&WritesNothing, 1, 3).expect("成功の大きさを返している");
        assert_eq!(listening_endpoint(&info), None);
        assert_eq!(info.psi.soi_family, 0);
        assert_eq!(info.psi.soi_kind, 0);
    }

    // =========================================================================
    // (b) ソケットの種別・状態・ポートの解読
    // =========================================================================

    #[test]
    fn test_listening_endpoint_accepts_tcp_listen_on_ipv4_and_ipv6() {
        assert_eq!(
            listening_endpoint(&tcp_socket(AF_INET, TSI_S_LISTEN, 3000)),
            Some((PortProtocol::Tcp, 3000))
        );
        assert_eq!(
            listening_endpoint(&tcp_socket(AF_INET6, TSI_S_LISTEN, 3000)),
            Some((PortProtocol::Tcp, 3000))
        );
    }

    #[test]
    fn test_listening_endpoint_rejects_non_listen_tcp() {
        // TSI_S_CLOSED (0) / SYN_SENT (2) / ESTABLISHED (4) / TIME_WAIT (10) / 範囲外の値
        for state in [0, 2, 3, 4, 5, 9, 10, 11, -1, c_int::MAX] {
            assert_eq!(
                listening_endpoint(&tcp_socket(AF_INET, state, 3000)),
                None,
                "TCP の状態 {state} を LISTEN として扱った"
            );
        }
    }

    #[test]
    fn test_listening_endpoint_accepts_udp_on_ipv4_and_ipv6() {
        assert_eq!(
            listening_endpoint(&udp_socket(AF_INET, 5353)),
            Some((PortProtocol::Udp, 5353))
        );
        assert_eq!(
            listening_endpoint(&udp_socket(AF_INET6, 5353)),
            Some((PortProtocol::Udp, 5353))
        );
    }

    #[test]
    fn test_listening_endpoint_rejects_raw_socket_without_panicking() {
        // SOCK_RAW + IPPROTO_TCP は kind が SOCKINFO_IN になる。netstat2 は protocol だけを見て
        // TCP の解析へ進み、kind に対する assert! で panic した。ここでは無視するだけにする。
        let mut info = udp_socket(AF_INET, 3000);
        info.psi.soi_type = 3; // SOCK_RAW
        info.psi.soi_protocol = IPPROTO_TCP;
        assert_eq!(listening_endpoint(&info), None);

        // 種別の組み合わせが一つでも食い違えば対象外
        let mut kind_in_but_tcp = tcp_listen(3000);
        kind_in_but_tcp.psi.soi_kind = SOCKINFO_IN;
        assert_eq!(listening_endpoint(&kind_in_but_tcp), None);

        let mut tcp_kind_but_dgram = tcp_listen(3000);
        tcp_kind_but_dgram.psi.soi_type = SOCK_DGRAM;
        assert_eq!(listening_endpoint(&tcp_kind_but_dgram), None);

        let mut tcp_kind_but_udp_protocol = tcp_listen(3000);
        tcp_kind_but_udp_protocol.psi.soi_protocol = IPPROTO_UDP;
        assert_eq!(listening_endpoint(&tcp_kind_but_udp_protocol), None);

        let mut udp_but_tcp_kind = udp_socket(AF_INET, 3000);
        udp_but_tcp_kind.psi.soi_kind = SOCKINFO_TCP;
        assert_eq!(listening_endpoint(&udp_but_tcp_kind), None);

        // ICMP のデータグラムソケット (SOCK_DGRAM + IPPROTO_ICMP) は UDP ではない
        let mut icmp = udp_socket(AF_INET, 3000);
        icmp.psi.soi_protocol = 1;
        assert_eq!(listening_endpoint(&icmp), None);
    }

    #[test]
    fn test_listening_endpoint_rejects_unknown_kind_and_family() {
        for kind in [0, 3, 4, 5, 6, 7, 99, -1] {
            let mut info = tcp_listen(3000);
            info.psi.soi_kind = kind;
            assert_eq!(listening_endpoint(&info), None, "kind {kind}");
        }
        // AF_UNIX (1) / AF_UNSPEC (0) / AF_SYSTEM (32) / 範囲外
        for family in [0, 1, 32, -1, 1000] {
            let mut info = tcp_listen(3000);
            info.psi.soi_family = family;
            assert_eq!(listening_endpoint(&info), None, "family {family}");
        }
    }

    #[test]
    fn test_decode_port() {
        // 実機の proc_pidfdinfo で確かめた値: 40001 は 0x419c、65534 は 0xfeff として入っている
        assert_eq!(decode_port(0x419c), Some(40001));
        assert_eq!(decode_port(0xfeff), Some(65534));
        assert_eq!(decode_port(c_int::from(80u16.to_be())), Some(80));
        assert_eq!(decode_port(c_int::from(65535u16.to_be())), Some(65535));
        // ポート 0（未割り当て）は「ポートなし」
        assert_eq!(decode_port(0), None);
        // 16 ビットに収まらない値・負数は解釈しない（panic もしない）
        assert_eq!(decode_port(0x1_0000), None);
        assert_eq!(decode_port(-1), None);
        assert_eq!(decode_port(c_int::MIN), None);
        assert_eq!(decode_port(c_int::MAX), None);
    }

    #[test]
    fn test_listening_endpoint_rejects_port_zero() {
        assert_eq!(listening_endpoint(&tcp_listen(0)), None);
        assert_eq!(listening_endpoint(&udp_socket(AF_INET, 0)), None);
    }

    // =========================================================================
    // (c) 列挙の途中で失敗した問い合わせが、別の PID の証拠にならない
    // =========================================================================

    /// PID L が対象ポートで LISTEN し、続く PID C の FD は問い合わせ前に閉じられる台本
    fn listener_then_closed_fd(port: u16, failure: SocketReply) -> FakeLibproc {
        let mut fake = FakeLibproc {
            pids: vec![100, 200],
            ..FakeLibproc::default()
        };
        fake.fds.insert(100, vec![socket_fd(5)]);
        fake.fds.insert(200, vec![socket_fd(9)]);
        fake.sockets
            .insert((100, 5), SocketReply::Success(tcp_listen(port)));
        fake.sockets.insert((200, 9), failure);
        fake
    }

    #[test]
    fn test_failure_after_listener_does_not_attribute_listener_to_next_pid() {
        // netstat2 の再現: L を問い合わせた直後に C の FD が閉じられ（EBADF）、C の問い合わせは
        // 失敗するがバッファには L の内容が残っている。C を候補にしてはならない。
        let port = 3998;
        for failure in [
            SocketReply::FailureWithStaleBuffer(raw(0, Errno::EBADF)),
            SocketReply::FailureWithStaleBuffer(raw(0, Errno::ENOTSOCK)),
            SocketReply::FailureWithStaleBuffer(raw(0, Errno::ESRCH)),
            SocketReply::FailureWithStaleBuffer(raw(0, Errno::EPERM)),
            SocketReply::FailureWithStaleBuffer(raw_no_errno(0)),
            SocketReply::FailureWithStaleBuffer(raw_no_errno(SOCKET_FDINFO_SIZE - 8)),
        ] {
            let fake = listener_then_closed_fd(port, failure);

            let holders = find_port_holders_with(&fake, port).expect("PID 一覧は取れる");
            assert_eq!(holders, vec![(100, PortProtocol::Tcp)]);

            assert!(pid_holds_port_with(&fake, 100, port, PortProtocol::Tcp));
            assert!(
                !pid_holds_port_with(&fake, 200, port, PortProtocol::Tcp),
                "問い合わせに失敗した PID を kill 直前の再検証で保持者とみなした"
            );
        }
    }

    #[test]
    fn test_gone_fd_is_skipped_but_other_sockets_still_count() {
        // 消えた FD は読み飛ばすだけで、同じプロセスの他のソケットの証拠は打ち消さない
        let port = 8080;
        let mut fake = FakeLibproc {
            pids: vec![300],
            ..FakeLibproc::default()
        };
        fake.fds.insert(300, vec![socket_fd(3), socket_fd(4)]);
        fake.sockets.insert(
            (300, 3),
            SocketReply::Failure {
                raw: raw(0, Errno::EBADF),
                prefill: tcp_listen(port),
            },
        );
        fake.sockets
            .insert((300, 4), SocketReply::Success(tcp_listen(port)));

        assert_eq!(
            find_port_holders_with(&fake, port).unwrap(),
            vec![(300, PortProtocol::Tcp)]
        );
        assert!(pid_holds_port_with(&fake, 300, port, PortProtocol::Tcp));
    }

    #[test]
    fn test_unexpected_failure_excludes_whole_process() {
        // 列挙後の消失以外の失敗が出たプロセスは、他の FD に LISTEN があっても候補にしない。
        // 走査そのものは続け、別のプロセスは候補になる。
        let port = 8080;
        let mut fake = FakeLibproc {
            pids: vec![400, 500],
            ..FakeLibproc::default()
        };
        fake.fds.insert(400, vec![socket_fd(3), socket_fd(4)]);
        fake.sockets
            .insert((400, 3), SocketReply::Success(tcp_listen(port)));
        fake.sockets.insert(
            (400, 4),
            SocketReply::Failure {
                raw: raw(0, Errno::EPERM),
                prefill: tcp_listen(port),
            },
        );
        fake.fds.insert(500, vec![socket_fd(3)]);
        fake.sockets
            .insert((500, 3), SocketReply::Success(udp_socket(AF_INET6, port)));

        assert_eq!(
            find_port_holders_with(&fake, port).unwrap(),
            vec![(500, PortProtocol::Udp)]
        );
        assert!(!pid_holds_port_with(&fake, 400, port, PortProtocol::Tcp));
        assert!(pid_holds_port_with(&fake, 500, port, PortProtocol::Udp));
    }

    #[test]
    fn test_find_port_holders_keeps_pid_and_fd_order() {
        // PID の列挙順・FD の順を保ち、別ポートや接続済みソケットは含めない
        let port = 3000;
        let mut fake = FakeLibproc {
            pids: vec![30, 10, 20],
            ..FakeLibproc::default()
        };
        fake.fds.insert(30, vec![socket_fd(3), socket_fd(4)]);
        fake.sockets
            .insert((30, 3), SocketReply::Success(udp_socket(AF_INET, port)));
        fake.sockets.insert(
            (30, 4),
            SocketReply::Success(tcp_socket(AF_INET6, TSI_S_LISTEN, port)),
        );
        fake.fds.insert(10, vec![socket_fd(3)]);
        fake.sockets.insert(
            (10, 3),
            SocketReply::Success(tcp_socket(AF_INET, 4, port)), // ESTABLISHED
        );
        fake.fds.insert(20, vec![socket_fd(3)]);
        fake.sockets
            .insert((20, 3), SocketReply::Success(tcp_listen(port + 1)));

        assert_eq!(
            find_port_holders_with(&fake, port).unwrap(),
            vec![(30, PortProtocol::Udp), (30, PortProtocol::Tcp)]
        );
    }

    #[test]
    fn test_unreadable_process_is_skipped_and_scan_continues() {
        // 他ユーザーのプロセス (EPERM)・終了したプロセス (ESRCH)・大きさの食い違う FD 一覧は
        // 候補にしないが、PID 一覧の取得自体は成功として走査を続ける
        let port = 3000;
        let mut fake = FakeLibproc {
            pids: vec![1, 2, 3, 4],
            ..FakeLibproc::default()
        };
        fake.fd_list_override.insert(1, raw(0, Errno::EPERM));
        // PID 2 は fds に無いので ESRCH
        fake.fd_list_override.insert(
            3,
            raw_no_errno(c_int::try_from(PROC_FDINFO_SIZE).unwrap() + 4),
        );
        fake.fds.insert(4, vec![socket_fd(3)]);
        fake.sockets
            .insert((4, 3), SocketReply::Success(tcp_listen(port)));

        assert_eq!(
            find_port_holders_with(&fake, port).unwrap(),
            vec![(4, PortProtocol::Tcp)]
        );
        assert!(!pid_holds_port_with(&fake, 1, port, PortProtocol::Tcp));
        assert!(!pid_holds_port_with(&fake, 2, port, PortProtocol::Tcp));
        assert!(!pid_holds_port_with(&fake, 3, port, PortProtocol::Tcp));
    }

    #[test]
    fn test_pid_holds_port_rejects_out_of_range_pid_without_querying() {
        let fake = FakeLibproc::single_socket(1, 3, SocketReply::Success(tcp_listen(80)));
        assert!(!pid_holds_port_with(&fake, 0, 80, PortProtocol::Tcp));
        assert!(!pid_holds_port_with(&fake, u32::MAX, 80, PortProtocol::Tcp));
        let over = u32::try_from(c_int::MAX).unwrap() + 1;
        assert!(!pid_holds_port_with(&fake, over, 80, PortProtocol::Tcp));
        assert!(fake.fd_list_capacities.borrow().is_empty());
    }

    #[test]
    fn test_pid_holds_port_checks_protocol() {
        let fake = FakeLibproc::single_socket(1, 3, SocketReply::Success(tcp_listen(80)));
        assert!(pid_holds_port_with(&fake, 1, 80, PortProtocol::Tcp));
        assert!(!pid_holds_port_with(&fake, 1, 80, PortProtocol::Udp));
        assert!(!pid_holds_port_with(&fake, 1, 81, PortProtocol::Tcp));
    }

    // =========================================================================
    // 一覧の取得（件数の検証と、上限付きの取り直し）
    // =========================================================================

    #[test]
    fn test_pid_list_failure_is_port_detection_error() {
        // proc_listallpids は失敗すると 0 を返す（-1 ではない）。どちらも検出エラーにする
        for failure in [
            raw(0, Errno::EPERM),
            raw_no_errno(0),
            raw(-1, Errno::EPERM),
            raw_no_errno(c_int::try_from(PID_LIST_INITIAL_CAPACITY).unwrap() + 1),
        ] {
            let fake = FakeLibproc {
                pid_list_override: Some(failure),
                ..FakeLibproc::default()
            };
            let result = find_port_holders_with(&fake, 3000);
            assert!(
                matches!(
                    result,
                    Err(SafeKillError::PortDetectionError { port: 3000, .. })
                ),
                "{failure:?}"
            );
        }
    }

    #[test]
    fn test_pid_list_grows_when_buffer_is_full() {
        // 初期の件数を超える PID があると 1 回目は埋まり切る。倍に広げて取り直し、全件を返す
        let pids: Vec<c_int> =
            (1..=c_int::try_from(PID_LIST_INITIAL_CAPACITY).unwrap() + 10).collect();
        let fake = FakeLibproc {
            pids: pids.clone(),
            ..FakeLibproc::default()
        };
        assert_eq!(list_all_pids(&fake).unwrap(), pids);
        assert_eq!(
            *fake.pid_list_capacities.borrow(),
            vec![PID_LIST_INITIAL_CAPACITY, PID_LIST_INITIAL_CAPACITY * 2]
        );
    }

    #[test]
    fn test_pid_list_drops_kernel_task_and_padding() {
        let fake = FakeLibproc {
            pids: vec![0, 1, 0, 523, -5],
            ..FakeLibproc::default()
        };
        assert_eq!(list_all_pids(&fake).unwrap(), vec![1, 523]);
    }

    #[test]
    fn test_fd_list_validates_byte_count() {
        let pid = 7;
        let fd_size = c_int::try_from(PROC_FDINFO_SIZE).unwrap();
        let initial = c_int::try_from(FD_LIST_INITIAL_CAPACITY).unwrap();
        let cases = [
            // 要素の大きさで割り切れない
            (
                raw_no_errno(fd_size + 1),
                Err(QueryError::UnexpectedSize(fd_size + 1)),
            ),
            (raw_no_errno(3), Err(QueryError::UnexpectedSize(3))),
            // 渡したバッファより多い
            (
                raw_no_errno((initial + 1) * fd_size),
                Err(QueryError::UnexpectedSize((initial + 1) * fd_size)),
            ),
            // 失敗
            (
                raw(0, Errno::EPERM),
                Err(QueryError::Os(Errno::EPERM as i32)),
            ),
            (raw(0, Errno::ESRCH), Err(QueryError::Gone(Errno::ESRCH))),
            (raw_no_errno(-8), Err(QueryError::UnexpectedSize(-8))),
            // FD を 1 つも開いていないプロセスは errno を立てずに 0 を返す
            (raw_no_errno(0), Ok(Vec::new())),
        ];
        for (reply, expected) in cases {
            let mut fake = FakeLibproc::default();
            fake.fd_list_override.insert(pid, reply);
            assert_eq!(list_socket_fds(&fake, pid), expected, "{reply:?}");
        }
    }

    #[test]
    fn test_fd_list_keeps_only_sockets_and_grows_when_full() {
        let pid = 7;
        let mut entries: Vec<sys::proc_fdinfo> = (0..c_int::try_from(FD_LIST_INITIAL_CAPACITY)
            .unwrap())
            .map(|fd| sys::proc_fdinfo {
                proc_fd: fd,
                proc_fdtype: 1, // PROX_FDTYPE_VNODE
            })
            .collect();
        entries.push(socket_fd(5000));
        let mut fake = FakeLibproc::default();
        fake.fds.insert(pid, entries);

        assert_eq!(list_socket_fds(&fake, pid).unwrap(), vec![5000]);
        assert_eq!(
            *fake.fd_list_capacities.borrow(),
            vec![FD_LIST_INITIAL_CAPACITY, FD_LIST_INITIAL_CAPACITY * 2]
        );
    }

    #[test]
    fn test_fetch_growing_gives_up_at_the_limit() {
        // 上限まで広げても埋まり切る一覧は、取りこぼしがあり得るので失敗にする
        let mut capacities = Vec::new();
        let result = fetch_growing(
            0u8,
            (2, 8),
            |buf| {
                capacities.push(buf.len());
                raw_no_errno(c_int::try_from(buf.len()).unwrap())
            },
            |raw| Ok(usize::try_from(raw.ret).unwrap()),
        );
        assert_eq!(result, Err(QueryError::Truncated));
        assert_eq!(capacities, vec![2, 4, 8]);
    }

    #[test]
    fn test_fetch_growing_returns_only_written_range() {
        let result = fetch_growing(
            0u8,
            (4, 8),
            |buf| {
                buf[0] = 1;
                buf[1] = 2;
                buf[2] = 3;
                raw_no_errno(2)
            },
            |raw| Ok(usize::try_from(raw.ret).unwrap()),
        );
        assert_eq!(result, Ok(vec![1, 2]));
    }

    #[test]
    fn test_fetch_growing_clamps_last_growth_to_the_limit() {
        // 上限が初期値の 2 の累乗倍でないときも、最後は上限ちょうどまで広げてから諦める
        let mut capacities = Vec::new();
        let result = fetch_growing(
            0u8,
            (2, 5),
            |buf| {
                capacities.push(buf.len());
                raw_no_errno(c_int::try_from(buf.len()).unwrap())
            },
            |raw| Ok(usize::try_from(raw.ret).unwrap()),
        );
        assert_eq!(result, Err(QueryError::Truncated));
        assert_eq!(capacities, vec![2, 4, 5]);
    }

    #[test]
    fn test_fetch_growing_propagates_failure_after_growth() {
        // 1 回目は埋まり切り、広げた 2 回目の呼び出しが失敗したら、その失敗を返す
        // （1 回目の内容を結果として返さない）
        let mut calls = 0;
        let result = fetch_growing(
            0u8,
            (2, 8),
            |buf| {
                calls += 1;
                if calls == 1 {
                    buf.fill(7);
                    raw_no_errno(c_int::try_from(buf.len()).unwrap())
                } else {
                    raw(0, Errno::ESRCH)
                }
            },
            |raw| {
                if raw.ret <= 0 {
                    Err(QueryError::from_failed_call(raw))
                } else {
                    Ok(usize::try_from(raw.ret).unwrap())
                }
            },
        );
        assert_eq!(result, Err(QueryError::Gone(Errno::ESRCH)));
        assert_eq!(calls, 2);
    }

    // =========================================================================
    // 実機の libproc での確認
    // =========================================================================

    /// 高い番号の FD を使うテストを直列にする（閉じた番号を別のテストが拾うと結果が変わる）
    static HIGH_FD_LOCK: Mutex<()> = Mutex::new(());

    /// 他のテストのスレッドが開く FD と番号が衝突しないよう、FD を高い番号へ複製する
    ///
    /// F_DUPFD_CLOEXEC は指定した番号以上で空いている最小の番号を割り当てる。並行して走る他の
    /// テストは空いている最小の番号（小さい番号）を使うので、この範囲とは重ならない。
    /// macOS の既定の上限 (ulimit -n = 256) でも使える番号にしておく。
    fn dup_to_high_fd(fd: impl AsFd) -> OwnedFd {
        let raw = fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(200)).expect("FD の複製に失敗");
        // SAFETY: fcntl が返したばかりの新しい FD で、ほかに所有者はいない
        unsafe { OwnedFd::from_raw_fd(raw) }
    }

    fn own_pid() -> c_int {
        c_int::try_from(std::process::id()).expect("PID が c_int に収まらない")
    }

    /// 列挙の後・問い合わせの直前に、対象の FD を消す方法
    enum Vanish {
        /// 閉じる
        Close,
        /// /dev/null で置き換える（同じ番号がソケット以外のファイルになる）
        ReplaceWithDevNull,
    }

    /// 実際の libproc を呼ぶが、自プロセスの対象 FD を「列挙した後・問い合わせる直前」に消す
    struct VanishBeforeQuery {
        target: c_int,
        fd: RefCell<Option<OwnedFd>>,
        how: Vanish,
        /// 置き換えた後の FD（問い合わせが終わるまで開いたままにする）
        replaced: RefCell<Option<OwnedFd>>,
        /// 対象 FD の問い合わせで実際に返った結果
        observed: Cell<Option<RawCall>>,
    }

    impl VanishBeforeQuery {
        fn new(fd: OwnedFd, how: Vanish) -> Self {
            Self {
                target: fd.as_raw_fd(),
                fd: RefCell::new(Some(fd)),
                how,
                replaced: RefCell::new(None),
                observed: Cell::new(None),
            }
        }
    }

    impl Libproc for VanishBeforeQuery {
        fn list_all_pids(&self, buf: &mut [c_int]) -> RawCall {
            SystemLibproc.list_all_pids(buf)
        }

        fn list_fds(&self, pid: c_int, buf: &mut [sys::proc_fdinfo]) -> RawCall {
            SystemLibproc.list_fds(pid, buf)
        }

        fn socket_info(&self, pid: c_int, fd: c_int, buf: &mut sys::socket_fdinfo) -> RawCall {
            let is_target = pid == own_pid() && fd == self.target;
            if is_target && let Some(mut owned) = self.fd.borrow_mut().take() {
                match self.how {
                    Vanish::Close => drop(owned),
                    Vanish::ReplaceWithDevNull => {
                        let devnull = File::open("/dev/null").expect("/dev/null を開けない");
                        nix::unistd::dup2(&devnull, &mut owned).expect("dup2 に失敗");
                        *self.replaced.borrow_mut() = Some(owned);
                    }
                }
            }
            let raw = SystemLibproc.socket_info(pid, fd, buf);
            if is_target {
                self.observed.set(Some(raw));
            }
            raw
        }
    }

    #[test]
    fn test_real_socket_closed_between_listing_and_query_is_not_evidence() {
        // 実機の再現: 対象ポートで LISTEN する FD (L) を問い合わせた直後に、列挙済みの別の
        // ソケット FD (H) が閉じられる。netstat2 ではここで H の問い合わせが「成功」し、
        // L の内容がもう一度数えられていた。L と H を隣り合う高い番号に置き、L の直後に H を
        // 問い合わせる順序を固定する。
        let _guard = HIGH_FD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
        let pid = own_pid();

        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let low = dup_to_high_fd(&listener);
        drop(listener);
        let other = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let other_port = other.local_addr().unwrap().port();
        let high = dup_to_high_fd(&other);
        drop(other);
        assert_eq!(high.as_raw_fd(), low.as_raw_fd() + 1, "前提: 隣り合う番号");

        let api = VanishBeforeQuery::new(high, Vanish::Close);
        let found = scan_process(&api, pid, port).expect("自プロセスを走査できない");
        assert_eq!(
            found,
            vec![PortProtocol::Tcp],
            "閉じた FD の問い合わせを、直前のリスナーの証拠として数えた"
        );
        assert_eq!(
            api.observed.get(),
            Some(raw(0, Errno::EBADF)),
            "列挙済みで閉じた FD への proc_pidfdinfo は 0 / EBADF を返すはず"
        );

        // 閉じたリスナー自身のポートについても、証拠は残らない
        assert!(!pid_holds_port_with(
            &SystemLibproc,
            std::process::id(),
            other_port,
            PortProtocol::Tcp
        ));
        drop(low);
    }

    #[test]
    fn test_real_listener_closed_between_listing_and_query_fails_recheck() {
        // kill 直前の再検証の最中に対象のリスナーが閉じられた場合は、保持していないと判断する
        let _guard = HIGH_FD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);

        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let high = dup_to_high_fd(&listener);
        drop(listener);

        assert!(
            pid_holds_port_with(&SystemLibproc, std::process::id(), port, PortProtocol::Tcp),
            "前提: 閉じる前は保持していると判断できる"
        );

        let api = VanishBeforeQuery::new(high, Vanish::Close);
        assert!(!pid_holds_port_with(
            &api,
            std::process::id(),
            port,
            PortProtocol::Tcp
        ));
        assert_eq!(api.observed.get(), Some(raw(0, Errno::EBADF)));
    }

    #[test]
    fn test_real_socket_replaced_by_file_between_listing_and_query_is_gone() {
        // 列挙した後に同じ番号がソケット以外（ここでは /dev/null）へ置き換わると、
        // proc_pidfdinfo は 0 / ENOTSOCK を返す。これも「消えた FD」として読み飛ばす
        let _guard = HIGH_FD_LOCK.lock().unwrap_or_else(PoisonError::into_inner);

        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let high = dup_to_high_fd(&listener);
        drop(listener);

        let api = VanishBeforeQuery::new(high, Vanish::ReplaceWithDevNull);
        let found = scan_process(&api, own_pid(), port).expect("自プロセスを走査できない");
        assert!(
            found.is_empty(),
            "置き換わった FD を証拠として数えた: {found:?}"
        );
        assert_eq!(api.observed.get(), Some(raw(0, Errno::ENOTSOCK)));
    }

    #[test]
    fn test_real_query_reads_listener_tcp_udp_and_ipv6() {
        let pid = own_pid();
        let tcp = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let udp = UdpSocket::bind("127.0.0.1:0").expect("UDP ソケットの作成に失敗");

        let tcp_port = tcp.local_addr().unwrap().port();
        let udp_port = udp.local_addr().unwrap().port();

        let tcp_info =
            query_socket(&SystemLibproc, pid, tcp.as_raw_fd()).expect("問い合わせに失敗");
        assert_eq!(
            listening_endpoint(&tcp_info),
            Some((PortProtocol::Tcp, tcp_port))
        );
        let udp_info =
            query_socket(&SystemLibproc, pid, udp.as_raw_fd()).expect("問い合わせに失敗");
        assert_eq!(
            listening_endpoint(&udp_info),
            Some((PortProtocol::Udp, udp_port))
        );

        // IPv6 のループバックが無効な環境では IPv6 の確認だけを飛ばす
        if let Ok(tcp6) = TcpListener::bind("[::1]:0") {
            let port6 = tcp6.local_addr().unwrap().port();
            let info6 =
                query_socket(&SystemLibproc, pid, tcp6.as_raw_fd()).expect("問い合わせに失敗");
            assert_eq!(listening_endpoint(&info6), Some((PortProtocol::Tcp, port6)));
        }
    }

    #[test]
    fn test_real_connected_tcp_socket_is_not_a_listener() {
        let pid = own_pid();
        let listener = TcpListener::bind("127.0.0.1:0").expect("TCP リスナーの作成に失敗");
        let port = listener.local_addr().unwrap().port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("接続に失敗");
        let info = query_socket(&SystemLibproc, pid, client.as_raw_fd()).expect("問い合わせに失敗");
        assert_eq!(listening_endpoint(&info), None);
    }

    #[test]
    fn test_real_listings_include_own_process_and_sockets() {
        let pid = own_pid();
        let pids = list_all_pids(&SystemLibproc).expect("PID を列挙できない");
        assert!(pids.contains(&pid));
        assert!(pids.iter().all(|&p| p > 0));

        let socket = UdpSocket::bind("127.0.0.1:0").expect("UDP ソケットの作成に失敗");
        let file = File::open("/dev/null").expect("/dev/null を開けない");
        let fds = list_socket_fds(&SystemLibproc, pid).expect("FD を列挙できない");
        assert!(fds.contains(&socket.as_raw_fd()));
        assert!(
            !fds.contains(&file.as_raw_fd()),
            "ソケット以外の FD を列挙した"
        );
    }

    #[test]
    fn test_real_exited_process_is_not_a_holder() {
        // 終了して回収済みのプロセスは ESRCH になり、保持者にならない
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("子プロセスを起動できない");
        let pid = child.id();
        child.wait().expect("子プロセスを回収できない");
        let pid_c = c_int::try_from(pid).unwrap();
        assert_eq!(
            list_socket_fds(&SystemLibproc, pid_c),
            Err(QueryError::Gone(Errno::ESRCH))
        );
        assert!(!pid_holds_port_with(
            &SystemLibproc,
            pid,
            80,
            PortProtocol::Tcp
        ));
    }
}
