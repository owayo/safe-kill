//! safe-kill の設定ファイルローダー
//!
//! ~/.config/safe-kill/config.toml 設定ファイルの読み込みと解析を行う。

use crate::error::SafeKillError;
use crate::terminal::{sanitize_path, sanitize_terminal};
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

fn ensure_no_dangling_symlink_ancestor(path: &Path) -> Result<(), SafeKillError> {
    for ancestor in path.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                fs::metadata(ancestor).map_err(|e| {
                    SafeKillError::ConfigError(format!(
                        "Failed to resolve symlink ancestor {} for {}: {}",
                        ancestor.display(),
                        path.display(),
                        e
                    ))
                })?;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(SafeKillError::ConfigError(format!(
                    "Failed to access ancestor {} for {}: {}",
                    ancestor.display(),
                    path.display(),
                    e
                )));
            }
        }
    }

    Ok(())
}

/// OS が報告するプロセス名の最大バイト数（切り詰められない OS では `None`）
///
/// Linux の sysinfo は `name` に `/proc/<pid>/stat` の comm をそのまま入れる。comm は
/// カーネルが `TASK_COMM_LEN`（16、終端 NUL を含む）に収めるため、実行ファイル名の
/// 先頭 15 バイトに切り詰められて観測される。macOS の名前は実行ファイルパスの
/// basename で、切り詰められない。
#[cfg(target_os = "linux")]
const OBSERVED_NAME_MAX_BYTES: Option<usize> = Some(15);
#[cfg(not(target_os = "linux"))]
const OBSERVED_NAME_MAX_BYTES: Option<usize> = None;

/// denylist のエントリが、OS から観測したプロセス名に一致するか判定する
///
/// 完全一致に加え、プロセス名が切り詰められる OS（Linux）では、上限より長いエントリを
/// 同じ上限で切り詰めた表現とも比べる。完全一致だけでは `gnome-terminal-server` の
/// ような 16 バイト以上のエントリが絶対に一致せず、利用者が気付かないまま保護が外れる。
/// 拒否側の照合なので、切り詰めで別の名前と重なっても保護が広がるだけで安全側に倒れる。
/// allowlist と `--name` は、過剰一致が許可範囲や対象の拡大になるため完全一致のまま扱う。
pub(crate) fn denylist_entry_matches(entry: &str, observed: &str) -> bool {
    denylist_entry_matches_within(entry, observed, OBSERVED_NAME_MAX_BYTES)
}

/// [`denylist_entry_matches`] の本体（名前の上限を引数で受け取り、どの OS でも検証できる）
fn denylist_entry_matches_within(entry: &str, observed: &str, max_bytes: Option<usize>) -> bool {
    if entry == observed {
        return true;
    }
    let Some(max_bytes) = max_bytes else {
        return false;
    };
    let bytes = entry.as_bytes();
    if bytes.len() <= max_bytes {
        return false;
    }
    // カーネルはバイト単位で切るので、UTF-8 の文字の途中で切れることがある。
    // `entry[..max_bytes]` は文字境界でないと panic するため使わず、観測名
    // （sysinfo の値を `to_string_lossy` したもの）と同じ lossy 変換をした表現で比べる。
    String::from_utf8_lossy(&bytes[..max_bytes]) == observed
}

/// メイン設定構造体
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// ancestry チェックをバイパスするプロセス（子孫検証なしで kill 可能）
    pub allowlist: Option<ProcessList>,
    /// kill 不可能なプロセス（allowlist より優先され、既定の保護対象にも合流される）
    pub denylist: Option<ProcessList>,
    /// --port kill 操作で許可されるポート
    pub allowed_ports: Option<AllowedPorts>,
}

/// プロセス名リスト
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessList {
    /// リスト内のプロセス名
    pub processes: Vec<String>,
}

/// 許可ポート設定
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowedPorts {
    /// ポート指定（単一ポート "3306" または範囲 "3000-3100"）
    pub ports: Vec<String>,
}

/// ポート範囲または単一ポートを表す
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortRange {
    /// 単一ポート番号
    Single(u16),
    /// ポート範囲（両端含む）
    Range { start: u16, end: u16 },
}

impl PortRange {
    /// ポート指定文字列を PortRange に解析する
    ///
    /// サポートする形式:
    /// - 単一ポート: "3306"
    /// - 範囲: "3000-3100"
    pub fn parse(spec: &str) -> Result<Self, SafeKillError> {
        let spec = spec.trim();

        if spec.contains('-') {
            let parts: Vec<&str> = spec.split('-').collect();
            if parts.len() != 2 {
                return Err(SafeKillError::InvalidPortRange(spec.to_string()));
            }

            let start = Self::parse_port(parts[0], spec)?;
            let end = Self::parse_port(parts[1], spec)?;

            if start > end {
                return Err(SafeKillError::InvalidPortRange(spec.to_string()));
            }

            Ok(PortRange::Range { start, end })
        } else {
            let port = Self::parse_port(spec, spec)?;
            Ok(PortRange::Single(port))
        }
    }

    /// ポート 0 は OS に割り当てを委ねる特殊値なので終了対象として扱わない。
    fn parse_port(value: &str, spec: &str) -> Result<u16, SafeKillError> {
        let port = value
            .trim()
            .parse::<u16>()
            .map_err(|_| SafeKillError::InvalidPortRange(spec.to_string()))?;

        if port == 0 {
            return Err(SafeKillError::InvalidPort(spec.to_string()));
        }

        Ok(port)
    }

    /// ポートがこの範囲内に含まれるか確認する
    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortRange::Single(p) => *p == port,
            PortRange::Range { start, end } => port >= *start && port <= *end,
        }
    }
}

/// 設定ディレクトリ直下の設定ファイル名
const CONFIG_FILE_NAME: &str = "config.toml";

impl Config {
    /// ~/.config/safe-kill/config.toml から設定を読み込む
    ///
    /// ファイルが存在しない場合はデフォルト設定を返す。
    /// 解析エラー時や、ホームディレクトリが相対パスで設定ファイルの場所を決められない
    /// 場合は、警告付きでデフォルト設定を返す。
    pub fn load() -> Self {
        Self::load_in_reporting(Self::resolve_config_dir(), &mut std::io::stderr())
    }

    /// ~/.config/safe-kill/config.toml から設定を厳格に読み込む
    ///
    /// 設定ファイルが存在するのに読めない、または解析できない場合は
    /// デフォルトにフォールバックせず、設定エラーとして返す。
    /// ホームディレクトリが相対パスの場合も設定エラーとして返す。
    pub fn try_load() -> Result<Self, SafeKillError> {
        Self::try_load_in(Self::resolve_config_dir())
    }

    /// 解決した設定ディレクトリから設定を厳格に読み込む（[`Config::try_load`] の本体）
    ///
    /// 場所の解決エラー（ホームが相対パス）はそのまま返す。`config_path()` の `None` を
    /// 経由して `try_load_from_path(None)`（ホームが無い環境としての既定値）へ落とすと、
    /// 誤設定を「設定ファイル未作成」と取り違え、利用者が設定した denylist が黙って外れる。
    fn try_load_in(
        config_dir: Result<Option<PathBuf>, SafeKillError>,
    ) -> Result<Self, SafeKillError> {
        let config_path = config_dir?.map(|dir| Self::config_file_in(&dir));
        Self::try_load_from_path(config_path)
    }

    /// 解決した設定ディレクトリから設定を読み込む（[`Config::load`] の本体）
    ///
    /// 寛容な読み込みの契約に合わせ、場所の解決エラーも読み込みの失敗と同じく
    /// 警告を書いて既定値を返す。
    fn load_in_reporting(
        config_dir: Result<Option<PathBuf>, SafeKillError>,
        warnings: &mut impl Write,
    ) -> Self {
        match config_dir {
            Ok(config_dir) => Self::load_from_path_reporting(
                config_dir.map(|dir| Self::config_file_in(&dir)),
                warnings,
            ),
            Err(e) => {
                Self::write_load_warning(warnings, None, &e);
                Self::with_defaults()
            }
        }
    }

    /// 指定されたパスから設定を読み込む
    pub fn load_from_path(path: Option<PathBuf>) -> Self {
        Self::load_from_path_reporting(path, &mut std::io::stderr())
    }

    /// 設定を読み込み、失敗したら警告を `warnings` へ書いて既定値を返す
    fn load_from_path_reporting(path: Option<PathBuf>, warnings: &mut impl Write) -> Self {
        match Self::try_load_from_path(path.clone()) {
            Ok(config) => config,
            Err(e) => {
                Self::write_load_warning(warnings, path.as_deref(), &e);
                Self::with_defaults()
            }
        }
    }

    /// 読み込みに失敗した旨の警告を 1 行書く
    ///
    /// 警告の書き込み失敗は無視する。`eprintln!` は stderr への書き込みに失敗すると
    /// panic する（std が成功扱いにするのは EBADF だけで、読み手が閉じたパイプの
    /// EPIPE は panic になる）。それでは「警告を出して既定値を返す」という契約が、
    /// 警告が届いたかどうかで崩れてしまう。
    fn write_load_warning(warnings: &mut impl Write, path: Option<&Path>, error: &SafeKillError) {
        let reason = sanitize_terminal(&error.to_string());
        let _ = match path {
            Some(path) => writeln!(
                warnings,
                "Warning: Failed to load config file {}: {}. Using defaults.",
                sanitize_path(path),
                reason
            ),
            None => writeln!(
                warnings,
                "Warning: Failed to load config file: {}. Using defaults.",
                reason
            ),
        };
    }

    /// 指定されたパスから設定を厳格に読み込む
    pub fn try_load_from_path(path: Option<PathBuf>) -> Result<Self, SafeKillError> {
        let Some(path) = path else {
            return Ok(Self::with_defaults());
        };

        // `try_exists()` は dangling symlink でも `Ok(false)` を返すため使わない。
        // パス自体が存在しない場合だけ既定値を許可し、symlink のリンク先消失は
        // 後続の metadata エラーとして扱うことで、設定消失時に fail-closed に倒す。
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // 親階層の dangling symlink も NotFound になるため、単純な未作成と
                // 区別してから既定値へフォールバックする。
                ensure_no_dangling_symlink_ancestor(&path)?;
                return Ok(Self::with_defaults());
            }
            Ok(_) => {}
            Err(e) => {
                return Err(SafeKillError::ConfigError(format!(
                    "Failed to access {}: {}",
                    path.display(),
                    e
                )));
            }
        }

        // FIFO へ差し替えられても open が待機しないようにし、開いたファイル記述子
        // 自体の種類を検証することで、検証と読み込みの間のパス差し替えも防ぐ。
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NONBLOCK)
            .open(&path)
            .map_err(|e| {
                SafeKillError::ConfigError(format!("Failed to access {}: {}", path.display(), e))
            })?;
        let metadata = file.metadata().map_err(|e| {
            SafeKillError::ConfigError(format!("Failed to access {}: {}", path.display(), e))
        })?;
        if !metadata.is_file() {
            return Err(SafeKillError::ConfigError(format!(
                "Config path {} is not a regular file",
                path.display()
            )));
        }

        let mut content = String::new();
        file.read_to_string(&mut content).map_err(|e| {
            SafeKillError::ConfigError(format!("Failed to read {}: {}", path.display(), e))
        })?;
        let mut config = toml::from_str::<Config>(&content).map_err(|e| {
            SafeKillError::ConfigError(format!("Failed to parse {}: {}", path.display(), e))
        })?;
        config.validate_allowed_ports(&path)?;
        config.merge_defaults();
        Ok(config)
    }

    /// 設定ファイルから読んだ `[allowed_ports]` の各指定を検証する
    ///
    /// 解析できない指定（ポート 0 を含む範囲、逆順の範囲、65535 を超える値、
    /// 全角ダッシュ等）を `is_port_allowed` のように黙って読み飛ばすと、範囲全体が
    /// 無視されたことに利用者が気付けない。拒否時のヒントも「既に書いた値を
    /// [allowed_ports] に追加せよ」と食い違う。未知フィールドを `deny_unknown_fields` で
    /// 設定エラーにしているのと揃え、1 つでも不正なら設定エラー（終了コード 3）にする。
    /// `PortRange::parse` のエラー（`InvalidPort` / `InvalidPortRange`）をそのまま返すと
    /// 終了コードが 255 になり、設定の問題だと伝わらないので `ConfigError` に包む。
    ///
    /// コードで組み立てた `Config` は検証を通らないので、`is_port_allowed` と
    /// `get_port_ranges` の寛容な扱い（不正な指定を一致させない）は残す。
    fn validate_allowed_ports(&self, path: &Path) -> Result<(), SafeKillError> {
        let Some(allowed_ports) = &self.allowed_ports else {
            return Ok(());
        };
        for (index, spec) in allowed_ports.ports.iter().enumerate() {
            PortRange::parse(spec).map_err(|e| {
                SafeKillError::ConfigError(format!(
                    "Invalid [allowed_ports] entry ports[{index}] ({spec:?}) in {}: {e} \
                     (expected \"PORT\" or \"START-END\" with 1 <= START <= END <= 65535)",
                    path.display()
                ))
            })?;
        }
        Ok(())
    }

    /// デフォルトの設定ファイルパスを取得する
    ///
    /// Linux/macOS では `~/.config/safe-kill/config.toml` を返す。
    /// ホームディレクトリが取得できない場合と、相対パスの場合は `None` を返す。
    /// 相対パスのホームをエラーとして扱う必要がある経路（CLI の厳格読み込みと
    /// `safe-kill init`）は、`None` と区別できる [`Config::resolve_config_dir`] を使う。
    pub fn config_path() -> Option<PathBuf> {
        Self::config_dir().map(|dir| Self::config_file_in(&dir))
    }

    /// 設定ディレクトリのパスを取得する
    ///
    /// ホームディレクトリが取得できない場合と、相対パスの場合は `None` を返す。
    pub fn config_dir() -> Option<PathBuf> {
        Self::resolve_config_dir().ok().flatten()
    }

    /// 設定ディレクトリ（`~/.config/safe-kill`）を解決する
    ///
    /// ホームディレクトリの取得と検証はここだけで行い、設定の読み込み（`load` /
    /// `try_load`）、`config_path` / `config_dir`、`safe-kill init` が同じ規則で
    /// 場所を決める。ホームが取得できない場合は `Ok(None)`、相対パスの場合は
    /// 設定エラーを返す（[`Config::config_dir_for_home`] 参照）。
    pub(crate) fn resolve_config_dir() -> Result<Option<PathBuf>, SafeKillError> {
        Self::config_dir_for_home(dirs::home_dir())
    }

    /// ホームディレクトリから設定ディレクトリを決める（[`Config::resolve_config_dir`] の本体）
    ///
    /// `dirs::home_dir()`（dirs-sys 0.5.0）は、空でない `HOME` を絶対パスかどうか
    /// 確かめずに返す。`HOME='~'` のような誤設定のまま join すると、設定ファイルの場所が
    /// カレントディレクトリ基準になり、未信頼のリポジトリで作業するエージェントが、
    /// そのリポジトリの置いた config.toml（ancestry を迂回する allowlist や
    /// allowed_ports）を読み込んでしまう。`safe-kill init` もカレントディレクトリの下に
    /// 設定を作る。相対パスは設定エラーにして fail-closed に倒す。`~` の展開や
    /// カレントディレクトリを基準にした絶対化はしない（どちらも誤設定を推測で補うことになり、
    /// 読む設定の場所が実行する場所で変わる）。
    ///
    /// ホームの値を引数で受け取るので、環境変数を書き換えずに検証できる。
    fn config_dir_for_home(home: Option<PathBuf>) -> Result<Option<PathBuf>, SafeKillError> {
        let Some(home) = home else {
            return Ok(None);
        };
        if !home.is_absolute() {
            return Err(SafeKillError::ConfigError(format!(
                "home directory is not an absolute path: {:?} (set HOME to an absolute path)",
                home
            )));
        }
        Ok(Some(home.join(".config").join("safe-kill")))
    }

    /// 設定ディレクトリ直下の設定ファイルのパス
    pub(crate) fn config_file_in(config_dir: &Path) -> PathBuf {
        config_dir.join(CONFIG_FILE_NAME)
    }

    /// デフォルト denylist 付きの設定を生成する
    fn with_defaults() -> Self {
        Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: Self::default_denylist(),
            }),
            allowed_ports: None,
        }
    }

    /// 既存の設定にデフォルト値をマージする
    pub(crate) fn merge_defaults(&mut self) {
        let mut processes = self
            .denylist
            .take()
            .map(|list| list.processes)
            .unwrap_or_default();

        // システム保護対象は常に denylist に含める。
        for default_process in Self::default_denylist() {
            if !processes.iter().any(|process| process == &default_process) {
                processes.push(default_process);
            }
        }

        self.denylist = Some(ProcessList { processes });

        // 注意: allowed_ports はデフォルトでは設定されない。
        // ポート指定 kill は明示的に設定しない限り無効。
    }

    /// OS 固有のデフォルト denylist を取得する
    pub fn default_denylist() -> Vec<String> {
        #[cfg(target_os = "macos")]
        {
            vec![
                "launchd".to_string(),
                "kernel_task".to_string(),
                "WindowServer".to_string(),
                "loginwindow".to_string(),
                "Finder".to_string(),
                "Dock".to_string(),
                "SystemUIServer".to_string(),
                // macOS 12 以降は AirPlay レシーバーとして ControlCenter（利用者自身の
                // プロセス）が TCP 5000 / 7000 で LISTEN する。5000（Flask の既定）を
                // allowed_ports に入れた利用者が、開発サーバーの止まっているときに
                // `--port 5000` を実行すると、ancestry を迂回する `--port` 経路で
                // ControlCenter を kill してしまう（dry-run で実際に対象として表示された）。
                "ControlCenter".to_string(),
            ]
        }

        #[cfg(target_os = "linux")]
        {
            vec![
                "systemd".to_string(),
                "init".to_string(),
                "kthreadd".to_string(),
                "dbus-daemon".to_string(),
                "gnome-shell".to_string(),
                "Xorg".to_string(),
                "sshd".to_string(),
            ]
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            vec!["init".to_string(), "systemd".to_string()]
        }
    }

    /// サンプル設定ファイル用の推奨許可ポートを取得する
    ///
    /// 開発でよく使われるポートで、`safe-kill init` で生成される
    /// サンプル設定に含まれる:
    /// - 1420: Tauri 開発サーバー
    /// - 3000-3010: Node.js 開発サーバー
    /// - 5173: Vite 開発サーバー
    /// - 8080: HTTP 代替ポート
    ///
    /// 注意: ランタイムのデフォルトとしては適用されない。
    /// ポート指定 kill は明示的に設定しない限り無効。
    pub fn default_allowed_ports() -> Vec<String> {
        vec![
            "1420".to_string(),
            "3000-3010".to_string(),
            "5173".to_string(),
            "8080".to_string(),
        ]
    }

    /// プロセス名が allowlist に含まれるか確認する
    pub fn is_allowed(&self, name: &str) -> bool {
        self.allowlist
            .as_ref()
            .map(|list| list.processes.iter().any(|p| p == name))
            .unwrap_or(false)
    }

    /// プロセス名が denylist に含まれるか確認する
    ///
    /// 照合規則は [`denylist_entry_matches`] を参照（Linux の comm の切り詰めを考慮する）。
    pub fn is_denied(&self, name: &str) -> bool {
        self.denylist
            .as_ref()
            .map(|list| {
                list.processes
                    .iter()
                    .any(|entry| denylist_entry_matches(entry, name))
            })
            .unwrap_or(false)
    }

    /// ポートが kill 操作に許可されているか確認する
    ///
    /// 設定されたポート指定のいずれかに一致する場合 true を返す。
    /// allowed_ports 設定が存在しない場合は false を返す（ポート kill は無効）。
    ///
    /// ポート指定 kill を有効にするには config.toml で allowed_ports を設定する:
    /// ```toml
    /// [allowed_ports]
    /// ports = ["1420", "3000-3010", "5173", "8080"]
    /// ```
    pub fn is_port_allowed(&self, port: u16) -> bool {
        if port == 0 {
            return false;
        }

        let Some(allowed_ports) = &self.allowed_ports else {
            return false;
        };

        for spec in &allowed_ports.ports {
            if let Ok(range) = PortRange::parse(spec)
                && range.contains(port)
            {
                return true;
            }
        }

        false
    }

    /// 設定から解析済みのポート範囲を取得する
    pub fn get_port_ranges(&self) -> Vec<PortRange> {
        self.allowed_ports
            .as_ref()
            .map(|ap| {
                ap.ports
                    .iter()
                    .filter_map(|s| PortRange::parse(s).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// ポートが許可されていない場合のヒントメッセージを生成する
    ///
    /// 設定ファイルでポートを許可する方法を説明する
    /// ユーザーフレンドリーなメッセージを生成する。
    pub fn port_not_allowed_hint(&self, port: u16) -> String {
        format!(
            "Add {} to [allowed_ports] in config.toml or run 'safe-kill init' to create a config file",
            port
        )
    }

    /// ポートが許可されているか確認し、許可されていない場合はヒント付きエラーを返す
    ///
    /// `is_port_allowed` とヒント付きエラー生成を組み合わせた
    /// 便利メソッド。
    pub fn check_port_allowed(&self, port: u16) -> Result<(), SafeKillError> {
        if port == 0 {
            return Err(SafeKillError::InvalidPort(port.to_string()));
        }

        if self.is_port_allowed(port) {
            Ok(())
        } else {
            Err(SafeKillError::PortNotAllowed {
                port,
                hint: self.port_not_allowed_hint(port),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Config 構造体のテスト
    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.allowlist.is_none());
        assert!(config.denylist.is_none());
    }

    #[test]
    fn test_config_with_defaults() {
        let config = Config::with_defaults();
        assert!(config.allowlist.is_none());
        assert!(config.denylist.is_some());
        assert!(!config.denylist.as_ref().unwrap().processes.is_empty());
        // allowed_ports はデフォルトで None（設定しない限りポート kill 無効）
        assert!(config.allowed_ports.is_none());
    }

    // デフォルト denylist のテスト
    #[test]
    fn test_default_denylist_not_empty() {
        let denylist = Config::default_denylist();
        assert!(!denylist.is_empty());
    }

    #[test]
    fn test_default_allowed_ports() {
        let ports = Config::default_allowed_ports();
        assert_eq!(
            ports,
            vec![
                "1420".to_string(),
                "3000-3010".to_string(),
                "5173".to_string(),
                "8080".to_string()
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_default_denylist_macos() {
        let denylist = Config::default_denylist();
        assert!(denylist.contains(&"launchd".to_string()));
        assert!(denylist.contains(&"kernel_task".to_string()));
        assert!(denylist.contains(&"WindowServer".to_string()));
        // AirPlay レシーバーとして TCP 5000 / 7000 で LISTEN するため、`--port` から守る
        assert!(denylist.contains(&"ControlCenter".to_string()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_control_center_stays_denied_after_merge_defaults() {
        // 利用者が自分の denylist を書いても（空のリストでも）、ControlCenter の保護は外れない。
        // `--port 5000` は ancestry を迂回するので、保護が外れると AirPlay レシーバーを落とす。
        for processes in [vec![], vec!["postgres".to_string()]] {
            let mut config = Config {
                denylist: Some(ProcessList { processes }),
                ..Default::default()
            };
            config.merge_defaults();
            assert!(config.is_denied("ControlCenter"));
            // 照合は完全一致のまま（大文字小文字や部分一致で広げない）
            assert!(!config.is_denied("controlcenter"));
            assert!(!config.is_denied("ControlCenterHelper"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_default_denylist_linux() {
        let denylist = Config::default_denylist();
        assert!(denylist.contains(&"systemd".to_string()));
        assert!(denylist.contains(&"init".to_string()));
    }

    // 設定ファイルパスのテスト
    #[test]
    fn test_config_path_exists() {
        let path = Config::config_path();
        assert!(path.is_some());
        let path = path.unwrap();
        // XDG 準拠のパス
        assert!(path.to_string_lossy().contains("safe-kill"));
        assert!(path.to_string_lossy().contains("config.toml"));
    }

    #[test]
    fn test_config_dir_exists() {
        let dir = Config::config_dir();
        assert!(dir.is_some());
        let dir = dir.unwrap();
        assert!(dir.to_string_lossy().contains("safe-kill"));
    }

    #[test]
    fn test_config_path_is_config_toml_in_config_dir() {
        // 設定ファイルの場所は設定ディレクトリから導く（ホームの解決は 1 か所だけ）
        assert_eq!(
            Config::config_path(),
            Config::config_dir().map(|dir| dir.join("config.toml"))
        );
    }

    // ホームディレクトリの検証のテスト。環境変数は書き換えず、ホームの値を引数で渡す。
    #[test]
    fn test_config_dir_for_home_accepts_absolute_home() {
        assert_eq!(
            Config::config_dir_for_home(Some(PathBuf::from("/home/user"))).unwrap(),
            Some(PathBuf::from("/home/user/.config/safe-kill"))
        );
    }

    #[test]
    fn test_config_dir_for_home_without_home_returns_none() {
        // ホームが取れない環境は従来どおり「場所が無い」（既定値）として扱う
        assert_eq!(Config::config_dir_for_home(None).unwrap(), None);
    }

    #[test]
    fn test_config_dir_for_home_rejects_relative_home() {
        // `HOME='~'` などをそのまま join すると、設定の場所がカレントディレクトリ基準になる。
        // `~` の展開やカレントディレクトリでの絶対化もしない。
        for home in ["~", "~/", "rel", "./home", "../home", "home/user", ""] {
            let result = Config::config_dir_for_home(Some(PathBuf::from(home)));
            assert!(
                matches!(
                    &result,
                    Err(SafeKillError::ConfigError(message))
                        if message.contains("home directory is not an absolute path")
                ),
                "HOME={home:?}: {result:?}"
            );
        }
    }

    #[test]
    fn test_try_load_in_relative_home_is_error_not_defaults() {
        // 厳格読み込みは、場所を決められない誤設定を「ホームが無い」（既定値）に
        // 落とさず、設定エラー（終了コード 3）として返す。
        let result = Config::try_load_in(Config::config_dir_for_home(Some(PathBuf::from("~"))));
        assert!(
            matches!(&result, Err(SafeKillError::ConfigError(_))),
            "{result:?}"
        );
        assert_eq!(
            result.unwrap_err().exit_code(),
            crate::error::SafeKillExitCode::ConfigError
        );
    }

    #[test]
    fn test_try_load_in_reads_config_under_absolute_home() {
        let home = tempfile::tempdir().unwrap();
        let config_dir = home.path().join(".config").join("safe-kill");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            "[denylist]\nprocesses = [\"home-process\"]\n",
        )
        .unwrap();

        let config =
            Config::try_load_in(Config::config_dir_for_home(Some(home.path().to_path_buf())))
                .unwrap();
        assert!(config.is_denied("home-process"));

        // ホームが無い環境は既定値
        let config = Config::try_load_in(Config::config_dir_for_home(None)).unwrap();
        assert_eq!(config, Config::with_defaults());
    }

    #[test]
    fn test_load_in_reporting_relative_home_warns_and_uses_defaults() {
        // 寛容な読み込み（ライブラリの `Config::load`）は、場所の解決エラーも
        // 読み込みの失敗と同じく 1 行の警告を出して既定値を返す。値に含まれる制御文字は
        // エスケープしてから出す。
        let mut warnings = Vec::new();
        let config = Config::load_in_reporting(
            Config::config_dir_for_home(Some(PathBuf::from("rel\x1b[2J\nhome"))),
            &mut warnings,
        );
        let warnings = String::from_utf8(warnings).unwrap();

        assert_eq!(config, Config::with_defaults());
        assert!(
            warnings.starts_with("Warning: Failed to load config file: "),
            "{warnings:?}"
        );
        assert!(
            warnings.contains("home directory is not an absolute path"),
            "{warnings:?}"
        );
        assert!(!warnings.contains('\x1b'), "{warnings:?}");
        assert_eq!(
            warnings.matches('\n').count(),
            1,
            "警告は 1 行で終わるべき: {warnings:?}"
        );
    }

    #[test]
    fn test_load_in_reporting_ignores_warning_write_failure_on_home_error() {
        let mut warnings = FailingWriter(std::io::ErrorKind::BrokenPipe);
        let config = Config::load_in_reporting(
            Config::config_dir_for_home(Some(PathBuf::from("~"))),
            &mut warnings,
        );
        assert_eq!(config, Config::with_defaults());
    }

    // パスからの読み込みテスト
    #[test]
    fn test_load_from_nonexistent_path() {
        let config = Config::load_from_path(Some(PathBuf::from("/nonexistent/path/config.toml")));
        // デフォルト値が返されるべき
        assert!(config.denylist.is_some());
    }

    #[test]
    fn test_try_load_from_nonexistent_path_returns_defaults() {
        let config =
            Config::try_load_from_path(Some(PathBuf::from("/nonexistent/path/config.toml")))
                .unwrap();
        // 厳格読み込みでも、設定ファイル未作成はエラーにせずデフォルトを使う。
        assert!(config.denylist.is_some());
        assert!(config.allowed_ports.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn test_try_load_config_dangling_symlink_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let missing_target = dir.path().join("missing.toml");
        std::os::unix::fs::symlink(&missing_target, &config_path).unwrap();

        let result = Config::try_load_from_path(Some(config_path));

        // 設定への symlink が壊れた状態を「未作成」と誤認してはならない。
        assert!(matches!(result, Err(SafeKillError::ConfigError(_))));
    }

    #[cfg(unix)]
    #[test]
    fn test_try_load_config_dangling_parent_symlink_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_parent = dir.path().join("managed-config");
        let missing_target = dir.path().join("missing-directory");
        std::os::unix::fs::symlink(&missing_target, &config_parent).unwrap();
        let config_path = config_parent.join("config.toml");

        let result = Config::try_load_from_path(Some(config_path));

        // 親階層の symlink が壊れていても、設定未作成として扱ってはならない。
        assert!(matches!(result, Err(SafeKillError::ConfigError(_))));
    }

    #[cfg(unix)]
    #[test]
    fn test_try_load_config_symlink_to_special_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::os::unix::fs::symlink("/dev/null", &config_path).unwrap();

        let result = Config::try_load_from_path(Some(config_path));

        // 特殊ファイルを空の TOML として受け入れ、既定設定へ移行してはならない。
        assert!(matches!(result, Err(SafeKillError::ConfigError(_))));
    }

    #[cfg(unix)]
    #[test]
    fn test_try_load_config_symlink_to_regular_file_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("managed-config.toml");
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &target_path,
            "[denylist]\nprocesses = [\"managed-process\"]\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&target_path, &config_path).unwrap();

        let config = Config::try_load_from_path(Some(config_path)).unwrap();

        assert!(config.is_denied("managed-process"));
    }

    #[test]
    fn test_load_from_none_path() {
        let config = Config::load_from_path(None);
        // デフォルト値が返されるべき
        assert!(config.denylist.is_some());
    }

    #[test]
    fn test_try_load_from_none_path_returns_defaults() {
        let config = Config::try_load_from_path(None).unwrap();
        // ホームディレクトリが解決できない環境では安全なデフォルトを使う。
        assert!(config.denylist.is_some());
        assert!(config.allowed_ports.is_none());
    }

    #[test]
    fn test_load_valid_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[allowlist]
processes = ["node", "npm", "cargo"]

[denylist]
processes = ["postgres", "mysql"]
"#
        )
        .unwrap();

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        assert!(config.allowlist.is_some());
        assert!(config.denylist.is_some());
        assert!(config.is_allowed("node"));
        assert!(config.is_allowed("npm"));
        assert!(config.is_allowed("cargo"));
        assert!(config.is_denied("postgres"));
        assert!(config.is_denied("mysql"));
    }

    #[test]
    fn test_load_config_only_allowlist() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[allowlist]
processes = ["node"]
"#
        )
        .unwrap();

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        assert!(config.allowlist.is_some());
        // デフォルト denylist が追加されるべき
        assert!(config.denylist.is_some());
        assert!(config.is_allowed("node"));
    }

    #[test]
    fn test_load_config_empty() {
        let file = NamedTempFile::new().unwrap();
        // 空ファイルは有効な TOML

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        // デフォルト値が使用されるべき
        assert!(config.denylist.is_some());
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "this is not valid TOML {{{{").unwrap();

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        // 解析エラー時はデフォルトにフォールバックするべき。`denylist.is_some()` だけでは
        // 読み込みに成功した場合（`merge_defaults` 後）とも区別できないため、既定値そのものと比べる。
        assert_eq!(config, Config::with_defaults());
    }

    /// 常に指定した種類の I/O エラーを返す書き込み先
    struct FailingWriter(std::io::ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(self.0))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::from(self.0))
        }
    }

    #[test]
    fn test_load_from_path_falls_back_even_if_warning_cannot_be_written() {
        // 読み手が閉じたパイプへ警告を書けなくても、既定値を返して処理を続けるべき。
        // `eprintln!` で書いていた頃は EPIPE で panic し、公開 API の
        // 「警告を出して既定値を返す」という契約が破れていた。
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "this is not valid TOML {{{{").unwrap();

        let mut warnings = FailingWriter(std::io::ErrorKind::BrokenPipe);
        let config =
            Config::load_from_path_reporting(Some(file.path().to_path_buf()), &mut warnings);

        assert_eq!(config, Config::with_defaults());
    }

    #[test]
    fn test_load_from_path_warning_escapes_control_characters_in_path() {
        // 警告にはパスとエラー本文（toml の複数行の診断を含む）が入る。制御文字入りの
        // ファイル名でも、生の ESC や改行を流さずに 1 行の警告として出すべき。
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad\x1b[2J\nname.toml");
        std::fs::write(&path, "this is not valid TOML {{").unwrap();

        let mut warnings = Vec::new();
        let config = Config::load_from_path_reporting(Some(path), &mut warnings);
        let warnings = String::from_utf8(warnings).unwrap();

        assert_eq!(config, Config::with_defaults());
        assert!(
            warnings.starts_with("Warning: Failed to load config file "),
            "{warnings:?}"
        );
        assert!(warnings.contains("bad\\x1B[2J\\nname.toml"), "{warnings:?}");
        assert!(!warnings.contains('\x1b'), "{warnings:?}");
        assert_eq!(
            warnings.matches('\n').count(),
            1,
            "警告は 1 行で終わるべき: {warnings:?}"
        );
    }

    #[test]
    fn test_try_load_config_invalid_toml_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "this is not valid TOML {{{{").unwrap();

        let result = Config::try_load_from_path(Some(file.path().to_path_buf()));
        assert!(matches!(result, Err(SafeKillError::ConfigError(_))));
    }

    #[test]
    fn test_try_load_config_invalid_type_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[allowed_ports]\nports = [3000, 8080]").unwrap();

        let result = Config::try_load_from_path(Some(file.path().to_path_buf()));
        assert!(matches!(result, Err(SafeKillError::ConfigError(_))));
    }

    #[test]
    fn test_try_load_config_unknown_top_level_field_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[denylst]\nprocesses = [\"postgres\"]").unwrap();

        let result = Config::try_load_from_path(Some(file.path().to_path_buf()));
        assert!(matches!(result, Err(SafeKillError::ConfigError(_))));
    }

    #[test]
    fn test_try_load_config_unknown_nested_field_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[denylist]\nprocesses = [\"postgres\"]\nextra = true").unwrap();

        let result = Config::try_load_from_path(Some(file.path().to_path_buf()));
        assert!(matches!(result, Err(SafeKillError::ConfigError(_))));
    }

    #[cfg(unix)]
    #[test]
    fn test_try_load_config_inaccessible_path_returns_error() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let locked_dir = dir.path().join("locked");
        std::fs::create_dir(&locked_dir).unwrap();
        let config_path = locked_dir.join("config.toml");

        // 親ディレクトリに入れない場合、存在確認自体を設定エラーとして扱う。
        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = Config::try_load_from_path(Some(config_path));
        std::fs::set_permissions(&locked_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(result, Err(SafeKillError::ConfigError(_))));
    }

    // is_allowed のテスト
    #[test]
    fn test_is_allowed_with_allowlist() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["node".to_string(), "npm".to_string()],
            }),
            denylist: None,
            allowed_ports: None,
        };
        assert!(config.is_allowed("node"));
        assert!(config.is_allowed("npm"));
        assert!(!config.is_allowed("python"));
    }

    #[test]
    fn test_is_allowed_without_allowlist() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        assert!(!config.is_allowed("node"));
        assert!(!config.is_allowed("anything"));
    }

    // is_denied のテスト
    #[test]
    fn test_is_denied_with_denylist() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["systemd".to_string(), "launchd".to_string()],
            }),
            allowed_ports: None,
        };
        assert!(config.is_denied("systemd"));
        assert!(config.is_denied("launchd"));
        assert!(!config.is_denied("node"));
    }

    #[test]
    fn test_is_denied_without_denylist() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        assert!(!config.is_denied("systemd"));
        assert!(!config.is_denied("anything"));
    }

    // denylist の照合規則（Linux の comm の切り詰め）のテスト。
    // 規則の本体は上限を引数で受け取るので、macOS でも Linux の挙動を検証できる。
    #[test]
    fn test_denylist_entry_matches_exact_name_only_for_short_entries() {
        assert!(denylist_entry_matches_within(
            "postgres",
            "postgres",
            Some(15)
        ));
        assert!(!denylist_entry_matches_within(
            "postgres",
            "postgresql",
            Some(15)
        ));
        // 15 バイト以下のエントリはカーネルに切り詰められないので、前方一致は認めない
        assert!(!denylist_entry_matches_within(
            "gnome-shell",
            "gnome-shel",
            Some(15)
        ));
    }

    #[test]
    fn test_denylist_entry_matches_long_entry_against_truncated_comm() {
        // Linux では `gnome-terminal-server` が comm の `gnome-terminal-` として観測される。
        // 完全一致だけでは絶対に一致せず、denylist の保護が黙って外れていた。
        assert!(denylist_entry_matches_within(
            "gnome-terminal-server",
            "gnome-terminal-",
            Some(15)
        ));
        // 切り詰め後の表現と異なる観測名には一致しない
        assert!(!denylist_entry_matches_within(
            "gnome-terminal-server",
            "gnome-terminal",
            Some(15)
        ));
        // 名前が切り詰められない OS（macOS）では完全一致だけ
        assert!(!denylist_entry_matches_within(
            "gnome-terminal-server",
            "gnome-terminal-",
            None
        ));
    }

    #[test]
    fn test_denylist_entry_matches_truncation_inside_multibyte_char() {
        // ASCII 14 バイトの直後に 3 バイト文字があると、15 バイト目で文字の途中が切れる。
        // 観測名は sysinfo の値を lossy 変換したもの（末尾が U+FFFD）になる。
        // panic せず、同じ lossy 表現どうしで一致させる。
        let entry = "abcdefghijklmnあ-server";
        let observed = String::from_utf8_lossy(&entry.as_bytes()[..15]).into_owned();
        assert_eq!(observed, "abcdefghijklmn\u{FFFD}");
        assert!(denylist_entry_matches_within(entry, &observed, Some(15)));
    }

    #[test]
    fn test_is_denied_applies_platform_truncation_rule() {
        let config = Config {
            denylist: Some(ProcessList {
                processes: vec!["gnome-terminal-server".to_string()],
            }),
            ..Default::default()
        };
        assert!(config.is_denied("gnome-terminal-server"));
        assert_eq!(
            config.is_denied("gnome-terminal-"),
            cfg!(target_os = "linux"),
            "切り詰めを考慮するのはプロセス名が 15 バイトに切り詰められる Linux だけ"
        );
    }

    #[test]
    fn test_is_allowed_does_not_apply_truncation_rule() {
        // allowlist は ancestry を迂回させる許可側の設定なので、切り詰めで一致範囲を広げない。
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["gnome-terminal-server".to_string()],
            }),
            ..Default::default()
        };
        assert!(config.is_allowed("gnome-terminal-server"));
        assert!(!config.is_allowed("gnome-terminal-"));
    }

    // Clone と等値性のテスト
    #[test]
    fn test_config_clone() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["node".to_string()],
            }),
            denylist: Some(ProcessList {
                processes: vec!["systemd".to_string()],
            }),
            allowed_ports: None,
        };
        let cloned = config.clone();
        assert_eq!(config, cloned);
    }

    #[test]
    fn test_process_list_clone() {
        let list = ProcessList {
            processes: vec!["a".to_string(), "b".to_string()],
        };
        let cloned = list.clone();
        assert_eq!(list, cloned);
    }

    #[test]
    fn test_merge_defaults_merges_custom_denylist_with_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[denylist]
processes = ["custom_process"]
"#
        )
        .unwrap();

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        // カスタム denylist を保持しつつ、既定の保護対象も必ず残す。
        let denylist = config.denylist.as_ref().unwrap();
        assert!(denylist.processes.contains(&"custom_process".to_string()));
        for default_process in Config::default_denylist() {
            assert!(denylist.processes.contains(&default_process));
        }
    }

    #[test]
    fn test_merge_defaults_deduplicates_existing_default_denylist_entries() {
        let mut file = NamedTempFile::new().unwrap();
        let default_process = Config::default_denylist()
            .into_iter()
            .next()
            .expect("default denylist should not be empty");
        writeln!(
            file,
            r#"
[denylist]
processes = ["{}", "custom_process"]
"#,
            default_process
        )
        .unwrap();

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        let denylist = config.denylist.as_ref().unwrap();
        let count = denylist
            .processes
            .iter()
            .filter(|process| *process == &default_process)
            .count();

        assert_eq!(count, 1);
        assert!(denylist.processes.contains(&"custom_process".to_string()));
    }

    #[test]
    fn test_merge_defaults_adds_denylist_when_missing() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[allowlist]
processes = ["node"]
"#
        )
        .unwrap();

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        // denylist が未指定だったため、デフォルト denylist が追加されるべき
        assert!(config.denylist.is_some());
        let denylist = config.denylist.as_ref().unwrap();
        assert!(!denylist.processes.is_empty());
        // OS 固有のデフォルト値を含むべき
        assert_eq!(denylist.processes, Config::default_denylist());
    }

    // Debug のテスト
    #[test]
    fn test_config_debug() {
        let config = Config::default();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("Config"));
    }

    #[test]
    fn test_process_list_debug() {
        let list = ProcessList {
            processes: vec!["test".to_string()],
        };
        let debug_str = format!("{:?}", list);
        assert!(debug_str.contains("ProcessList"));
        assert!(debug_str.contains("test"));
    }

    // PortRange のテスト
    #[test]
    fn test_port_range_parse_single() {
        let range = PortRange::parse("3306").unwrap();
        assert_eq!(range, PortRange::Single(3306));
    }

    #[test]
    fn test_port_range_parse_range() {
        let range = PortRange::parse("3000-3100").unwrap();
        assert_eq!(
            range,
            PortRange::Range {
                start: 3000,
                end: 3100
            }
        );
    }

    #[test]
    fn test_port_range_parse_with_spaces() {
        let range = PortRange::parse(" 3000 - 3100 ").unwrap();
        assert_eq!(
            range,
            PortRange::Range {
                start: 3000,
                end: 3100
            }
        );
    }

    #[test]
    fn test_port_range_parse_invalid() {
        assert!(PortRange::parse("abc").is_err());
        assert!(PortRange::parse("123-abc").is_err());
        assert!(PortRange::parse("abc-456").is_err());
        assert!(PortRange::parse("100-50").is_err()); // start > end で無効
        assert!(PortRange::parse("1-2-3").is_err());
    }

    // =============================================================================
    // 境界値テスト
    // =============================================================================

    #[test]
    fn test_port_range_boundary_values() {
        // ポート 0 は OS に割り当てを委ねる特殊値なので対象外
        assert!(PortRange::parse("0").is_err());

        // ポート65535は最大有効値
        assert!(PortRange::parse("65535").is_ok());
        assert_eq!(PortRange::parse("65535").unwrap(), PortRange::Single(65535));
        assert!(PortRange::parse("65535").unwrap().contains(65535));

        // 最大範囲
        assert!(PortRange::parse("0-65535").is_err());
        let full_range = PortRange::parse("1-65535").unwrap();
        assert!(full_range.contains(1));
        assert!(full_range.contains(32768));
        assert!(full_range.contains(65535));
    }

    #[test]
    fn test_port_range_overflow_values() {
        // 65536はu16の範囲外なのでエラー
        assert!(PortRange::parse("65536").is_err());

        // 範囲の終端が65536を超える場合
        assert!(PortRange::parse("1-65536").is_err());
        assert!(PortRange::parse("65535-65536").is_err());

        // 非常に大きな値
        assert!(PortRange::parse("99999").is_err());
        assert!(PortRange::parse("999999999").is_err());
    }

    #[test]
    fn test_port_range_edge_cases() {
        // 同じポートの範囲（start == end）
        assert!(PortRange::parse("8080-8080").is_ok());
        let same_range = PortRange::parse("8080-8080").unwrap();
        assert!(same_range.contains(8080));
        assert!(!same_range.contains(8079));
        assert!(!same_range.contains(8081));

        // 1ポート違いの範囲
        assert!(PortRange::parse("8080-8081").is_ok());

        // 範囲の端だけ使用
        let range = PortRange::parse("3000-3010").unwrap();
        assert!(range.contains(3000)); // start
        assert!(range.contains(3010)); // end
        assert!(!range.contains(2999)); // start の前
        assert!(!range.contains(3011)); // end の後
    }

    #[test]
    fn test_port_range_empty_and_whitespace() {
        // 空文字列
        assert!(PortRange::parse("").is_err());

        // 空白のみ
        assert!(PortRange::parse("   ").is_err());

        // ハイフンのみ
        assert!(PortRange::parse("-").is_err());
        assert!(PortRange::parse("--").is_err());

        // 片方のみ指定
        assert!(PortRange::parse("-3000").is_err());
        assert!(PortRange::parse("3000-").is_err());
    }

    #[test]
    fn test_port_range_contains_single() {
        let range = PortRange::Single(3306);
        assert!(range.contains(3306));
        assert!(!range.contains(3307));
    }

    #[test]
    fn test_port_range_contains_range() {
        let range = PortRange::Range {
            start: 3000,
            end: 3100,
        };
        assert!(range.contains(3000));
        assert!(range.contains(3050));
        assert!(range.contains(3100));
        assert!(!range.contains(2999));
        assert!(!range.contains(3101));
    }

    // is_port_allowed のテスト
    #[test]
    fn test_is_port_allowed_no_config() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        // allowed_ports 設定なしはポート kill 無効を意味する
        // すべてのポートで false を返す
        assert!(!config.is_port_allowed(1420));
        assert!(!config.is_port_allowed(3000));
        assert!(!config.is_port_allowed(3005));
        assert!(!config.is_port_allowed(8080));
        assert!(!config.is_port_allowed(22));
        assert!(!config.is_port_allowed(3306));
    }

    #[test]
    fn test_is_port_allowed_with_single_port() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3306".to_string()],
            }),
        };
        assert!(config.is_port_allowed(3306));
        assert!(!config.is_port_allowed(3307));
        assert!(!config.is_port_allowed(22));
    }

    #[test]
    fn test_is_port_allowed_with_range() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3100".to_string()],
            }),
        };
        assert!(config.is_port_allowed(3000));
        assert!(config.is_port_allowed(3050));
        assert!(config.is_port_allowed(3100));
        assert!(!config.is_port_allowed(2999));
        assert!(!config.is_port_allowed(3101));
    }

    #[test]
    fn test_is_port_allowed_with_mixed() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec![
                    "3000-3100".to_string(),
                    "3306".to_string(),
                    "5432".to_string(),
                ],
            }),
        };
        assert!(config.is_port_allowed(3050)); // 範囲内
        assert!(config.is_port_allowed(3306)); // 単一ポート
        assert!(config.is_port_allowed(5432)); // 単一ポート
        assert!(!config.is_port_allowed(22)); // 許可されていない
    }

    #[test]
    fn test_load_config_with_allowed_ports() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[allowed_ports]
ports = ["3000-3100", "3306", "5432"]
"#
        )
        .unwrap();

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        assert!(config.allowed_ports.is_some());
        let ports = config.allowed_ports.unwrap();
        assert_eq!(ports.ports.len(), 3);
        assert!(ports.ports.contains(&"3000-3100".to_string()));
        assert!(ports.ports.contains(&"3306".to_string()));
        assert!(ports.ports.contains(&"5432".to_string()));
    }

    #[test]
    fn test_get_port_ranges() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3100".to_string(), "3306".to_string()],
            }),
        };
        let ranges = config.get_port_ranges();
        assert_eq!(ranges.len(), 2);
    }

    #[test]
    fn test_get_port_ranges_empty() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        let ranges = config.get_port_ranges();
        assert!(ranges.is_empty());
    }

    // port_not_allowed_hint のテスト
    #[test]
    fn test_port_not_allowed_hint_with_config() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3100".to_string()],
            }),
        };
        let hint = config.port_not_allowed_hint(22);
        assert!(hint.contains("22"));
        assert!(hint.contains("[allowed_ports]"));
        assert!(hint.contains("config.toml"));
    }

    #[test]
    fn test_port_not_allowed_hint_includes_port_number() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["8080".to_string()],
            }),
        };
        let hint = config.port_not_allowed_hint(3306);
        assert!(hint.contains("3306"));
    }

    // check_port_allowed のテスト
    #[test]
    fn test_check_port_allowed_no_config_all_fail() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        // allowed_ports 設定なしはすべてのポートチェックが失敗することを意味する
        assert!(config.check_port_allowed(1420).is_err());
        assert!(config.check_port_allowed(3000).is_err());
        assert!(config.check_port_allowed(8080).is_err());
        assert!(config.check_port_allowed(22).is_err());
        assert!(config.check_port_allowed(3306).is_err());
    }

    #[test]
    fn test_check_port_allowed_success_in_list() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3100".to_string(), "3306".to_string()],
            }),
        };
        assert!(config.check_port_allowed(3050).is_ok());
        assert!(config.check_port_allowed(3306).is_ok());
    }

    #[test]
    fn test_check_port_allowed_failure() {
        use crate::error::SafeKillError;

        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["3000-3100".to_string()],
            }),
        };
        let result = config.check_port_allowed(22);
        assert!(result.is_err());
        match result {
            Err(SafeKillError::PortNotAllowed { port, hint }) => {
                assert_eq!(port, 22);
                assert!(hint.contains("22"));
            }
            _ => panic!("Expected PortNotAllowed error"),
        }
    }

    #[test]
    fn test_is_port_allowed_invalid_spec_skipped() {
        // 無効なポート指定が混在しても、有効な指定は機能する
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec![
                    "not-a-port".to_string(),
                    "8080".to_string(),
                    "abc".to_string(),
                ],
            }),
        };
        assert!(config.is_port_allowed(8080));
        assert!(!config.is_port_allowed(3000));
    }

    #[test]
    fn test_port_range_reversed_start_end() {
        // start > end は無効
        assert!(PortRange::parse("100-50").is_err());
        assert!(PortRange::parse("8080-3000").is_err());
        assert!(PortRange::parse("65535-1").is_err());
    }

    #[test]
    fn test_port_range_parse_with_spaces_around_dash() {
        // ダッシュ前後のスペースは許容される
        let range = PortRange::parse("3000 - 3100").unwrap();
        assert!(range.contains(3000));
        assert!(range.contains(3100));
        assert!(!range.contains(2999));
    }

    #[test]
    fn test_port_range_single_port_zero() {
        // ポート 0 は実サービスの終了対象としては無効
        assert!(matches!(
            PortRange::parse("0"),
            Err(SafeKillError::InvalidPort(_))
        ));
        assert!(!Config::default().is_port_allowed(0));
    }

    #[test]
    fn test_port_range_max_single_port() {
        // u16::MAX (65535) は有効
        let range = PortRange::parse("65535").unwrap();
        assert!(range.contains(65535));
        assert!(!range.contains(65534));
    }

    #[test]
    fn test_check_port_allowed_all_specs_malformed() {
        // すべてのポート指定が無効な場合、どのポートも許可されない
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec![
                    "not-a-port".to_string(),
                    "abc".to_string(),
                    "xxx-yyy".to_string(),
                ],
            }),
        };
        // allowed_ports は存在するがすべて無効 → PortNotAllowed エラー
        let result = config.check_port_allowed(8080);
        assert!(
            matches!(
                result,
                Err(SafeKillError::PortNotAllowed { port: 8080, .. })
            ),
            "すべてのポート指定が無効な場合、PortNotAllowed エラーを返すべき"
        );
        // is_port_allowed も false
        assert!(!config.is_port_allowed(3000));
        assert!(!config.is_port_allowed(0));
        assert!(!config.is_port_allowed(65535));
    }

    #[test]
    fn test_check_port_allowed_rejects_port_zero_even_when_configured() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec!["0-65535".to_string(), "0".to_string()],
            }),
        };

        assert!(!config.is_port_allowed(0));
        assert!(matches!(
            config.check_port_allowed(0),
            Err(SafeKillError::InvalidPort(port)) if port == "0"
        ));
        assert!(!config.is_port_allowed(3000));
    }

    #[test]
    fn test_get_port_ranges_skips_invalid() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: Some(AllowedPorts {
                ports: vec![
                    "invalid".to_string(),
                    "3000-3010".to_string(),
                    "".to_string(),
                ],
            }),
        };
        let ranges = config.get_port_ranges();
        // 有効な範囲のみ返される
        assert_eq!(ranges.len(), 1);
        assert_eq!(
            ranges[0],
            PortRange::Range {
                start: 3000,
                end: 3010
            }
        );
    }

    // =========================================================================
    // 設定ファイルの [allowed_ports] の検証（厳格読み込み）
    // =========================================================================

    /// `[allowed_ports]` だけを書いた設定ファイルを作って厳格に読み込む
    fn try_load_ports(ports: &str) -> Result<Config, SafeKillError> {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[allowed_ports]\nports = {ports}").unwrap();
        Config::try_load_from_path(Some(file.path().to_path_buf()))
    }

    #[test]
    fn test_try_load_rejects_invalid_allowed_ports_entry() {
        // 解析できない指定を黙って捨てると、範囲全体が無視されたことに気付けない。
        // ポート 0 を含む範囲・逆順・65535 超・全角ダッシュ（U+2013）・数字でない値・空文字列
        for spec in [
            "0-3010",
            "3010-3000",
            "65536",
            "3000\u{2013}3010",
            "abc",
            "",
            "0",
        ] {
            let result = try_load_ports(&format!("[{spec:?}]"));
            let Err(SafeKillError::ConfigError(message)) = &result else {
                panic!("{spec:?} は設定エラーになるべき: {result:?}");
            };
            assert!(
                message.contains("ports[0]") && message.contains(&format!("{spec:?}")),
                "どの指定が不正か示すべき ({spec:?}): {message}"
            );
            assert_eq!(
                result.unwrap_err().exit_code(),
                crate::error::SafeKillExitCode::ConfigError,
                "{spec:?}"
            );
        }
    }

    #[test]
    fn test_try_load_reports_index_of_first_invalid_allowed_ports_entry() {
        let result = try_load_ports(r#"["3000", "8080", "0-100"]"#);
        assert!(
            matches!(&result, Err(SafeKillError::ConfigError(message)) if message.contains("ports[2]")),
            "{result:?}"
        );
    }

    #[test]
    fn test_try_load_accepts_valid_allowed_ports_entries() {
        // 単一ポート・範囲・両端・前後の空白（従来どおり trim する）は受理する。
        // 空のリストと重複も、新しい制約は足さずに受理する
        let config =
            try_load_ports(r#"["1", "65535", "1-65535", " 3000 - 3010 ", "8080", "8080"]"#)
                .unwrap();
        for port in [1, 3005, 8080, 65535] {
            assert!(config.is_port_allowed(port), "{port}");
        }
        let config = try_load_ports("[]").unwrap();
        assert!(!config.is_port_allowed(3000));
    }

    #[test]
    fn test_lenient_load_falls_back_on_invalid_allowed_ports_entry() {
        // 寛容な読み込み（ライブラリの `load_from_path`）は警告を出して設定全体を既定値にする。
        // 不正な指定のある設定を部分的に採用すると、利用者の認識と実効設定が食い違う
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[denylist]\nprocesses = [\"custom-protected\"]\n[allowed_ports]\nports = [\"0-3010\"]"
        )
        .unwrap();
        let mut warnings = Vec::new();
        let config =
            Config::load_from_path_reporting(Some(file.path().to_path_buf()), &mut warnings);
        let warnings = String::from_utf8(warnings).unwrap();

        assert_eq!(config, Config::with_defaults());
        assert!(warnings.contains("ports[0]"), "{warnings}");
    }

    // =========================================================================
    // 厳格読み込みで「未作成」と取り違えてはいけない失敗
    //
    // 設定パス自体が存在しない（ENOENT）ときだけ既定値に倒す。ほかの失敗を未作成と
    // 扱うと、管理している設定のカスタム denylist が黙って外れる。
    // =========================================================================

    #[test]
    fn test_try_load_config_with_file_as_parent_directory_returns_error() {
        // `~/.config/safe-kill` が通常ファイル（ENOTDIR）
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("safe-kill");
        std::fs::write(&not_a_dir, "not a directory").unwrap();

        let result = Config::try_load_from_path(Some(not_a_dir.join("config.toml")));

        assert!(
            matches!(result, Err(SafeKillError::ConfigError(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_try_load_config_symlink_loop_returns_error() {
        let dir = tempfile::tempdir().unwrap();

        // config.toml 自身がループしている symlink（ELOOP）
        let self_loop = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&self_loop, &self_loop).unwrap();
        let result = Config::try_load_from_path(Some(self_loop));
        assert!(
            matches!(result, Err(SafeKillError::ConfigError(_))),
            "{result:?}"
        );

        // 親ディレクトリ同士がループしている symlink（パスの解決で ELOOP）
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();
        let result = Config::try_load_from_path(Some(a.join("config.toml")));
        assert!(
            matches!(result, Err(SafeKillError::ConfigError(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_try_load_config_directory_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::create_dir(&config_path).unwrap();

        let result = Config::try_load_from_path(Some(config_path));

        assert!(
            matches!(&result, Err(SafeKillError::ConfigError(message)) if message.contains("not a regular file")),
            "{result:?}"
        );
    }

    #[test]
    fn test_try_load_config_non_utf8_content_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"[denylist]\nprocesses = [\"\xff\xfe\"]\n")
            .unwrap();

        let result = Config::try_load_from_path(Some(file.path().to_path_buf()));

        assert!(
            matches!(result, Err(SafeKillError::ConfigError(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_try_load_config_dangling_grandparent_symlink_returns_error() {
        // `~/.config` 自体が壊れた symlink（設定ファイルの 2 つ上の階層）
        let dir = tempfile::tempdir().unwrap();
        let dot_config = dir.path().join(".config");
        std::os::unix::fs::symlink(dir.path().join("missing"), &dot_config).unwrap();
        let config_path = dot_config.join("safe-kill").join("config.toml");

        let result = Config::try_load_from_path(Some(config_path));

        assert!(
            matches!(result, Err(SafeKillError::ConfigError(_))),
            "{result:?}"
        );
    }

    #[test]
    fn test_try_load_config_symlinked_directory_without_file_returns_defaults() {
        // 設定ディレクトリが実在するディレクトリへの symlink で、ファイルはまだ無い（未作成）
        let dir = tempfile::tempdir().unwrap();
        let real_dir = dir.path().join("real-safe-kill");
        std::fs::create_dir(&real_dir).unwrap();
        let linked_dir = dir.path().join("safe-kill");
        std::os::unix::fs::symlink(&real_dir, &linked_dir).unwrap();

        let config = Config::try_load_from_path(Some(linked_dir.join("config.toml"))).unwrap();

        assert_eq!(config, Config::with_defaults());
    }

    #[test]
    fn test_try_load_config_fifo_does_not_block() {
        // FIFO を設定ファイルとして開くとき、書き手が現れるまで待たずに拒否する（O_NONBLOCK）。
        // 退行して待つようになってもテストがハングしないよう、別スレッドで読み込む。
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("config.toml");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();

        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = tx.send(Config::try_load_from_path(Some(fifo)));
        });
        // 期限内に結果が来なければ失敗させる。後始末に FIFO の相手側をブロッキングで開くと、
        // スレッドが既に FIFO を閉じていた（あるいは panic した）場合に相手が現れず、
        // テスト自体が止まる。待ったままのスレッドは切り離し、テストの終了とともに消える。
        let result = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("期限内に読み込みが終わらなかった（FIFO の書き手を待っているか、スレッドが panic した）");
        handle.join().expect("読み込みのスレッドが panic した");

        assert!(
            matches!(&result, Err(SafeKillError::ConfigError(message)) if message.contains("not a regular file")),
            "{result:?}"
        );
    }
}
