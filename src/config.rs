//! safe-kill の設定ファイルローダー
//!
//! ~/.config/safe-kill/config.toml 設定ファイルの読み込みと解析を行う。

use crate::error::SafeKillError;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// メイン設定構造体
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct Config {
    /// ancestry チェックをバイパスするプロセス（子孫検証なしで kill 可能）
    pub allowlist: Option<ProcessList>,
    /// kill 不可能なプロセス（allowlist より優先される）
    pub denylist: Option<ProcessList>,
    /// --port kill 操作で許可されるポート
    pub allowed_ports: Option<AllowedPorts>,
}

/// プロセス名リスト
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ProcessList {
    /// リスト内のプロセス名
    pub processes: Vec<String>,
}

/// 許可ポート設定
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
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

            let start = parts[0]
                .trim()
                .parse::<u16>()
                .map_err(|_| SafeKillError::InvalidPortRange(spec.to_string()))?;
            let end = parts[1]
                .trim()
                .parse::<u16>()
                .map_err(|_| SafeKillError::InvalidPortRange(spec.to_string()))?;

            if start > end {
                return Err(SafeKillError::InvalidPortRange(spec.to_string()));
            }

            Ok(PortRange::Range { start, end })
        } else {
            let port = spec
                .parse::<u16>()
                .map_err(|_| SafeKillError::InvalidPortRange(spec.to_string()))?;
            Ok(PortRange::Single(port))
        }
    }

    /// ポートがこの範囲内に含まれるか確認する
    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortRange::Single(p) => *p == port,
            PortRange::Range { start, end } => port >= *start && port <= *end,
        }
    }
}

impl Config {
    /// ~/.config/safe-kill/config.toml から設定を読み込む
    ///
    /// ファイルが存在しない場合はデフォルト設定を返す。
    /// 解析エラー時は警告付きでデフォルト設定を返す。
    pub fn load() -> Self {
        Self::load_from_path(Self::config_path())
    }

    /// 指定されたパスから設定を読み込む
    pub fn load_from_path(path: Option<PathBuf>) -> Self {
        let Some(path) = path else {
            return Self::with_defaults();
        };

        if !path.exists() {
            return Self::with_defaults();
        }

        match fs::read_to_string(&path) {
            Ok(content) => match toml::from_str::<Config>(&content) {
                Ok(mut config) => {
                    config.merge_defaults();
                    config
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to parse config file {:?}: {}. Using defaults.",
                        path, e
                    );
                    Self::with_defaults()
                }
            },
            Err(e) => {
                eprintln!(
                    "Warning: Failed to read config file {:?}: {}. Using defaults.",
                    path, e
                );
                Self::with_defaults()
            }
        }
    }

    /// デフォルトの設定ファイルパスを取得する
    ///
    /// Linux/macOS では `~/.config/safe-kill/config.toml` を返す
    pub fn config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".config").join("safe-kill").join("config.toml"))
    }

    /// 設定ディレクトリのパスを取得する
    pub fn config_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".config").join("safe-kill"))
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
    fn merge_defaults(&mut self) {
        // denylist が未指定の場合、デフォルトの denylist を追加
        if self.denylist.is_none() {
            self.denylist = Some(ProcessList {
                processes: Self::default_denylist(),
            });
        }
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
    pub fn is_denied(&self, name: &str) -> bool {
        self.denylist
            .as_ref()
            .map(|list| list.processes.iter().any(|p| p == name))
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
        let Some(allowed_ports) = &self.allowed_ports else {
            return false;
        };

        for spec in &allowed_ports.ports {
            if let Ok(range) = PortRange::parse(spec) {
                if range.contains(port) {
                    return true;
                }
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

    // パスからの読み込みテスト
    #[test]
    fn test_load_from_nonexistent_path() {
        let config = Config::load_from_path(Some(PathBuf::from("/nonexistent/path/config.toml")));
        // デフォルト値が返されるべき
        assert!(config.denylist.is_some());
    }

    #[test]
    fn test_load_from_none_path() {
        let config = Config::load_from_path(None);
        // デフォルト値が返されるべき
        assert!(config.denylist.is_some());
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
        // 解析エラー時はデフォルトにフォールバックするべき
        assert!(config.denylist.is_some());
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
    fn test_merge_defaults_preserves_custom_denylist() {
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
        // カスタム denylist はデフォルトで上書きされないこと
        let denylist = config.denylist.as_ref().unwrap();
        assert_eq!(denylist.processes, vec!["custom_process".to_string()]);
        // デフォルトのプロセス（例: launchd, systemd）はリストに含まれないこと
        assert!(!denylist.processes.contains(&"launchd".to_string()));
        assert!(!denylist.processes.contains(&"systemd".to_string()));
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
    // 境界値テスト（Codex分析により追加）
    // =============================================================================

    #[test]
    fn test_port_range_boundary_values() {
        // ポート0は有効
        assert!(PortRange::parse("0").is_ok());
        assert_eq!(PortRange::parse("0").unwrap(), PortRange::Single(0));
        assert!(PortRange::parse("0").unwrap().contains(0));

        // ポート65535は最大有効値
        assert!(PortRange::parse("65535").is_ok());
        assert_eq!(PortRange::parse("65535").unwrap(), PortRange::Single(65535));
        assert!(PortRange::parse("65535").unwrap().contains(65535));

        // 最大範囲
        assert!(PortRange::parse("0-65535").is_ok());
        let full_range = PortRange::parse("0-65535").unwrap();
        assert!(full_range.contains(0));
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
}
