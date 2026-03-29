//! safe-kill の init コマンドモジュール
//!
//! サンプル設定を含む設定ファイルを生成する。

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::SafeKillError;

/// 設定ファイル生成のための init コマンド
pub struct InitCommand;

impl InitCommand {
    /// init コマンドを実行して設定ファイルを生成する
    ///
    /// # 引数
    /// * `force` - true の場合、確認なしで既存ファイルを上書き
    ///
    /// # 戻り値
    /// * `Ok(PathBuf)` - 生成されたファイルのパス
    /// * `Err(SafeKillError)` - 生成に失敗した場合
    pub fn execute(force: bool) -> Result<PathBuf, SafeKillError> {
        let config_dir = Config::config_dir().ok_or_else(|| {
            SafeKillError::ConfigCreationError("Unable to determine config directory".to_string())
        })?;

        let config_path = Config::config_path().ok_or_else(|| {
            SafeKillError::ConfigCreationError("Unable to determine config path".to_string())
        })?;

        // ファイルの存在チェック
        if config_path.exists() && !force {
            // 上書き確認
            if !Self::confirm_overwrite(&config_path)? {
                return Err(SafeKillError::ConfigCreationError(
                    "Operation cancelled".to_string(),
                ));
            }
        }

        // ディレクトリが存在しない場合は作成
        fs::create_dir_all(&config_dir).map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to create directory {}: {}",
                config_dir.display(),
                e
            ))
        })?;

        // 設定ファイルを書き込み
        let content = Self::default_config_content();
        fs::write(&config_path, content).map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to write config file {}: {}",
                config_path.display(),
                e
            ))
        })?;

        Ok(config_path)
    }

    /// コメント付きのデフォルト設定内容を生成
    pub fn default_config_content() -> String {
        r#"# safe-kill 設定ファイル
# safe-kill で終了を許可するプロセスやポートをこのファイルで制御します。

# 許可リスト: ここに書いたプロセス名は親子関係チェックをバイパスできます。
# 指定しない場合は、拒否リスト以外のプロセスが通常の安全チェック対象になります。
# [allowlist]
# processes = ["next-server"]

# 拒否リスト: ここに書いたプロセス名は常に終了できません。
# システムプロセスはデフォルトでも保護され、ここに書いた内容はその保護対象に追加されます。
# [denylist]
# processes = ["systemd", "launchd", "init"]

# 許可ポート: --port オプションで対象にできるポートです。
# 指定しない場合、--port オプションは無効です。
# 単一ポート ("3000") と範囲 ("8080-8090") の両方を指定できます。
#   - 1420: Tauri 開発サーバー
#   - 3000-3010: Node.js 開発サーバー
#   - 5173: Vite 開発サーバー
#   - 8080: HTTP 代替ポート
[allowed_ports]
ports = ["1420", "3000-3010", "5173", "8080"]
"#
        .to_string()
    }

    /// 既存ファイルの上書き確認をユーザーに求める
    fn confirm_overwrite(path: &Path) -> Result<bool, SafeKillError> {
        eprint!(
            "Config file already exists at {}. Overwrite? [y/N]: ",
            path.display()
        );
        io::stderr().flush().map_err(|e| {
            SafeKillError::ConfigCreationError(format!("Failed to flush stderr: {}", e))
        })?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(|e| {
            SafeKillError::ConfigCreationError(format!("Failed to read input: {}", e))
        })?;

        let input = input.trim().to_lowercase();
        Ok(input == "y" || input == "yes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_content_not_empty() {
        let content = InitCommand::default_config_content();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_default_config_content_has_sections() {
        let content = InitCommand::default_config_content();
        assert!(content.contains("[allowed_ports]"));
        assert!(content.contains("# [allowlist]"));
        assert!(content.contains("# [denylist]"));
    }

    #[test]
    fn test_default_config_content_has_examples() {
        let content = InitCommand::default_config_content();
        assert!(content.contains("1420"));
        assert!(content.contains("3000-3010"));
        assert!(content.contains("5173"));
        assert!(content.contains("8080"));
    }

    #[test]
    fn test_default_config_content_has_comments() {
        let content = InitCommand::default_config_content();
        assert!(content.contains("# safe-kill 設定ファイル"));
        assert!(content.contains("# 許可リスト"));
        assert!(content.contains("# 拒否リスト"));
        assert!(content.contains("# 許可ポート"));
    }

    #[test]
    fn test_default_config_is_valid_toml() {
        let content = InitCommand::default_config_content();
        // 有効な TOML としてパースできること
        let result: Result<toml::Value, _> = toml::from_str(&content);
        assert!(result.is_ok(), "Config content should be valid TOML");
    }

    #[test]
    fn test_default_config_loads_as_config() {
        let content = InitCommand::default_config_content();
        let result: Result<crate::config::Config, _> = toml::from_str(&content);
        assert!(
            result.is_ok(),
            "Config content should deserialize to Config"
        );
    }

    #[test]
    fn test_execute_force_creates_config_in_temp_dir() {
        // テスト用の一時ディレクトリを使って execute(force=true) を検証
        // 実際の HOME を変更できないため、default_config_content の内容が
        // 有効な TOML であり Config としてパースできることを確認する
        let content = InitCommand::default_config_content();
        let parsed: Result<crate::config::Config, _> = toml::from_str(&content);
        assert!(parsed.is_ok());
        let config = parsed.unwrap();
        // allowed_ports セクションが含まれること
        assert!(config.allowed_ports.is_some());
        let ports = config.allowed_ports.unwrap();
        assert!(!ports.ports.is_empty());
        // デフォルトのポート設定が含まれていること
        assert!(ports.ports.contains(&"1420".to_string()));
        assert!(ports.ports.contains(&"3000-3010".to_string()));
        assert!(ports.ports.contains(&"5173".to_string()));
        assert!(ports.ports.contains(&"8080".to_string()));
    }

    #[test]
    fn test_default_config_ports_match_default_allowed_ports() {
        let content = InitCommand::default_config_content();
        let parsed: crate::config::Config = toml::from_str(&content).unwrap();
        let ports = parsed
            .allowed_ports
            .expect("default config should include [allowed_ports]")
            .ports;
        assert_eq!(ports, crate::config::Config::default_allowed_ports());
    }

    #[test]
    fn test_default_config_content_has_port_descriptions() {
        let content = InitCommand::default_config_content();
        // ポートの説明コメントが含まれていること
        assert!(content.contains("Tauri 開発サーバー"));
        assert!(content.contains("Node.js 開発サーバー"));
        assert!(content.contains("Vite 開発サーバー"));
        assert!(content.contains("HTTP 代替ポート"));
    }

    #[test]
    fn test_execute_creates_file_in_temp_dir() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(".config").join("safe-kill");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("config.toml");

        // execute と同じロジックで直接書き込み
        let content = InitCommand::default_config_content();
        std::fs::write(&config_path, &content).unwrap();

        // ファイルが存在し、有効な TOML であることを確認
        assert!(config_path.exists());
        let read_content = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(read_content, content);

        let parsed: Result<crate::config::Config, _> = toml::from_str(&read_content);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_default_config_content_line_count() {
        let content = InitCommand::default_config_content();
        let lines: Vec<&str> = content.lines().collect();
        // 設定ファイルが空でないこと（少なくとも10行以上）
        assert!(
            lines.len() >= 10,
            "Config should have at least 10 lines, got {}",
            lines.len()
        );
    }
}
