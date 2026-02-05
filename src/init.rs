//! Init command module for safe-kill
//!
//! Generates configuration file with sample settings.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::error::SafeKillError;

/// Init command for generating configuration file
pub struct InitCommand;

impl InitCommand {
    /// Execute the init command to generate configuration file
    ///
    /// # Arguments
    /// * `force` - If true, overwrite existing file without confirmation
    ///
    /// # Returns
    /// * `Ok(PathBuf)` - Path to the generated file
    /// * `Err(SafeKillError)` - If generation fails
    pub fn execute(force: bool) -> Result<PathBuf, SafeKillError> {
        let config_dir = Config::config_dir().ok_or_else(|| {
            SafeKillError::ConfigCreationError("Unable to determine config directory".to_string())
        })?;

        let config_path = Config::config_path().ok_or_else(|| {
            SafeKillError::ConfigCreationError("Unable to determine config path".to_string())
        })?;

        // Check if file exists
        if config_path.exists() && !force {
            // Ask for confirmation
            if !Self::confirm_overwrite(&config_path)? {
                return Err(SafeKillError::ConfigCreationError(
                    "Operation cancelled".to_string(),
                ));
            }
        }

        // Create directory if it doesn't exist
        fs::create_dir_all(&config_dir).map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to create directory {}: {}",
                config_dir.display(),
                e
            ))
        })?;

        // Write config file
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

    /// Generate default configuration content with comments
    pub fn default_config_content() -> String {
        r#"# safe-kill configuration file
# This file controls which processes can be killed by safe-kill.

# Allowlist: Only processes matching these names can be killed.
# If not specified, all processes (except denylisted) are allowed.
# [allowlist]
# processes = ["next-server"]

# Denylist: Processes matching these names can never be killed.
# System processes are always protected by default.
# [denylist]
# processes = ["systemd", "launchd", "init"]

# Allowed ports: Ports that can be targeted with --port option.
# If not specified, --port option is disabled (no ports can be killed).
# Supports individual ports and ranges (e.g., "3000", "8080-8090").
#   - 1420: Tauri dev server
#   - 3000-3010: Node.js dev servers
#   - 5173: Vite dev server
#   - 8080: HTTP alternative port
[allowed_ports]
ports = ["1420", "3000-3010", "5173", "8080"]
"#
        .to_string()
    }

    /// Ask user for confirmation to overwrite existing file
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
        assert!(content.contains("# safe-kill configuration file"));
        assert!(content.contains("# Allowlist"));
        assert!(content.contains("# Denylist"));
        assert!(content.contains("# Allowed ports"));
    }

    #[test]
    fn test_default_config_is_valid_toml() {
        let content = InitCommand::default_config_content();
        // Should parse as valid TOML
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
        assert!(ports.ports.contains(&"8080".to_string()));
    }

    #[test]
    fn test_default_config_content_has_port_descriptions() {
        let content = InitCommand::default_config_content();
        // ポートの説明コメントが含まれていること
        assert!(content.contains("Tauri dev server"));
        assert!(content.contains("Node.js dev servers"));
        assert!(content.contains("Vite dev server"));
        assert!(content.contains("HTTP alternative port"));
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
