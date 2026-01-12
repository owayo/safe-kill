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
#   - 8080: HTTP alternative port
[allowed_ports]
ports = ["1420", "3000-3010", "8080"]
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
}
