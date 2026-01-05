//! Configuration file loader for safe-kill
//!
//! Loads and parses ~/.safe-kill.toml configuration file.

use serde::Deserialize;
use std::fs;
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct Config {
    /// Processes that bypass ancestry checks (killed without descendant verification)
    pub allowlist: Option<ProcessList>,
    /// Processes that can never be killed (takes precedence over allowlist)
    pub denylist: Option<ProcessList>,
}

/// List of process names
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ProcessList {
    /// Process names in the list
    pub processes: Vec<String>,
}

impl Config {
    /// Load configuration from ~/.safe-kill.toml
    ///
    /// Returns default config if file doesn't exist.
    /// Returns default config with warning on parse error.
    pub fn load() -> Self {
        Self::load_from_path(Self::config_path())
    }

    /// Load configuration from a specific path
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

    /// Get the default config file path
    pub fn config_path() -> Option<PathBuf> {
        dirs::home_dir().map(|home| home.join(".safe-kill.toml"))
    }

    /// Create config with default denylist
    fn with_defaults() -> Self {
        Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: Self::default_denylist(),
            }),
        }
    }

    /// Merge defaults into existing config
    fn merge_defaults(&mut self) {
        // Add default denylist items if denylist is not specified
        if self.denylist.is_none() {
            self.denylist = Some(ProcessList {
                processes: Self::default_denylist(),
            });
        }
    }

    /// Get OS-specific default denylist
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

    /// Check if a process name is in the allowlist
    pub fn is_allowed(&self, name: &str) -> bool {
        self.allowlist
            .as_ref()
            .map(|list| list.processes.iter().any(|p| p == name))
            .unwrap_or(false)
    }

    /// Check if a process name is in the denylist
    pub fn is_denied(&self, name: &str) -> bool {
        self.denylist
            .as_ref()
            .map(|list| list.processes.iter().any(|p| p == name))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Config structure tests
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
        assert!(!config.denylist.unwrap().processes.is_empty());
    }

    // Default denylist tests
    #[test]
    fn test_default_denylist_not_empty() {
        let denylist = Config::default_denylist();
        assert!(!denylist.is_empty());
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

    // Config path tests
    #[test]
    fn test_config_path_exists() {
        let path = Config::config_path();
        assert!(path.is_some());
        let path = path.unwrap();
        assert!(path.to_string_lossy().contains(".safe-kill.toml"));
    }

    // Load from path tests
    #[test]
    fn test_load_from_nonexistent_path() {
        let config = Config::load_from_path(Some(PathBuf::from("/nonexistent/path/config.toml")));
        // Should return defaults
        assert!(config.denylist.is_some());
    }

    #[test]
    fn test_load_from_none_path() {
        let config = Config::load_from_path(None);
        // Should return defaults
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
        // Default denylist should be added
        assert!(config.denylist.is_some());
        assert!(config.is_allowed("node"));
    }

    #[test]
    fn test_load_config_empty() {
        let file = NamedTempFile::new().unwrap();
        // Empty file is valid TOML

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        // Should use defaults
        assert!(config.denylist.is_some());
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "this is not valid TOML {{{{").unwrap();

        let config = Config::load_from_path(Some(file.path().to_path_buf()));
        // Should fall back to defaults on parse error
        assert!(config.denylist.is_some());
    }

    // is_allowed tests
    #[test]
    fn test_is_allowed_with_allowlist() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["node".to_string(), "npm".to_string()],
            }),
            denylist: None,
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
        };
        assert!(!config.is_allowed("node"));
        assert!(!config.is_allowed("anything"));
    }

    // is_denied tests
    #[test]
    fn test_is_denied_with_denylist() {
        let config = Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: vec!["systemd".to_string(), "launchd".to_string()],
            }),
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
        };
        assert!(!config.is_denied("systemd"));
        assert!(!config.is_denied("anything"));
    }

    // Clone and equality tests
    #[test]
    fn test_config_clone() {
        let config = Config {
            allowlist: Some(ProcessList {
                processes: vec!["node".to_string()],
            }),
            denylist: Some(ProcessList {
                processes: vec!["systemd".to_string()],
            }),
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

    // Debug tests
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
}
