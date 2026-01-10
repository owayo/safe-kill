//! Configuration file loader for safe-kill
//!
//! Loads and parses ~/.config/safe-kill/config.toml configuration file.

use crate::error::SafeKillError;
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
    /// Allowed ports for --port kill operations
    pub allowed_ports: Option<AllowedPorts>,
}

/// List of process names
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ProcessList {
    /// Process names in the list
    pub processes: Vec<String>,
}

/// Allowed ports configuration
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct AllowedPorts {
    /// Port specifications (can be single port "3306" or range "3000-3100")
    pub ports: Vec<String>,
}

/// Represents a port range or single port
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortRange {
    /// Single port number
    Single(u16),
    /// Port range (inclusive)
    Range { start: u16, end: u16 },
}

impl PortRange {
    /// Parse a port specification string into PortRange
    ///
    /// Supports:
    /// - Single port: "3306"
    /// - Range: "3000-3100"
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

    /// Check if a port is within this range
    pub fn contains(&self, port: u16) -> bool {
        match self {
            PortRange::Single(p) => *p == port,
            PortRange::Range { start, end } => port >= *start && port <= *end,
        }
    }
}

impl Config {
    /// Load configuration from ~/.config/safe-kill/config.toml
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

    /// Get the default config file path (XDG-compliant)
    ///
    /// Returns `~/.config/safe-kill/config.toml` on Linux/macOS
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|config_dir| config_dir.join("safe-kill").join("config.toml"))
    }

    /// Get the config directory path
    pub fn config_dir() -> Option<PathBuf> {
        dirs::config_dir().map(|config_dir| config_dir.join("safe-kill"))
    }

    /// Create config with default denylist
    fn with_defaults() -> Self {
        Config {
            allowlist: None,
            denylist: Some(ProcessList {
                processes: Self::default_denylist(),
            }),
            allowed_ports: None,
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
        // Note: allowed_ports is NOT set by default.
        // Port-based killing is disabled unless explicitly configured.
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

    /// Get recommended allowed ports for sample config file
    ///
    /// These ports are commonly used in development and are included
    /// in the sample configuration generated by `safe-kill init`:
    /// - 1420: Tauri dev server
    /// - 3000-3010: Node.js dev servers
    /// - 8080: HTTP alternative port
    ///
    /// Note: This is NOT applied as a runtime default.
    /// Port-based killing is disabled unless explicitly configured.
    pub fn default_allowed_ports() -> Vec<String> {
        vec![
            "1420".to_string(),
            "3000-3010".to_string(),
            "8080".to_string(),
        ]
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

    /// Check if a port is allowed for killing
    ///
    /// Returns true if the port matches any of the configured port specifications.
    /// If no allowed_ports configuration exists, returns false (port killing is disabled).
    ///
    /// To enable port-based killing, configure allowed_ports in config.toml:
    /// ```toml
    /// [allowed_ports]
    /// ports = ["1420", "3000-3010", "8080"]
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

    /// Get parsed port ranges from configuration
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

    /// Generate a hint message for when a port is not allowed
    ///
    /// This method creates a user-friendly message explaining how to allow
    /// the port in the configuration file.
    pub fn port_not_allowed_hint(&self, port: u16) -> String {
        format!(
            "Add {} to [allowed_ports] in config.toml or run 'safe-kill init' to create a config file",
            port
        )
    }

    /// Check if a port is allowed and return an error with hint if not
    ///
    /// This is a convenience method that combines `is_port_allowed` with
    /// error generation including helpful hints.
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
        assert!(!config.denylist.as_ref().unwrap().processes.is_empty());
        // allowed_ports is None by default (port killing disabled unless configured)
        assert!(config.allowed_ports.is_none());
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
        // XDG-compliant path
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

    // is_denied tests
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

    // PortRange tests
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
        assert!(PortRange::parse("100-50").is_err()); // start > end
        assert!(PortRange::parse("1-2-3").is_err());
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

    // is_port_allowed tests
    #[test]
    fn test_is_port_allowed_no_config() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        // No allowed_ports configuration means port killing is disabled
        // All ports return false
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
        assert!(config.is_port_allowed(3050)); // In range
        assert!(config.is_port_allowed(3306)); // Single
        assert!(config.is_port_allowed(5432)); // Single
        assert!(!config.is_port_allowed(22)); // Not allowed
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

    // port_not_allowed_hint tests
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

    // check_port_allowed tests
    #[test]
    fn test_check_port_allowed_no_config_all_fail() {
        let config = Config {
            allowlist: None,
            denylist: None,
            allowed_ports: None,
        };
        // No allowed_ports configuration means all port checks fail
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
}
