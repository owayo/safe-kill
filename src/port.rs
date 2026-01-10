//! Port detection module for safe-kill
//!
//! Detects processes using specific ports via netstat2.

use crate::error::SafeKillError;
use crate::process_info::{ProcessInfo, ProcessInfoProvider};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

/// Information about a process using a specific port
#[derive(Debug, Clone)]
pub struct PortProcess {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Port number
    pub port: u16,
    /// Protocol (TCP or UDP)
    pub protocol: PortProtocol,
}

/// Protocol type for port binding
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

/// Port detector that finds processes using specific ports
pub struct PortDetector {
    provider: ProcessInfoProvider,
}

impl PortDetector {
    /// Create a new PortDetector
    pub fn new() -> Self {
        Self {
            provider: ProcessInfoProvider::new(),
        }
    }

    /// Find all processes using the specified port
    ///
    /// Returns processes listening on the port (both TCP and UDP).
    /// Multiple processes may be returned if they share the port.
    pub fn find_by_port(&self, port: u16) -> Result<Vec<PortProcess>, SafeKillError> {
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
            let (local_port, protocol) = match &si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp_si) => (tcp_si.local_port, PortProtocol::Tcp),
                ProtocolSocketInfo::Udp(udp_si) => (udp_si.local_port, PortProtocol::Udp),
            };

            if local_port == port {
                for pid in &si.associated_pids {
                    let pid = *pid;
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
        }

        // Remove duplicates (same PID may appear multiple times for different sockets)
        results.sort_by_key(|p| p.pid);
        results.dedup_by_key(|p| p.pid);

        Ok(results)
    }

    /// Get process info for all processes using the specified port
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

    /// Refresh the underlying process information
    pub fn refresh(&mut self) {
        self.provider.refresh();
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

    #[test]
    fn test_port_detector_new() {
        let detector = PortDetector::new();
        // Should not panic
        let _ = detector;
    }

    #[test]
    fn test_port_detector_default() {
        let detector = PortDetector::default();
        // Should not panic
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
        // Use a high port that's unlikely to be in use
        let result = detector.find_by_port(59999);
        assert!(result.is_ok());
        // Port might or might not have processes, but should not error
    }

    #[test]
    fn test_find_by_port_returns_vec() {
        let detector = PortDetector::new();
        let result = detector.find_by_port(80);
        assert!(result.is_ok());
        // Result is a Vec, may be empty
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
        // Should not panic
    }
}
