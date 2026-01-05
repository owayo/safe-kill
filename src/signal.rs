//! Signal handling for safe-kill
//!
//! Provides Unix signal parsing and sending functionality using nix crate.

use crate::error::SafeKillError;
use nix::sys::signal::{self, Signal as NixSignal};
use nix::unistd::Pid;

/// Supported signals for process termination
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Signal {
    /// SIGHUP (1) - Hangup
    SIGHUP,
    /// SIGINT (2) - Interrupt
    SIGINT,
    /// SIGQUIT (3) - Quit
    SIGQUIT,
    /// SIGKILL (9) - Kill (cannot be caught)
    SIGKILL,
    /// SIGTERM (15) - Terminate
    #[default]
    SIGTERM,
    /// SIGUSR1 (10/30) - User defined signal 1
    SIGUSR1,
    /// SIGUSR2 (12/31) - User defined signal 2
    SIGUSR2,
}

impl Signal {
    /// Convert to nix Signal type
    fn to_nix(self) -> NixSignal {
        match self {
            Signal::SIGHUP => NixSignal::SIGHUP,
            Signal::SIGINT => NixSignal::SIGINT,
            Signal::SIGQUIT => NixSignal::SIGQUIT,
            Signal::SIGKILL => NixSignal::SIGKILL,
            Signal::SIGTERM => NixSignal::SIGTERM,
            Signal::SIGUSR1 => NixSignal::SIGUSR1,
            Signal::SIGUSR2 => NixSignal::SIGUSR2,
        }
    }

    /// Get signal number
    pub fn number(&self) -> i32 {
        self.to_nix() as i32
    }

    /// Get signal name
    pub fn name(&self) -> &'static str {
        match self {
            Signal::SIGHUP => "SIGHUP",
            Signal::SIGINT => "SIGINT",
            Signal::SIGQUIT => "SIGQUIT",
            Signal::SIGKILL => "SIGKILL",
            Signal::SIGTERM => "SIGTERM",
            Signal::SIGUSR1 => "SIGUSR1",
            Signal::SIGUSR2 => "SIGUSR2",
        }
    }
}

/// Signal sender for Unix processes
pub struct SignalSender;

impl SignalSender {
    /// Parse signal from string (name or number)
    ///
    /// Accepts:
    /// - Signal names: "SIGTERM", "SIGKILL", "TERM", "KILL", etc.
    /// - Signal numbers: "15", "9", etc.
    pub fn parse_signal(s: &str) -> Result<Signal, SafeKillError> {
        let s = s.trim().to_uppercase();

        // Try parsing as number first
        if let Ok(num) = s.parse::<i32>() {
            return Self::from_number(num);
        }

        // Try parsing as name
        Self::from_name(&s)
    }

    /// Parse signal from number
    fn from_number(num: i32) -> Result<Signal, SafeKillError> {
        match num {
            1 => Ok(Signal::SIGHUP),
            2 => Ok(Signal::SIGINT),
            3 => Ok(Signal::SIGQUIT),
            9 => Ok(Signal::SIGKILL),
            15 => Ok(Signal::SIGTERM),
            10 | 30 => Ok(Signal::SIGUSR1), // Linux: 10, macOS: 30
            12 | 31 => Ok(Signal::SIGUSR2), // Linux: 12, macOS: 31
            _ => Err(SafeKillError::InvalidSignal(num.to_string())),
        }
    }

    /// Parse signal from name
    fn from_name(s: &str) -> Result<Signal, SafeKillError> {
        // Remove SIG prefix if present
        let name = s.strip_prefix("SIG").unwrap_or(s);

        match name {
            "HUP" => Ok(Signal::SIGHUP),
            "INT" => Ok(Signal::SIGINT),
            "QUIT" => Ok(Signal::SIGQUIT),
            "KILL" => Ok(Signal::SIGKILL),
            "TERM" => Ok(Signal::SIGTERM),
            "USR1" => Ok(Signal::SIGUSR1),
            "USR2" => Ok(Signal::SIGUSR2),
            _ => Err(SafeKillError::InvalidSignal(s.to_string())),
        }
    }

    /// Send signal to process
    pub fn send(pid: u32, signal: Signal) -> Result<(), SafeKillError> {
        let nix_pid = Pid::from_raw(pid as i32);
        let nix_signal = signal.to_nix();

        signal::kill(nix_pid, nix_signal).map_err(|e| match e {
            nix::errno::Errno::ESRCH => SafeKillError::ProcessNotFound(pid),
            nix::errno::Errno::EPERM => SafeKillError::PermissionDenied(pid),
            _ => SafeKillError::SystemError(format!("Failed to send signal: {}", e)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signal enum tests
    #[test]
    fn test_signal_default() {
        assert_eq!(Signal::default(), Signal::SIGTERM);
    }

    #[test]
    fn test_signal_name() {
        assert_eq!(Signal::SIGHUP.name(), "SIGHUP");
        assert_eq!(Signal::SIGINT.name(), "SIGINT");
        assert_eq!(Signal::SIGQUIT.name(), "SIGQUIT");
        assert_eq!(Signal::SIGKILL.name(), "SIGKILL");
        assert_eq!(Signal::SIGTERM.name(), "SIGTERM");
        assert_eq!(Signal::SIGUSR1.name(), "SIGUSR1");
        assert_eq!(Signal::SIGUSR2.name(), "SIGUSR2");
    }

    #[test]
    fn test_signal_number() {
        assert_eq!(Signal::SIGHUP.number(), 1);
        assert_eq!(Signal::SIGINT.number(), 2);
        assert_eq!(Signal::SIGQUIT.number(), 3);
        assert_eq!(Signal::SIGKILL.number(), 9);
        assert_eq!(Signal::SIGTERM.number(), 15);
    }

    // Parse from number tests
    #[test]
    fn test_parse_signal_from_number() {
        assert_eq!(SignalSender::parse_signal("1").unwrap(), Signal::SIGHUP);
        assert_eq!(SignalSender::parse_signal("2").unwrap(), Signal::SIGINT);
        assert_eq!(SignalSender::parse_signal("3").unwrap(), Signal::SIGQUIT);
        assert_eq!(SignalSender::parse_signal("9").unwrap(), Signal::SIGKILL);
        assert_eq!(SignalSender::parse_signal("15").unwrap(), Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_usr1_linux() {
        assert_eq!(SignalSender::parse_signal("10").unwrap(), Signal::SIGUSR1);
    }

    #[test]
    fn test_parse_signal_usr1_macos() {
        assert_eq!(SignalSender::parse_signal("30").unwrap(), Signal::SIGUSR1);
    }

    #[test]
    fn test_parse_signal_usr2_linux() {
        assert_eq!(SignalSender::parse_signal("12").unwrap(), Signal::SIGUSR2);
    }

    #[test]
    fn test_parse_signal_usr2_macos() {
        assert_eq!(SignalSender::parse_signal("31").unwrap(), Signal::SIGUSR2);
    }

    // Parse from name tests
    #[test]
    fn test_parse_signal_from_name_with_prefix() {
        assert_eq!(
            SignalSender::parse_signal("SIGTERM").unwrap(),
            Signal::SIGTERM
        );
        assert_eq!(
            SignalSender::parse_signal("SIGKILL").unwrap(),
            Signal::SIGKILL
        );
        assert_eq!(
            SignalSender::parse_signal("SIGHUP").unwrap(),
            Signal::SIGHUP
        );
        assert_eq!(
            SignalSender::parse_signal("SIGINT").unwrap(),
            Signal::SIGINT
        );
        assert_eq!(
            SignalSender::parse_signal("SIGQUIT").unwrap(),
            Signal::SIGQUIT
        );
        assert_eq!(
            SignalSender::parse_signal("SIGUSR1").unwrap(),
            Signal::SIGUSR1
        );
        assert_eq!(
            SignalSender::parse_signal("SIGUSR2").unwrap(),
            Signal::SIGUSR2
        );
    }

    #[test]
    fn test_parse_signal_from_name_without_prefix() {
        assert_eq!(SignalSender::parse_signal("TERM").unwrap(), Signal::SIGTERM);
        assert_eq!(SignalSender::parse_signal("KILL").unwrap(), Signal::SIGKILL);
        assert_eq!(SignalSender::parse_signal("HUP").unwrap(), Signal::SIGHUP);
        assert_eq!(SignalSender::parse_signal("INT").unwrap(), Signal::SIGINT);
        assert_eq!(SignalSender::parse_signal("QUIT").unwrap(), Signal::SIGQUIT);
        assert_eq!(SignalSender::parse_signal("USR1").unwrap(), Signal::SIGUSR1);
        assert_eq!(SignalSender::parse_signal("USR2").unwrap(), Signal::SIGUSR2);
    }

    #[test]
    fn test_parse_signal_case_insensitive() {
        assert_eq!(
            SignalSender::parse_signal("sigterm").unwrap(),
            Signal::SIGTERM
        );
        assert_eq!(
            SignalSender::parse_signal("Sigkill").unwrap(),
            Signal::SIGKILL
        );
        assert_eq!(SignalSender::parse_signal("term").unwrap(), Signal::SIGTERM);
        assert_eq!(SignalSender::parse_signal("kill").unwrap(), Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_with_whitespace() {
        assert_eq!(
            SignalSender::parse_signal("  SIGTERM  ").unwrap(),
            Signal::SIGTERM
        );
        assert_eq!(SignalSender::parse_signal(" 15 ").unwrap(), Signal::SIGTERM);
    }

    // Invalid signal tests
    #[test]
    fn test_parse_invalid_signal_number() {
        let result = SignalSender::parse_signal("99");
        assert!(result.is_err());
        match result {
            Err(SafeKillError::InvalidSignal(s)) => assert_eq!(s, "99"),
            _ => panic!("Expected InvalidSignal error"),
        }
    }

    #[test]
    fn test_parse_invalid_signal_name() {
        let result = SignalSender::parse_signal("SIGFOO");
        assert!(result.is_err());
        match result {
            Err(SafeKillError::InvalidSignal(s)) => assert_eq!(s, "SIGFOO"),
            _ => panic!("Expected InvalidSignal error"),
        }
    }

    #[test]
    fn test_parse_empty_signal() {
        let result = SignalSender::parse_signal("");
        assert!(result.is_err());
    }

    // Send signal tests
    #[test]
    fn test_send_to_nonexistent_process() {
        // Use a very high PID that's unlikely to exist
        let result = SignalSender::send(999999999, Signal::SIGTERM);
        assert!(result.is_err());
        match result {
            Err(SafeKillError::ProcessNotFound(pid)) => assert_eq!(pid, 999999999),
            Err(SafeKillError::PermissionDenied(_)) => {
                // Some systems may return permission denied instead
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
            Ok(_) => panic!("Expected error for nonexistent process"),
        }
    }

    #[test]
    fn test_signal_number_all_variants() {
        // Verify that all signals have valid numbers
        let signals = [
            (Signal::SIGHUP, 1),
            (Signal::SIGINT, 2),
            (Signal::SIGQUIT, 3),
            (Signal::SIGKILL, 9),
            (Signal::SIGTERM, 15),
        ];
        for (sig, expected_num) in &signals {
            assert_eq!(sig.number(), *expected_num);
        }
        // SIGUSR1 and SIGUSR2 have platform-specific numbers
        assert!(Signal::SIGUSR1.number() > 0);
        assert!(Signal::SIGUSR2.number() > 0);
    }

    // Clone and Copy tests
    #[test]
    fn test_signal_clone() {
        let sig = Signal::SIGTERM;
        let cloned = sig;
        assert_eq!(sig, cloned);
    }

    #[test]
    fn test_signal_debug() {
        let sig = Signal::SIGTERM;
        let debug_str = format!("{:?}", sig);
        assert_eq!(debug_str, "SIGTERM");
    }
}
