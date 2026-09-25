# CLI Reference

Every command, option, signal, exit code, and environment variable of `safe-kill`. The configuration file is described in [configuration.md](configuration.md).

## Commands

```bash
safe-kill [OPTIONS] [PID]
safe-kill init [--force]
```

`init` is a standalone subcommand. It cannot be combined with `PID`, `--name`, `--port`, `--list`, `--signal`, or `--dry-run`. It creates `~/.config/safe-kill/config.toml`; what it writes and how it treats an existing file are described in [configuration.md](configuration.md#creating-the-file-with-safe-kill-init).

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--name <NAME>` | `-N` | Kill processes by exact process name |
| `--port <PORT>` | `-p` | Kill configured TCP listener or UDP socket using the specified port (`1`-`65535`; `0` is rejected) |
| `--signal <SIGNAL>` | `-s` | Signal to send (default: SIGTERM) |
| `--list` | `-l` | List killable processes |
| `--dry-run` | `-n` | Preview without sending signals |
| `--help` | `-h` | Show help |
| `--version` | `-V` | Show version |

## Signals

Supported signals can be specified by name or number:

| Signal | Number | Description |
|--------|--------|-------------|
| SIGTERM | 15 | Graceful termination (default) |
| SIGKILL | 9 | Force kill |
| SIGHUP | 1 | Hangup |
| SIGINT | 2 | Interrupt |
| SIGQUIT | 3 | Quit |
| SIGUSR1 | 10 (Linux) / 30 (macOS) | User-defined signal 1 (platform-native number only) |
| SIGUSR2 | 12 (Linux) / 31 (macOS) | User-defined signal 2 (platform-native number only) |

## Choosing Targets

`--name` matches the executable name exactly. It does not perform substring or pattern matching.

When multiple processes match `--name`, results are processed and displayed in ascending PID order so repeated runs stay stable.

`--port` targets TCP sockets only when they are in `LISTEN` state. Established TCP client sockets with the same local port are ignored. UDP has no connection state, so UDP matches use the local port. Port `0` is always rejected because it is an OS auto-assignment sentinel, not a kill target. The port must be listed in `[allowed_ports]` of the configuration file; without that table, `--port` is disabled.

For `--name` and `--port` dry runs, batch summaries use `would kill` so preview output is not mistaken for an actual termination.

## Error Handling

If a process matched policy checks but disappeared before signal delivery, or the OS rejected the signal, `safe-kill` returns the original runtime error such as `ProcessNotFound` or `PermissionDenied` instead of collapsing it into `NoKillableTarget`.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | No target found (no name match, no process on allowed port, or no killable match) |
| 2 | Permission denied |
| 3 | Configuration error |
| 4 | Port not allowed |
| 255 | General error (invalid signal/port, suicide attempt, and all CLI usage errors) |

CLI usage errors — unknown flags, malformed option values, an out-of-range PID, and conflicting targets such as `--list --port 3000` — all exit with **255**, never 2. Exit code 2 means *only* "permission denied", so a caller can branch on it without mistaking a typo for a real permission failure. `--help` and `--version` exit 0.

A reader closing the output stream does not change the exit code: `safe-kill --list | head -1` exits 0 because the listing itself completed and only the reader went away. Other write failures (a full disk, for example) exit with **255**, since the result was genuinely lost. The exit code always describes the operation, never whether its description reached anyone — a kill that succeeded reports success even if the result line could not be printed. Rust ignores `SIGPIPE` at startup, so without this handling `println!` would panic and yield exit code 101, which is outside the documented set.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SAFE_KILL_ROOT_PID` | Override root PID for ancestry checks (`0`, `1` (init/launchd), or invalid values are ignored; the root PID itself is not killable) |
