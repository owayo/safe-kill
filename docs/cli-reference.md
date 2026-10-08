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

`--name` matches the process name the OS reports exactly: the executable's file name on macOS, the kernel's `comm` (truncated to 15 bytes) on Linux — see [Process Names](configuration.md#process-names). It does not perform substring or pattern matching, so on Linux a name longer than 15 bytes never matches; pass its first 15 bytes instead.

When multiple processes match `--name`, results are processed and displayed in ascending PID order so repeated runs stay stable.

`--port` targets TCP sockets only when they are in `LISTEN` state. Established TCP client sockets with the same local port are ignored. UDP has no connection state, so UDP matches use the local port. Port `0` is always rejected because it is an OS auto-assignment sentinel, not a kill target. The port must be listed in `[allowed_ports]` of the configuration file; without that table, `--port` is disabled.

For `--name` and `--port` dry runs, batch summaries use `would kill` so preview output is not mistaken for an actual termination.

## Error Handling

If a process matched policy checks but disappeared before signal delivery, or the OS rejected the signal, `safe-kill` returns the original runtime error such as `ProcessNotFound` or `PermissionDenied` instead of collapsing it into `NoKillableTarget`. A target that exits while the pre-kill ancestry re-check runs is reported as `ProcessNotFound` (exit 1), not as `NotDescendant`.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | A specified target was not found (PID not found, no name match, no process on allowed port, or no killable match) |
| 2 | Permission denied |
| 3 | Configuration error |
| 4 | Port not allowed |
| 255 | General error (invalid signal/port, suicide attempt, and all CLI usage errors) |

CLI usage errors — unknown flags, malformed option values, an out-of-range PID, a missing target (no `PID`, `--name`, `--port`, or `--list`, e.g. `safe-kill`, `safe-kill --dry-run`, or an empty unquoted `$PID`), and conflicting targets such as `--list --port 3000` — all exit with **255**, never 1 or 2. Exit code 1 is reserved for a target that was specified but not found, so a caller does not mistake a forgotten argument for "the process is already gone". Exit code 2 means *only* "permission denied", so a caller can branch on it without mistaking a typo for a real permission failure. `--help` and `--version` exit 0.

A reader closing the output stream does not change the exit code: `safe-kill --list | head -1` exits 0 because the listing itself completed and only the reader went away. Other write failures (a full disk or a file-size limit, for example) depend on what the output is for. For `--list` and every `--dry-run`, the output is the product, so `safe-kill` exits with **255** (`safe-kill: failed to write to stdout: ...`). After an actual kill (PID, `--name`, or `--port`) or `init`, the operation has already happened: the exit code stays 0 and stderr gets one warning line (`safe-kill: warning: operation completed, but failed to write to stdout: ...`), because a non-zero code would make a caller retry or escalate a kill that succeeded. The exit code always describes the operation, never whether its description reached anyone. Rust ignores `SIGPIPE` at startup, so without this handling `println!` would panic and yield exit code 101, which is outside the documented set.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SAFE_KILL_ROOT_PID` | Override root PID for ancestry checks (`0`, `1` (init/launchd), or invalid values are ignored; the root PID itself is not killable) |

Without `SAFE_KILL_ROOT_PID`, the trust root is detected automatically. When the direct parent of `safe-kill` is a shell (`sh`, `bash`, `zsh`, `dash`, `fish`, …), the root is the shell's parent — the agent that ran the shell. Otherwise the root is the direct parent: a shell that `exec`s its last command (`sh -c 'safe-kill …'`) disappears, leaving the agent itself as the parent. PID 1 and processes on the built-in denylist (such as `systemd`) are never chosen; detection falls back to the parent, then to `safe-kill` itself. If you run `safe-kill` through a wrapper such as `timeout`, `make`, or an npm script, the wrapper becomes the parent and fewer processes are killable; set `SAFE_KILL_ROOT_PID` to the agent's PID (for example `os.getpid()` in the agent process) in that case. Details: [architecture.md](architecture.md) (Safety Layers 7).
