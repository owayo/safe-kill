# Configuration

`safe-kill` reads one configuration file, `~/.config/safe-kill/config.toml`. There is no project-level configuration and no option to point at another file. Without the file, the built-in defaults apply: no allowlist, the default denylist below, and `--port` disabled.

## Settings

```toml
# Processes that bypass ancestry checks (use with caution)
[allowlist]
processes = ["trusted-worker"]

# Additional processes that can never be killed (takes precedence over allowlist)
# Built-in system protections stay enabled even when you customize this list.
[denylist]
processes = ["postgres"]

# Allowed ports for --port option
# If not specified, --port option is disabled (no ports can be killed)
# Valid values are 1-65535. An entry that is not a valid port or range (including
# a range that contains 0) is a configuration error.
[allowed_ports]
ports = ["1420", "3000-3010", "5173", "8080"]
#   - 1420: Tauri dev server
#   - 3000-3010: Node.js dev servers
#   - 5173: Vite dev server
#   - 8080: HTTP alternative port
```

| Table | Key | Meaning |
|-------|-----|---------|
| `[allowlist]` | `processes` | Process names that skip the ancestry check. The denylist, the trust root, PID 1, and the suicide check still apply |
| `[denylist]` | `processes` | Process names that can never be killed, added to the default denylist |
| `[allowed_ports]` | `ports` | Ports that `--port` may target, as single ports (`"8080"`) or ranges (`"START-END"` with `1 <= START <= END <= 65535`, such as `"3000-3010"`). An entry that does not parse — a range that contains `0` (`"0-3010"`), a reversed range, a value above `65535`, or a dash other than ASCII `-` — makes the whole file invalid (configuration error, exit code 3) instead of being skipped. Use `1-65535` for the full valid range |

`--port` kills bypass the ancestry check for the configured ports, which is useful for orphaned dev servers started in another terminal. Suicide prevention, the denylist, and the protection of the trust root and PID 1 still apply.

## Process Names

`[allowlist]`, `[denylist]`, and `--name` compare against the process name the OS reports, not a package name or a command-line title:

- **macOS**: the file name of the executable. A Next.js dev server is `node`, even though it sets its title to `next-server (v15…)`.
- **Linux**: the kernel's `comm`, truncated to the first 15 bytes. A program can rename it (Node.js's `process.title` does), so the same server shows up as `next-server (v1`.

For a process that `safe-kill --list` shows, copy its NAME column. On Linux you can also read the name with `ps -o comm= -p <PID>`.

The allowlist and `--name` require an exact match. The allowlist bypasses the ancestry check for every process with that name, so avoid generic names such as `node`. On Linux, a denylist entry longer than 15 bytes also matches its first 15 bytes (`gnome-terminal-server` protects `gnome-terminal-`), so long names stay protected; any other process sharing those 15 bytes is protected too, which errs on the safe side.

## Default Denylist

The following system processes are protected by default:

**macOS**: `launchd`, `kernel_task`, `WindowServer`, `loginwindow`, `Finder`, `Dock`, `SystemUIServer`, `ControlCenter`

**Linux**: `systemd`, `init`, `kthreadd`, `dbus-daemon`, `gnome-shell`, `Xorg`, `sshd`

User-defined `[denylist]` entries are appended to this built-in protection set. Customizing the list does not remove system safeguards.

On macOS 12 and later, the AirPlay Receiver runs in `ControlCenter`, which listens on TCP ports 5000 and 7000. Port 5000 is also Flask's default, so with `5000` in `[allowed_ports]`, `safe-kill --port 5000` run after your own server has stopped would find `ControlCenter` instead. The default denylist refuses it; turn off the AirPlay Receiver in System Settings if you need those ports for development.

## How the File Is Loaded

If `config.toml` exists but cannot be accessed, read, or parsed, or if it contains unknown fields or an invalid `[allowed_ports]` entry, kill/list commands fail with a configuration error instead of falling back to partial defaults. Only a config path that does not exist at all falls back to the defaults; any other failure to reach it (a path component that is a regular file, a symlink loop, a permission error) is a configuration error. Regular files and symlinks that resolve to regular files are accepted. Dangling symlinks — the file itself or a directory above it — and paths that resolve to directories, FIFOs, or devices are rejected before reading; this prevents a missing managed config from silently disabling custom protections and avoids blocking or unbounded reads from special files.

The location comes from `HOME` (or the user database when `HOME` is unset or empty). If `HOME` is a relative path, such as `HOME='~'` left unexpanded, `safe-kill` stops with a configuration error (exit code 3), and `init` creates nothing. Resolving the path against the current directory would let the repository an agent happens to be working in supply an `[allowlist]` or `[allowed_ports]`.

## Creating the File with `safe-kill init`

`safe-kill init` writes a commented starter `config.toml`: `[allowed_ports]` is enabled with the ports shown above, and `[allowlist]` and `[denylist]` are left as commented-out examples.

If the config file already exists, `init` prompts for confirmation before overwriting (use `--force` to skip the prompt). Only `y` or `yes` (case-insensitive, surrounding whitespace ignored) overwrites the file. Any other answer — including an empty line, the end of input, and input that is not valid UTF-8 — declines: the existing file stays unchanged and `init` exits successfully (code 0). Failing to create or write the file, and refusing a dangling symlink or a special file, are configuration errors (code 3); if the prompt itself cannot be written, `init` stops without reading an answer (code 255).

Symlinked config files (the common dotfiles pattern, `~/.config/safe-kill/config.toml -> ~/dotfiles/safe-kill.toml`) keep working: `init` follows the link and updates the real file, leaving the symlink intact. Because the file it rewrites is *not* the path you typed, both the confirmation prompt and the success line disclose the resolved target. A **dangling** symlink is refused outright (code 3, even with `--force`) rather than silently creating a file at the link target.

`init` accepts only regular files (or symlinks that resolve to regular files). Directories, FIFOs, devices, and symlinks to those special files are rejected before opening, so `--force` cannot block on a FIFO or write to a device. The validated parent directory is pinned by file descriptor after checking its device/inode, and the destination is opened relative to that descriptor with non-blocking, no-symlink-following flags. The opened file's device/inode is also checked before truncation. A replacement before open therefore fails closed; after open, the pinned descriptor prevents a later path change from redirecting the write to another file.

For a new configuration, `init` creates `~/.config/safe-kill` with mode `0700` and `config.toml` with mode `0600`. These are explicit upper bounds, so a permissive caller `umask` cannot make the authorization settings writable by another user; a stricter `umask` remains effective.
