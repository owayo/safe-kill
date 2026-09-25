# Configuration

`safe-kill` reads one configuration file, `~/.config/safe-kill/config.toml`. There is no project-level configuration and no option to point at another file. Without the file, the built-in defaults apply: no allowlist, the default denylist below, and `--port` disabled.

## Settings

```toml
# Processes that bypass ancestry checks (use with caution)
[allowlist]
processes = ["my-trusted-app", "next-server"]

# Additional processes that can never be killed (takes precedence over allowlist)
# Built-in system protections stay enabled even when you customize this list.
[denylist]
processes = ["postgres"]

# Allowed ports for --port option
# If not specified, --port option is disabled (no ports can be killed)
# Valid values are 1-65535. Port 0 is always rejected even if configured.
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
| `[allowed_ports]` | `ports` | Ports that `--port` may target, as single ports (`"8080"`) or ranges (`"3000-3010"`). Port `0` is rejected even inside a range; use `1-65535` for the full valid range |

`--port` kills bypass the ancestry check for the configured ports, which is useful for orphaned dev servers started in another terminal. Suicide prevention, the denylist, and the protection of the trust root and PID 1 still apply.

## Default Denylist

The following system processes are protected by default:

**macOS**: `launchd`, `kernel_task`, `WindowServer`, `loginwindow`, `Finder`, `Dock`, `SystemUIServer`

**Linux**: `systemd`, `init`, `kthreadd`, `dbus-daemon`, `gnome-shell`, `Xorg`, `sshd`

User-defined `[denylist]` entries are appended to this built-in protection set. Customizing the list does not remove system safeguards.

## How the File Is Loaded

If `config.toml` exists but cannot be accessed, read, or parsed, or if it contains unknown fields, kill/list commands fail with a configuration error instead of falling back to partial defaults. Regular files and symlinks that resolve to regular files are accepted. Dangling symlinks and paths that resolve to directories, FIFOs, or devices are rejected before reading; this prevents a missing managed config from silently disabling custom protections and avoids blocking or unbounded reads from special files.

## Creating the File with `safe-kill init`

`safe-kill init` writes a commented starter `config.toml`: `[allowed_ports]` is enabled with the ports shown above, and `[allowlist]` and `[denylist]` are left as commented-out examples.

If the config file already exists, `init` prompts for confirmation before overwriting (use `--force` to skip the prompt). Declining the prompt leaves the existing file unchanged and exits successfully (code 0); only an actual write failure is reported as a configuration error (code 3).

Symlinked config files (the common dotfiles pattern, `~/.config/safe-kill/config.toml -> ~/dotfiles/safe-kill.toml`) keep working: `init` follows the link and updates the real file, leaving the symlink intact. Because the file it rewrites is *not* the path you typed, both the confirmation prompt and the success line disclose the resolved target. A **dangling** symlink is refused outright (code 3, even with `--force`) rather than silently creating a file at the link target.

`init` accepts only regular files (or symlinks that resolve to regular files). Directories, FIFOs, devices, and symlinks to those special files are rejected before opening, so `--force` cannot block on a FIFO or write to a device. The validated parent directory is pinned by file descriptor after checking its device/inode, and the destination is opened relative to that descriptor with non-blocking, no-symlink-following flags. The opened file's device/inode is also checked before truncation. A replacement before open therefore fails closed; after open, the pinned descriptor prevents a later path change from redirecting the write to another file.

For a new configuration, `init` creates `~/.config/safe-kill` with mode `0700` and `config.toml` with mode `0600`. These are explicit upper bounds, so a permissive caller `umask` cannot make the authorization settings writable by another user; a stricter `umask` remains effective.
