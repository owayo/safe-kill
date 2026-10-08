# Integrations

## Claude Code

Configure `safe-kill` as a safer alternative to `kill`/`pkill` commands in Claude Code.

### 1. Hook Configuration

Add to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "if jq -r '.tool_input.command // empty' | grep -qE '(^|[;&|])[[:space:]]*(kill|pkill|killall)[[:space:]]'; then echo '🚫 Use safe-kill instead: safe-kill <PID> or safe-kill --name <exact-name>. Use -s <signal> for signal.' >&2; exit 2; fi"
          }
        ]
      }
    ]
  }
}
```

Claude Code passes the tool call to the hook as JSON on stdin, so the hook reads the command with [jq](https://jqlang.org/) (`.tool_input.command`); jq must be installed. Claude Code does not set a `TOOL_INPUT` environment variable, so a hook that reads `$TOOL_INPUT` sees an empty string and never blocks anything. When a `kill`/`pkill`/`killall` command is detected, the hook outputs a message to stderr and exits with code 2, which blocks the tool call and shows the message to Claude.

From a clone of this repository, `make install-hooks` prints a one-line version of this hook together with the other setup steps.

### 2. CLAUDE.md Instructions

Add to your `CLAUDE.md`:

```markdown
## Process Management Rules

- Do NOT use `kill`, `pkill`, or `killall`. These are restricted for safety.
- Use `safe-kill <PID>`, `safe-kill --name <PROCESS_NAME>`, or `safe-kill --port <PORT>` to terminate processes.
- `safe-kill` will automatically verify that the target process is a child of your session.
- If `safe-kill` fails, the process is likely not owned by you.

### Examples
- Terminate a test server: `safe-kill --name node`
- Terminate a process using port 3000: `safe-kill --port 3000`
- Force kill a stuck process: `safe-kill -s 9 <PID>`
- Preview what would be killed: `safe-kill --name python --dry-run`
```

### 3. Permission Rule (Optional)

To let Claude run `safe-kill` without a permission prompt, allow it in `.claude/settings.json`. `Bash(safe-kill *)` matches `safe-kill` with any arguments, and `safe-kill` on its own. You can also add the rule from the `/permissions` dialog inside Claude Code.

```json
{
  "permissions": {
    "allow": ["Bash(safe-kill *)"]
  }
}
```
