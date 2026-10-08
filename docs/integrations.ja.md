# 連携

## Claude Code

Claude Code で `kill`/`pkill` コマンドの代わりに `safe-kill` を使用するための設定。

### 1. フック設定

`.claude/settings.json` に追加:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "if jq -r '.tool_input.command // empty' | grep -qE '(^|[;&|])[[:space:]]*(kill|pkill|killall)[[:space:]]'; then echo '🚫 safe-kill を使用: safe-kill <PID> または safe-kill --name <完全一致名>。シグナル指定は -s <signal>' >&2; exit 2; fi"
          }
        ]
      }
    ]
  }
}
```

Claude Code はツール呼び出しを JSON にして stdin でフックへ渡すので、フックは [jq](https://jqlang.org/) でコマンド (`.tool_input.command`) を取り出します。jq が必要です。Claude Code は `TOOL_INPUT` という環境変数を設定しないため、`$TOOL_INPUT` を読むフックは空文字列しか受け取れず、何もブロックしません。`kill`/`pkill`/`killall` コマンドが検出されると、フックがメッセージを stderr に出力し、終了コード 2 でツール呼び出しをブロックします。メッセージは Claude に表示されます。

このリポジトリを clone してあれば、`make install-hooks` がこのフックを 1 行にまとめたものと、残りの設定手順を表示します。

### 2. CLAUDE.md への記載

`CLAUDE.md` に追加:

```markdown
## プロセス管理ルール

- `kill`、`pkill`、`killall` を直接使用しないでください。安全のため制限されています。
- プロセスを終了するには `safe-kill <PID>`、`safe-kill --name <プロセス名>`、または `safe-kill --port <ポート>` を使用してください。
- `safe-kill` はターゲットプロセスがセッションの子孫であることを自動的に検証します。
- `safe-kill` が失敗した場合、そのプロセスはあなたの管理下にない可能性があります。

### 使用例
- テストサーバーを終了: `safe-kill --name node`
- ポート3000を使用するプロセスを終了: `safe-kill --port 3000`
- スタックしたプロセスを強制終了: `safe-kill -s 9 <PID>`
- 終了対象をプレビュー: `safe-kill --name python --dry-run`
```

### 3. 権限ルール (任意)

Claude が `safe-kill` を権限の確認なしで実行できるようにするには、`.claude/settings.json` で許可します。`Bash(safe-kill *)` は引数付きの `safe-kill` にも、引数なしの `safe-kill` にも一致します。Claude Code の中の `/permissions` ダイアログからルールを足すこともできます。

```json
{
  "permissions": {
    "allow": ["Bash(safe-kill *)"]
  }
}
```
