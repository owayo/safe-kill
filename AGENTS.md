# AGENTS.md

このファイルは、このリポジトリで作業するエージェント向けのガイドです。

## Project Overview

safe-kill は AI エージェント向けの安全なプロセス終了 CLI ツール。ancestry-based access control により、セッションの子孫プロセスのみを終了可能にする。Rust 1.85+ / macOS・Linux 対応。

## Commands

```bash
# ビルド
make build              # デバッグビルド
make release            # リリースビルド
make install            # /usr/local/bin にインストール

# テスト
make test               # 全テスト実行 (lib 287 + bin 26 + E2E 65 + integration 65)
make test-e2e           # E2Eテストのみ
make test-integration   # 統合テストのみ
cargo test ancestry     # 特定モジュールのテスト
cargo test test_is_suicide_self  # 特定テスト名で実行

# リント・フォーマット
make fmt                # cargo fmt
make check              # cargo clippy -- -D warnings && cargo check
```

## Architecture

```
CLI Parser (cli.rs) → Policy Engine (policy.rs) → Killer (killer.rs) → Signal Sender (signal.rs)
                            ↓
                    Ancestry Checker (ancestry.rs) + Config (config.rs) + Port Detector (port.rs)
                            ↓
                    Process Info Provider (process_info.rs)
```

### Safety Layers（優先順）

1. **自殺防止**: 自プロセス・親プロセスの kill 禁止
2. **PID検証**: `0` や `i32::MAX` を超える PID は拒否
3. **Denylist**: システムプロセスは常に保護
4. **Ancestry検証**: セッションの子孫のみ kill 可能
5. **Allowlist**: 信頼プロセスは ancestry チェックをバイパス

### Port-based killing の特殊性

`--port` は ancestry チェックをバイパスする（孤立した開発サーバー終了用途）。ただし `config.toml` の `[allowed_ports]` で明示的に許可されたポートのみ。未設定時は `--port` オプション自体が無効。

## Key Modules

| Module | Role |
|--------|------|
| `policy.rs` | Kill 許可判定のオーケストレーション。`KillPermission` enum を返す |
| `ancestry.rs` | プロセスツリー検証。`SAFE_KILL_ROOT_PID`（0/無効値は無視）または祖父プロセスをルートとする |
| `killer.rs` | シグナル送信と結果追跡。dry-run 対応。`KillResult` に元の `SafeKillError` を保持する |
| `config.rs` | `~/.config/safe-kill/config.toml` の読み込み。OS別デフォルト denylist とユーザー denylist を合流 |
| `signal.rs` | Unix シグナル解析と送信。名前/番号両対応、macOS/Linux の番号差異吸収、危険 PID 値の拒否 |
| `port.rs` | netstat2 による port→PID 解決 |
| `process_info.rs` | sysinfo ベースのプロセス一覧取得とプロセス名の完全一致検索 |
| `init.rs` | `safe-kill init` で config.toml を生成 |
| `error.rs` | thiserror ベースのエラー型と終了コード (0/1/2/3/4/255) |

## Versioning

YY.M.COUNTER 形式（例: 26.1.105）。リリースは GitHub Actions の workflow_dispatch で実行。

## Testing Notes

- E2E テストは `assert_cmd` を使用し、実際のバイナリを実行する
- 統合テストは実プロセスツリーを使ったテスト
- ancestry テストでは `SAFE_KILL_ROOT_PID` 環境変数でルート PID を制御可能（`0` や無効値は無視）
