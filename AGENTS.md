# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

safe-kill は AI エージェント向けの安全なプロセス終了 CLI ツール。ancestry-based access control により、セッションの子孫プロセスのみを終了可能にする。Rust 1.70+ / macOS・Linux 対応。

## Commands

```bash
# ビルド
make build              # デバッグビルド
make release            # リリースビルド
make install            # /usr/local/bin にインストール

# テスト
make test               # 全テスト実行 (unit 263 + integration 38 + E2E 54)
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
2. **Denylist**: システムプロセスは常に保護
3. **Ancestry検証**: セッションの子孫のみ kill 可能
4. **Allowlist**: 信頼プロセスは ancestry チェックをバイパス

### Port-based killing の特殊性

`--port` は ancestry チェックをバイパスする（孤立した開発サーバー終了用途）。ただし `config.toml` の `[allowed_ports]` で明示的に許可されたポートのみ。未設定時は `--port` オプション自体が無効。

## Key Modules

| Module | Role |
|--------|------|
| `policy.rs` | Kill 許可判定のオーケストレーション。`KillPermission` enum を返す |
| `ancestry.rs` | プロセスツリー検証。`SAFE_KILL_ROOT_PID` env or grandparent をルートとする |
| `killer.rs` | シグナル送信と結果追跡。dry-run 対応 |
| `config.rs` | `~/.config/safe-kill/config.toml` の読み込み。OS別デフォルト denylist |
| `signal.rs` | Unix シグナル解析。名前/番号両対応、macOS/Linux でシグナル番号が異なる点を吸収 |
| `port.rs` | netstat2 による port→PID 解決 |
| `init.rs` | `safe-kill init` で config.toml を生成 |
| `error.rs` | thiserror ベースのエラー型と終了コード (0/1/2/3/4/255) |

## Versioning

YY.M.COUNTER 形式（例: 26.1.105）。リリースは GitHub Actions の workflow_dispatch で実行。

## Testing Notes

- E2E テストは `assert_cmd` を使用し、実際のバイナリを実行する
- 統合テストは実プロセスツリーを使ったテスト
- ancestry テストでは `SAFE_KILL_ROOT_PID` 環境変数でルート PID を制御可能
