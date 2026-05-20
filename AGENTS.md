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
make test               # 全テスト実行 (lib 346 + bin 26 + E2E 83 + integration 78)
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
4. **Root PID保護**: `SAFE_KILL_ROOT_PID` または自動検出された信頼ルート自体は kill 禁止
5. **Allowlist**: 信頼プロセスは ancestry チェックをバイパス
6. **Ancestry検証**: セッションの子孫のみ kill 可能
7. **PID再利用検出 (TOCTOU 緩和)**: ポリシー判定後、kill 直前に最新のプロセス情報を OS から取得し、`pid + start_time + name` の同一性を再検証する。判定時と異なるプロセスへ PID が再利用されていれば `ProcessNotFound` として fail-closed する。`start_time` は秒精度のため、同一秒内の同名プロセスへの再利用は検出できない（実用上は極めて稀）。完全な保護には Linux の `pidfd_open` + `pidfd_send_signal` が必要だが、現状は窓を大幅に狭めている
8. **ポート保持の再検証**: `--port` 指定 kill では、判定～kill の間に対象 PID が当該ポートを離していないかを再取得した保持者集合と照合する。離していれば `NoProcessOnPort` として fail-closed する（既に意図したサービスは停止しているため余計な kill を抑止する）

### Port-based killing の特殊性

`--port` は ancestry チェックをバイパスする（孤立した開発サーバー終了用途）。ただし `config.toml` の `[allowed_ports]` で明示的に許可されたポートのみ。未設定時は `--port` オプション自体が無効。ポート `0` は OS の自動割り当て用の特殊値なので、設定に含まれていても常に拒否する。信頼ルート PID 自体はポート指定でも保護する。TCP は LISTEN 状態のソケットのみ対象にし、ESTABLISHED などの接続済みクライアントソケットは対象外。UDP は状態を持たないためローカルポート一致で対象にする。プロセス名解決に失敗した PID は `pid:<pid>` 形式のプレースホルダ名でフォールバックされるが、この名前はあくまで表示用であり、ポリシー判定は fresh なプロセス情報が取れない時点で `ProcessNotFound` として fail-closed する（denylist のバイパス防止）。さらに kill 直前に対象ポートの保持者集合を再取得し、判定時の PID/プロトコルが含まれなければ `NoProcessOnPort` として fail-closed する（判定～kill 間にポートを離した場合の追加防御）。

## Key Modules

| Module | Role |
|--------|------|
| `cli.rs` | clap ベースの CLI 定義と実行モード判定。`init` サブコマンドと通常 kill オプションの排他も担う |
| `policy.rs` | Kill 許可判定のオーケストレーション。root PID 自体の保護、既定 denylist の強制合流、`KillPermission` enum の返却、kill 直前の PID 再利用検証 (`verify_identity_before_kill`) も担う |
| `ancestry.rs` | プロセスツリー検証。`SAFE_KILL_ROOT_PID`（0/無効値は無視）または祖父プロセスをルートとする |
| `killer.rs` | シグナル送信と結果追跡。dry-run 対応。`KillResult` に元の `SafeKillError` を保持する |
| `config.rs` | `~/.config/safe-kill/config.toml` の読み込み。CLI 実行ではアクセス不可・解析不能・未知フィールドを設定エラーとして fail-closed にし、OS別デフォルト denylist とユーザー denylist を合流 |
| `signal.rs` | Unix シグナル解析と送信。名前/番号両対応、macOS/Linux のプラットフォーム固有番号のみ受付、危険 PID 値の拒否 |
| `port.rs` | netstat2 による port→PID 解決。TCP は LISTEN のみ、UDP はローカルポート一致 |
| `process_info.rs` | sysinfo ベースのプロセス一覧取得とプロセス名の完全一致検索。`ProcessInfo.start_time` で PID 再利用を検出可能。`fetch_fresh(pid)` は新しい `System` を作って指定 PID のみ refresh する TOCTOU 検証専用関数。結果は PID 昇順で安定化 |
| `init.rs` | `safe-kill init` で config.toml を生成 |
| `error.rs` | thiserror ベースのエラー型と終了コード (0/1/2/3/4/255) |

## Versioning

YY.M.COUNTER 形式（例: 26.1.105）。リリースは GitHub Actions の workflow_dispatch で実行。

## Testing Notes

- E2E テストは `assert_cmd` を使用し、実際のバイナリを実行する
- 統合テストは実プロセスツリーを使ったテスト
- ancestry テストでは `SAFE_KILL_ROOT_PID` 環境変数でルート PID を制御可能（`0` や無効値は無視、root PID 自体は kill 不可）
