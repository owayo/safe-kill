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
make test               # 全テスト実行 (lib 396 + bin 34 + E2E 85 + integration 78)
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

1. **自殺防止**: 自プロセス・親プロセスの kill 禁止。ポリシー判定時の早期拒否（構築時スナップショット）に加え、kill 直前に最新の親 PID を OS から再取得して再検証する（`verify_not_suicide_before_kill`）。判定～kill 間の再ペアレント（親の入れ替わり）に対して fail-closed であり、親 PID が不明な場合も安全側に倒して拒否する
2. **PID検証**: `0` や `i32::MAX` を超える PID は拒否
3. **Denylist**: システムプロセスは常に保護
4. **PID 1 保護**: PID 1（init/launchd 相当）自体は常に kill 拒否する。コンテナ環境では PID 1 が `node` / `python` など非標準プロセスとして既定 denylist 外になることがあり、allowlist 一致やポート kill 経路で巻き添えで終了させるとコンテナ全体が落ちるため、ancestry / allowlist 判定より手前で fail-closed する（`can_kill` と `can_kill_for_port` の両方）
5. **Root PID保護**: `SAFE_KILL_ROOT_PID` または自動検出された信頼ルート自体は kill 禁止
6. **Allowlist**: 信頼プロセスは ancestry チェックをバイパス
7. **Ancestry検証**: セッションの子孫のみ kill 可能。信頼ルートは PID 1（init/launchd）を採用せず、自動検出で祖父が PID 1 になる場合（コンテナ・systemd サービス配下など）は親→現在プロセスへフォールバックして fail-closed に倒す（PID 1 をルートにすると、親チェーンが init に到達する全プロセスが子孫扱いになる fail-open を防止）。公開 API の `is_descendant_of` も `ancestor_pid` が 0/1 なら子孫判定を拒否する。さらに `AncestryChecker` は構築時に信頼ルートの初期 identity（`pid + start_time + name`）を保持し、すべての子孫判定 (`is_descendant` / `is_descendant_of` / `is_descendant_fresh`) で identity 同一性を検証する。識別子検証と子孫判定は同一 snapshot 上で行うことで両者の間の TOCTOU 窓を最小化する。`refresh()` で identity 不一致を検出した場合は `root_identity` を `None` 化して以後 fail-closed に倒す（初期 identity を更新しないことで、PID 再利用後のプロセスを信頼ルートとして受け入れない）
8. **PID再利用検出 (TOCTOU 緩和)**: ポリシー判定後、kill 直前に最新のプロセス情報を OS から取得し、`pid + start_time + name` の同一性を再検証する。判定時と異なるプロセスへ PID が再利用されていれば `ProcessNotFound` として fail-closed する。`start_time` は秒精度のため、同一秒内の同名プロセスへの再利用は検出できない（実用上は極めて稀）。完全な保護には Linux の `pidfd_open` + `pidfd_send_signal` が必要だが、現状は窓を大幅に狭めている
9. **kill 直前の ancestry 再評価**: PID/名前指定で `KillPermission::Allowed`（ancestry 経由）で許可されたプロセスは、kill 直前に新しい `ProcessInfoProvider` snapshot で root identity と子孫判定をやり直す（`is_descendant_fresh`）。判定～kill 間に対象プロセスが再ペアレントされて信頼ルート外に出たケースを `NotDescendant` として fail-closed する。`AllowedByAllowlist`（allowlist は ancestry をバイパスする設計）と `--port` kill では設計上 ancestry を適用しないため再評価をバイパスする。`FinalAncestryCheck::try_from_permission` で `Required` / `Bypassed` の区別を型レベルで表現し、拒否系の permission が紛れ込んだ場合は `Err(SystemError)` で fail-loud にする（呼び出し漏れの早期検出）
10. **ポート保持の再検証**: `--port` 指定 kill では、判定～kill の間に対象 PID が当該ポートを離していないかを再取得した保持者集合と照合する。離していれば `NoProcessOnPort` として fail-closed する（既に意図したサービスは停止しているため余計な kill を抑止する）
11. **表示時の端末制御文字サニタイズ**: `--list` / kill 結果表示 / エラー出力（stderr の `safe-kill: ...`）のすべての経路で、OS から取得したプロセス名・コマンドライン引数・エラーメッセージ本文に含まれる ANSI escape（画面消去・OSC 等）・改行・タブ・その他制御文字を `\xHH` 等のエスケープ表記に置き換えてから出力する（`main.rs::sanitize_terminal`）。`KillResult::failure` の `message` には `NotDescendant(pid, name)` や `Denylisted(name)` のようにプロセス名を含むエラー文字列が保持されるため、`name` だけでなく `message` 側もサニタイズする。stderr へ流れる `SafeKillError` の Display 結果（プロセス名を含むことがある）も `e.to_string()` を介して同様にサニタイズしてから表示する。攻撃者が任意の引数でプロセスを起動して表示行を上書きする偽装や、端末状態の改ざんを防ぐ。サニタイズは `truncate` より前に行い、escape sequence の途中で切られて端末状態が残ることも防ぐ

### Port-based killing の特殊性

`--port` は ancestry チェックをバイパスする（孤立した開発サーバー終了用途）。ただし `config.toml` の `[allowed_ports]` で明示的に許可されたポートのみ。未設定時は `--port` オプション自体が無効。ポート `0` は OS の自動割り当て用の特殊値なので、設定に含まれていても常に拒否する。信頼ルート PID 自体はポート指定でも保護する。TCP は LISTEN 状態のソケットのみ対象にし、ESTABLISHED などの接続済みクライアントソケットは対象外。UDP は状態を持たないためローカルポート一致で対象にする。プロセス名解決に失敗した PID は `pid:<pid>` 形式のプレースホルダ名でフォールバックされるが、この名前はあくまで表示用であり、ポリシー判定は fresh なプロセス情報が取れない時点で `ProcessNotFound` として fail-closed する（denylist のバイパス防止）。さらに kill 直前に対象ポートの保持者集合を再取得し、判定時の PID/プロトコルが含まれなければ `NoProcessOnPort` として fail-closed する（判定～kill 間にポートを離した場合の追加防御）。

## Key Modules

| Module | Role |
|--------|------|
| `cli.rs` | clap ベースの CLI 定義と実行モード判定。`init` サブコマンドと通常 kill オプションの排他も担う |
| `policy.rs` | Kill 許可判定のオーケストレーション。root PID 自体の保護、PID 1 自体の保護（コンテナ環境での巻き添え防止、`can_kill` / `can_kill_for_port` の両経路で fail-closed）、既定 denylist の強制合流、`KillPermission` enum の返却（拒否判定→`SafeKillError` 変換は `KillPermission::to_error` に集約）、kill 直前の最終安全検証 (`verify_final_safety_before_kill` = 自殺防止の再確認 `verify_not_suicide_before_kill` + ancestry の fresh 再評価 (Required 時) + PID 再利用検証 `verify_identity_before_kill`) も担う。`FinalAncestryCheck` enum で再評価の Required/Bypassed を型レベルに固定し、`try_from_permission` で拒否系を fail-loud に拒絶する |
| `ancestry.rs` | プロセスツリー検証。`SAFE_KILL_ROOT_PID`（0/1/無効値は無視）または祖父プロセスをルートとする。PID 1（init/launchd）は信頼ルートにできず、祖父が PID 1 等で不適格なら親→現在プロセスへフォールバックする（fail-closed）。構築時に信頼ルートの初期 identity を `root_identity: Option<ProcessInfo>` で保持し、`root_identity_matches_in_provider` で同一 snapshot 内に identity 検証を組み込む。`is_descendant` / `is_descendant_of`（ancestor が root_pid 時）/ `is_descendant_fresh` の各経路で identity 整合性を fail-closed 検証する。`is_descendant_fresh` は新規 snapshot で identity と ancestry を同時検証して TOCTOU 窓を最小化。`refresh()` は identity を更新せず、不一致時に `root_identity = None` にして以後 fail-closed に倒す（PID 再利用後のプロセスを信頼ルートにしない）。木探索本体は `is_descendant_of_with_provider` に分離し、任意 provider snapshot に対して再利用可能 |
| `killer.rs` | シグナル送信と結果追跡。dry-run 対応。`KillResult` に元の `SafeKillError` を保持する |
| `config.rs` | `~/.config/safe-kill/config.toml` の読み込み。CLI 実行ではアクセス不可・解析不能・未知フィールドを設定エラーとして fail-closed にし、OS別デフォルト denylist とユーザー denylist を合流 |
| `signal.rs` | Unix シグナル解析と送信。名前/番号両対応、macOS/Linux のプラットフォーム固有番号のみ受付、危険 PID 値の拒否 |
| `port.rs` | netstat2 による port→PID 解決。TCP は LISTEN のみ、UDP はローカルポート一致 |
| `process_info.rs` | sysinfo ベースのプロセス一覧取得とプロセス名の完全一致検索。`ProcessInfo.start_time` で PID 再利用を検出可能。`fetch_fresh(pid)` は新しい `System` を作って指定 PID のみ refresh する TOCTOU 検証専用関数。結果は PID 昇順で安定化 |
| `init.rs` | `safe-kill init` で config.toml を生成。既存ファイルの上書き確認を行い、ユーザーが拒否した場合は作成失敗（終了コード3）ではなく正常な no-op（終了コード0、`InitOutcome::SkippedExisting`）として扱う |
| `error.rs` | thiserror ベースのエラー型と終了コード (0/1/2/3/4/255) |
| `main.rs` | CLI のエントリポイント。実行モードごとの分岐、終了コード変換、表示出力を担う。`sanitize_terminal` で OS から取得したプロセス名・コマンドライン引数・エラーメッセージ本文の端末制御文字（ANSI escape / 改行 / 制御文字）を `\xHH` 表記にエスケープしてから `truncate` する。`--list` 出力、kill 結果表示（`print_kill_result` の `name` と `message` の両方）、`main()` での stderr エラー出力（`eprintln!("safe-kill: {}", sanitize_terminal(&e.to_string()))`）のすべてでサニタイズ済みの文字列のみが端末へ流れるため、悪意ある起動引数を持つプロセスでも偽装や端末状態改ざんが起きない |

## Versioning

YY.M.COUNTER 形式（例: 26.1.105）。リリースは GitHub Actions の workflow_dispatch で実行。

## Testing Notes

- E2E テストは `assert_cmd` を使用し、実際のバイナリを実行する
- 統合テストは実プロセスツリーを使ったテスト
- ancestry テストでは `SAFE_KILL_ROOT_PID` 環境変数でルート PID を制御可能（`0`・`1` や無効値は無視、root PID 自体は kill 不可）
