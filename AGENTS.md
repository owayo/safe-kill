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
make test               # 全テスト実行 (lib 425 + bin 35 + E2E 90 + integration 79)
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
2. **PID検証**: `0` や `i32::MAX` を超える PID は拒否。kill 直前の fresh なプロセス情報取得 (`ProcessInfoProvider::fetch_fresh`) でも同じ境界を公開 API 側で拒否し、OS や `sysinfo` の特殊 PID 解釈に依存しない
3. **Denylist**: システムプロセスは常に保護
4. **PID 1 保護**: PID 1（init/launchd 相当）自体は常に kill 拒否する。コンテナ環境では PID 1 が `node` / `python` など非標準プロセスとして既定 denylist 外になることがあり、allowlist 一致やポート kill 経路で巻き添えで終了させるとコンテナ全体が落ちるため、ancestry / allowlist 判定より手前で fail-closed する（`can_kill` と `can_kill_for_port` の両方）
5. **Root PID保護**: `SAFE_KILL_ROOT_PID` または自動検出された信頼ルート自体は kill 禁止
6. **Allowlist**: 信頼プロセスは ancestry チェックをバイパス
7. **Ancestry検証**: セッションの子孫のみ kill 可能。信頼ルートは PID 1（init/launchd）を採用せず、自動検出で祖父が PID 1 になる場合（コンテナ・systemd サービス配下など）は親→現在プロセスへフォールバックして fail-closed に倒す（PID 1 をルートにすると、親チェーンが init に到達する全プロセスが子孫扱いになる fail-open を防止）。公開 API の `is_descendant_of` も `ancestor_pid` が 0/1 なら子孫判定を拒否する。木探索本体は `target_pid == ancestor_pid` の同一 PID ケースでも、対象 PID が snapshot に存在しなければ子孫扱いせず fail-closed に倒す。さらに `AncestryChecker` は構築時に信頼ルートの初期 identity（`pid + start_time + name`）を保持し、すべての子孫判定 (`is_descendant` / `is_descendant_of` / `is_descendant_fresh`) で identity 同一性を検証する。識別子検証と子孫判定は同一 snapshot 上で行うことで両者の間の TOCTOU 窓を最小化する。`refresh()` で identity 不一致を検出した場合は `root_identity` を `None` 化して以後 fail-closed に倒す（初期 identity を更新しないことで、PID 再利用後のプロセスを信頼ルートとして受け入れない）
8. **PID再利用検出 (TOCTOU 緩和)**: ポリシー判定後、kill 直前に最新のプロセス情報を OS から取得し、`pid + start_time + name` の同一性を再検証する。判定時と異なるプロセスへ PID が再利用されていれば `ProcessNotFound` として fail-closed する。`start_time` は秒精度のため、同一秒内の同名プロセスへの再利用は検出できない（実用上は極めて稀）。完全な保護には Linux の `pidfd_open` + `pidfd_send_signal` が必要だが、現状は窓を大幅に狭めている
9. **kill 直前の ancestry 再評価**: PID/名前指定で `KillPermission::Allowed`（ancestry 経由）で許可されたプロセスは、kill 直前に新しい `ProcessInfoProvider` snapshot で root identity と子孫判定をやり直す（`is_descendant_fresh`）。判定～kill 間に対象プロセスが再ペアレントされて信頼ルート外に出たケースを `NotDescendant` として fail-closed する。`AllowedByAllowlist`（allowlist は ancestry をバイパスする設計）と `--port` kill では設計上 ancestry を適用しないため再評価をバイパスする。`FinalAncestryCheck::try_from_permission` で `Required` / `Bypassed` の区別を型レベルで表現し、拒否系の permission が紛れ込んだ場合は `Err(SystemError)` で fail-loud にする（呼び出し漏れの早期検出）
10. **ポート保持の再検証**: `--port` 指定 kill では、判定～kill の間に対象 PID が当該ポートを離していないかを再取得した保持者集合と照合する。離していれば `NoProcessOnPort` として fail-closed する（既に意図したサービスは停止しているため余計な kill を抑止する）
11. **表示時の端末制御文字サニタイズ**: `--list` / kill 結果表示 / エラー出力（stderr の `safe-kill: ...`）/ `safe-kill init` のパス表示 / 設定読み込み警告の各経路で、OS から取得したプロセス名・コマンドライン引数・エラーメッセージ本文・設定パスに含まれる ANSI escape（画面消去・OSC 等）・改行・タブ・その他制御文字・Unicode 17.0 の general category `Cf` に属する全 170 個の format 制御文字（双方向テキスト制御等）を `\xHH` または `\u{HHHH}` のエスケープ表記に置き換えてから出力する（`terminal.rs::sanitize_terminal` / `sanitize_path`）。`KillResult::failure` の `message` には `NotDescendant(pid, name)` や `Denylisted(name)` のようにプロセス名を含むエラー文字列が保持されるため、`name` だけでなく `message` 側もサニタイズする。stderr へ流れる `SafeKillError` の Display 結果（プロセス名を含むことがある）も `e.to_string()` を介して同様にサニタイズしてから表示する。攻撃者が任意の引数やパスで表示行を上書きする偽装、双方向制御文字による表示順偽装、端末状態の改ざんを防ぐ。サニタイズは `truncate` より前に行い、escape sequence の途中で切られて端末状態が残ることも防ぐ。エスケープ導入文字である `\` 自身も `\\` に置き換える（これを省くと変換が非単射になり、実際に ESC を含むプロセス名と、リテラルで `\x1B[2J` という名前を持つ別プロセスの表示が完全に一致してしまい、どちらが本当に制御文字を含むのか読み手が判別できなくなる）

12. **スレッド（TID）除外による denylist バイパス防止**: `sysinfo` の `refresh_processes` は既定で `with_tasks()` を含み、Linux では `/proc/<pid>/task/<tid>` のスレッドが独立したプロセスとして一覧に載る（sysinfo 側のコメントも "tasks are considered processes on their own in linux"）。スレッドは `prctl(PR_SET_NAME)` / `pthread_setname_np` で自分の `comm` を自由に変更でき、しかも TID への `kill(2)` はスレッドグループ全体へ配送される。そのため放置すると、denylist に載せたプロセスでも「そのスレッド名」を `--name` に指定すれば名前一致を回避して本体を落とせてしまう。`ProcessInfoProvider` は `without_tasks()` を明示した refresh のみを行い、さらに `ProcessesToUpdate::Some` 指定では tasks 設定に関わらず TID が返るため、参照側でも `thread_kind().is_none()` で一律に弾く（macOS の `proc_listallpids` はプロセスのみ返すため影響なし）

13. **設定ファイル種別の fail-closed 検証**: CLI の厳格読み込みは、設定パス自体が本当に存在しない場合だけ既定値を使用する。通常ファイルと通常ファイルへ解決できる symlink は許可するが、壊れた symlink は「未作成」と誤認せず設定エラーにする。ディレクトリ・FIFO・デバイス等の特殊ファイルも読み込み前に拒否し、管理対象設定の消失によるカスタム denylist の暗黙解除、FIFO での無期限待機、デバイスからの無制限読み込みを防ぐ

14. **設定初期化時の特殊ファイル・パス置換競合対策**: `safe-kill init` は通常ファイルと通常ファイルへ解決できる symlink だけを許可し、ディレクトリ・FIFO・デバイスおよびそれらへの symlink を open 前に拒否する。検証済みの親ディレクトリは device/inode を照合してファイルディスクリプタで固定し、そこから `openat(O_NONBLOCK | O_NOFOLLOW)` で書き込み先を開く。取得したファイルハンドルも通常ファイルかつ検証時と同じ device/inode であることを確認する。検証時に存在しなかったパスは `O_CREAT | O_EXCL` による原子的な新規作成に限定するため、`--force` でも FIFO で無期限に待機したりデバイスへ書き込んだりしない。open 前の symlink・通常ファイル・親ディレクトリ置換は fail-closed で拒否し、open 後の置換でも固定済みFDへの書き込みにより別ファイルへの誘導を防ぐ

### Port-based killing の特殊性

`--port` は ancestry チェックをバイパスする（孤立した開発サーバー終了用途）。ただし `config.toml` の `[allowed_ports]` で明示的に許可されたポートのみ。未設定時は `--port` オプション自体が無効。ポート `0` は OS の自動割り当て用の特殊値なので、設定に含まれていても常に拒否する。信頼ルート PID 自体はポート指定でも保護する。TCP は LISTEN 状態のソケットのみ対象にし、ESTABLISHED などの接続済みクライアントソケットは対象外。UDP は状態を持たないためローカルポート一致で対象にする。プロセス名解決に失敗した PID は `pid:<pid>` 形式のプレースホルダ名でフォールバックされるが、この名前はあくまで表示用であり、ポリシー判定は fresh なプロセス情報が取れない時点で `ProcessNotFound` として fail-closed する（denylist のバイパス防止）。さらに kill 直前に対象ポートの保持者集合を再取得し、判定時の PID/プロトコルが含まれなければ `NoProcessOnPort` として fail-closed する（判定～kill 間にポートを離した場合の追加防御）。

## Key Modules

| Module | Role |
|--------|------|
| `cli.rs` | clap ベースの CLI 定義と実行モード判定。`init` サブコマンドと通常 kill オプションの排他も担う。`parse_args` は clap 既定の `parse()`（使用方法エラーで `exit(2)`）ではなく `try_parse()` を使い、終了コードを自前で決める。2 は `PermissionDenied` に割り当て済みのため、未知フラグや値の形式エラーを 2 で返すと権限エラーと区別できなくなる。clap 由来のエラーは `validate()` の `InvalidUsage` と同じ `GeneralError`(255) に揃え、`--help` / `--version` のみ 0 で終了する |
| `policy.rs` | Kill 許可判定のオーケストレーション。root PID 自体の保護、PID 1 自体の保護（コンテナ環境での巻き添え防止、`can_kill` / `can_kill_for_port` の両経路で fail-closed）、既定 denylist の強制合流、`KillPermission` enum の返却（拒否判定→`SafeKillError` 変換は `KillPermission::to_error` に集約）、kill 直前の最終安全検証 (`verify_final_safety_before_kill` = 自殺防止の再確認 `verify_not_suicide_before_kill` + ancestry の fresh 再評価 (Required 時) + PID 再利用検証 `verify_identity_before_kill`) も担う。`FinalAncestryCheck` enum で再評価の Required/Bypassed を型レベルに固定し、`try_from_permission` で拒否系を fail-loud に拒絶する |
| `ancestry.rs` | プロセスツリー検証。`SAFE_KILL_ROOT_PID`（0/1/無効値は無視）または祖父プロセスをルートとする。PID 1（init/launchd）は信頼ルートにできず、祖父が PID 1 等で不適格なら親→現在プロセスへフォールバックする（fail-closed）。構築時に信頼ルートの初期 identity を `root_identity: Option<ProcessInfo>` で保持し、`root_identity_matches_in_provider` で同一 snapshot 内に identity 検証を組み込む。`is_descendant` / `is_descendant_of`（ancestor が root_pid 時）/ `is_descendant_fresh` の各経路で identity 整合性を fail-closed 検証する。`is_descendant_fresh` は新規 snapshot で identity と ancestry を同時検証して TOCTOU 窓を最小化。`refresh()` は identity を更新せず、不一致時に `root_identity = None` にして以後 fail-closed に倒す（PID 再利用後のプロセスを信頼ルートにしない）。木探索本体は `is_descendant_of_with_provider` に分離し、任意 provider snapshot に対して再利用可能。同一 PID 指定でも対象 PID が snapshot に存在しなければ子孫扱いしない |
| `killer.rs` | シグナル送信と結果追跡。dry-run 対応。`KillResult` に元の `SafeKillError` を保持する |
| `config.rs` | `~/.config/safe-kill/config.toml` の読み込み。CLI 実行ではアクセス不可・解析不能・未知フィールド・壊れた symlink・特殊ファイルを設定エラーとして fail-closed にし、通常ファイルへの symlink は許可する。OS別デフォルト denylist とユーザー denylist を合流。フォールバック読み込み時の警告は設定パスとエラー本文をサニタイズしてから表示する |
| `signal.rs` | Unix シグナル解析と送信。名前/番号両対応、macOS/Linux のプラットフォーム固有番号のみ受付、危険 PID 値の拒否 |
| `port.rs` | netstat2 による port→PID 解決。TCP は LISTEN のみ、UDP はローカルポート一致 |
| `process_info.rs` | sysinfo ベースのプロセス一覧取得とプロセス名の完全一致検索。`ProcessInfo.start_time` で PID 再利用を検出可能。`fetch_fresh(pid)` は PID 0 と `i32::MAX` 超過を拒否した上で新しい `System` を作り、指定 PID のみ refresh する TOCTOU 検証専用関数。結果は PID 昇順で安定化。refresh は `refresh_kind()`（`without_tasks()` 指定）で行い、Linux のスレッド（TID）を一覧に入れない（下記「スレッド経由の denylist バイパス防止」参照）。参照側（`get` / `find_by_name` / `all` / `fetch_fresh`）でも `thread_kind().is_none()` で二重に弾く |
| `init.rs` | `safe-kill init` で config.toml を生成。既存ファイルの上書き確認を行い、ユーザーが拒否した場合は作成失敗（終了コード3）ではなく正常な no-op（終了コード0、`InitOutcome::SkippedExisting`）として扱う。確認プロンプトの設定パスはサニタイズ済みで表示する。既存判定は `Path::exists()` ではなく `fs::symlink_metadata()` で行い、symlink の場合は `canonicalize()` で実体を解決してプロンプトと結果表示の両方に開示する。壊れた symlink、特殊ファイル、特殊ファイルへ解決される symlink は fail-closed で拒否する（`--force` でも同様）。親ディレクトリを device/inode 検証済みのFDで固定して `openat(O_NONBLOCK | O_NOFOLLOW)` を行い、既存ファイルの device/inode も再検証する。未作成パスは `O_CREAT | O_EXCL` に限定し、検証～書き込み間のパス置換競合を拒否する |
| `error.rs` | thiserror ベースのエラー型と終了コード (0/1/2/3/4/255) |
| `terminal.rs` | 端末表示用サニタイズ。ANSI escape・改行・タブ・C0/C1 制御文字・Unicode 17.0 の `Cf` 全 170 文字を表示用エスケープへ置換し、プロセス情報・エラー本文・設定パスの表示偽装を防ぐ。エスケープ導入文字 `\` 自身も `\\` へ置換して変換の単射性を保つ |
| `main.rs` | CLI のエントリポイント。実行モードごとの分岐、終了コード変換、表示出力を担う。`terminal.rs` のサニタイズを使い、`--list` 出力、kill 結果表示（`print_kill_result` の `name` と `message` の両方）、`main()` での stderr エラー出力、`safe-kill init` の生成/スキップパス表示にサニタイズ済み文字列のみを流す |

## Versioning

YY.M.COUNTER 形式（例: 26.1.105）。リリースは GitHub Actions の workflow_dispatch で実行。

## Testing Notes

- E2E テストは `assert_cmd` を使用し、実際のバイナリを実行する
- 統合テストは実プロセスツリーを使ったテスト
- 統合テストの一意なプロセス名はテストランナーの PID と連番から生成し、Linux の `comm` 15 バイト上限内に収める。これにより複数の `cargo test` を並行実行しても名前が衝突しない
- ancestry テストでは `SAFE_KILL_ROOT_PID` 環境変数でルート PID を制御可能（`0`・`1` や無効値は無視、root PID 自体は kill 不可）
