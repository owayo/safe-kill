//! safe-kill の CLI 引数パーサー
//!
//! clap derive を使用した型安全な引数解析を提供する。
//!
//! clap derive の型（`CliArgs` / `Command`）とそのフィールド・variant には `///` を書かない。
//! clap derive は `///` を help 文（`help` / `long_help`、`about` / `long_about`）として
//! 取り込むため、日本語の説明を `///` で書くと `--help` へそのまま漏れる（過去に実際に
//! 漏れていた）。明示した `help = "..."` / `about = "..."` で上書きしても防げない。
//! clap derive は doc comment 由来の設定を明示属性より先に適用するので、短い方は
//! 上書きされても、段落を足した doc comment から生まれる `long_help` / `long_about` は
//! 残り、`--help` ではそちらが優先される。利用者向けの文言は英語の明示属性で書き、
//! 開発者向けの説明は `//` コメントに分けて、help への混入経路そのものを断つ。

use std::ffi::OsString;
use std::io::{self, Write};

use clap::builder::styling::Styles;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::error::{SafeKillError, SafeKillExitCode};
use crate::signal::{Signal, SignalSender};
use crate::terminal::sanitize_terminal;

/// 使用方法エラーの本文を組み立てられなかったときに出す固定の診断
///
/// 引数を一切埋め込まない。ここへ来るのは想定外の経路なので、利用者の引数を
/// サニタイズせずに表示する危険を冒すより、情報を減らしてでも安全側に倒す。
const GENERIC_USAGE_ERROR: &str = "safe-kill: error: invalid command line. Use --help for usage.";

/// CLI 引数から決定される実行モード
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionMode {
    /// PID 指定でプロセスを kill
    KillByPid(u32),
    /// プロセス名の完全一致で終了
    KillByName(String),
    /// ポート指定でプロセスを kill
    KillByPort(u16),
    /// kill 可能なプロセスを一覧表示
    ListKillable,
    /// 設定ファイルを初期化
    InitConfig { force: bool },
}

// safe-kill のサブコマンド
// （clap derive の型なので `///` は使わない。理由はモジュール先頭のコメントを参照）
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // ~/.config/safe-kill/config.toml に設定ファイルを初期化する
    #[command(about = "Create ~/.config/safe-kill/config.toml with a starter configuration")]
    Init {
        // 既存の設定ファイルを確認なしで上書きする
        #[arg(long, help = "Overwrite an existing config file without prompting")]
        force: bool,
    },
}

// safe-kill の CLI 引数
// （clap derive の型なので `///` は使わない。理由はモジュール先頭のコメントを参照）
#[derive(Parser, Debug)]
#[command(
    name = "safe-kill",
    // `bin_name` を明示しないと、clap は Usage 行に `argv[0]` の basename を使う。
    // `name` は表示名を決めるだけで、この経路は塞げない。制御文字を含む名前の
    // symlink 経由で起動されたり `exec -a` で argv[0] を差し替えられたりすると、
    // `Usage: fake\rFORGED [OPTIONS] [PID]` のように生の制御文字が help へ載り、
    // Usage 行の上書き偽装が成立する。固定名にして argv[0] の混入経路を断つ。
    bin_name = "safe-kill",
    version,
    args_conflicts_with_subcommands = true,
    about = "Safe process termination tool for AI agents",
    long_about = "A CLI tool that provides ancestry-based access control for process termination.\n\
                  It allows killing only descendant processes of the current session,\n\
                  preventing accidental termination of system or unrelated processes."
)]
pub struct CliArgs {
    // サブコマンド（例: init）
    #[command(subcommand)]
    pub command: Option<Command>,

    // kill 対象の PID
    #[arg(value_name = "PID", help = "Target PID to kill")]
    pub pid: Option<u32>,

    // プロセス名の完全一致で終了する（部分一致・パターン一致はしない）
    #[arg(
        short = 'N',
        long,
        value_name = "NAME",
        help = "Kill processes whose name exactly matches NAME"
    )]
    pub name: Option<String>,

    // 指定ポートを使用するプロセスを kill する（TCP は LISTEN のみ、UDP はローカルポート一致）。
    // config.toml の [allowed_ports] に載っているポートだけが対象
    #[arg(
        short = 'p',
        long,
        value_name = "PORT",
        help = "Kill the TCP listener or UDP socket using PORT (must be listed in [allowed_ports])"
    )]
    pub port: Option<u16>,

    // 送信するシグナル（名前または番号）。既定値の表示は clap が `[default: SIGTERM]` を付ける
    #[arg(
        short,
        long,
        default_value = "SIGTERM",
        value_name = "SIGNAL",
        help = "Signal to send (name or number)"
    )]
    pub signal: String,

    // kill 可能なプロセスを一覧表示する
    #[arg(short, long, help = "List killable processes")]
    pub list: bool,

    // dry-run モード（実際にはシグナルを送信しない）
    #[arg(
        short = 'n',
        long,
        help = "Show what would be killed without sending signals"
    )]
    pub dry_run: bool,
}

impl CliArgs {
    /// コマンドラインから CLI 引数を解析
    ///
    /// clap 既定の `parse()` は使用方法エラーで自前に `exit(2)` する。しかし終了コード 2 は
    /// `SafeKillExitCode::PermissionDenied` に割り当て済みで、README の終了コード表でも
    /// 「権限不足」として公開している。そのままだと `safe-kill --bogus` のような単なる
    /// typo が権限エラーと同じコードになり、終了コードで分岐する呼び出し側（AI エージェント
    /// のスクリプト等）が誤判定する。
    ///
    /// 同じ「使用方法エラー」でも `validate()` 側が返す `InvalidUsage` は 255 になるため、
    /// 内部的にも不整合だった（例: `safe-kill 0` は 255、`safe-kill 99999999999` は 2）。
    /// clap 由来のエラーも `GeneralError`(255) に揃える。`--help` / `--version` は
    /// エラーではないので従来どおり 0 で終了する。
    ///
    /// argv は 1 度だけ取得して使い回す。使用方法エラーの表示用に同じ argv を
    /// もう 1 度解析し直すため（`render_usage_error` を参照）。
    pub fn parse_args() -> Self {
        let argv: Vec<OsString> = std::env::args_os().collect();
        match Self::try_parse_from(&argv) {
            Ok(args) => args,
            Err(e) => {
                // clap の `Error::print()` は use_stderr() に従って出力先を選ぶ
                // （エラーは stderr、--help / --version は stdout）。
                if !e.use_stderr() {
                    // --help / --version は `Command` の静的な定義から描画され、
                    // argv の値を一切埋め込まない（argv[0] も `bin_name` の固定で塞いである）。
                    // 攻撃者が制御文字を差し込む経路が構造的に無いため、clap の色付けを
                    // 保ったまま出力する。
                    let _ = e.print();
                    std::process::exit(i32::from(SafeKillExitCode::Success as u8));
                }

                // 使用方法エラーには利用者が渡した引数値がそのまま埋め込まれる
                // （例: `invalid value '<値>' for '[PID]'`）。clap 側に制御文字の
                // 除去は無く、`Error::print()` は anstream 経由で書くため、端末直結では
                // `\x1b[2J`（画面消去）や `\x1b]52`（クリップボード書き換え）が生のまま
                // 画面へ届く。パイプ時だけ anstream が ANSI を落とすので見落としやすい。
                // そこで `print()` は使わず、サニタイズ済みの 1 行を自前で書く。
                // 組み立て方と、制御文字を削除せずエスケープして見せる理由は
                // `render_usage_error` を参照。
                let line = usage_error_line(&argv);
                let mut stderr = io::stderr();
                // 診断が届かなくても終了コードは変えない（`main()` のエラー出力と同じ方針）。
                // stderr はバッファを持たず（`exit()` も終了前に stdout を flush する）、
                // flush は書き込み先が変わっても診断を失わないための念のための処理。
                let _ = writeln!(stderr, "{line}");
                let _ = stderr.flush();
                std::process::exit(i32::from(SafeKillExitCode::GeneralError as u8));
            }
        }
    }

    /// 引数を検証し、実行モードを決定する
    ///
    /// 以下の場合にエラーを返す:
    /// - ターゲットが指定されていない（PID、--name、--port、--list のいずれもなし）
    /// - 複数のターゲットが指定されている（PID と --name/--port、または --list と他の組み合わせ）
    pub fn validate(&self) -> Result<ExecutionMode, SafeKillError> {
        // サブコマンドを先に処理
        if let Some(ref cmd) = self.command {
            let has_runtime_options = self.pid.is_some()
                || self.name.is_some()
                || self.port.is_some()
                || self.list
                || self.dry_run
                || !self.signal.eq_ignore_ascii_case("SIGTERM");

            if has_runtime_options {
                return Err(SafeKillError::InvalidUsage(
                    "init cannot be combined with PID, --name, --port, --list, --signal, or --dry-run"
                        .to_string(),
                ));
            }

            match cmd {
                Command::Init { force } => {
                    return Ok(ExecutionMode::InitConfig { force: *force });
                }
            }
        }

        // ターゲットオプションの指定数をカウント
        let has_pid = self.pid.is_some();
        let has_name = self.name.is_some();
        let has_port = self.port.is_some();
        let has_list = self.list;

        // 排他性チェック
        let target_count = [has_pid, has_name, has_port, has_list]
            .iter()
            .filter(|&&b| b)
            .count();

        match target_count {
            0 => Err(SafeKillError::NoTarget),
            1 => {
                if has_list {
                    Ok(ExecutionMode::ListKillable)
                } else if let Some(pid) = self.pid {
                    Ok(ExecutionMode::KillByPid(pid))
                } else if let Some(ref name) = self.name {
                    Ok(ExecutionMode::KillByName(name.clone()))
                } else if let Some(port) = self.port {
                    Ok(ExecutionMode::KillByPort(port))
                } else {
                    // 上記のロジックからここには到達しないはず
                    Err(SafeKillError::NoTarget)
                }
            }
            _ => {
                // 複数ターゲット指定はエラー
                if has_list {
                    Err(SafeKillError::InvalidUsage(
                        "--list cannot be combined with PID, --name, or --port".to_string(),
                    ))
                } else if has_port {
                    Err(SafeKillError::InvalidUsage(
                        "--port cannot be combined with PID or --name".to_string(),
                    ))
                } else {
                    Err(SafeKillError::InvalidUsage(
                        "Cannot specify both PID and --name".to_string(),
                    ))
                }
            }
        }
    }

    /// シグナル引数を Signal enum に解析する
    pub fn parse_signal(&self) -> Result<Signal, SafeKillError> {
        SignalSender::parse_signal(&self.signal)
    }
}

/// 使用方法エラーとして stderr へ書く 1 行（末尾の改行なし）を返す
///
/// 本文を組み立てられなければ、引数を一切含まない固定の診断に倒す。
fn usage_error_line(argv: &[OsString]) -> String {
    render_usage_error(argv).unwrap_or_else(|| GENERIC_USAGE_ERROR.to_string())
}

/// argv を解析し直し、使用方法エラーを端末へ安全に出せる 1 行へ変換する
///
/// 戻り値は `safe-kill: ` から始まる 1 行（末尾の改行なし）。解析が成功した場合と、
/// 結果が `--help` / `--version` のように stdout へ出す種類だった場合は `None`。
/// 呼び出し元では同じ argv が使用方法エラーになったことを確認済みなので、
/// `None` は想定外の経路であり、固定の診断へ倒す。
///
/// ## 色付けを無効にした `Command` で解析し直す理由
///
/// 最初の解析で得たエラーをそのまま描画すると、利用者が渡した制御文字を開示できない。
/// `StyledStr` の `Display`（`render().to_string()`）は anstream の `strip_str` を通り、
/// clap 自身の色付けと一緒に、引数値に含まれていた ESC シーケンスや BEL・BS などの
/// C0 制御文字まで黙って削除する。安全性は保たれるが、`safe-kill $'x\a\by'` と
/// `safe-kill xy` の診断がバイト単位で一致し、`$'\e[2Jx'` は `x` と表示される。
/// 削除は非単射なので、読み手は「引数に何が含まれていたか」を診断から判別できない。
/// これはサニタイズ（`sanitize_terminal`）の「削除せず、エスケープして見せる」方針と
/// 矛盾する。
///
/// 逆に `render().ansi()` は生の文字列を返すが、既定のスタイルでは clap 自身の色付け
/// （`error:` の太字赤など）の ESC も含み、それがエスケープ表記の雑音として残る。
/// 最初のエラーへ `Error::format` で別の `Command` を当て直しても、エラー生成時に
/// 描画済みの Usage 行は色付きのまま残る。そこで、すべてのスタイルを `Styles::plain()`
/// にした `Command` で同じ argv を解析し直す。plain スタイルでは clap は ESC を一切
/// 出さないので、`ansi()` に残る制御文字は利用者の引数由来のものだけになり、
/// サニタイズでそのまま `\x1B` などのエスケープ表記として開示できる。
///
/// 解析は argv だけで決まる（環境変数を読む `env` 属性は使っていない）ので、
/// 解析し直しても最初と同じエラーになる。
///
/// ## 1 行に畳む理由
///
/// 改行も含めてすべてエスケープし、1 行に畳んで出す。clap の描画結果からは
/// 「clap 自身のレイアウト改行」と「引数値に含まれていた改行」を区別できず、
/// 行構造を残すと引数に改行を混ぜるだけで独立した `error:` 行を偽造できる。
/// 診断を読む人間や AI エージェントに、ツール自身の出力として偽の復旧手順
/// （例:「保護設定を外して再実行せよ」）を提示されるのを防ぐ。エラー表示の色と
/// 改行は失うが、表示偽装を防ぐ方を優先する。
fn render_usage_error(argv: &[OsString]) -> Option<String> {
    let mut cmd = plain_command();
    let err = match cmd.try_get_matches_from_mut(argv) {
        // derive の `try_parse_from` と同じく、照合後の `FromArgMatches` で出る
        // エラーも拾う。`Error::format` で plain スタイルの `Command` を当てる。
        Ok(mut matches) => match CliArgs::from_arg_matches_mut(&mut matches) {
            Ok(_) => return None,
            Err(e) => e.format(&mut cmd),
        },
        Err(e) => e,
    };
    if !err.use_stderr() {
        return None;
    }

    let rendered = err.render().ansi().to_string();
    // 他の診断（`main()` の `safe-kill: ...`）と同じ接頭辞に揃える。行頭が
    // 常に固定文字列になるので、本文側に `error:` が現れても行の出自を誤れない。
    // `trim_end()` で落とすのは clap が付ける末尾の改行。使用方法エラーの末尾は clap が
    // 付ける固定の行で、引数値の末尾の空白や改行が削られて開示から漏れることはない。
    // 通常は `For more information, try '--help'.` で終わる。自動生成の `help`
    // サブコマンドの文脈（`safe-kill help help x`）では help フラグが無いので案内行は
    // 付かないが、`Usage: safe-kill help [COMMAND]...` の行が必ず最後に付く。
    Some(format!(
        "safe-kill: {}",
        sanitize_terminal(rendered.trim_end())
    ))
}

/// 端末向けの装飾を一切出さない `Command` を組み立てる
///
/// サブコマンドのエラー（例: `init --bogus`）はサブコマンド側の `Command` の
/// スタイルで描画される。clap は構築時に親の設定をサブコマンドへ伝播させるが、
/// その内部挙動に頼らず、全階層へ明示的に `Styles::plain()` を当てる。
fn plain_command() -> clap::Command {
    fn without_styles(cmd: clap::Command) -> clap::Command {
        cmd.styles(Styles::plain()).mut_subcommands(without_styles)
    }
    without_styles(CliArgs::command())
}

#[cfg(test)]
mod tests {
    use super::*;

    // テスト用の CliArgs を作成するヘルパー
    fn make_args(
        pid: Option<u32>,
        name: Option<String>,
        port: Option<u16>,
        signal: &str,
        list: bool,
        dry_run: bool,
    ) -> CliArgs {
        CliArgs {
            command: None,
            pid,
            name,
            port,
            signal: signal.to_string(),
            list,
            dry_run,
        }
    }

    // サブコマンド付きの CliArgs を作成するヘルパー
    fn make_args_with_command(command: Command) -> CliArgs {
        CliArgs {
            command: Some(command),
            pid: None,
            name: None,
            port: None,
            signal: "SIGTERM".to_string(),
            list: false,
            dry_run: false,
        }
    }

    // ExecutionMode テスト
    #[test]
    fn test_execution_mode_debug() {
        let mode = ExecutionMode::KillByPid(1234);
        let debug_str = format!("{:?}", mode);
        assert!(debug_str.contains("KillByPid"));
        assert!(debug_str.contains("1234"));
    }

    #[test]
    fn test_execution_mode_clone() {
        let mode = ExecutionMode::KillByName("test".to_string());
        let cloned = mode.clone();
        assert_eq!(mode, cloned);
    }

    #[test]
    fn test_execution_mode_eq() {
        assert_eq!(ExecutionMode::ListKillable, ExecutionMode::ListKillable);
        assert_eq!(ExecutionMode::KillByPid(100), ExecutionMode::KillByPid(100));
        assert_ne!(ExecutionMode::KillByPid(100), ExecutionMode::KillByPid(200));
    }

    // CliArgs バリデーションテスト
    #[test]
    fn test_validate_no_target() {
        let args = make_args(None, None, None, "SIGTERM", false, false);
        let result = args.validate();
        assert!(matches!(result, Err(SafeKillError::NoTarget)));
    }

    #[test]
    fn test_validate_pid_only() {
        let args = make_args(Some(1234), None, None, "SIGTERM", false, false);
        let result = args.validate();
        assert!(matches!(result, Ok(ExecutionMode::KillByPid(1234))));
    }

    #[test]
    fn test_validate_name_only() {
        let args = make_args(
            None,
            Some("node".to_string()),
            None,
            "SIGTERM",
            false,
            false,
        );
        let result = args.validate();
        match result {
            Ok(ExecutionMode::KillByName(name)) => assert_eq!(name, "node"),
            _ => panic!("Expected KillByName"),
        }
    }

    #[test]
    fn test_validate_list_only() {
        let args = make_args(None, None, None, "SIGTERM", true, false);
        let result = args.validate();
        assert!(matches!(result, Ok(ExecutionMode::ListKillable)));
    }

    #[test]
    fn test_validate_port_only() {
        let args = make_args(None, None, Some(8080), "SIGTERM", false, false);
        let result = args.validate();
        assert!(matches!(result, Ok(ExecutionMode::KillByPort(8080))));
    }

    #[test]
    fn test_validate_pid_and_name_conflict() {
        let args = make_args(
            Some(1234),
            Some("node".to_string()),
            None,
            "SIGTERM",
            false,
            false,
        );
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("Cannot specify both"));
        }
    }

    #[test]
    fn test_validate_port_and_pid_conflict() {
        let args = make_args(Some(1234), None, Some(8080), "SIGTERM", false, false);
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("--port cannot be combined"));
        }
    }

    #[test]
    fn test_validate_port_and_name_conflict() {
        let args = make_args(
            None,
            Some("node".to_string()),
            Some(8080),
            "SIGTERM",
            false,
            false,
        );
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("--port cannot be combined"));
        }
    }

    #[test]
    fn test_validate_list_and_pid_conflict() {
        let args = make_args(Some(1234), None, None, "SIGTERM", true, false);
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("--list cannot be combined"));
        }
    }

    #[test]
    fn test_validate_list_and_name_conflict() {
        let args = make_args(None, Some("node".to_string()), None, "SIGTERM", true, false);
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("--list cannot be combined"));
        }
    }

    #[test]
    fn test_validate_list_and_port_conflict() {
        let args = make_args(None, None, Some(8080), "SIGTERM", true, false);
        let result = args.validate();
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("--list cannot be combined"));
        }
    }

    #[test]
    fn test_validate_all_targets_conflict() {
        let args = make_args(
            Some(1234),
            Some("node".to_string()),
            Some(8080),
            "SIGTERM",
            true,
            false,
        );
        let result = args.validate();
        assert!(result.is_err());
    }

    // parse_signal テスト
    #[test]
    fn test_parse_signal_default() {
        let args = make_args(Some(1234), None, None, "SIGTERM", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_sigkill() {
        let args = make_args(Some(1234), None, None, "SIGKILL", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_number() {
        let args = make_args(Some(1234), None, None, "9", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGKILL);
    }

    #[test]
    fn test_parse_signal_without_prefix() {
        let args = make_args(Some(1234), None, None, "TERM", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_lowercase() {
        let args = make_args(Some(1234), None, None, "sigterm", false, false);
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);
    }

    #[test]
    fn test_parse_signal_invalid() {
        let args = make_args(Some(1234), None, None, "INVALID", false, false);
        let result = args.parse_signal();
        assert!(result.is_err());
    }

    // dry_run テスト
    #[test]
    fn test_dry_run_flag() {
        let args = make_args(Some(1234), None, None, "SIGTERM", false, true);
        assert!(args.dry_run);
    }

    #[test]
    fn test_dry_run_default() {
        let args = make_args(Some(1234), None, None, "SIGTERM", false, false);
        assert!(!args.dry_run);
    }

    // CliArgs 構造体テスト
    #[test]
    fn test_cli_args_debug() {
        let args = make_args(Some(1234), None, None, "SIGTERM", false, false);
        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("CliArgs"));
        assert!(debug_str.contains("1234"));
    }

    #[test]
    fn test_cli_args_fields() {
        let args = make_args(
            Some(100),
            Some("test".to_string()),
            Some(3000),
            "SIGKILL",
            true,
            true,
        );
        assert_eq!(args.pid, Some(100));
        assert_eq!(args.name, Some("test".to_string()));
        assert_eq!(args.port, Some(3000));
        assert_eq!(args.signal, "SIGKILL");
        assert!(args.list);
        assert!(args.dry_run);
    }

    // 統合的テスト
    #[test]
    fn test_workflow_pid_kill() {
        let args = make_args(Some(1234), None, None, "SIGTERM", false, false);

        // バリデーション
        let mode = args.validate().unwrap();
        assert!(matches!(mode, ExecutionMode::KillByPid(1234)));

        // シグナル解析
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);

        // dry_run 確認
        assert!(!args.dry_run);
    }

    #[test]
    fn test_workflow_name_kill_dry_run() {
        let args = make_args(None, Some("node".to_string()), None, "SIGKILL", false, true);

        // バリデーション
        let mode = args.validate().unwrap();
        match mode {
            ExecutionMode::KillByName(name) => assert_eq!(name, "node"),
            _ => panic!("Expected KillByName"),
        }

        // シグナル解析
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGKILL);

        // dry_run 確認
        assert!(args.dry_run);
    }

    #[test]
    fn test_workflow_port_kill() {
        let args = make_args(None, None, Some(8080), "SIGTERM", false, false);

        // バリデーション
        let mode = args.validate().unwrap();
        assert!(matches!(mode, ExecutionMode::KillByPort(8080)));

        // シグナル解析
        let signal = args.parse_signal().unwrap();
        assert_eq!(signal, Signal::SIGTERM);

        // dry_run 確認
        assert!(!args.dry_run);
    }

    #[test]
    fn test_workflow_list() {
        let args = make_args(None, None, None, "SIGTERM", true, false);

        // バリデーション
        let mode = args.validate().unwrap();
        assert!(matches!(mode, ExecutionMode::ListKillable));
    }

    // Init サブコマンドテスト
    #[test]
    fn test_init_command() {
        let args = make_args_with_command(Command::Init { force: false });
        let result = args.validate();
        assert!(matches!(
            result,
            Ok(ExecutionMode::InitConfig { force: false })
        ));
    }

    #[test]
    fn test_init_command_with_force() {
        let args = make_args_with_command(Command::Init { force: true });
        let result = args.validate();
        assert!(matches!(
            result,
            Ok(ExecutionMode::InitConfig { force: true })
        ));
    }

    #[test]
    fn test_init_command_rejects_runtime_options() {
        let args = CliArgs {
            command: Some(Command::Init { force: false }),
            pid: Some(1234),
            name: None,
            port: None,
            signal: "SIGTERM".to_string(),
            list: false,
            dry_run: true,
        };
        let result = args.validate();
        assert!(matches!(result, Err(SafeKillError::InvalidUsage(_))));
    }

    #[test]
    fn test_init_command_rejects_each_runtime_option() {
        let cases = [
            CliArgs {
                command: Some(Command::Init { force: false }),
                pid: None,
                name: Some("node".to_string()),
                port: None,
                signal: "SIGTERM".to_string(),
                list: false,
                dry_run: false,
            },
            CliArgs {
                command: Some(Command::Init { force: false }),
                pid: None,
                name: None,
                port: Some(3000),
                signal: "SIGTERM".to_string(),
                list: false,
                dry_run: false,
            },
            CliArgs {
                command: Some(Command::Init { force: false }),
                pid: None,
                name: None,
                port: None,
                signal: "SIGTERM".to_string(),
                list: true,
                dry_run: false,
            },
            CliArgs {
                command: Some(Command::Init { force: false }),
                pid: None,
                name: None,
                port: None,
                signal: "SIGTERM".to_string(),
                list: false,
                dry_run: true,
            },
        ];

        for args in cases {
            let result = args.validate();
            assert!(matches!(result, Err(SafeKillError::InvalidUsage(_))));
        }
    }

    #[test]
    fn test_init_command_rejects_signal_option_value() {
        let args = CliArgs {
            command: Some(Command::Init { force: false }),
            pid: None,
            name: None,
            port: None,
            signal: "SIGKILL".to_string(),
            list: false,
            dry_run: false,
        };
        let result = args.validate();
        assert!(matches!(result, Err(SafeKillError::InvalidUsage(_))));
    }

    #[test]
    fn test_cli_parser_rejects_list_with_init_subcommand() {
        let result = CliArgs::try_parse_from(["safe-kill", "--list", "init"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parser_rejects_pid_with_init_subcommand() {
        let result = CliArgs::try_parse_from(["safe-kill", "1234", "init"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parser_rejects_signal_with_init_subcommand() {
        let result = CliArgs::try_parse_from(["safe-kill", "init", "--signal", "SIGTERM"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parser_rejects_name_with_init_subcommand() {
        let result = CliArgs::try_parse_from(["safe-kill", "init", "--name", "node"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parser_rejects_port_with_init_subcommand() {
        let result = CliArgs::try_parse_from(["safe-kill", "init", "--port", "3000"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parser_rejects_dry_run_with_init_subcommand() {
        let result = CliArgs::try_parse_from(["safe-kill", "init", "--dry-run"]);
        assert!(result.is_err());
    }

    // =========================================================================
    // help 文の言語の回帰テスト
    //
    // clap derive は `///` を help 文として取り込むため、コメントの日本語化で
    // `--help` が日本語に化けたことがある。利用者向けの文言は英語の明示属性で書く。
    // =========================================================================

    /// 利用者が help を表示する各経路の argv
    const HELP_INVOCATIONS: [&[&str]; 7] = [
        &["safe-kill", "--help"],
        &["safe-kill", "-h"],
        &["safe-kill", "help"],
        &["safe-kill", "init", "--help"],
        &["safe-kill", "init", "-h"],
        &["safe-kill", "help", "init"],
        &["safe-kill", "help", "help"],
    ];

    #[test]
    fn test_help_output_is_english_only() {
        // 実際に `e.print()` で出る文面（DisplayHelp エラーの描画）を経路ごとに検査する。
        // 英語の文言は ASCII だけで書けるので、非 ASCII が 1 文字でもあれば混入とみなす。
        for argv in HELP_INVOCATIONS {
            let err = CliArgs::try_parse_from(argv).expect_err("help はエラー経路で返る");
            assert!(!err.use_stderr(), "{argv:?} は stdout へ出す help のはず");
            let rendered = err.render().to_string();
            assert!(!rendered.is_empty(), "{argv:?} の help が空");
            let non_ascii: String = rendered.chars().filter(|c| !c.is_ascii()).collect();
            assert!(
                non_ascii.is_empty(),
                "{argv:?} の help に非 ASCII 文字が混入している ({non_ascii:?}):\n{rendered}"
            );
        }
    }

    #[test]
    fn test_help_strings_are_english_only_in_command_definition() {
        // 描画経路に現れない長い help（long_help / long_about）も含め、定義そのものを
        // 全階層で検査する。段落を足した `///` は明示した `help` を上書きできないが
        // `long_help` として残り、`--help` ではそちらが優先されるため。
        fn check(cmd: &clap::Command) {
            let mut texts: Vec<String> = Vec::new();
            for s in [cmd.get_about(), cmd.get_long_about()]
                .into_iter()
                .flatten()
            {
                texts.push(s.to_string());
            }
            for arg in cmd.get_arguments() {
                for s in [arg.get_help(), arg.get_long_help()].into_iter().flatten() {
                    texts.push(s.to_string());
                }
            }
            for text in texts {
                assert!(
                    text.is_ascii(),
                    "`{}` の help 文に非 ASCII 文字が混入している: {text:?}",
                    cmd.get_name()
                );
            }
            for sub in cmd.get_subcommands() {
                check(sub);
            }
        }

        let mut cmd = CliArgs::command();
        // 自動生成される `help` サブコマンドや `--help` / `--version` も含めて検査する
        cmd.build();
        check(&cmd);
    }

    #[test]
    fn test_help_describes_each_option_consistently_with_cli_reference() {
        // docs/cli-reference.md の説明と食い違わないよう、主要な文言を固定する。
        let long = CliArgs::try_parse_from(["safe-kill", "--help"])
            .unwrap_err()
            .render()
            .to_string();
        for expected in [
            "Target PID to kill",
            "Kill processes whose name exactly matches NAME",
            "Kill the TCP listener or UDP socket using PORT (must be listed in [allowed_ports])",
            "Signal to send (name or number)",
            "[default: SIGTERM]",
            "List killable processes",
            "Show what would be killed without sending signals",
            "Create ~/.config/safe-kill/config.toml with a starter configuration",
        ] {
            assert!(
                long.contains(expected),
                "--help に {expected:?} が無い:\n{long}"
            );
        }

        let init = CliArgs::try_parse_from(["safe-kill", "init", "--help"])
            .unwrap_err()
            .render()
            .to_string();
        for expected in [
            "Create ~/.config/safe-kill/config.toml with a starter configuration",
            "Overwrite an existing config file without prompting",
        ] {
            assert!(
                init.contains(expected),
                "init --help に {expected:?} が無い:\n{init}"
            );
        }
    }

    // =========================================================================
    // 使用方法エラーの描画（render_usage_error）の回帰テスト
    //
    // 利用者の引数に含まれる制御文字は「削除」ではなく「エスケープして開示」する。
    // 削除すると `x\a\by` と `xy` の診断が一致し、読み手が中身を判別できない。
    // =========================================================================

    fn os_argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn render(args: &[&str]) -> String {
        render_usage_error(&os_argv(args))
            .unwrap_or_else(|| panic!("{args:?} は使用方法エラーとして描画されるべき"))
    }

    /// 端末へ生で届くと表示を壊せる文字が 1 つも残っていないこと
    fn assert_no_raw_controls(line: &str) {
        let raw: Vec<char> = line
            .chars()
            .filter(|&c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202E}'))
            .collect();
        assert!(
            raw.is_empty(),
            "生の制御文字 {raw:?} が残っている: {line:?}"
        );
    }

    #[test]
    fn test_render_usage_error_is_single_prefixed_line() {
        let line = render(&["safe-kill", "--bogus"]);
        assert!(line.starts_with("safe-kill: error: "), "{line}");
        assert!(line.contains("'--bogus'"), "{line}");
        // clap のレイアウト改行も畳まれて 1 行になり、末尾の改行は落ちている
        assert!(!line.contains('\n') && !line.contains('\r'), "{line:?}");
        assert!(
            line.contains("\\n"),
            "レイアウト改行はエスケープ表記で残る: {line}"
        );
        assert!(
            line.ends_with("For more information, try '--help'."),
            "{line}"
        );
    }

    #[test]
    fn test_render_usage_error_emits_no_clap_styling() {
        // clap 自身の色付け（`error:` の太字赤など）が混ざると、サニタイズ後に
        // `\x1B[1m` のような雑音になり、利用者由来の ESC と区別できなくなる。
        // plain スタイルの適用が外れていないことを、制御文字を含まない引数で確かめる。
        for args in [
            &["safe-kill", "--bogus"][..],
            &["safe-kill", "--port", "abc"],
            &["safe-kill", "99999999999"],
            &["safe-kill", "--name"],
            &["safe-kill", "--list", "init"],
            // サブコマンドのエラーはサブコマンド側の `Command` のスタイルで描画される
            &["safe-kill", "init", "--bogus"],
            &["safe-kill", "init", "--force", "extra"],
            &["safe-kill", "help", "nonexistent"],
        ] {
            let line = render(args);
            assert!(
                !line.contains("\\x1B"),
                "clap 自身の ANSI 装飾が混入している ({args:?}): {line}"
            );
            assert_no_raw_controls(&line);
            // `trim_end()` が削るのは clap 固定の末尾の後ろだけ、という前提を固定する
            assert!(
                line.ends_with("For more information, try '--help'."),
                "末尾が clap 固定の文言で終わっていない ({args:?}): {line}"
            );
        }
    }

    #[test]
    fn test_render_usage_error_in_help_subcommand_context_ends_with_usage_line() {
        // 自動生成の `help` サブコマンドは help フラグを持たないので、clap は
        // `For more information` の案内行を付けない。それでも末尾は clap 固定の Usage 行で、
        // 引数値が最後に来て `trim_end()` で削られることはない。制御文字を混ぜた引数でも
        // エスケープ表記で開示される。
        let line = render(&["safe-kill", "help", "help", "x"]);
        assert!(
            line.ends_with("Usage: safe-kill help [COMMAND]..."),
            "{line}"
        );
        assert!(line.contains("'x'"), "{line}");
        assert!(!line.contains("\\x1B"), "{line}");
        assert_no_raw_controls(&line);

        let line = render(&["safe-kill", "help", "help", "x \x1b[2J\r"]);
        assert!(line.contains("'x \\x1B[2J\\r'"), "{line}");
        assert!(
            line.ends_with("Usage: safe-kill help [COMMAND]..."),
            "{line}"
        );
        assert_no_raw_controls(&line);
    }

    #[test]
    fn test_render_usage_error_escapes_bel_and_backspace_instead_of_deleting() {
        let line = render(&["safe-kill", "x\x07\x08y"]);
        assert!(line.contains("'x\\x07\\x08y'"), "{line}");
        assert_no_raw_controls(&line);
    }

    #[test]
    fn test_render_usage_error_is_injective_for_control_characters() {
        // anstream の strip で制御文字を削除していた頃は、この 2 つがバイト単位で一致した。
        assert_ne!(
            render(&["safe-kill", "x\x07\x08y"]),
            render(&["safe-kill", "xy"])
        );
        // ESC シーケンスごと消えて `x` と同じ表示になることもない
        assert_ne!(
            render(&["safe-kill", "\x1b[2Jx"]),
            render(&["safe-kill", "x"])
        );
        // 実 ESC と、リテラルで `\x1B` と書いた引数も区別できる（`\` 自身もエスケープ）
        assert_ne!(
            render(&["safe-kill", "\x1b[2Jx"]),
            render(&["safe-kill", "\\x1B[2Jx"])
        );
    }

    #[test]
    fn test_render_usage_error_escapes_ansi_escape_sequences() {
        let line = render(&["safe-kill", "\x1b[2J\x1b]52;c;ZXZpbA==\x07x"]);
        assert!(
            line.contains("'\\x1B[2J\\x1B]52;c;ZXZpbA==\\x07x'"),
            "{line}"
        );
        assert_no_raw_controls(&line);
    }

    #[test]
    fn test_render_usage_error_cannot_forge_lines() {
        // CR（行頭復帰で行を上書き）、LF、Unicode の行区切り（U+2028）のどれを混ぜても
        // 独立した行を作れず、エスケープ表記で開示される。
        for (arg, escaped) in [
            (
                "fake\rerror: killed successfully",
                "fake\\rerror: killed successfully",
            ),
            (
                "x\nerror: protection disabled",
                "x\\nerror: protection disabled",
            ),
            ("x\u{2028}error: forged", "x\\u{2028}error: forged"),
            ("x\u{2029}error: forged", "x\\u{2029}error: forged"),
        ] {
            let line = render(&["safe-kill", arg]);
            assert!(line.starts_with("safe-kill: error: "), "{line}");
            assert!(line.contains(escaped), "{arg:?} が開示されていない: {line}");
            assert_no_raw_controls(&line);
            assert_eq!(line.lines().count(), 1, "{line:?}");
        }
    }

    #[test]
    fn test_render_usage_error_escapes_bidi_controls() {
        // 双方向テキスト制御で表示順を入れ替える偽装も開示する
        let line = render(&["safe-kill", "x\u{202E}y"]);
        assert!(line.contains("x\\u{202E}y"), "{line}");
        assert_no_raw_controls(&line);
    }

    #[test]
    fn test_render_usage_error_for_subcommand_errors() {
        let line = render(&["safe-kill", "init", "--bogus"]);
        assert!(line.starts_with("safe-kill: error: "), "{line}");
        assert!(line.contains("'--bogus'"), "{line}");
        assert!(line.contains("Usage: safe-kill init"), "{line}");

        // サブコマンドの引数に混ぜた制御文字も開示される
        let line = render(&["safe-kill", "init", "--x\x1b[2J\x07"]);
        assert!(line.contains("--x\\x1B[2J\\x07"), "{line}");
        assert_no_raw_controls(&line);
    }

    #[test]
    fn test_render_usage_error_handles_invalid_utf8() {
        use std::os::unix::ffi::OsStringExt;

        // UTF-8 でない引数でも panic せず、生バイトを出さずに診断を組み立てる
        let argv = vec![
            OsString::from("safe-kill"),
            OsString::from_vec(vec![b'x', 0xff, 0x1b, b'y']),
        ];
        let line = render_usage_error(&argv).expect("使用方法エラーとして描画されるべき");
        assert!(line.starts_with("safe-kill: error: "), "{line}");
        assert_no_raw_controls(&line);
    }

    #[test]
    fn test_render_usage_error_returns_none_for_non_errors() {
        // 解析が成功する argv と help / version は使用方法エラーではない
        for args in [
            &["safe-kill"][..],
            &["safe-kill", "--list"],
            &["safe-kill", "1234"],
            &["safe-kill", "init", "--force"],
            &["safe-kill", "--help"],
            &["safe-kill", "--version"],
            &["safe-kill", "help", "init"],
        ] {
            assert_eq!(render_usage_error(&os_argv(args)), None, "{args:?}");
        }
    }

    #[test]
    fn test_usage_error_line_falls_back_to_generic_message() {
        // 再解析が想定外に成功した場合は、引数を一切含まない固定の診断に倒す
        let line = usage_error_line(&os_argv(&["safe-kill", "--list"]));
        assert_eq!(line, GENERIC_USAGE_ERROR);
        assert_eq!(
            GENERIC_USAGE_ERROR,
            "safe-kill: error: invalid command line. Use --help for usage."
        );
    }

    #[test]
    fn test_usage_error_line_uses_rendered_error() {
        let argv = os_argv(&["safe-kill", "--bogus"]);
        assert_eq!(usage_error_line(&argv), render(&["safe-kill", "--bogus"]));
    }
}
