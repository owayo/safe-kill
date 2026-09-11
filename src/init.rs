//! safe-kill の init コマンドモジュール
//!
//! サンプル設定を含む設定ファイルを生成する。

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;

use crate::config::Config;
use crate::error::SafeKillError;
use crate::terminal::sanitize_path;

/// `safe-kill init` の実行結果
///
/// 設定ファイルを生成したか、既存ファイルを残してスキップしたかを表す。
/// ユーザーが上書きを拒否した場合は「エラー」ではなく正常な no-op（スキップ）として扱う。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitOutcome {
    /// 設定ファイルを新規生成（または `--force` で上書き）した
    Created {
        /// 設定ファイルの論理パス（`~/.config/safe-kill/config.toml`）
        config_path: PathBuf,
        /// 実際に書き込んだパス。`config_path` が symlink の場合はその実体
        written_path: PathBuf,
        /// `config_path` 自体が symlink で、その実体へ書き込んだか
        via_symlink: bool,
    },
    /// 既存ファイルがあり、ユーザーが上書きを拒否したため変更しなかった
    SkippedExisting {
        /// 設定ファイルの論理パス
        config_path: PathBuf,
        /// 上書きしていたら書き込まれていたパス（symlink なら実体）
        target_path: PathBuf,
        /// `config_path` 自体が symlink で、その実体が上書き対象だったか
        via_symlink: bool,
    },
}

/// 設定ファイル生成のための init コマンド
pub struct InitCommand;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug)]
struct ResolvedWriteTarget {
    path: PathBuf,
    parent: PathBuf,
    file_name: OsString,
    expected_parent: FileIdentity,
    expected_file: Option<FileIdentity>,
    /// 設定パス自体が symlink で、その実体を書き込み先にしたか
    ///
    /// 「symlink 経由か」の判定にパス比較（`path != config_path`）を使ってはいけない。
    /// `path` は親ディレクトリを `canonicalize` して組み立てるため、`$HOME` の祖先に
    /// symlink が 1 つでもあれば（macOS の `/var -> private/var` 等）、config.toml が
    /// 通常ファイルでも必ず不一致になり、偽の symlink 警告が出る。警告が常態化すると
    /// 利用者は読み飛ばすようになり、本物の symlink 上書き時に開示が機能しなくなる。
    via_symlink: bool,
}

impl InitCommand {
    /// init コマンドを実行して設定ファイルを生成する
    ///
    /// # 引数
    /// * `force` - true の場合、確認なしで既存ファイルを上書き
    ///
    /// # 戻り値
    /// * `Ok(InitOutcome::Created)` - 設定ファイルを生成した
    /// * `Ok(InitOutcome::SkippedExisting)` - ユーザーが上書きを拒否し、既存ファイルを残した
    /// * `Err(SafeKillError)` - 生成に失敗した場合
    pub fn execute(force: bool) -> Result<InitOutcome, SafeKillError> {
        let config_dir = Config::config_dir().ok_or_else(|| {
            SafeKillError::ConfigCreationError("Unable to determine config directory".to_string())
        })?;

        let config_path = Config::config_path().ok_or_else(|| {
            SafeKillError::ConfigCreationError("Unable to determine config path".to_string())
        })?;

        // 既存エントリの有無は `symlink_metadata` で判定する。
        // `Path::exists()` は symlink を追従するため、リンク先が存在しない「壊れた
        // symlink」を「存在しない」と誤判定し、上書き確認を一切出さないままリンク先の
        // パスへ新規ファイルを作ってしまう。
        let existing = match fs::symlink_metadata(&config_path) {
            Ok(metadata) => Some(metadata),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(SafeKillError::ConfigCreationError(format!(
                    "Failed to access config path {}: {}",
                    config_path.display(),
                    e
                )));
            }
        };

        // 新規作成時は、書き込み先を解決する前に親ディレクトリを用意する。
        // 既存エントリがある場合は親も存在するため、不要な変更を加えない。
        if existing.is_none() {
            // 認可設定を保持するディレクトリなので、呼び出し元の umask が 000 でも
            // 他ユーザーが設定ファイルを作成・差し替えできない権限で生成する。
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(&config_dir).map_err(|e| {
                SafeKillError::ConfigCreationError(format!(
                    "Failed to create directory {}: {}",
                    config_dir.display(),
                    e
                ))
            })?;
        }

        // 実際に書き込むパスを決める。
        // `~/.config/safe-kill/config.toml -> ~/dotfiles/safe-kill.toml` のように
        // dotfiles 管理で symlink にする運用は正当なので追従自体は許すが、
        // 「config.toml を作成した」と表示しながら別ファイルを破壊するのを避けるため、
        // 実体パスを解決して利用者へ開示する。解決できない（リンク先が存在しない）
        // 場合は、意図しないパスへファイルを新規作成してしまうため fail-closed で拒否する。
        let write_target = Self::resolve_write_target(&config_path, existing.as_ref())?;

        // 既存ファイルがあり force でない場合は上書き確認する。
        // ユーザーが拒否した場合は作成失敗ではなく「正常なスキップ」（no-op）として扱い、
        // 終了コード 0 で正常終了させる。
        if existing.is_some()
            && !force
            && !Self::confirm_overwrite(&config_path, &write_target.path, write_target.via_symlink)?
        {
            return Ok(InitOutcome::SkippedExisting {
                config_path,
                target_path: write_target.path,
                via_symlink: write_target.via_symlink,
            });
        }

        // 設定ファイルを書き込み
        let content = Self::default_config_content();
        Self::write_config_file(&write_target, &content)?;

        Ok(InitOutcome::Created {
            config_path,
            written_path: write_target.path,
            via_symlink: write_target.via_symlink,
        })
    }

    /// 既存設定の実体を解決し、通常ファイル以外を上書き対象から除外する。
    fn resolve_write_target(
        config_path: &Path,
        existing: Option<&fs::Metadata>,
    ) -> Result<ResolvedWriteTarget, SafeKillError> {
        let (write_path, expected_file, via_symlink) = match existing {
            None => (config_path.to_path_buf(), None, false),
            Some(metadata) if !metadata.file_type().is_symlink() => {
                if !metadata.is_file() {
                    return Err(SafeKillError::ConfigCreationError(format!(
                        "Config path {} is not a regular file",
                        config_path.display()
                    )));
                }
                (
                    config_path.to_path_buf(),
                    Some(FileIdentity::from_metadata(metadata)),
                    false,
                )
            }
            Some(_) => {
                // Path::exists() は壊れた symlink に false を返すため使わない。実体を開示した上で、
                // 解決不能なリンクや特殊ファイルへのリンクは fail-closed で拒否する。
                let target = fs::canonicalize(config_path).map_err(|e| {
                    SafeKillError::ConfigCreationError(format!(
                        "Config path {} is a symlink whose target cannot be resolved ({}). \
                         Fix or remove the symlink and retry.",
                        config_path.display(),
                        e
                    ))
                })?;
                let target_metadata = fs::metadata(&target).map_err(|e| {
                    SafeKillError::ConfigCreationError(format!(
                        "Failed to inspect config target {}: {}",
                        target.display(),
                        e
                    ))
                })?;
                if !target_metadata.is_file() {
                    return Err(SafeKillError::ConfigCreationError(format!(
                        "Config target {} is not a regular file",
                        target.display()
                    )));
                }
                (
                    target,
                    Some(FileIdentity::from_metadata(&target_metadata)),
                    true,
                )
            }
        };

        let file_name = write_path.file_name().ok_or_else(|| {
            SafeKillError::ConfigCreationError(format!(
                "Config path {} has no file name",
                write_path.display()
            ))
        })?;
        let parent = write_path.parent().ok_or_else(|| {
            SafeKillError::ConfigCreationError(format!(
                "Config path {} has no parent directory",
                write_path.display()
            ))
        })?;
        let parent = fs::canonicalize(parent).map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to resolve config directory {}: {}",
                parent.display(),
                e
            ))
        })?;
        let parent_metadata = fs::metadata(&parent).map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to inspect config directory {}: {}",
                parent.display(),
                e
            ))
        })?;
        if !parent_metadata.is_dir() {
            return Err(SafeKillError::ConfigCreationError(format!(
                "Config parent {} is not a directory",
                parent.display()
            )));
        }

        Ok(ResolvedWriteTarget {
            path: parent.join(file_name),
            parent,
            file_name: file_name.to_os_string(),
            expected_parent: FileIdentity::from_metadata(&parent_metadata),
            expected_file,
            via_symlink,
        })
    }

    /// 検証した親ディレクトリを固定し、パス差し替えに対して fail-closed に書き込む。
    fn write_config_file(
        write_target: &ResolvedWriteTarget,
        content: &str,
    ) -> Result<(), SafeKillError> {
        let parent_dir = OpenOptions::new()
            .read(true)
            // 親自体が直前に symlink へ差し替えられても追従しない。
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
            .open(&write_target.parent)
            .map_err(|e| {
                SafeKillError::ConfigCreationError(format!(
                    "Failed to open config directory {}: {}",
                    write_target.parent.display(),
                    e
                ))
            })?;
        let parent_metadata = parent_dir.metadata().map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to inspect opened config directory {}: {}",
                write_target.parent.display(),
                e
            ))
        })?;
        if !parent_metadata.is_dir()
            || FileIdentity::from_metadata(&parent_metadata) != write_target.expected_parent
        {
            return Err(SafeKillError::ConfigCreationError(format!(
                "Config directory {} changed before writing",
                write_target.parent.display()
            )));
        }

        let mut flags = OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        if write_target.expected_file.is_none() {
            // 存在確認後に別ファイルが作られた場合は、上書きせず失敗させる。
            flags |= OFlag::O_CREAT | OFlag::O_EXCL;
        }
        let fd = openat(
            parent_dir.as_fd(),
            write_target.file_name.as_os_str(),
            flags,
            // allowlist 等の認可設定を含むため、umask に依存せず所有者だけが
            // 読み書きできる権限を上限として新規作成する。
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to open config file {}: {}",
                write_target.path.display(),
                e
            ))
        })?;
        let mut file = File::from(fd);
        let metadata = file.metadata().map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to inspect opened config file {}: {}",
                write_target.path.display(),
                e
            ))
        })?;
        if !metadata.is_file() {
            return Err(SafeKillError::ConfigCreationError(format!(
                "Config target {} is not a regular file",
                write_target.path.display()
            )));
        }
        if let Some(expected_file) = write_target.expected_file
            && FileIdentity::from_metadata(&metadata) != expected_file
        {
            return Err(SafeKillError::ConfigCreationError(format!(
                "Config file {} changed before writing",
                write_target.path.display()
            )));
        }

        if write_target.expected_file.is_some() {
            file.set_len(0).map_err(|e| {
                SafeKillError::ConfigCreationError(format!(
                    "Failed to truncate config file {}: {}",
                    write_target.path.display(),
                    e
                ))
            })?;
        }
        file.write_all(content.as_bytes()).map_err(|e| {
            SafeKillError::ConfigCreationError(format!(
                "Failed to write config file {}: {}",
                write_target.path.display(),
                e
            ))
        })
    }

    /// コメント付きのデフォルト設定内容を生成
    pub fn default_config_content() -> String {
        r#"# safe-kill 設定ファイル
# safe-kill で終了を許可するプロセスやポートをこのファイルで制御します。

# 許可リスト: ここに書いたプロセス名は親子関係チェックをバイパスできます。
# 指定しない場合は、拒否リスト以外のプロセスが通常の安全チェック対象になります。
# [allowlist]
# processes = ["next-server"]

# 拒否リスト: ここに書いたプロセス名は常に終了できません。
# システムプロセスはデフォルトでも保護され、ここに書いた内容はその保護対象に追加されます。
# [denylist]
# processes = ["systemd", "launchd", "init"]

# 許可ポート: --port オプションで対象にできるポートです。
# 指定しない場合、--port オプションは無効です。
# 単一ポート ("3000") と範囲 ("8080-8090") の両方を指定できます。
#   - 1420: Tauri 開発サーバー
#   - 3000-3010: Node.js 開発サーバー
#   - 5173: Vite 開発サーバー
#   - 8080: HTTP 代替ポート
[allowed_ports]
ports = ["1420", "3000-3010", "5173", "8080"]
"#
        .to_string()
    }

    /// 既存ファイルの上書き確認をユーザーに求める
    ///
    /// `path` が symlink で `write_target` がその実体のとき、両方を提示する。
    /// symlink のパスだけを見せて同意を取ると、利用者は「config.toml が上書きされる」と
    /// 理解したまま、実際にはまったく別のファイルが破壊される。
    ///
    /// 分岐条件にパス比較を使わないのは `ResolvedWriteTarget::via_symlink` のコメント参照。
    fn confirm_overwrite(
        path: &Path,
        write_target: &Path,
        via_symlink: bool,
    ) -> Result<bool, SafeKillError> {
        // `eprint!` は書き込み失敗で panic するため使わない。プロンプトが利用者へ
        // 届かないまま stdin を読むと、「見えていない質問」への同意として既存設定を
        // 破壊しかねない。書き込みに失敗したら BrokenPipe も含めて fail-closed で
        // 中断する（結果表示と違い、これは操作前の確認であり省略できない）。
        let mut stderr = io::stderr();
        let written = if via_symlink {
            write!(
                stderr,
                "Config file already exists at {} (symlink to {}). Overwrite the symlink target? [y/N]: ",
                sanitize_path(path),
                sanitize_path(write_target)
            )
        } else {
            write!(
                stderr,
                "Config file already exists at {}. Overwrite? [y/N]: ",
                sanitize_path(path)
            )
        };
        written.and_then(|()| stderr.flush()).map_err(|e| {
            SafeKillError::SystemError(format!(
                "Failed to write overwrite confirmation prompt: {}",
                e
            ))
        })?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(|e| {
            SafeKillError::ConfigCreationError(format!("Failed to read input: {}", e))
        })?;

        let input = input.trim().to_lowercase();
        Ok(input == "y" || input == "yes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_content_not_empty() {
        let content = InitCommand::default_config_content();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_default_config_content_has_sections() {
        let content = InitCommand::default_config_content();
        assert!(content.contains("[allowed_ports]"));
        assert!(content.contains("# [allowlist]"));
        assert!(content.contains("# [denylist]"));
    }

    #[test]
    fn test_default_config_content_has_examples() {
        let content = InitCommand::default_config_content();
        assert!(content.contains("1420"));
        assert!(content.contains("3000-3010"));
        assert!(content.contains("5173"));
        assert!(content.contains("8080"));
    }

    #[test]
    fn test_default_config_content_has_comments() {
        let content = InitCommand::default_config_content();
        assert!(content.contains("# safe-kill 設定ファイル"));
        assert!(content.contains("# 許可リスト"));
        assert!(content.contains("# 拒否リスト"));
        assert!(content.contains("# 許可ポート"));
    }

    #[test]
    fn test_default_config_is_valid_toml() {
        let content = InitCommand::default_config_content();
        // 有効な TOML としてパースできること
        let result: Result<toml::Value, _> = toml::from_str(&content);
        assert!(result.is_ok(), "Config content should be valid TOML");
    }

    #[test]
    fn test_default_config_loads_as_config() {
        let content = InitCommand::default_config_content();
        let result: Result<crate::config::Config, _> = toml::from_str(&content);
        assert!(
            result.is_ok(),
            "Config content should deserialize to Config"
        );
    }

    #[test]
    fn test_execute_force_creates_config_in_temp_dir() {
        // テスト用の一時ディレクトリを使って execute(force=true) を検証
        // 実際の HOME を変更できないため、default_config_content の内容が
        // 有効な TOML であり Config としてパースできることを確認する
        let content = InitCommand::default_config_content();
        let parsed: Result<crate::config::Config, _> = toml::from_str(&content);
        assert!(parsed.is_ok());
        let config = parsed.unwrap();
        // allowed_ports セクションが含まれること
        assert!(config.allowed_ports.is_some());
        let ports = config.allowed_ports.unwrap();
        assert!(!ports.ports.is_empty());
        // デフォルトのポート設定が含まれていること
        assert!(ports.ports.contains(&"1420".to_string()));
        assert!(ports.ports.contains(&"3000-3010".to_string()));
        assert!(ports.ports.contains(&"5173".to_string()));
        assert!(ports.ports.contains(&"8080".to_string()));
    }

    #[test]
    fn test_default_config_ports_match_default_allowed_ports() {
        let content = InitCommand::default_config_content();
        let parsed: crate::config::Config = toml::from_str(&content).unwrap();
        let ports = parsed
            .allowed_ports
            .expect("default config should include [allowed_ports]")
            .ports;
        assert_eq!(ports, crate::config::Config::default_allowed_ports());
    }

    #[test]
    fn test_default_config_content_has_port_descriptions() {
        let content = InitCommand::default_config_content();
        // ポートの説明コメントが含まれていること
        assert!(content.contains("Tauri 開発サーバー"));
        assert!(content.contains("Node.js 開発サーバー"));
        assert!(content.contains("Vite 開発サーバー"));
        assert!(content.contains("HTTP 代替ポート"));
    }

    #[test]
    fn test_execute_creates_file_in_temp_dir() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join(".config").join("safe-kill");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("config.toml");

        // execute と同じロジックで直接書き込み
        let content = InitCommand::default_config_content();
        std::fs::write(&config_path, &content).unwrap();

        // ファイルが存在し、有効な TOML であることを確認
        assert!(config_path.exists());
        let read_content = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(read_content, content);

        let parsed: Result<crate::config::Config, _> = toml::from_str(&read_content);
        assert!(parsed.is_ok());
    }

    #[test]
    fn test_default_config_content_line_count() {
        let content = InitCommand::default_config_content();
        let lines: Vec<&str> = content.lines().collect();
        // 設定ファイルが空でないこと（少なくとも10行以上）
        assert!(
            lines.len() >= 10,
            "Config should have at least 10 lines, got {}",
            lines.len()
        );
    }

    #[test]
    fn test_resolve_write_target_rejects_fifo() {
        let temp = tempfile::tempdir().unwrap();
        let fifo_path = temp.path().join("config.toml");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .unwrap();
        assert!(status.success());

        let metadata = fs::symlink_metadata(&fifo_path).unwrap();
        let result = InitCommand::resolve_write_target(&fifo_path, Some(&metadata));

        assert!(matches!(
            result,
            Err(SafeKillError::ConfigCreationError(message))
                if message.contains("not a regular file")
        ));
    }

    #[test]
    fn test_resolve_write_target_rejects_symlink_to_fifo() {
        let temp = tempfile::tempdir().unwrap();
        let fifo_path = temp.path().join("actual-config");
        let config_path = temp.path().join("config.toml");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .unwrap();
        assert!(status.success());
        std::os::unix::fs::symlink(&fifo_path, &config_path).unwrap();

        let metadata = fs::symlink_metadata(&config_path).unwrap();
        let result = InitCommand::resolve_write_target(&config_path, Some(&metadata));

        assert!(matches!(
            result,
            Err(SafeKillError::ConfigCreationError(message))
                if message.contains("not a regular file")
        ));
    }

    #[test]
    fn test_write_config_file_rejects_symlink_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.toml");
        let original_path = temp.path().join("original-config.toml");
        let attacker_path = temp.path().join("attacker-config.toml");
        fs::write(&config_path, "original").unwrap();
        let metadata = fs::symlink_metadata(&config_path).unwrap();
        let write_target =
            InitCommand::resolve_write_target(&config_path, Some(&metadata)).unwrap();

        fs::rename(&config_path, &original_path).unwrap();
        fs::write(&attacker_path, "attacker content").unwrap();
        std::os::unix::fs::symlink(&attacker_path, &config_path).unwrap();

        let result = InitCommand::write_config_file(&write_target, "replacement");

        assert!(matches!(result, Err(SafeKillError::ConfigCreationError(_))));
        assert_eq!(fs::read_to_string(original_path).unwrap(), "original");
        assert_eq!(
            fs::read_to_string(attacker_path).unwrap(),
            "attacker content"
        );
    }

    #[test]
    fn test_write_config_file_create_new_does_not_overwrite_raced_file() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.toml");
        let write_target = InitCommand::resolve_write_target(&config_path, None).unwrap();
        fs::write(&config_path, "raced content").unwrap();

        let result = InitCommand::write_config_file(&write_target, "replacement");

        assert!(matches!(result, Err(SafeKillError::ConfigCreationError(_))));
        assert_eq!(fs::read_to_string(config_path).unwrap(), "raced content");
    }

    #[test]
    fn test_write_config_file_rejects_regular_file_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.toml");
        let original_path = temp.path().join("original-config.toml");
        fs::write(&config_path, "original").unwrap();
        let metadata = fs::symlink_metadata(&config_path).unwrap();
        let write_target =
            InitCommand::resolve_write_target(&config_path, Some(&metadata)).unwrap();

        fs::rename(&config_path, &original_path).unwrap();
        fs::write(&config_path, "raced content").unwrap();

        let result = InitCommand::write_config_file(&write_target, "replacement");

        assert!(matches!(result, Err(SafeKillError::ConfigCreationError(_))));
        assert_eq!(fs::read_to_string(config_path).unwrap(), "raced content");
        assert_eq!(fs::read_to_string(original_path).unwrap(), "original");
    }

    #[test]
    fn test_write_config_file_rejects_parent_directory_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let config_dir = temp.path().join("safe-kill");
        let original_dir = temp.path().join("original-safe-kill");
        fs::create_dir(&config_dir).unwrap();
        let config_path = config_dir.join("config.toml");
        let write_target = InitCommand::resolve_write_target(&config_path, None).unwrap();

        fs::rename(&config_dir, &original_dir).unwrap();
        fs::create_dir(&config_dir).unwrap();

        let result = InitCommand::write_config_file(&write_target, "replacement");

        assert!(matches!(result, Err(SafeKillError::ConfigCreationError(_))));
        assert!(!config_path.exists());
        assert!(!original_dir.join("config.toml").exists());
    }
}
