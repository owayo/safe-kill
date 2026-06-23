//! 端末出力を安全にするための表示用ユーティリティ

use std::path::Path;

/// 端末制御文字をエスケープ表記に置き換える
///
/// OS から取得したプロセス名・コマンドライン引数・パス・エラー文には、
/// 改行・ANSI escape（`\x1b[2J` で画面消去等）・双方向テキスト制御文字が
/// 含まれ得る。
/// それらを無加工で表示すると、出力行を上書き／消去する偽装表示や、
/// 端末状態の改ざんが可能。表示の安全性のため、印字可能文字以外は
/// `\xHH` または `\u{HHHH}` 形式にエスケープする。
pub fn sanitize_terminal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || is_format_control(c) => push_escaped_char(&mut out, c),
            c => out.push(c),
        }
    }
    out
}

/// 端末表示を偽装できる非印字の Unicode format 文字か判定する。
///
/// Rust 標準ライブラリには Unicode general category の `Cf` 判定 API がないため、
/// 表示順や文字結合に影響する代表的な format/control code point を明示的に扱う。
fn is_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{08E2}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// 制御文字を表示用エスケープに変換して追加する
fn push_escaped_char(out: &mut String, c: char) {
    use std::fmt::Write;

    let code = c as u32;
    if code <= 0xFF {
        let _ = write!(out, "\\x{code:02X}");
    } else {
        let _ = write!(out, "\\u{{{code:04X}}}");
    }
}

/// パスを端末表示用にサニタイズする
pub fn sanitize_path(path: &Path) -> String {
    sanitize_terminal(&path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_sanitize_terminal_passes_printable_ascii() {
        assert_eq!(sanitize_terminal("node --watch"), "node --watch");
    }

    #[test]
    fn test_sanitize_terminal_escapes_line_controls() {
        assert_eq!(
            sanitize_terminal("line1\nline2\rline3\tend"),
            "line1\\nline2\\rline3\\tend"
        );
    }

    #[test]
    fn test_sanitize_terminal_escapes_ansi_escape_sequence() {
        let input = "evil\x1b[2Jprocess";
        let sanitized = sanitize_terminal(input);
        assert_eq!(sanitized, "evil\\x1B[2Jprocess");
        assert!(!sanitized.contains('\x1b'));
    }

    #[test]
    fn test_sanitize_terminal_preserves_unicode_printable_chars() {
        assert_eq!(sanitize_terminal("プロセス😀"), "プロセス😀");
    }

    #[test]
    fn test_sanitize_terminal_escapes_other_control_chars() {
        let input = format!("a{}b{}c{}d", '\0', '\x07', '\x7f');
        assert_eq!(sanitize_terminal(&input), "a\\x00b\\x07c\\x7Fd");
    }

    #[test]
    fn test_sanitize_terminal_escapes_unicode_format_controls() {
        let input = "safe\u{202E}txt\u{2066}end";
        let sanitized = sanitize_terminal(input);

        assert_eq!(sanitized, "safe\\u{202E}txt\\u{2066}end");
        assert!(!sanitized.contains('\u{202E}'));
        assert!(!sanitized.contains('\u{2066}'));
    }

    #[test]
    fn test_sanitize_path_escapes_control_chars() {
        let path = PathBuf::from("/tmp/safe-kill\x1b[2J\nconfig.toml");
        let sanitized = sanitize_path(&path);

        assert!(sanitized.contains("\\x1B[2J"));
        assert!(sanitized.contains("\\nconfig.toml"));
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\n'));
    }
}
