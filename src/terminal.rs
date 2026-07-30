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
            // バックスラッシュ自身をエスケープしないと、エスケープ表記が非単射になる。
            // 例: 実 ESC を含む "worker\x1b[2J" と、リテラル 6 文字 "\x1B[2J" を
            // 名前に持つ別プロセスの表示が完全に一致してしまい、どちらが本当に
            // 制御文字を含むのか読み手が判別できない（表示の偽造が成立する）。
            '\\' => out.push_str("\\\\"),
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
/// Unicode 17.0 で `Cf` に分類される format/control code point を明示的に扱う。
fn is_format_control(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
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
    fn test_sanitize_terminal_escapes_c1_control_introducer() {
        // U+009B は C1 制御の CSI（Control Sequence Introducer）で、ESC+'[' と
        // 等価の単独バイト制御シーケンス導入子。char::is_control() の C1 範囲
        // （0x7F..=0x9F）で捕捉され \x9B にエスケープされることを固定する。
        // 既存テストは C0（\x00/\x07）と DEL（\x7F）のみで C1 を検証していない。
        let input = "evil\u{009B}2Jprocess";
        let sanitized = sanitize_terminal(input);

        assert_eq!(sanitized, "evil\\x9B2Jprocess");
        assert!(!sanitized.contains('\u{009B}'));
    }

    #[test]
    fn test_sanitize_terminal_escapes_soft_hyphen_as_byte_escape() {
        // U+00AD SOFT HYPHEN は Cf（Format）だが、符号位置 0xAD は
        // char::is_control() の C1 範囲（0x7F..=0x9F）の外なので false になる。
        // is_format_control 側で捕捉され、かつ 0xFF 以下なので \xHH 形式で
        // エスケープされる（push_escaped_char の <=0xFF 分岐）ことを固定する。
        let input = "soft\u{00AD}hyphen";
        let sanitized = sanitize_terminal(input);

        assert_eq!(sanitized, "soft\\xADhyphen");
        assert!(!sanitized.contains('\u{00AD}'));
    }

    #[test]
    fn test_sanitize_terminal_escapes_arabic_prepended_concealment_marks() {
        // U+0890 / U+0891 は Unicode 14.0 で追加された Cf（Format）文字で、
        // U+0600..U+0605 や U+06DD と同じく後続文字を視覚的に隠す
        // prepended-concealment 系。char::is_control() では捕捉できないため、
        // is_format_control 側で確実にエスケープされることを固定する。
        let input = "amount\u{0890}1234\u{0891}end";
        let sanitized = sanitize_terminal(input);

        assert_eq!(sanitized, "amount\\u{0890}1234\\u{0891}end");
        assert!(!sanitized.contains('\u{0890}'));
        assert!(!sanitized.contains('\u{0891}'));
    }

    #[test]
    fn test_sanitize_terminal_escapes_supplementary_plane_format_controls() {
        // 0xFFFF を超える面（supplementary plane）の Cf 文字も確実にエスケープする。
        // - U+E0061: TAG LATIN SMALL LETTER A（U+E0020..=E007F の TAG 文字）。
        //   不可視のまま後続テキストへ紛れ込ませる表示偽装に悪用され得る。
        // - U+1D173: MUSICAL SYMBOL BEGIN BEAM（U+1D173..=1D17A）。
        // 符号位置が 0xFFFF を超えるため push_escaped_char の `\u{HHHH}` 分岐（5 桁）を通る。
        // 既存テストは U+202E / U+2066 / U+0890 など 4 桁以下しか検証しておらず、
        // supplementary plane の 5 桁エスケープ出力が固定されていなかった。
        let input = "tag\u{E0061}mid\u{1D173}end";
        let sanitized = sanitize_terminal(input);

        assert_eq!(sanitized, "tag\\u{E0061}mid\\u{1D173}end");
        assert!(!sanitized.contains('\u{E0061}'));
        assert!(!sanitized.contains('\u{1D173}'));
    }

    #[test]
    fn test_sanitize_terminal_escapes_all_unicode_17_format_controls() {
        // Unicode 17.0 の DerivedGeneralCategory.txt に定義された Cf 全範囲。
        // 代表値だけでなく全 170 コードポイントを検証し、範囲端や単独値の
        // 取りこぼしで不可視文字が端末出力へ残る回帰を防ぐ。
        const FORMAT_CONTROL_RANGES: &[(u32, u32)] = &[
            (0x00AD, 0x00AD),
            (0x0600, 0x0605),
            (0x061C, 0x061C),
            (0x06DD, 0x06DD),
            (0x070F, 0x070F),
            (0x0890, 0x0891),
            (0x08E2, 0x08E2),
            (0x180E, 0x180E),
            (0x200B, 0x200F),
            (0x202A, 0x202E),
            (0x2060, 0x2064),
            (0x2066, 0x206F),
            (0xFEFF, 0xFEFF),
            (0xFFF9, 0xFFFB),
            (0x110BD, 0x110BD),
            (0x110CD, 0x110CD),
            (0x13430, 0x1343F),
            (0x1BCA0, 0x1BCA3),
            (0x1D173, 0x1D17A),
            (0xE0001, 0xE0001),
            (0xE0020, 0xE007F),
        ];

        let mut tested = 0;
        for &(start, end) in FORMAT_CONTROL_RANGES {
            for code in start..=end {
                let ch = char::from_u32(code).expect("Cf のコードポイントは有効な文字であるべき");
                let expected = if code <= 0xFF {
                    format!("\\x{code:02X}")
                } else {
                    format!("\\u{{{code:04X}}}")
                };

                assert_eq!(
                    sanitize_terminal(&ch.to_string()),
                    expected,
                    "U+{code:04X} がエスケープされていない"
                );
                tested += 1;
            }
        }

        assert_eq!(tested, 170);
    }

    #[test]
    fn test_sanitize_terminal_escapes_backslash_to_stay_injective() {
        // エスケープ導入文字である `\` 自身をエスケープしないと変換が非単射になり、
        // 「実際に制御文字を含むプロセス名」と「リテラルのエスケープ文字列を名前に
        // 持つプロセス名」の表示が区別できなくなる（表示の偽造）。
        assert_eq!(sanitize_terminal(r"C:\tmp"), r"C:\\tmp");

        // 実 ESC を含む入力と、その表示表記をリテラルで持つ入力が衝突しないこと。
        let real_escape = sanitize_terminal("worker\u{1b}[2Jgone");
        let literal_text = sanitize_terminal(r"worker\x1B[2Jgone");
        assert_eq!(real_escape, r"worker\x1B[2Jgone");
        assert_eq!(literal_text, r"worker\\x1B[2Jgone");
        assert_ne!(
            real_escape, literal_text,
            "実制御文字とリテラル表記の表示が衝突してはいけない"
        );

        // 改行についても同様に衝突しないこと。
        assert_ne!(sanitize_terminal("a\nb"), sanitize_terminal(r"a\nb"));
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
