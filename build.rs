//! safe-kill のビルドスクリプト
//!
//! macOS 向けのビルドでだけ、SDK のヘッダ `<libproc.h>` / `<sys/proc_info.h>` から、
//! ポート検出の macOS 実装 (`src/port/macos.rs`) が使う libproc の FFI 定義を bindgen で生成し、
//! `$OUT_DIR/libproc_sys.rs` へ書き出す。macOS 以外のターゲットでは何もしない。
//!
//! 生成物には bindgen のレイアウト検査を残している。構造体の size / align と各フィールドの
//! offset を、SDK のヘッダを解釈した clang の値と const 評価で突き合わせるもので、
//! ずれていればコンパイルが失敗する。カーネルが書き込むバッファの形を取り違えたまま
//! 動くバイナリは作らない。

use std::env;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    // build.rs 自体はホスト向けにコンパイルされるので、ここでの `cfg!(target_os)` はホストを指す。
    // 生成するかどうかはビルド対象の OS (cargo が渡す CARGO_CFG_TARGET_OS) で決める。
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        libproc::generate();
    }
}

/// libproc の FFI 定義の生成
///
/// bindgen は Cargo.toml で `[target.'cfg(target_os = "macos")'.build-dependencies]` に置いている。
/// cargo は build-dependencies の target 条件をホストで評価する（ビルド対象ではない）ので、
/// bindgen が使えるのは「ホストが macOS のとき」であり、このモジュールの cfg と一致する。
#[cfg(target_os = "macos")]
mod libproc {
    use std::env;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// 生成物のファイル名（`src/port/macos.rs` の `include!` と対）
    const OUTPUT_FILE: &str = "libproc_sys.rs";

    pub fn generate() {
        // xcrun は DEVELOPER_DIR で使う Xcode / Command Line Tools を切り替える
        println!("cargo::rerun-if-env-changed=DEVELOPER_DIR");

        let sdk = sdk_path();
        let target = env::var("TARGET").expect("cargo が TARGET を渡していない");
        let clang_target = clang_target(&target);

        let bindings = bindgen::Builder::default()
            .header_contents(
                "safe_kill_libproc.h",
                "#include <libproc.h>\n#include <sys/proc_info.h>\n",
            )
            // レイアウトはビルド対象のアーキテクチャで計算させる
            // (arm64 のホストで x86_64-apple-darwin を作るときに arm64 の形で生成しない)
            .clang_arg(format!("--target={clang_target}"))
            .clang_arg("-isysroot")
            .clang_arg(&sdk)
            .rust_edition(bindgen::RustEdition::Edition2024)
            // 使うものだけを取り込む（構造体が参照する型は bindgen が自動で辿る）
            .allowlist_type("socket_fdinfo")
            .allowlist_type("proc_fdinfo")
            .allowlist_function("proc_listallpids")
            .allowlist_function("proc_pidinfo")
            .allowlist_function("proc_pidfdinfo")
            .allowlist_item(
                "PROC_PIDLISTFDS|PROC_PIDFDSOCKETINFO|PROX_FDTYPE_SOCKET\
                 |SOCKINFO_IN|SOCKINFO_TCP|TSI_S_LISTEN\
                 |AF_INET|AF_INET6|SOCK_STREAM|SOCK_DGRAM|IPPROTO_TCP|IPPROTO_UDP",
            )
            .layout_tests(true)
            // 読み込んだヘッダと参照した環境変数が変わったら作り直す
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()
            .unwrap_or_else(|e| {
                panic!("SDK ({sdk}) のヘッダから libproc の FFI 定義を生成できない: {e}")
            });

        let out_dir = PathBuf::from(env::var("OUT_DIR").expect("cargo が OUT_DIR を渡していない"));
        let output = out_dir.join(OUTPUT_FILE);
        bindings
            .write_to_file(&output)
            .unwrap_or_else(|e| panic!("{} へ書き出せない: {e}", output.display()));
    }

    /// macOS SDK のパスを xcrun で求める（Command Line Tools / Xcode の場所を決め打ちしない）
    fn sdk_path() -> String {
        let output = Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .unwrap_or_else(|e| {
                panic!("xcrun を起動できない ({e})。Xcode か Command Line Tools を入れてから再ビルドすること")
            });
        if !output.status.success() {
            panic!(
                "`xcrun --sdk macosx --show-sdk-path` が失敗した ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let path = String::from_utf8(output.stdout)
            .expect("xcrun が返した SDK のパスが UTF-8 ではない")
            .trim()
            .to_owned();
        if path.is_empty() || !Path::new(&path).is_dir() {
            panic!("xcrun が返した SDK のパスがディレクトリではない: {path:?}");
        }
        path
    }

    /// cargo のターゲット (`aarch64-apple-darwin` 等) を clang のターゲットへ変換する
    ///
    /// アーキテクチャ名だけが Rust と clang で異なる（Rust の `aarch64` は clang では `arm64`）。
    fn clang_target(rust_target: &str) -> String {
        let arch = rust_target
            .split('-')
            .next()
            .filter(|arch| !arch.is_empty())
            .unwrap_or_else(|| panic!("ターゲットの書式が想定外: {rust_target:?}"));
        let arch = if arch == "aarch64" { "arm64" } else { arch };
        format!("{arch}-apple-macosx")
    }
}

/// ホストが macOS 以外のときは bindgen が build-dependencies に入らない（上の説明を参照）
#[cfg(not(target_os = "macos"))]
mod libproc {
    pub fn generate() {
        panic!(
            "macOS 向けのビルドは macOS のホストでのみ行える \
             (libproc の FFI 定義を macOS SDK のヘッダから生成するため)"
        );
    }
}
