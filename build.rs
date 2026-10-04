//! 构建脚本：Windows 下让 `pcap` crate 能找到 wpcap 库。
//!
//! 优先使用环境变量 `NPCAP_SDK_DIR`（Npcap SDK 安装目录）；否则回退到仓库内
//! `vendor/npcap/x64`（随仓库携带的 x64 导入库）。非 Windows 平台不做任何事。

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=vendor/npcap/x64/wpcap.lib");
        if let Ok(dir) = std::env::var("NPCAP_SDK_DIR") {
            let lib = std::path::Path::new(&dir).join("Lib").join("x64");
            if lib.join("wpcap.lib").exists() {
                println!("cargo:rustc-link-search=native={}", lib.display());
                return;
            }
            if std::path::Path::new(&dir).join("wpcap.lib").exists() {
                println!("cargo:rustc-link-search=native={dir}");
                return;
            }
        }
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
        let vendored = std::path::Path::new(&manifest)
            .join("vendor")
            .join("npcap")
            .join("x64");
        if vendored.join("wpcap.lib").exists() {
            println!("cargo:rustc-link-search=native={}", vendored.display());
        }
    }
}
