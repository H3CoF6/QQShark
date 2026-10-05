//! qqshark —— QQ NT 协议取证工具：密钥扫描 + 全进程/UIN 映射 + 抓包解密。

mod art;
mod capture;
mod codec;
mod crypto;
mod frame;
mod locate;
mod login_db;
mod platform;
mod process;
mod scan;
mod tea;
mod ui;
mod wal_merge;

use std::io::Write;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "qqshark",
    version,
    about = "QQ NT 协议取证工具：密钥扫描 + 全进程/UIN 映射 + 原始抓包解密",
    long_about = "非侵入式逆向/取证 QQ NT 协议。\n\
    · scan    运行时扫描某 pid 的 a2/d2/d2key（RTTI 自举，零硬编码 RVA）\n\
    · procs   枚举全部在线 QQ 进程并映射到 UIN（login.db 解密 + 锁探测）\n\
    · capture 原始抓包 + MSF 帧解密（TUI 方框输出，默认完整 hexdump + 展开，Ctrl+C/ESC 结束）\n\
    · live    一条龙：先扫进程与 UIN，再自动取 d2key 抓包\n\
    · decode  在终端展开一段 hex：hexdump + TEA 解密（可选）+ protobuf/JCE 完整解析"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 运行时扫描 QQ 进程，取 a2/d2/d2key
    Scan(ScanArgs),
    /// 枚举全部在线 QQ 进程 + pid↔UIN 映射
    Procs(ProcsArgs),
    /// 原始抓包并按 MSF 帧解密，双向 TUI 输出（需 root/CAP_NET_RAW）
    Capture(CapArgs),
    /// 一条龙：先扫后抓
    Live(LiveArgs),
    /// 在终端展开一段 hex：hexdump + TEA 解密（可选）+ protobuf/JCE 完整解析
    Decode(DecodeArgs),
}

#[derive(clap::Args)]
struct DecodeArgs {
    /// hex 字符串（可含空格/冒号/0x 前缀）；`-` 表示从 stdin 读取
    input: String,
    /// 帧密文的 d2key（32 字符 hex）。提供则先按 MSF 帧 TEA 解密再解析
    #[arg(long)]
    d2key: Option<String>,
    /// 只显示 hexdump 预览（前 128 字节），不打印完整 hexdump
    #[arg(long = "only-head", visible_alias = "no-hex")]
    only_head: bool,
    /// 不展开正文的 protobuf/JCE 树（默认展开）
    #[arg(long = "no-expand")]
    no_expand: bool,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// QQ 进程 pid；省略则自动查找 comm==qq 或 choices 里唯一已登录进程
    #[arg(short, long)]
    pid: Option<u32>,
    /// 以 JSON 输出
    #[arg(long)]
    json: bool,
    /// QQ 数据目录（用于 pid↔UIN 映射；默认自动检测）
    #[arg(long)]
    data_root: Option<PathBuf>,
}

#[derive(clap::Args)]
struct ProcsArgs {
    /// QQ 数据目录（默认自动检测 ~/.config/QQ）
    #[arg(long)]
    data_root: Option<PathBuf>,
    /// 以 JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct CapArgs {
    /// 抓包接口：`auto`（默认）自动识别默认出口网卡；也可显式填 en0/wlan0/eth0
    /// 等（Windows 填 Npcap 设备名）
    #[arg(short, long, default_value = DEFAULT_IFACE)]
    iface: String,
    /// MSF 服务端口；`auto`（默认）/`0` = 按流量自动识别，也可写 80/443/14000 等
    #[arg(short, long, default_value = DEFAULT_PORT, value_parser = parse_port)]
    port: u16,
    /// d2key (32 字符 hex)；省略则用 --pid 自动扫描
    #[arg(long)]
    d2key: Option<String>,
    /// 自动扫描该 pid 的 d2key（省略则尝试唯一已登录进程）
    #[arg(long)]
    pid: Option<u32>,
    /// 数据目录
    #[arg(long)]
    data_root: Option<PathBuf>,
    /// 把原始包写入 pcap 文件
    #[arg(short, long)]
    write: Option<PathBuf>,
    /// 只显示 hexdump 预览（前 128 字节），不打印完整 hexdump（默认打印完整）
    #[arg(long = "only-head", visible_alias = "no-hex")]
    only_head: bool,
    /// 不展开正文的 protobuf/JCE 树（默认展开）
    #[arg(long = "no-expand")]
    no_expand: bool,
    /// 抓到 N 个帧后退出（调试用）
    #[arg(short = 'n', long)]
    count: Option<usize>,
}

#[derive(clap::Args)]
struct LiveArgs {
    /// 抓包接口：`auto`（默认）自动识别默认出口网卡；也可显式填 en0/wlan0/eth0
    /// 等（Windows 填 Npcap 设备名）
    #[arg(short, long, default_value = DEFAULT_IFACE)]
    iface: String,
    /// MSF 服务端口；`auto`（默认）/`0` = 按流量自动识别，也可写 80/443/14000 等
    #[arg(short, long, default_value = DEFAULT_PORT, value_parser = parse_port)]
    port: u16,
    /// 直接指定 pid（跳过交互选择）
    #[arg(long)]
    pid: Option<u32>,
    #[arg(long)]
    data_root: Option<PathBuf>,
    #[arg(short, long)]
    write: Option<PathBuf>,
    /// 只显示 hexdump 预览（前 128 字节），不打印完整 hexdump（默认打印完整）
    #[arg(long = "only-head", visible_alias = "no-hex")]
    only_head: bool,
    /// 不展开正文的 protobuf/JCE 树（默认展开）
    #[arg(long = "no-expand")]
    no_expand: bool,
    #[arg(short = 'n', long)]
    count: Option<usize>,
}

/// 端口解析：`auto`/`0` → 0（运行时按流量自动识别），否则普通 u16。
fn parse_port(v: &str) -> Result<u16, String> {
    if v.eq_ignore_ascii_case("auto") {
        return Ok(0);
    }
    v.parse::<u16>()
        .map_err(|_| format!("无效端口 '{v}'（应为 0..=65535 或 auto）"))
}

/// 默认抓包接口：各平台统一 `auto`（自动选默认出口网卡）。
const DEFAULT_IFACE: &str = "auto";

/// 默认端口：`auto`。QQ 的 MSF 服务端口由服务器下发，实测会变（见过 80/443/14000），
/// 所以默认按 MSF 帧签名在运行时自动识别；也可用 `-p <port>` 指定。
const DEFAULT_PORT: &str = "auto";
fn hex16(s: &str) -> anyhow::Result<[u8; 16]> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() != 32 {
        anyhow::bail!("d2key 必须是 32 字符 hex");
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = (b[i * 2] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("bad hex"))?;
        let lo = (b[i * 2 + 1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow::anyhow!("bad hex"))?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

fn hex_bytes(v: &Option<Vec<u8>>) -> String {
    v.as_ref().map(hex::encode).unwrap_or_default()
}

fn main() {
    ui::app_banner("QQ NT 协议取证工具 · 密钥扫描 / 进程映射 / 抓包解密");
    if let Err(e) = real_main() {
        ui::error(&format!("{e:#}"));
        std::process::exit(1);
    }
}

fn real_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    platform::report_privileges();
    match cli.cmd {
        Cmd::Scan(a) => cmd_scan(a),
        Cmd::Procs(a) => cmd_procs(a),
        Cmd::Capture(a) => cmd_capture(a),
        Cmd::Live(a) => cmd_live(a),
        Cmd::Decode(a) => cmd_decode(a),
    }
}

/// 宽松 hex 解析：去掉空白、冒号、`0x` 前缀。
fn hex_decode_loose(s: &str) -> anyhow::Result<Vec<u8>> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect::<String>()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .to_string();
    if clean.is_empty()
        || !clean.len().is_multiple_of(2)
        || !clean.chars().all(|c| c.is_ascii_hexdigit())
    {
        anyhow::bail!("无效的 hex（需要偶数个十六进制字符）");
    }
    Ok((0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
        .collect())
}

fn print_indented(lines: &[String]) {
    for line in lines {
        println!("  {line}");
    }
}

fn cmd_decode(a: DecodeArgs) -> anyhow::Result<()> {
    let raw = if a.input == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        s
    } else {
        a.input
    };
    let bytes = hex_decode_loose(&raw)?;
    // 默认完整 hexdump + 完整展开；`--only-head` / `--no-expand` 可分别关闭。
    let hex = !a.only_head;
    let expand = !a.no_expand;

    ui::section("输入");
    ui::field("字节数", &bytes.len().to_string());
    ui::field(
        "hexdump[0..128]",
        if hex {
            "预览（截断，完整见下方）"
        } else {
            "预览（截断，--only-head 仅预览）"
        },
    );
    print_indented(&ui::hexdump_lines(&bytes, 16, Some(128)));

    // 可选：TEA 解密。既能吃完整 MSF 帧（自动取其密文），也能吃裸密文。
    let mut plain = bytes.clone();
    if let Some(k) = &a.d2key {
        let key = hex16(k)?;
        let cipher: Vec<u8> = match frame::parse_frame(&bytes) {
            Some(mf) if mf.encrypt_type == 1 => {
                ui::info("识别为完整 MSF 帧，取其密文段解密。");
                mf.cipher.to_vec()
            }
            _ => {
                ui::info("按裸 TEA 密文解密。");
                bytes.clone()
            }
        };
        plain = tea::decrypt(&cipher, &key);
        ui::ok(&format!("TEA 解密完成，明文 {} 字节", plain.len()));
        ui::field("plain hexdump[0..128]", "预览（截断）");
        print_indented(&ui::hexdump_lines(&plain, 16, Some(128)));
    }

    // 默认：完整 hexdump（明文优先，否则原始字节），不截断。`--only-head` 关闭。
    if hex {
        let target = &plain;
        ui::section(&format!("hexdump（完整 {} 字节）", target.len()));
        print_indented(&ui::hexdump_lines(target, 16, None));
    }

    // 默认：完整解析 protobuf/JCE 树，不截断。`--no-expand` 关闭。
    if expand {
        ui::section("展开");
        // 1) 尝试当作 SsoPacker 明文取 body（仅在确实识别出 SSO 头时才走这条）
        if let Some(d) = frame::decode_plain(&plain)
            && (d.cmd.is_some() || !d.body.is_empty())
        {
            if let Some(cmd) = &d.cmd {
                ui::key_line("cmd", cmd);
            }
            ui::field("body", &format!("{} 字节", d.body.len()));
            if !d.body.is_empty() {
                match codec::decode_auto(&d.body) {
                    Some((kind, nodes, prefix)) => {
                        if let Some(p) = prefix {
                            ui::info(&format!(
                                "剥离 {} 字节{}长度前缀（值 {} = {}）",
                                p.width,
                                if p.endian == "be" { "大端" } else { "小端" },
                                p.value,
                                p.declared
                            ));
                        }
                        print_indented(&codec::render_tree(kind, &nodes));
                        return Ok(());
                    }
                    None => ui::warn("body 无法按 protobuf/JCE 解析，改试整体解析。"),
                }
            }
        }
        // 2) 整体按 protobuf/JCE
        match codec::decode_auto(&plain) {
            Some((kind, nodes, prefix)) => {
                if let Some(p) = prefix {
                    ui::info(&format!(
                        "剥离 {} 字节{}长度前缀（值 {} = {}）",
                        p.width,
                        if p.endian == "be" { "大端" } else { "小端" },
                        p.value,
                        p.declared
                    ));
                }
                print_indented(&codec::render_tree(kind, &nodes));
            }
            None => ui::warn("无法按 protobuf 或 JCE 解析该输入。"),
        }
    }
    Ok(())
}

fn cmd_scan(a: ScanArgs) -> anyhow::Result<()> {
    let pid = match a.pid {
        Some(p) => p,
        None => {
            // 优先用 procs 映射出的唯一已登录进程。
            let all = process::scan_all(a.data_root.clone());
            process::resolve_pid(&all.procs, None).or_else(|_| {
                scan::find_qq_pid()
                    .ok_or_else(|| anyhow::anyhow!("未找到 qq 进程，请用 --pid 指定"))
            })?
        }
    };
    ui::info(&format!("扫描 pid={pid} ..."));
    let info = scan::scan(pid)?;
    if a.json {
        println!("{}", serde_json_like(&info));
    } else {
        ui::section("会话密钥");
        ui::field("pid", &pid.to_string());
        ui::field("wrapper base", &format!("0x{:x}", info.base));
        ui::field("instance", &format!("0x{:x}", info.instance));
        ui::field(
            "vtable",
            &format!("0x{:x}  (RVA 0x{:x})", info.vtable, info.vtable_rva),
        );
        ui::key_line("a2", &hex_bytes(&info.a2));
        ui::key_line("d2", &hex_bytes(&info.d2));
        ui::key_line("d2key", &info.d2key_hex);
    }
    Ok(())
}

fn cmd_procs(a: ProcsArgs) -> anyhow::Result<()> {
    let all = process::scan_all(a.data_root);
    if a.json {
        println!("{}", procs_json(&all));
        return Ok(());
    }
    ui::section("进程 ↔ UIN 映射");
    if let Some(r) = &all.root {
        ui::field("数据目录", &r.display().to_string());
    }
    ui::field(
        "login.db",
        if all.accounts_loaded {
            "已解密"
        } else {
            "未读到（无 UIN 映射）"
        },
    );
    ui::field("login 账号数", &all.accounts.len().to_string());
    ui::field("在线 QQ 进程", &all.procs.len().to_string());
    if all.procs.is_empty() {
        ui::warn("未发现加载 wrapper.node 的 QQ 进程。QQ 是否在运行？");
    }
    for p in &all.procs {
        let role = if p.is_main { "主进程" } else { "占用者" };
        let uin = p.account_label();
        let tag = if p.logged_in {
            "已登录"
        } else {
            "未确认"
        };
        ui::field(
            &format!("pid {}", p.pid),
            &format!(
                "[{role}/{tag}] uin={uin} comm={}",
                if p.comm.is_empty() { "?" } else { &p.comm }
            ),
        );
    }
    Ok(())
}

/// 若存在多个候选，让用户从列表里选择 pid。
fn pick_pid(all: &process::ScanAll, wanted: Option<u32>) -> anyhow::Result<u32> {
    if let Some(p) = wanted {
        if platform::pid_alive(p) {
            return Ok(p);
        }
        anyhow::bail!("pid {p} 不存在或已退出");
    }
    // 唯一可推断时直接返回。
    if let Ok(p) = process::resolve_pid(&all.procs, None) {
        return Ok(p);
    }
    // 多个候选 → 交互选择。
    let candidates: Vec<&process::ProcInfo> = all.procs.iter().filter(|p| p.is_main).collect();
    if candidates.is_empty() {
        anyhow::bail!("未找到可用的 QQ 主进程，请用 --pid 指定");
    }
    ui::section("请选择要抓包的进程");
    for (i, p) in candidates.iter().enumerate() {
        ui::field(
            &format!("[{}]", i + 1),
            &format!(
                "pid={} uin={} {}",
                p.pid,
                p.account_label(),
                if p.logged_in {
                    "已登录"
                } else {
                    "未确认"
                }
            ),
        );
    }
    print!("  选择编号> ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let idx: usize = line.trim().parse().unwrap_or(1);
    let chosen = candidates
        .get(idx.saturating_sub(1))
        .ok_or_else(|| anyhow::anyhow!("无效编号 {idx}"))?;
    Ok(chosen.pid)
}

/// 扫描某 pid 的 d2key（若给出显式 hex 则优先）。
fn resolve_d2key(explicit: Option<&str>, pid: Option<u32>) -> anyhow::Result<Option<[u8; 16]>> {
    if let Some(s) = explicit {
        return Ok(Some(hex16(s)?));
    }
    let Some(pid) = pid else { return Ok(None) };
    // 扫描失败（如 macOS 未关 SIP、权限不足）不应中断抓包——无 d2key 也能看
    // 帧结构，只是不解密正文。
    let info = match scan::scan(pid) {
        Ok(info) => info,
        Err(e) => {
            ui::warn(&format!("自动扫描 d2key 失败，继续抓包（不解密）：{e:#}"));
            return Ok(None);
        }
    };
    match &info.d2key {
        Some(k) if k.len() == 16 => {
            ui::ok(&format!("自动扫描到 d2key = {}", info.d2key_hex));
            let mut arr = [0u8; 16];
            arr.copy_from_slice(k);
            Ok(Some(arr))
        }
        _ => {
            ui::warn("扫描到的 d2key 无效，帧内容将无法解密。");
            Ok(None)
        }
    }
}

fn cmd_capture(a: CapArgs) -> anyhow::Result<()> {
    capture::check_capture_privileges(&a.iface);
    // 未显式给出 d2key/pid 时，尝试从已登录进程自动补全 pid。
    let pid = match (a.d2key.as_ref(), a.pid) {
        (None, None) => {
            let all = process::scan_all(a.data_root.clone());
            process::resolve_pid(&all.procs, None).ok()
        }
        (_, p) => p,
    };
    let d2key = resolve_d2key(a.d2key.as_deref(), pid)?;
    if d2key.is_none() {
        ui::warn("未提供 d2key，帧内容将无法解密（仅显示长度/序号）。");
    }
    capture::run(capture::CaptureOpts {
        iface: a.iface,
        port: a.port,
        d2key,
        write: a.write,
        hex: !a.only_head,
        expand: !a.no_expand,
        count: a.count,
    })
}

fn cmd_live(a: LiveArgs) -> anyhow::Result<()> {
    capture::check_capture_privileges(&a.iface);
    ui::section("第一步 · 扫描进程与 UIN");
    let all = process::scan_all(a.data_root.clone());
    if let Some(r) = &all.root {
        ui::field("数据目录", &r.display().to_string());
    }
    ui::field(
        "login.db",
        if all.accounts_loaded {
            "已解密"
        } else {
            "未读到（无 UIN 映射）"
        },
    );
    for p in &all.procs {
        let role = if p.is_main { "主进程" } else { "占用者" };
        ui::field(
            &format!("pid {}", p.pid),
            &format!(
                "[{role}{}] uin={}",
                if p.logged_in { "/已登录" } else { "" },
                p.account_label()
            ),
        );
    }
    let pid = pick_pid(&all, a.pid)?;
    ui::ok(&format!("选用 pid={pid}"));

    ui::section("第二步 · 提取会话密钥");
    let info = scan::scan(pid)?;
    ui::key_line("d2key", &info.d2key_hex);
    let d2key = match &info.d2key {
        Some(k) if k.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(k);
            Some(arr)
        }
        _ => {
            ui::warn("d2key 无效，帧内容将无法解密。");
            None
        }
    };

    ui::section("第三步 · 抓包");
    capture::run(capture::CaptureOpts {
        iface: a.iface,
        port: a.port,
        d2key,
        write: a.write,
        hex: !a.only_head,
        expand: !a.no_expand,
        count: a.count,
    })
}

// 无 serde 依赖的极简 JSON 输出
fn serde_json_like(info: &scan::SessionInfo) -> String {
    format!(
        "{{\"base\":\"0x{:x}\",\"instance\":\"0x{:x}\",\"vtable\":\"0x{:x}\",\"vtable_rva\":\"0x{:x}\",\"a2\":\"{}\",\"d2\":\"{}\",\"d2key\":\"{}\"}}",
        info.base,
        info.instance,
        info.vtable,
        info.vtable_rva,
        hex_bytes(&info.a2),
        hex_bytes(&info.d2),
        info.d2key_hex
    )
}

fn procs_json(all: &process::ScanAll) -> String {
    let root = all
        .root
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let procs: Vec<String> = all
        .procs
        .iter()
        .map(|p| {
            format!(
                "{{\"pid\":{},\"comm\":\"{}\",\"main\":{},\"logged_in\":{},\"uin\":\"{}\",\"uid\":\"{}\",\"nick\":\"{}\"}}",
                p.pid,
                p.comm.replace('"', "'"),
                p.is_main,
                p.logged_in,
                p.uin.clone().unwrap_or_default(),
                p.uid.clone().unwrap_or_default(),
                p.nick.clone().unwrap_or_default().replace('"', "'"),
            )
        })
        .collect();
    format!(
        "{{\"root\":\"{}\",\"accounts_loaded\":{},\"procs\":[{}]}}",
        root,
        all.accounts_loaded,
        procs.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex16_parses_d2key() {
        let k = hex16("44773377403d28545d752a734e42432e").unwrap();
        assert_eq!(k[0], 0x44);
        assert_eq!(k[15], 0x2e);
        assert_eq!(k.len(), 16);
    }

    #[test]
    fn hex16_rejects_bad_length_and_chars() {
        assert!(hex16("abcd").is_err());
        assert!(hex16(&"z".repeat(32)).is_err());
    }
}
