//! 原始抓包（libpcap），像 wireshark 一样读网卡/TUN 流量，TCP 重组后按 MSF
//! 帧签名切帧并解密。收发包用方框 + 顶部方向/seq/命令字标注输出。
//!
//! 结束方式：Ctrl+C（SIGINT）或 ESC 键。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;

use crate::codec;
use crate::frame;
use crate::tea;
use crate::ui::{self, Dir};

/// MSF 端口配置。
///
/// * `auto = true`：BPF 过滤器始终保持宽松，运行时持续按 MSF 帧签名发现端口，
///   在端口切换 / 多端口并存时动态纳管，不会锁死在单一端口上。
/// * `ports`：预置/固定的候选端口集合。可与 `auto` 叠加（既保留固定端口，
///   又持续发现新端口）；`auto = false` 时退化为只抓这些端口。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortSpec {
    pub auto: bool,
    pub ports: Vec<u16>,
}

impl PortSpec {
    /// 纯自动：持续按签名识别，无预置端口。
    #[cfg(test)]
    pub fn auto() -> Self {
        Self {
            auto: true,
            ports: Vec::new(),
        }
    }

    /// 单端口固定抓取（向后兼容旧 `-p 14000` 语义）。
    #[cfg(test)]
    pub fn fixed(port: u16) -> Self {
        Self {
            auto: false,
            ports: vec![port],
        }
    }

    /// 是否需要在内核层收紧 BPF 过滤（仅固定端口集合且不自动发现时）。
    pub fn tight_filter(&self) -> Option<String> {
        if self.auto {
            return None;
        }
        match self.ports.as_slice() {
            [] => None,
            [p] => Some(format!("tcp port {p}")),
            ps => Some(format!(
                "tcp port {}",
                ps.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(" or ")
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaptureOpts {
    pub iface: String,
    pub ports: PortSpec,
    pub d2key: Option<[u8; 16]>,
    pub write: Option<PathBuf>,
    pub hex: bool,
    /// 展开正文的 protobuf/JCE 树。
    pub expand: bool,
    pub count: Option<usize>,
}

static STOP: AtomicBool = AtomicBool::new(false);

/// 是否已请求停止（Ctrl+C / ESC）。
pub fn stop_requested() -> bool {
    STOP.load(Ordering::Relaxed)
}

fn request_stop() {
    STOP.store(true, Ordering::Relaxed);
}

/// 安装 Ctrl+C 处理器（优雅收尾而非直接杀进程）。
pub fn install_interrupt_handler() {
    #[cfg(unix)]
    {
        extern "C" fn on_sigint(_sig: libc::c_int) {
            request_stop();
        }
        // SAFETY: standard signal registration with a plain C handler.
        unsafe {
            libc::signal(
                libc::SIGINT,
                on_sigint as *const () as usize as libc::sighandler_t,
            );
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
        extern "system" fn on_ctrl(_kind: u32) -> i32 {
            request_stop();
            1
        }
        // SAFETY: registers a process-wide ctrl handler; the callback only sets an atomic flag.
        unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), 1);
        }
    }
}

/// 终端 raw 模式守卫：进入 cbreak（关闭 ICANON/ECHO），Drop 时恢复。
#[cfg(unix)]
struct RawGuard {
    saved: Option<libc::termios>,
}

#[cfg(unix)]
impl RawGuard {
    fn new() -> Self {
        // SAFETY: tcgetattr/tcsetattr on fd 0 with a properly sized termios.
        unsafe {
            if libc::isatty(0) != 1 {
                return Self { saved: None };
            }
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut term) != 0 {
                return Self { saved: None };
            }
            let saved = term;
            term.c_lflag &= !(libc::ICANON | libc::ECHO);
            term.c_cc[libc::VMIN] = 1;
            term.c_cc[libc::VTIME] = 0;
            if libc::tcsetattr(0, libc::TCSANOW, &term) != 0 {
                return Self { saved: None };
            }
            Self { saved: Some(saved) }
        }
    }
}

#[cfg(unix)]
impl Drop for RawGuard {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved {
            // SAFETY: restoring the termios captured in new().
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, saved);
            }
        }
    }
}

/// Windows 控制台 raw 模式守卫：关闭行缓冲/回显，Drop 时恢复。
#[cfg(not(unix))]
struct RawGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
    saved: Option<u32>,
}

#[cfg(not(unix))]
impl RawGuard {
    fn new() -> Self {
        use windows_sys::Win32::System::Console::{
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE,
            SetConsoleMode,
        };
        // SAFETY: queries and updates the console input mode.
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            if GetConsoleMode(handle, &mut mode) == 0 {
                return Self {
                    handle,
                    saved: None,
                };
            }
            let new_mode = mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
            if SetConsoleMode(handle, new_mode) == 0 {
                return Self {
                    handle,
                    saved: None,
                };
            }
            Self {
                handle,
                saved: Some(mode),
            }
        }
    }
}

#[cfg(not(unix))]
impl Drop for RawGuard {
    fn drop(&mut self) {
        if let Some(mode) = self.saved {
            // SAFETY: restores the console mode captured in new().
            unsafe {
                windows_sys::Win32::System::Console::SetConsoleMode(self.handle, mode);
            }
        }
    }
}

/// 监听 ESC / q 按键的线程（仅在 TTY/控制台生效）。
fn spawn_key_watcher() {
    #[cfg(unix)]
    {
        if unsafe { libc::isatty(0) } != 1 {
            return;
        }
        std::thread::spawn(|| {
            let mut b = [0u8; 1];
            loop {
                if stop_requested() {
                    return;
                }
                // SAFETY: single-byte read from stdin.
                let n = unsafe { libc::read(0, b.as_mut_ptr() as *mut libc::c_void, 1) };
                if n <= 0 {
                    return;
                }
                if b[0] == 0x1b || b[0] == b'q' || b[0] == b'Q' {
                    request_stop();
                    return;
                }
            }
        });
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, ReadConsoleA, STD_INPUT_HANDLE,
        };
        // SAFETY: probe stdin console mode; skip if not a console (e.g. redirected).
        let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let mut mode = 0u32;
        if handle.is_null() || unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
            return;
        }
        let handle = handle as usize;
        std::thread::spawn(move || {
            let handle = handle as windows_sys::Win32::Foundation::HANDLE;
            loop {
                if stop_requested() {
                    return;
                }
                let mut b = [0u8; 1];
                let mut read = 0u32;
                // SAFETY: single-byte console read into a 1-byte buffer.
                let ok = unsafe {
                    ReadConsoleA(
                        handle,
                        b.as_mut_ptr() as *mut _,
                        1,
                        &mut read,
                        std::ptr::null_mut(),
                    )
                };
                if ok == 0 || read == 0 {
                    return;
                }
                if b[0] == 0x1b || b[0] == b'q' || b[0] == b'Q' {
                    request_stop();
                    return;
                }
            }
        });
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    client: (IpAddr, u16),
    server: (IpAddr, u16),
}

#[derive(Default)]
struct DirBuf {
    started: bool,
    next: u32,
    buf: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
}

#[derive(Default)]
struct Flow {
    c2s: DirBuf,
    s2c: DirBuf,
    /// 最近一次收到该流数据包的秒级时间戳，用于清理陈旧流。
    last_seen: u32,
}

fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn feed(d: &mut DirBuf, seq: u32, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    if !d.started {
        d.started = true;
        d.next = seq;
    }
    let end = seq.wrapping_add(payload.len() as u32);
    if seq_before(seq, d.next) {
        let skip = d.next.wrapping_sub(seq) as usize;
        if skip >= payload.len() {
            return;
        }
        d.buf.extend_from_slice(&payload[skip..]);
        d.next = end;
        drain(d);
    } else if seq == d.next {
        d.buf.extend_from_slice(payload);
        d.next = end;
        drain(d);
    } else {
        d.pending.insert(seq, payload.to_vec());
    }
    if d.buf.len() > 4 * 1024 * 1024 {
        d.buf.clear();
    }
}

fn drain(d: &mut DirBuf) {
    while let Some((&k, _)) = d.pending.iter().next() {
        if k == d.next {
            let v = d.pending.remove(&k).unwrap();
            d.buf.extend_from_slice(&v);
            d.next = d.next.wrapping_add(v.len() as u32);
        } else if seq_before(k, d.next) {
            d.pending.remove(&k);
        } else {
            break;
        }
    }
}

/// 链路层头长度。
pub fn l2_offset(linktype: i32) -> usize {
    match linktype {
        12 | 101 => 0, // DLT_RAW
        1 => 14,       // Ethernet
        113 => 16,     // LINUX_SLL
        276 => 20,     // LINUX_SLL2
        0 | 108 => 4,  // NULL / LOOP
        _ => 14,
    }
}

/// 返回 (src, dst, 协议号, 传输层 payload)。
fn parse_ip(data: &[u8]) -> Option<(IpAddr, IpAddr, u8, &[u8])> {
    if data.is_empty() {
        return None;
    }
    match data[0] >> 4 {
        4 => {
            if data.len() < 20 {
                return None;
            }
            let ihl = ((data[0] & 0x0f) as usize) * 4;
            if ihl < 20 || data.len() < ihl {
                return None;
            }
            let proto = data[9];
            let src = IpAddr::from([data[12], data[13], data[14], data[15]]);
            let dst = IpAddr::from([data[16], data[17], data[18], data[19]]);
            Some((src, dst, proto, &data[ihl..]))
        }
        6 => {
            if data.len() < 40 {
                return None;
            }
            let proto = data[6];
            let mut s = [0u8; 16];
            s.copy_from_slice(&data[8..24]);
            let mut d = [0u8; 16];
            d.copy_from_slice(&data[24..40]);
            Some((IpAddr::from(s), IpAddr::from(d), proto, &data[40..]))
        }
        _ => None,
    }
}

struct TcpInfo {
    sport: u16,
    dport: u16,
    seq: u32,
    payload_off: usize,
}

fn parse_tcp(data: &[u8]) -> Option<TcpInfo> {
    if data.len() < 20 {
        return None;
    }
    let sport = u16::from_be_bytes([data[0], data[1]]);
    let dport = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let off = (((data[12] >> 4) as usize) * 4).max(20);
    if off > data.len() {
        return None;
    }
    Some(TcpInfo {
        sport,
        dport,
        seq,
        payload_off: off,
    })
}

/// 简易经典 pcap 写文件。
struct PcapWriter {
    f: std::fs::File,
}

impl PcapWriter {
    fn new(path: &PathBuf, linktype: i32) -> std::io::Result<Self> {
        let mut f = std::fs::File::create(path)?;
        let mut hdr = Vec::with_capacity(24);
        hdr.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        hdr.extend_from_slice(&2u16.to_le_bytes());
        hdr.extend_from_slice(&4u16.to_le_bytes());
        hdr.extend_from_slice(&0i32.to_le_bytes());
        hdr.extend_from_slice(&0u32.to_le_bytes());
        hdr.extend_from_slice(&65535u32.to_le_bytes());
        hdr.extend_from_slice(&(linktype as u32).to_le_bytes());
        f.write_all(&hdr)?;
        Ok(Self { f })
    }

    fn write(&mut self, sec: u32, usec: u32, data: &[u8], orig_len: u32) -> std::io::Result<()> {
        let mut ph = Vec::with_capacity(16);
        ph.extend_from_slice(&sec.to_le_bytes());
        ph.extend_from_slice(&usec.to_le_bytes());
        ph.extend_from_slice(&(data.len() as u32).to_le_bytes());
        ph.extend_from_slice(&orig_len.to_le_bytes());
        self.f.write_all(&ph)?;
        self.f.write_all(data)?;
        Ok(())
    }
}

/// 权限相关错误的中文提示。
fn open_error_hint(iface: &str, e: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        format!(
            "无法在接口 '{iface}' 上开启抓包：{e}\n\
             → 抓包需要 root 或 CAP_NET_RAW。请：\n\
             1) 直接提权重跑： `sudo ./qqshark capture -i {iface}`\n\
             2) 或给二进制放开规则（免 sudo）：\n\
                `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f ./qqshark)`\n\
             3) 接口一般无需手动指定：`-i auto`（默认）会自动选默认路由出口网卡；\n\
                确需指定时填物理网卡名（如 `-i wlan0` / `-i eth0`）即可。"
        )
    }
    #[cfg(target_os = "macos")]
    {
        format!(
            "无法在接口 '{iface}' 上开启抓包：{e}\n\
             → macOS 的 BPF 设备（/dev/bpf*）默认仅 root 可读，请用 sudo 重跑：\n\
             1) `sudo ./qqshark capture -i {iface}`（内存扫描也需 sudo）。\n\
             2) 想免 sudo：安装 Wireshark 的 “ChmodBPF” 并把自己加入 `access_bpf` 组，\n\
                或 `sudo chown $USER /dev/bpf*`（重启后失效）。\n\
             3) 接口名用 `en0`（Wi-Fi/有线）或 `lo0`（回环）；若走代理 TUN，流量可能在\n\
                `utun*` 上——仍建议直接抓物理网卡（en0）上的 TCP 14000 流量，无需 TUN。"
        )
    }
    #[cfg(windows)]
    {
        format!(
            "无法在接口 '{iface}' 上开启抓包：{e}\n\
             → Windows 抓包依赖 Npcap 驱动 + 管理员权限。请：\n\
             1) 以管理员身份重跑：在“管理员 PowerShell / 终端”里执行\n\
                `qqshark capture -i \"{iface}\"`（等价于 Linux 的 sudo）；\n\
             2) 安装/修复 Npcap（https://npcap.com/dist/）：安装时勾选\n\
                “Install Npcap in WinPcap API-compatible Mode”，确保\n\
                `wpcap.dll`、`Packet.dll` 位于 `C:\\Windows\\System32\\Npcap\\`\n\
                （或与本工具 exe 同目录）；\n\
             3) 接口名要填 Npcap 设备名（形如 `\\Device\\NPF_{{GUID}}` 或网卡描述）：\n\
                直接运行 `qqshark capture` 会列出全部可用设备；\n\
             4) 若只列出“回环适配器”：重装 Npcap 并勾选安装到所有网卡\n\
                （含 “Support loopback traffic capture”），或改选物理网卡；\n\
             5) 若走代理/TUN（Clash 等），选对应虚拟网卡，或直接抓物理卡的\n\
                TCP 443 流量即可（无需 TUN）。"
        )
    }
}

/// 检查是否具备抓包权限，给出可读诊断。
pub fn check_capture_privileges(iface: &str) -> bool {
    let elevated = crate::platform::is_elevated();
    #[cfg(target_os = "macos")]
    {
        if elevated {
            return true;
        }
        crate::ui::warn(&format!(
            "当前没有 root 权限，接口 '{iface}' 的 BPF 抓包会失败（/dev/bpf* 仅 root 可读）。\
             请用 `sudo ./qqshark capture -i {iface}` 重跑；若想免 sudo 可安装 Wireshark 的 ChmodBPF。"
        ));
        false
    }
    #[cfg(target_os = "linux")]
    {
        let has_cap = std::fs::read_to_string("/proc/self/status")
            .map(|s| {
                s.lines().any(|l| {
                    l.starts_with("CapEff:") && {
                        // 位 13 = CAP_NET_RAW, 位 12 = CAP_NET_ADMIN
                        let hex = l.split_whitespace().nth(1).unwrap_or("0");
                        u64::from_str_radix(hex, 16)
                            .map(|v| v & (1 << 13) != 0)
                            .unwrap_or(false)
                    }
                })
            })
            .unwrap_or(false);
        if elevated || has_cap {
            return true;
        }
        crate::ui::warn(&format!(
            "当前没有 root/CAP_NET_RAW 权限，抓包可能失败。接口 '{iface}' 需要提权或放开规则；\
             若失败请按提示执行 setcap 或 sudo。"
        ));
        false
    }
    #[cfg(windows)]
    {
        if elevated {
            return true;
        }
        crate::ui::warn(&format!(
            "当前没有管理员权限，接口 '{iface}' 的抓包大概率失败（等价于 Linux 的 root/CAP_NET_RAW）。\
             请在“管理员终端”重跑；若从未装过 Npcap，请先安装并勾选 WinPcap API 兼容模式。"
        ));
        false
    }
}

/// 设备名 / 描述是否匹配用户提供的接口名。
fn device_matches(d: &pcap::Device, iface: &str) -> bool {
    if d.name == iface || d.name.eq_ignore_ascii_case(iface) {
        return true;
    }
    if d.desc.as_deref() == Some(iface)
        || d.desc
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case(iface))
    {
        return true;
    }
    // 兜底：设备名 / 描述包含给定关键字（如 "WLAN"、"Ethernet"）。
    let needle = iface.to_ascii_uppercase();
    d.name.to_ascii_uppercase().contains(&needle)
        || d.desc
            .as_deref()
            .is_some_and(|s| s.to_ascii_uppercase().contains(&needle))
}

/// 自动挑选抓包设备：优先默认路由出口网卡，其次第一个非回环设备。
fn pick_auto_device(list: &[pcap::Device]) -> Option<usize> {
    let is_loopback = |d: &pcap::Device| {
        if d.flags.is_loopback() {
            return true;
        }
        let name = d.name.to_ascii_lowercase();
        let desc = d.desc.as_deref().unwrap_or("").to_ascii_lowercase();
        name.contains("loopback") || desc.contains("loopback")
    };

    #[cfg(windows)]
    {
        // 默认路由网卡的适配器 GUID → Npcap 设备名 `\Device\NPF_{GUID}`。
        for guid in crate::platform::default_route_guids() {
            let want = format!("\\Device\\NPF_{guid}");
            if let Some(i) = list.iter().position(|d| d.name.eq_ignore_ascii_case(&want)) {
                return Some(i);
            }
            if let Some(i) = list.iter().position(|d| {
                d.name
                    .to_ascii_uppercase()
                    .contains(&guid.to_ascii_uppercase())
            }) {
                return Some(i);
            }
        }
    }

    #[cfg(not(windows))]
    {
        // 默认路由出口网卡（Linux: /proc/net/route；macOS: route get default）。
        if let Some(iface) = crate::platform::default_route_iface()
            && let Some(i) = list
                .iter()
                .position(|d| d.name.eq_ignore_ascii_case(&iface))
        {
            return Some(i);
        }
    }

    list.iter().position(|d| !is_loopback(d))
}
fn dir_of(is_c2s: bool) -> Dir {
    if is_c2s { Dir::Tx } else { Dir::Rx }
}

/// 输出一个已解密的帧（方框：顶部方向/seq/cmd/proto/len，正文含展开树/hex）。
/// 一帧的展示视图（避免 emit_frame 参数过多）。
#[derive(Clone, Copy)]
struct FrameView<'a> {
    direction: Dir,
    proto: u32,
    et: u8,
    seq: u32,
    raw: &'a [u8],
    plain: Option<&'a [u8]>,
    decoded: Option<&'a frame::Decoded>,
}

fn emit_frame(opts: &CaptureOpts, v: &FrameView<'_>) {
    let FrameView {
        direction,
        proto,
        et,
        seq,
        raw: f,
        plain,
        decoded,
    } = *v;
    let cmd_s = decoded.and_then(|d| d.cmd.clone()).unwrap_or_else(|| {
        if direction == Dir::Rx {
            "(响应)".to_string()
        } else {
            "-".to_string()
        }
    });
    let bodylen = decoded.map(|d| d.body.len()).unwrap_or(0);
    let mut segments = vec![
        format!("seq={seq}"),
        format!("cmd={cmd_s}"),
        format!("proto={proto}"),
        format!("et={et}"),
        format!("len={}", f.len()),
    ];
    if decoded.is_some() {
        segments.push(format!("body={bodylen}B"));
    } else if plain.is_some() {
        segments.push("密文/明文可读".to_string());
    }

    let mut body: Vec<String> = Vec::new();
    // 默认：hexdump 预览（前 128 字节，截断；有明文看明文，否则看原始帧）。
    let content = plain.unwrap_or(f);
    let what = if plain.is_some() { "plain" } else { "raw" };
    body.push(format!(
        "{what} hexdump[0..128]：预览（截断；默认下方还有完整 hexdump，--only-head 可关闭）"
    ));
    body.extend(ui::hexdump_lines(content, 16, Some(128)));

    // 默认：完整 hexdump，不截断（`--only-head` 关闭）。
    if opts.hex {
        body.push(format!("{what} hexdump（完整 {} 字节）：", content.len()));
        body.extend(ui::hexdump_lines(content, 16, None));
    }

    // 默认：完整解析 protobuf/JCE 树，不截断（`--no-expand` 关闭）。
    if opts.expand {
        match decoded {
            Some(d) if !d.body.is_empty() => match codec::decode_auto(&d.body) {
                Some((kind, nodes, prefix)) => {
                    if let Some(p) = prefix {
                        body.push(format!(
                            "剥离 {} 字节{}长度前缀（值 {} = {}）",
                            p.width,
                            if p.endian == "be" { "大端" } else { "小端" },
                            p.value,
                            p.declared
                        ));
                    }
                    body.push(format!(
                        "正文 {} 字节，按 {kind:?} 完整展开：",
                        d.body.len()
                    ));
                    body.extend(codec::render_tree(kind, &nodes));
                }
                None => body.push("(正文无法按 protobuf/JCE 解析)".to_string()),
            },
            Some(_) => body.push("(正文为空)".to_string()),
            None => {
                if et != 1 {
                    body.push(format!(
                        "(et={et} 未加密帧，无 TEA 密文；正文见上方 raw hexdump)"
                    ));
                } else if plain.is_none() {
                    body.push("(et=1 但未提供 d2key，无法解密展开)".to_string());
                } else {
                    body.push("(未识别出 SSO 头，无法展开)".to_string());
                }
            }
        }
    }
    ui::packet_box(direction, &segments, &body, 60);
}

/// MSF 帧签名检测：在 TCP 负载里寻找 `[4B total][4B proto(12|13)][1B encryptType]`。
/// 用于 `-p auto` 时的动态端口识别（total 需合理、encryptType ∈ {0,1}）。
fn looks_like_msf(payload: &[u8]) -> bool {
    if payload.len() < 9 {
        return false;
    }
    for i in 0..=payload.len() - 9 {
        let proto = u32::from_be_bytes([
            payload[i + 4],
            payload[i + 5],
            payload[i + 6],
            payload[i + 7],
        ]);
        if proto != frame::PROTO_D2AUTH && proto != frame::PROTO_SIMPLE {
            continue;
        }
        let total =
            u32::from_be_bytes([payload[i], payload[i + 1], payload[i + 2], payload[i + 3]]);
        if (16..=1_000_000).contains(&total) && payload[i + 8] <= 1 {
            return true;
        }
    }
    false
}

/// 临时端口判定（IANA 动态/私有端口段），用于区分客户端源端口与服务端口。
fn is_ephemeral(port: u16) -> bool {
    port >= 32768
}

/// 在匹配 MSF 签名的包上判断其服务端口：客户端一般从临时端口发起，服务端口
/// 非临时；两侧都不是临时端口时取较小者兜底。
fn service_port_of(sport: u16, dport: u16) -> u16 {
    match (is_ephemeral(sport), is_ephemeral(dport)) {
        (true, false) => dport,
        (false, true) => sport,
        _ => sport.min(dport),
    }
}

/// 从单个 TCP 负载持续识别 MSF 服务端口：命中帧签名即返回该包的服务端口。
/// 每个包都会调用，因此端口切换 / 多端口并发时新端口都能被纳管。
fn detect_msf_service_port(payload: &[u8], sport: u16, dport: u16) -> Option<u16> {
    if looks_like_msf(payload) {
        Some(service_port_of(sport, dport))
    } else {
        None
    }
}

pub fn run(opts: CaptureOpts) -> anyhow::Result<()> {
    install_interrupt_handler();
    let _guard = RawGuard::new();
    spawn_key_watcher();

    // 解析接口：`auto`/空 → 自动选默认出口网卡；否则按名字或描述匹配。
    let auto = opts.iface.is_empty() || opts.iface.eq_ignore_ascii_case("auto");
    let device = match pcap::Device::list() {
        Ok(list) => {
            let picked = if auto {
                pick_auto_device(&list)
            } else {
                list.iter().position(|d| device_matches(d, &opts.iface))
            };
            match picked {
                Some(i) => {
                    if auto {
                        ui::info(&format!(
                            "自动选择接口：{} ({})",
                            list[i].name,
                            list[i].desc.as_deref().unwrap_or("-")
                        ));
                    }
                    list[i].clone()
                }
                None => {
                    ui::warn(&format!("未找到接口 '{}'，可用设备如下：", opts.iface));
                    for d in &list {
                        ui::field(&d.name, d.desc.as_deref().unwrap_or(""));
                    }
                    anyhow::bail!("请用上表中的设备名作为 -i/--iface 重试（或 -i auto 自动选择）");
                }
            }
        }
        Err(_) => pcap::Device::from(opts.iface.as_str()),
    };
    let device_label = match &device.desc {
        Some(d) => format!("{} ({})", device.name, d),
        None => device.name.clone(),
    };
    let mut cap = pcap::Capture::from_device(device)
        .context("open device")?
        .immediate_mode(true)
        .promisc(false)
        .snaplen(65535)
        .timeout(500)
        .open()
        .map_err(|e| anyhow::anyhow!(open_error_hint(&device_label, &e.to_string())))?;

    // 端口：动态端口集合。
    //
    // * `auto = true` → BPF 始终保持宽松的 `tcp`（绝不收敛），端口识别在用户态
    //   持续进行，因此抓包过程中端口切换 / 多端口并存都能被纳管。
    // * `auto = false` → 只抓给定端口，可安全收紧内核过滤。
    let mut ports: HashSet<u16> = opts.ports.ports.iter().copied().collect();
    let auto_port = opts.ports.auto;
    // 即便 auto，预置端口集合里若已给出候选也一并纳入。
    let filter = opts
        .ports
        .tight_filter()
        .unwrap_or_else(|| "tcp".to_string());
    cap.filter(&filter, true)
        .with_context(|| format!("set filter '{filter}'"))?;
    let linktype = cap.get_datalink();
    let lt = linktype.0;
    let l2 = l2_offset(lt);
    ui::section("抓包");
    ui::field("接口", &device_label);
    ui::field("过滤", &filter);
    let port_label = {
        let mut fixed: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        fixed.sort();
        if auto_port {
            if fixed.is_empty() {
                "auto（持续按流量识别，支持中途切换端口）".to_string()
            } else {
                format!("auto（预置 {}，并持续识别新端口）", fixed.join("/"))
            }
        } else if fixed.is_empty() {
            "auto".to_string()
        } else {
            fixed.join("/")
        }
    };
    ui::field("端口", &port_label);
    ui::field("链路层", &format!("linktype={lt} (l2={l2})"));
    ui::field(
        "d2key",
        &opts
            .d2key
            .map(hex::encode)
            .unwrap_or_else(|| "（未提供，帧内容不解密）".to_string()),
    );
    ui::info("按 Ctrl+C 或 ESC 结束抓包。");

    let mut writer = match &opts.write {
        Some(p) => Some(PcapWriter::new(p, lt).with_context(|| format!("create {p:?}"))?),
        None => None,
    };
    if let Some(p) = &opts.write {
        ui::info(&format!("原始 pcap 写入 -> {}", p.display()));
    }

    let mut flows: HashMap<FlowKey, Flow> = HashMap::new();
    let mut emitted = 0usize;
    let mut pkt_no = 0usize;
    // auto 模式下过滤器宽松，会看到大量无关流；定期清理陈旧流避免内存无界增长。
    const FLOW_TTL_SECS: u32 = 180;
    let mut last_sweep = 0u32;

    loop {
        if stop_requested() {
            ui::ok("收到结束信号，停止抓包。");
            break;
        }
        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                ui::warn(&format!("抓包错误：{e}"));
                break;
            }
        };
        pkt_no += 1;
        let sec = packet.header.ts.tv_sec as u32;
        let usec = packet.header.ts.tv_usec as u32;
        if sec.saturating_sub(last_sweep) >= 30 {
            last_sweep = sec;
            flows.retain(|_, f| sec.saturating_sub(f.last_seen) < FLOW_TTL_SECS);
        }
        if let Some(w) = writer.as_mut() {
            let _ = w.write(sec, usec, packet.data, packet.header.len);
        }

        let data = packet.data;
        if data.len() <= l2 {
            continue;
        }
        let ip = &data[l2..];
        let Some((src, dst, proto, l4)) = parse_ip(ip) else {
            continue;
        };
        if proto != 6 {
            continue;
        }
        let Some(tcp) = parse_tcp(l4) else { continue };
        let payload = &l4[tcp.payload_off..];

        // 持续端口识别：已纳管端口直接重组；auto 下未纳管端口先跑帧签名，
        // 命中即把服务端口加入集合（端口切换 / 多端口并存都能接住）。
        let mut known_dport = ports.contains(&tcp.dport);
        let mut known_sport = ports.contains(&tcp.sport);
        if !known_dport && !known_sport {
            if !auto_port {
                continue;
            }
            match detect_msf_service_port(payload, tcp.sport, tcp.dport) {
                Some(p) => {
                    let is_new = ports.insert(p);
                    if is_new && ports.len() == 1 {
                        ui::ok(&format!(
                            "自动识别 MSF 端口 = {p}（持续监测，切换端口会自动纳管）"
                        ));
                    } else if is_new {
                        ui::ok(&format!("发现新的 MSF 端口 = {p}（已纳管）"));
                    }
                    // 重新判定：让发现该端口的那一包也进入重组，避免预热丢包。
                    known_dport = ports.contains(&tcp.dport);
                    known_sport = ports.contains(&tcp.sport);
                }
                None => continue,
            }
        }

        // 服务端口的确定：恰好一侧命中集合时即以该侧为服务端口；两侧都命中
        // （两个端口都在集合内的罕见情形）取较小者，保证同一连接的两个方向
        // 得到一致的 flow key 与方向。
        let server_port = if known_dport && known_sport {
            tcp.sport.min(tcp.dport)
        } else if known_dport {
            tcp.dport
        } else {
            tcp.sport
        };

        let (key, is_c2s) = if tcp.dport == server_port {
            (
                FlowKey {
                    client: (src, tcp.sport),
                    server: (dst, tcp.dport),
                },
                true,
            )
        } else {
            (
                FlowKey {
                    client: (dst, tcp.dport),
                    server: (src, tcp.sport),
                },
                false,
            )
        };

        let flow = flows.entry(key.clone()).or_default();
        flow.last_seen = sec;
        let dir = if is_c2s { &mut flow.c2s } else { &mut flow.s2c };
        feed(dir, tcp.seq, payload);
        let frames = frame::extract_frames(&mut dir.buf);

        for f in frames {
            let direction = dir_of(is_c2s);
            let parsed = frame::parse_frame(&f);
            let proto_v = u32::from_be_bytes([f[4], f[5], f[6], f[7]]);
            let seq = f
                .get(8..12)
                .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
                .unwrap_or(0);
            let et = f.get(8).copied().unwrap_or(0);
            let plain: Option<Vec<u8>> = match (&parsed, opts.d2key) {
                (Some(mf), Some(key)) if mf.encrypt_type == 1 => {
                    Some(tea::decrypt(mf.cipher, &key))
                }
                _ => None,
            };
            let decoded = plain.as_deref().and_then(frame::decode_plain);
            emit_frame(
                &opts,
                &FrameView {
                    direction,
                    proto: proto_v,
                    et,
                    seq,
                    raw: &f,
                    plain: plain.as_deref(),
                    decoded: decoded.as_ref(),
                },
            );
            emitted += 1;
            if let Some(c) = opts.count
                && emitted >= c
            {
                ui::info(&format!("已达 count={c}，停止。packets={pkt_no}"));
                return Ok(());
            }
        }

        // 说明：auto 模式下 BPF 过滤器**永不收敛**，始终保留 `tcp`。端口识别与
        // 切换全部在用户态完成，这样抓包过程中端口变化（14000 → 80/443 …）
        // 以及多端口并发都不会漏包。
    }
    ui::ok(&format!("抓包结束。packets={pkt_no} frames={emitted}"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msf_signature_detects_frame() {
        let mut p = 32u32.to_be_bytes().to_vec();
        p.extend_from_slice(&13u32.to_be_bytes());
        p.push(1);
        p.extend_from_slice(&[0u8; 20]);
        assert!(looks_like_msf(&p));
        assert!(!looks_like_msf(&[0u8; 40]));
        assert!(!looks_like_msf(&[1, 2, 3]));
    }

    #[test]
    fn detect_service_port_ignores_client_ephemeral() {
        let mut p = 32u32.to_be_bytes().to_vec();
        p.extend_from_slice(&13u32.to_be_bytes());
        p.push(1);
        p.extend_from_slice(&[0u8; 20]);
        // 客户端 51000 → 服务端 14000：应识别出非临时端口 14000。
        assert_eq!(detect_msf_service_port(&p, 51000, 14000), Some(14000));
        // 反向（服务端回复）：仍应识别出 14000。
        assert_eq!(detect_msf_service_port(&p, 14000, 51000), Some(14000));
        // 非 MSF 负载不识别。
        assert_eq!(detect_msf_service_port(&[0u8; 40], 51000, 14000), None);
    }

    #[test]
    fn detect_service_port_handles_port_switch() {
        let mut p = 32u32.to_be_bytes().to_vec();
        p.extend_from_slice(&12u32.to_be_bytes());
        p.push(0);
        p.extend_from_slice(&[0u8; 20]);
        // 同一会话先走 14000，随后切到 443：两次都能识别（端口不断纳管）。
        assert_eq!(detect_msf_service_port(&p, 52001, 14000), Some(14000));
        assert_eq!(detect_msf_service_port(&p, 52002, 443), Some(443));
    }

    #[test]
    fn port_spec_tight_filter_only_when_fixed() {
        assert_eq!(PortSpec::auto().tight_filter(), None);
        assert_eq!(
            PortSpec::fixed(14000).tight_filter().as_deref(),
            Some("tcp port 14000")
        );
        let multi = PortSpec {
            auto: false,
            ports: vec![443, 80, 14000],
        };
        assert_eq!(
            multi.tight_filter().as_deref(),
            Some("tcp port 443 or 80 or 14000")
        );
        let mixed = PortSpec {
            auto: true,
            ports: vec![443],
        };
        assert_eq!(mixed.tight_filter(), None);
    }

    #[test]
    fn l2_offset_known_linktypes() {
        assert_eq!(l2_offset(12), 0);
        assert_eq!(l2_offset(1), 14);
        assert_eq!(l2_offset(113), 16);
        assert_eq!(l2_offset(276), 20);
    }

    #[test]
    fn parse_ipv4_header() {
        let mut p = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        p.extend_from_slice(&[0xde, 0xad]);
        let (src, dst, proto, l4) = parse_ip(&p).unwrap();
        assert_eq!(src, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(dst, "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(proto, 6);
        assert_eq!(l4, &[0xde, 0xad]);
    }

    #[test]
    fn parse_ipv6_header() {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, 17, 64];
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(&[0xffu8; 16]);
        p.extend_from_slice(&[0x01]);
        let (_, _, proto, l4) = parse_ip(&p).unwrap();
        assert_eq!(proto, 17);
        assert_eq!(l4, &[0x01]);
    }

    #[test]
    fn parse_tcp_fields() {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&14000u16.to_be_bytes());
        t[2..4].copy_from_slice(&38096u16.to_be_bytes());
        t[4..8].copy_from_slice(&100u32.to_be_bytes());
        t[12] = 5 << 4;
        t.extend_from_slice(&[1, 2, 3]);
        let info = parse_tcp(&t).unwrap();
        assert_eq!(info.sport, 14000);
        assert_eq!(info.dport, 38096);
        assert_eq!(info.seq, 100);
        assert_eq!(info.payload_off, 20);
    }

    #[test]
    fn seq_before_wraps() {
        assert!(seq_before(1, 2));
        assert!(!seq_before(2, 1));
        assert!(seq_before(0xffff_ffff, 0));
    }

    #[test]
    fn reassembly_in_order_and_out_of_order() {
        let mut d = DirBuf::default();
        feed(&mut d, 100, b"AB");
        feed(&mut d, 104, b"EF");
        feed(&mut d, 102, b"CD");
        assert_eq!(d.buf, b"ABCDEF");
    }

    #[test]
    fn reassembly_drops_retransmit() {
        let mut d = DirBuf::default();
        feed(&mut d, 100, b"AB");
        feed(&mut d, 100, b"AB");
        assert_eq!(d.buf, b"AB");
    }
}
