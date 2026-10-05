//! NNP 思路：RTTI 驱动，运行时自举，零硬编码 RVA。
//!
//! * Linux（Itanium C++ ABI / ELF）：磁盘搜 `N2nt12SessionForNtE`，再按
//!   typeinfo -> vtable -> 实例 逐级反查。
//! * macOS（Itanium C++ ABI / Mach-O）：与 Linux 同理，但直接从内存搜
//!   `N2nt12SessionForNtE`（wrapper.node 是 universal 二进制，磁盘偏移映射不可靠）。
//! * Windows（MSVC C++ ABI / PE）：内存搜 `.?AVSessionForNt@nt@@`，定位
//!   RTTI Type Descriptor，再经 Complete Object Locator -> vtable -> 实例。
//!
//! 两条路径最终都落在同一个 `SessionForNt` 对象上，并按平台偏移读取
//! a2 / d2 / d2key 三个字段。

use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;

const CHUNK: usize = 1024 * 1024;

/// 私有堆区间上限（超过则跳过，避免读进超大保留区）。
#[cfg(windows)]
const MAX_HEAP_REGION: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_HEAP_REGION: u64 = 4 * 1024 * 1024;
#[cfg(target_os = "macos")]
const MAX_HEAP_REGION: u64 = 64 * 1024 * 1024;

/// Itanium ABI 的 mangled typeinfo 名（Linux/ELF）。
#[cfg(not(windows))]
const TYPEINFO_NAME: &[u8] = b"N2nt12SessionForNtE";
/// MSVC ABI 的 RTTI 类型描述符名（Windows/PE）。
#[cfg(windows)]
const TYPEINFO_NAME: &[u8] = b".?AVSessionForNt@nt@@";

// SessionForNt 对象里三个密钥字段的相对偏移。
//
// | ABI                    | 架构   | a2    | d2    | d2key |
// | ---------------------- | ------ | ----- | ----- | ----- |
// | MSVC (Windows)         | x86_64 | 0x158 | 0x170 | 0x188 |
// | Itanium (Linux/macOS)  | x86_64 | 0x150 | 0x168 | 0x180 |
// | Itanium (Linux/macOS)  | arm64  | 0x150 | 0x168 | 0x180 |
//
// arm64（Linux aarch64 / macOS Apple Silicon）与 x86_64 共用同一 Itanium 布局：
// 字段均按 8 字节对齐且无架构相关填充，故偏移一致。此处分架构显式列出，
// 便于日后只需针对单一架构单独校正。
macro_rules! key_offsets {
    ($a2:expr, $d2:expr, $d2key:expr) => {
        const A2_OFF: u64 = $a2;
        const D2_OFF: u64 = $d2;
        const D2KEY_OFF: u64 = $d2key;
    };
}

#[cfg(windows)]
key_offsets!(0x158, 0x170, 0x188);

#[cfg(all(not(windows), any(target_arch = "x86_64", target_arch = "aarch64")))]
key_offsets!(0x150, 0x168, 0x180);

// 兜底：其他架构沿用 Itanium 布局（未实测）。
#[cfg(all(
    not(windows),
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
key_offsets!(0x150, 0x168, 0x180);

#[derive(Clone, Debug)]
struct Region {
    start: u64,
    end: u64,
    perms: String,
    #[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
    off: u64,
    path: String,
}

/// 目标进程的可读内存句柄 + 读接口。
struct Mem {
    #[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
    pid: u32,
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(target_os = "macos")]
    task: libc::mach_port_t,
}

impl Mem {
    fn open(pid: u32) -> Option<Mem> {
        #[cfg(windows)]
        {
            let handle = unsafe {
                windows_sys::Win32::System::Threading::OpenProcess(
                    windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION
                        | windows_sys::Win32::System::Threading::PROCESS_VM_READ,
                    0,
                    pid,
                )
            };
            if handle.is_null() {
                return None;
            }
            Some(Mem { pid, handle })
        }
        #[cfg(target_os = "macos")]
        {
            let mut task: libc::mach_port_t = 0;
            // SAFETY: task_for_pid writes a send right into `task` on success. Root
            // (or a signed debugger) is required; hardened-runtime targets may deny it.
            let kr = unsafe { task_for_pid_ffi(self_mach_task(), pid as libc::pid_t, &mut task) };
            if kr != 0 || task == 0 {
                return None;
            }
            Some(Mem { pid, task })
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            Some(Mem { pid })
        }
    }

    fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        if size == 0 {
            return Some(Vec::new());
        }
        #[cfg(target_os = "linux")]
        {
            let mut buf = vec![0u8; size];
            let local = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: size,
            };
            let remote = libc::iovec {
                iov_base: addr as *mut libc::c_void,
                iov_len: size,
            };
            let n = unsafe {
                libc::process_vm_readv(self.pid as libc::pid_t, &local, 1, &remote, 1, 0)
            };
            if n != size as isize {
                return None;
            }
            Some(buf)
        }
        #[cfg(target_os = "macos")]
        {
            let mut data: libc::vm_offset_t = 0;
            let mut count: libc::mach_msg_type_number_t = 0;
            // SAFETY: mach_vm_read allocates `count` readable bytes at `data` on success.
            let kr =
                unsafe { mach_vm_read_ffi(self.task, addr, size as u64, &mut data, &mut count) };
            if kr != 0 {
                return None;
            }
            // SAFETY: mach handed us `count` valid bytes at `data`; copy out then free.
            let out = unsafe {
                let slice = std::slice::from_raw_parts(data as *const u8, count as usize);
                let v = slice.to_vec();
                libc::vm_deallocate(self_mach_task(), data, count as usize);
                v
            };
            Some(out)
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
            let mut buf = vec![0u8; size];
            let mut got = 0usize;
            // SAFETY: reads into a buffer of `size` bytes; `got` reflects the actual count.
            let ok = unsafe {
                ReadProcessMemory(
                    self.handle,
                    addr as *const _,
                    buf.as_mut_ptr() as *mut _,
                    size,
                    &mut got,
                )
            };
            if ok == 0 && got == 0 {
                return None;
            }
            buf.truncate(got);
            Some(buf)
        }
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "task_for_pid"]
    fn task_for_pid_ffi(
        target: libc::mach_port_t,
        pid: libc::pid_t,
        task: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;

    #[link_name = "mach_vm_read"]
    fn mach_vm_read_ffi(
        target: libc::mach_port_t,
        address: u64,
        size: u64,
        data: *mut libc::vm_offset_t,
        data_count: *mut libc::mach_msg_type_number_t,
    ) -> libc::kern_return_t;
}

#[cfg(windows)]
impl Drop for Mem {
    fn drop(&mut self) {
        // SAFETY: handle was created by OpenProcess and is non-null.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for Mem {
    fn drop(&mut self) {
        // SAFETY: release the send right obtained from task_for_pid.
        unsafe {
            mach_port_deallocate_ffi(self_mach_task(), self.task);
        }
    }
}

/// 当前任务的 mach port（`mach_task_self()` 在 libc 中已标记 deprecated）。
#[cfg(target_os = "macos")]
#[allow(deprecated)]
fn self_mach_task() -> libc::mach_port_t {
    // SAFETY: reads the cached global self task port.
    unsafe { libc::mach_task_self() }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    #[link_name = "mach_port_deallocate"]
    fn mach_port_deallocate_ffi(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

fn read_u64(mem: &Mem, addr: u64) -> Option<u64> {
    let d = mem.read(addr, 8)?;
    (d.len() >= 8).then(|| u64::from_le_bytes(d[0..8].try_into().unwrap()))
}

fn read_i64(mem: &Mem, addr: u64) -> Option<i64> {
    let d = mem.read(addr, 8)?;
    (d.len() >= 8).then(|| i64::from_le_bytes(d[0..8].try_into().unwrap()))
}

/// 读取字符串风格字段（非 Windows）。
///
/// `std::string` 的两种对象布局在盘面上都会出现，且与 CPU 架构相关
/// （Linux x86_64 与 Intel macOS 是 A 型，Apple Silicon 是 B 型），所以**不能按
/// 平台猜**，这里按字段实际内容做运行时探测：
///
/// * A 型（Linux / Intel macOS）：`+0` 容量、`+8` 长度、`+0x10` 数据指针。
/// * B 型（Apple Silicon macOS）：`+0` 数据指针、`+8` 长度、`+0x10` 容量/标志。
///
/// 两种布局的长度都在 `+8`，只有指针位置不同（`+0` 或 `+0x10`）。指针读数
/// 失败、长度越界或内容不像 key 字符串时判为无效，从而在两个候选中选出正确的
/// 一个。
fn read_qstring(mem: &dyn FieldMem, addr: u64) -> Option<Vec<u8>> {
    #[cfg(windows)]
    {
        // MSVC 布局固定为 `+0` 长度、`+8` 指针。
        let sz = mem.u64_at(addr)?;
        let ptr = mem.u64_at(addr + 8)?;
        return mem.bytes_at(ptr, sz);
    }
    #[cfg(not(windows))]
    {
        // 长度两种布局一致，都放在 `+8`。
        let sz = mem.u64_at(addr + 8)?;
        // 依次探测两种指针位置，取更像 key 字符串的那个。
        let ptrs = [
            mem.u64_at(addr + 16)?, // A 型：指针在 +0x10
            mem.u64_at(addr)?,      // B 型：指针在 +0
        ];
        pick_best_field(&ptrs, sz, mem)
    }
}

/// `read_qstring` 需要的最小内存访问面；生产实现是 [`Mem`]，测试用假内存。
trait FieldMem {
    fn u64_at(&self, addr: u64) -> Option<u64>;
    /// 读取 `addr` 处恰好 `size` 字节，长度不符返回 `None`。
    fn bytes_at(&self, addr: u64, size: u64) -> Option<Vec<u8>>;
}

impl FieldMem for Mem {
    fn u64_at(&self, addr: u64) -> Option<u64> {
        read_u64(self, addr)
    }

    fn bytes_at(&self, addr: u64, size: u64) -> Option<Vec<u8>> {
        read_exact(self, addr, size)
    }
}

/// 从若干候选指针里挑出内容最像密钥字段的那个。
///
/// 这是运行时布局探测的核心：两种 `std::string` 布局只有数据指针位置不同，
/// 因此把两个候选指针都交给它，`mem` 负责按 `(ptr, len)` 取字节，返回值中
/// "像 key"分值最高者；都读不到则返回 `None`。
fn pick_best_field(ptrs: &[u64], size: u64, mem: &dyn FieldMem) -> Option<Vec<u8>> {
    if size == 0 || size > 4096 {
        return None;
    }
    let mut best: Option<(u32, Vec<u8>)> = None;
    for &ptr in ptrs {
        let Some(data) = mem.bytes_at(ptr, size) else {
            continue;
        };
        let score = key_like_score(&data);
        if best.as_ref().is_none_or(|(b, _)| score > *b) {
            best = Some((score, data));
        }
    }
    best.map(|(_, d)| d)
}

/// 读 `ptr` 处恰好 `size` 字节，长度不符视为无效。
fn read_exact(mem: &Mem, ptr: u64, size: u64) -> Option<Vec<u8>> {
    if ptr == 0 || size == 0 || size > 4096 {
        return None;
    }
    let data = mem.read(ptr, size as usize)?;
    (data.len() == size as usize).then_some(data)
}

/// 给候选原始字节打"像不像密钥字段"的分值。
///
/// a2 / d2 / d2key 都是可打印的十六进制 ASCII 串（d2key 为 32 位 hex，解出 16
/// 字节），故给全 hex ASCII 且偶数长度的最高分，可打印次之，其余最低。分值用于
/// 在极端情况下两个指针都可读时决出更合理的一个。
#[cfg_attr(windows, allow(dead_code))]
fn key_like_score(data: &[u8]) -> u32 {
    if data.is_empty() {
        return 0;
    }
    if !data.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        return 1;
    }
    let hex = data.len().is_multiple_of(2) && data.iter().all(|&b| b.is_ascii_hexdigit());
    if hex { 4 } else { 2 }
}

/// 在满足 pred 的区间里按 `align` 对齐地找 `pat`，返回绝对地址。
fn find_pattern(
    mem: &Mem,
    regions: &[Region],
    pat: &[u8],
    align: usize,
    pred: &dyn Fn(&Region) -> bool,
    limit: usize,
) -> Vec<u64> {
    let mut hits = Vec::new();
    if pat.is_empty() {
        return hits;
    }
    for r in regions {
        if !pred(r) {
            continue;
        }
        let mut pos = r.start;
        while pos < r.end {
            let want = std::cmp::min(CHUNK as u64, r.end - pos) as usize;
            if let Some(data) = mem.read(pos, want) {
                let mut i = 0usize;
                while i + pat.len() <= data.len() {
                    if data[i..i + pat.len()] == *pat {
                        hits.push(pos + i as u64);
                        if hits.len() >= limit {
                            return hits;
                        }
                    }
                    i += align.max(1);
                }
            }
            pos += want as u64;
        }
    }
    hits
}

fn find_qwords(
    mem: &Mem,
    regions: &[Region],
    value: u64,
    pred: &dyn Fn(&Region) -> bool,
    limit: usize,
) -> Vec<u64> {
    find_pattern(mem, regions, &value.to_le_bytes(), 8, pred, limit)
}

#[cfg(windows)]
fn find_dwords(
    mem: &Mem,
    regions: &[Region],
    value: u32,
    pred: &dyn Fn(&Region) -> bool,
    limit: usize,
) -> Vec<u64> {
    find_pattern(mem, regions, &value.to_le_bytes(), 4, pred, limit)
}

#[derive(Debug, Default)]
pub struct SessionInfo {
    pub base: u64,
    pub instance: u64,
    pub vtable: u64,
    pub vtable_rva: u64,
    pub a2: Option<Vec<u8>>,
    pub d2: Option<Vec<u8>>,
    pub d2key: Option<Vec<u8>>,
    pub d2key_hex: String,
}

/// 一组密钥字段的原始字节：a2 / d2 / d2key。
type KeyBytes = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = (b[i] as char).to_digit(16)?;
        let lo = (b[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// 枚举 Linux `/proc/<pid>/maps`。
#[cfg(target_os = "linux")]
fn parse_maps(pid: u32) -> Vec<Region> {
    let txt = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
    let mut out = Vec::new();
    for line in txt.lines() {
        let mut f = line.splitn(6, ' ');
        let Some(range) = f.next() else { continue };
        let Some(perms) = f.next() else { continue };
        let Some(off) = f.next() else { continue };
        let mut rest = f;
        // dev, inode, path（可能带空格，取剩余）
        let _dev = rest.next();
        let _inode = rest.next();
        let path = rest.next().unwrap_or("").trim().to_string();
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16)) else {
            continue;
        };
        let off = u64::from_str_radix(off, 16).unwrap_or(0);
        out.push(Region {
            start,
            end,
            perms: perms.to_string(),
            off,
            path,
        });
    }
    out
}

/// 枚举 macOS 虚拟内存区间（`proc_pidinfo` + `proc_regionfilename`），
/// 并标注 `wrapper.node` 模块区间。无需 `task_for_pid`。
#[cfg(target_os = "macos")]
fn parse_maps(pid: u32) -> Vec<Region> {
    const PROC_PIDREGIONINFO: libc::c_int = 7;
    const VM_PROT_READ: u32 = 0x1;
    const VM_PROT_WRITE: u32 = 0x2;
    const VM_PROT_EXECUTE: u32 = 0x4;
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcRegionInfo {
        pri_protection: u32,
        pri_max_protection: u32,
        pri_inheritance: u32,
        pri_flags: u32,
        pri_offset: u64,
        pri_behavior: u32,
        pri_user_wired_count: u32,
        pri_user_tag: u32,
        pri_pages_resident: u32,
        pri_pages_shared_now_private: u32,
        pri_pages_swapped_out: u32,
        pri_pages_dirtied: u32,
        pri_ref_count: u32,
        pri_shadow_depth: u32,
        pri_share_mode: u32,
        pri_private_pages_resident: u32,
        pri_shared_pages_resident: u32,
        pri_obj_id: u32,
        pri_depth: u32,
        pri_address: u64,
        pri_size: u64,
    }
    const _: () = assert!(size_of::<ProcRegionInfo>() == 96);

    let mut out = Vec::new();
    let mut addr: u64 = 0;
    for _ in 0..2_000_000 {
        // SAFETY: proc_pidinfo fills a correctly-sized ProcRegionInfo or returns <= 0.
        let mut info: ProcRegionInfo = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                PROC_PIDREGIONINFO,
                addr,
                &mut info as *mut _ as *mut libc::c_void,
                size_of::<ProcRegionInfo>() as libc::c_int,
            )
        };
        if rc <= 0 || info.pri_size == 0 {
            break;
        }
        let prot = info.pri_protection;
        if prot & VM_PROT_READ != 0 {
            let mut path = [0u8; 4096];
            // SAFETY: writes a NUL-terminated path (or nothing) into the buffer.
            let plen = unsafe {
                libc::proc_regionfilename(
                    pid as libc::c_int,
                    info.pri_address,
                    path.as_mut_ptr() as *mut libc::c_void,
                    path.len() as u32,
                )
            };
            let path_s = if plen > 0 {
                let end = path.iter().position(|&b| b == 0).unwrap_or(plen as usize);
                String::from_utf8_lossy(&path[..end]).into_owned()
            } else {
                String::new()
            };
            // share_mode: 1=COW,2=PRIVATE,3=EMPTY,6=PRIVATE_ALIASED,8=LARGE_PAGE
            // 视为「私有」；4=SHARED,5=TRUESHARED,7=SHARED_ALIASED 视为共享。
            let private = !matches!(info.pri_share_mode, 4 | 5 | 7);
            let perms = format!(
                "r{}{}{}",
                if prot & VM_PROT_WRITE != 0 { 'w' } else { '-' },
                if prot & VM_PROT_EXECUTE != 0 {
                    'x'
                } else {
                    '-'
                },
                if private { 'p' } else { 's' },
            );
            out.push(Region {
                start: info.pri_address,
                end: info.pri_address + info.pri_size,
                perms,
                off: info.pri_offset,
                path: path_s,
            });
        }
        let next = info.pri_address.saturating_add(info.pri_size);
        if next <= addr {
            break;
        }
        addr = next;
    }
    out
}

/// 枚举 Windows 虚拟内存区间，并标注 `wrapper.node` 模块区间。
#[cfg(windows)]
fn parse_maps(pid: u32) -> Vec<Region> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY, PAGE_READWRITE,
        PAGE_WRITECOPY, VirtualQueryEx,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    const READABLE: [u32; 6] = [
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    ];
    const EXEC: [u32; 3] = [
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    ];
    const WRITE: [u32; 3] = [PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE];

    fn wide_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    // wrapper.node 模块范围。
    let mut mod_base = 0u64;
    let mut mod_end = 0u64;
    // SAFETY: standard Toolhelp module snapshot.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap != INVALID_HANDLE_VALUE {
            let mut me: MODULEENTRY32W = std::mem::zeroed();
            me.dwSize = size_of::<MODULEENTRY32W>() as u32;
            let mut ok = Module32FirstW(snap, &mut me);
            while ok != 0 {
                if wide_to_string(&me.szModule).eq_ignore_ascii_case("wrapper.node") {
                    mod_base = me.modBaseAddr as u64;
                    mod_end = mod_base + me.modBaseSize as u64;
                    break;
                }
                ok = Module32NextW(snap, &mut me);
            }
            CloseHandle(snap);
        }
    }

    let mut out = Vec::new();
    // SAFETY: repeated VirtualQueryEx over the target address space.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        return out;
    }
    unsafe {
        let mut addr = 0usize;
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        while VirtualQueryEx(
            handle,
            addr as *const _,
            &mut mbi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        ) != 0
        {
            let base = mbi.BaseAddress as u64;
            let size = mbi.RegionSize as u64;
            let committed = mbi.State == MEM_COMMIT;
            let guarded = mbi.Protect & PAGE_GUARD != 0;
            let prot = mbi.Protect & 0xff;
            if committed && !guarded && size > 0 && READABLE.contains(&prot) {
                let exec = EXEC.contains(&prot);
                let write = WRITE.contains(&prot);
                let private = mbi.Type == MEM_PRIVATE;
                let perms = format!(
                    "r{}{}{}",
                    if write { 'w' } else { '-' },
                    if exec { 'x' } else { '-' },
                    if private { 'p' } else { 's' },
                );
                let (path, off) = if mod_base != 0 && base >= mod_base && base < mod_end {
                    ("wrapper.node".to_string(), base - mod_base)
                } else {
                    (String::new(), 0)
                };
                out.push(Region {
                    start: base,
                    end: base + size,
                    perms,
                    off,
                    path,
                });
            }
            let next = base.saturating_add(size);
            if next <= addr as u64 {
                break;
            }
            addr = next as usize;
        }
        CloseHandle(handle);
    }
    out
}

fn module_base(regions: &[Region]) -> Option<u64> {
    regions
        .iter()
        .filter(|r| r.path.contains("wrapper.node"))
        .map(|r| r.start)
        .min()
}

fn is_mod(r: &Region) -> bool {
    r.path.contains("wrapper.node")
}

/// 找到 typeinfo 名字在内存中的地址（Linux：磁盘 ELF；Windows 直接内存搜）。
#[cfg(target_os = "linux")]
fn find_typeinfo_name(_mem: &Mem, regions: &[Region], _base: u64) -> Option<u64> {
    let mods: Vec<Region> = regions.iter().filter(|r| is_mod(r)).cloned().collect();
    let mod_path = mods.first()?.path.clone();
    let elf = fs::read(&mod_path).ok()?;
    let mut name_file_off = None;
    let mut i = 0usize;
    while i + TYPEINFO_NAME.len() < elf.len() {
        if let Some(p) = elf[i..]
            .windows(TYPEINFO_NAME.len())
            .position(|w| w == TYPEINFO_NAME)
        {
            let off = i + p;
            if off == 0 || elf[off - 1] == 0 {
                name_file_off = Some(off as u64);
                break;
            }
            i = off + 1;
        } else {
            break;
        }
    }
    let fo = name_file_off?;
    for r in &mods {
        let size = r.end - r.start;
        if fo >= r.off && fo < r.off + size {
            return Some(r.start + (fo - r.off));
        }
    }
    None
}

#[cfg(windows)]
fn find_typeinfo_name(mem: &Mem, regions: &[Region], _base: u64) -> Option<u64> {
    let pred = |r: &Region| is_mod(r) && r.perms.contains('r');
    find_pattern(mem, regions, TYPEINFO_NAME, 1, &pred, 1)
        .into_iter()
        .next()
}

/// macOS：Mach-O 里字符串常量与 Linux 的 ELF 一样是连续的 mangled 名。
/// 取「前一字节为 NUL（或区间首）」的首次命中作为真正的类型名。
#[cfg(target_os = "macos")]
fn find_typeinfo_name(mem: &Mem, regions: &[Region], _base: u64) -> Option<u64> {
    let pred = |r: &Region| is_mod(r) && r.perms.contains('r');
    for r in regions.iter().filter(|r| pred(r)) {
        let mut pos = r.start;
        while pos < r.end {
            let want = std::cmp::min(CHUNK as u64, r.end - pos) as usize;
            if let Some(data) = mem.read(pos, want) {
                let mut i = 0usize;
                while i + TYPEINFO_NAME.len() <= data.len() {
                    if data[i..i + TYPEINFO_NAME.len()] == *TYPEINFO_NAME {
                        let prev_ok = if i == 0 {
                            pos == r.start
                        } else {
                            data[i - 1] == 0
                        };
                        if prev_ok {
                            return Some(pos + i as u64);
                        }
                    }
                    i += 1;
                }
            }
            pos += want as u64;
        }
    }
    None
}

#[cfg(windows)]
fn open_mem_error(pid: u32) -> String {
    format!(
        "无法打开 pid {pid} 的内存（OpenProcess 失败）。请在管理员终端运行，并确认 QQ 未提权/未受保护。"
    )
}

#[cfg(target_os = "linux")]
fn open_mem_error(pid: u32) -> String {
    format!(
        "无法打开 pid {pid} 的内存（process_vm_readv 失败）。请用 root 运行（或授予 CAP_SYS_PTRACE），\
         并检查 /proc/sys/kernel/yama/ptrace_scope 是否放行。"
    )
}

#[cfg(target_os = "macos")]
fn open_mem_error(pid: u32) -> String {
    format!(
        "无法打开 pid {pid} 的内存（task_for_pid 失败）。macOS 需满足：\n\
         1) 以 root 运行：`sudo ./qqshark scan`；\n\
         2) **关闭 SIP**：目标启用了强化运行时（hardened runtime，QQ 即如此），即便 root 也会被\n\
            taskgated 拒绝（kern_return=5）。关闭方式：重启进恢复模式执行 `csrutil disable` 后重启；\n\
         3) 若只是想抓包（capture），无需关闭 SIP，sudo 即可。"
    )
}

pub fn scan(pid: u32) -> anyhow::Result<SessionInfo> {
    let mem = Mem::open(pid).ok_or_else(|| anyhow::anyhow!("{}", open_mem_error(pid)))?;
    let regions = parse_maps(pid);

    let base = module_base(&regions)
        .ok_or_else(|| anyhow::anyhow!("未找到 wrapper.node 模块（pid={pid}）"))?;

    let name_rt = find_typeinfo_name(&mem, &regions, base).ok_or_else(|| {
        anyhow::anyhow!("在 wrapper.node 中未找到 typeinfo 名（客户端版本可能已变）")
    })?;
    #[cfg_attr(not(windows), allow(unused_variables))]
    let name_rva = name_rt - base;

    let is_mod_data = |r: &Region| is_mod(r) && r.perms.contains('r') && !r.perms.contains('x');
    let is_mod_text = |r: &Region| is_mod(r) && r.perms.contains('x');

    // 2. 由 typeinfo 找全部相关 vtable（各 ABI 不同）。
    let vtables: BTreeSet<u64>;

    #[cfg(not(windows))]
    {
        // name_slots 指向 name 的 qword => typeinfo = slot - 8
        let name_slots = find_qwords(&mem, &regions, name_rt, &is_mod_data, 16);
        let mut typeinfos = BTreeSet::new();
        for slot in name_slots {
            if slot >= 8 {
                typeinfos.insert(slot - 8);
            }
        }
        if typeinfos.is_empty() {
            anyhow::bail!("未能从 typeinfo 名反查到 typeinfo 对象");
        }
        let mut all_vt = BTreeSet::new();
        for &tinfo in &typeinfos {
            for slot in find_qwords(&mem, &regions, tinfo, &is_mod_data, 64) {
                if slot < 8 {
                    continue;
                }
                let vtable = slot + 8;
                let Some(o2t) = read_i64(&mem, slot - 8) else {
                    continue;
                };
                let Some(first_fn) = read_u64(&mem, vtable) else {
                    continue;
                };
                if !(-0x100000..=0x100000).contains(&o2t) {
                    continue;
                }
                let in_text = regions
                    .iter()
                    .any(|r| is_mod_text(r) && r.start <= first_fn && first_fn < r.end);
                if in_text {
                    all_vt.insert(vtable);
                }
            }
        }
        vtables = all_vt;
    }

    #[cfg(windows)]
    {
        // MSVC：TypeDescriptor 位于 name - 0x10；COL 里存的是该 TD 的 RVA（4 字节）。
        let td_rva = (name_rva - 0x10) as u32;
        let cols: BTreeSet<u64> = find_dwords(&mem, &regions, td_rva, &is_mod_data, 32)
            .into_iter()
            .filter_map(|p| p.checked_sub(0x0C))
            .collect();
        if cols.is_empty() {
            anyhow::bail!("未找到 RTTI Complete Object Locator");
        }
        let mut all_vt = BTreeSet::new();
        for &col in &cols {
            for slot in find_qwords(&mem, &regions, col, &is_mod_data, 64) {
                if slot < 8 {
                    continue;
                }
                let vtable = slot + 8;
                let Some(o2t) = read_i64(&mem, slot - 8) else {
                    continue;
                };
                let Some(first_fn) = read_u64(&mem, vtable) else {
                    continue;
                };
                if !(-0x1000000..=0x1000000).contains(&o2t) {
                    continue;
                }
                let in_text = regions
                    .iter()
                    .any(|r| is_mod_text(r) && r.start <= first_fn && first_fn < r.end);
                if in_text {
                    all_vt.insert(vtable);
                }
            }
        }
        vtables = all_vt;
    }

    if vtables.is_empty() {
        anyhow::bail!("未找到 vtable");
    }

    // 3. 扫私有堆寻找 vtable 指针 => 实例。
    let is_heap = |r: &Region| {
        if !(r.perms.starts_with("rw") && r.perms.ends_with('p')) {
            return false;
        }
        if is_mod(r)
            || r.path.contains("/opt/QQ/")
            || r.path.starts_with("[stack")
            || r.path.starts_with("[vdso]")
            || r.path.starts_with("[vvar]")
        {
            return false;
        }
        if !r.path.is_empty() && r.path != "[heap]" && !r.path.starts_with("[anon:") {
            return false;
        }
        (r.end - r.start) <= MAX_HEAP_REGION
    };

    let mut instances = BTreeSet::new();
    for &v in &vtables {
        for h in find_qwords(&mem, &regions, v, &is_heap, 64) {
            instances.insert(h);
        }
    }
    if instances.is_empty() {
        anyhow::bail!("未在堆中找到 SessionForNt 实例");
    }

    // 候选里挑一个密钥字段最完整的实例（对象常有多个子对象，先命中的可能字段为空）。
    let mut chosen: Option<(u64, u32, KeyBytes, Option<Vec<u8>>)> = None;
    for &inst in &instances {
        let fields = read_key_fields(&mem, inst);
        let (score, d2key) = score_key_bytes(&fields);
        if chosen.as_ref().is_none_or(|(_, best, _, _)| score > *best) {
            chosen = Some((inst, score, fields, d2key));
        }
        if score == KEY_BYTES_MAX_SCORE {
            break;
        }
    }
    let Some((instance, _, (a2, d2, d2key_raw), d2key)) = chosen else {
        anyhow::bail!("未找到有效的 SessionForNt 实例");
    };

    let vtable = read_u64(&mem, instance).unwrap_or_else(|| *vtables.iter().next().unwrap());
    let mut info = SessionInfo {
        base,
        instance,
        vtable,
        vtable_rva: vtable.saturating_sub(base),
        ..Default::default()
    };

    // 4. 读取三个密钥字段。
    info.a2 = a2.and_then(|s| {
        let t = String::from_utf8_lossy(&s).trim().to_string();
        hex_decode(&t).or(Some(s))
    });
    info.d2 = d2.and_then(|s| {
        let t = String::from_utf8_lossy(&s).trim().to_string();
        hex_decode(&t).or(Some(s))
    });
    if let Some(raw) = d2key_raw {
        let t = String::from_utf8_lossy(&raw).trim().to_string();
        info.d2key_hex = t;
        info.d2key = d2key;
    }

    Ok(info)
}

/// 一组密钥字段的满分：d2key 有效 2 分 + a2 可读 1 分 + d2 可读 1 分。
const KEY_BYTES_MAX_SCORE: u32 = 4;

/// 给一组 a2/d2/d2key 原始字节打分，并顺带解出 d2key。
///
/// d2key 能解出恰好 16 字节记 2 分，a2、d2 各自可读记 1 分。分越高说明这个
/// 实例越像一个真实、字段齐全的 `SessionForNt`。
fn score_key_bytes(fields: &KeyBytes) -> (u32, Option<Vec<u8>>) {
    let d2key = fields
        .2
        .as_ref()
        .map(|s| String::from_utf8_lossy(s).trim().to_string())
        .and_then(|t| hex_decode(&t));
    let mut score = 0u32;
    if d2key.as_ref().is_some_and(|k| k.len() == 16) {
        score += 2;
    }
    if fields.0.is_some() {
        score += 1;
    }
    if fields.1.is_some() {
        score += 1;
    }
    (score, d2key)
}

/// 读取实例的三个字符串字段：a2 / d2 / d2key（原始字节）。
fn read_key_fields(mem: &Mem, instance: u64) -> KeyBytes {
    (
        read_qstring(mem, instance + A2_OFF),
        read_qstring(mem, instance + D2_OFF),
        read_qstring(mem, instance + D2KEY_OFF),
    )
}

/// 自动找 QQ 进程 pid。
pub fn find_qq_pid() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        for entry in fs::read_dir("/proc").ok()? {
            let Ok(e) = entry else { continue };
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm"))
                && comm.trim() == "qq"
            {
                return Some(pid);
            }
        }
        None
    }
    #[cfg(windows)]
    {
        crate::platform::find_wrapper_node_pids()
            .ok()?
            .into_iter()
            .next()
    }
    #[cfg(target_os = "macos")]
    {
        crate::platform::find_wrapper_node_pids()
            .ok()?
            .into_iter()
            .next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_ok() {
        assert_eq!(hex_decode("4a4b").unwrap(), vec![0x4a, 0x4b]);
        assert_eq!(hex_decode("0a").unwrap(), vec![0x0a]);
    }

    #[test]
    fn hex_decode_rejects_bad() {
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn typeinfo_anchor_matches_abi() {
        assert!(
            TYPEINFO_NAME.ends_with(b"SessionForNtE")
                || TYPEINFO_NAME.ends_with(b"SessionForNt@nt@@")
        );
    }

    #[test]
    fn key_like_score_ranks_hex_over_raw() {
        // 32 位 hex（d2key 的形态）应得最高分。
        assert_eq!(key_like_score(b"3d2c69392a38707d762c7370654b3a4e"), 4);
        // 可打印但非 hex。
        assert_eq!(key_like_score(b"hello world"), 2);
        // 含不可打印字节。
        assert_eq!(key_like_score(&[0x00, 0x01, 0x02]), 1);
        assert_eq!(key_like_score(&[]), 0);
        // 奇数长度的 hex 串不算 hex。
        assert_eq!(key_like_score(b"abc"), 2);
    }

    /// 假内存：`words` 模拟字段对象本体，`blobs` 模拟指针指向的数据。
    #[derive(Default)]
    struct FakeMem {
        words: std::collections::HashMap<u64, u64>,
        blobs: std::collections::HashMap<u64, Vec<u8>>,
    }

    impl FakeMem {
        fn word(mut self, addr: u64, value: u64) -> Self {
            self.words.insert(addr, value);
            self
        }
        fn blob(mut self, addr: u64, data: &[u8]) -> Self {
            self.blobs.insert(addr, data.to_vec());
            self
        }
    }

    impl FieldMem for FakeMem {
        fn u64_at(&self, addr: u64) -> Option<u64> {
            self.words.get(&addr).copied()
        }
        fn bytes_at(&self, addr: u64, size: u64) -> Option<Vec<u8>> {
            if size == 0 || size > 4096 {
                return None;
            }
            let b = self.blobs.get(&addr)?;
            (b.len() == size as usize).then(|| b.clone())
        }
    }

    // A 型（Linux x64 / Intel macOS）：+0 容量、+8 长度、+0x10 指针。
    // 回归自 Linux 实测：+0 是小整数容量，真正的指针在 +0x10。
    #[cfg(not(windows))]
    #[test]
    fn probe_picks_pointer_at_plus_16_layout_a() {
        let obj = 0x1000u64;
        let data_addr = 0x5_0000u64;
        let key = b"3d0734cfce071b5b101db5c32eadb53a";
        let mem = FakeMem::default()
            .word(obj, 0x91) // +0 容量（会被误当指针的小整数）
            .word(obj + 8, key.len() as u64) // +8 长度
            .word(obj + 16, data_addr) // +16 数据指针
            .blob(data_addr, key);
        assert_eq!(read_qstring(&mem, obj).as_deref(), Some(&key[..]));
    }

    // B 型（Apple Silicon）：+0 指针、+8 长度、+0x10 容量/标志（最高位有 0x8000…）。
    // 回归自你给的 mac ARM heapdump：真正的指针在 +0，+0x10 是无效地址。
    #[cfg(not(windows))]
    #[test]
    fn probe_picks_pointer_at_plus_0_layout_b() {
        let obj = 0x2000u64;
        let data_addr = 0x13c0367_9900u64;
        let key = b"3d2c69392a38707d762c7370654b3a4e";
        let mem = FakeMem::default()
            .word(obj, data_addr) // +0 数据指针
            .word(obj + 8, key.len() as u64) // +8 长度
            .word(obj + 16, 0x8000_0000_0000_0028) // +16 标志/容量，非法地址
            .blob(data_addr, key);
        assert_eq!(read_qstring(&mem, obj).as_deref(), Some(&key[..]));
    }

    // 两个候选指针都可读时，优先选内容像密钥（全 hex ASCII）的那个。
    #[cfg(not(windows))]
    #[test]
    fn probe_prefers_hex_when_both_readable() {
        let obj = 0x3000u64;
        let (len, bad_addr, good_addr) = (16u64, 0x6_0000u64, 0x6_1000u64);
        let mem = FakeMem::default()
            .word(obj, bad_addr) // +0 也能读，但不是 hex
            .word(obj + 8, len)
            .word(obj + 16, good_addr) // +16 才是真 key
            .blob(bad_addr, b"randombytes!!!!!")
            .blob(good_addr, b"3d0734cfce071b5b");
        assert_eq!(
            read_qstring(&mem, obj).as_deref(),
            Some(&b"3d0734cfce071b5b"[..])
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn probe_returns_none_when_no_candidate_readable() {
        let obj = 0x4000u64;
        let mem = FakeMem::default()
            .word(obj, 0x11) // 小整数，不是有效指针
            .word(obj + 8, 32)
            .word(obj + 16, 0x8000_0000_0000_0020); // 非法地址
        assert!(read_qstring(&mem, obj).is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn probe_rejects_oversized_length() {
        let obj = 0x5000u64;
        let mem = FakeMem::default()
            .word(obj, 0x60000)
            .word(obj + 8, 999_999) // 超过 4096 上限
            .word(obj + 16, 0x60000)
            .blob(0x60000, &[0u8; 8]);
        assert!(read_qstring(&mem, obj).is_none());
    }

    #[test]
    fn score_key_bytes_full_marks_for_valid_instance() {
        let fields = (
            Some(b"aabbccdd".to_vec()),
            Some(b"11223344".to_vec()),
            Some(b"3d2c69392a38707d762c7370654b3a4e".to_vec()), // 32 位 hex -> 16B
        );
        let (score, d2key) = score_key_bytes(&fields);
        assert_eq!(score, KEY_BYTES_MAX_SCORE);
        assert_eq!(d2key.unwrap().len(), 16);
    }

    #[test]
    fn score_key_bytes_empty_instance_scores_zero() {
        let (score, d2key) = score_key_bytes(&(None, None, None));
        assert_eq!(score, 0);
        assert!(d2key.is_none());
    }

    #[test]
    fn score_key_bytes_partial_when_d2key_unreadable() {
        let fields = (Some(b"aabb".to_vec()), None, Some(b"nothex".to_vec()));
        let (score, d2key) = score_key_bytes(&fields);
        assert_eq!(score, 1); // 只有 a2 可读
        assert!(d2key.is_none());
    }
}
