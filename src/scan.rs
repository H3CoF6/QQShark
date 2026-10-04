//! NNP 思路：RTTI 驱动，运行时自举，零硬编码 RVA。
//!
//! * Linux（Itanium C++ ABI / ELF）：磁盘搜 `N2nt12SessionForNtE`，再按
//!   typeinfo -> vtable -> 实例 逐级反查。
//! * Windows（MSVC C++ ABI / PE）：内存搜 `.?AVSessionForNt@nt@@`，定位
//!   RTTI Type Descriptor，再经 Complete Object Locator -> vtable -> 实例。
//!
//! 两条路径最终都落在同一个 `SessionForNt` 对象上，并按平台偏移读取
//! a2 / d2 / d2key 三个字段。

use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs;

const CHUNK: usize = 1024 * 1024;

/// 私有堆区间上限（超过则跳过，避免读进超大保留区）。
#[cfg(windows)]
const MAX_HEAP_REGION: u64 = 256 * 1024 * 1024;
#[cfg(not(windows))]
const MAX_HEAP_REGION: u64 = 4 * 1024 * 1024;

/// Itanium ABI 的 mangled typeinfo 名（Linux/ELF）。
#[cfg(not(windows))]
const TYPEINFO_NAME: &[u8] = b"N2nt12SessionForNtE";
/// MSVC ABI 的 RTTI 类型描述符名（Windows/PE）。
#[cfg(windows)]
const TYPEINFO_NAME: &[u8] = b".?AVSessionForNt@nt@@";

/// SessionForNt 对象里三个密钥字段的相对偏移。
#[cfg(windows)]
const A2_OFF: u64 = 0x158;
#[cfg(windows)]
const D2_OFF: u64 = 0x170;
#[cfg(windows)]
const D2KEY_OFF: u64 = 0x188;
#[cfg(not(windows))]
const A2_OFF: u64 = 0x150;
#[cfg(not(windows))]
const D2_OFF: u64 = 0x168;
#[cfg(not(windows))]
const D2KEY_OFF: u64 = 0x180;

#[derive(Clone, Debug)]
struct Region {
    start: u64,
    end: u64,
    perms: String,
    #[cfg_attr(windows, allow(dead_code))]
    off: u64,
    path: String,
}

/// 目标进程的可读内存句柄 + 读接口。
struct Mem {
    #[cfg_attr(windows, allow(dead_code))]
    pid: u32,
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
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
        #[cfg(not(windows))]
        {
            Some(Mem { pid })
        }
    }

    fn read(&self, addr: u64, size: usize) -> Option<Vec<u8>> {
        if size == 0 {
            return Some(Vec::new());
        }
        #[cfg(unix)]
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

#[cfg(windows)]
impl Drop for Mem {
    fn drop(&mut self) {
        // SAFETY: handle was created by OpenProcess and is non-null.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

fn read_u64(mem: &Mem, addr: u64) -> Option<u64> {
    let d = mem.read(addr, 8)?;
    (d.len() >= 8).then(|| u64::from_le_bytes(d[0..8].try_into().unwrap()))
}

fn read_i64(mem: &Mem, addr: u64) -> Option<i64> {
    let d = mem.read(addr, 8)?;
    (d.len() >= 8).then(|| i64::from_le_bytes(d[0..8].try_into().unwrap()))
}

/// 读取字符串风格字段。
///
/// * Windows：`+0` 为长度、`+8` 为数据指针。
/// * Linux：`+8` 为长度、`+0x10` 为数据指针。
fn read_qstring(mem: &Mem, addr: u64) -> Option<Vec<u8>> {
    #[cfg(windows)]
    let (sz, ptr) = (read_u64(mem, addr)?, read_u64(mem, addr + 8)?);
    #[cfg(not(windows))]
    let (sz, ptr) = (read_u64(mem, addr + 8)?, read_u64(mem, addr + 16)?);
    if ptr == 0 || sz == 0 || sz > 4096 {
        return None;
    }
    let data = mem.read(ptr, sz as usize)?;
    (data.len() >= sz as usize).then_some(data)
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
#[cfg(unix)]
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

/// 找到 typeinfo 名字在内存中的地址（Linux：磁盘 ELF；Windows：直接内存搜）。
#[cfg(not(windows))]
fn find_typeinfo_name(mem: &Mem, regions: &[Region], _base: u64) -> Option<u64> {
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

pub fn scan(pid: u32) -> anyhow::Result<SessionInfo> {
    let mem = Mem::open(pid).ok_or_else(|| {
        anyhow::anyhow!(
            "无法打开 pid {pid} 的内存（OpenProcess 失败）。请以管理员身份运行，并确认 QQ 未提权/未受保护。"
        )
    })?;
    let regions = parse_maps(pid);

    let base = module_base(&regions)
        .ok_or_else(|| anyhow::anyhow!("未找到 wrapper.node 模块（pid={pid}）"))?;

    let name_rt = find_typeinfo_name(&mem, &regions, base).ok_or_else(|| {
        anyhow::anyhow!("在 wrapper.node 中未找到 typeinfo 名（客户端版本可能已变）")
    })?;
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

    // 候选里挑一个密钥字段有效的实例（对象常有多个子对象，先命中的可能字段为空）。
    let mut chosen: Option<(u64, KeyBytes, Option<Vec<u8>>)> = None;
    for &inst in &instances {
        let fields = read_key_fields(&mem, inst);
        let d2key = fields
            .2
            .as_ref()
            .map(|s| String::from_utf8_lossy(s).trim().to_string())
            .and_then(|t| hex_decode(&t));
        let valid = d2key.as_ref().is_some_and(|k| k.len() == 16);
        if chosen.is_none() || valid {
            chosen = Some((inst, fields, d2key));
        }
        if valid {
            break;
        }
    }
    let Some((instance, (a2, d2, d2key_raw), d2key)) = chosen else {
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
}
