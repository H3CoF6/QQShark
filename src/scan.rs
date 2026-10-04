//! NNP 思路：RTTI 驱动，运行时自举，零硬编码 RVA。
//!
//! ```text
//! 磁盘 ELF 搜精确 typeinfo 名 (N2nt12SessionForNtE)
//!   -> 模块数据段找引用该字符串的 qword  => typeinfo 对象
//!   -> 再找引用 typeinfo 的 qword        => vtable[-1], vtable = slot + 8
//!      vtable[-2] = offset_to_top; ==0 为 primary vtable
//!   -> 扫匿名私有堆找 vtable 指针        => SessionForNt 实例
//!   -> 读 +0x150 a2 / +0x168 d2 / +0x180 d2key
//! ```

use std::collections::BTreeSet;
use std::fs;

const MAX_HEAP_REGION: u64 = 4 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;
const TYPEINFO_NAME: &[u8] = b"N2nt12SessionForNtE";

#[derive(Clone, Debug)]
struct Region {
    start: u64,
    end: u64,
    perms: String,
    off: u64,
    path: String,
}

fn read_mem(pid: u32, addr: u64, size: usize) -> Option<Vec<u8>> {
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: size };
    let remote =
        libc::iovec { iov_base: addr as *mut libc::c_void, iov_len: size };
    let n = unsafe {
        libc::process_vm_readv(
            pid as libc::pid_t,
            &local,
            1,
            &remote,
            1,
            0,
        )
    };
    if n != size as isize {
        return None;
    }
    Some(buf)
}

fn read_u64(pid: u32, addr: u64) -> Option<u64> {
    let d = read_mem(pid, addr, 8)?;
    Some(u64::from_le_bytes(d[0..8].try_into().unwrap()))
}

fn read_i64(pid: u32, addr: u64) -> Option<i64> {
    let d = read_mem(pid, addr, 8)?;
    Some(i64::from_le_bytes(d[0..8].try_into().unwrap()))
}

fn parse_maps(pid: u32) -> Vec<Region> {
    let txt = fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
    let mut out = Vec::new();
    for line in txt.lines() {
        let mut f = line.splitn(6, ' ');
        let Some(range) = f.next() else { continue };
        let Some(perms) = f.next() else { continue };
        let Some(off) = f.next() else { continue };
        let mut rest = f;
        // dev, inode, path (可能带空格，取剩余)
        let _dev = rest.next();
        let _inode = rest.next();
        let path = rest.next().unwrap_or("").trim().to_string();
        let Some((s, e)) = range.split_once('-') else { continue };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16))
        else {
            continue;
        };
        let off = u64::from_str_radix(off, 16).unwrap_or(0);
        out.push(Region { start, end, perms: perms.to_string(), off, path });
    }
    out
}

/// 在满足 pred 的区间里找 8 字节小端 == value 的绝对地址（8 对齐）。
fn find_qwords(
    pid: u32,
    regions: &[Region],
    value: u64,
    pred: &dyn Fn(&Region) -> bool,
    limit: usize,
) -> Vec<u64> {
    let pat = value.to_le_bytes();
    let mut hits = Vec::new();
    for r in regions {
        if !pred(r) {
            continue;
        }
        let mut pos = r.start;
        while pos < r.end {
            let want = std::cmp::min(CHUNK as u64, r.end - pos) as usize;
            if let Some(data) = read_mem(pid, pos, want) {
                let mut i = 0usize;
                while i + 8 <= data.len() {
                    if data[i..i + 8] == pat {
                        hits.push(pos + i as u64);
                        if hits.len() >= limit {
                            return hits;
                        }
                    }
                    i += 8;
                }
            }
            pos += want as u64;
        }
    }
    hits
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

fn read_qstring(pid: u32, addr: u64) -> Option<Vec<u8>> {
    let sz = read_u64(pid, addr + 8)?;
    let ptr = read_u64(pid, addr + 16)?;
    if ptr == 0 || sz == 0 || sz > 4096 {
        return None;
    }
    read_mem(pid, ptr, sz as usize)
}

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

pub fn scan(pid: u32) -> anyhow::Result<SessionInfo> {
    let regions = parse_maps(pid);
    let is_mod = |r: &Region| r.path.contains("wrapper.node");
    let mods: Vec<Region> = regions.iter().filter(|r| is_mod(r)).cloned().collect();
    if mods.is_empty() {
        anyhow::bail!("wrapper.node not found in /proc/{pid}/maps");
    }
    let base = mods.iter().map(|r| r.start - r.off).min().unwrap();
    let mod_path = mods[0].path.clone();

    let is_mod_data =
        |r: &Region| r.path.contains("wrapper.node") && r.perms.contains('r') && !r.perms.contains('x');
    let is_mod_text = |r: &Region| r.path.contains("wrapper.node") && r.perms.contains('x');

    // 1. 磁盘 ELF 搜精确 typeinfo 名
    let elf = fs::read(&mod_path)?;
    let mut name_file_off = None;
    let mut i = 0usize;
    while i + TYPEINFO_NAME.len() < elf.len() {
        if let Some(p) = elf[i..].windows(TYPEINFO_NAME.len()).position(|w| w == TYPEINFO_NAME) {
            let off = i + p;
            let left_ok = off == 0 || elf[off - 1] == 0;
            if left_ok {
                name_file_off = Some(off);
                break;
            }
            i = off + 1;
        } else {
            break;
        }
    }
    let name_file_off =
        name_file_off.ok_or_else(|| anyhow::anyhow!("typeinfo name not found in binary"))?;

    let file_off_to_rt = |fo: u64| -> u64 {
        for r in &mods {
            let size = r.end - r.start;
            if fo >= r.off && fo < r.off + size {
                return r.start + (fo - r.off);
            }
        }
        0
    };
    let name_rt = file_off_to_rt(name_file_off as u64);
    if name_rt == 0 {
        anyhow::bail!("failed to map typeinfo string to runtime");
    }

    // 2. 找引用 name 的 qword => typeinfo
    let name_slots = find_qwords(pid, &regions, name_rt, &is_mod_data, 16);
    let mut typeinfos = BTreeSet::new();
    for slot in name_slots {
        if slot >= 8 {
            typeinfos.insert(slot - 8);
        }
    }
    if typeinfos.is_empty() {
        anyhow::bail!("no typeinfo resolved");
    }

    // 3. 找引用 typeinfo 的 qword => vtable
    let mut all_vt = BTreeSet::new();
    let mut primaries = BTreeSet::new();
    for &tinfo in &typeinfos {
        for slot in find_qwords(pid, &regions, tinfo, &is_mod_data, 64) {
            if slot < 8 {
                continue;
            }
            let vtable = slot + 8;
            let o2t = match read_i64(pid, slot - 8) {
                Some(v) => v,
                None => continue,
            };
            let first_fn = match read_u64(pid, vtable) {
                Some(v) => v,
                None => continue,
            };
            if !(-0x100000..=0x100000).contains(&o2t) {
                continue;
            }
            let in_text = regions
                .iter()
                .any(|r| is_mod_text(r) && r.start <= first_fn && first_fn < r.end);
            if !in_text {
                continue;
            }
            all_vt.insert(vtable);
            if o2t == 0 {
                primaries.insert(vtable);
            }
        }
    }
    if primaries.is_empty() {
        anyhow::bail!("no primary vtable found");
    }

    // 4. 扫匿名私有堆找实例
    let is_heap = |r: &Region| {
        let p = r.path.as_str();
        if !(r.perms.starts_with("rw") && r.perms.ends_with('p')) {
            return false;
        }
        if p.contains("wrapper.node") || p.contains("/opt/QQ/") || p.starts_with("[stack")
            || p.starts_with("[vdso]") || p.starts_with("[vvar]")
        {
            return false;
        }
        if !p.is_empty() && p != "[heap]" && !p.starts_with("[anon:") {
            return false;
        }
        (r.end - r.start) <= MAX_HEAP_REGION
    };

    let mut instances = BTreeSet::new();
    for &v in &primaries {
        for h in find_qwords(pid, &regions, v, &is_heap, 64) {
            instances.insert(h);
        }
    }
    if instances.is_empty() {
        anyhow::bail!("no SessionForNt instance found in heap");
    }

    let mut info = SessionInfo {
        base,
        instance: *instances.iter().next().unwrap(),
        vtable: *primaries.iter().next().unwrap(),
        vtable_rva: *primaries.iter().next().unwrap() - base,
        ..Default::default()
    };

    let inst = info.instance;
    info.a2 = read_qstring(pid, inst + 0x150)
        .and_then(|s| {
            let t = String::from_utf8_lossy(&s).trim().to_string();
            hex_decode(&t).or(Some(s))
        });
    info.d2 = read_qstring(pid, inst + 0x168).and_then(|s| {
        let t = String::from_utf8_lossy(&s).trim().to_string();
        hex_decode(&t).or(Some(s))
    });
    let d2key_raw = read_qstring(pid, inst + 0x180);
    if let Some(raw) = d2key_raw {
        let t = String::from_utf8_lossy(&raw).trim().to_string();
        info.d2key_hex = t.clone();
        info.d2key = hex_decode(&t);
    }

    Ok(info)
}

/// 自动找 qq 进程 pid（comm == "qq"）。
pub fn find_qq_pid() -> Option<u32> {
    for entry in fs::read_dir("/proc").ok()? {
        let Ok(e) = entry else { continue };
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else { continue };
        if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm"))
            && comm.trim() == "qq"
        {
            return Some(pid);
        }
    }
    None
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
        assert!(hex_decode("abc").is_none()); // 奇数长度
        assert!(hex_decode("zz").is_none()); // 非 hex
    }

    #[test]
    fn typeinfo_anchor_matches_dynsym_name() {
        // 锚点就是未 strip 的 C++ 类型名
        assert!(TYPEINFO_NAME.ends_with(b"SessionForNtE"));
    }
}
