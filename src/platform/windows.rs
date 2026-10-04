//! Windows 实现（移植自 `../x_key_scanner`，已在仓库中就绪，等待未来在 Windows
//! 上编译/实测）。仅保留 pid 探测与提权检测。

use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

const WRAPPER_NODE: &str = "wrapper.node";

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// 枚举所有加载了 `wrapper.node` 的进程。
pub fn find_wrapper_node_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    // SAFETY: standard Toolhelp snapshot walk; handle is closed before return.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut pe);
        while ok != 0 {
            if process_has_wrapper(pe.th32ProcessID) {
                pids.push(pe.th32ProcessID);
            }
            ok = Process32NextW(snap, &mut pe);
        }
        CloseHandle(snap);
    }
    pids.sort_unstable();
    Ok(pids)
}

fn process_has_wrapper(pid: u32) -> bool {
    // SAFETY: module snapshot for one pid; handle closed before return.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut me: MODULEENTRY32W = std::mem::zeroed();
        me.dwSize = size_of::<MODULEENTRY32W>() as u32;
        let mut found = false;
        let mut ok = Module32FirstW(snap, &mut me);
        while ok != 0 {
            if wide_to_string(&me.szModule).eq_ignore_ascii_case(WRAPPER_NODE) {
                found = true;
                break;
            }
            ok = Module32NextW(snap, &mut me);
        }
        CloseHandle(snap);
        found
    }
}

/// 当前进程 token 是否提权（管理员）。
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TokenElevation};
    const TOKEN_QUERY: u32 = 0x0008;

    // SAFETY: opens the current process token, queries elevation, closes it.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// 某个 pid 是否存活。
/// 读取进程名（exe 文件名，如 `QQ.exe`）。找不到返回 None。
pub fn comm_of(pid: u32) -> Option<String> {
    // SAFETY: standard process snapshot walk; handle closed before return.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut name = None;
        let mut ok = Process32FirstW(snap, &mut pe);
        while ok != 0 {
            if pe.th32ProcessID == pid {
                name = Some(wide_to_string(&pe.szExeFile));
                break;
            }
            ok = Process32NextW(snap, &mut pe);
        }
        CloseHandle(snap);
        name
    }
}

pub fn pid_alive(pid: u32) -> bool {
    // SAFETY: OpenProcess query, handle closed immediately.
    unsafe {
        let h = windows_sys::Win32::System::Threading::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if h.is_null() {
            false
        } else {
            CloseHandle(h);
            true
        }
    }
}

/// 解析默认路由所在的网卡 GUID（用于把 `\Device\NPF_{GUID}` 自动对上）。
///
/// 先按 IPv4 默认路由（`GetBestInterface` → 8.8.8.8）匹配，再按 IPv6 默认路由
/// （`GetBestInterfaceEx` → 2001:4860:4860::8888）匹配；返回形如
/// `{XXXXXXXX-....}`（大写）的适配器名，可拼成 Npcap 设备名。
pub fn default_route_guids() -> Vec<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GetBestInterface, GetBestInterfaceEx, GAA_FLAG_INCLUDE_PREFIX,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, AF_UNSPEC, SOCKADDR_IN6};

    // 目标索引：IPv4 8.8.8.8 / IPv6 2001:4860:4860::8888。
    let mut idx4: u32 = 0;
    // GetBestInterface 的地址参数用网络字节序。
    let dest4 = u32::from_be_bytes([8, 8, 8, 8]);
    // SAFETY: single out-param write.
    let r4 = unsafe { GetBestInterface(dest4, &mut idx4) };
    let idx4 = (r4 == 0).then_some(idx4);

    let mut sin6: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
    sin6.sin6_family = AF_INET6;
    // 2001:4860:4860::8888
    sin6.sin6_addr.u.Byte = [0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88];
    let mut idx6: u32 = 0;
    // SAFETY: SOCKADDR_IN6 outlives the call; out-param write.
    let r6 = unsafe {
        GetBestInterfaceEx(&sin6 as *const _ as *const _, &mut idx6)
    };
    let idx6 = (r6 == 0).then_some(idx6);

    // 枚举适配器，按索引取 GUID。
    let mut size: u32 = 16 * 1024;
    let mut buf = vec![0u8; size as usize];
    // SAFETY: two-call GetAdaptersAddresses pattern with a properly sized buffer.
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        )
    };
    if ret != 0 {
        buf = vec![0u8; size as usize];
        let ret2 = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if ret2 != 0 {
            return Vec::new();
        }
    }

    let mut out = Vec::new();
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        // SAFETY: walking the linked list returned by GetAdaptersAddresses.
        let a = unsafe { &*cur };
        let ifindex = unsafe { a.Anonymous1.Anonymous.IfIndex };
        let matches = idx4 == Some(ifindex) || idx6 == Some(a.Ipv6IfIndex);
        if matches && !a.AdapterName.is_null() {
            // SAFETY: AdapterName is a NUL-terminated ANSI string.
            let name = unsafe { std::ffi::CStr::from_ptr(a.AdapterName as *const i8) }
                .to_string_lossy()
                .to_ascii_uppercase();
            if !out.contains(&name) {
                out.push(name);
            }
        }
        cur = a.Next;
    }
    out
}