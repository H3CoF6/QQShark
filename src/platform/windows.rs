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
