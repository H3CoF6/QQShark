//! 跨平台「哪些进程占用着这个 QQ 数据库」探测（移植自 `../x_key_scanner`）。
//!
//! 账号登录时 QQ 主进程会保持其 SQLite 数据库打开（Windows）/ 持有 POSIX 写锁
//! （Linux/macOS）。把文件反查到持有者可一步确认账号已登录且拿到确切 pid。
//!
//! * **Windows**：Restart Manager（`rstrtmgr.dll`）枚举持有该文件的进程。
//! * **Linux/macOS**：`fcntl(F_GETLK)` 在 `l_pid` 返回写锁持有者；只读探测，不加锁。

use std::io;
use std::path::Path;

/// 一个打开数据库（Windows）或持有写锁（Unix）的进程。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbHolder {
    pub pid: u32,
    pub name: String,
}

/// 探测单个数据库文件，返回所有持有它的进程。文件不存在返回 `Ok(vec![])`。
pub fn probe_db_lock(db_path: &Path) -> io::Result<Vec<DbHolder>> {
    #[cfg(windows)]
    {
        windows::probe_db_lock(db_path)
    }
    #[cfg(not(windows))]
    {
        unix::probe_db_lock(db_path)
    }
}

#[cfg(windows)]
mod windows {
    use super::DbHolder;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA,
        ERROR_SESSION_CREDENTIAL_CONFLICT, ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::RestartManager::{
        CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
        RmStartSession,
    };

    fn decode_wide(buf: &[u16]) -> String {
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..len])
    }

    fn describe_err(label: &str, err: u32) -> String {
        let hint = match err {
            ERROR_FILE_NOT_FOUND => " (file missing)".to_string(),
            ERROR_ACCESS_DENIED => {
                " (无法在无权限下枚举持有者 —— 若 QQ 以提权运行，本工具也必须提权)".to_string()
            }
            ERROR_SESSION_CREDENTIAL_CONFLICT => {
                " (会话凭据冲突 —— 无法枚举该会话中的进程)".to_string()
            }
            _ => String::new(),
        };
        format!("{label} failed: error=0x{err:X}{hint}")
    }

    pub fn probe_db_lock(db_path: &Path) -> io::Result<Vec<DbHolder>> {
        if !db_path.exists() {
            return Ok(Vec::new());
        }

        let wide: Vec<u16> = db_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut session_key = [0u16; (CCH_RM_SESSION_KEY + 1) as usize];
        let mut session_handle: u32 = 0;

        // SAFETY: `session_key` is a NUL-terminated 33-WCHAR buffer that outlives
        // the call; `session_handle` is written by the API.
        let start_err = unsafe { RmStartSession(&mut session_handle, 0, session_key.as_mut_ptr()) };
        if start_err != ERROR_SUCCESS {
            return Err(io::Error::other(describe_err("RmStartSession", start_err)));
        }

        struct SessionGuard(u32);
        impl Drop for SessionGuard {
            fn drop(&mut self) {
                // SAFETY: handle came from RmStartSession and is still valid.
                unsafe {
                    let _ = RmEndSession(self.0);
                }
            }
        }
        let _guard = SessionGuard(session_handle);

        let resources = [wide.as_ptr()];
        // SAFETY: `resources` points to one NUL-terminated UTF-16 path.
        let reg_err = unsafe {
            RmRegisterResources(
                session_handle,
                1,
                resources.as_ptr(),
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
            )
        };
        if reg_err != ERROR_SUCCESS {
            return Err(io::Error::other(describe_err(
                "RmRegisterResources",
                reg_err,
            )));
        }

        let mut needed: u32 = 0;
        let mut count: u32 = 0;
        let mut reboot_reasons: u32 = 0;
        // SAFETY: null buffer + in/out counts + reboot-reason out param.
        let list_err = unsafe {
            RmGetList(
                session_handle,
                &mut needed,
                &mut count,
                std::ptr::null_mut(),
                &mut reboot_reasons,
            )
        };
        if list_err != ERROR_SUCCESS && list_err != ERROR_MORE_DATA {
            return Err(io::Error::other(describe_err("RmGetList(first)", list_err)));
        }
        if needed == 0 {
            return Ok(Vec::new());
        }

        for _ in 0..4 {
            // SAFETY: RM_PROCESS_INFO is plain-old-data; zeroed is a valid initial state.
            let mut infos = vec![unsafe { std::mem::zeroed::<RM_PROCESS_INFO>() }; needed as usize];
            count = needed;
            let err = unsafe {
                RmGetList(
                    session_handle,
                    &mut needed,
                    &mut count,
                    infos.as_mut_ptr(),
                    &mut reboot_reasons,
                )
            };
            if err == ERROR_SUCCESS {
                let holders = infos
                    .iter()
                    .take(count as usize)
                    .map(|info| DbHolder {
                        pid: info.Process.dwProcessId,
                        name: decode_wide(&info.strAppName),
                    })
                    .collect();
                return Ok(holders);
            }
            if err == ERROR_MORE_DATA && needed > count {
                continue;
            }
            return Err(io::Error::other(describe_err("RmGetList(second)", err)));
        }
        Err(io::Error::other("RmGetList did not converge"))
    }
}

#[cfg(not(windows))]
mod unix {
    use super::DbHolder;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    pub fn probe_db_lock(db_path: &Path) -> io::Result<Vec<DbHolder>> {
        if !db_path.exists() {
            return Ok(Vec::new());
        }
        let c_path = match std::ffi::CString::new(db_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "database path contains a NUL byte",
                ));
            }
        };

        // SAFETY: standard libc fcntl(F_GETLK) probe. O_RDONLY without
        // O_CREAT/O_TRUNC so the DB is never mutated; F_GETLK acquires nothing.
        unsafe {
            let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut fl: libc::flock = std::mem::zeroed();
            fl.l_type = libc::F_WRLCK as _;
            fl.l_whence = libc::SEEK_SET as _;
            fl.l_start = 0;
            fl.l_len = 0; // 0 == to EOF, i.e. the whole file
            let rc = libc::fcntl(fd, libc::F_GETLK, &mut fl);
            let err = io::Error::last_os_error();
            libc::close(fd);
            if rc != 0 {
                return Err(err);
            }
            if fl.l_type == libc::F_UNLCK as libc::c_short {
                return Ok(Vec::new());
            }
            let pid = fl.l_pid as u32;
            Ok(vec![DbHolder {
                pid,
                name: process_name(pid),
            }])
        }
    }

    fn process_name(pid: u32) -> String {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        }
        #[cfg(target_os = "macos")]
        {
            super::super::macos::process_name(pid).unwrap_or_default()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            String::new()
        }
    }
}
