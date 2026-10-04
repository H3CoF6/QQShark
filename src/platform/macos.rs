//! macOS 实现（移植自 `../x_key_scanner`，无 macOS 实测设备，保持最小 FFI 面）。
//!
//!   * QQ 主进程发现：`NSRunningApplication` 按 bundle id `com.tencent.qq` 查询，
//!     或 headless 时枚举全部 pid 并匹配可执行路径后缀。
//!   * 内存读取（qqshark 的 `scan.rs`）另行处理；本模块只负责 pid 探测与进程名。

use std::io;

const MAXPATHLEN: usize = 1024;

unsafe extern "C" {
    fn proc_name(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
}

/// `pid` 的进程名（一次廉价的 libproc 调用）。
pub fn process_name(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; MAXPATHLEN];
    // SAFETY: buffer is MAXPATHLEN bytes; proc_name writes a NUL-terminated string.
    let n = unsafe {
        proc_name(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_void,
            MAXPATHLEN as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
    String::from_utf8(buf[..end].to_vec()).ok()
}

/// 枚举 QQ NT 主进程（加载 `wrapper.node` 的那个，即 QQ 主进程）。
pub fn find_wrapper_node_pids() -> io::Result<Vec<u32>> {
    Ok(get_all_qq_processes(None))
}

/// QQ 主进程枚举（移植自 nt_helper）。
pub fn get_all_qq_processes(headless: Option<bool>) -> Vec<u32> {
    if headless.unwrap_or(false) {
        libproc::qq_main_pids()
    } else {
        ns_running_application::qq_main_pids()
    }
}

/// libproc 全 pid 枚举 + 可执行路径后缀匹配（无需任何 entitlement，和 `ps` 同级）。
mod libproc {
    use std::ffi::{c_int, c_void};

    unsafe extern "C" {
        fn proc_listallpids(buffer: *mut c_int, buffersize: c_int) -> c_int;
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    }

    const QQ_MAIN_EXE_SUFFIX: &str = "/QQ.app/Contents/MacOS/QQ";

    pub fn qq_main_pids() -> Vec<u32> {
        let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Vec::new();
        }
        let mut pids = vec![0i32; count as usize + 16];
        let n = unsafe {
            proc_listallpids(
                pids.as_mut_ptr(),
                (pids.len() * size_of::<c_int>()) as c_int,
            )
        };
        if n <= 0 {
            return Vec::new();
        }
        pids.truncate(n as usize);
        pids.into_iter()
            .map(|pid| pid as u32)
            .filter(|pid| is_qq_main_process(*pid))
            .collect()
    }

    fn is_qq_main_process(pid: u32) -> bool {
        let mut buf = [0u8; 4096];
        let len = unsafe {
            proc_pidpath(
                pid as c_int,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
            )
        };
        if len <= 0 {
            return false;
        }
        let end = buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(len as usize)
            .min(len as usize);
        let Ok(path) = std::str::from_utf8(&buf[..end]) else {
            return false;
        };
        path.ends_with(QQ_MAIN_EXE_SUFFIX)
    }
}

/// `NSRunningApplication.runningApplicationsWithBundleIdentifier:` 直查主进程。
/// 手写最小 objc_msgSend FFI（零新依赖）。
mod ns_running_application {
    use std::ffi::{CStr, c_char, c_int, c_void};

    const QQ_BUNDLE_ID: &CStr = c"com.tencent.qq";
    const UTF8_ENCODING: u32 = 0x0800_0100;

    #[allow(clashing_extern_declarations)]
    #[link(name = "objc")]
    unsafe extern "C" {
        fn objc_getClass(name: *const c_char) -> *const c_void;
        fn sel_registerName(name: *const c_char) -> *const c_void;
        #[link_name = "objc_msgSend"]
        fn msg_send1(obj: *const c_void, sel: *const c_void, arg: *const c_void) -> *const c_void;
        #[link_name = "objc_msgSend"]
        fn msg_send0_usize(obj: *const c_void, sel: *const c_void) -> usize;
        #[link_name = "objc_msgSend"]
        fn msg_send0_i32(obj: *const c_void, sel: *const c_void) -> c_int;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFStringCreateWithCString(
            alloc: *const c_void,
            c_str: *const c_char,
            encoding: u32,
        ) -> *const c_void;
        fn CFRelease(cf: *const c_void);
    }

    #[link(name = "AppKit", kind = "framework")]
    unsafe extern "C" {}

    fn sel(name: &'static CStr) -> *const c_void {
        unsafe { sel_registerName(name.as_ptr()) }
    }

    pub fn qq_main_pids() -> Vec<u32> {
        let cls = unsafe { objc_getClass(c"NSRunningApplication".as_ptr()) };
        if cls.is_null() {
            return Vec::new();
        }

        let bundle_id = unsafe {
            CFStringCreateWithCString(std::ptr::null(), QQ_BUNDLE_ID.as_ptr(), UTF8_ENCODING)
        };
        if bundle_id.is_null() {
            return Vec::new();
        }
        let apps = unsafe {
            msg_send1(
                cls,
                sel(c"runningApplicationsWithBundleIdentifier:"),
                bundle_id,
            )
        };
        unsafe { CFRelease(bundle_id) };
        if apps.is_null() {
            return Vec::new();
        }

        let count = unsafe { msg_send0_usize(apps, sel(c"count")) };
        let object_at_index = sel(c"objectAtIndex:");
        let process_identifier = sel(c"processIdentifier");

        let mut pids = Vec::with_capacity(count);
        for index in 0..count {
            let app = unsafe { msg_send1(apps, object_at_index, index as *const c_void) };
            if app.is_null() {
                continue;
            }
            let pid = unsafe { msg_send0_i32(app, process_identifier) };
            if pid > 0 {
                pids.push(pid as u32);
            }
        }
        pids
    }
}
