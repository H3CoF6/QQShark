//! 平台抽象：QQ 主进程枚举、权限检测、数据库占用（锁）探测。
//!
//! 移植自 `../x_key_scanner`，去掉其内存读取 trait（qqshark 的 `scan.rs` 已自带
//! 跨平台实现：Linux 用 process_vm_readv，Windows 用 ReadProcessMemory），
//! 只保留与 pid→UIN 映射相关的能力。

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::find_wrapper_node_pids;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::find_wrapper_node_pids;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{find_wrapper_node_pids, process_name};

pub mod db_lock;
pub use db_lock::DbHolder;

mod login_status;
pub use login_status::{is_qq_process_name, probe_account_db_holders};

/// 当前进程是否具备读取其他进程内存所需的权限（Windows 管理员 / Unix root）。
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows::is_elevated()
    }
    #[cfg(unix)]
    {
        // SAFETY: geteuid is always safe.
        unsafe { libc::geteuid() == 0 }
    }
}

/// 一行、平台相关的提权重跑提示。
pub fn elevation_hint() -> &'static str {
    #[cfg(windows)]
    {
        "在管理员终端中重新运行本工具"
    }
    #[cfg(target_os = "macos")]
    {
        "使用 `sudo` 重新运行（内存扫描需要 task_for_pid，macOS 仅授予 root 或已签名的调试器）"
    }
    #[cfg(target_os = "linux")]
    {
        "使用 `sudo` 重新运行（或授予 CAP_SYS_PTRACE / CAP_NET_RAW），并检查 /proc/sys/kernel/yama/ptrace_scope"
    }
}

/// 探测权限并给出可读的诊断提示。返回是否提权。
pub fn report_privileges() -> bool {
    let elevated = is_elevated();
    if elevated {
        crate::ui::info("已获得 root/管理员权限。");
    } else {
        crate::ui::warn(&format!(
            "当前未以管理员/root 权限运行，内存扫描与抓包很可能失败。请{}。",
            elevation_hint()
        ));
    }
    elevated
}

/// 便携：某个 pid 当前是否存活。
pub fn pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(windows)]
    {
        windows::pid_alive(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos::process_name(pid).is_some()
    }
}

/// 读取进程可执行名（Unix 为 `/proc/<pid>/comm`；Windows 为 exe 文件名）。
pub fn comm_of(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(target_os = "macos")]
    {
        process_name(pid)
    }
    #[cfg(windows)]
    {
        windows::comm_of(pid)
    }
}
