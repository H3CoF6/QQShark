//! Linux 实现：扫描 `/proc/*/maps` 找加载了 `wrapper.node` 的进程。

use std::io::{self, BufRead};

const WRAPPER_NODE: &str = "wrapper.node";

/// 枚举 `/proc/<pid>/maps` 中含 `wrapper.node` 的 pid。
pub fn find_wrapper_node_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else { continue };
        if maps_has_wrapper(pid) {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

fn maps_has_wrapper(pid: u32) -> bool {
    let path = format!("/proc/{pid}/maps");
    let Ok(file) = std::fs::File::open(&path) else {
        return false;
    };
    for line in io::BufReader::new(file).lines() {
        let Ok(line) = line else { break };
        if line.contains(WRAPPER_NODE) {
            return true;
        }
    }
    false
}
