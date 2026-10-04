//! 账号级登录检测：把账号的 `nt_msg.db` 反查到持有进程（移植自 `../x_key_scanner`）。

use std::path::Path;

use crate::platform::db_lock::{DbHolder, probe_db_lock};

/// 账号登录时 QQ 保持打开的那个数据库文件。
const LOGIN_DB_FILE: &str = "nt_msg.db";

/// 探测账号的 `nt_msg.db`，返回持有它的进程。文件缺失或探测失败返回空。
pub fn probe_account_db_holders(db_dir: &Path) -> Vec<DbHolder> {
    probe_db_lock(&db_dir.join(LOGIN_DB_FILE)).unwrap_or_default()
}

/// 进程名是否属于 QQ NT：比较文件 stem（不区分大小写），接受 `QQ` 前缀的辅助进程。
pub fn is_qq_process_name(name: &str) -> bool {
    let stem = Path::new(name)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());
    let stem = stem.to_ascii_lowercase();
    stem == "qq" || stem.starts_with("qq")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qq_name_matching() {
        assert!(is_qq_process_name("qq"));
        assert!(is_qq_process_name("QQ.exe"));
        assert!(is_qq_process_name("/opt/QQ/qq"));
        assert!(is_qq_process_name("qq helper"));
        assert!(!is_qq_process_name("chrome"));
        assert!(!is_qq_process_name(""));
    }
}
