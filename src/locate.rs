//! 定位 QQ NT 数据目录与各账号数据库目录（移植自 `../x_key_scanner`）。

use std::path::{Path, PathBuf};

/// 全局（与账号无关）login.db 路径（相对数据根）。
pub fn login_db_path(root: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        root.join("nt_qq").join("global").join("nt_db").join("login.db")
    }
    #[cfg(not(windows))]
    {
        root.join("global").join("nt_db").join("login.db")
    }
}

/// 全局 login.db 的候选位置，最优先在前。Linux 存在两种布局，故返回两个。
pub fn login_db_candidates(root: &Path) -> Vec<PathBuf> {
    let primary = login_db_path(root);
    #[cfg(target_os = "linux")]
    {
        let alt = root.join("nt_qq").join("global").join("nt_db").join("login.db");
        if alt == primary { vec![primary] } else { vec![primary, alt] }
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![primary]
    }
}

/// 某账号的 `nt_db` 目录（保存 settings.db、nt_msg.db 等）。
///   * Windows: `<root>/<uin>/nt_qq/nt_db`
///   * Unix:    `<root>/nt_qq_<hash>/nt_db`，hash = md5(md5(uid) + "nt_kernel")
pub fn account_db_dir(root: &Path, uin: &str, uid: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = uid;
        root.join(uin).join("nt_qq").join("nt_db")
    }
    #[cfg(not(windows))]
    {
        let _ = uin;
        root.join(format!("nt_qq_{}", account_hash(uid))).join("nt_db")
    }
}

/// 账号目录哈希：`md5(md5(uid) + "nt_kernel")`，全部小写。
#[cfg_attr(windows, allow(dead_code))]
pub fn account_hash(uid: &str) -> String {
    use md5::{Digest, Md5};
    let inner = hex::encode(Md5::digest(uid.as_bytes()));
    let outer = Md5::digest(format!("{inner}nt_kernel").as_bytes());
    hex::encode(outer)
}

/// 检测当前平台的 QQ 数据根；无法确定时返回 None。
pub fn detect_data_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        detect_windows_root()
    }
    #[cfg(target_os = "linux")]
    {
        linux_config_qq()
    }
    #[cfg(target_os = "macos")]
    {
        Some(home_dir()?.join("Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ"))
    }
}

#[cfg(windows)]
fn detect_windows_root() -> Option<PathBuf> {
    const INI: &str = r"C:\Users\Public\Documents\Tencent\QQ\UserDataInfo.ini";
    let text = std::fs::read_to_string(INI).ok()?;
    let mut in_section = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_section = line.eq_ignore_ascii_case("[UserDataSet]");
            continue;
        }
        if in_section {
            let stripped = line
                .split_once('=')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("UserDataSavePath"))
                .map(|(_, v)| v.trim());
            if let Some(val) = stripped {
                if !val.is_empty() {
                    let p = PathBuf::from(val);
                    if p.file_name().is_some_and(|n| n.eq_ignore_ascii_case("Tencent Files")) {
                        return Some(p);
                    }
                    return Some(p.join("Tencent Files"));
                }
            }
        }
    }
    None
}

#[cfg(unix)]
pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| !p.as_os_str().is_empty())
}

/// 解析 `~/.config/QQ`，并容忍 `sudo`（此时 HOME=/root 无 login.db，回退到
/// `$SUDO_USER` 或 `/home/*`）。
#[cfg(target_os = "linux")]
fn linux_config_qq() -> Option<PathBuf> {
    let direct = home_dir().map(|h| h.join(".config").join("QQ"));
    if let Some(p) = &direct
        && has_login_db(p)
    {
        return Some(p.clone());
    }

    if let Some(p) = sudo_user_config_qq().or_else(scan_home_config_qq) {
        crate::ui::warn(&format!(
            "当前 HOME 下的 .config/QQ 无 login.db（可能是 sudo 运行）；改用 {} 。",
            p.display()
        ));
        return Some(p);
    }

    direct
}

#[cfg(target_os = "linux")]
fn has_login_db(root: &Path) -> bool {
    login_db_candidates(root).iter().any(|p| p.exists())
}

#[cfg(target_os = "linux")]
fn sudo_user_config_qq() -> Option<PathBuf> {
    let user = std::env::var_os("SUDO_USER")?;
    let user = user.to_str()?;
    if user.is_empty() || user == "root" {
        return None;
    }
    let candidate = PathBuf::from("/home").join(user).join(".config").join("QQ");
    has_login_db(&candidate).then_some(candidate)
}

#[cfg(target_os = "linux")]
fn scan_home_config_qq() -> Option<PathBuf> {
    for entry in std::fs::read_dir("/home").ok()?.flatten() {
        let candidate = entry.path().join(".config").join("QQ");
        if has_login_db(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_hash_is_deterministic_md5_chain() {
        // md5(md5("u_test") + "nt_kernel")
        let h = account_hash("u_test");
        assert_eq!(h.len(), 32);
        assert_eq!(h, account_hash("u_test"));
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn login_db_candidates_nonempty() {
        let root = Path::new("/tmp/QQ");
        let c = login_db_candidates(root);
        assert!(!c.is_empty());
        assert!(c[0].ends_with("login.db"));
    }
}
