//! 全进程扫描 + pid↔UIN 映射。
//!
//! 步骤（实现参考 `../x_key_scanner`）：
//!   1. 枚举加载了 `wrapper.node` 的 QQ 主进程 pid；
//!   2. 解密 login.db 得到全部缓存账号（uin/uid/nick）；
//!   3. 对每个账号探测 `nt_msg.db` 的持有进程（锁/占用）→ 已登录且拿到确切 pid；
//!   4. 汇总为 pid → 账号 的映射，供用户选择。

use std::collections::HashMap;
use std::path::PathBuf;

use crate::locate;
use crate::login_db::{self, Account};
use crate::platform::{self, DbHolder};
use crate::ui;

/// 一个在线 QQ 进程及其账号映射。
#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub comm: String,
    /// 加载了 wrapper.node（真正的 QQ 主进程）。
    pub is_main: bool,
    pub uin: Option<String>,
    pub uid: Option<String>,
    pub nick: Option<String>,
    /// 通过数据库占用探测确认处于登录态。
    pub logged_in: bool,
}

impl ProcInfo {
    pub fn account_label(&self) -> String {
        match (&self.uin, &self.nick) {
            (Some(u), Some(n)) if !n.is_empty() => format!("{u} ({n})"),
            (Some(u), _) => u.clone(),
            _ => "?".to_string(),
        }
    }
}

/// 一次全量扫描的结果。
pub struct ScanAll {
    pub root: Option<PathBuf>,
    pub procs: Vec<ProcInfo>,
    /// login.db 是否成功读取（否则只有进程、无 UIN 映射）。
    pub accounts_loaded: bool,
    pub accounts: Vec<Account>,
}

/// 枚举全部在线 QQ 进程并尽力映射 UIN。
///
/// `root` 为 None 时自动检测 QQ 数据根。login.db 不可读时不报错，只是没有
/// UIN 映射（`accounts_loaded == false`）。
pub fn scan_all(root: Option<PathBuf>) -> ScanAll {
    let root = root.or_else(locate::detect_data_root);
    let wrapper_pids = platform::find_wrapper_node_pids().unwrap_or_default();

    let mut accounts: Vec<Account> = Vec::new();
    let mut accounts_loaded = false;
    if let Some(r) = &root {
        let candidates = locate::login_db_candidates(r);
        if candidates.iter().any(|p| p.exists()) {
            match login_db::read_accounts_merged(&candidates) {
                Ok((a, _algo)) => {
                    accounts = a;
                    accounts_loaded = true;
                }
                Err(e) => {
                    ui::warn(&format!("读取 login.db 失败：{e}"));
                }
            }
        }
    }

    // 每个账号 → 持有其 nt_msg.db 的进程。
    let mut by_pid: HashMap<u32, (Account, String, bool)> = HashMap::new();
    if let (Some(r), true) = (&root, accounts_loaded) {
        for acc in &accounts {
            let db_dir = locate::account_db_dir(r, &acc.uin, &acc.uid);
            let holders: Vec<DbHolder> = platform::probe_account_db_holders(&db_dir)
                .into_iter()
                .filter(|h| platform::is_qq_process_name(&h.name) || wrapper_pids.contains(&h.pid))
                .collect();
            // 优先真正的 wrapper.node 主进程。
            let chosen = holders
                .iter()
                .find(|h| wrapper_pids.contains(&h.pid))
                .or_else(|| holders.first());
            if let Some(h) = chosen {
                by_pid
                    .entry(h.pid)
                    .or_insert_with(|| (acc.clone(), h.name.clone(), true));
            }
        }
    }

    let mut procs: Vec<ProcInfo> = Vec::new();
    // 先放 wrapper.node 主进程。
    for &pid in &wrapper_pids {
        let mapped = by_pid.get(&pid);
        procs.push(ProcInfo {
            pid,
            comm: mapped
                .map(|(_, n, _)| n.clone())
                .or_else(|| platform::comm_of(pid))
                .unwrap_or_default(),
            is_main: true,
            uin: mapped.map(|(a, _, _)| a.uin.clone()),
            uid: mapped.map(|(a, _, _)| a.uid.clone()),
            nick: mapped.map(|(a, _, _)| a.nick.clone()),
            logged_in: mapped.is_some(),
        });
    }
    // 再补上被占用探测发现、但不在主进程列表里的 pid（例如权限受限时）。
    for (pid, (acc, name, logged_in)) in &by_pid {
        if wrapper_pids.contains(pid) {
            continue;
        }
        procs.push(ProcInfo {
            pid: *pid,
            comm: name.clone(),
            is_main: false,
            uin: Some(acc.uin.clone()),
            uid: Some(acc.uid.clone()),
            nick: Some(acc.nick.clone()),
            logged_in: *logged_in,
        });
    }
    procs.sort_by_key(|p| (!p.logged_in, p.pid));

    ScanAll {
        root,
        procs,
        accounts_loaded,
        accounts,
    }
}

/// 解析用户选择的 pid：`None` 时若只有一个已登录进程则自动选它，否则报错。
pub fn resolve_pid(procs: &[ProcInfo], wanted: Option<u32>) -> anyhow::Result<u32> {
    if let Some(p) = wanted {
        if platform::pid_alive(p) {
            return Ok(p);
        }
        anyhow::bail!("pid {p} 不存在或已退出");
    }
    let logged: Vec<&ProcInfo> = procs.iter().filter(|p| p.logged_in && p.is_main).collect();
    match logged.len() {
        1 => Ok(logged[0].pid),
        0 => {
            let mains: Vec<&ProcInfo> = procs.iter().filter(|p| p.is_main).collect();
            match mains.len() {
                1 => Ok(mains[0].pid),
                _ => anyhow::bail!("未找到可用的 QQ 主进程，请用 --pid 指定"),
            }
        }
        _ => anyhow::bail!("检测到多个已登录 QQ 进程，请用 --pid 指定其中之一"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(pid: u32, main: bool, logged: bool) -> ProcInfo {
        ProcInfo {
            pid,
            comm: "qq".into(),
            is_main: main,
            uin: None,
            uid: None,
            nick: None,
            logged_in: logged,
        }
    }

    #[test]
    fn resolve_prefers_explicit_pid() {
        let procs = vec![mk(1, true, true)];
        assert_eq!(
            resolve_pid(&procs, Some(std::process::id())).unwrap(),
            std::process::id()
        );
    }

    #[test]
    fn resolve_errors_on_multiple_logged_in() {
        let procs = vec![mk(1, true, true), mk(2, true, true)];
        assert!(resolve_pid(&procs, None).is_err());
    }

    #[test]
    fn resolve_single_logged_in() {
        // 唯一已登录且存活的进程（用本进程 pid 保证 alive）。
        let me = std::process::id();
        let procs = vec![
            mk(1, true, false),
            ProcInfo {
                pid: me,
                comm: "qq".into(),
                is_main: true,
                uin: None,
                uid: None,
                nick: None,
                logged_in: true,
            },
        ];
        assert_eq!(resolve_pid(&procs, None).unwrap(), me);
    }
}
