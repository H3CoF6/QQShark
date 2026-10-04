//! 读取解密后的 login.db 以枚举账号（移植自 `../x_key_scanner`）。
//!
//! 到这里 SQLCipher 层已被 [`crate::crypto::decrypt_database`] 手工剥离，得到
//! 普通 SQLite 文件，用 rusqlite（纯 bundled，无 sqlcipher/openssl）读取
//! `login_table`。列名是数字字符串："1000"=uin, "1001"=uid, "1007"=nick。

use std::io;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};

use crate::crypto::{Algo, detect_algo};
use crate::wal_merge;

/// QQ NT 内置的登录前口令，用于解密 login.db。
pub const PRE_LOGIN_KEY: &[u8] = b"BD156D6710D54D8782F4";

#[derive(Debug, Clone)]
pub struct Account {
    pub uin: String,
    pub uid: String,
    pub nick: String,
}

/// 解密 `login.db` 并返回缓存的账号，附带探测到的算法。
pub fn read_accounts(path: &Path) -> io::Result<(Vec<Account>, Algo)> {
    let bytes = std::fs::read(path)?;
    let verified = detect_algo(&bytes, PRE_LOGIN_KEY).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "无法解密 login.db：12 种算法对均不匹配内置登录前口令（客户端布局可能已变）",
        )
    })?;
    let merged = wal_merge::decrypt_db_bytes(
        &bytes,
        &wal_merge::wal_sidecar(path),
        PRE_LOGIN_KEY,
        &verified.algo,
    )?;
    if let Some(warning) = &merged.wal_warning {
        crate::ui::warn(&format!("{}：{warning}", path.display()));
    } else if merged.wal_frames > 0 {
        crate::ui::info(&format!(
            "{}：合并 -wal {} 帧（算法 page={} kdf={}）",
            path.display(),
            merged.wal_frames,
            verified.algo.page.label(),
            verified.algo.kdf.label()
        ));
    }

    let accounts = query_login_table(&merged.bytes)?;
    Ok((accounts, verified.algo))
}

/// 读取并合并多个候选 login.db 的账号，靠前路径在冲突时优先。
pub fn read_accounts_merged(paths: &[PathBuf]) -> io::Result<(Vec<Account>, Algo)> {
    let mut merged: Vec<Account> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut algo: Option<Algo> = None;
    let mut last_err: Option<io::Error> = None;

    for path in paths {
        if !path.exists() {
            continue;
        }
        match read_accounts(path) {
            Ok((accounts, a)) => {
                algo.get_or_insert(a);
                for acc in accounts {
                    if seen.insert(acc.uin.clone()) {
                        merged.push(acc);
                    }
                }
            }
            Err(e) => last_err = Some(e),
        }
    }

    match algo {
        Some(a) => Ok((merged, a)),
        None => Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "没有任何 login.db 候选项可读取")
        })),
    }
}

/// 把明文 SQLite 镜像写入临时文件并读取 `login_table`。
fn query_login_table(plain: &[u8]) -> io::Result<Vec<Account>> {
    let tmp = tempfile_path("login");
    std::fs::write(&tmp, plain)?;
    let result = (|| -> rusqlite::Result<Vec<Account>> {
        let conn = Connection::open_with_flags(
            &tmp,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        let mut stmt = conn.prepare(r#"SELECT "1000", "1001", "1007" FROM login_table"#)?;
        let rows = stmt.query_map([], |row| {
            Ok(Account {
                uin: value_to_string(row.get_ref(0)?),
                uid: value_to_string(row.get_ref(1)?),
                nick: value_to_string(row.get_ref(2)?),
            })
        })?;
        Ok(rows.filter_map(Result::ok).collect())
    })();
    let _ = std::fs::remove_file(&tmp);
    result.map_err(|e| io::Error::other(format!("login_table 读取失败：{e}")))
}

fn value_to_string(v: rusqlite::types::ValueRef<'_>) -> String {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        ValueRef::Integer(i) => i.to_string(),
        ValueRef::Real(r) => r.to_string(),
        ValueRef::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        ValueRef::Null => String::new(),
    }
}

/// 唯一的临时路径（不引入 tempfile crate）。
fn tempfile_path(tag: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    let salt = &dir as *const _ as usize;
    dir.push(format!("qqshark_{tag}_{}_{salt:x}.db", std::process::id()));
    dir
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::types::ValueRef;

    #[test]
    fn value_to_string_handles_kinds() {
        assert_eq!(value_to_string(ValueRef::Integer(42)), "42");
        assert_eq!(value_to_string(ValueRef::Text(b"hi")), "hi");
        assert_eq!(value_to_string(ValueRef::Null), "");
    }
}
