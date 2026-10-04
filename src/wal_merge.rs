//! 把数据库的 `-wal` 侧车折叠回解密后的 SQLite 镜像（移植自 `../x_key_scanner`）。

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{Connection, OpenFlags};

use crate::crypto::decrypt::{PAGE_SIZE, WAL_FRAME_HDR_SIZE, WAL_HDR_SIZE};
use crate::crypto::{Algo, decrypt_database, decrypt_wal};

/// 解密后的数据库 + 折叠 `-wal` 的结果。
pub struct Decrypted {
    /// 自包含的明文 SQLite 镜像。
    pub bytes: Vec<u8>,
    /// 从 `-wal` 折叠进来的帧数（无则 0）。
    pub wal_frames: usize,
    /// 存在 `-wal` 却未合并的原因。
    pub wal_warning: Option<String>,
}

/// 解密 `db_path`，若有 `-wal` 侧车则回放它。
///
/// 目前 login.db 先整体读入内存再走 [`decrypt_db_bytes`]（便于多候选合并），
/// 此函数保留给需要逐文件解密的场景（如未来的 `--output` 解密导出）。
#[allow(dead_code)]
pub fn decrypt_db_file(path: &Path, passphrase: &[u8], algo: &Algo) -> io::Result<Decrypted> {
    let bytes = std::fs::read(path)?;
    decrypt_db_bytes(&bytes, &wal_sidecar(path), passphrase, algo)
}

/// 解密已读取的数据库镜像，并在 `wal_path` 可回放时折叠它。
pub fn decrypt_db_bytes(
    db_bytes: &[u8],
    wal_path: &Path,
    passphrase: &[u8],
    algo: &Algo,
) -> io::Result<Decrypted> {
    let plain = decrypt_database(db_bytes, passphrase, algo).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "数据库解密失败（算法或密钥不匹配）",
        )
    })?;

    let skip = |warning: Option<String>| Decrypted {
        bytes: plain.clone(),
        wal_frames: 0,
        wal_warning: warning,
    };

    let wal = match std::fs::read(wal_path) {
        Ok(b) if b.len() > WAL_HDR_SIZE => b,
        Ok(_) => return Ok(skip(None)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(skip(None)),
        Err(e) => return Ok(skip(Some(format!("无法读取 {}：{e}", wal_path.display())))),
    };

    let Some(plain_wal) = decrypt_wal(db_bytes, &wal, passphrase, algo) else {
        return Ok(skip(Some(
            "WAL 头/首页校验不通过（可能来自运行中 QQ 的半截写入）".to_string(),
        )));
    };
    let frames = (plain_wal.len() - WAL_HDR_SIZE) / (WAL_FRAME_HDR_SIZE + PAGE_SIZE);

    match replay(&plain, &plain_wal) {
        Ok(bytes) => Ok(Decrypted {
            bytes,
            wal_frames: frames,
            wal_warning: None,
        }),
        Err(e) => Ok(skip(Some(format!("WAL 回放失败：{e}")))),
    }
}

/// `db_path` 的 WAL 侧车路径：`<db_path>-wal`。
pub fn wal_sidecar(db_path: &Path) -> PathBuf {
    let mut os = db_path.as_os_str().to_os_string();
    os.push("-wal");
    PathBuf::from(os)
}

/// 让 SQLite 把 `wal_plain` 回放进 `db_plain` 并返回合并镜像。
fn replay(db_plain: &[u8], wal_plain: &[u8]) -> io::Result<Vec<u8>> {
    let dir = scratch_dir()?;
    let result = replay_in(&dir, db_plain, wal_plain);
    let _ = std::fs::remove_dir_all(&dir);
    result
}

fn replay_in(dir: &Path, db_plain: &[u8], wal_plain: &[u8]) -> io::Result<Vec<u8>> {
    let db = dir.join("merged.db");
    let wal = dir.join("merged.db-wal");
    std::fs::write(&db, db_plain)?;
    std::fs::write(&wal, wal_plain)?;

    let committed_pages = wal_committed_pages(wal_plain);
    {
        let conn = Connection::open_with_flags(&db, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(sqlite_err)?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(sqlite_err)?;

        let pages: i64 = conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .map_err(sqlite_err)?;
        if committed_pages != 0 && pages < i64::from(committed_pages) {
            return Err(io::Error::other(format!(
                "SQLite 只得到 {pages} 页，WAL 最后一个提交却声明 {committed_pages} 页",
            )));
        }

        let mode: String = conn
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))
            .map_err(sqlite_err)?;
        if !mode.eq_ignore_ascii_case("delete") {
            return Err(io::Error::other(format!(
                "SQLite 未能退出 WAL 模式（当前为 {mode}）"
            )));
        }
    }

    if std::fs::metadata(&wal).is_ok_and(|m| m.len() > 0) {
        return Err(io::Error::other("SQLite 未能完整回放 WAL"));
    }
    std::fs::read(&db)
}

/// WAL 最后一个提交帧声明的页数（0 = 无提交）。
fn wal_committed_pages(wal_plain: &[u8]) -> u32 {
    let frame_size = WAL_FRAME_HDR_SIZE + PAGE_SIZE;
    let mut pages = 0;
    let mut off = WAL_HDR_SIZE;
    while off + frame_size <= wal_plain.len() {
        let n = u32::from_be_bytes(wal_plain[off + 4..off + 8].try_into().expect("4 bytes"));
        if n != 0 {
            pages = n;
        }
        off += frame_size;
    }
    pages
}

fn sqlite_err(e: rusqlite::Error) -> io::Error {
    io::Error::other(format!("SQLite: {e}"))
}

/// 一次回放用的私有临时目录（owner-only）。
fn scratch_dir() -> io::Result<PathBuf> {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    for _ in 0..64 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut dir = std::env::temp_dir();
        let salt = &n as *const _ as usize;
        dir.push(format!("qqshark_wal_{}_{n}_{salt:x}", std::process::id()));
        match create_private_dir(&dir) {
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
            Ok(()) => return Ok(dir),
        }
    }
    Err(io::Error::other("无法创建临时目录"))
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir(dir)
}
