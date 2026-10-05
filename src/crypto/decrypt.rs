//! 手工 SQLCipher v4 页面解密（移植自 `../x_key_scanner`）。
//!
//! QQ NT 加密数据库布局（页大小 4096）：
//! ```text
//! [ 1024 字节 QQ 包装头 ][ SQLCipher 第 1 页 ][ 第 2 页 ] ...
//!                         ^ salt = 第 1 页前 16 字节
//! ```
//! 每页尾部是 reserve 区 = IV(16) + 页面 HMAC 摘要（对齐到 16）。
//! 第 1 页加密体从 salt 之后开始；后续页无 salt。

use crate::crypto::cipher::{Algo, IV_SIZE};

/// QQ NT 在真正的 SQLCipher 流前加的字节数。
pub const EXT_HEADER: usize = 1024;
pub const PAGE_SIZE: usize = 4096;
pub const SALT_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;

/// SQLCipher v4 默认的 KDF 迭代次数。
pub const KDF_ITER: u32 = 4000;
/// 每页 HMAC 密钥派生所用快速迭代次数。
pub const FAST_ITER: u32 = 2;
/// SQLCipher 的 HMAC-salt 掩码：HMAC 密钥 salt = 页面 salt XOR 0x3a。
pub const HMAC_MASK: u8 = 0x3a;

/// SQLite WAL 头：magic, format version, page size, salt, checksum。
pub const WAL_HDR_SIZE: usize = 32;
/// SQLite WAL 帧头：page number, commit size, salt, checksum。
pub const WAL_FRAME_HDR_SIZE: usize = 24;

/// 从口令 + 第 1 页 salt 派生 32 字节 AES 密钥。
pub fn derive_key(passphrase: &[u8], salt: &[u8], algo: &Algo) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    algo.pbkdf2(passphrase, salt, KDF_ITER, &mut key);
    key
}

/// 解密单页（已派生密钥）。`skip` 为跳过的前导字节（第 1 页 16，其余 0）。
fn decrypt_page(page: &[u8], key: &[u8; KEY_SIZE], skip: usize, reserve: usize) -> Option<Vec<u8>> {
    let data_len = PAGE_SIZE - skip;
    let enc_len = data_len.checked_sub(reserve)?;
    let ct = &page[skip..skip + enc_len];
    let iv = &page[skip + enc_len..skip + enc_len + IV_SIZE];
    crate::crypto::cipher::aes256_cbc_decrypt(key, iv, ct)
}

/// 探测一个 (key, algo) 配对的结果。
pub struct Verified {
    pub algo: Algo,
}

/// 读取前 `EXT_HEADER + PAGE_SIZE` 字节并返回第 1 页（salt 开头）。
pub fn read_page1(bytes: &[u8]) -> Option<&[u8]> {
    bytes.get(EXT_HEADER..EXT_HEADER + PAGE_SIZE)
}

/// 对第 1 页验证一个 (passphrase, algo) 猜测。成功返回派生的 AES 密钥。
pub fn verify_key(db_bytes: &[u8], passphrase: &[u8], algo: &Algo) -> Option<[u8; KEY_SIZE]> {
    let page1 = read_page1(db_bytes)?;
    let salt = &page1[..SALT_SIZE];
    let key = derive_key(passphrase, salt, algo);

    let hmac_size = algo.page.digest_size();
    if hmac_size == 0 {
        let reserve = algo.page.reserve();
        let body = decrypt_page(page1, &key, SALT_SIZE, reserve)?;
        return sqlite_header_tail_ok(&body).then_some(key);
    }

    let reserve = algo.page.reserve();
    let data_end = PAGE_SIZE - reserve;

    let mut hmac_salt = [0u8; SALT_SIZE];
    for i in 0..SALT_SIZE {
        hmac_salt[i] = page1[i] ^ HMAC_MASK;
    }
    let mut hmac_key = [0u8; KEY_SIZE];
    algo.pbkdf2(&key, &hmac_salt, FAST_ITER, &mut hmac_key);

    let mut hmac_in = Vec::with_capacity(data_end - SALT_SIZE + IV_SIZE + 4);
    hmac_in.extend_from_slice(&page1[SALT_SIZE..data_end]);
    hmac_in.extend_from_slice(&page1[data_end..data_end + IV_SIZE]);
    hmac_in.extend_from_slice(&1u32.to_le_bytes()); // 页号，小端

    let computed = algo.page_hmac(&hmac_key, &hmac_in);
    let stored = &page1[data_end + IV_SIZE..data_end + IV_SIZE + hmac_size];

    let matches = computed.len() == hmac_size
        && computed
            .iter()
            .zip(stored)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    matches.then_some(key)
}

/// 解密后的第 1 页体从文件偏移 16 开始（salt 占用了 0..16）。检查其后的固定头字段。
fn sqlite_header_tail_ok(body: &[u8]) -> bool {
    if body.len() < 8 {
        return false;
    }
    let page_size = u16::from_be_bytes([body[0], body[1]]);
    let page_ok = page_size == 1 /* 65536 哨兵 */
        || (page_size >= 512 && page_size.is_power_of_two());
    page_ok && body[5] == 64 && body[6] == 32 && body[7] == 32
}

/// 对 `db_bytes` 暴力枚举算法对。
pub fn detect_algo(db_bytes: &[u8], passphrase: &[u8]) -> Option<Verified> {
    Algo::all().find_map(|algo| verify_key(db_bytes, passphrase, &algo).map(|_| Verified { algo }))
}

/// 把整个数据库解密为明文 SQLite 镜像（内存中）。
pub fn decrypt_database(db_bytes: &[u8], passphrase: &[u8], algo: &Algo) -> Option<Vec<u8>> {
    if db_bytes.len() < EXT_HEADER + PAGE_SIZE {
        return None;
    }
    let sc = &db_bytes[EXT_HEADER..];
    let total_pages = sc.len() / PAGE_SIZE;
    let reserve = algo.page.reserve();
    let salt = &sc[..SALT_SIZE];
    let key = derive_key(passphrase, salt, algo);

    let mut out = Vec::with_capacity(total_pages * PAGE_SIZE);
    for page_num in 1..=total_pages {
        let off = (page_num - 1) * PAGE_SIZE;
        let page = &sc[off..off + PAGE_SIZE];
        let skip = if page_num == 1 { SALT_SIZE } else { 0 };
        let dec = decrypt_page(page, &key, skip, reserve)?;
        out.extend_from_slice(&plaintext_page(page_num as u32, &dec));
    }
    Some(out)
}

/// 由解密后的页面体重建明文页。
fn plaintext_page(page_num: u32, body: &[u8]) -> Vec<u8> {
    let mut full = vec![0u8; PAGE_SIZE];
    if page_num == 1 {
        full[..16].copy_from_slice(b"SQLite format 3\0");
        let n = body.len().min(PAGE_SIZE - 16);
        full[16..16 + n].copy_from_slice(&body[..n]);
        full[16] = (PAGE_SIZE >> 8) as u8;
        full[17] = (PAGE_SIZE & 0xff) as u8;
    } else {
        let n = body.len().min(PAGE_SIZE);
        full[..n].copy_from_slice(&body[..n]);
    }
    full
}

/// SQLite 滚动 WAL 校验和。
fn wal_checksum(seed: [u32; 2], chunks: [&[u8]; 2], little_endian: bool) -> [u32; 2] {
    let word = |b: &[u8]| -> u32 {
        let b: [u8; 4] = b.try_into().expect("checksum runs on whole words");
        if little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };
    let mut s = seed;
    for src in chunks {
        for pair in src.as_chunks::<8>().0 {
            let (w0, w1) = (word(&pair[..4]), word(&pair[4..]));
            s[0] = s[0].wrapping_add(w0).wrapping_add(s[1]);
            s[1] = s[1].wrapping_add(w1).wrapping_add(s[0]);
        }
    }
    s
}

fn be_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.try_into().ok()?))
}

/// 解密属于 `db_bytes` 的 `-wal` 侧车文件。
pub fn decrypt_wal(db_bytes: &[u8], wal: &[u8], passphrase: &[u8], algo: &Algo) -> Option<Vec<u8>> {
    let page1 = read_page1(db_bytes)?;
    let salt = &page1[..SALT_SIZE];
    let key = derive_key(passphrase, salt, algo);
    let reserve = algo.page.reserve();

    let magic = be_u32(wal.get(0..4)?)?;
    let little_endian = match magic {
        0x377f_0682 => true,
        0x377f_0683 => false,
        _ => return None,
    };
    if be_u32(wal.get(8..12)?)? as usize != PAGE_SIZE {
        return None;
    }

    let hdr = wal.get(..WAL_HDR_SIZE)?;
    let hdr_seed = wal_checksum([0, 0], [&hdr[..24], &[]], little_endian);
    if hdr_seed != [be_u32(&hdr[24..28])?, be_u32(&hdr[28..32])?] {
        return None;
    }

    let frame_size = WAL_FRAME_HDR_SIZE + PAGE_SIZE;
    let frames = (wal.len() - WAL_HDR_SIZE) / frame_size;

    let mut running = hdr_seed;
    let mut intact = 0usize;
    for i in 0..frames {
        let off = WAL_HDR_SIZE + i * frame_size;
        let fh = &wal[off..off + WAL_FRAME_HDR_SIZE];
        let page = &wal[off + WAL_FRAME_HDR_SIZE..off + frame_size];
        running = wal_checksum(running, [&fh[..8], page], little_endian);
        if running != [be_u32(&fh[16..20])?, be_u32(&fh[20..24])?] {
            break;
        }
        intact += 1;
    }
    if intact == 0 {
        return None;
    }

    let mut out = Vec::with_capacity(WAL_HDR_SIZE + intact * frame_size);
    out.extend_from_slice(hdr);
    let mut running = hdr_seed;
    for i in 0..intact {
        let off = WAL_HDR_SIZE + i * frame_size;
        let fh = &wal[off..off + WAL_FRAME_HDR_SIZE];
        let page = &wal[off + WAL_FRAME_HDR_SIZE..off + frame_size];

        let page_num = be_u32(&fh[..4])?;
        let skip = if page_num == 1 { SALT_SIZE } else { 0 };
        let body = decrypt_page(page, &key, skip, reserve)?;
        let plain = plaintext_page(page_num, &body);

        let mut new_hdr = [0u8; WAL_FRAME_HDR_SIZE];
        new_hdr.copy_from_slice(fh);
        running = wal_checksum(running, [&new_hdr[..8], &plain], little_endian);
        new_hdr[16..20].copy_from_slice(&running[0].to_be_bytes());
        new_hdr[20..24].copy_from_slice(&running[1].to_be_bytes());

        out.extend_from_slice(&new_hdr);
        out.extend_from_slice(&plain);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn wal_checksum_matches_sqlite() {
        let dir = std::env::temp_dir().join(format!("qqshark_cksum_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("t.db");
        let _ = std::fs::remove_file(&db);
        let mut wal_path = db.as_os_str().to_os_string();
        wal_path.push("-wal");
        let wal_path = PathBuf::from(wal_path);

        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE t(x);",
        )
        .unwrap();
        for i in 0..64 {
            conn.execute("INSERT INTO t VALUES (?1)", [i]).unwrap();
        }
        let wal = std::fs::read(&wal_path).unwrap();
        drop(conn);

        let little_endian = match u32::from_be_bytes(wal[..4].try_into().unwrap()) {
            0x377f_0682 => true,
            0x377f_0683 => false,
            magic => panic!("unexpected WAL magic {magic:#x}"),
        };
        let mut running = wal_checksum([0, 0], [&wal[..24], &[]], little_endian);
        assert_eq!(
            running,
            [be_u32(&wal[24..28]).unwrap(), be_u32(&wal[28..32]).unwrap()],
            "wal header checksum"
        );

        let page_size = u32::from_be_bytes(wal[8..12].try_into().unwrap()) as usize;
        let frame = WAL_FRAME_HDR_SIZE + page_size;
        let frames = (wal.len() - WAL_HDR_SIZE) / frame;
        assert!(frames > 0, "the inserts should have produced WAL frames");
        for i in 0..frames {
            let off = WAL_HDR_SIZE + i * frame;
            let fh = &wal[off..off + WAL_FRAME_HDR_SIZE];
            let page = &wal[off + WAL_FRAME_HDR_SIZE..off + frame];
            running = wal_checksum(running, [&fh[..8], page], little_endian);
            assert_eq!(
                running,
                [be_u32(&fh[16..20]).unwrap(), be_u32(&fh[20..24]).unwrap()],
                "frame {} checksum",
                i + 1
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
