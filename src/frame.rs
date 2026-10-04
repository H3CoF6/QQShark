//! MSF 外层帧解析 + SsoPacker 头解析。
//!
//! 外层帧（含长度前缀，proto 12/13）:
//! ```text
//! [4B total_len][4B proto][1B encryptType][ ... payload ... ]
//! ```
//! proto == 12 (D2Auth):
//! ```text
//! [1B zero][4B d2len(含前缀)][d2][4B uinlen(含前缀)][uin][cipher]
//! ```
//! proto == 13 (Simple):
//! ```text
//! [4B seq][1B zero][4B uinlen(含前缀)][uin][cipher]
//! ```
//! cipher 明文 = SsoPacker: `[4B headlen][head][4B bodylen][body]`。

use crate::tea;

pub const PROTO_D2AUTH: u32 = 12;
pub const PROTO_SIMPLE: u32 = 13;

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[derive(Debug)]
pub struct MsfFrame<'a> {
    pub encrypt_type: u8,
    pub cipher: &'a [u8],
}

/// 找帧里的 uin：一段 5..12 位十进制数字，且紧邻其前的长度字段
/// (4 字节 BE 或 1 字节) == 数字长度 + 4。命中后其余即 TEA 密文。
fn find_uin(b: &[u8]) -> Option<(usize, usize)> {
    let mut i = 12usize;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let s = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let l = i - s;
            if (5..=12).contains(&l) {
                let want = (l + 4) as u32;
                if s >= 4 && be32(&b[s - 4..s]) == want {
                    return Some((s, l));
                }
                if s >= 1 && b[s - 1] as u32 == want {
                    return Some((s, l));
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// 解析一个完整的外层帧 (proto 12/13)。失败返回 None。
pub fn parse_frame(b: &[u8]) -> Option<MsfFrame<'_>> {
    if b.len() < 16 {
        return None;
    }
    let total = be32(&b[0..4]) as usize;
    if total != b.len() {
        return None;
    }
    let proto = be32(&b[4..8]);
    if proto != PROTO_D2AUTH && proto != PROTO_SIMPLE {
        return None;
    }
    let encrypt_type = b[8];
    let (_us, ul) = find_uin(b)?;
    let cipher = &b[_us + ul..];
    if cipher.is_empty() || !cipher.len().is_multiple_of(8) {
        return None;
    }
    Some(MsfFrame {
        encrypt_type,
        cipher,
    })
}

/// 解密 SsoPacker 明文里的命令名。
///
/// 明文布局：`[4B headlen(含前缀)][head][4B bodylen(含前缀)][body]`。
/// 实测 `headlen` 计入了自身 4 字节前缀，故 head 内容 = `plain[4..headlen]`。
pub fn parse_cmd(plain: &[u8]) -> Option<String> {
    if plain.len() < 8 {
        return None;
    }
    let headlen = be32(&plain[0..4]) as usize;
    if headlen < 4 || headlen > plain.len() {
        return None;
    }
    let head = &plain[4..headlen];
    // seq(4) subAppId(4) const(4) 12B zeros => 24
    let mut o = 24usize;
    let a2l = be32(head.get(o..o + 4)?) as usize;
    if a2l < 4 {
        return None;
    }
    o += a2l;
    let cl = be32(head.get(o..o + 4)?) as usize;
    if cl < 4 || o + cl > head.len() {
        return None;
    }
    let cmd = &head[o + 4..o + cl];
    Some(String::from_utf8_lossy(cmd).into_owned())
}

pub struct Decoded {
    pub cmd: Option<String>,
    pub body: Vec<u8>,
}

/// 用 d2key 解密 cipher，并解析出 cmd / body。
///
/// capture/decode 路径会自行解密以同时拿到明文，故这里主要作为便捷 API 与测试入口。
#[allow(dead_code)]
pub fn decode(cipher: &[u8], key: &[u8; 16]) -> Option<Decoded> {
    decode_plain(&tea::decrypt(cipher, key))
}

/// 解析已解密的 SsoPacker 明文，取出 cmd / body。
pub fn decode_plain(plain: &[u8]) -> Option<Decoded> {
    if plain.len() < 8 {
        return None;
    }
    let headlen = be32(&plain[0..4]) as usize;
    // 头/体长度字段均含自身 4 字节前缀：head=plain[4..headlen]，
    // bodylen 在 plain[headlen..headlen+4]，正文 = plain[headlen+4..headlen+bodylen]。
    let body = if headlen >= 4 && headlen + 4 <= plain.len() {
        let bodylen = be32(&plain[headlen..headlen + 4]) as usize;
        let start = headlen + 4;
        let end = headlen.checked_add(bodylen).unwrap_or(0);
        if bodylen >= 4 && end <= plain.len() {
            plain[start..end].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    Some(Decoded {
        cmd: parse_cmd(plain),
        body,
    })
}

/// 从重组流里切出完整帧，返回 (帧列表, 剩余残留)。
pub fn extract_frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    let mut i = 0usize;
    while i + 8 <= buf.len() {
        let total = be32(&buf[i..i + 4]) as usize;
        let proto = be32(&buf[i + 4..i + 8]);
        if total >= 8 && (proto == PROTO_D2AUTH || proto == PROTO_SIMPLE) && i + total <= buf.len()
        {
            frames.push(buf[i..i + total].to_vec());
            i += total;
        } else {
            // 未对齐 -> 逐字节重同步（保留尾部）
            i += 1;
        }
    }
    buf.drain(0..i);
    frames
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    const CIPHER_HEX: &str = "ca58c3426541a4ba995a879fb8408978a7b5e26a9167700a549858728f5b225658d55560beaa6462c16ce76c96a65235bf946512a2a6134d6222498a8a133bac71d7ae8e044784f78ac7d28e0da46b12ebc582ccdf76b601a174971386fdb2a5a6906767b01f80ed0f55396804c9e70152e521643a04ec5e302d78d64c0e873df70a3c3c5c7e664a44b84f9959aad91479473aa95164ba3986f1f8a3c3a0305171db5ca5f45df33b321f05b1924843391f04faa3f15139aae4dcc27525d648105727495d2dcd0ba8b82e2eb9fb835ab5f627490306b2a35cea329968ecb1a444e8aa5b8d1d40cf313a7cf616198a4f19a354a145cde90dc256945b61e5ba34683e019ed1d1b5b9384f8507c31b8ecc42c3dffe23a5505f19152fb7e7afdd55887c2b0d0bd24b71d02c3b42d06a92e19116cfed7de088c72736f89b34470cb30b25f6dc328622fdf47e17131ded93b6f6771fb1885aba6f6ada6bd6ea1e79bdeea38f1bcf4911b0a8ea4dca76b08e7037";

    /// 构造一个 proto12 外层帧：[total][proto=12][et=1][d2len:4=0][uinlen:4][uin][cipher]
    fn build_tx_frame(cipher: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0u8; 4]); // total 占位
        b.extend_from_slice(&12u32.to_be_bytes());
        b.push(1); // encType = TEA
        b.extend_from_slice(&0u32.to_be_bytes()); // d2 长度 0
        b.extend_from_slice(&14u32.to_be_bytes()); // uinlen = 4 + 10
        b.extend_from_slice(b"1707889225");
        b.extend_from_slice(cipher);
        let total = b.len() as u32;
        b[0..4].copy_from_slice(&total.to_be_bytes());
        b
    }

    #[test]
    fn parse_frame_extracts_cipher() {
        let cipher = unhex(CIPHER_HEX);
        let frame = build_tx_frame(&cipher);
        let mf = parse_frame(&frame).expect("should parse");
        assert_eq!(mf.encrypt_type, 1);
        assert_eq!(mf.cipher, cipher.as_slice());
    }

    #[test]
    fn find_uin_picks_digit_run_with_len_prefix() {
        let frame = build_tx_frame(&unhex(CIPHER_HEX));
        let (s, l) = find_uin(&frame).unwrap();
        assert_eq!(&frame[s..s + l], b"1707889225");
    }

    #[test]
    fn extract_frames_splits_and_keeps_partial() {
        let mut stream = Vec::new();
        let f1 = build_tx_frame(&unhex(CIPHER_HEX));
        stream.extend_from_slice(&f1);
        stream.extend_from_slice(&f1);
        stream.extend_from_slice(&[0x41, 0x42, 0x43]); // 残缺尾
        let frames = extract_frames(&mut stream);
        assert_eq!(frames.len(), 2);
        assert_eq!(stream, vec![0x41, 0x42, 0x43]);
    }

    #[test]
    fn parse_cmd_reads_sso_head() {
        let cmd = b"MessageSvc.PbSendMsg";
        let mut head = Vec::new();
        head.extend_from_slice(&[0u8; 4]); // seq
        head.extend_from_slice(&[0u8; 4]); // subAppId
        head.extend_from_slice(&[0x08, 0x04, 0, 0]); // const 2052
        head.extend_from_slice(&[0u8; 12]); // zeros
        head.extend_from_slice(&6u32.to_be_bytes()); // a2 前缀 (含 4)
        head.extend_from_slice(&[0xaa, 0xbb]);
        head.extend_from_slice(&((cmd.len() + 4) as u32).to_be_bytes());
        head.extend_from_slice(cmd);
        // headlen 含自身 4 字节前缀
        let mut plain = ((head.len() + 4) as u32).to_be_bytes().to_vec();
        plain.extend_from_slice(&head);
        plain.extend_from_slice(&4u32.to_be_bytes()); // body 长度（含前缀）= 4
        assert_eq!(parse_cmd(&plain).as_deref(), Some("MessageSvc.PbSendMsg"));
    }

    /// 真实抓包帧：TEA 解密 → SsoPacker 切出 cmd 与正文 → 正文按 protobuf 展开。
    #[test]
    fn decode_real_frame_yields_cmd_and_protobuf_body() {
        let key: [u8; 16] = unhex("44773377403d28545d752a734e42432e")
            .try_into()
            .unwrap();
        let cipher = unhex(CIPHER_HEX);
        let d = decode(&cipher, &key).expect("decode");
        assert_eq!(d.cmd.as_deref(), Some("OidbSvcTrpcTcp.0x10c0_1"));
        // 正文应为 protobuf：字段 1 = 0x10c0 (4288)、字段 2 = 1
        let (kind, nodes, prefix) = crate::codec::decode_auto(&d.body).expect("body should decode");
        assert_eq!(kind, crate::codec::Kind::Protobuf);
        assert!(prefix.is_none(), "正文本身已是 protobuf，不应剥前缀");
        assert!(matches!(
            nodes[0].value,
            crate::codec::RvValue::Int { raw: 0x10c0, .. }
        ));
    }
}
