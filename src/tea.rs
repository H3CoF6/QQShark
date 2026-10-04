//! QQ 变体 TEA (等价 Lagrange TeaProvider)。已在 Python 侧对真实帧验证。

const ENCD: [u32; 16] = [
    0x9e3779b9, 0x3c6ef372, 0xdaa66d2b, 0x78dde6e4, 0x1715609d, 0xb54cda56, 0x5384540f, 0xf1bbcdc8,
    0x8ff34781, 0x2e2ac13a, 0xcc623af3, 0x6a99b4ac, 0x08d12e65, 0xa708a81e, 0x454021d7, 0xe3779b90,
];

#[inline]
fn f(v: u32, k1: u32, k2: u32, k: u32) -> u32 {
    v.wrapping_add(k) ^ (v.wrapping_shl(4).wrapping_add(k1)) ^ (v.wrapping_shr(5).wrapping_add(k2))
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// 解密返回去头 `(dec[0]&7)+3` 字节、去尾 7 字节后的明文。
/// 与 Lagrange `CreateDecryptSpan` 语义一致。
pub fn decrypt(src: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let a = be32(&key[0..4]);
    let b = be32(&key[4..8]);
    let c = be32(&key[8..12]);
    let d = be32(&key[12..16]);

    let n = src.len() - src.len() % 8;
    let mut dest = Vec::with_capacity(n);
    let mut px: u64 = 0;
    let mut prev: u64 = 0;

    let mut i = 0;
    while i < n {
        let p = u64::from_be_bytes(src[i..i + 8].try_into().unwrap());
        px ^= p;
        let mut x = (px >> 32) as u32;
        let mut y = (px & 0xffff_ffff) as u32;
        for &k in ENCD.iter().rev() {
            y = y.wrapping_sub(f(x, c, d, k));
            x = x.wrapping_sub(f(y, a, b, k));
        }
        let dec = ((x as u64) << 32) | (y as u64);
        dest.extend_from_slice(&(dec ^ prev).to_be_bytes());
        px = dec;
        prev = p;
        i += 8;
    }

    if dest.len() < 7 {
        return Vec::new();
    }
    let strip = (dest[0] as usize & 7) + 3;
    if strip + 7 >= dest.len() {
        return Vec::new();
    }
    dest[strip..dest.len() - 7].to_vec()
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

    // 真实抓包向量 (QQ 3.2.34, cmd=OidbSvcTrpcTcp.0x10c0_1)
    const KEY_HEX: &str = "44773377403d28545d752a734e42432e";
    const CIPHER_HEX: &str = "ca58c3426541a4ba995a879fb8408978a7b5e26a9167700a549858728f5b225658d55560beaa6462c16ce76c96a65235bf946512a2a6134d6222498a8a133bac71d7ae8e044784f78ac7d28e0da46b12ebc582ccdf76b601a174971386fdb2a5a6906767b01f80ed0f55396804c9e70152e521643a04ec5e302d78d64c0e873df70a3c3c5c7e664a44b84f9959aad91479473aa95164ba3986f1f8a3c3a0305171db5ca5f45df33b321f05b1924843391f04faa3f15139aae4dcc27525d648105727495d2dcd0ba8b82e2eb9fb835ab5f627490306b2a35cea329968ecb1a444e8aa5b8d1d40cf313a7cf616198a4f19a354a145cde90dc256945b61e5ba34683e019ed1d1b5b9384f8507c31b8ecc42c3dffe23a5505f19152fb7e7afdd55887c2b0d0bd24b71d02c3b42d06a92e19116cfed7de088c72736f89b34470cb30b25f6dc328622fdf47e17131ded93b6f6771fb1885aba6f6ada6bd6ea1e79bdeea38f1bcf4911b0a8ea4dca76b08e7037";
    const PLAIN_HEX: &str = "00000151005fc15b2007f230000008040000000000000000000003000000004ceed890ddc6ce93b3914cf23c40d19e7574538089442c699aa9cb103ad0e568d342bc8be82a184ca1a4110bd635de1679aaf4caef1c57bf84071e8ec015a28e6fdda27f572d8e3c0f0000001b4f696462537663547270635463702e3078313063305f3100000004000000243931376163663061616533626338306263316637373830393432623765303530000000040002000000a0622039313761636630616165336263383062633166373738303934326237653035306a01007a3730302d61386562653965373231356334303436323033363735366230323965383830362d613739336431373435616337666261302d3030820118755f6d47494254425737674634576f6377387a6170633677ba011d0a0f636c69656e745f636f6e6e5f736571120a31373931313137343437d001650000001108c02110012204081410006000";

    #[test]
    fn decrypt_real_captured_frame() {
        let key: [u8; 16] = unhex(KEY_HEX).try_into().unwrap();
        let plain = decrypt(&unhex(CIPHER_HEX), &key);
        assert_eq!(plain, unhex(PLAIN_HEX));
    }

    #[test]
    fn decrypt_empty_on_short_input() {
        assert!(decrypt(&[0u8; 7], &[0u8; 16]).is_empty());
    }

    #[test]
    fn decrypt_ignores_trailing_non_block() {
        let key: [u8; 16] = unhex(KEY_HEX).try_into().unwrap();
        let mut c = unhex(CIPHER_HEX);
        c.extend_from_slice(&[0xde, 0xad, 0xbe]); // 非 8 字节尾部被忽略
        assert_eq!(decrypt(&c, &key), unhex(PLAIN_HEX));
    }
}
