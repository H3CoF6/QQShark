//! SQLCipher 算法处理（移植自 `../x_key_scanner`）。
//!
//! QQ NT 数据库是 SQLCipher v4 流，但页面 HMAC / KDF HMAC 算法并非固定，因此
//! 不硬编码默认值：对 login.db 暴力枚举一次算法对，随后复用。
//! 全部纯 RustCrypto —— 不引入 rusqlite（读取时）也不引入 openssl。

use aes::Aes256;
use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use cbc::Decryptor;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

type Aes256CbcDec = Decryptor<Aes256>;

pub const IV_SIZE: usize = 16;
pub const AES_BLOCK: usize = 16;

/// 页面级 HMAC 算法。`None` 对应 SQLCipher 的 `cipher_use_hmac=OFF`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageHmac {
    None,
    Sha1,
    Sha256,
    Sha512,
}

/// KDF（PBKDF2）HMAC 算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfHmac {
    Sha1,
    Sha256,
    Sha512,
}

/// 一组已解析的算法配对。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Algo {
    pub page: PageHmac,
    pub kdf: KdfHmac,
}

pub const ALL_PAGE_HMAC: [PageHmac; 4] = [
    PageHmac::None,
    PageHmac::Sha1,
    PageHmac::Sha256,
    PageHmac::Sha512,
];
pub const ALL_KDF_HMAC: [KdfHmac; 3] = [KdfHmac::Sha1, KdfHmac::Sha256, KdfHmac::Sha512];

impl PageHmac {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// 每页 HMAC 摘要字节数（关闭时为 0）。
    pub fn digest_size(self) -> usize {
        match self {
            Self::None => 0,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    /// 每页保留区 = IV + HMAC 摘要，向上取整到 AES 块大小。
    pub fn reserve(self) -> usize {
        (IV_SIZE + self.digest_size()).div_ceil(AES_BLOCK) * AES_BLOCK
    }
}

impl KdfHmac {
    pub fn label(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl Algo {
    /// 按暴力枚举顺序遍历全部 12 种算法组合。
    pub fn all() -> impl Iterator<Item = Algo> {
        ALL_PAGE_HMAC
            .into_iter()
            .flat_map(|page| ALL_KDF_HMAC.into_iter().map(move |kdf| Algo { page, kdf }))
    }

    /// 以配置的 KDF-HMAC 运行 PBKDF2，填充 `out`。
    pub fn pbkdf2(&self, pass: &[u8], salt: &[u8], iter: u32, out: &mut [u8]) {
        match self.kdf {
            KdfHmac::Sha1 => pbkdf2_hmac::<Sha1>(pass, salt, iter, out),
            KdfHmac::Sha256 => pbkdf2_hmac::<Sha256>(pass, salt, iter, out),
            KdfHmac::Sha512 => pbkdf2_hmac::<Sha512>(pass, salt, iter, out),
        }
    }

    /// 计算页面级 HMAC。页面 HMAC 为 None 时返回空 vec。
    pub fn page_hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! mac {
            ($t:ty) => {{
                let mut m = Hmac::<$t>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }};
        }
        match self.page {
            PageHmac::None => Vec::new(),
            PageHmac::Sha1 => mac!(Sha1),
            PageHmac::Sha256 => mac!(Sha256),
            PageHmac::Sha512 => mac!(Sha512),
        }
    }
}

/// 原地解密一段 AES-256-CBC，返回明文。`iv` 必须 16 字节，`ciphertext` 是 16 的倍数。
pub fn aes256_cbc_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let iv: &[u8; IV_SIZE] = iv.try_into().ok()?;
    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    let mut buf = ciphertext.to_vec();
    cipher.decrypt_padded_mut::<NoPadding>(&mut buf).ok()?;
    Some(buf)
}
