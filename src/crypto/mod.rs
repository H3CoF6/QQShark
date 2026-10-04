//! SQLCipher v4 手工页面解密（移植自 `../x_key_scanner`，用于 login.db）。

pub mod cipher;
pub mod decrypt;

pub use cipher::Algo;
pub use decrypt::{detect_algo, decrypt_database, decrypt_wal};
