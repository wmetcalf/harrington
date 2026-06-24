//! AES-CBC + GZip primitives for the AES dropper chain.
//!
//! The malware's AES key/IV is plaintext in the script body, so this is
//! key-recovery, not crypto. We just want the decrypted bytes. Every
//! call is bounded by an explicit size cap to keep a malicious sample
//! from forcing unbounded work.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use thiserror::Error;

pub const MAX_CIPHERTEXT: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ciphertext too large: {0} bytes")]
    TooLarge(usize),
    #[error("invalid key length: {0}")]
    BadKey(usize),
    #[error("invalid iv length: {0}")]
    BadIv(usize),
    #[error("decrypt failed")]
    DecryptFailed,
    #[error("gunzip: {0}")]
    Gunzip(String),
}

type Aes128Cbc = cbc::Decryptor<aes::Aes128>;
type Aes192Cbc = cbc::Decryptor<aes::Aes192>;
type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ct.len() > MAX_CIPHERTEXT {
        return Err(CryptoError::TooLarge(ct.len()));
    }
    if ct.is_empty() || ct.len() % 16 != 0 {
        return Err(CryptoError::DecryptFailed);
    }
    if iv.len() != 16 {
        return Err(CryptoError::BadIv(iv.len()));
    }
    let mut buf = ct.to_vec();
    let out = match key.len() {
        16 => {
            let dec =
                Aes128Cbc::new_from_slices(key, iv).map_err(|_| CryptoError::BadKey(key.len()))?;
            dec.decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| CryptoError::DecryptFailed)?
                .to_vec()
        }
        24 => {
            let dec =
                Aes192Cbc::new_from_slices(key, iv).map_err(|_| CryptoError::BadKey(key.len()))?;
            dec.decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| CryptoError::DecryptFailed)?
                .to_vec()
        }
        32 => {
            let dec =
                Aes256Cbc::new_from_slices(key, iv).map_err(|_| CryptoError::BadKey(key.len()))?;
            dec.decrypt_padded_mut::<Pkcs7>(&mut buf)
                .map_err(|_| CryptoError::DecryptFailed)?
                .to_vec()
        }
        n => return Err(CryptoError::BadKey(n)),
    };
    Ok(out)
}

pub fn gunzip(input: &[u8], max_out: usize) -> Result<Vec<u8>, CryptoError> {
    use std::io::Read;
    let mut d = flate2::read::GzDecoder::new(input);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = d
            .read(&mut buf)
            .map_err(|e| CryptoError::Gunzip(e.to_string()))?;
        if n == 0 {
            break;
        }
        if out.len() + n > max_out {
            return Err(CryptoError::Gunzip(format!(
                "output exceeds {max_out} bytes"
            )));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut};
    use base64::Engine;

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    fn b64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    }

    #[test]
    fn aes256_cbc_roundtrip_with_known_key() {
        // Key and IV captured from a corpus sample's stage-3 PS.
        let key = b64("YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=");
        let iv = b64("PcWh4S5zqexZ2ueefstJ6A==");
        assert_eq!(key.len(), 32);
        assert_eq!(iv.len(), 16);

        let plaintext = b"hello world this is a payload that decrypts cleanly";
        // Round-trip encrypt with the same key/iv.
        let mut buf = plaintext.to_vec();
        buf.resize(plaintext.len() + 16, 0);
        let enc = Aes256CbcEnc::new_from_slices(&key, &iv).unwrap();
        let ct_slice = enc
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap();
        let ct = ct_slice.to_vec();

        let pt = aes_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn aes_cbc_rejects_oversize_ciphertext() {
        let key = vec![0u8; 32];
        let iv = vec![0u8; 16];
        let too_big = vec![0u8; MAX_CIPHERTEXT + 16];
        assert!(matches!(
            aes_cbc_decrypt(&key, &iv, &too_big),
            Err(CryptoError::TooLarge(_))
        ));
    }

    #[test]
    fn aes_cbc_rejects_bad_iv() {
        let key = vec![0u8; 32];
        let iv = vec![0u8; 8];
        let ct = vec![0u8; 16];
        assert!(matches!(
            aes_cbc_decrypt(&key, &iv, &ct),
            Err(CryptoError::BadIv(8))
        ));
    }

    #[test]
    fn aes_cbc_rejects_bad_key() {
        let key = vec![0u8; 17];
        let iv = vec![0u8; 16];
        let ct = vec![0u8; 16];
        assert!(matches!(
            aes_cbc_decrypt(&key, &iv, &ct),
            Err(CryptoError::BadKey(17))
        ));
    }

    #[test]
    fn gunzip_decompresses_known_blob() {
        use std::io::Write;
        let original = b"hello gzip world";
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(original).unwrap();
        let gz = e.finish().unwrap();
        let out = gunzip(&gz, 1024).unwrap();
        assert_eq!(out, original);
    }

    #[test]
    fn gunzip_respects_size_limit() {
        use std::io::Write;
        let big = vec![0u8; 100 * 1024];
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&big).unwrap();
        let gz = e.finish().unwrap();
        assert!(matches!(gunzip(&gz, 1024), Err(CryptoError::Gunzip(_))));
    }
}
