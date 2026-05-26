//! Post-Quantum Web3 Security
//! Hybrid post-quantum signatures combining ed25519 (current standard)
//! with Falcon-512 (NIST PQC) for Solana, Aptos, and other blockchains.

use falconed::{
    Signature as FalconSignature, SigningKey as FalconSigningKey,
    VerifyingKey as FalconVerifyingKey,
};
use rand_core::OsRng;

/// Размер приватного ключа в байтах (1313)
pub const SIGNING_KEY_SIZE: usize = 1313;
/// Размер публичного ключа в байтах (929)
pub const VERIFYING_KEY_SIZE: usize = 929;
/// Размер подписи в байтах (730)
pub const SIGNATURE_SIZE: usize = 730;

/// Гибридный приватный ключ (ed25519 + Falcon-512)
pub struct SigningKey(FalconSigningKey);

impl SigningKey {
    /// Генерирует новую гибридную ключевую пару
    pub fn generate() -> Self {
        Self(FalconSigningKey::generate(&mut OsRng))
    }

    /// Создает ключ из байтов (массив фиксированного размера)
    pub fn from_bytes(bytes: &[u8; SIGNING_KEY_SIZE]) -> Result<Self, &'static str> {
        FalconSigningKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| "Invalid private key bytes")
    }

    /// Возвращает байтовое представление ключа
    pub fn to_bytes(&self) -> [u8; SIGNING_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// Возвращает соответствующий публичный ключ
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key().unwrap())
    }

    /// Подписывает сообщение, возвращает гибридную подпись
    pub fn sign(&self, message: &[u8]) -> Result<Signature, &'static str> {
        self.0
            .sign(message)
            .map(Signature)
            .map_err(|_| "Signing failed")
    }
}

/// Гибридный публичный ключ (ed25519 + Falcon-512)
pub struct VerifyingKey(FalconVerifyingKey);

impl VerifyingKey {
    /// Создает ключ из байтов (массив фиксированного размера)
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_SIZE]) -> Result<Self, &'static str> {
        FalconVerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| "Invalid public key bytes")
    }

    /// Возвращает байтовое представление ключа
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// Проверяет подпись сообщения
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), &'static str> {
        self.0
            .verify(message, &signature.0)
            .map_err(|_| "Invalid signature")
    }
}

/// Гибридная подпись (ed25519 + Falcon-512)
pub struct Signature(FalconSignature);

impl Signature {
    /// Создает подпись из байтов (массив фиксированного размера)
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Result<Self, &'static str> {
        FalconSignature::from_bytes(bytes)
            .map(Self)
            .map_err(|_| "Invalid signature bytes")
    }

    /// Возвращает байтовое представление подписи
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lib_constants() {
        assert_eq!(SIGNING_KEY_SIZE, 1313);
        assert_eq!(VERIFYING_KEY_SIZE, 929);
        assert_eq!(SIGNATURE_SIZE, 730);
    }

    #[test]
    fn test_lib_sign_and_verify() {
        let sk = SigningKey::generate();
        let pk = sk.verifying_key();
        let msg = b"Library test message";

        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_lib_wrong_key_fails() {
        let sk1 = SigningKey::generate();
        let pk1 = sk1.verifying_key();
        let sk2 = SigningKey::generate();

        let msg = b"Secret transaction";
        let sig = sk2.sign(msg).unwrap();

        assert!(pk1.verify(msg, &sig).is_err());
    }
}
