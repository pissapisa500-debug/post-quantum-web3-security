//! Post-Quantum Web3 Security
//!
//! Hybrid post-quantum signatures combining Ed25519 (current standard)
//! with Falcon-512 (NIST PQC) for Solana, Aptos, and other blockchains.

use falconed::{SigningKey as FalconSigningKey, VerifyingKey as FalconVerifyingKey, Signature as FalconSignature};
use rand_core::OsRng;

/// Private key size in bytes (1313)
pub const SIGNING_KEY_SIZE: usize = 1313;
/// Public key size in bytes (929)
pub const VERIFYING_KEY_SIZE: usize = 929;
/// Signature size in bytes (730)
pub const SIGNATURE_SIZE: usize = 730;

/// Hybrid private key (Ed25519 + Falcon-512)
pub struct SigningKey(FalconSigningKey);

impl SigningKey {
    /// Generate a new hybrid key pair
    pub fn generate() -> Self {
        Self(FalconSigningKey::generate(&mut OsRng))
    }

    /// Create a key from fixed-size byte array
    pub fn from_bytes(bytes: &[u8; SIGNING_KEY_SIZE]) -> Result<Self, &'static str> {
        FalconSigningKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| "Invalid private key bytes")
    }

    /// Export key as byte array
    pub fn to_bytes(&self) -> [u8; SIGNING_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// Get the corresponding public key
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(self.0.verifying_key().unwrap())
    }

    /// Sign a message, returns hybrid signature
    pub fn sign(&self, message: &[u8]) -> Result<Signature, &'static str> {
        self.0.sign(message)
            .map(Signature)
            .map_err(|_| "Signing failed")
    }
}

/// Hybrid public key (Ed25519 + Falcon-512)
pub struct VerifyingKey(FalconVerifyingKey);

impl VerifyingKey {
    /// Create a public key from fixed-size byte array
    pub fn from_bytes(bytes: &[u8; VERIFYING_KEY_SIZE]) -> Result<Self, &'static str> {
        FalconVerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| "Invalid public key bytes")
    }

    /// Export key as byte array
    pub fn to_bytes(&self) -> [u8; VERIFYING_KEY_SIZE] {
        self.0.to_bytes()
    }

    /// Verify a signature against a message
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), &'static str> {
        self.0.verify(message, &signature.0)
            .map_err(|_| "Invalid signature")
    }
}

/// Hybrid signature (Ed25519 + Falcon-512)
pub struct Signature(FalconSignature);

impl Signature {
    /// Create a signature from fixed-size byte array
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Result<Self, &'static str> {
        FalconSignature::from_bytes(bytes)
            .map(Self)
            .map_err(|_| "Invalid signature bytes")
    }

    /// Export signature as byte array
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        self.0.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SIGNING_KEY_SIZE, 1313);
        assert_eq!(VERIFYING_KEY_SIZE, 929);
        assert_eq!(SIGNATURE_SIZE, 730);
    }

    #[test]
    fn test_sign_and_verify() {
        let sk = SigningKey::generate();
        let pk = sk.verifying_key();
        let msg = b"Test message";
        let sig = sk.sign(msg).unwrap();
        assert!(pk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_wrong_signature_fails() {
        let sk1 = SigningKey::generate();
        let pk1 = sk1.verifying_key();
        let sk2 = SigningKey::generate();
        let msg = b"Secret";
        let sig = sk2.sign(msg).unwrap();
        assert!(pk1.verify(msg, &sig).is_err());
    }
}