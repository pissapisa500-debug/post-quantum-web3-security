use clap::{Parser, Subcommand};
use falconed::{SigningKey, VerifyingKey, Signature};
use rand_core::OsRng;
use std::fs;
use std::path::PathBuf;

// Размеры ключей и подписей из документации falconed:
// SigningKey = 1313 bytes, VerifyingKey = 929 bytes, Signature = 730 bytes
const SIGNING_KEY_SIZE: usize = 1313;
const VERIFYING_KEY_SIZE: usize = 929;
const SIGNATURE_SIZE: usize = 730;

#[derive(Parser)]
#[command(name = "pqcrypto")]
#[command(about = "Post-Quantum Crypto Defender - Hybrid Signatures (Ed25519 + Falcon)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Сгенерировать гибридную ключевую пару (Ed25519 + Falcon)
    Generate {
        /// Базовое имя файла (без расширения)
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Подписать сообщение
    Sign {
        /// Путь к приватному ключу (.sk файл)
        #[arg(short, long)]
        key: PathBuf,
        /// Сообщение для подписи
        #[arg(short, long)]
        message: String,
    },
    /// Проверить подпись
    Verify {
        /// Путь к публичному ключу (.pk файл)
        #[arg(short, long)]
        pubkey: PathBuf,
        /// Сообщение, которое было подписано
        #[arg(short, long)]
        message: String,
        /// Подпись (hex-строка)
        #[arg(short, long)]
        signature: String,
    },
    /// Показать информацию о ключах
    Info {
        /// Путь к ключу (.sk или .pk файл)
        #[arg(short, long)]
        key: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Generate { output } => {
            generate_keys(&output);
        }
        Commands::Sign { key, message } => {
            sign_message(&key, &message);
        }
        Commands::Verify { pubkey, message, signature } => {
            verify_signature(&pubkey, &message, &signature);
        }
        Commands::Info { key } => {
            show_info(&key);
        }
    }
}

fn generate_keys(output: &PathBuf) {
    println!("🔐 Generating hybrid keys (Ed25519 + Falcon-512)...");
    
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().unwrap();
    
    let sk_path = output.with_extension("sk");
    let pk_path = output.with_extension("pk");
    
    // Получаем байты ключей
    let sk_bytes = sk.to_bytes();
    let pk_bytes = pk.to_bytes();
    
    fs::write(&sk_path, sk_bytes).unwrap();
    fs::write(&pk_path, pk_bytes).unwrap();
    
    println!("✅ Private key saved to:   {}", sk_path.display());
    println!("✅ Public key saved to:    {}", pk_path.display());
    println!("\n📊 Key sizes:");
    println!("   Private key: {} bytes", SIGNING_KEY_SIZE);
    println!("   Public key:  {} bytes", VERIFYING_KEY_SIZE);
}

fn sign_message(key_path: &PathBuf, message: &str) {
    println!("✍️  Signing message...");
    println!("   Message: \"{}\"", message);
    
    let sk_bytes = fs::read(key_path).expect("Failed to read private key");
    
    // Проверяем размер
    if sk_bytes.len() != SIGNING_KEY_SIZE {
        eprintln!("❌ Invalid key size: expected {}, got {}", SIGNING_KEY_SIZE, sk_bytes.len());
        std::process::exit(1);
    }
    
    // Конвертируем в массив фиксированного размера
    let sk_array: [u8; SIGNING_KEY_SIZE] = sk_bytes
        .try_into()
        .expect("Failed to convert to fixed-size array");
    
    let sk = SigningKey::from_bytes(&sk_array).expect("Invalid private key");
    
    let signature = sk.sign(message.as_bytes()).expect("Signing failed");
    let sig_bytes = signature.to_bytes();
    let sig_hex = hex::encode(sig_bytes);
    
    println!("✅ Signature (hex):");
    println!("{}", sig_hex);
    println!("\n📊 Signature size: {} bytes", SIGNATURE_SIZE);
}

fn verify_signature(pubkey_path: &PathBuf, message: &str, sig_hex: &str) {
    println!("🔍 Verifying signature...");
    println!("   Message: \"{}\"", message);
    
    let pk_bytes = fs::read(pubkey_path).expect("Failed to read public key");
    
    if pk_bytes.len() != VERIFYING_KEY_SIZE {
        eprintln!("❌ Invalid key size: expected {}, got {}", VERIFYING_KEY_SIZE, pk_bytes.len());
        std::process::exit(1);
    }
    
    let pk_array: [u8; VERIFYING_KEY_SIZE] = pk_bytes
        .try_into()
        .expect("Failed to convert to fixed-size array");
    
    let pk = VerifyingKey::from_bytes(&pk_array).expect("Invalid public key");
    
    let sig_bytes_vec = hex::decode(sig_hex).expect("Invalid hex signature");
    
    if sig_bytes_vec.len() != SIGNATURE_SIZE {
        eprintln!("❌ Invalid signature size: expected {}, got {}", SIGNATURE_SIZE, sig_bytes_vec.len());
        std::process::exit(1);
    }
    
    let sig_array: [u8; SIGNATURE_SIZE] = sig_bytes_vec
        .try_into()
        .expect("Failed to convert to fixed-size array");
    
    let signature = Signature::from_bytes(&sig_array).expect("Invalid signature");
    
    match pk.verify(message.as_bytes(), &signature) {
        Ok(_) => {
            println!("✅ Signature is VALID");
        }
        Err(e) => {
            println!("❌ Signature is INVALID: {:?}", e);
        }
    }
}

fn show_info(key_path: &PathBuf) {
    println!("📋 Key info for: {}", key_path.display());
    
    let bytes = fs::read(key_path).expect("Failed to read key");
    println!("   Size: {} bytes", bytes.len());
    
    let ext = key_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    
    match ext {
        "sk" => {
            if bytes.len() == SIGNING_KEY_SIZE {
                println!("   Type: FalconEd25519 private key (valid size)");
                // Пытаемся десериализовать для проверки
                if let Ok(sk_array) = <[u8; SIGNING_KEY_SIZE]>::try_from(bytes.as_slice()) {
                    if SigningKey::from_bytes(&sk_array).is_ok() {
                        println!("   Status: Valid key");
                    } else {
                        println!("   Status: Corrupted or invalid key data");
                    }
                }
            } else {
                println!("   Type: Invalid key size (expected {}, got {})", SIGNING_KEY_SIZE, bytes.len());
            }
        }
        "pk" => {
            if bytes.len() == VERIFYING_KEY_SIZE {
                println!("   Type: FalconEd25519 public key (valid size)");
                if let Ok(pk_array) = <[u8; VERIFYING_KEY_SIZE]>::try_from(bytes.as_slice()) {
                    if VerifyingKey::from_bytes(&pk_array).is_ok() {
                        println!("   Status: Valid key");
                    } else {
                        println!("   Status: Corrupted or invalid key data");
                    }
                }
            } else {
                println!("   Type: Invalid key size (expected {}, got {})", VERIFYING_KEY_SIZE, bytes.len());
            }
        }
        _ => {
            println!("   Type: Unknown key type (use .sk or .pk extension)");
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_constants_sizes() {
        assert_eq!(SIGNING_KEY_SIZE, 1313);
        assert_eq!(VERIFYING_KEY_SIZE, 929);
        assert_eq!(SIGNATURE_SIZE, 730);
    }

    #[test]
    fn test_constants_not_zero() {
        assert!(SIGNING_KEY_SIZE > 0);
        assert!(VERIFYING_KEY_SIZE > 0);
        assert!(SIGNATURE_SIZE > 0);
    }

    #[test]
    fn test_key_generation_creates_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("testkey");
        
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().unwrap();
        
        let sk_path = path.with_extension("sk");
        let pk_path = path.with_extension("pk");
        
        fs::write(&sk_path, sk.to_bytes()).unwrap();
        fs::write(&pk_path, pk.to_bytes()).unwrap();
        
        assert!(sk_path.exists());
        assert!(pk_path.exists());
    }
    
    #[test]
    fn test_sign_and_verify() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().unwrap();
        let message = b"Test message for quantum resistance";
        
        let signature = sk.sign(message).unwrap();
        assert!(pk.verify(message, &signature).is_ok());
    }
    
    #[test]
    fn test_wrong_signature_fails() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let pk1 = sk1.verifying_key().unwrap();
        let sk2 = SigningKey::generate(&mut OsRng);
        
        let message = b"Important transaction";
        let signature = sk2.sign(message).unwrap();
        
        // Подпись от другого ключа не должна пройти проверку
        assert!(pk1.verify(message, &signature).is_err());
    }
}