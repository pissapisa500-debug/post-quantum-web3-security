use clap::{Parser, Subcommand};
use falconed::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::fs;
use std::path::PathBuf;

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
    
    fs::write(&sk_path, sk.to_bytes()).unwrap();
    fs::write(&pk_path, pk.to_bytes()).unwrap();
    
    println!("✅ Private key saved to:   {}", sk_path.display());
    println!("✅ Public key saved to:    {}", pk_path.display());
    println!("\n📊 Key sizes:");
    println!("   Private key: {} bytes", sk.to_bytes().len());
    println!("   Public key:  {} bytes", pk.to_bytes().len());
}

fn sign_message(key_path: &PathBuf, message: &str) {
    println!("✍️  Signing message...");
    println!("   Message: \"{}\"", message);
    
    let sk_bytes = fs::read(key_path).expect("Failed to read private key");
    let sk = SigningKey::from_bytes(&sk_bytes).expect("Invalid private key");
    
    let signature = sk.sign(message.as_bytes()).expect("Signing failed");
    let sig_hex = hex::encode(signature.to_bytes());
    
    println!("✅ Signature (hex):");
    println!("{}", sig_hex);
    println!("\n📊 Signature size: {} bytes", signature.to_bytes().len());
}

fn verify_signature(pubkey_path: &PathBuf, message: &str, sig_hex: &str) {
    println!("🔍 Verifying signature...");
    println!("   Message: \"{}\"", message);
    
    let pk_bytes = fs::read(pubkey_path).expect("Failed to read public key");
    let pk = VerifyingKey::from_bytes(&pk_bytes).expect("Invalid public key");
    
    let sig_bytes = hex::decode(sig_hex).expect("Invalid hex signature");
    let signature = falconed::Signature::from_bytes(&sig_bytes).expect("Invalid signature");
    
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
            match SigningKey::from_bytes(&bytes) {
                Ok(_) => println!("   Type: Valid FalconEd25519 private key"),
                Err(e) => println!("   Type: Invalid key: {:?}", e),
            }
        }
        "pk" => {
            match VerifyingKey::from_bytes(&bytes) {
                Ok(_) => println!("   Type: Valid FalconEd25519 public key"),
                Err(e) => println!("   Type: Invalid key: {:?}", e),
            }
        }
        _ => {
            println!("   Type: Unknown key type (use .sk or .pk extension)");
        }
    }
}
