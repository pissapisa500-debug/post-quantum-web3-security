use clap::{Parser, Subcommand};
use pq_web3_security::{
    Signature, SigningKey, VerifyingKey, SIGNATURE_SIZE, SIGNING_KEY_SIZE, VERIFYING_KEY_SIZE,
};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "pqcrypto")]
#[command(about = "Post-Quantum Crypto Defender - Hybrid Signatures (Ed25519 + Falcon-512)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate hybrid key pair (Ed25519 + Falcon-512)
    Generate {
        /// Base output filename (without extension)
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Sign a message
    Sign {
        /// Path to private key (.sk file)
        #[arg(short, long)]
        key: PathBuf,
        /// Message to sign
        #[arg(short, long)]
        message: String,
    },
    /// Verify a signature
    Verify {
        /// Path to public key (.pk file)
        #[arg(short, long)]
        pubkey: PathBuf,
        /// Message that was signed
        #[arg(short, long)]
        message: String,
        /// Signature (hex string)
        #[arg(short, long)]
        signature: String,
    },
    /// Show key information
    Info {
        /// Path to key file (.sk or .pk)
        #[arg(short, long)]
        key: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { output } => generate_keys(&output),
        Commands::Sign { key, message } => sign_message(&key, &message),
        Commands::Verify {
            pubkey,
            message,
            signature,
        } => verify_signature(&pubkey, &message, &signature),
        Commands::Info { key } => show_info(&key),
    }
}

fn generate_keys(output: &Path) {
    println!("🔐 Generating hybrid keys (Ed25519 + Falcon-512)...");

    let sk = SigningKey::generate();
    let pk = sk.verifying_key();

    let sk_path = output.with_extension("sk");
    let pk_path = output.with_extension("pk");

    fs::write(&sk_path, sk.to_bytes()).unwrap();
    fs::write(&pk_path, pk.to_bytes()).unwrap();

    println!("✅ Private key saved to: {}", sk_path.display());
    println!("✅ Public key saved to: {}", pk_path.display());
    println!("\n📊 Key sizes:");
    println!("   Private key: {} bytes", SIGNING_KEY_SIZE);
    println!("   Public key:  {} bytes", VERIFYING_KEY_SIZE);
}

fn sign_message(key_path: &Path, message: &str) {
    println!("✍️ Signing message...");
    println!("   Message: \"{}\"", message);

    let sk_bytes = fs::read(key_path).expect("Failed to read private key");

    if sk_bytes.len() != SIGNING_KEY_SIZE {
        eprintln!(
            "❌ Invalid key size: expected {}, got {}",
            SIGNING_KEY_SIZE,
            sk_bytes.len()
        );
        std::process::exit(1);
    }

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

fn verify_signature(pubkey_path: &Path, message: &str, sig_hex: &str) {
    println!("🔍 Verifying signature...");
    println!("   Message: \"{}\"", message);

    let pk_bytes = fs::read(pubkey_path).expect("Failed to read public key");

    if pk_bytes.len() != VERIFYING_KEY_SIZE {
        eprintln!(
            "❌ Invalid key size: expected {}, got {}",
            VERIFYING_KEY_SIZE,
            pk_bytes.len()
        );
        std::process::exit(1);
    }

    let pk_array: [u8; VERIFYING_KEY_SIZE] = pk_bytes
        .try_into()
        .expect("Failed to convert to fixed-size array");
    let pk = VerifyingKey::from_bytes(&pk_array).expect("Invalid public key");

    let sig_bytes_vec = hex::decode(sig_hex).expect("Invalid hex signature");

    if sig_bytes_vec.len() != SIGNATURE_SIZE {
        eprintln!(
            "❌ Invalid signature size: expected {}, got {}",
            SIGNATURE_SIZE,
            sig_bytes_vec.len()
        );
        std::process::exit(1);
    }

    let sig_array: [u8; SIGNATURE_SIZE] = sig_bytes_vec
        .try_into()
        .expect("Failed to convert to fixed-size array");
    let signature = Signature::from_bytes(&sig_array).expect("Invalid signature");

    match pk.verify(message.as_bytes(), &signature) {
        Ok(_) => println!("✅ Signature is VALID"),
        Err(e) => println!("❌ Signature is INVALID: {}", e),
    }
}

fn show_info(key_path: &Path) {
    println!("📋 Key info for: {}", key_path.display());

    let bytes = fs::read(key_path).expect("Failed to read key");
    println!("   Size: {} bytes", bytes.len());

    let ext = key_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    match ext {
        "sk" => {
            if bytes.len() == SIGNING_KEY_SIZE {
                println!("   Type: FalconEd25519 private key (valid size)");
                if let Ok(sk_array) = <[u8; SIGNING_KEY_SIZE]>::try_from(bytes.as_slice()) {
                    if SigningKey::from_bytes(&sk_array).is_ok() {
                        println!("   Status: Valid key");
                    } else {
                        println!("   Status: Corrupted or invalid key data");
                    }
                }
            } else {
                println!(
                    "   Type: Invalid key size (expected {}, got {})",
                    SIGNING_KEY_SIZE,
                    bytes.len()
                );
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
                println!(
                    "   Type: Invalid key size (expected {}, got {})",
                    VERIFYING_KEY_SIZE,
                    bytes.len()
                );
            }
        }
        _ => {
            println!("   Type: Unknown key type (use .sk or .pk extension)");
        }
    }
}
