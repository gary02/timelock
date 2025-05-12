use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rand::{Rng, thread_rng};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::{Parser, Subcommand};
use std::{thread, time::Duration};

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

const KEY: &[u8; 16] = b"0123456789abcdef"; // 16-byte key
const IV: &[u8; 16] = b"abcdef0123456789"; // 16-byte IV

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 生成加密字符串
    Generate {
        /// 有效时间（分钟）
        #[arg(short, long)]
        time: u32,
    },
    /// 解密并等待指定时间
    Reveal {
        /// 加密字符串
        #[arg(short, long)]
        input: String,
    },
}

fn generate_passcode() -> String {
    let mut rng = thread_rng();
    (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
}

fn encrypt(data: &str) -> String {
    let cipher = Aes128Cbc::new_from_slices(KEY, IV).unwrap();
    let ciphertext = cipher.encrypt_vec(data.as_bytes());
    BASE64.encode(ciphertext)
}

fn decrypt(enc_data: &str) -> String {
    let cipher = Aes128Cbc::new_from_slices(KEY, IV).unwrap();
    let decoded = BASE64.decode(enc_data).unwrap();
    let decrypted_data = cipher.decrypt_vec(&decoded).unwrap();
    String::from_utf8(decrypted_data).unwrap()
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Generate { time } => {
            let passcode = generate_passcode();
            let plain = format!("{}:{}", passcode, time);
            let encrypted = encrypt(&plain);
            println!("Passcode: {}", passcode);
            println!("Encrypted String: {}", encrypted);
        }
        Commands::Reveal { input } => {
            let decrypted = decrypt(input);
            let parts: Vec<&str> = decrypted.split(':').collect();
            if parts.len() != 2 {
                eprintln!("Invalid decrypted format");
                return;
            }
            let passcode = parts[0];
            let wait_minutes: u64 = parts[1].parse().unwrap_or(0);
            println!("Waiting {} minutes...", wait_minutes);
            thread::sleep(Duration::from_secs(wait_minutes * 60));
            println!("Passcode: {}", passcode);
        }
    }
}

