use alloy_signer_local::PrivateKeySigner;
use anyhow::{Result, anyhow};
use bip39::{Language, Mnemonic};
use dotenv::dotenv;
use sha2::{Digest, Sha256};
use solana_sdk::signer::SeedDerivable;
use solana_sdk::signer::{Signer as SolanaSigner, keypair::Keypair}; // Import Solana signer
use std::env;
use std::fs::File;
use std::io::{self, Write};
use tiny_hderive::bip32::ExtendedPrivKey;

// --- Constants for BIP-44 Derivation ---
const BIP44_PURPOSE: u32 = 44;
const ETH_COIN_TYPE: u32 = 60;
const SOL_COIN_TYPE: u32 = 501;
const CHANGE_INDEX: u32 = 0; // External chain

/// Generates a deterministic, non-hardened 31-bit integer ID from a string input.
fn generate_deterministic_id(input_string: &str) -> Result<u32> {
    let mut hasher = Sha256::new();
    hasher.update(input_string.as_bytes());
    let hash_result = hasher.finalize();
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&hash_result[0..4]);
    let id = u32::from_be_bytes(bytes);
    Ok(id & 0x7FFFFFFF)
}

/// Derives an Ethereum address using the full derivation path.
fn derive_ethereum_address(
    mnemonic_phrase: &str,
    user_id: u32,
    token_address_index: u32,
) -> Result<()> {
    let derivation_path = format!(
        "m/{}'/{}'/{}'/{}'/{}",
        BIP44_PURPOSE, ETH_COIN_TYPE, user_id, CHANGE_INDEX, token_address_index
    );
    println!("Derivation Path: {}", derivation_path);

    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)?;
    let seed = mnemonic.to_seed("");

    let extended_key = ExtendedPrivKey::derive(&seed, &*derivation_path)
        .map_err(|e| anyhow!("Failed to derive key: {:?}", e))?;

    let wallet = PrivateKeySigner::from_bytes((&extended_key.secret()).into())
        .map_err(|e| anyhow!("Failed to create signer: {:?}", e))?;

    println!("✅ Derived Ethereum Deposit Address: {}", wallet.address());
    Ok(())
}

/// Derives a Solana address using the full derivation path.
fn derive_solana_address(
    mnemonic_phrase: &str,
    user_id: u32,
    token_address_index: u32,
) -> Result<()> {
    let derivation_path = format!(
        "m/{}'/{}'/{}'/{}'/{}",
        BIP44_PURPOSE, SOL_COIN_TYPE, user_id, CHANGE_INDEX, token_address_index
    );
    println!("Derivation Path: {}", derivation_path);

    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)?;
    let seed = mnemonic.to_seed("");

    let extended_key = ExtendedPrivKey::derive(&seed, &*derivation_path)
        .map_err(|e| anyhow!("Failed to derive key: {:?}", e))?;

    // Create a Solana Keypair from the 32-byte secret (private key).
    // The `from_seed` method in the solana_sdk is designed for this.
    let keypair = Keypair::from_seed(&extended_key.secret())
        .map_err(|e| anyhow!("Failed to create Solana keypair from seed: {:?}", e))?;

    println!("✅ Derived Solana Deposit Address: {}", keypair.pubkey());
    Ok(())
}

/// Main function to drive the POC.
fn main() -> Result<()> {
    dotenv().ok();
    let phrase = env::var("MASTER_MNEMONIC")
        .expect("MASTER_MNEMONIC must be set in your .env file. Run the setup function if needed.");
    println!("🔒 Master Mnemonic loaded successfully.\n");

    let master_key = derive_extended_master_key(&phrase)?;
    println!(
        "🔑 Extended Master Private Key:\n  Private Key: {}",
        hex::encode(master_key.secret()),
    );

    println!("\nEnter the user's L2 address:");
    let mut l2_address = String::new();
    io::stdin().read_line(&mut l2_address)?;

    println!("\nEnter the chain ID ('eth' or 'sol'):");
    let mut chain_id = String::new();
    io::stdin().read_line(&mut chain_id)?;

    println!("\nEnter the token contract address:");
    let mut token_address = String::new();
    io::stdin().read_line(&mut token_address)?;

    let l2_address = l2_address.trim();
    let chain_id = chain_id.trim().to_lowercase();
    let token_address = token_address.trim();

    println!("\n--- Generating Deterministic IDs ---");

    let user_id = generate_deterministic_id(l2_address)?;
    println!("User L2 Address '{}' -> User ID: {}", l2_address, user_id);

    let token_address_index = generate_deterministic_id(token_address)?;
    println!(
        "Token Address '{}' -> Address Index: {}",
        token_address, token_address_index
    );

    println!("\n--- Deriving Deposit Address ---");

    match chain_id.as_str() {
        "eth" => derive_ethereum_address(&phrase, user_id, token_address_index)?,
        "sol" => derive_solana_address(&phrase, user_id, token_address_index)?,
        _ => return Err(anyhow!("Invalid chain ID. Please use 'eth' or 'sol'.")),
    }

    Ok(())
}

/// One-time setup function to generate and save a master mnemonic.
fn setup_mnemonic() -> Result<()> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12)?;
    let phrase = mnemonic.to_string();
    println!("Generated Mnemonic: {}", phrase);
    let mut file = File::create(".env")?;
    writeln!(file, "MASTER_MNEMONIC=\"{}\"", phrase)?;
    println!("\n✅ Master mnemonic saved to .env file.");
    println!("⚠️ IMPORTANT: This is for POC only. Never commit this file to version control!");
    Ok(())
}

/// Derives the extended master private key from the mnemonic phrase.
fn derive_extended_master_key(mnemonic_phrase: &str) -> Result<ExtendedPrivKey> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)?;
    let seed = mnemonic.to_seed("");
    let master_key = ExtendedPrivKey::derive(&seed, "m")
        .map_err(|e| anyhow!("Failed to derive master key: {:?}", e))?;
    Ok(master_key)
}
