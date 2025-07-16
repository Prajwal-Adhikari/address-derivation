use alloy_signer_local::PrivateKeySigner;
use anyhow::{Result, anyhow};
use bip32::{DerivationPath, Seed as Bip32Seed, XPrv};
use bip39::{Language, Mnemonic};
use dotenv::dotenv;
use sha2::{Digest, Sha256};
use solana_sdk::signature::Signer as SolanaSigner;
use solana_sdk::signer::keypair::Keypair;
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
/// This is used to derive a user-specific or token-specific part of the derivation path.
///
/// WARNING: This method carries a non-zero risk of collision. For a production system
/// with many users, using a unique, sequential ID from a database is safer.
fn generate_deterministic_id(input_string: &str) -> Result<u32> {
    // 1. Hash the input string using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(input_string.as_bytes());
    let hash_result = hasher.finalize();

    // 2. Take the first 4 bytes of the hash to create a u32
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&hash_result[0..4]);
    let id = u32::from_be_bytes(bytes);

    // 3. Apply a mask to ensure it's a valid non-hardened index (31-bit)
    // The BIP-32 spec reserves the most significant bit for hardening.
    Ok(id & 0x7FFFFFFF)
}

/// Derives an Ethereum address using the full derivation path.
fn derive_ethereum_address(
    mnemonic_phrase: &str,
    user_id: u32,
    token_address_index: u32,
) -> Result<()> {
    // Construct the full, hardened BIP-44 path for Ethereum
    let derivation_path = format!(
        "m/{}'/{}'/{}'/{}'/{}",
        BIP44_PURPOSE, ETH_COIN_TYPE, user_id, CHANGE_INDEX, token_address_index
    );
    println!("Derivation Path: {}", derivation_path);

    // 1. Generate the master seed from the mnemonic
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_phrase)?;
    let seed = mnemonic.to_seed(""); // Use empty passphrase

    // 2. Derive the private key using tiny-hderive
    let extended_key = ExtendedPrivKey::derive(&seed, &*derivation_path)
        .map_err(|e| anyhow!("Failed to derive key: {:?}", e))?;

    // 3. Create a PrivateKeySigner from the derived private key
    let wallet = PrivateKeySigner::from_bytes((&extended_key.secret()).into())
        .map_err(|e| anyhow!("Failed to create signer: {:?}", e))?;

    // The .address() method on the Signer trait returns the checksummed Ethereum address
    println!("✅ Derived Ethereum Deposit Address: {}", wallet.address());
    Ok(())
}

/// Main function to drive the POC.
fn main() -> Result<()> {
    // --- Setup: Load Master Mnemonic ---
    dotenv().ok();
    let phrase = env::var("MASTER_MNEMONIC")
        .expect("MASTER_MNEMONIC must be set in your .env file. Run the setup function if needed.");

    println!("🔒 Master Mnemonic loaded successfully.\n");

    // --- User Input ---
    println!("Enter the user's L2 address:");
    let mut l2_address = String::new();
    io::stdin().read_line(&mut l2_address)?;

    println!("\nEnter the chain ID ('eth' or 'sol'):");
    let mut chain_id = String::new();
    io::stdin().read_line(&mut chain_id)?;

    println!("\nEnter the token contract address:");
    let mut token_address = String::new();
    io::stdin().read_line(&mut token_address)?;

    // Trim whitespace from inputs
    let l2_address = l2_address.trim();
    let chain_id = chain_id.trim().to_lowercase();
    let token_address = token_address.trim();

    println!("\n--- Generating Deterministic IDs ---");

    // --- Deterministic ID Generation ---
    let user_id = generate_deterministic_id(l2_address)?;
    println!("User L2 Address '{}' -> User ID: {}", l2_address, user_id);

    let token_address_index = generate_deterministic_id(token_address)?;
    println!(
        "Token Address '{}' -> Address Index: {}",
        token_address, token_address_index
    );

    println!("\n--- Deriving Deposit Address ---");

    // --- Address Derivation ---
    match chain_id.as_str() {
        "eth" => derive_ethereum_address(&phrase, user_id, token_address_index)?,
        // "sol" => derive_solana_address(&phrase, user_id, token_address_index)?,
        _ => return Err(anyhow!("Invalid chain ID. Please use 'eth' or 'sol'.")),
    }

    // Run setup_mnemonic if needed to generate a new mnemonic
    // setup_mnemonic()?;

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
