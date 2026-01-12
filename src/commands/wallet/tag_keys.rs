//! Tag key management commands for PIR-based transaction detection.
//!
//! Detection tags enable wallets to filter relevant Orchard transactions without
//! trial decryption, reducing bandwidth and battery usage for mobile wallets.

use anyhow::anyhow;
use blake2b_simd::Params;
use clap::{Args, Subcommand};
use rand::rngs::OsRng;
use uuid::Uuid;

use orchard::TaggingKey;
use zcash_client_backend::data_api::Account;
use zcash_client_sqlite::{util::SystemClock, WalletDb};
use zcash_keys::keys::UnifiedFullViewingKey;

use crate::{commands::select_account, config::get_wallet_network, data::get_db_paths};

const TAG_KEY_PERSONALIZATION: &[u8; 16] = b"Zcash_TagKeyDerv";

/// Derives a tagging key from an Orchard full viewing key.
///
/// The tagging key is derived using BLAKE2b with a personalization string,
/// taking the FVK bytes as input. This produces a deterministic 32-byte key
/// that can be shared with senders to enable tag-based detection.
pub fn derive_tagging_key(ufvk: &UnifiedFullViewingKey) -> Option<TaggingKey> {
    let orchard_fvk = ufvk.orchard()?;
    let fvk_bytes = orchard_fvk.to_bytes();

    let key = Params::new()
        .hash_length(32)
        .personal(TAG_KEY_PERSONALIZATION)
        .hash(&fvk_bytes);

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key.as_bytes());

    Some(TaggingKey::from_bytes(key_bytes))
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Display the tagging key for an account
    Show(ShowCommand),

    /// Export the tagging key in a shareable format
    Export(ExportCommand),

    /// Generate detection tags for specific indices
    Generate(GenerateCommand),

    /// Verify that a tag matches a specific index
    Verify(VerifyCommand),
}

/// Show the tagging key for an account
#[derive(Debug, Args)]
pub(crate) struct ShowCommand {
    /// The UUID of the account
    #[arg(long)]
    account_id: Option<Uuid>,
}

impl ShowCommand {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;

        let account = select_account(&db_data, self.account_id)?;
        let ufvk = account
            .ufvk()
            .ok_or(anyhow!("Account has no unified full viewing key"))?;

        let tagging_key = derive_tagging_key(ufvk)
            .ok_or(anyhow!("Account has no Orchard key component"))?;

        eprintln!("Tagging Key Information");
        eprintln!("=======================");
        eprintln!();
        eprintln!("Account: {:?}", account.id());
        eprintln!();
        eprintln!("Tag Key (hex): {}", hex::encode(tagging_key.to_bytes()));
        eprintln!();
        eprintln!("This key can be shared with senders to enable tag-based detection.");
        eprintln!("Tags generated from this key allow PIR pre-filtering of transactions.");

        Ok(())
    }
}

/// Export the tagging key in various formats
#[derive(Debug, Args)]
pub(crate) struct ExportCommand {
    /// The UUID of the account
    #[arg(long)]
    account_id: Option<Uuid>,

    /// Output format: hex, base64, or json
    #[arg(long, default_value = "hex")]
    format: String,
}

impl ExportCommand {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;

        let account = select_account(&db_data, self.account_id)?;
        let ufvk = account
            .ufvk()
            .ok_or(anyhow!("Account has no unified full viewing key"))?;

        let tagging_key = derive_tagging_key(ufvk)
            .ok_or(anyhow!("Account has no Orchard key component"))?;

        let key_bytes = tagging_key.to_bytes();

        match self.format.as_str() {
            "hex" => println!("{}", hex::encode(key_bytes)),
            "base64" => {
                use base64::{engine::general_purpose::STANDARD, Engine};
                println!("{}", STANDARD.encode(key_bytes));
            }
            "json" => {
                println!(
                    "{{\"tagging_key\": \"{}\", \"format\": \"hex\"}}",
                    hex::encode(key_bytes)
                );
            }
            _ => return Err(anyhow!("Unknown format: {}. Use hex, base64, or json.", self.format)),
        }

        Ok(())
    }
}

/// Generate detection tags for specific indices
#[derive(Debug, Args)]
pub(crate) struct GenerateCommand {
    /// The UUID of the account
    #[arg(long)]
    account_id: Option<Uuid>,

    /// Starting index for tag generation
    #[arg(long, default_value = "0")]
    start: u64,

    /// Number of tags to generate
    #[arg(long, default_value = "10")]
    count: u64,

    /// Output format: hex or json
    #[arg(long, default_value = "hex")]
    format: String,
}

impl GenerateCommand {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;

        let account = select_account(&db_data, self.account_id)?;
        let ufvk = account
            .ufvk()
            .ok_or(anyhow!("Account has no unified full viewing key"))?;

        let tagging_key = derive_tagging_key(ufvk)
            .ok_or(anyhow!("Account has no Orchard key component"))?;

        let end = self.start.saturating_add(self.count);

        match self.format.as_str() {
            "hex" => {
                eprintln!("Generated tags for indices {} to {}:", self.start, end - 1);
                eprintln!();
                for index in self.start..end {
                    let tag = tagging_key.generate_tag(index);
                    println!("{:>8}: {}", index, hex::encode(tag));
                }
            }
            "json" => {
                let tags: Vec<_> = (self.start..end)
                    .map(|index| {
                        let tag = tagging_key.generate_tag(index);
                        format!("{{\"index\": {}, \"tag\": \"{}\"}}", index, hex::encode(tag))
                    })
                    .collect();
                println!("[{}]", tags.join(", "));
            }
            _ => return Err(anyhow!("Unknown format: {}. Use hex or json.", self.format)),
        }

        Ok(())
    }
}

/// Verify that a tag matches a specific index
#[derive(Debug, Args)]
pub(crate) struct VerifyCommand {
    /// The UUID of the account
    #[arg(long)]
    account_id: Option<Uuid>,

    /// The tag to verify (hex encoded, 32 hex chars = 16 bytes)
    #[arg(long)]
    tag: String,

    /// The expected index
    #[arg(long)]
    index: u64,
}

impl VerifyCommand {
    pub(crate) fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;

        let account = select_account(&db_data, self.account_id)?;
        let ufvk = account
            .ufvk()
            .ok_or(anyhow!("Account has no unified full viewing key"))?;

        let tagging_key = derive_tagging_key(ufvk)
            .ok_or(anyhow!("Account has no Orchard key component"))?;

        let tag_bytes = hex::decode(&self.tag)
            .map_err(|_| anyhow!("Invalid hex encoding for tag"))?;

        if tag_bytes.len() != 16 {
            return Err(anyhow!(
                "Tag must be 16 bytes (32 hex characters), got {} bytes",
                tag_bytes.len()
            ));
        }

        let mut tag_array = [0u8; 16];
        tag_array.copy_from_slice(&tag_bytes);

        if tagging_key.verify_tag(&tag_array, self.index) {
            eprintln!("✓ Tag matches index {}", self.index);
            println!("true");
        } else {
            eprintln!("✗ Tag does NOT match index {}", self.index);
            let expected_tag = tagging_key.generate_tag(self.index);
            eprintln!("  Expected tag for index {}: {}", self.index, hex::encode(expected_tag));
            println!("false");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_derivation_is_deterministic() {
        // Same input bytes must always produce the same tagging key
        let fvk_bytes = [0x42u8; 96];
        
        let key1 = Params::new()
            .hash_length(32)
            .personal(TAG_KEY_PERSONALIZATION)
            .hash(&fvk_bytes);
        
        let key2 = Params::new()
            .hash_length(32)
            .personal(TAG_KEY_PERSONALIZATION)
            .hash(&fvk_bytes);
        
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn tag_generation_verification_roundtrip() {
        let key = TaggingKey::from_bytes([0x42; 32]);
        
        for index in [0u64, 1, 42, 1000, u64::MAX] {
            let tag = key.generate_tag(index);
            assert!(key.verify_tag(&tag, index), "Tag should verify at index {}", index);
            assert!(!key.verify_tag(&tag, index.wrapping_add(1)), "Tag should not verify at wrong index");
        }
    }
}
