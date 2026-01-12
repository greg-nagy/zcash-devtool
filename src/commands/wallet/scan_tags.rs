//! PIR-based tag scanning for efficient Orchard transaction detection.
//!
//! This module provides functionality to scan compact blocks using detection tags,
//! pre-filtering Orchard actions before expensive trial decryption.

use std::collections::HashSet;

use anyhow::anyhow;
use clap::Args;
use futures_util::TryStreamExt;
use rand::rngs::OsRng;
use tonic::transport::Channel;
use tracing::info;
use uuid::Uuid;

use zcash_client_backend::{
    data_api::Account,
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
    scanning::matches_tag,
};
use zcash_client_sqlite::{util::SystemClock, WalletDb};
use zcash_protocol::consensus::BlockHeight;

use crate::{
    commands::select_account,
    config::get_wallet_network,
    data::get_db_paths,
    remote::Servers,
};

use super::tag_keys::derive_tagging_key;

/// Scan the chain for transactions using PIR tag pre-filtering
#[derive(Debug, Args)]
pub(crate) struct Command {
    /// The UUID of the account to scan for
    #[arg(long)]
    account_id: Option<Uuid>,

    /// The server to scan from
    #[arg(short, long)]
    #[arg(default_value = "ecc", value_parser = Servers::parse)]
    server: Servers,

    /// Start height for scanning
    #[arg(long)]
    start_height: Option<u32>,

    /// End height for scanning (defaults to chain tip)
    #[arg(long)]
    end_height: Option<u32>,

    /// Starting tag index (tags from start_index to start_index + tag_window will be generated)
    #[arg(long, default_value = "0")]
    start_index: u64,

    /// Number of tag indices to check (tag window size)
    #[arg(long, default_value = "1000")]
    tag_window: u64,

    /// Show detailed output for each matching action
    #[arg(long)]
    verbose: bool,
}

impl Command {
    pub(crate) async fn run(self, wallet_dir: Option<String>) -> Result<(), anyhow::Error> {
        let params = get_wallet_network(wallet_dir.as_ref())?;
        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params.clone(), SystemClock, OsRng)?;

        let account = select_account(&db_data, self.account_id)?;
        let ufvk = account
            .ufvk()
            .ok_or(anyhow!("Account has no unified full viewing key"))?;

        let tagging_key = derive_tagging_key(ufvk)
            .ok_or(anyhow!("Account has no Orchard key component"))?;

        // Generate expected tags for the window
        let expected_tags: HashSet<[u8; 16]> = (self.start_index
            ..self.start_index.saturating_add(self.tag_window))
            .map(|i| tagging_key.generate_tag(i))
            .collect();

        info!(
            "Generated {} expected tags for indices {} to {}",
            expected_tags.len(),
            self.start_index,
            self.start_index + self.tag_window - 1
        );

        let mut client = self.server.pick(&params)?.connect_direct().await?;

        // Get chain tip if end height not specified
        let tip_height: u32 = client
            .get_latest_block(service::ChainSpec::default())
            .await?
            .get_ref()
            .height
            .try_into()
            .map_err(|_| anyhow!("Invalid block height"))?;

        let start_height = self.start_height.unwrap_or(1);
        let end_height = self.end_height.unwrap_or(tip_height);

        eprintln!("Scanning blocks {} to {} with tag pre-filtering...", start_height, end_height);
        eprintln!("Tag window: indices {} to {}", self.start_index, self.start_index + self.tag_window - 1);
        eprintln!();

        let stats = scan_with_tags(
            &mut client,
            BlockHeight::from_u32(start_height),
            BlockHeight::from_u32(end_height),
            &expected_tags,
            self.verbose,
        )
        .await?;

        eprintln!();
        eprintln!("Scan Results");
        eprintln!("============");
        eprintln!("Blocks scanned:       {}", stats.blocks_scanned);
        eprintln!("Total Orchard actions: {}", stats.total_actions);
        eprintln!("Actions with tags:     {}", stats.actions_with_tags);
        eprintln!("Tag matches:           {}", stats.tag_matches);
        eprintln!("Actions to decrypt:    {} ({}%)",
            stats.actions_to_decrypt,
            if stats.total_actions > 0 {
                (stats.actions_to_decrypt * 100) / stats.total_actions
            } else {
                0
            }
        );
        eprintln!();

        if stats.tag_matches > 0 {
            eprintln!("✓ Found {} potential matches using tag pre-filtering", stats.tag_matches);
            eprintln!("  Use `wallet sync` to perform full decryption and discover notes.");
        } else if stats.actions_with_tags == stats.total_actions && stats.total_actions > 0 {
            eprintln!("No tag matches found in the scanned range.");
            eprintln!("This could mean:");
            eprintln!("  - No transactions were sent to this account in this range");
            eprintln!("  - The sender used different tag indices than expected");
        } else if stats.total_actions > 0 {
            eprintln!("Note: {} actions had no tags (pre-NU7 transactions)", 
                stats.total_actions - stats.actions_with_tags);
            eprintln!("These require trial decryption via `wallet sync`.");
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
struct ScanStats {
    blocks_scanned: u64,
    total_actions: u64,
    actions_with_tags: u64,
    tag_matches: u64,
    actions_to_decrypt: u64,
}

async fn scan_with_tags(
    client: &mut CompactTxStreamerClient<Channel>,
    start: BlockHeight,
    end: BlockHeight,
    expected_tags: &HashSet<[u8; 16]>,
    verbose: bool,
) -> Result<ScanStats, anyhow::Error> {
    let mut stats = ScanStats::default();

    let mut start_block = service::BlockId::default();
    start_block.height = start.into();
    let mut end_block = service::BlockId::default();
    end_block.height = end.into();

    let range = service::BlockRange {
        start: Some(start_block),
        end: Some(end_block),
    };

    let block_stream = client.get_block_range(range).await?.into_inner();
    tokio::pin!(block_stream);

    while let Some(block) = block_stream.try_next().await? {
        stats.blocks_scanned += 1;
        let block_height = block.height;

        for tx in block.vtx.iter() {
            for (action_idx, action) in tx.actions.iter().enumerate() {
                stats.total_actions += 1;

                // Convert to CompactAction for tag matching
                if let Some(compact_action) = to_compact_action(action) {
                    let has_tag = compact_action.tag().is_some();
                    if has_tag {
                        stats.actions_with_tags += 1;
                    }

                    let should_decrypt = matches_tag(&compact_action, expected_tags);
                    if should_decrypt {
                        stats.actions_to_decrypt += 1;

                        // If it had a tag and matches, it's a tag match
                        // If no tag (pre-activation), we must decrypt anyway
                        if has_tag {
                            stats.tag_matches += 1;

                            if verbose {
                                eprintln!(
                                    "  Match: block {} tx {} action {} tag={}",
                                    block_height,
                                    hex::encode(&tx.hash),
                                    action_idx,
                                    hex::encode(compact_action.tag().unwrap())
                                );
                            }
                        }
                    }
                }
            }
        }

        // Progress indicator
        if stats.blocks_scanned % 1000 == 0 {
            eprint!("\rScanned {} blocks...", stats.blocks_scanned);
        }
    }

    if stats.blocks_scanned >= 1000 {
        eprintln!(); // Clear the progress line
    }

    Ok(stats)
}

/// Convert a protobuf CompactOrchardAction to an orchard::note_encryption::CompactAction
fn to_compact_action(
    proto_action: &zcash_client_backend::proto::compact_formats::CompactOrchardAction,
) -> Option<orchard::note_encryption::CompactAction> {
    use orchard::note_encryption::CompactAction;

    // Extract nullifier (32 bytes)
    let nullifier: [u8; 32] = proto_action.nullifier.as_slice().try_into().ok()?;
    let nullifier = orchard::note::Nullifier::from_bytes(&nullifier);
    let nullifier = if nullifier.is_some().into() {
        nullifier.unwrap()
    } else {
        return None;
    };

    // Extract cmx (32 bytes)
    let cmx: [u8; 32] = proto_action.cmx.as_slice().try_into().ok()?;
    let cmx = orchard::note::ExtractedNoteCommitment::from_bytes(&cmx);
    let cmx = if cmx.is_some().into() {
        cmx.unwrap()
    } else {
        return None;
    };

    // Extract ephemeral key (32 bytes)
    let ephemeral_key: [u8; 32] = proto_action.ephemeral_key.as_slice().try_into().ok()?;
    let ephemeral_key = zcash_note_encryption::EphemeralKeyBytes(ephemeral_key);

    // Extract enc_ciphertext (52 bytes for compact)
    let enc_ciphertext: [u8; 52] = proto_action.ciphertext.as_slice().try_into().ok()?;

    // Build CompactAction with or without tag
    if proto_action.tag.len() == 16 {
        let tag: [u8; 16] = proto_action.tag.as_slice().try_into().unwrap();
        Some(CompactAction::from_parts_with_tag(
            nullifier,
            cmx,
            ephemeral_key,
            enc_ciphertext,
            tag,
        ))
    } else {
        Some(CompactAction::from_parts(
            nullifier,
            cmx,
            ephemeral_key,
            enc_ciphertext,
        ))
    }
}
