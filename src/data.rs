use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use zcash_client_sqlite::chain::init::init_blockmeta_db;
use zcash_client_sqlite::util::SystemClock;
use zcash_client_sqlite::wallet::init::init_wallet_db;
use zcash_client_sqlite::{FsBlockDb, WalletDb};

use tracing::error;

use zcash_client_sqlite::chain::BlockMeta;
use zcash_protocol::consensus::{self, BlockHeight, Parameters};
use zcash_protocol::local_consensus::LocalNetwork;

use crate::error;

pub(crate) const DEFAULT_WALLET_DIR: &str = "./zec_sqlite_wallet";
const BLOCKS_FOLDER: &str = "blocks";
const DATA_DB: &str = "data.sqlite";
const TOR_DIR: &str = "tor";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) enum Network {
    #[default]
    Test,
    Main,
    Regtest,
}

impl Network {
    pub(crate) fn parse(name: &str) -> Result<Network, String> {
        match name {
            "main" => Ok(Network::Main),
            "test" => Ok(Network::Test),
            "regtest" => Ok(Network::Regtest),
            other => Err(format!("Unsupported network: {other}")),
        }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            Network::Test => "test",
            Network::Main => "main",
            Network::Regtest => "regtest",
        }
    }

    /// Returns true if this is Regtest network
    pub(crate) fn is_regtest(&self) -> bool {
        matches!(self, Network::Regtest)
    }
}

/// Default Regtest network parameters matching Zebra's default configuration.
/// All upgrades activate at height 1 (except Genesis at 0).
pub(crate) fn regtest_network() -> LocalNetwork {
    LocalNetwork {
        overwinter: Some(BlockHeight::from_u32(1)),
        sapling: Some(BlockHeight::from_u32(1)),
        blossom: Some(BlockHeight::from_u32(1)),
        heartwood: Some(BlockHeight::from_u32(1)),
        canopy: Some(BlockHeight::from_u32(1)),
        nu5: Some(BlockHeight::from_u32(1)),
        nu6: Some(BlockHeight::from_u32(1)),
        nu6_1: None, // Not activated by default
        #[cfg(zcash_unstable = "nu7")]
        nu7: None,
        #[cfg(zcash_unstable = "zfuture")]
        z_future: None,
    }
}

impl From<Network> for consensus::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Test => consensus::Network::TestNetwork,
            Network::Main => consensus::Network::MainNetwork,
            // Regtest should use LocalNetwork, not consensus::Network
            // This conversion is kept for backwards compatibility but should not be used for Regtest
            Network::Regtest => consensus::Network::TestNetwork,
        }
    }
}

impl From<consensus::Network> for Network {
    fn from(value: consensus::Network) -> Self {
        match value {
            consensus::Network::TestNetwork => Network::Test,
            consensus::Network::MainNetwork => Network::Main,
        }
    }
}

pub(crate) fn get_db_paths<P: AsRef<Path>>(wallet_dir: Option<P>) -> (PathBuf, PathBuf) {
    let a = wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .to_owned();
    let mut b = a.clone();
    b.push(DATA_DB);
    (a, b)
}

pub(crate) fn get_block_path(fsblockdb_root: &Path, meta: &BlockMeta) -> PathBuf {
    meta.block_file_path(&fsblockdb_root.join(BLOCKS_FOLDER))
}

pub(crate) fn get_tor_dir<P: AsRef<Path>>(wallet_dir: Option<P>) -> PathBuf {
    wallet_dir
        .as_ref()
        .map(|p| p.as_ref())
        .unwrap_or(DEFAULT_WALLET_DIR.as_ref())
        .join(TOR_DIR)
}

pub(crate) async fn erase_wallet_state<P: AsRef<Path>>(wallet_dir: Option<P>) {
    let (fsblockdb_root, db_data) = get_db_paths(wallet_dir);
    let blocks_meta = fsblockdb_root.join("blockmeta.sqlite");
    let blocks_folder = fsblockdb_root.join(BLOCKS_FOLDER);

    if let Err(e) = tokio::fs::remove_dir_all(&blocks_folder).await {
        error!("Failed to remove {:?}: {}", blocks_folder, e);
    }

    if let Err(e) = tokio::fs::remove_file(&blocks_meta).await {
        error!("Failed to remove {:?}: {}", blocks_meta, e);
    }

    if let Err(e) = tokio::fs::remove_file(&db_data).await {
        error!("Failed to remove {:?}: {}", db_data, e);
    }
}

pub(crate) fn init_dbs<P: Parameters + 'static>(
    params: P,
    wallet_dir: Option<&String>,
) -> Result<WalletDb<rusqlite::Connection, P, SystemClock, OsRng>, anyhow::Error> {
    // Initialise the block and wallet DBs.
    let (db_cache, db_data) = get_db_paths(wallet_dir);
    let mut db_cache = FsBlockDb::for_path(db_cache).map_err(error::Error::from)?;
    let mut db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
    init_blockmeta_db(&mut db_cache)?;
    init_wallet_db(&mut db_data, None)?;

    Ok(db_data)
}
