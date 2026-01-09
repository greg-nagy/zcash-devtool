use std::{borrow::Cow, fmt, future::Future, path::Path};

use anyhow::anyhow;
use tonic::transport::{Channel, ClientTlsConfig};

use tracing::info;
use zcash_client_backend::{
    proto::service::compact_tx_streamer_client::CompactTxStreamerClient, tor,
};

use crate::data::{get_tor_dir, Network, NetworkParams};

const ECC_TESTNET: &[Server<'_>] = &[Server::fixed("lightwalletd.testnet.electriccoin.co", 9067)];

const YWALLET_MAINNET: &[Server<'_>] = &[
    Server::fixed("lwd1.zcash-infra.com", 9067),
    Server::fixed("lwd2.zcash-infra.com", 9067),
    Server::fixed("lwd3.zcash-infra.com", 9067),
    Server::fixed("lwd4.zcash-infra.com", 9067),
    Server::fixed("lwd5.zcash-infra.com", 9067),
    Server::fixed("lwd6.zcash-infra.com", 9067),
    Server::fixed("lwd7.zcash-infra.com", 9067),
    Server::fixed("lwd8.zcash-infra.com", 9067),
];

const ZEC_ROCKS_MAINNET: &[Server<'_>] = &[
    Server::fixed("zec.rocks", 443),
    Server::fixed("ap.zec.rocks", 443),
    Server::fixed("eu.zec.rocks", 443),
    Server::fixed("na.zec.rocks", 443),
    Server::fixed("sa.zec.rocks", 443),
];
const ZEC_ROCKS_TESTNET: &[Server<'_>] = &[Server::fixed("testnet.zec.rocks", 443)];

#[derive(Clone, Debug)]
pub(crate) enum ServerOperator {
    Ecc,
    YWallet,
    ZecRocks,
}

impl ServerOperator {
    fn servers(&self, network: Network) -> &[Server<'_>] {
        match (self, network) {
            (ServerOperator::Ecc, Network::Main) => &[],
            (ServerOperator::Ecc, Network::Test) => ECC_TESTNET,
            (ServerOperator::Ecc, Network::Regtest) => &[],
            (ServerOperator::YWallet, Network::Main) => YWALLET_MAINNET,
            (ServerOperator::YWallet, Network::Test) => &[],
            (ServerOperator::YWallet, Network::Regtest) => &[],
            (ServerOperator::ZecRocks, Network::Main) => ZEC_ROCKS_MAINNET,
            (ServerOperator::ZecRocks, Network::Test) => ZEC_ROCKS_TESTNET,
            (ServerOperator::ZecRocks, Network::Regtest) => &[],
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Servers {
    Hosted(ServerOperator),
    Custom(Vec<Server<'static>>),
}

impl Servers {
    pub(crate) fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "ecc" => Ok(Self::Hosted(ServerOperator::Ecc)),
            "ywallet" => Ok(Self::Hosted(ServerOperator::YWallet)),
            "zecrocks" => Ok(Self::Hosted(ServerOperator::ZecRocks)),
            _ => s
                .split(',')
                .map(|sub| {
                    sub.rsplit_once(':').and_then(|(host, port_str)| {
                        port_str
                            .parse()
                            .ok()
                            .map(|port| Server::custom_with_parts(host.into(), port))
                    })
                })
                .collect::<Option<_>>()
                .map(Self::Custom)
                .ok_or(anyhow!("'{}' must be one of ['ecc', 'ywallet', 'zecrocks'], or a comma-separated list of host:port", s)),
        }
    }

    pub(crate) fn pick(&self, params: &NetworkParams) -> anyhow::Result<&Server<'_>> {
        let network = params.network();
        // For now just use the first server in the list.
        match self {
            Servers::Hosted(server_operator) => server_operator
                .servers(network)
                .first()
                .ok_or(anyhow!("{:?} doesn't serve {:?}", server_operator, network)),
            Servers::Custom(servers) => Ok(servers.first().expect("not empty")),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Server<'a> {
    host: Cow<'a, str>,
    port: u16,
}

impl fmt::Display for Server<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

impl Server<'static> {
    const fn fixed(host: &'static str, port: u16) -> Self {
        Self {
            host: Cow::Borrowed(host),
            port,
        }
    }
}

impl Server<'static> {
    /// Create a custom server from a "host:port" string
    pub(crate) fn custom(addr: &str) -> Self {
        let (host, port) = addr
            .rsplit_once(':')
            .and_then(|(h, p)| p.parse().ok().map(|port| (h, port)))
            .unwrap_or((addr, 8137)); // Default to 8137 (Zaino default port)
        Self {
            host: Cow::Owned(host.to_string()),
            port,
        }
    }
}

impl Server<'_> {
    fn custom_with_parts(host: String, port: u16) -> Self {
        Self {
            host: Cow::Owned(host),
            port,
        }
    }

    fn use_tls(&self) -> bool {
        // Assume that localhost will never have a cert, and require remotes to have one.
        !matches!(self.host.as_ref(), "localhost" | "127.0.0.1" | "::1")
    }

    fn endpoint(&self) -> String {
        format!(
            "{}://{}:{}",
            if self.use_tls() { "https" } else { "http" },
            self.host,
            self.port
        )
    }

    pub(crate) async fn connect_direct(&self) -> anyhow::Result<CompactTxStreamerClient<Channel>> {
        info!("Connecting to {}", self);

        let channel = Channel::from_shared(self.endpoint())?;

        let channel = if self.use_tls() {
            let tls = ClientTlsConfig::new()
                .domain_name(self.host.to_string())
                .with_webpki_roots();
            channel.tls_config(tls)?
        } else {
            channel
        };

        Ok(CompactTxStreamerClient::new(channel.connect().await?))
    }

    async fn connect_over_tor(
        &self,
        tor: &tor::Client,
    ) -> Result<CompactTxStreamerClient<Channel>, anyhow::Error> {
        if !self.use_tls() {
            return Err(anyhow!(
                "Cannot connect to local lightwalletd server over Tor"
            ));
        }

        info!("Connecting to {} over Tor", self);
        let endpoint = self.endpoint().try_into()?;
        Ok(tor.connect_to_lightwalletd(endpoint).await?)
    }

    /// Connects to the server over Tor, unless it is running on localhost without HTTPS.
    pub(crate) async fn connect<F>(
        &self,
        tor: impl FnOnce() -> F,
    ) -> Result<CompactTxStreamerClient<Channel>, anyhow::Error>
    where
        F: Future<Output = anyhow::Result<tor::Client>>,
    {
        if self.use_tls() {
            self.connect_over_tor(&tor().await?).await
        } else {
            self.connect_direct().await
        }
    }
}

pub(crate) async fn tor_client<P: AsRef<Path>>(
    wallet_dir: Option<P>,
) -> anyhow::Result<tor::Client> {
    let tor_dir = get_tor_dir(wallet_dir);

    // Ensure Tor directory exists.
    tokio::fs::create_dir_all(&tor_dir).await?;

    Ok(tor::Client::create(&tor_dir, |_| {}).await?)
}
