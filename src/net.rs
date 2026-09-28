//! Node connectivity and the live feerate, behind the `node` feature.

use std::time::Duration;

use anyhow::{Result, anyhow};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_wrpc_client::prelude::{ConnectOptions, ConnectStrategy};
use kaspa_wrpc_client::{KaspaRpcClient, Resolver, WrpcEncoding};

pub struct Connection {
    pub client: KaspaRpcClient,
    /// The URL connected to, which differs from the candidate when that was [`RESOLVER`].
    pub url: String,
    /// At connect time. A syncing node answers with a partial view of the UTXO set.
    pub is_synced: bool,
}

/// Stands for the public-node resolver, which lags the network, so it belongs last.
pub const RESOLVER: &str = "resolver";

/// Connects to the first candidate that answers. A candidate must be on `network`, because a node on
/// another network answers plausibly while every derived address holds nothing.
pub async fn connect(
    network: &str,
    candidates: &[String],
    strategy: ConnectStrategy,
    connect_timeout: Option<Duration>,
) -> Result<Connection> {
    let network_id = crate::fees::network_id(network)?;
    anyhow::ensure!(!candidates.is_empty(), "no wRPC endpoint configured");
    let mut last_err = None;
    for entry in candidates {
        let url = if entry == RESOLVER {
            match Resolver::default().get_url(WrpcEncoding::Borsh, network_id).await {
                Ok(u) => u,
                Err(e) => {
                    last_err = Some(anyhow!("resolver: {e}"));
                    continue;
                }
            }
        } else {
            entry.clone()
        };
        let client = match KaspaRpcClient::new(WrpcEncoding::Borsh, Some(&url), None, Some(network_id), None) {
            Ok(c) => c,
            Err(e) => {
                last_err = Some(anyhow!("building a client for {url}: {e}"));
                continue;
            }
        };
        let opts = ConnectOptions { block_async_connect: true, connect_timeout, strategy, ..Default::default() };
        match client.connect(Some(opts)).await {
            Ok(_) => match client.get_server_info().await {
                Ok(info) if info.network_id == network_id => {
                    return Ok(Connection { client, url, is_synced: info.is_synced });
                }
                Ok(info) => last_err = Some(anyhow!("node at {url} is on {}, expected {network_id}", info.network_id)),
                Err(e) => last_err = Some(anyhow!("node at {url} did not answer getServerInfo: {e}")),
            },
            Err(e) => last_err = Some(anyhow!("connecting to {url}: {e}")),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no wRPC endpoint answered")))
}

/// Retries only an orphan rejection, the one that resolves by itself.
pub async fn submit(client: &KaspaRpcClient, tx: &kaspa_consensus_core::tx::Transaction) -> Result<String> {
    let mut last = String::new();
    for _ in 0..10 {
        match client.submit_transaction(tx.into(), false).await {
            Ok(id) => return Ok(id.to_string()),
            Err(e) => {
                last = e.to_string();
                if !last.contains("orphan") {
                    return Err(anyhow!("submit: {last}"));
                }
                workflow_core::task::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    Err(anyhow!("submit: {last}"))
}

/// The node's normal-priority feerate estimate in sompi/gram, or 1.0 when it cannot answer.
pub async fn feerate(client: &KaspaRpcClient) -> f64 {
    match client.get_fee_estimate().await {
        Ok(est) => est.normal_buckets.first().map(|b| b.feerate).unwrap_or(est.priority_bucket.feerate),
        Err(_) => 1.0,
    }
}
