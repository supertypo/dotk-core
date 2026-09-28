//! Mass-based fees that mirror the mempool's standardness rule, priced at the higher of the relay
//! minimum and the node's feerate estimate.

use anyhow::{Context, Result, bail};
use kaspa_consensus_core::config::params::Params as ConsensusParams;
use kaspa_consensus_core::mass::{BlockMassLimits, MassCalculator};
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction};

use crate::assemble::{
    Amount, AssembledTx, FundingUtxo, MASS_CEILING, assemble, assemble_payment, assemble_sweep, assemble_unfunded_evict,
    assemble_with_cards,
};
use crate::cards::{CardInput, CardPlan};
use crate::intents::TxIntent;
use crate::sign::FUNDING_SIG_SCRIPT_LEN as SIG_SCRIPT_PLACEHOLDER_LEN;

/// Mempool default `minimum_relay_transaction_fee`, in sompi per kilogram.
pub const MINIMUM_RELAY_FEE_SOMPI_PER_KG: u64 = 100_000;

/// The networks with consensus params in this build.
pub fn network_id(network: &str) -> Result<NetworkId> {
    Ok(match network {
        "mainnet" => NetworkId::new(NetworkType::Mainnet),
        "testnet-10" => NetworkId::with_suffix(NetworkType::Testnet, 10),
        other => bail!("unknown network {other}"),
    })
}

pub fn net_bps(network: &str) -> Result<u64> {
    Ok(ConsensusParams::from(network_id(network)?).bps())
}

/// The minimum relayable fee for `tx`, as the rusty-kaspa mempool computes it.
pub fn minimum_standard_fee(network: &str, tx: &Transaction) -> Result<u64> {
    let params = ConsensusParams::from(network_id(network)?);
    let calc = MassCalculator::new_with_consensus_params(&params);
    let masses = calc.calc_non_contextual_masses(tx);
    let cofactors = params.mempool_block_mass_limits().raw_post().cofactors();
    let fee_mass = masses.compute_mass.max(masses.normalized_transient(&cofactors));
    Ok(fee_mass_to_fee(fee_mass, MINIMUM_RELAY_FEE_SOMPI_PER_KG))
}

/// The largest mass a node carries per transaction, in each dimension.
pub fn mass_caps(network: &str) -> Result<BlockMassLimits> {
    Ok(caps_of(&ConsensusParams::from(network_id(network)?)))
}

fn caps_of(params: &ConsensusParams) -> BlockMassLimits {
    params.mempool_block_mass_limits().after()
}

/// The longest signature script a node admits on one input.
pub fn max_signature_script_len(network: &str) -> Result<usize> {
    Ok(ConsensusParams::from(network_id(network)?).max_signature_script_len().after())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MassOverrun {
    pub dimension: &'static str,
    pub mass: u64,
    pub cap: u64,
}

impl std::error::Error for MassOverrun {}

impl std::fmt::Display for MassOverrun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "its {} mass is {}, over the {} a node carries", self.dimension, self.mass, self.cap)
    }
}

/// Which mass dimension the assembled transaction overruns, if any, measured with placeholder
/// signature scripts. A small output grows KIP-9 storage mass as `C / value`.
pub fn mass_overrun(network: &str, assembled: &AssembledTx) -> Result<Option<MassOverrun>> {
    let params = ConsensusParams::from(network_id(network)?);
    let calc = MassCalculator::new_with_consensus_params(&params);
    let tx = &as_broadcast(assembled);
    let non_contextual = calc.calc_non_contextual_masses(tx);
    // KIP-9 answers `None` on a zero-valued output or an overflow, which no node prices.
    let storage = calc
        .calc_contextual_masses(&PopulatedTransaction::new(tx, assembled.entries.clone()))
        .context("this transaction has no computable storage mass, so no node can price it")?
        .storage_mass;
    let caps = caps_of(&params);
    Ok([
        ("compute", non_contextual.compute_mass, caps.compute),
        ("transient", non_contextual.transient_mass, caps.transient),
        ("storage", storage, caps.storage),
    ]
    .into_iter()
    .find(|(_, mass, cap)| mass > cap)
    .map(|(dimension, mass, cap)| MassOverrun { dimension, mass, cap }))
}

fn fee_mass_to_fee(mass: u64, relay_fee_sompi_per_kg: u64) -> u64 {
    let f = (mass * relay_fee_sompi_per_kg) / 1000;
    if f == 0 { relay_fee_sompi_per_kg } else { f }
}

/// The fee for `tx` at a live feerate in sompi/gram: max(relay minimum, feerate × fee_mass).
pub fn required_fee(network: &str, tx: &Transaction, feerate_sompi_per_gram: f64) -> Result<u64> {
    let params = ConsensusParams::from(network_id(network)?);
    let calc = MassCalculator::new_with_consensus_params(&params);
    let masses = calc.calc_non_contextual_masses(tx);
    let cofactors = params.mempool_block_mass_limits().raw_post().cofactors();
    let fee_mass = masses.compute_mass.max(masses.normalized_transient(&cofactors));
    let relay_min = fee_mass_to_fee(fee_mass, MINIMUM_RELAY_FEE_SOMPI_PER_KG);
    // A negative or NaN estimate counts as zero, a huge one saturates, and `assemble` caps the fee.
    let market = (feerate_sompi_per_gram.max(0.0) * fee_mass as f64).ceil().min(u64::MAX as f64) as u64;
    // 5% margin absorbs sigscript-size estimation drift and small feerate movement.
    Ok(relay_min.max(market).saturating_mul(105).div_ceil(100))
}

/// Iterates because the fee changes the change output, which feeds back into mass.
pub fn assemble_with_auto_fee(
    intent: &TxIntent,
    funding: &[FundingUtxo],
    change_spk: &str,
    network: &str,
    feerate_sompi_per_gram: f64,
) -> Result<AssembledTx> {
    converge(network, feerate_sompi_per_gram, |fee| assemble(intent, funding, change_spk, fee))
}

pub fn assemble_with_cards_and_auto_fee(
    intent: &TxIntent,
    cards: &CardPlan,
    funding: &[FundingUtxo],
    change_spk: &str,
    network: &str,
    feerate_sompi_per_gram: f64,
) -> Result<AssembledTx> {
    converge(network, feerate_sompi_per_gram, |fee| assemble_with_cards(intent, cards, funding, change_spk, fee))
}

/// The cards pay the fee.
pub fn assemble_sweep_with_auto_fee(
    sweep: &[CardInput],
    dest_spk: &str,
    network: &str,
    feerate_sompi_per_gram: f64,
) -> Result<AssembledTx> {
    converge(network, feerate_sompi_per_gram, |fee| assemble_sweep(sweep, dest_spk, fee))
}

/// For [`Amount::All`] the output shrinks as the fee grows.
pub fn assemble_payment_with_auto_fee(
    funding: &[FundingUtxo],
    dest_spk: &str,
    amount: Amount,
    change_spk: &str,
    network: &str,
    feerate_sompi_per_gram: f64,
) -> Result<AssembledTx> {
    converge(network, feerate_sompi_per_gram, |fee| assemble_payment(funding, dest_spk, amount, change_spk, fee))
}

/// The bounty pays the fee.
pub fn assemble_unfunded_evict_with_auto_fee(
    intent: &TxIntent,
    payout_spk: &str,
    network: &str,
    feerate_sompi_per_gram: f64,
) -> Result<AssembledTx> {
    converge(network, feerate_sompi_per_gram, |fee| assemble_unfunded_evict(intent, payout_spk, fee))
}

/// Placeholders for every unsigned input, so the mass measured is the mass broadcast.
fn as_broadcast(assembled: &AssembledTx) -> Transaction {
    let mut measured = assembled.tx.clone();
    for &idx in &assembled.unsigned_inputs {
        measured.inputs[idx].signature_script = vec![0u8; SIG_SCRIPT_PLACEHOLDER_LEN];
    }
    measured
}

/// Refuses a transaction a node does not carry. A caller that names its own fee applies it itself.
pub fn refuse_if_overweight(network: &str, assembled: &AssembledTx) -> Result<()> {
    match mass_overrun(network, assembled)? {
        // The overrun stays the error's source, so a coin-selecting caller can downcast it.
        Some(overrun) => Err(anyhow::Error::new(overrun).context(MASS_CEILING)),
        None => Ok(()),
    }
}

/// Mass is checked once the loop settles, because an intermediate pass is never submitted.
fn converge(network: &str, feerate_sompi_per_gram: f64, build: impl Fn(u64) -> Result<AssembledTx>) -> Result<AssembledTx> {
    let mut fee = MINIMUM_RELAY_FEE_SOMPI_PER_KG;
    for _ in 0..5 {
        let assembled = build(fee)?;
        let measured = as_broadcast(&assembled);
        let required = required_fee(network, &measured, feerate_sompi_per_gram)?;
        if fee >= required {
            refuse_if_overweight(network, &assembled)?;
            return Ok(assembled);
        }
        fee = required;
    }
    bail!("fee calculation did not converge")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assemble::{FundingUtxo, MAX_FEE_SOMPI};
    use crate::fixture;
    use crate::state::OwnerType;

    const SPK: &str = "2022222222222222222222222222222222222222222222222222222222222222222222ac";

    fn funded_split() -> (TxIntent, Vec<FundingUtxo>) {
        let t = fixture::templates();
        let whole = fixture::gap(&t, crate::registry::KEY_MIN, crate::registry::KEY_MAX, 0xaa);
        let intent = crate::intents::split_intent(&t, &whole, "kaspa", OwnerType::Pubkey, &fixture::owner(5)).unwrap();
        (intent, vec![FundingUtxo { outpoint: fixture::outpoint(0xf0), value: 100_000 * 100_000_000, spk: SPK.into() }])
    }

    /// The feerate comes from a node, and a large coin pays whatever it implies.
    #[test]
    fn an_absurd_feerate_is_refused_rather_than_signed() {
        let (intent, funding) = funded_split();
        let sane = assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", 1.0).unwrap();
        let paid = sane.entries.iter().map(|e| e.amount).sum::<u64>() - sane.tx.outputs.iter().map(|o| o.value).sum::<u64>();
        assert!(paid < MAX_FEE_SOMPI);
        let refused = assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", 10_000_000.0).err().unwrap().to_string();
        assert!(refused.contains("ceiling"), "{refused}");
    }
}
