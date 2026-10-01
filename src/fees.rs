//! Mass-based fees. A transaction pays the relay floor, and above it only what the mempool's ranking
//! asks for while the ready mempool overflows one block.

use anyhow::{Context, Result, bail};
use kaspa_consensus_core::config::params::Params as ConsensusParams;
use kaspa_consensus_core::mass::{BlockMassLimits, ContextualMasses, Mass, MassCalculator};
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, UtxoEntry};

use crate::assemble::{
    Amount, AssembledTx, DUST_SOMPI, FundingUtxo, INSUFFICIENT_FUNDING, MASS_CEILING, MAX_FEE_SOMPI, assemble, assemble_payment,
    assemble_sweep, assemble_unfunded_evict, assemble_with_cards, assemble_with_payload,
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

/// The mass the relay floor is priced on: the larger of compute and normalized transient mass.
pub fn fee_mass(network: &str, tx: &Transaction) -> Result<u64> {
    let params = ConsensusParams::from(network_id(network)?);
    let masses = MassCalculator::new_with_consensus_params(&params).calc_non_contextual_masses(tx);
    let cofactors = params.mempool_block_mass_limits().raw_post().cofactors();
    Ok(masses.compute_mass.max(masses.normalized_transient(&cofactors)))
}

/// The minimum relayable fee for `tx`, as the rusty-kaspa mempool computes it.
pub fn minimum_standard_fee(network: &str, tx: &Transaction) -> Result<u64> {
    Ok(fee_mass_to_fee(fee_mass(network, tx)?, MINIMUM_RELAY_FEE_SOMPI_PER_KG))
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

/// What a node reports about its fee market.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Market {
    /// The normal-priority feerate, in sompi per gram.
    pub feerate: f64,
    /// The total frontier mass of the transactions the node holds ready for a block, where the
    /// node reports it.
    pub ready_mass: Option<u64>,
}

/// A bare feerate is a market whose ready mass is unknown.
impl From<f64> for Market {
    fn from(feerate: f64) -> Self {
        Self { feerate, ready_mass: None }
    }
}

/// The mass the mempool ranks a transaction by and quotes its feerate estimates in: the largest of
/// its compute, transient and storage masses, each normalized to the compute scale.
pub fn frontier_mass(network: &str, tx: &Transaction, entries: &[UtxoEntry]) -> Result<u64> {
    let params = ConsensusParams::from(network_id(network)?);
    let calc = MassCalculator::new_with_consensus_params(&params);
    let storage = calc
        .calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec()))
        .context("this transaction has no computable storage mass, so no node can price it")?
        .storage_mass;
    let cofactors = params.mempool_block_mass_limits().after().cofactors();
    Ok(Mass::new(calc.calc_non_contextual_masses(tx), ContextualMasses::new(storage)).normalized_max(&cofactors))
}

/// The fee for `tx` in `market`. While the ready mass fits in one block the node takes every
/// transaction, so the fee is the relay floor. Past one block the node ranks by feerate over
/// [`frontier_mass`], and the fee is the feerate on that mass where that is more than the floor.
/// Where the ready mass is unknown, the fee is the feerate on [`fee_mass`] where that is more.
pub fn required_fee(network: &str, tx: &Transaction, entries: &[UtxoEntry], market: impl Into<Market>) -> Result<u64> {
    let Market { feerate, ready_mass } = market.into();
    let floor = minimum_standard_fee(network, tx)?;
    // A negative or NaN rate counts as zero, a huge one saturates, and `assemble` caps the fee.
    if feerate.is_nan() || feerate <= 0.0 {
        return Ok(floor);
    }
    let block = ConsensusParams::from(network_id(network)?).mempool_block_mass_limits().after().reference();
    let mass = match ready_mass {
        Some(ready) if ready <= block => return Ok(floor),
        Some(_) => frontier_mass(network, tx, entries)?,
        None => fee_mass(network, tx)?,
    };
    Ok(floor.max((feerate * mass as f64).ceil().min(u64::MAX as f64) as u64))
}

/// Iterates because the fee changes the change output, which feeds back into mass.
pub fn assemble_with_auto_fee(
    intent: &TxIntent,
    funding: &[FundingUtxo],
    change_spk: &str,
    network: &str,
    market: impl Into<Market>,
) -> Result<AssembledTx> {
    converge(network, market.into(), |fee| assemble(intent, funding, change_spk, fee))
}

pub fn assemble_with_payload_and_auto_fee(
    intent: &TxIntent,
    funding: &[FundingUtxo],
    change_spk: &str,
    payload: &[u8],
    network: &str,
    market: impl Into<Market>,
) -> Result<AssembledTx> {
    converge(network, market.into(), |fee| assemble_with_payload(intent, funding, change_spk, fee, payload))
}

pub fn assemble_with_cards_and_auto_fee(
    intent: &TxIntent,
    cards: &CardPlan,
    funding: &[FundingUtxo],
    change_spk: &str,
    network: &str,
    market: impl Into<Market>,
) -> Result<AssembledTx> {
    converge(network, market.into(), |fee| assemble_with_cards(intent, cards, funding, change_spk, fee))
}

/// The cards pay the fee.
pub fn assemble_sweep_with_auto_fee(
    sweep: &[CardInput],
    dest_spk: &str,
    network: &str,
    market: impl Into<Market>,
) -> Result<AssembledTx> {
    converge(network, market.into(), |fee| assemble_sweep(sweep, dest_spk, fee))
}

/// For [`Amount::All`] the output shrinks as the fee grows.
pub fn assemble_payment_with_auto_fee(
    funding: &[FundingUtxo],
    dest_spk: &str,
    amount: Amount,
    change_spk: &str,
    network: &str,
    market: impl Into<Market>,
) -> Result<AssembledTx> {
    converge(network, market.into(), |fee| assemble_payment(funding, dest_spk, amount, change_spk, fee))
}

/// The bounty pays the fee.
pub fn assemble_unfunded_evict_with_auto_fee(
    intent: &TxIntent,
    payout_spk: &str,
    network: &str,
    market: impl Into<Market>,
) -> Result<AssembledTx> {
    converge(network, market.into(), |fee| assemble_unfunded_evict(intent, payout_spk, fee))
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

/// The most a transaction pays above its own requirement. That excess is change folded into the
/// fee, with the price of the change output the fold removed.
pub const OVERPAY_CEILING_SOMPI: u64 = 2 * DUST_SOMPI;

/// The mass a registration's split and activation rank by in a full block, with room for the
/// change that funds the activation to carry its own storage mass.
pub const REGISTRATION_FULL_BLOCK_GRAMS: u64 = 150_000;

/// Headroom a registration's funding takes beyond its fixed buffer while blocks are full, so the
/// split's change still pays for the activation. It returns as change where the fees need less.
pub fn full_block_headroom(network: &str, market: impl Into<Market>) -> Result<u64> {
    let Market { feerate, ready_mass } = market.into();
    let block = ConsensusParams::from(network_id(network)?).mempool_block_mass_limits().after().reference();
    let full = ready_mass.is_some_and(|ready| ready > block) && feerate.is_finite() && feerate > 0.0;
    Ok(if full { (feerate * REGISTRATION_FULL_BLOCK_GRAMS as f64).ceil().min(MAX_FEE_SOMPI as f64) as u64 } else { 0 })
}

/// Why a transaction refused for its change fails: the change is too small for its own storage
/// mass at the feerate. Another coin is the remedy.
pub const CHANGE_TOO_SMALL: &str = "at this feerate the change cannot pay for its own storage mass";

/// The most passes [`converge`] takes. From below, a pass never needs less than the one before.
const CONVERGE_PASSES: usize = 64;

/// What leaves the inputs: the fee a node sees, folded dust included.
fn paid(assembled: &AssembledTx) -> u64 {
    let total_in = assembled.entries.iter().map(|e| e.amount).sum::<u64>();
    total_in.saturating_sub(assembled.tx.outputs.iter().map(|o| o.value).sum())
}

/// The fee feeds back into the change output, and small change adds storage mass, so the fee
/// climbs until a pass needs exactly the fee it was built with. A pass counts only where a node
/// carries it and it pays at most [`OVERPAY_CEILING_SOMPI`] above what it needs, and the loop keeps
/// the cheapest one. Where a pass cannot be built, or the fixed point overruns the storage limit,
/// the loop tries once to fold all of the change into the fee.
fn converge(network: &str, market: Market, build: impl Fn(u64) -> Result<AssembledTx>) -> Result<AssembledTx> {
    let mut fee = MINIMUM_RELAY_FEE_SOMPI_PER_KG;
    let mut cheapest: Option<(u64, AssembledTx)> = None;
    let mut tried = std::collections::HashSet::new();
    let (mut remainder, mut folded, mut least_required) = (None, false, u64::MAX);
    let (mut failure, mut failed_at, mut last) = (None, 0, None);
    for _ in 0..CONVERGE_PASSES {
        if !tried.insert(fee) {
            break;
        }
        let assembled = match build(fee) {
            Ok(assembled) => assembled,
            Err(e) => {
                (failure, failed_at) = (Some(e), fee);
                match remainder.filter(|all: &u64| !folded && *all < fee) {
                    Some(all) => {
                        (folded, fee) = (true, all);
                        continue;
                    }
                    None => break,
                }
            }
        };
        let paying = paid(&assembled);
        let all = paying + assembled.change.map_or(0, |(_, value)| value);
        remainder = Some(all);
        let required = required_fee(network, &as_broadcast(&assembled), &assembled.entries, market)?;
        least_required = least_required.min(required);
        let carried = mass_overrun(network, &assembled)?.is_none();
        let covers = carried && paying >= required && paying - required <= OVERPAY_CEILING_SOMPI;
        if covers && cheapest.as_ref().is_none_or(|(least, _)| paying < *least) {
            cheapest = Some((paying, assembled));
        } else {
            last = Some(assembled);
        }
        if fee == required {
            // A fixed point whose change is too small for its own storage mass.
            if !carried && !folded && all > fee {
                (folded, fee) = (true, all);
                continue;
            }
            break;
        }
        fee = required;
    }
    match cheapest {
        Some((_, assembled)) => Ok(assembled),
        // The climb ran past every requirement a built pass had, so the change is what failed.
        None if remainder.is_some() && failed_at > least_required.saturating_add(OVERPAY_CEILING_SOMPI) => {
            Err(anyhow::anyhow!("{INSUFFICIENT_FUNDING}: {CHANGE_TOO_SMALL}"))
        }
        None => match (failure, last) {
            (Some(e), _) => Err(e),
            (None, Some(assembled)) => {
                refuse_if_overweight(network, &assembled)?;
                Err(anyhow::anyhow!("{INSUFFICIENT_FUNDING}: {CHANGE_TOO_SMALL}"))
            }
            (None, None) => bail!("fee calculation did not converge"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assemble::{FEE_CEILING, FundingUtxo, MAX_FEE_SOMPI};
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

    /// Blocks with room take every transaction, so the fee is the relay floor and not a sompi more.
    #[test]
    fn with_room_in_the_block_the_fee_is_exactly_the_relay_floor() {
        let (intent, funding) = funded_split();
        let block = mass_caps("testnet-10").unwrap().compute;
        let split = assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", full(700.0, block)).unwrap();
        let measured = as_broadcast(&split);
        assert_eq!(paid(&split), minimum_standard_fee("testnet-10", &measured).unwrap());
    }

    fn full(feerate: f64, ready_mass: u64) -> Market {
        Market { feerate, ready_mass: Some(ready_mass) }
    }

    /// Under congestion the fee ranks at the quoted rate on the mass the node ranks by, and one
    /// sompi less ranks below it.
    #[test]
    fn a_full_block_pays_the_rate_on_the_frontier_mass_and_no_more() {
        let (intent, funding) = funded_split();
        let block = mass_caps("testnet-10").unwrap().compute;
        let rate = 500.0;
        let split = assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", full(rate, block + 1)).unwrap();
        let measured = as_broadcast(&split);
        let mass = frontier_mass("testnet-10", &measured, &split.entries).unwrap();
        let fee = paid(&split);
        assert_eq!(fee, (rate * mass as f64).ceil() as u64);
        assert!(fee as f64 / mass as f64 >= rate && (fee - 1) as f64 / (mass as f64) < rate);
        assert!(mass > fee_mass("testnet-10", &measured).unwrap(), "storage dominates a split");
    }

    /// A node that does not report its ready mass prices on fee mass, with no margin.
    #[test]
    fn an_unknown_ready_mass_prices_the_rate_on_fee_mass() {
        let (intent, funding) = funded_split();
        let rate = 500.0;
        let split = assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", rate).unwrap();
        let measured = as_broadcast(&split);
        let mass = fee_mass("testnet-10", &measured).unwrap();
        assert_eq!(paid(&split), (rate * mass as f64).ceil() as u64);
        let idle = assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", 100.0).unwrap();
        assert_eq!(paid(&idle), minimum_standard_fee("testnet-10", &as_broadcast(&idle)).unwrap());
    }

    fn coin(value: u64) -> Vec<FundingUtxo> {
        vec![FundingUtxo { outpoint: fixture::outpoint(0xf1), value, spk: SPK.into() }]
    }

    fn requirement(a: &AssembledTx, market: Market) -> u64 {
        required_fee("testnet-10", &as_broadcast(a), &a.entries, market).unwrap()
    }

    fn congested(rate: f64) -> Market {
        full(rate, mass_caps("testnet-10").unwrap().compute + 1)
    }

    /// A higher fee leaves less change, and less change adds storage mass, so the requirement climbs
    /// with the fee. The loop follows it to the least fee that pays for itself.
    #[test]
    fn a_climbing_requirement_settles_on_its_fixed_point() {
        let market = congested(500.0);
        let a =
            assemble_payment_with_auto_fee(&coin(150_000_000), SPK, Amount::Exact(100_000_000), SPK, "testnet-10", market).unwrap();
        assert_eq!(paid(&a), requirement(&a, market));
    }

    /// Change too small to carry its own storage mass folds into the fee, where that costs at most
    /// the overpay ceiling.
    #[test]
    fn change_that_cannot_pay_for_itself_folds_when_it_is_dust() {
        let market = congested(100.0);
        let a =
            assemble_payment_with_auto_fee(&coin(100_300_000), SPK, Amount::Exact(100_000_000), SPK, "testnet-10", market).unwrap();
        assert!(a.change.is_none());
        let over = paid(&a) - requirement(&a, market);
        assert!(over <= OVERPAY_CEILING_SOMPI, "{over}");
    }

    /// No coin size makes the loop pay more than the overpay ceiling over what its own transaction
    /// needs, in any market. Where no such fee exists, it refuses.
    #[test]
    fn no_coin_size_pays_more_than_the_ceiling_over_its_requirement() {
        for market in [congested(100.0), congested(500.0), congested(1234.5), 500.0.into(), full(900.0, 0)] {
            let (mut built, mut refused) = (0, 0);
            for step in 0..400u64 {
                let value = 100_000_000 + 100_000 + step * 997_331;
                match assemble_payment_with_auto_fee(&coin(value), SPK, Amount::Exact(100_000_000), SPK, "testnet-10", market) {
                    Ok(a) => {
                        built += 1;
                        let (paying, needed) = (paid(&a), requirement(&a, market));
                        let over = paying - needed;
                        assert!(paying >= needed && over <= OVERPAY_CEILING_SOMPI, "{value} at {market:?}: {paying} for {needed}");
                    }
                    Err(e) => {
                        refused += 1;
                        let why = e.to_string();
                        assert!([INSUFFICIENT_FUNDING, FEE_CEILING, MASS_CEILING].iter().any(|k| why.contains(k)), "{why}");
                    }
                }
            }
            assert!(built > 0, "{market:?}: {built} built, {refused} refused");
        }
    }

    #[test]
    fn a_fractional_rate_rounds_the_fee_up() {
        let (intent, funding) = funded_split();
        let market = congested(250.123_456_7);
        let split = assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", market).unwrap();
        let mass = frontier_mass("testnet-10", &as_broadcast(&split), &split.entries).unwrap() as f64;
        assert_eq!(paid(&split), (market.feerate * mass).ceil() as u64);
        assert!(((paid(&split) - 1) as f64) < market.feerate * mass);
    }

    /// A fixed point whose change is too small for its own storage mass folds that change, where the
    /// fold costs at most the overpay ceiling.
    #[test]
    fn an_overweight_fixed_point_folds_its_change() {
        let t = fixture::templates();
        let (_, deed, _) = fixture::pending(&t, "abcde");
        let intent = crate::intents::activate_intent(&t, &deed, "abcde", OwnerType::Pubkey, &fixture::owner(5)).unwrap();
        let a = assemble_with_auto_fee(&intent, &coin(1_839_526), SPK, "testnet-10", 0.0).unwrap();
        assert!(a.change.is_none());
        let over = paid(&a) - requirement(&a, 0.0.into());
        assert!(over <= OVERPAY_CEILING_SOMPI, "{over}");
    }

    /// A requirement that runs away with shrinking change is a funding problem, not a feerate one.
    #[test]
    fn a_runaway_names_the_change_and_not_the_feerate() {
        let (intent, _) = funded_split();
        for rate in [200.0, 500.0] {
            let why = assemble_with_auto_fee(&intent, &coin(intent.required_funding + 40_000_000), SPK, "testnet-10", congested(rate))
                .err()
                .unwrap()
                .to_string();
            assert!(why.contains(INSUFFICIENT_FUNDING) && why.contains("storage mass"), "{rate}: {why}");
        }
    }

    /// A market rate below what the floor already pays on the frontier mass changes nothing.
    #[test]
    fn a_low_market_rate_leaves_the_floor() {
        let (intent, funding) = funded_split();
        let floor = paid(&assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", 0.0).unwrap());
        assert_eq!(paid(&assemble_with_auto_fee(&intent, &funding, SPK, "testnet-10", 1.0).unwrap()), floor);
    }
}
