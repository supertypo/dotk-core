//! Turns a `TxIntent` into a consensus transaction. Card inputs, funding, a minted card and change all
//! follow the protocol inputs and outputs, where no covenant looks.

use anyhow::{Result, ensure};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry};
use serde::{Deserialize, Serialize};

use crate::cards::{CARD_VALUE, CardInput, CardPlan, encode_payload};
use crate::intents::{Outpoint, TxIntent, budgets};

/// Change below this folds into the fee instead of becoming an output.
pub const DUST_SOMPI: u64 = 100_000;

/// The most network fee any transaction built here can pay: 5 KAS. A constant, so no configuration
/// can loosen it, because a node's feerate estimate is unvalidated.
pub const MAX_FEE_SOMPI: u64 = 500_000_000;

/// The prefix of a shortfall error, the one failure a caller fixes by funding.
pub const INSUFFICIENT_FUNDING: &str = "insufficient funding";

/// The prefix of a fee-ceiling refusal.
pub const FEE_CEILING: &str = "fee-ceiling";

/// The prefix of a refusal over a per-transaction mass limit. A small change output is the usual cause.
pub const MASS_CEILING: &str = "mass-ceiling";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingUtxo {
    pub outpoint: Outpoint,
    pub value: u64,
    /// The owner's P2PK script (hex, no version prefix).
    pub spk: String,
}

pub struct AssembledTx {
    pub tx: Transaction,
    pub entries: Vec<UtxoEntry>,
    /// Funding inputs that still need signatures.
    pub unsigned_inputs: Vec<usize>,
    pub covenant_inputs: Vec<usize>,
    /// Swept card inputs, each with a placeholder for the spender's signature.
    pub card_inputs: Vec<usize>,
    /// The change output's (index, value), if one was added.
    pub change: Option<(u32, u64)>,
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    let mut v = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut v)?;
    Ok(v)
}

fn push_protocol_input(
    inputs: &mut Vec<TransactionInput>,
    entries: &mut Vec<UtxoEntry>,
    input: &crate::intents::IntentInput,
) -> Result<()> {
    inputs.push(TransactionInput::new_with_compute_budget(
        input.outpoint.to_consensus()?,
        unhex(&input.sig_script)?,
        input.sequence,
        input.compute_budget,
    ));
    entries.push(UtxoEntry::new(
        input.value,
        ScriptPublicKey::from_vec(0, unhex(&input.spk)?),
        0,
        false,
        input.utxo_covenant_id.as_ref().map(|c| c.parse()).transpose()?,
    ));
    Ok(())
}

/// Assembles an intent with funding and change, and refuses change that no input signs. A covenant
/// pins only its own outputs, so only a `SIGHASH_ALL` signature on some input commits to change.
/// `fee` is in sompi, and change above dust goes to `change_spk` (hex).
pub fn assemble(intent: &TxIntent, funding: &[FundingUtxo], change_spk: &str, fee: u64) -> Result<AssembledTx> {
    assemble_with_cards(intent, &CardPlan::default(), funding, change_spk, fee)
}

/// [`assemble`] with cards. Only a `transfer` can mint, because a card must be output 1. A swept card
/// signs with `SIGHASH_ALL`, so it discharges the change duty.
pub fn assemble_with_cards(
    intent: &TxIntent,
    cards: &CardPlan,
    funding: &[FundingUtxo],
    change_spk: &str,
    fee: u64,
) -> Result<AssembledTx> {
    ensure!(cards.mint.is_none() || intent.kind == "transfer", "a card is minted in a transfer, never in a {}", intent.kind);
    ensure!(
        cards.mint.is_none() || intent.outputs.len() == 1,
        "a card is output 1, and this {} pins {} outputs of its own",
        intent.kind,
        intent.outputs.len()
    );
    assemble_checked(intent, cards, funding, change_spk, fee, &[])
}

/// [`assemble`] with a transaction payload. Every sighash covers the payload, so a signer commits to it.
pub fn assemble_with_payload(
    intent: &TxIntent,
    funding: &[FundingUtxo],
    change_spk: &str,
    fee: u64,
    payload: &[u8],
) -> Result<AssembledTx> {
    assemble_checked(intent, &CardPlan::default(), funding, change_spk, fee, payload)
}

fn assemble_checked(
    intent: &TxIntent,
    cards: &CardPlan,
    funding: &[FundingUtxo],
    change_spk: &str,
    fee: u64,
    payload: &[u8],
) -> Result<AssembledTx> {
    let assembled = build(intent, cards, funding, change_spk, fee, payload)?;
    // Not in `build`, because `assemble_unfunded_evict` is the one sanctioned waiver.
    ensure!(
        !funding.is_empty() || !cards.sweep.is_empty() || assembled.change.is_none(),
        "refusing to build a {} whose {} sompi of change no input signs: signature scripts are \
         outside the sighash, so nothing commits to that output and anyone who wins the txid \
         conflict re-points it. Fund it with one signed input, however small.",
        intent.kind,
        assembled.change.map(|(_, value)| value).unwrap_or_default()
    );
    Ok(assembled)
}

/// The one way past the change duty. The payout is a bearer value that any mempool watcher can
/// re-point. Only `evict` gets it, because `merge` pins the merged gap, so a rewrite changes only who
/// takes a bounty nobody was owed.
pub fn assemble_unfunded_evict(intent: &TxIntent, payout_spk: &str, fee: u64) -> Result<AssembledTx> {
    ensure!(intent.kind == "evict", "only an evict may be built unfunded, never a {}", intent.kind);
    build(intent, &CardPlan::default(), &[], payout_spk, fee, &[])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amount {
    Exact(u64),
    All,
}

/// What leaves the wallet: input value that no output carries. Folded dust change makes this
/// exceed the named fee, so this is what [`MAX_FEE_SOMPI`] must bound.
fn paid_out(entries: &[UtxoEntry], tx: &Transaction) -> Result<u64> {
    let total_in = total(entries.iter().map(|e| e.amount), "the input values")?;
    let total_out = total(tx.outputs.iter().map(|o| o.value), "the output values")?;
    Ok(total_in.saturating_sub(total_out))
}

/// Values come from a node and from callers, so a sum past `u64::MAX` is a named error.
fn total(values: impl IntoIterator<Item = u64>, what: &str) -> Result<u64> {
    values.into_iter().try_fold(0u64, |acc, v| acc.checked_add(v)).ok_or_else(|| anyhow::anyhow!("{what} overflow u64"))
}

fn refuse_over_ceiling(kind: &str, entries: &[UtxoEntry], tx: &Transaction) -> Result<()> {
    let paid = paid_out(entries, tx)?;
    ensure!(
        paid <= MAX_FEE_SOMPI,
        "{FEE_CEILING}: refusing to build a {kind} paying {paid} sompi, over the {MAX_FEE_SOMPI} sompi ceiling"
    );
    Ok(())
}

/// A payment from the wallet, with the remainder back to `change_spk` for [`Amount::Exact`]. Every
/// input is the wallet's own signed coin.
pub fn assemble_payment(funding: &[FundingUtxo], dest_spk: &str, amount: Amount, change_spk: &str, fee: u64) -> Result<AssembledTx> {
    ensure!(!funding.is_empty(), "a payment needs a coin to pay from");
    ensure!(fee <= MAX_FEE_SOMPI, "{FEE_CEILING}: refusing to build a payment paying {fee} sompi in network fee");
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    let mut unsigned_inputs = Vec::new();
    for f in funding {
        unsigned_inputs.push(inputs.len());
        inputs.push(TransactionInput::new_with_compute_budget(f.outpoint.to_consensus()?, vec![], 0, budgets::FUNDING));
        entries.push(UtxoEntry::new(f.value, ScriptPublicKey::from_vec(0, unhex(&f.spk)?), 0, false, None));
    }
    let total_in = total(entries.iter().map(|e| e.amount), "the input values")?;
    let paid = match amount {
        Amount::Exact(value) => value,
        // Saturating, so an underfunded drain reports the shortfall instead of a wrapped amount.
        Amount::All => total_in.saturating_sub(fee),
    };
    ensure!(
        paid >= crate::params::MIN_OUTPUT_VALUE,
        "a payment of {paid} sompi is below the {} sompi floor an output must clear",
        crate::params::MIN_OUTPUT_VALUE
    );
    let needed = total([paid, fee], "the payment and its fee")?;
    ensure!(total_in >= needed, "{INSUFFICIENT_FUNDING}: the coins hold {total_in}, the payment is {paid} + fee {fee}");
    let mut outputs =
        vec![TransactionOutput { value: paid, script_public_key: ScriptPublicKey::from_vec(0, unhex(dest_spk)?), covenant: None }];
    let change = total_in - paid - fee;
    let mut change_info = None;
    if change >= DUST_SOMPI {
        change_info = Some((outputs.len() as u32, change));
        outputs.push(TransactionOutput {
            value: change,
            script_public_key: ScriptPublicKey::from_vec(0, unhex(change_spk)?),
            covenant: None,
        });
    }
    let tx = Transaction::new(1, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    refuse_over_ceiling("payment", &entries, &tx)?;
    Ok(AssembledTx { tx, entries, unsigned_inputs, covenant_inputs: vec![], card_inputs: vec![], change: change_info })
}

/// A standalone sweep of cards, paying `dest_spk` what they hold less the fee.
pub fn assemble_sweep(sweep: &[CardInput], dest_spk: &str, fee: u64) -> Result<AssembledTx> {
    ensure!(!sweep.is_empty(), "a sweep needs a card to sweep");
    ensure!(fee <= MAX_FEE_SOMPI, "{FEE_CEILING}: refusing to build a sweep paying {fee} sompi in network fee");
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for card in sweep {
        push_card_input(&mut inputs, &mut entries, card)?;
    }
    let total_in = total(entries.iter().map(|e| e.amount), "the input values")?;
    // A lone output is cheap in storage mass at any value, so this floor is policy.
    ensure!(total_in >= fee + crate::params::MIN_OUTPUT_VALUE, "{INSUFFICIENT_FUNDING}: the cards hold {total_in}, the fee is {fee}");
    let outputs = vec![TransactionOutput {
        value: total_in - fee,
        script_public_key: ScriptPublicKey::from_vec(0, unhex(dest_spk)?),
        covenant: None,
    }];
    let card_inputs: Vec<usize> = (0..sweep.len()).collect();
    let tx = Transaction::new(1, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    refuse_over_ceiling("sweep", &entries, &tx)?;
    Ok(AssembledTx { tx, entries, unsigned_inputs: vec![], covenant_inputs: vec![], card_inputs, change: Some((0, total_in - fee)) })
}

fn push_card_input(inputs: &mut Vec<TransactionInput>, entries: &mut Vec<UtxoEntry>, card: &CardInput) -> Result<()> {
    inputs.push(TransactionInput::new_with_compute_budget(
        card.outpoint.to_consensus()?,
        card.state.sweep_sig_script(None),
        0,
        budgets::FUNDING,
    ));
    entries.push(UtxoEntry::new(card.value, ScriptPublicKey::from_vec(0, card.state.spk()), 0, false, None));
    Ok(())
}

fn build(
    intent: &TxIntent,
    cards: &CardPlan,
    funding: &[FundingUtxo],
    change_spk: &str,
    fee: u64,
    payload: &[u8],
) -> Result<AssembledTx> {
    ensure!(
        cards.mint.is_none() || payload.is_empty(),
        "a mint writes the payload, so a {} with a card carries no other",
        intent.kind
    );
    // In `build`, so the unfunded evict is covered too.
    ensure!(
        fee <= MAX_FEE_SOMPI,
        "{FEE_CEILING}: refusing to build a {} paying {fee} sompi in network fee, over the {MAX_FEE_SOMPI} \
         sompi ceiling. The fee is the node's feerate estimate times this transaction's mass, so a node \
         overstating the estimate is what sets a number like this. Nothing is wrong with the wallet or \
         the funds.",
        intent.kind
    );
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for input in &intent.inputs {
        push_protocol_input(&mut inputs, &mut entries, input)?;
    }

    let mut card_inputs = Vec::new();
    for card in &cards.sweep {
        card_inputs.push(inputs.len());
        push_card_input(&mut inputs, &mut entries, card)?;
    }

    let mut unsigned_inputs = Vec::new();
    for f in funding {
        unsigned_inputs.push(inputs.len());
        inputs.push(TransactionInput::new_with_compute_budget(f.outpoint.to_consensus()?, vec![], 0, budgets::FUNDING));
        entries.push(UtxoEntry::new(f.value, ScriptPublicKey::from_vec(0, unhex(&f.spk)?), 0, false, None));
    }

    let mut outputs: Vec<TransactionOutput> = Vec::new();
    for o in &intent.outputs {
        outputs.push(TransactionOutput {
            value: o.value,
            script_public_key: ScriptPublicKey::from_vec(0, unhex(&o.spk)?),
            covenant: o
                .covenant
                .as_ref()
                .map(|c| -> Result<CovenantBinding> {
                    Ok(CovenantBinding { covenant_id: c.covenant_id.parse()?, authorizing_input: u16::try_from(c.authorizing_input)? })
                })
                .transpose()?,
        });
    }
    if let Some(mint) = &cards.mint {
        // A deserialized mint skips `CardMint::for_deed`, and an off-curve spender locks the card.
        crate::address::check_payload(mint.state.spender_type, &mint.state.spender)
            .map_err(|e| anyhow::anyhow!("card spender: {e}"))?;
        outputs.push(TransactionOutput {
            value: CARD_VALUE,
            script_public_key: ScriptPublicKey::from_vec(0, mint.state.spk()),
            covenant: None,
        });
    }
    let payload = if cards.mint.is_some() { encode_payload(cards.mint.as_ref())? } else { payload.to_vec() };

    let total_in = total(entries.iter().map(|e| e.amount), "the input values")?;
    let total_out = total(outputs.iter().map(|o| o.value), "the output values")?;
    let needed = total([total_out, fee], "the outputs and the fee")?;
    ensure!(total_in >= needed, "{INSUFFICIENT_FUNDING}: in {total_in}, out {total_out} + fee {fee}");
    let change = total_in - total_out - fee;
    let mut change_info = None;
    if change >= DUST_SOMPI {
        change_info = Some((outputs.len() as u32, change));
        outputs.push(TransactionOutput {
            value: change,
            script_public_key: ScriptPublicKey::from_vec(0, unhex(change_spk)?),
            covenant: None,
        });
    }

    let covenant_inputs: Vec<usize> = (0..intent.inputs.len()).collect();
    let tx = Transaction::new(1, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, payload);
    refuse_over_ceiling(&intent.kind, &entries, &tx)?;
    Ok(AssembledTx { tx, entries, unsigned_inputs, covenant_inputs, card_inputs, change: change_info })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{self, owner};
    use crate::intents::{activate_intent, evict_intent, release_intent, split_intent, transfer_intent};
    use crate::state::OwnerType;

    const SPK: &str = "2022222222222222222222222222222222222222222222222222222222222222222222ac";

    fn coin(b: u8, value: u64) -> FundingUtxo {
        FundingUtxo { outpoint: fixture::outpoint(b), value, spk: SPK.into() }
    }

    /// Unsigned change is a bearer value, whatever the kind. Only an evict can waive that.
    #[test]
    fn an_unsigned_change_output_is_never_built() {
        let t = fixture::templates();
        let (pred, active, succ) = fixture::active(&t, "kaspa");
        let (_, pending, _) = fixture::pending(&t, "kaspa");
        let intents = [
            transfer_intent(&t, &active, OwnerType::ScriptHash, &[6u8; 32], 0).unwrap(),
            release_intent(&t, &pred, &active, &succ, 0).unwrap(),
            evict_intent(&t, &pred, &pending, &succ).unwrap(),
            activate_intent(&t, &pending, "kaspa", OwnerType::Pubkey, &owner(5)).unwrap(),
        ];
        let funded = [coin(0xf0, 10 * 100_000_000)];
        for intent in &intents {
            let why = assemble(intent, &[], SPK, 100_000).err().unwrap().to_string();
            let short = matches!(intent.kind.as_str(), "transfer" | "activate");
            assert!(why.contains(if short { INSUFFICIENT_FUNDING } else { "nothing commits to that output" }), "{why}");
            let asm = assemble(intent, &funded, SPK, 100_000).unwrap();
            assert_eq!(asm.unsigned_inputs, vec![intent.inputs.len()], "funding follows the protocol inputs");

            let unfunded = assemble_unfunded_evict(intent, SPK, 100_000);
            if intent.kind == "evict" {
                let asm = unfunded.unwrap();
                assert!(asm.unsigned_inputs.is_empty() && asm.change.is_some(), "the bounty rides out as change");
            } else {
                assert!(unfunded.err().unwrap().to_string().contains("only an evict"));
            }
        }
        let whole = fixture::gap(&t, crate::registry::KEY_MIN, crate::registry::KEY_MAX, 0xa3);
        let split = split_intent(&t, &whole, "kaspa", OwnerType::Pubkey, &owner(5)).unwrap();
        assert!(assemble(&split, &[], SPK, 100_000).err().unwrap().to_string().contains(INSUFFICIENT_FUNDING));
    }

    /// Dust change folds into the fee, so the ceiling binds the outlay rather than the named fee.
    #[test]
    fn folded_dust_counts_against_the_fee_ceiling() {
        let dest = format!("20{}ac", "33".repeat(32));
        let funding = [coin(0xf0, 10 * 100_000_000)];
        let leftover = DUST_SOMPI - 1;
        let paid = 10 * 100_000_000 - MAX_FEE_SOMPI - leftover;
        let why = assemble_payment(&funding, &dest, Amount::Exact(paid), SPK, MAX_FEE_SOMPI).err().unwrap().to_string();
        assert!(why.contains(FEE_CEILING), "the named fee is at the ceiling, and the folded dust takes it over: {why}");
        let at_ceiling = 10 * 100_000_000 - MAX_FEE_SOMPI;
        let asm = assemble_payment(&funding, &dest, Amount::Exact(at_ceiling), SPK, MAX_FEE_SOMPI - leftover).unwrap();
        assert!(asm.change.is_none(), "the leftover folds into the fee, and the outlay is exactly the ceiling");
    }

    #[test]
    fn values_that_overflow_are_refused_by_name() {
        let dest = format!("20{}ac", "33".repeat(32));
        let why = assemble_payment(&[coin(0xf0, 100_000_000)], &dest, Amount::Exact(u64::MAX), SPK, 100_000).err().unwrap();
        assert!(why.to_string().contains("overflow"), "{why}");
        let why = assemble_payment(&[coin(0xf0, u64::MAX), coin(0xf1, 1)], &dest, Amount::All, SPK, 100_000).err().unwrap();
        assert!(why.to_string().contains("overflow"), "{why}");
    }

    /// The ceiling binds a protocol build too, before funding is even considered.
    #[test]
    fn a_protocol_build_is_bound_by_the_fee_ceiling() {
        let t = fixture::templates();
        let (pred, active, succ) = fixture::active(&t, "kaspa");
        let release = release_intent(&t, &pred, &active, &succ, 0).unwrap();
        let why = assemble(&release, &[], SPK, MAX_FEE_SOMPI + 1).err().unwrap().to_string();
        assert!(why.contains(FEE_CEILING), "{why}");

        // A named fee under the ceiling whose folded dust change takes the outlay over it.
        let fee = MAX_FEE_SOMPI - DUST_SOMPI / 2;
        let funding = fee + (DUST_SOMPI - 1) - release.released;
        let why = assemble(&release, &[coin(0xf0, funding)], SPK, fee).err().unwrap().to_string();
        assert!(why.contains(FEE_CEILING), "{why}");
    }

    #[test]
    fn only_a_transfer_mints_a_card() {
        let t = fixture::templates();
        let (pred, active, succ) = fixture::active(&t, "kaspa");
        let next = crate::state::DeedState { owner: owner(6), ..active.state };
        assert!(crate::cards::CardMint::for_deed(&next, vec![], OwnerType::Pubkey, [0xff; 32]).is_err(), "an off-curve spender");
        let mint = crate::cards::CardMint::for_deed(&next, vec![0xa0], OwnerType::Pubkey, owner(6)).unwrap();
        let plan = CardPlan { mint: Some(mint), sweep: vec![] };
        let funded = [coin(0xf0, 10 * 100_000_000)];
        let transfer = transfer_intent(&t, &active, OwnerType::Pubkey, &owner(6), 0).unwrap();
        assemble_with_cards(&transfer, &plan, &funded, SPK, 100_000).unwrap();
        let release = release_intent(&t, &pred, &active, &succ, 0).unwrap();
        let why = assemble_with_cards(&release, &plan, &funded, SPK, 100_000).err().unwrap().to_string();
        assert!(why.contains("minted in a transfer"), "{why}");
    }

    #[test]
    fn a_payload_rides_into_the_transaction_and_never_beside_a_mint() {
        let t = fixture::templates();
        let (_, active, _) = fixture::active(&t, "kaspa");
        let funded = [coin(0xf0, 10 * 100_000_000)];
        let transfer = transfer_intent(&t, &active, OwnerType::Pubkey, &owner(6), 0).unwrap();
        let payload = b"terms".to_vec();
        let asm = assemble_with_payload(&transfer, &funded, SPK, 100_000, &payload).unwrap();
        assert_eq!(asm.tx.payload, payload);
        assert!(assemble(&transfer, &funded, SPK, 100_000).unwrap().tx.payload.is_empty());

        let next = crate::state::DeedState { owner: owner(6), ..active.state };
        let mint = crate::cards::CardMint::for_deed(&next, vec![0xa0], OwnerType::Pubkey, owner(6)).unwrap();
        let plan = CardPlan { mint: Some(mint), sweep: vec![] };
        let why = build(&transfer, &plan, &funded, SPK, 100_000, &payload).err().unwrap().to_string();
        assert!(why.contains("a mint writes the payload"), "{why}");
    }
}
