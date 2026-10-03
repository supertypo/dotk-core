use anyhow::{Context, Result, ensure};
use kaspa_consensus_core::hashing::covenant_id::covenant_id;
use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionOutpoint, TransactionOutput};
use serde::{Deserialize, Serialize};

use crate::contracts::Templates;
use crate::names::{self, SubnameFault};
use crate::params::Params;
use crate::state::{DeedState, GapState, OwnerType, Status};

/// Per-input compute budgets in units of 10,000 script units. Each one is several times the minimum
/// that its entrypoint measures, as a reserve against repricing.
pub mod budgets {
    pub const SPLIT: u16 = 150;
    pub const MERGE: u16 = 150;
    pub const ABSORBED: u16 = 50;
    pub const ACTIVATE: u16 = 100;
    pub const TRANSFER: u16 = 100;
    pub const RELEASE: u16 = 100;
    pub const EVICT: u16 = 50;
    pub const FUNDING: u16 = 20;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outpoint {
    /// Hex.
    pub transaction_id: String,
    pub index: u32,
}

impl Outpoint {
    pub fn to_consensus(&self) -> Result<TransactionOutpoint> {
        Ok(TransactionOutpoint::new(self.transaction_id.parse()?, self.index))
    }
}

/// A live gap UTXO, the interval `(lo, hi)` of unregistered keyspace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapUtxo {
    pub outpoint: Outpoint,
    pub value: u64,
    pub state: GapState,
    /// Hex. Every registry UTXO carries the same covenant id.
    pub covenant_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeedUtxo {
    pub outpoint: Outpoint,
    pub value: u64,
    pub state: DeedState,
    pub covenant_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CovenantBindingIntent {
    /// Hex.
    pub covenant_id: String,
    pub authorizing_input: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentInput {
    pub outpoint: Outpoint,
    pub value: u64,
    /// Hex, no version prefix.
    pub spk: String,
    /// Hex: entrypoint args ‖ dispatch tag ‖ redeem push.
    pub sig_script: String,
    pub compute_budget: u16,
    /// Non-zero only where a relative lock applies (evict: T_EVICT).
    #[serde(default)]
    pub sequence: u64,
    pub utxo_covenant_id: Option<String>,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentOutput {
    pub value: u64,
    /// Hex, no version prefix.
    pub spk: String,
    pub covenant: Option<CovenantBindingIntent>,
    pub role: String,
}

/// A protocol transaction without its funding inputs and change, which must come strictly after the
/// protocol inputs and outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIntent {
    pub kind: String,
    pub inputs: Vec<IntentInput>,
    pub outputs: Vec<IntentOutput>,
    /// Value the funding inputs must add on top of the covenant inputs, fees excluded.
    pub required_funding: u64,
    /// Input values minus output values, saturating at zero. It never overstates, so callers read
    /// `released > 0` as self-funding.
    pub released: u64,
    /// For split: the newborn deed's state and output index, which a wallet needs to chain the
    /// activate.
    #[serde(default)]
    pub pending_state: Option<DeedState>,
    #[serde(default)]
    pub pending_output_index: Option<u32>,
}

fn hex(b: &[u8]) -> String {
    faster_hex::hex_string(b)
}

/// Sums values into a named error on overflow, never a panic or a wrap.
pub(crate) fn sum(parts: &[u64], what: &str) -> Result<u64> {
    parts.iter().try_fold(0u64, |acc, v| acc.checked_add(*v)).ok_or_else(|| anyhow::anyhow!("{what} overflows u64"))
}

/// A funding signature commits to its own amount only, so an understated covenant input value
/// leaves the difference to the miner past every fee ceiling.
pub(crate) fn check_value(what: &str, constant: &str, got: u64, pinned: u64) -> Result<(), String> {
    if got == pinned { Ok(()) } else { Err(format!("{what} holds exactly {constant} ({pinned}), this one holds {got}")) }
}

/// [`check_value`] for a deed, whose pinned value follows its status.
pub(crate) fn check_deed_value(deed: &DeedUtxo, params: &Params) -> Result<(), String> {
    match deed.state.status {
        Status::Pending => {
            let posting = sum(&[params.bond, params.deposit], "bond + deposit").map_err(|e| e.to_string())?;
            check_value("a PENDING deed", "BOND + DEPOSIT", deed.value, posting)
        }
        Status::Active => check_value("an ACTIVE deed", "BOND", deed.value, params.bond),
    }
}

/// Every rule an owner value must satisfy. The covenant cannot test that a key is a curve point, so
/// this is the only guard against a deed that no signature can spend.
pub fn validate_owner(scheme: OwnerType, owner: &[u8; 32], registry_covenant_id: &str) -> Result<()> {
    // A deed owned by the registry's own covenant id authorizes its own spend for anybody.
    let mut id = [0u8; 32];
    faster_hex::hex_decode(registry_covenant_id.as_bytes(), &mut id)
        .map_err(|e| anyhow::anyhow!("the registry covenant id is not 32 bytes of hex: {e}"))?;
    anyhow::ensure!(
        id != *owner,
        "refusing the registry's own covenant id as an owner: such a deed authorizes its own spend for anybody"
    );
    crate::address::check_payload(scheme, owner).map_err(|fault| match fault {
        SubnameFault::ZeroPayload => anyhow::anyhow!("the owner is zero, and no scheme can ever satisfy it"),
        SubnameFault::NotAPoint(e) => {
            let what = match scheme {
                OwnerType::Pubkey => "a valid secp256k1 x-only public key",
                _ => "the x of a secp256k1 public key under this scheme's y-parity",
            };
            anyhow::anyhow!(
                "{} is not {what} ({e}). A {scheme:?} owner IS the key, so no signature could \
                 ever satisfy this deed: the name and its bond would be locked away from \
                 everyone, permanently, with no eviction path.",
                hex(owner)
            )
        }
        other => anyhow::anyhow!("{other}"),
    })
}

pub fn genesis_covenant_id(authorizing_outpoint: &Outpoint, output_index: u32, value: u64, spk: &[u8]) -> Result<String> {
    let out = TransactionOutput::new(value, ScriptPublicKey::from_vec(0, spk.to_vec()));
    let id = covenant_id(authorizing_outpoint.to_consensus()?, [(output_index, &out)].into_iter());
    Ok(id.to_string())
}

/// Checks an intent's output roles, and the script and value of its devfund output, against the
/// params. An extra output is consensus-legal and no fee rail sees it, so the whole role sequence is
/// matched. Without `name` the devfund value must equal one of the five tiers.
pub fn validate_against_params(intent: &TxIntent, params: &Params, name: Option<&str>) -> Result<()> {
    let expected: &[&str] = match intent.kind.as_str() {
        "genesis" => &["genesisGap"],
        "split" => &["lowerGap", "upperGap", "newborn"],
        "activate" => &["continuation", "registrationFee"],
        "transfer" => &["continuation"],
        "release" => &["mergedGap"],
        "evict" => &["mergedGap", "depositToDevfund"],
        other => anyhow::bail!("this build knows no intent of kind {other}"),
    };
    let roles: Vec<&str> = intent.outputs.iter().map(|o| o.role.as_str()).collect();
    ensure!(roles == expected, "a {} writes {expected:?}, and this one writes {roles:?}", intent.kind);

    let tiers = [params.fee_1ch, params.fee_2ch, params.fee_3ch, params.fee_4ch, params.fee_5plus];
    let (pinned, expected_value) = match intent.kind.as_str() {
        "activate" => (&intent.outputs[1], name.map(|name| params.fee_for_name(name))),
        "evict" => (&intent.outputs[1], Some(params.deposit)),
        _ => return Ok(()),
    };
    ensure!(pinned.spk == params.devfund_spk, "this {} pays a script that is not the devfund's", intent.kind);
    match expected_value {
        Some(want) => {
            ensure!(pinned.value == want, "this {} pays the devfund {} where the params price it at {want}", intent.kind, pinned.value)
        }
        None => ensure!(
            tiers.contains(&pinned.value),
            "this {} pays the devfund {}, which is not one of the five prices this deployment charges",
            intent.kind,
            pinned.value
        ),
    }
    Ok(())
}

/// [`split_intent`] without its guards.
#[doc(hidden)]
pub fn split_intent_unchecked(t: &Templates, gap: &GapUtxo, new_key: &[u8; 32], claim: &[u8; 32]) -> Result<TxIntent> {
    let lower = GapState { lo: gap.state.lo, hi: *new_key };
    let upper = GapState { lo: *new_key, hi: gap.state.hi };
    let newborn = DeedState::pending(*new_key, *claim);
    let newborn_value = sum(&[t.params.bond, t.params.deposit], "bond + deposit")?;
    // The registrant funds one extra gap value, and the exit merge frees it again.
    let posting = sum(&[newborn_value, t.params.gap_value, t.params.gap_value], "bond + deposit + 2 · gap_value")?;
    // Every registry UTXO carries the id minted at the genesis gap.
    let covenant_id = gap.covenant_id.clone();
    Ok(TxIntent {
        kind: "split".into(),
        inputs: vec![IntentInput {
            outpoint: gap.outpoint.clone(),
            value: gap.value,
            spk: hex(&t.gap.p2sh_spk(&gap.state.encode())?),
            sig_script: hex(&t.split_sig_script(&gap.state, new_key, claim)?),
            compute_budget: budgets::SPLIT,
            sequence: 0,
            utxo_covenant_id: Some(covenant_id.clone()),
            role: "gap".into(),
        }],
        outputs: vec![
            IntentOutput {
                value: t.params.gap_value,
                spk: hex(&t.gap.p2sh_spk(&lower.encode())?),
                covenant: Some(CovenantBindingIntent { covenant_id: covenant_id.clone(), authorizing_input: 0 }),
                role: "lowerGap".into(),
            },
            IntentOutput {
                value: t.params.gap_value,
                spk: hex(&t.gap.p2sh_spk(&upper.encode())?),
                covenant: Some(CovenantBindingIntent { covenant_id: covenant_id.clone(), authorizing_input: 0 }),
                role: "upperGap".into(),
            },
            IntentOutput {
                value: newborn_value,
                spk: hex(&t.deed.p2sh_spk(&newborn.encode())?),
                covenant: Some(CovenantBindingIntent { covenant_id, authorizing_input: 0 }),
                role: "newborn".into(),
            },
        ],
        required_funding: posting.saturating_sub(gap.value),
        released: 0,
        pending_state: Some(newborn),
        pending_output_index: Some(2),
    })
}

/// Refuses a bad name, owner or gap before building, so a failure names its reason.
pub fn split_intent(t: &Templates, gap: &GapUtxo, name: &str, owner_type: OwnerType, owner_payload: &[u8; 32]) -> Result<TxIntent> {
    names::validate(name).map_err(anyhow::Error::msg)?;
    // The claim binds this owner permanently, so an owner that `activate` refuses makes a posting
    // that can never be revealed and ends as an evict bounty.
    anyhow::ensure!(owner_type.mintable(), "{owner_type:?} cannot be minted by activate; register to a key and transfer");
    validate_owner(owner_type, owner_payload, &gap.covenant_id).context("registration owner")?;
    let new_key = names::key_of(name);
    let claim = names::claim_of(name, owner_type, owner_payload);
    anyhow::ensure!(gap.state.contains(&new_key), "the name's key is not inside this gap");
    check_value("a gap", "GAP_VALUE", gap.value, t.params.gap_value).map_err(anyhow::Error::msg)?;
    split_intent_unchecked(t, gap, &new_key, &claim)
}

/// The reveal: prove both preimages, pay the fee, stamp the name, release the DEPOSIT.
pub fn activate_intent(
    t: &Templates,
    deed: &DeedUtxo,
    name: &str,
    owner_type: OwnerType,
    owner_payload: &[u8; 32],
) -> Result<TxIntent> {
    names::validate(name).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(deed.state.status == Status::Pending, "deed is not PENDING");
    anyhow::ensure!(owner_type.mintable(), "{owner_type:?} cannot be minted by activate; register to a key and transfer");
    validate_owner(owner_type, owner_payload, &deed.covenant_id).context("reveal owner")?;
    anyhow::ensure!(names::key_of(name) == deed.state.key, "name does not match the deed key");
    anyhow::ensure!(
        names::claim_of(name, owner_type, owner_payload) == deed.state.owner,
        "claim does not match: wrong owner, scheme or name"
    );
    check_deed_value(deed, &t.params).map_err(anyhow::Error::msg)?;

    let fee = t.params.fee_for_name(name);
    let outputs_value = sum(&[t.params.bond, fee], "bond + registration fee")?;
    let next = DeedState::active(deed.state.key, owner_type, *owner_payload, names::padded_name(name));
    Ok(TxIntent {
        kind: "activate".into(),
        inputs: vec![IntentInput {
            outpoint: deed.outpoint.clone(),
            value: deed.value,
            spk: hex(&t.deed.p2sh_spk(&deed.state.encode())?),
            sig_script: hex(&t.activate_sig_script(&deed.state, name, owner_type as u8, owner_payload)?),
            compute_budget: budgets::ACTIVATE,
            sequence: 0,
            utxo_covenant_id: Some(deed.covenant_id.clone()),
            role: "deed".into(),
        }],
        outputs: vec![
            IntentOutput {
                value: t.params.bond,
                spk: hex(&t.deed.p2sh_spk(&next.encode())?),
                covenant: Some(CovenantBindingIntent { covenant_id: deed.covenant_id.clone(), authorizing_input: 0 }),
                role: "continuation".into(),
            },
            IntentOutput { value: fee, spk: t.params.devfund_spk.clone(), covenant: None, role: "registrationFee".into() },
        ],
        required_funding: outputs_value.saturating_sub(deed.value),
        // The fee comes out of the refunded DEPOSIT, so the gross DEPOSIT overstates the surplus.
        released: deed.value.saturating_sub(outputs_value),
        pending_state: None,
        pending_output_index: None,
    })
}

/// Owner-authorized transfer on the deed input alone. A signing owner's sigscript carries a zero
/// placeholder: sign input 0 after assembly and patch it in, which leaves the txid unchanged. A P2SH
/// owner's `witness_index` points at the co-present authority input.
pub fn transfer_intent(
    t: &Templates,
    deed: &DeedUtxo,
    new_owner_type: OwnerType,
    new_owner: &[u8; 32],
    witness_index: i64,
) -> Result<TxIntent> {
    anyhow::ensure!(deed.state.status == Status::Active, "deed is not ACTIVE");
    check_deed_value(deed, &t.params).map_err(anyhow::Error::msg)?;
    validate_owner(new_owner_type, new_owner, &deed.covenant_id).context("transfer target")?;

    let next = DeedState { owner_type: new_owner_type, owner: *new_owner, ..deed.state };
    Ok(TxIntent {
        kind: "transfer".into(),
        inputs: vec![IntentInput {
            outpoint: deed.outpoint.clone(),
            value: deed.value,
            spk: hex(&t.deed.p2sh_spk(&deed.state.encode())?),
            sig_script: hex(&t.transfer_sig_script(
                &deed.state,
                new_owner_type as u8,
                new_owner,
                witness_index,
                owner_sig_placeholder(&deed.state),
            )?),
            compute_budget: budgets::TRANSFER,
            sequence: 0,
            utxo_covenant_id: Some(deed.covenant_id.clone()),
            role: "deed".into(),
        }],
        outputs: vec![IntentOutput {
            value: t.params.bond,
            spk: hex(&t.deed.p2sh_spk(&next.encode())?),
            covenant: Some(CovenantBindingIntent { covenant_id: deed.covenant_id.clone(), authorizing_input: 0 }),
            role: "continuation".into(),
        }],
        required_funding: 0,
        released: 0,
        pending_state: None,
        pending_output_index: None,
    })
}

fn owner_sig_placeholder(deed: &DeedState) -> Option<&'static [u8]> {
    deed.owner_type.needs_signature().then_some(&crate::sign::SIG_PLACEHOLDER[..])
}

/// The owner's exit: `pred` runs `merge` at seat 0, the deed `release` at seat 1, and `succ`
/// `absorbed` at seat 2. A signing owner patches input 1.
pub fn release_intent(t: &Templates, pred: &GapUtxo, deed: &DeedUtxo, succ: &GapUtxo, witness_index: i64) -> Result<TxIntent> {
    anyhow::ensure!(deed.state.status == Status::Active, "deed is not ACTIVE");
    anyhow::ensure!(deed.state.owner_type != OwnerType::CovenantId, "covenant-owned names exit via their owner covenant");
    // The covenant enforces adjacency too, but a stale neighborhood must fail before a fee is paid.
    anyhow::ensure!(pred.state.hi == deed.state.key, "predecessor gap is not adjacent to the deed");
    anyhow::ensure!(succ.state.lo == deed.state.key, "successor gap is not adjacent to the deed");
    release_intent_unchecked(t, pred, deed, succ, witness_index)
}

/// [`release_intent`] without its adjacency guards.
#[doc(hidden)]
pub fn release_intent_unchecked(
    t: &Templates,
    pred: &GapUtxo,
    deed: &DeedUtxo,
    succ: &GapUtxo,
    witness_index: i64,
) -> Result<TxIntent> {
    crate::watch::release_shape(
        &t.gap,
        &t.deed,
        &t.params,
        pred,
        deed,
        succ,
        t.merge_sig_script(&pred.state)?,
        t.release_sig_script(&deed.state, witness_index, owner_sig_placeholder(&deed.state))?,
        t.absorbed_sig_script(&succ.state)?,
    )
    .map_err(anyhow::Error::msg)
}

/// Permissionless cleanup of a stale PENDING deed. DEPOSIT is pinned to the devfund at output 1.
pub fn evict_intent(t: &Templates, pred: &GapUtxo, deed: &DeedUtxo, succ: &GapUtxo) -> Result<TxIntent> {
    anyhow::ensure!(pred.state.hi == deed.state.key, "predecessor gap is not adjacent to the deed");
    anyhow::ensure!(succ.state.lo == deed.state.key, "successor gap is not adjacent to the deed");
    evict_intent_unchecked(t, pred, deed, succ)
}

/// [`evict_intent`] without its adjacency guards.
#[doc(hidden)]
pub fn evict_intent_unchecked(t: &Templates, pred: &GapUtxo, deed: &DeedUtxo, succ: &GapUtxo) -> Result<TxIntent> {
    anyhow::ensure!(deed.state.status == Status::Pending, "deed is not PENDING");
    crate::watch::evict_shape(
        &t.gap,
        &t.deed,
        &t.params,
        pred,
        deed,
        succ,
        t.merge_sig_script(&pred.state)?,
        t.evict_sig_script(&deed.state)?,
        t.absorbed_sig_script(&succ.state)?,
    )
    .map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{self, owner};

    fn values(intent: &TxIntent) -> Vec<(&str, u64)> {
        intent.outputs.iter().map(|o| (o.role.as_str(), o.value)).collect()
    }

    /// Every value a builder emits comes from the params, never from a caller or a UTXO.
    #[test]
    fn builders_price_every_output_from_the_params() {
        let t = fixture::templates();
        let p = &t.params;
        let whole = fixture::gap(&t, crate::registry::KEY_MIN, crate::registry::KEY_MAX, 0xa3);
        let split = split_intent(&t, &whole, "kaspa", OwnerType::Pubkey, &owner(5)).unwrap();
        assert_eq!(values(&split), [("lowerGap", p.gap_value), ("upperGap", p.gap_value), ("newborn", p.bond + p.deposit)]);
        validate_against_params(&split, p, Some("kaspa")).unwrap();

        let (pred, pending, succ) = fixture::pending(&t, "kaspa");
        let activate = activate_intent(&t, &pending, "kaspa", OwnerType::Pubkey, &owner(5)).unwrap();
        assert_eq!(values(&activate), [("continuation", p.bond), ("registrationFee", p.fee_for_name("kaspa"))]);
        validate_against_params(&activate, p, Some("kaspa")).unwrap();

        let evict = evict_intent(&t, &pred, &pending, &succ).unwrap();
        assert_eq!(values(&evict)[1].1, p.deposit, "the devfund takes the deposit");
        validate_against_params(&evict, p, None).unwrap();

        let (_, active, _) = fixture::active(&t, "kaspa");
        let transfer = transfer_intent(&t, &active, OwnerType::Pubkey, &owner(6), 0).unwrap();
        assert_eq!(values(&transfer), [("continuation", p.bond)]);
    }

    #[test]
    fn a_tampered_intent_fails_the_params_check() {
        let t = fixture::templates();
        let (_, pending, _) = fixture::pending(&t, "kaspa");
        let honest = activate_intent(&t, &pending, "kaspa", OwnerType::Pubkey, &owner(5)).unwrap();

        let mut overpaid = honest.clone();
        overpaid.outputs[1].value += 1;
        assert!(validate_against_params(&overpaid, &t.params, Some("kaspa")).is_err(), "a fee off every tier");

        let mut extra = honest.clone();
        extra.outputs.push(IntentOutput { value: 1, spk: t.params.devfund_spk.clone(), covenant: None, role: "extra".into() });
        assert!(validate_against_params(&extra, &t.params, Some("kaspa")).is_err(), "an output the kind does not have");
    }

    /// A deed owned by the registry's own covenant id authorizes its own spend for anybody.
    #[test]
    fn the_registry_never_owns_a_deed() {
        let id = [0xcc; 32];
        assert!(validate_owner(OwnerType::CovenantId, &id, fixture::COVENANT_ID).unwrap_err().to_string().contains("own covenant id"));
        assert!(validate_owner(OwnerType::CovenantId, &id, &fixture::COVENANT_ID.to_uppercase()).is_err());
        assert!(validate_owner(OwnerType::Pubkey, &owner(5), fixture::COVENANT_ID).is_ok());
    }

    /// A funding signature commits to its own amount only, so an understated covenant input
    /// hands the difference to the miner past the fee ceiling.
    #[test]
    fn an_understated_input_value_is_refused_by_every_builder() {
        let t = fixture::templates();
        let whole = fixture::gap(&t, crate::registry::KEY_MIN, crate::registry::KEY_MAX, 0xa3);
        let light = GapUtxo { value: 0, ..whole.clone() };
        assert!(split_intent(&t, &light, "kaspa", OwnerType::Pubkey, &owner(5)).is_err());

        let (pred, pending, succ) = fixture::pending(&t, "kaspa");
        let light = DeedUtxo { value: 0, ..pending.clone() };
        assert!(activate_intent(&t, &light, "kaspa", OwnerType::Pubkey, &owner(5)).is_err());
        assert!(evict_intent(&t, &pred, &light, &succ).is_err());
        let light_flank = GapUtxo { value: t.params.gap_value - 1, ..succ.clone() };
        assert!(evict_intent(&t, &pred, &pending, &light_flank).is_err());

        let (pred, active, succ) = fixture::active(&t, "kaspa");
        let light = DeedUtxo { value: t.params.bond - 1, ..active.clone() };
        assert!(release_intent(&t, &pred, &light, &succ, 0).is_err());
        assert!(transfer_intent(&t, &light, OwnerType::Pubkey, &owner(6), 0).is_err());
        assert!(release_intent(&t, &pred, &active, &succ, 0).is_ok());
    }
}
