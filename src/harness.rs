//! Test helpers for the crates that build on this one. They assemble raw transactions from
//! intents with no builder checks, so an adversarial case reaches the script engine instead of a
//! builder's refusal. Every function panics on a malformed argument.

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::{
    CovenantBinding, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
};
use kaspa_txscript::EngineFlags;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::opcodes::codes::OpTrue;
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript_errors::TxScriptError;

use crate::registry::{KEY_MAX, KEY_MIN};
use crate::watch::{Entrypoint, GenesisFile};
use crate::*;

/// [`TEST_GENESIS`], parsed.
pub fn test_genesis() -> GenesisFile {
    serde_json::from_str(TEST_GENESIS).expect("the test deployment parses")
}

/// The templates of [`TEST_GENESIS`], loaded from its manifest.
pub fn test_templates() -> &'static Templates {
    use std::sync::OnceLock;
    static T: OnceLock<Templates> = OnceLock::new();
    T.get_or_init(|| Templates::from_manifest(&test_genesis()).expect("the test deployment loads its own templates"))
}

/// Bytes from hex.
pub fn unhex(s: &str) -> Vec<u8> {
    let mut v = vec![0u8; s.len() / 2];
    faster_hex::hex_decode(s.as_bytes(), &mut v).unwrap();
    v
}

/// Lowercase hex.
pub fn hex(b: &[u8]) -> String {
    faster_hex::hex_string(b)
}

pub fn outpoint(seed: u8, index: u32) -> Outpoint {
    Outpoint { transaction_id: hex(&[seed; 32]), index }
}

pub const FUNDING_VALUE: u64 = 1_000_000_000_000;
/// The registry lineage: one covenant id shared by every gap and every deed.
pub const COVENANT_ID: [u8; 32] = [0xcc; 32];
/// A second lineage, for a `covenant-id/v1` owner such as a sale escrow.
pub const ESCROW_COVENANT_ID: [u8; 32] = [0xee; 32];

pub fn covenant_id_hex() -> String {
    hex(&COVENANT_ID)
}

pub fn escrow_covenant_id_hex() -> String {
    hex(&ESCROW_COVENANT_ID)
}

// `transfer` and `release` verify real signatures, so the owner secrets are real keys.
pub const KEY_A: [u8; 32] = [5u8; 32];
pub const KEY_B: [u8; 32] = [6u8; 32];
pub const KEY_C: [u8; 32] = [7u8; 32];

pub fn owner_pub(secret: &[u8; 32]) -> [u8; 32] {
    secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, secret).unwrap().x_only_public_key().0.serialize()
}

pub fn owner_a() -> [u8; 32] {
    owner_pub(&KEY_A)
}

pub fn owner_b() -> [u8; 32] {
    owner_pub(&KEY_B)
}

/// The bare name zero-padded to 32 bytes, with no length assertion, so an over-long reveal can
/// reach the engine. An over-long name yields all zeros.
pub fn padded_bytes(name: &str) -> [u8; 32] {
    let b = name.as_bytes();
    let mut out = [0u8; 32];
    if b.len() <= 32 {
        out[..b.len()].copy_from_slice(b);
    }
    out
}

// ---- non-protocol inputs -------------------------------------------------------------------

/// An input outside the registry: wallet funding, the P2SH witness of a `p2sh/v1` owner, or a
/// co-present input of a foreign lineage. Never executed: the harness runs only the intent's
/// inputs.
#[derive(Debug, Clone)]
pub struct PlainInput {
    pub spk: Vec<u8>,
    pub covenant_id: Option<String>,
    pub value: u64,
}

impl PlainInput {
    pub fn funding() -> Self {
        Self { spk: vec![OpTrue], covenant_id: None, value: FUNDING_VALUE }
    }

    /// Locked to `redeem`'s P2SH address: what a `p2sh/v1` (0x03) owner approves by co-presence.
    pub fn p2sh(redeem: &[u8]) -> Self {
        Self { spk: kaspa_txscript::pay_to_script_hash_script(redeem).script().to_vec(), covenant_id: None, value: FUNDING_VALUE }
    }

    /// Carrying a covenant id: what a `covenant-id/v1` (0x04) owner approves by co-presence.
    pub fn lineage(covenant_id: &str) -> Self {
        Self { spk: vec![OpTrue], covenant_id: Some(covenant_id.to_string()), value: FUNDING_VALUE }
    }
}

/// The owner value a `p2sh/v1` deed stores for `redeem`: the KCC-2 script hash, blake2b on Kaspa.
pub fn p2sh_owner(redeem: &[u8]) -> [u8; 32] {
    blake2b(redeem)
}

// ---- assembly and execution ----------------------------------------------------------------

fn push_input(inputs: &mut Vec<TransactionInput>, entries: &mut Vec<UtxoEntry>, plain: &PlainInput, seed: u8, index: u32) {
    inputs.push(TransactionInput::new_with_compute_budget(outpoint(seed, index).to_consensus().unwrap(), vec![], 0, budgets::FUNDING));
    entries.push(UtxoEntry::new(
        plain.value,
        ScriptPublicKey::from_vec(0, plain.spk.clone()),
        0,
        false,
        plain.covenant_id.as_ref().map(|c| c.parse::<Hash>().unwrap()),
    ));
}

/// Assemble a transaction from an intent, appending one plain funding input after the protocol
/// inputs, the ordering `assemble` uses for an intent with no cards.
pub fn tx_from_intent(intent: &TxIntent, sequences: &[u64]) -> (Transaction, Vec<UtxoEntry>) {
    tx_from_intent_with(intent, sequences, &[], &[PlainInput::funding()])
}

/// Assemble with plain inputs before the protocol inputs as well as after. Leading inputs shift
/// every seat without changing the lineage count.
pub fn tx_from_intent_with(
    intent: &TxIntent,
    sequences: &[u64],
    leading: &[PlainInput],
    trailing: &[PlainInput],
) -> (Transaction, Vec<UtxoEntry>) {
    let mut inputs = Vec::new();
    let mut entries = Vec::new();
    for (i, plain) in leading.iter().enumerate() {
        push_input(&mut inputs, &mut entries, plain, 0xe0, i as u32);
    }
    for (i, input) in intent.inputs.iter().enumerate() {
        inputs.push(TransactionInput::new_with_compute_budget(
            input.outpoint.to_consensus().unwrap(),
            unhex(&input.sig_script),
            sequences.get(i).copied().unwrap_or(input.sequence),
            input.compute_budget,
        ));
        entries.push(UtxoEntry::new(
            input.value,
            ScriptPublicKey::from_vec(0, unhex(&input.spk)),
            0,
            false,
            input.utxo_covenant_id.as_ref().map(|c| c.parse::<Hash>().unwrap()),
        ));
    }
    for (i, plain) in trailing.iter().enumerate() {
        push_input(&mut inputs, &mut entries, plain, 0xf0, i as u32);
    }

    let outputs = intent
        .outputs
        .iter()
        .map(|o| TransactionOutput {
            value: o.value,
            script_public_key: ScriptPublicKey::from_vec(0, unhex(&o.spk)),
            covenant: o.covenant.as_ref().map(|c| CovenantBinding {
                covenant_id: c.covenant_id.parse().unwrap(),
                authorizing_input: c.authorizing_input as u16,
            }),
        })
        .collect();

    (Transaction::new(1, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]), entries)
}

/// Execute one input of a finished transaction, with covenants enabled. Panics when `entries`
/// and the inputs differ in length or the index is out of range.
pub fn execute(tx: &Transaction, entries: &[UtxoEntry], input_idx: usize) -> Result<(), TxScriptError> {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = CovenantsContext::from_tx(&populated)?;
    crate::vm::execute_input(&populated, &cov_ctx, input_idx)
}

/// Run every protocol input of `intent` on the engine.
pub fn run(intent: &TxIntent, sequences: &[u64]) -> Result<(), TxScriptError> {
    run_with(intent, sequences, &[], &[PlainInput::funding()])
}

/// Add `leading` to every output's authorizing input, so that each binding still names its
/// lineage input after [`tx_from_intent_with`] places `leading` plain inputs first. Without it,
/// consensus refuses the binding before any covenant opcode runs.
pub fn rebind_after_leading(intent: &TxIntent, leading: usize) -> TxIntent {
    let mut out = intent.clone();
    for o in &mut out.outputs {
        if let Some(c) = &mut o.covenant {
            c.authorizing_input += leading as u32;
        }
    }
    out
}

pub fn run_with(intent: &TxIntent, sequences: &[u64], leading: &[PlainInput], trailing: &[PlainInput]) -> Result<(), TxScriptError> {
    let (tx, entries) = tx_from_intent_with(intent, sequences, leading, trailing);
    for i in 0..intent.inputs.len() {
        execute(&tx, &entries, leading.len() + i)?;
    }
    Ok(())
}

/// Run one protocol seat, by its index within the intent.
pub fn run_seat(intent: &TxIntent, sequences: &[u64], seat: usize) -> Result<(), TxScriptError> {
    run_seat_with(intent, sequences, &[], &[PlainInput::funding()], seat)
}

pub fn run_seat_with(
    intent: &TxIntent,
    sequences: &[u64],
    leading: &[PlainInput],
    trailing: &[PlainInput],
    seat: usize,
) -> Result<(), TxScriptError> {
    let (tx, entries) = tx_from_intent_with(intent, sequences, leading, trailing);
    execute(&tx, &entries, leading.len() + seat)
}

// ---- fixtures ------------------------------------------------------------------------------

pub fn gap_utxo(t: &Templates, seed: u8, lo: [u8; 32], hi: [u8; 32]) -> GapUtxo {
    GapUtxo { outpoint: outpoint(seed, 0), value: t.params.gap_value, state: GapState { lo, hi }, covenant_id: covenant_id_hex() }
}

/// The one gap a fresh deployment holds: the whole keyspace, unregistered.
pub fn genesis_gap_utxo(t: &Templates) -> GapUtxo {
    gap_utxo(t, 0xaa, KEY_MIN, KEY_MAX)
}

/// The gap below a registered key. With [`succ_gap`], it is the pair an exit merges over.
pub fn pred_gap(t: &Templates, key: [u8; 32]) -> GapUtxo {
    gap_utxo(t, 0xba, KEY_MIN, key)
}

pub fn succ_gap(t: &Templates, key: [u8; 32]) -> GapUtxo {
    gap_utxo(t, 0xbb, key, KEY_MAX)
}

fn deed_seed(name: &str) -> u8 {
    key_of(name)[0] | 0x01
}

pub fn pending_deed(t: &Templates, name: &str, owner: &[u8; 32]) -> DeedUtxo {
    DeedUtxo {
        outpoint: outpoint(deed_seed(name), 2),
        value: t.params.bond + t.params.deposit,
        state: DeedState::pending(key_of(name), claim_of(name, OwnerType::Pubkey, owner)),
        covenant_id: covenant_id_hex(),
    }
}

pub fn active_deed(t: &Templates, name: &str, owner: &[u8; 32]) -> DeedUtxo {
    DeedUtxo {
        outpoint: outpoint(deed_seed(name), 0),
        value: t.params.bond,
        state: DeedState::active(key_of(name), OwnerType::Pubkey, *owner, padded_name(name)),
        covenant_id: covenant_id_hex(),
    }
}

/// The `p2pk-ecdsa` owner record of a 32-byte secret or a 33-byte compressed key, derived
/// through its Kaspa ECDSA address so the scheme byte carries the key's real parity.
pub fn ecdsa_owner_of(k: &[u8]) -> (OwnerType, [u8; 32]) {
    use kaspa_addresses::{Address, Prefix, Version};
    let key: [u8; 33] = match k.len() {
        32 => crate::sign::compressed_public_key(k.try_into().unwrap()).unwrap(),
        33 => k.try_into().unwrap(),
        n => panic!("expected a 32-byte secret or a 33-byte compressed key, got {n} bytes"),
    };
    crate::address::owner_of(&Address::new(Prefix::Testnet, Version::PubKeyECDSA, &key)).unwrap()
}

/// The scheme byte of [`ecdsa_owner_of`]: even or odd, per the key's y.
pub fn ecdsa_scheme(k: &[u8]) -> OwnerType {
    ecdsa_owner_of(k).0
}

/// The owner value of [`ecdsa_owner_of`]: the compressed key's x.
pub fn ecdsa_x(k: &[u8]) -> [u8; 32] {
    ecdsa_owner_of(k).1
}

/// An ACTIVE deed under any owner scheme.
pub fn owned_deed(t: &Templates, name: &str, owner_type: OwnerType, owner: &[u8; 32]) -> DeedUtxo {
    let deed = active_deed(t, name, owner);
    DeedUtxo { state: DeedState { owner_type, owner: *owner, ..deed.state }, ..deed }
}

// ---- raw shape building --------------------------------------------------------------------

pub fn gap_input(t: &Templates, gap: &GapUtxo, sig_script: Vec<u8>, budget: u16) -> IntentInput {
    IntentInput {
        outpoint: gap.outpoint.clone(),
        value: gap.value,
        spk: hex(&t.gap.p2sh_spk(&gap.state.encode()).unwrap()),
        sig_script: hex(&sig_script),
        compute_budget: budget,
        sequence: 0,
        utxo_covenant_id: Some(gap.covenant_id.clone()),
        role: "gap".into(),
    }
}

pub fn deed_input(t: &Templates, deed: &DeedUtxo, sig_script: Vec<u8>, budget: u16, sequence: u64) -> IntentInput {
    IntentInput {
        outpoint: deed.outpoint.clone(),
        value: deed.value,
        spk: hex(&t.deed.p2sh_spk(&deed.state.encode()).unwrap()),
        sig_script: hex(&sig_script),
        compute_budget: budget,
        sequence,
        utxo_covenant_id: Some(deed.covenant_id.clone()),
        role: "deed".into(),
    }
}

/// A plain input inside the protocol input list, which moves only the seats above it.
pub fn plain_input(seed: u8) -> IntentInput {
    IntentInput {
        outpoint: outpoint(seed, 0),
        value: FUNDING_VALUE,
        spk: hex(&[OpTrue]),
        sig_script: String::new(),
        compute_budget: budgets::FUNDING,
        sequence: 0,
        utxo_covenant_id: None,
        role: "funding".into(),
    }
}

/// A deed input over raw state bytes, for a state the typed codec refuses to build.
pub fn raw_deed_input(t: &Templates, op: Outpoint, value: u64, state: &[u8], sig_script: Vec<u8>, budget: u16) -> IntentInput {
    IntentInput {
        outpoint: op,
        value,
        spk: hex(&t.deed.p2sh_spk(state).unwrap()),
        sig_script: hex(&sig_script),
        compute_budget: budget,
        sequence: 0,
        utxo_covenant_id: Some(covenant_id_hex()),
        role: "deed".into(),
    }
}

pub fn gap_output(t: &Templates, state: &GapState, value: u64, covenant_id: &str) -> IntentOutput {
    IntentOutput {
        value,
        spk: hex(&t.gap.p2sh_spk(&state.encode()).unwrap()),
        covenant: Some(CovenantBindingIntent { covenant_id: covenant_id.to_string(), authorizing_input: 0 }),
        role: "gap".into(),
    }
}

pub fn deed_output(t: &Templates, state: &DeedState, value: u64, covenant_id: &str) -> IntentOutput {
    IntentOutput {
        value,
        spk: hex(&t.deed.p2sh_spk(&state.encode()).unwrap()),
        covenant: Some(CovenantBindingIntent { covenant_id: covenant_id.to_string(), authorizing_input: 0 }),
        role: "deed".into(),
    }
}

/// An output with no covenant binding: the activation fee, an owner's payout, plain change.
pub fn plain_output(value: u64, spk: &str) -> IntentOutput {
    IntentOutput { value, spk: spk.to_string(), covenant: None, role: "plain".into() }
}

pub fn devfund_output(t: &Templates, value: u64) -> IntentOutput {
    IntentOutput { value, spk: t.params.devfund_spk.clone(), covenant: None, role: "registrationFee".into() }
}

pub fn shape(kind: &str, inputs: Vec<IntentInput>, outputs: Vec<IntentOutput>) -> TxIntent {
    TxIntent { kind: kind.into(), inputs, outputs, required_funding: 0, released: 0, pending_state: None, pending_output_index: None }
}

/// An activate with any deed state, revealed name, owner key and fee, and the continuation the
/// covenant demands for them.
pub fn activate_shape(t: &Templates, deed: &DeedUtxo, name: &str, owner_key: &[u8; 32], fee: u64) -> TxIntent {
    let next = DeedState {
        status: Status::Active,
        key: deed.state.key,
        owner_type: OwnerType::Pubkey,
        owner: *owner_key,
        name: padded_bytes(name),
    };
    let sig = t.activate_sig_script(&deed.state, name, OwnerType::Pubkey as u8, owner_key).unwrap();
    shape(
        "activate",
        vec![deed_input(t, deed, sig, budgets::ACTIVATE, 0)],
        vec![deed_output(t, &next, t.params.bond, &deed.covenant_id), devfund_output(t, fee)],
    )
}

/// A transfer with a raw scheme byte, any new owner and any witness index. A signing owner gets
/// the placeholder, which [`sign_deed_seat`] patches.
pub fn transfer_shape(t: &Templates, deed: &DeedUtxo, new_owner_type: u8, new_owner: &[u8; 32], witness: i64) -> TxIntent {
    let placeholder = deed.state.owner_type.needs_signature().then_some(&crate::sign::SIG_PLACEHOLDER[..]);
    let sig = t.transfer_sig_script(&deed.state, new_owner_type, new_owner, witness, placeholder).unwrap();
    let next = DeedState {
        owner_type: OwnerType::from_byte(new_owner_type).unwrap_or(deed.state.owner_type),
        owner: *new_owner,
        ..deed.state
    };
    shape(
        "transfer",
        vec![deed_input(t, deed, sig, budgets::TRANSFER, 0)],
        vec![deed_output(t, &next, t.params.bond, &deed.covenant_id)],
    )
}

// ---- sigscript surgery ---------------------------------------------------------------------

/// Byte spans of a push-only script's pushes, opcode included.
pub fn push_spans(script: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i < script.len() {
        let start = i;
        let op = script[i];
        i += 1;
        let n = match op {
            0x00 | 0x51..=0x60 => 0,
            0x01..=0x4b => op as usize,
            0x4c => {
                let n = script[i] as usize;
                i += 1;
                n
            }
            0x4d => {
                let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
                i += 2;
                n
            }
            0x4e => {
                let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]]) as usize;
                i += 4;
                n
            }
            other => panic!("non-push opcode {other:#04x} in a signature script"),
        };
        i += n;
        spans.push((start, i));
    }
    spans
}

/// One minimal data push, as the compiler's builder emits it.
pub fn push_bytes(payload: &[u8]) -> Vec<u8> {
    let mut b = ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() });
    b.add_data(payload).unwrap();
    b.drain()
}

pub fn splice_push(script: &[u8], index: usize, payload: &[u8]) -> Vec<u8> {
    let (start, end) = push_spans(script)[index];
    let mut out = script[..start].to_vec();
    out.extend(push_bytes(payload));
    out.extend_from_slice(&script[end..]);
    out
}

/// Swap the redeem, the final push.
pub fn with_redeem(script: &[u8], redeem: &[u8]) -> Vec<u8> {
    let last = push_spans(script).len() - 1;
    splice_push(script, last, redeem)
}

/// Swap the dispatch tag (the push before the redeem).
pub fn with_tag(script: &[u8], tag: &[u8]) -> Vec<u8> {
    let tag_at = push_spans(script).len() - 2;
    splice_push(script, tag_at, tag)
}

// ---- signing -------------------------------------------------------------------------------

/// Sign a deed seat and patch the placeholder in place. A Kaspa sighash excludes signature
/// scripts and compute budgets, so the patch changes nothing the signature commits to.
pub fn sign_deed_seat(intent: &mut TxIntent, seat: usize, secret: &[u8; 32], scheme: OwnerType, sequences: &[u64]) {
    sign_deed_seat_with(intent, seat, secret, scheme, sequences, &[], &[PlainInput::funding()]);
}

pub fn sign_deed_seat_with(
    intent: &mut TxIntent,
    seat: usize,
    secret: &[u8; 32],
    scheme: OwnerType,
    sequences: &[u64],
    leading: &[PlainInput],
    trailing: &[PlainInput],
) {
    let (tx, entries) = tx_from_intent_with(intent, sequences, leading, trailing);
    let idx = leading.len() + seat;
    let sig = match scheme {
        OwnerType::P2pkEcdsaEven | OwnerType::P2pkEcdsaOdd => crate::sign::ecdsa_sign_input(&tx, &entries, idx, secret).unwrap(),
        _ => crate::sign::schnorr_sign_input(&tx, &entries, idx, secret).unwrap(),
    };
    let mut bytes = unhex(&intent.inputs[seat].sig_script);
    crate::sign::patch_placeholder_sig(&mut bytes, &sig).unwrap();
    intent.inputs[seat].sig_script = hex(&bytes);
}

// ---- the entrypoint alphabet ---------------------------------------------------------------

/// Every sigscript a gap can present. The `split` arm splits at the key `[0x80; 32]`, so it is
/// well-formed only for a gap that contains that key.
pub fn gap_sig_scripts(t: &Templates, gap: &GapState) -> Vec<(Entrypoint, Vec<u8>)> {
    let mid = [0x80u8; 32];
    vec![
        (Entrypoint::Split, t.split_sig_script(gap, &mid, &[0x42u8; 32]).unwrap()),
        (Entrypoint::Merge, t.merge_sig_script(gap).unwrap()),
        (Entrypoint::Absorbed, t.absorbed_sig_script(gap).unwrap()),
    ]
}

/// Every sigscript a deed can present, with the signing arms left at the placeholder.
pub fn deed_sig_scripts(t: &Templates, deed: &DeedState) -> Vec<(Entrypoint, Vec<u8>)> {
    let placeholder = Some(&crate::sign::SIG_PLACEHOLDER[..]);
    vec![
        (Entrypoint::Activate, t.activate_sig_script(deed, "kaspa", OwnerType::Pubkey as u8, &owner_a()).unwrap()),
        (Entrypoint::Transfer, t.transfer_sig_script(deed, OwnerType::Pubkey as u8, &owner_b(), 0, placeholder).unwrap()),
        (Entrypoint::Release, t.release_sig_script(deed, 0, placeholder).unwrap()),
        (Entrypoint::Evict, t.evict_sig_script(deed).unwrap()),
    ]
}

// ---- measurement ---------------------------------------------------------------------------

/// Serialized size, non-contextual masses and relay-fee floor of a finished transaction, as a
/// node measures them.
pub fn measure_tx(network: &str, tx: &Transaction) -> (u64, kaspa_consensus_core::mass::NonContextualMasses, u64) {
    use kaspa_consensus_core::config::params::Params as ConsensusParams;
    use kaspa_consensus_core::mass::{MassCalculator, transaction_estimated_serialized_size};
    let consensus = ConsensusParams::from(fees::network_id(network).expect("a known network"));
    let masses = MassCalculator::new_with_consensus_params(&consensus).calc_non_contextual_masses(tx);
    (transaction_estimated_serialized_size(tx), masses, minimum_standard_fee(network, tx).expect("the relay minimum"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A broken fixture or assembly fails here before a dependent crate meets it.
    #[test]
    fn the_test_deployment_activates_a_name_on_the_engine() {
        let t = test_templates();
        let deed = pending_deed(t, "kaspa", &owner_a());
        run(&activate_shape(t, &deed, "kaspa", &owner_a(), t.params.fee_5plus), &[]).expect("the honest activate executes");
        run(&activate_shape(t, &deed, "kaspa", &owner_a(), t.params.fee_5plus - 1), &[])
            .expect_err("an underpaid activate is refused");
    }
}
