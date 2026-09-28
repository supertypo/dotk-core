//! Decodes registry transactions and builds exits from a deployment manifest.

use serde::{Deserialize, Serialize};
use silverscript_abi::SilAbiArtifact;

use crate::contracts::{Template, Templates};
use crate::intents::{
    CovenantBindingIntent, DeedUtxo, GapUtxo, IntentInput, IntentOutput, TxIntent, budgets, check_deed_value, check_value, sum,
};
use crate::names;
use crate::params::Params;
use crate::state::{DeedState, GapState, OwnerType, Status};

/// Dispatch is by KCC-1 tag over the name and argument types, so a rename orphans every deployed UTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entrypoint {
    /// Gap: the uniqueness event, which mints a PENDING deed.
    Split,
    /// Gap: an exit's leader at seat 0.
    Merge,
    /// Gap: an exit's successor at seat 2.
    Absorbed,
    /// Deed: the reveal, PENDING to ACTIVE.
    Activate,
    /// Deed: an owner-authorized move.
    Transfer,
    /// Deed: an exit's owner-consent arm at seat 1.
    Release,
    /// Deed: an exit's maturity-consent arm at seat 1.
    Evict,
}

impl Entrypoint {
    pub const GAP: [Entrypoint; 3] = [Self::Split, Self::Merge, Self::Absorbed];
    pub const DEED: [Entrypoint; 4] = [Self::Activate, Self::Transfer, Self::Release, Self::Evict];

    /// The string the dispatch tag hashes.
    pub fn signature(self) -> &'static str {
        match self {
            Self::Split => "split(byte[32],byte[32],byte[],byte[])",
            Self::Merge => "merge()",
            Self::Absorbed => "absorbed()",
            Self::Activate => "activate(byte[],byte,byte[32])",
            Self::Transfer => "transfer(byte,byte[32],sig[],int)",
            Self::Release => "release(sig[],int)",
            Self::Evict => "evict()",
        }
    }

    pub fn tag(self) -> [u8; 4] {
        dispatch_tag(self.signature())
    }

    /// Arguments are read by position, so a padded sigscript is refused by its count.
    pub fn arity(self) -> usize {
        match self {
            Self::Merge | Self::Absorbed | Self::Evict => 0,
            Self::Release => 2,
            Self::Activate => 3,
            Self::Split | Self::Transfer => 4,
        }
    }

    pub fn from_tag(tag: &[u8], candidates: &[Entrypoint]) -> Option<Entrypoint> {
        candidates.iter().copied().find(|e| e.tag() == tag)
    }

    pub fn name(self) -> &'static str {
        self.signature().split('(').next().unwrap_or_default()
    }
}

/// The KCC-1 dispatch tag, `blake3(signature)[0:4]`.
pub fn dispatch_tag(signature: &str) -> [u8; 4] {
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&crate::blake3_32(signature.as_bytes())[..4]);
    tag
}

/// Push-only decoding. An `Err` on a registry spend is a decoder gap, never a transaction to ignore.
pub fn parse_pushes(script: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let take = |i: &mut usize, n: usize| -> Result<Vec<u8>, String> {
        let end = i.checked_add(n).filter(|&e| e <= script.len()).ok_or("truncated push")?;
        let v = script[*i..end].to_vec();
        *i = end;
        Ok(v)
    };
    while i < script.len() {
        let op = script[i];
        i += 1;
        match op {
            0x00 => out.push(vec![]),
            0x01..=0x4b => out.push(take(&mut i, op as usize)?),
            0x4c => {
                let n = take(&mut i, 1)?[0] as usize;
                out.push(take(&mut i, n)?);
            }
            0x4d => {
                let l = take(&mut i, 2)?;
                out.push(take(&mut i, u16::from_le_bytes([l[0], l[1]]) as usize)?);
            }
            0x4e => {
                let l = take(&mut i, 4)?;
                out.push(take(&mut i, u32::from_le_bytes([l[0], l[1], l[2], l[3]]) as usize)?);
            }
            0x4f => out.push(vec![0x81]),
            0x51..=0x60 => out.push(vec![op - 0x50]),
            other => {
                return Err(format!("non-push opcode {other:#04x} in a signature script"));
            }
        }
    }
    Ok(out)
}

/// A covenant sigscript is the arguments in ABI order, then the dispatch tag, then the redeem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedGapInput {
    pub state: GapState,
    pub entry: Entrypoint,
    pub args: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedDeedInput {
    pub state: DeedState,
    pub entry: Entrypoint,
    pub args: Vec<Vec<u8>>,
}

/// `fingerprint` is the versioned devfund SPK, which the deed template bakes in.
pub struct WatchTemplates {
    pub gap: Template,
    pub deed: Template,
    gap_hash: [u8; 32],
    deed_hash: [u8; 32],
    pub fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryOp {
    Split { gap: GapState, new_key: [u8; 32], claim: [u8; 32] },
    Activate { spent: DeedState, name: String, owner_type: OwnerType, owner: [u8; 32] },
    Transfer { spent: DeedState, new_owner_type: OwnerType, new_owner: [u8; 32] },
    Release { pred: GapState, dying: DeedState, succ: GapState },
    Evict { pred: GapState, dying: DeedState, succ: GapState },
}

impl WatchTemplates {
    pub fn new(gap: Template, deed: Template, fingerprint: Vec<u8>) -> Self {
        let gap_hash = gap.template_hash();
        let deed_hash = deed.template_hash();
        Self { gap, deed, gap_hash, deed_hash, fingerprint }
    }

    pub fn from_templates(t: &Templates) -> anyhow::Result<Self> {
        Ok(Self::new(t.gap.clone(), t.deed.clone(), t.params.devfund_spk_versioned()?))
    }

    pub fn gap_hash(&self) -> [u8; 32] {
        self.gap_hash
    }

    pub fn deed_hash(&self) -> [u8; 32] {
        self.deed_hash
    }

    /// A cheap prefilter. Every deed redeem and every `split` embed the fingerprint, and the template check
    /// discards spoofs.
    pub fn matches_fingerprint(&self, sig_script: &[u8]) -> bool {
        !self.fingerprint.is_empty() && sig_script.windows(self.fingerprint.len()).any(|w| w == self.fingerprint)
    }

    /// The state region of `redeem`, if it has the length and hash of `template`.
    fn state_region<'a>(template: &Template, expected_hash: &[u8; 32], redeem: &'a [u8]) -> Option<&'a [u8]> {
        if redeem.len() != template.bytecode.len() {
            return None;
        }
        let end = template.state_start.checked_add(template.state_len)?;
        let state = redeem.get(template.state_start..end)?;
        (silverscript_abi::template_hash(&redeem[..template.state_start], &redeem[end..]) == *expected_hash).then_some(state)
    }

    pub fn decode_gap_input(&self, sig_script: &[u8]) -> Result<DecodedGapInput, String> {
        let pushes = parse_pushes(sig_script)?;
        let (tag, redeem) = tag_and_redeem(&pushes)?;
        let region = Self::state_region(&self.gap, &self.gap_hash, redeem).ok_or("redeem does not match the deployed gap template")?;
        let entry = Entrypoint::from_tag(tag, &Entrypoint::GAP).ok_or("unknown dispatch tag for the gap template")?;
        Ok(DecodedGapInput { state: GapState::decode(region)?, entry, args: args_of(entry, &pushes)? })
    }

    pub fn decode_deed_input(&self, sig_script: &[u8]) -> Result<DecodedDeedInput, String> {
        let pushes = parse_pushes(sig_script)?;
        let (tag, redeem) = tag_and_redeem(&pushes)?;
        let region =
            Self::state_region(&self.deed, &self.deed_hash, redeem).ok_or("redeem does not match the deployed deed template")?;
        let entry = Entrypoint::from_tag(tag, &Entrypoint::DEED).ok_or("unknown dispatch tag for the deed template")?;
        Ok(DecodedDeedInput { state: DeedState::decode(region)?, entry, args: args_of(entry, &pushes)? })
    }

    /// `Ok(None)` is not a registry transaction. `Err` is a registry spend that does not decode, which a
    /// consensus-accepted transaction cannot produce, so callers must log it. The caller checks the covenant
    /// id on output 0 against the registry's.
    pub fn classify(&self, input_sig_scripts: &[Vec<u8>]) -> Result<Option<RegistryOp>, String> {
        let Some(first) = input_sig_scripts.first() else {
            return Ok(None);
        };
        if let Ok(gap) = self.decode_gap_input(first) {
            return self.classify_gap_leader(&gap, input_sig_scripts).map(Some);
        }
        let Ok(deed) = self.decode_deed_input(first) else {
            return Ok(None);
        };
        match deed.entry {
            Entrypoint::Activate => {
                let name_bytes = deed.args.first().ok_or("activate without a name argument")?;
                let name = String::from_utf8(name_bytes.clone()).map_err(|e| e.to_string())?;
                names::validate(&name)?;
                // Re-derive the binding, or a reader records a name the transaction never registered.
                if names::key_of(&name) != deed.state.key {
                    return Err(format!("activate reveals {name:?}, which does not hash to the spent deed's key"));
                }
                // `activate` mints key-owned schemes only.
                let ot = deed.args.get(1).and_then(|a| a.first().copied()).unwrap_or(0);
                let owner_type = OwnerType::from_byte(ot).ok_or(format!("unknown owner type {ot:#04x}"))?;
                if !owner_type.mintable() {
                    return Err(format!("activate cannot mint owner type {ot:#04x}"));
                }
                Ok(Some(RegistryOp::Activate { spent: deed.state, name, owner_type, owner: arg32(&deed.args, 2)? }))
            }
            Entrypoint::Transfer => {
                let ot = deed.args.first().and_then(|a| a.first().copied()).unwrap_or(0);
                let new_owner_type = OwnerType::from_byte(ot).ok_or(format!("unknown owner type {ot:#04x}"))?;
                Ok(Some(RegistryOp::Transfer { spent: deed.state, new_owner_type, new_owner: arg32(&deed.args, 1)? }))
            }
            other => Err(format!("a deed at input 0 cannot run {}", other.name())),
        }
    }

    fn classify_gap_leader(&self, gap: &DecodedGapInput, input_sig_scripts: &[Vec<u8>]) -> Result<RegistryOp, String> {
        match gap.entry {
            Entrypoint::Split => Ok(RegistryOp::Split { gap: gap.state, new_key: arg32(&gap.args, 0)?, claim: arg32(&gap.args, 1)? }),
            Entrypoint::Merge => {
                let deed = input_sig_scripts
                    .get(1)
                    .ok_or("merge without an input 1")
                    .and_then(|s| self.decode_deed_input(s).map_err(|_| "input 1 of a merge is no deed redeem"))?;
                let succ = input_sig_scripts
                    .get(2)
                    .ok_or("merge without an input 2")
                    .and_then(|s| self.decode_gap_input(s).map_err(|_| "input 2 of a merge is no gap redeem"))?;
                if succ.entry != Entrypoint::Absorbed {
                    return Err(format!("input 2 of a merge runs {} instead of absorbed", succ.entry.name()));
                }
                match deed.entry {
                    Entrypoint::Release => Ok(RegistryOp::Release { pred: gap.state, dying: deed.state, succ: succ.state }),
                    Entrypoint::Evict => Ok(RegistryOp::Evict { pred: gap.state, dying: deed.state, succ: succ.state }),
                    other => Err(format!("merge paired with {}", other.name())),
                }
            }
            other => Err(format!("a gap at input 0 cannot run {}", other.name())),
        }
    }

    /// A complete evict intent, built from the deployment manifest alone.
    pub fn build_evict(&self, pred: &GapUtxo, deed: &DeedUtxo, succ: &GapUtxo, params: &Params) -> Result<TxIntent, String> {
        if pred.state.hi != deed.state.key {
            return Err("predecessor gap is not adjacent to the deed".into());
        }
        if succ.state.lo != deed.state.key {
            return Err("successor gap is not adjacent to the deed".into());
        }
        if deed.state.status != Status::Pending {
            return Err("deed is not PENDING".into());
        }
        let gap_redeem =
            |state: &GapState| -> Result<Vec<u8>, String> { self.gap.materialize(&state.encode()).map_err(|e| e.to_string()) };
        evict_shape(
            &self.gap,
            &self.deed,
            params,
            pred,
            deed,
            succ,
            entry_sig_script(Entrypoint::Merge, &gap_redeem(&pred.state)?),
            entry_sig_script(Entrypoint::Evict, &self.deed.materialize(&deed.state.encode()).map_err(|e| e.to_string())?),
            entry_sig_script(Entrypoint::Absorbed, &gap_redeem(&succ.state)?),
        )
    }

    /// The seat of this deed's exit merge that already satisfies a `p2sh/v1` owner, or `None`. Anyone can
    /// release a deed owned by a flanking gap. A split or merge beside the deed changes the verdict, so
    /// never cache it.
    pub fn exposed_flank(&self, deed: &DeedState, pred: &GapState, succ: &GapState) -> Option<MergeSeat> {
        if deed.status != Status::Active || deed.owner_type != OwnerType::ScriptHash {
            return None;
        }
        let owned_by =
            |gap: &GapState| self.gap.materialize(&gap.encode()).map(|redeem| crate::blake2b(&redeem) == deed.owner).unwrap_or(false);
        if owned_by(pred) {
            Some(MergeSeat::Predecessor)
        } else if owned_by(succ) {
            Some(MergeSeat::Successor)
        } else {
            None
        }
    }

    /// The exit of a deed that [`WatchTemplates::exposed_flank`] exposes. The witness seat is derived here.
    pub fn build_stranger_release(
        &self,
        pred: &GapUtxo,
        deed: &DeedUtxo,
        succ: &GapUtxo,
        params: &Params,
    ) -> Result<TxIntent, String> {
        if pred.state.hi != deed.state.key {
            return Err("predecessor gap is not adjacent to the deed".into());
        }
        if succ.state.lo != deed.state.key {
            return Err("successor gap is not adjacent to the deed".into());
        }
        let witness = self
            .exposed_flank(&deed.state, &pred.state, &succ.state)
            .ok_or("this deed is not owned by either of its flanking gaps; only its owner can release it")?;
        let gap_redeem =
            |state: &GapState| -> Result<Vec<u8>, String> { self.gap.materialize(&state.encode()).map_err(|e| e.to_string()) };
        let deed_redeem = self.deed.materialize(&deed.state.encode()).map_err(|e| e.to_string())?;
        release_shape(
            &self.gap,
            &self.deed,
            params,
            pred,
            deed,
            succ,
            entry_sig_script(Entrypoint::Merge, &gap_redeem(&pred.state)?),
            release_copresence_sig_script(&deed_redeem, witness),
            entry_sig_script(Entrypoint::Absorbed, &gap_redeem(&succ.state)?),
        )
    }
}

fn tag_and_redeem(pushes: &[Vec<u8>]) -> Result<(&[u8], &[u8]), String> {
    if pushes.len() < 2 {
        return Err("sigscript has no dispatch tag + redeem".into());
    }
    Ok((&pushes[pushes.len() - 2], &pushes[pushes.len() - 1]))
}

/// Refused unless the argument count is [`Entrypoint::arity`], before any argument is read.
fn args_of(entry: Entrypoint, pushes: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let args = &pushes[..pushes.len() - 2];
    if args.len() != entry.arity() {
        return Err(format!("{} takes {} arguments, this sigscript pushes {}", entry.name(), entry.arity(), args.len()));
    }
    Ok(args.to_vec())
}

fn arg32(args: &[Vec<u8>], i: usize) -> Result<[u8; 32], String> {
    args.get(i).and_then(|a| <[u8; 32]>::try_from(a.as_slice()).ok()).ok_or_else(|| format!("argument {i} is not 32 bytes"))
}

/// Minimal data push, byte-identical to the encoding of rusty-kaspa's `ScriptBuilder`.
pub fn push_data(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 3);
    match data.len() {
        0 => out.push(0x00),
        n if n <= 75 => out.push(n as u8),
        n if n <= 0xff => out.extend([0x4c, n as u8]),
        n if n <= 0xffff => {
            out.push(0x4d);
            out.extend((n as u16).to_le_bytes());
        }
        n => {
            out.push(0x4e);
            out.extend((n as u32).to_le_bytes());
        }
    }
    out.extend_from_slice(data);
    out
}

/// The sigscript of an argument-less entrypoint, byte-identical to what silverscript encodes.
pub fn entry_sig_script(entry: Entrypoint, redeem: &[u8]) -> Vec<u8> {
    debug_assert!(entry.signature().ends_with("()"), "only argument-less entrypoints can be built from a tag alone");
    let mut out = Vec::with_capacity(redeem.len() + 8);
    out.extend(push_data(&entry.tag()));
    out.extend(push_data(redeem));
    out
}

/// The seat of an exit merge whose co-presence approves a `p2sh/v1` owner: one of the two flanking gaps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeSeat {
    Predecessor = 0,
    Successor = 2,
}

impl MergeSeat {
    /// The `witness` argument, which is also the input index it names.
    pub fn index(self) -> i64 {
        self as i64
    }

    fn opcode(self) -> u8 {
        match self {
            Self::Predecessor => 0x00, // OP_0: script number zero is the empty push
            Self::Successor => 0x52,   // OP_2
        }
    }
}

/// `release` for a `p2sh/v1` owner, which approves by co-presence, so nothing is signed.
pub(crate) fn release_copresence_sig_script(redeem: &[u8], witness: MergeSeat) -> Vec<u8> {
    let mut out = Vec::with_capacity(redeem.len() + 12);
    out.push(0x00); // sig[]: empty, and the prologue's stride check accepts a zero-length blob
    out.push(witness.opcode());
    out.extend(push_data(&Entrypoint::Release.tag()));
    out.extend(push_data(redeem));
    out
}

/// The evict exit: `merge` at seat 0, `evict` at seat 1 under the `t_evict` lock, `absorbed` at seat 2.
/// Output 1 pins DEPOSIT to the devfund. Adjacency is left to the covenant.
#[allow(clippy::too_many_arguments)]
pub fn evict_shape(
    gap_tpl: &Template,
    deed_tpl: &Template,
    params: &Params,
    pred: &GapUtxo,
    deed: &DeedUtxo,
    succ: &GapUtxo,
    merge_sig_script: Vec<u8>,
    evict_sig_script: Vec<u8>,
    absorbed_sig_script: Vec<u8>,
) -> Result<TxIntent, String> {
    let hex = faster_hex::hex_string;
    let gap_spk = |state: &GapState| -> Result<Vec<u8>, String> { gap_tpl.p2sh_spk(&state.encode()).map_err(|e| e.to_string()) };
    let widened = GapState { lo: pred.state.lo, hi: succ.state.hi };
    check_exit_values(pred, deed, succ, params)?;
    let released = sum(&[deed.value, pred.value, succ.value], "the exit merge's input value").map_err(|e| e.to_string())?;
    let spent = sum(&[params.gap_value, params.deposit], "the merged gap + the deposit").map_err(|e| e.to_string())?;
    Ok(TxIntent {
        kind: "evict".into(),
        inputs: vec![
            IntentInput {
                outpoint: pred.outpoint.clone(),
                value: pred.value,
                spk: hex(&gap_spk(&pred.state)?),
                sig_script: hex(&merge_sig_script),
                compute_budget: budgets::MERGE,
                sequence: 0,
                utxo_covenant_id: Some(pred.covenant_id.clone()),
                role: "predecessorGap".into(),
            },
            IntentInput {
                outpoint: deed.outpoint.clone(),
                value: deed.value,
                spk: hex(&deed_tpl.p2sh_spk(&deed.state.encode()).map_err(|e| e.to_string())?),
                sig_script: hex(&evict_sig_script),
                compute_budget: budgets::EVICT,
                sequence: params.t_evict,
                utxo_covenant_id: Some(deed.covenant_id.clone()),
                role: "deed".into(),
            },
            IntentInput {
                outpoint: succ.outpoint.clone(),
                value: succ.value,
                spk: hex(&gap_spk(&succ.state)?),
                sig_script: hex(&absorbed_sig_script),
                compute_budget: budgets::ABSORBED,
                sequence: 0,
                utxo_covenant_id: Some(succ.covenant_id.clone()),
                role: "successorGap".into(),
            },
        ],
        outputs: vec![
            IntentOutput {
                value: params.gap_value,
                spk: hex(&gap_spk(&widened)?),
                covenant: Some(CovenantBindingIntent { covenant_id: pred.covenant_id.clone(), authorizing_input: 0 }),
                role: "mergedGap".into(),
            },
            // Without this output a squatter evicts their own deed and recovers the whole posting.
            IntentOutput { value: params.deposit, spk: params.devfund_spk.clone(), covenant: None, role: "depositToDevfund".into() },
        ],
        required_funding: 0,
        released: released.saturating_sub(spent),
        pending_state: None,
        pending_output_index: None,
    })
}

fn check_exit_values(pred: &GapUtxo, deed: &DeedUtxo, succ: &GapUtxo, params: &Params) -> Result<(), String> {
    check_value("the predecessor gap", "GAP_VALUE", pred.value, params.gap_value)?;
    check_deed_value(deed, params)?;
    check_value("the successor gap", "GAP_VALUE", succ.value, params.gap_value)
}

/// [`evict_shape`] with `release` at seat 1, no deposit output and no lock.
#[allow(clippy::too_many_arguments)]
pub fn release_shape(
    gap_tpl: &Template,
    deed_tpl: &Template,
    params: &Params,
    pred: &GapUtxo,
    deed: &DeedUtxo,
    succ: &GapUtxo,
    merge_sig_script: Vec<u8>,
    release_sig_script: Vec<u8>,
    absorbed_sig_script: Vec<u8>,
) -> Result<TxIntent, String> {
    let hex = faster_hex::hex_string;
    let gap_spk = |state: &GapState| -> Result<Vec<u8>, String> { gap_tpl.p2sh_spk(&state.encode()).map_err(|e| e.to_string()) };
    let widened = GapState { lo: pred.state.lo, hi: succ.state.hi };
    check_exit_values(pred, deed, succ, params)?;
    let released = sum(&[deed.value, pred.value, succ.value], "the released exit value").map_err(|e| e.to_string())?;
    Ok(TxIntent {
        kind: "release".into(),
        inputs: vec![
            IntentInput {
                outpoint: pred.outpoint.clone(),
                value: pred.value,
                spk: hex(&gap_spk(&pred.state)?),
                sig_script: hex(&merge_sig_script),
                compute_budget: budgets::MERGE,
                sequence: 0,
                utxo_covenant_id: Some(pred.covenant_id.clone()),
                role: "predecessorGap".into(),
            },
            IntentInput {
                outpoint: deed.outpoint.clone(),
                value: deed.value,
                spk: hex(&deed_tpl.p2sh_spk(&deed.state.encode()).map_err(|e| e.to_string())?),
                sig_script: hex(&release_sig_script),
                compute_budget: budgets::RELEASE,
                sequence: 0,
                utxo_covenant_id: Some(deed.covenant_id.clone()),
                role: "deed".into(),
            },
            IntentInput {
                outpoint: succ.outpoint.clone(),
                value: succ.value,
                spk: hex(&gap_spk(&succ.state)?),
                sig_script: hex(&absorbed_sig_script),
                compute_budget: budgets::ABSORBED,
                sequence: 0,
                utxo_covenant_id: Some(succ.covenant_id.clone()),
                role: "successorGap".into(),
            },
        ],
        outputs: vec![IntentOutput {
            value: params.gap_value,
            spk: hex(&gap_spk(&widened)?),
            covenant: Some(CovenantBindingIntent { covenant_id: pred.covenant_id.clone(), authorizing_input: 0 }),
            role: "mergedGap".into(),
        }],
        required_funding: 0,
        released: released.saturating_sub(params.gap_value),
        pending_state: None,
        pending_output_index: None,
    })
}

pub const GENESIS_VERSION: u32 = 6;

/// The deployment manifest. The template hashes cover the bytecode alone, so a client that trusts a
/// manifest trusts its `params` with it. `params` keeps snake_case fields inside the camelCase document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisFile {
    /// Checked by [`Templates::from_manifest`].
    #[serde(default)]
    pub version: u32,
    pub network: String,
    pub registry_covenant_id: String,
    /// Checked against the two hashes below, which protect only a manifest the client trusts.
    pub gap_abi: SilAbiArtifact,
    pub deed_abi: SilAbiArtifact,
    pub gap_template_hash: String,
    pub deed_template_hash: String,
    /// Not covered by the template hashes. The covenant charges the registration fee it is
    /// given, so a forged tier overpays the devfund.
    pub params: Params,
    /// Checked by [`GenesisFile::verify_genesis_binding`].
    #[serde(default)]
    pub genesis_binding: Option<GenesisBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisBinding {
    /// The deployer input at `authorizing_input = 0`.
    pub authorizing_outpoint: ManifestOutpoint,
    pub output_index: u32,
    /// The group the covenant id commits to: the genesis gap alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_outputs: Vec<AuthorizedOutput>,
}

/// An outpoint in camelCase, where [`crate::intents::Outpoint`] is snake_case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestOutpoint {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    pub index: u32,
}

impl From<crate::intents::Outpoint> for ManifestOutpoint {
    fn from(o: crate::intents::Outpoint) -> Self {
        Self { transaction_id: o.transaction_id, index: o.index }
    }
}

impl ManifestOutpoint {
    pub fn outpoint(&self) -> crate::intents::Outpoint {
        crate::intents::Outpoint { transaction_id: self.transaction_id.clone(), index: self.index }
    }
}

/// One output of the genesis binding group, plus the redeem script and state behind its P2SH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedOutput {
    pub index: u32,
    pub value: u64,
    pub script_version: u16,
    /// Hex: `aa20 ‖ blake2b-256(redeemScript) ‖ 87`.
    pub script_public_key: String,
    /// Hex: the gap template with `state` in its state span.
    pub redeem_script: String,
    /// Hex: the keyspace floor and ceiling as two 32-byte pushes.
    pub state: String,
}

impl GenesisBinding {
    /// The binding of a group that holds only the genesis gap, derived from the templates.
    pub fn minted_over_genesis_gap(templates: &Templates, authorizing_outpoint: crate::intents::Outpoint) -> Result<Self, String> {
        let state = templates.genesis_gap().encode();
        let redeem = templates.gap.materialize(&state).map_err(|e| e.to_string())?;
        let spk = templates.gap.p2sh_spk(&state).map_err(|e| e.to_string())?;
        Ok(Self {
            authorizing_outpoint: authorizing_outpoint.into(),
            output_index: 0,
            authorized_outputs: vec![AuthorizedOutput {
                index: 0,
                value: templates.params.gap_value,
                script_version: 0,
                script_public_key: faster_hex::hex_string(&spk),
                redeem_script: faster_hex::hex_string(&redeem),
                state: faster_hex::hex_string(&state),
            }],
        })
    }
}

impl GenesisFile {
    /// Proves the genesis covenant id was minted over the genesis gap alone. A smuggled ungoverned output
    /// can forge an exit's seat 2 and merge a gap over live names.
    pub fn verify_genesis_binding(&self) -> Result<(), String> {
        let binding = self.genesis_binding.as_ref().ok_or_else(|| {
            "manifest records no genesisBinding, so the genesis covenant id cannot be recomputed and \
             the lineage's base case is unverified"
                .to_string()
        })?;
        let templates = Templates::from_manifest(self).map_err(|e| e.to_string())?;
        self.devfund_spk_versioned()?;
        let expected = GenesisBinding::minted_over_genesis_gap(&templates, binding.authorizing_outpoint.outpoint())?;
        // Another recorded index makes the published preimage disagree with the recomputed id.
        if binding.output_index != expected.output_index {
            return Err(format!(
                "genesisBinding.outputIndex is {}, but the genesis gap is output {} of its transaction: the recorded \
                 index and the spelled-out group disagree, so the published preimage would not reproduce the id",
                binding.output_index, expected.output_index
            ));
        }
        if binding.authorized_outputs.is_empty() {
            return Err("genesisBinding records no authorizedOutputs".to_string());
        }
        // The spelled-out group is a copy of derived bytes, so any drift is refused.
        if binding.authorized_outputs != expected.authorized_outputs {
            return Err("genesisBinding.authorizedOutputs does not match the group derived from the artifacts and params: the \
                 spelled-out preimage has drifted from the bytecode it claims to expand, so the manifest is refused"
                .to_string());
        }
        let spk = templates.gap.p2sh_spk(&templates.genesis_gap().encode()).map_err(|e| e.to_string())?;
        let recomputed = crate::intents::genesis_covenant_id(
            &binding.authorizing_outpoint.outpoint(),
            binding.output_index,
            self.params.gap_value,
            &spk,
        )
        .map_err(|e| e.to_string())?;
        if recomputed != self.registry_covenant_id {
            return Err(format!(
                "genesis binding does not reproduce the registry covenant id: recomputing over the \
                 lone genesis gap gives {recomputed}, the manifest declares {}. The binding group \
                 held something other than exactly that one output, so an ungoverned UTXO can carry \
                 this lineage's covenant id and forge seat 2 of an exit",
                self.registry_covenant_id
            ));
        }
        Ok(())
    }

    /// The detection fingerprint, `0x0000 ‖ params.devfund_spk`, as SPK introspection returns it.
    pub fn devfund_spk_versioned(&self) -> Result<Vec<u8>, String> {
        let fingerprint = self.params.devfund_spk_versioned().map_err(|e| e.to_string())?;
        // A versioned `devfund_spk` yields a fingerprint that matches nothing.
        if fingerprint.len() <= 2 {
            return Err("params.devfund_spk is empty, so the devfund fingerprint matches nothing".into());
        }
        if fingerprint.starts_with(&[0, 0, 0, 0]) {
            return Err("params.devfund_spk already carries a 0x0000 version prefix, but it must be the bare \
                 script, or the derived fingerprint matches nothing"
                .into());
        }
        Ok(fingerprint)
    }

    pub fn watch_templates(&self) -> Result<WatchTemplates, String> {
        let t = Templates::from_manifest(self).map_err(|e| e.to_string())?;
        Ok(WatchTemplates::new(t.gap.clone(), t.deed.clone(), self.devfund_spk_versioned()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use crate::state::Status;

    fn watcher() -> (Templates, WatchTemplates) {
        (fixture::templates(), fixture::genesis().watch_templates().unwrap())
    }

    /// Arguments are read positionally, so a padded sigscript must be refused by its arity.
    #[test]
    fn every_entrypoint_declares_the_argument_count_the_compiler_pushes() {
        let (t, w) = watcher();
        let key = names::key_of("kaspa");
        let claim = names::claim_of("kaspa", OwnerType::Pubkey, &[5u8; 32]);
        let pending = DeedState::pending(key, claim);
        let active = DeedState::active(key, OwnerType::Pubkey, [5u8; 32], names::padded_name("kaspa"));
        let gap = t.genesis_gap();

        let scripts: Vec<(Entrypoint, Vec<u8>)> = vec![
            (Entrypoint::Split, t.split_sig_script(&gap, &key, &claim).unwrap()),
            (Entrypoint::Merge, t.merge_sig_script(&gap).unwrap()),
            (Entrypoint::Absorbed, t.absorbed_sig_script(&gap).unwrap()),
            (Entrypoint::Activate, t.activate_sig_script(&pending, "kaspa", OwnerType::Pubkey as u8, &[5u8; 32]).unwrap()),
            (Entrypoint::Transfer, t.transfer_sig_script(&active, 0x03, &[6u8; 32], 0, Some(&[0u8; 65])).unwrap()),
            (Entrypoint::Release, t.release_sig_script(&active, 0, Some(&[0u8; 65])).unwrap()),
            (Entrypoint::Evict, t.evict_sig_script(&pending).unwrap()),
        ];
        for (entry, script) in &scripts {
            let pushes = parse_pushes(script).unwrap();
            assert_eq!(pushes.len() - 2, entry.arity(), "{} pushes a different number of arguments", entry.name());
        }

        for (entry, script) in &scripts {
            let mut padded = push_data(&[0xab; 32]);
            padded.extend_from_slice(script);
            let why = match entry {
                Entrypoint::Split | Entrypoint::Merge | Entrypoint::Absorbed => w.decode_gap_input(&padded).unwrap_err(),
                _ => w.decode_deed_input(&padded).unwrap_err(),
            };
            assert!(why.contains("arguments"), "{} must refuse a padded sigscript by arity: {why}", entry.name());
        }

        let mut padded = push_data(&[0xab; 32]);
        padded.extend_from_slice(&t.split_sig_script(&gap, &key, &claim).unwrap());
        assert!(w.classify(&[padded]).unwrap().is_none(), "a padded gap redeem is not a registry transaction we can read");
    }

    /// The decoder re-derives the name's binding to the spent key instead of believing it.
    #[test]
    fn activate_only_decodes_a_name_that_hashes_to_the_spent_key() {
        let (t, w) = watcher();
        let owner = [5u8; 32];
        let pending = DeedState::pending(names::key_of("kaspa"), names::claim_of("kaspa", OwnerType::Pubkey, &owner));
        let honest = vec![t.activate_sig_script(&pending, "kaspa", OwnerType::Pubkey as u8, &owner).unwrap()];
        assert!(matches!(w.classify(&honest).unwrap(), Some(RegistryOp::Activate { ref name, .. }) if name == "kaspa"));

        let forged = vec![t.activate_sig_script(&pending, "hijack", OwnerType::Pubkey as u8, &owner).unwrap()];
        let why = w.classify(&forged).unwrap_err();
        assert!(why.contains("does not hash to the spent deed's key"), "{why}");
    }

    #[test]
    fn every_operation_classifies_from_its_sigscripts() {
        let (t, w) = watcher();
        let name = "kaspa";
        let owner = [5u8; 32];
        let key = names::key_of(name);
        let claim = names::claim_of(name, OwnerType::Pubkey, &owner);
        let pending = DeedState::pending(key, claim);
        let active = DeedState::active(key, OwnerType::Pubkey, owner, names::padded_name(name));
        let pred = GapState { lo: crate::registry::KEY_MIN, hi: key };
        let succ = GapState { lo: key, hi: crate::registry::KEY_MAX };

        let split = vec![t.split_sig_script(&t.genesis_gap(), &key, &claim).unwrap()];
        assert_eq!(
            w.classify(&split).unwrap(),
            Some(RegistryOp::Split { gap: t.genesis_gap(), new_key: key, claim }),
            "a split republishes the consumed interval and the newborn's key and claim"
        );

        let activate = vec![t.activate_sig_script(&pending, name, OwnerType::Pubkey as u8, &owner).unwrap()];
        assert_eq!(
            w.classify(&activate).unwrap(),
            Some(RegistryOp::Activate { spent: pending, name: name.to_string(), owner_type: OwnerType::Pubkey, owner }),
            "activate is the reveal: the name arrives in cleartext"
        );

        let transfer = vec![t.transfer_sig_script(&active, 0x03, &[6u8; 32], 0, Some(&[0u8; 65])).unwrap()];
        assert_eq!(
            w.classify(&transfer).unwrap(),
            Some(RegistryOp::Transfer { spent: active, new_owner_type: OwnerType::ScriptHash, new_owner: [6u8; 32] }),
            "the spent ACTIVE deed names itself, so ownership events stay self-describing"
        );

        let exit = |deed_script: Vec<u8>| vec![t.merge_sig_script(&pred).unwrap(), deed_script, t.absorbed_sig_script(&succ).unwrap()];
        assert_eq!(
            w.classify(&exit(t.release_sig_script(&active, 0, Some(&[0u8; 65])).unwrap())).unwrap(),
            Some(RegistryOp::Release { pred, dying: active, succ })
        );
        assert_eq!(
            w.classify(&exit(t.evict_sig_script(&pending).unwrap())).unwrap(),
            Some(RegistryOp::Evict { pred, dying: pending, succ })
        );

        assert_eq!(w.classify(&[vec![0x51]]).unwrap(), None);
        assert_eq!(w.classify(&[]).unwrap(), None);
        // A delegator arm at seat 0 is a shape no valid transaction has: loudly wrong, not None.
        assert!(w.classify(&[t.absorbed_sig_script(&succ).unwrap()]).is_err());
    }

    /// `build_evict` must equal `evict_intent` byte for byte.
    #[test]
    fn the_manifest_built_evict_matches_the_builders() {
        let (t, w) = watcher();
        let (pred, deed, succ) = fixture::pending(&t, "kaspa");

        let ours = w.build_evict(&pred, &deed, &succ, &t.params).expect("manifest-built evict");
        let theirs = crate::intents::evict_intent(&t, &pred, &deed, &succ).expect("builder-built evict");
        assert_eq!(ours, theirs, "the manifest-built evict must equal the builder's, byte for byte");
        assert_eq!(ours.released, t.params.bond + t.params.gap_value, "the bounty is what the devfund output leaves");

        let detached = GapUtxo { state: GapState { lo: [0x11u8; 32], hi: [0x22u8; 32] }, ..succ.clone() };
        assert!(w.build_evict(&pred, &deed, &detached, &t.params).is_err(), "a successor that does not start at the key");
        let far = GapUtxo { state: GapState { lo: [0x11u8; 32], hi: [0x22u8; 32] }, ..pred.clone() };
        assert!(w.build_evict(&far, &deed, &succ, &t.params).is_err(), "a predecessor that does not end at the key");
    }

    /// The witness comes from which flank owns the deed, never from a caller.
    #[test]
    fn the_manifest_built_stranger_release_matches_the_builders() {
        let (t, w) = watcher();
        let (pred, active, succ) = fixture::active(&t, "kaspa");
        let key = active.state.key;
        let owned_by = |g: &GapUtxo| crate::blake2b(&t.gap.materialize(&g.state.encode()).unwrap());
        let deed_at =
            |owner| DeedUtxo { state: DeedState { owner_type: OwnerType::ScriptHash, owner, ..active.state }, ..active.clone() };

        let deed = deed_at(owned_by(&pred));
        assert_eq!(w.exposed_flank(&deed.state, &pred.state, &succ.state), Some(MergeSeat::Predecessor));
        let ours = w.build_stranger_release(&pred, &deed, &succ, &t.params).expect("manifest-built release");
        let theirs = crate::intents::release_intent(&t, &pred, &deed, &succ, MergeSeat::Predecessor.index()).expect("builder-built");
        assert_eq!(ours, theirs, "the manifest-built release must equal the builder's, byte for byte");
        assert_eq!(ours.released, t.params.bond + t.params.gap_value, "the same bounty an eviction pays");

        let by_succ = deed_at(owned_by(&succ));
        assert_eq!(w.exposed_flank(&by_succ.state, &pred.state, &succ.state), Some(MergeSeat::Successor));
        assert_eq!(
            w.build_stranger_release(&pred, &by_succ, &succ, &t.params).expect("seat 2"),
            crate::intents::release_intent(&t, &pred, &by_succ, &succ, MergeSeat::Successor.index()).expect("builder-built"),
            "the witness index is the only thing that differs between the two flanks"
        );

        let stranger = deed_at([0x99u8; 32]);
        assert_eq!(w.exposed_flank(&stranger.state, &pred.state, &succ.state), None, "an ordinary script owner is not a flank");
        assert!(w.build_stranger_release(&pred, &stranger, &succ, &t.params).is_err());
        let schnorr = DeedUtxo { state: DeedState { owner_type: OwnerType::Pubkey, ..deed.state }, ..deed.clone() };
        assert_eq!(w.exposed_flank(&schnorr.state, &pred.state, &succ.state), None, "only the p2sh scheme approves by co-presence");
        // Only the status check can refuse a PENDING state that carries a flank's hash.
        let masquerade = DeedState { status: Status::Pending, ..deed.state };
        assert_eq!(w.exposed_flank(&masquerade, &pred.state, &succ.state), None, "a PENDING deed exits by evict, not release");
        let detached = GapUtxo { state: GapState { lo: [0x11u8; 32], hi: [0x22u8; 32] }, ..succ.clone() };
        assert!(w.build_stranger_release(&pred, &deed, &detached, &t.params).is_err(), "adjacency is guarded before the fee");
        // Owned by a non-adjacent predecessor: only the adjacency guard refuses it.
        let far = GapUtxo { state: GapState { lo: [0x11u8; 32], hi: [0x22u8; 32] }, ..pred.clone() };
        let owned_by_far = deed_at(owned_by(&far));
        assert_eq!(w.exposed_flank(&owned_by_far.state, &far.state, &succ.state), Some(MergeSeat::Predecessor), "owned by it");
        assert!(
            w.build_stranger_release(&far, &owned_by_far, &succ, &t.params).is_err(),
            "a predecessor that does not end at the deed's key is refused before the fee"
        );

        let narrowed = GapState { lo: [0x44u8; 32], hi: key };
        assert_eq!(w.exposed_flank(&deed.state, &narrowed, &succ.state), None, "a reshaped flank is a different script");
    }

    /// The base case: a covenant id minted over anything but the lone genesis gap is refused.
    #[test]
    fn the_genesis_binding_is_recomputed_over_the_lone_genesis_gap() {
        let t = fixture::templates();
        let outpoint = fixture::outpoint(0x7a);
        let spk = t.gap.p2sh_spk(&t.genesis_gap().encode()).unwrap();
        let mut g = fixture::genesis();
        assert!(g.verify_genesis_binding().is_err(), "an unbound manifest is unverified");
        g.genesis_binding = Some(GenesisBinding::minted_over_genesis_gap(&t, outpoint.clone()).unwrap());
        g.registry_covenant_id = crate::intents::genesis_covenant_id(&outpoint, 0, t.params.gap_value, &spk).unwrap();
        g.verify_genesis_binding().unwrap();

        let smuggled = crate::intents::genesis_covenant_id(&outpoint, 1, t.params.gap_value, &spk).unwrap();
        let why = GenesisFile { registry_covenant_id: smuggled, ..g.clone() }.verify_genesis_binding().unwrap_err();
        assert!(why.contains("ungoverned"), "{why}");
        let mut drifted = g.clone();
        drifted.genesis_binding.as_mut().unwrap().authorized_outputs[0].value += 1;
        assert!(drifted.verify_genesis_binding().is_err());
    }
}
