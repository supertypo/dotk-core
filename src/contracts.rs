use anyhow::{Context, Result, anyhow, ensure};
use silverscript_abi::{
    ArtifactValue, CompiledContractArtifact, SilAbiArtifact, TypeArtifact, encode_contract_entry_sig_script, template_hash,
};

use crate::params::Params;
use crate::registry::{KEY_MAX, KEY_MIN};
use crate::state::{DEED_STATE_LEN, DeedState, GAP_STATE_LEN, GapState};
use crate::watch::{Entrypoint, GENESIS_VERSION};

/// A compiled, param-baked contract template: fixed prefix/suffix around a splicable state region.
#[derive(Debug, Clone)]
pub struct Template {
    pub bytecode: Vec<u8>,
    pub state_start: usize,
    pub state_len: usize,
}

impl Template {
    /// `None` on overflow, because the offsets come from an untrusted deployment manifest.
    fn state_end(&self) -> Option<usize> {
        self.state_start.checked_add(self.state_len)
    }

    /// Empty when the offsets do not fit, so a malformed template hashes to nothing on chain.
    pub fn prefix(&self) -> &[u8] {
        self.bytecode.get(..self.state_start).unwrap_or(&[])
    }

    pub fn suffix(&self) -> &[u8] {
        self.state_end().and_then(|end| self.bytecode.get(end..)).unwrap_or(&[])
    }

    /// The hash the covenant builtins `readInputStateWithTemplate` and `validateOutputStateWithTemplate` compare against.
    pub fn template_hash(&self) -> [u8; 32] {
        template_hash(self.prefix(), self.suffix())
    }

    /// Offsets from a manifest are checked, so a hostile one is an error rather than a panic.
    pub(crate) fn from_artifact(a: &CompiledContractArtifact) -> Result<Self> {
        let end = a
            .state_span
            .offset
            .checked_add(a.state_span.len)
            .ok_or_else(|| anyhow!("state span offset + length overflows, so the artifact declares no real state region"))?;
        if end > a.bytecode.len() {
            return Err(anyhow!("state span lies outside the {} bytes of template bytecode", a.bytecode.len()));
        }
        Ok(Self { bytecode: a.bytecode.clone(), state_start: a.state_span.offset, state_len: a.state_span.len })
    }

    pub fn materialize(&self, state: &[u8]) -> Result<Vec<u8>> {
        if state.len() != self.state_len {
            return Err(anyhow!("state region must be {} bytes, got {}", self.state_len, state.len()));
        }
        let end = self.state_end().ok_or_else(|| anyhow!("state span overflows"))?;
        let mut script = self.bytecode.clone();
        script.get_mut(self.state_start..end).ok_or_else(|| anyhow!("state span lies outside the bytecode"))?.copy_from_slice(state);
        Ok(script)
    }

    pub fn p2sh_spk(&self, state: &[u8]) -> Result<Vec<u8>> {
        let redeem = self.materialize(state)?;
        Ok(kaspa_txscript::pay_to_script_hash_script(&redeem).script().to_vec())
    }
}

/// Both covenant templates and their ABIs.
pub struct Templates {
    pub params: Params,
    pub deed: Template,
    pub gap: Template,
    deed_abi: SilAbiArtifact,
    gap_abi: SilAbiArtifact,
}

/// The compiler emits one contract per artifact, so any other count is a malformed artifact.
fn sole_contract(abi: &SilAbiArtifact) -> Result<&str> {
    let mut names = abi.contracts.keys();
    match (names.next(), names.next()) {
        (Some(name), None) => Ok(name.as_str()),
        _ => Err(anyhow!("abi artifact must describe exactly one contract, got {}", abi.contracts.len())),
    }
}

/// The template of `abi`, refused unless it reproduces `expected_hash`.
fn pinned_template(abi: &SilAbiArtifact, expected_hash: &str, state_len: usize, what: &str) -> Result<Template> {
    let name = sole_contract(abi)?;
    let contract = abi.contracts.get(name).expect("sole_contract returned a key of this map");
    let template = Template::from_artifact(&contract.compiled).with_context(|| format!("{what} template"))?;
    if template.state_len != state_len {
        return Err(anyhow!("{what} template state layout is {} bytes, expected {state_len}", template.state_len));
    }
    let got = faster_hex::hex_string(&template.template_hash());
    if got != expected_hash {
        return Err(anyhow!("{what} template bytecode hashes to {got}, but the deployment pins {expected_hash}"));
    }
    Ok(template)
}

/// Only the leaf types the covenants use reach the ABI codec, whose struct walk is exponential on a
/// branching graph. The dispatch tags are checked too.
fn check_abi_shape(abi: &SilAbiArtifact, entries: &[Entrypoint], what: &str) -> Result<()> {
    fn leaf(ty: &TypeArtifact) -> bool {
        match ty {
            TypeArtifact::Int | TypeArtifact::Bool | TypeArtifact::Byte | TypeArtifact::Bytes | TypeArtifact::Sig => true,
            TypeArtifact::FixedBytes { .. } => true,
            TypeArtifact::DynamicArray { item } => matches!(**item, TypeArtifact::Sig),
            _ => false,
        }
    }
    let contract = abi.contracts.get(sole_contract(abi)?).expect("sole_contract returned a key of this map");
    for field in &contract.runtime_state.fields {
        ensure!(leaf(&field.ty), "{what} abi: state field {} has a type this build does not encode", field.name);
    }
    ensure!(
        contract.entries.len() == entries.len(),
        "{what} abi publishes {} entrypoints, expected {}",
        contract.entries.len(),
        entries.len()
    );
    for entry in entries {
        let published = contract.entries.get(entry.name()).ok_or_else(|| anyhow!("{what} abi has no {}", entry.name()))?;
        ensure!(
            *published.dispatch_tag.as_bytes() == entry.tag(),
            "{what} abi: {} has a dispatch tag this build does not know",
            entry.name()
        );
        for param in &published.params {
            ensure!(leaf(&param.ty), "{what} abi: {} takes a type this build does not encode", entry.name());
        }
    }
    Ok(())
}

/// Empty for the co-presence schemes. A zero placeholder before signing keeps the mass exact.
fn av_sig_array(sig: Option<&[u8]>) -> ArtifactValue {
    ArtifactValue::Array(sig.map(|s| vec![ArtifactValue::Bytes(s.to_vec())]).unwrap_or_default())
}

fn av_bytes32(v: &[u8; 32]) -> ArtifactValue {
    ArtifactValue::Bytes(v.to_vec())
}

impl Templates {
    /// Checks the version, the params, each ABI's shape and consistency, and each template against its
    /// pinned hash. The pins protect only a manifest the client trusts.
    pub fn from_manifest(g: &crate::watch::GenesisFile) -> Result<Self> {
        ensure!(g.version == GENESIS_VERSION, "manifest version {} is not the {GENESIS_VERSION} this build reads", g.version);
        g.params.validate().map_err(|e| anyhow!("params: {e}"))?;
        check_abi_shape(&g.gap_abi, &Entrypoint::GAP, "gap")?;
        check_abi_shape(&g.deed_abi, &Entrypoint::DEED, "deed")?;
        g.gap_abi.check_consistency().map_err(|e| anyhow!("gap abi: {e}"))?;
        g.deed_abi.check_consistency().map_err(|e| anyhow!("deed abi: {e}"))?;
        let deed = pinned_template(&g.deed_abi, &g.deed_template_hash, DEED_STATE_LEN, "deed")?;
        let gap = pinned_template(&g.gap_abi, &g.gap_template_hash, GAP_STATE_LEN, "gap")?;
        Ok(Self { params: g.params.clone(), deed, gap, deed_abi: g.deed_abi.clone(), gap_abi: g.gap_abi.clone() })
    }

    /// Whether these templates hash to the given pins, which cover the bytecode and not `params`. Only a
    /// pin held out of band stops a hostile publisher.
    pub fn matches_manifest(&self, gap_hash_hex: &str, deed_hash_hex: &str) -> bool {
        faster_hex::hex_string(&self.gap.template_hash()) == gap_hash_hex
            && faster_hex::hex_string(&self.deed.template_hash()) == deed_hash_hex
    }

    pub fn gap_abi(&self) -> &SilAbiArtifact {
        &self.gap_abi
    }

    pub fn deed_abi(&self) -> &SilAbiArtifact {
        &self.deed_abi
    }

    /// The whole keyspace, which the registry is again when the last name is released.
    pub fn genesis_gap(&self) -> GapState {
        GapState { lo: KEY_MIN, hi: KEY_MAX }
    }

    fn sig_script(&self, abi: &SilAbiArtifact, func: &str, args: Vec<ArtifactValue>, redeem: Vec<u8>) -> Result<Vec<u8>> {
        let mut script = encode_contract_entry_sig_script(abi, sole_contract(abi)?, func, &args)
            .map_err(|e| anyhow!("building sigscript for {func}: {e}"))?;
        let mut builder = kaspa_txscript::script_builder::ScriptBuilder::with_flags(kaspa_txscript::EngineFlags {
            covenants_enabled: true,
            ..Default::default()
        });
        builder.add_data(&redeem).map_err(|e| anyhow!("pushing redeem script: {e}"))?;
        script.extend(builder.drain());
        Ok(script)
    }

    /// `split` takes the deed template's parts as witness arguments, and the gap pins them by hash.
    pub fn split_sig_script(&self, current: &GapState, new_key: &[u8; 32], claim: &[u8; 32]) -> Result<Vec<u8>> {
        let redeem = self.gap.materialize(&current.encode())?;
        let args = vec![
            av_bytes32(new_key),
            av_bytes32(claim),
            ArtifactValue::Bytes(self.deed.prefix().to_vec()),
            ArtifactValue::Bytes(self.deed.suffix().to_vec()),
        ];
        self.sig_script(&self.gap_abi, "split", args, redeem)
    }

    /// `merge`, the leader of an exit at seat 0.
    pub fn merge_sig_script(&self, predecessor: &GapState) -> Result<Vec<u8>> {
        let redeem = self.gap.materialize(&predecessor.encode())?;
        self.sig_script(&self.gap_abi, "merge", vec![], redeem)
    }

    /// `absorbed`, the successor gap at seat 2 of an exit.
    pub fn absorbed_sig_script(&self, successor: &GapState) -> Result<Vec<u8>> {
        let redeem = self.gap.materialize(&successor.encode())?;
        self.sig_script(&self.gap_abi, "absorbed", vec![], redeem)
    }

    pub fn activate_sig_script(&self, current: &DeedState, name: &str, owner_type: u8, owner: &[u8; 32]) -> Result<Vec<u8>> {
        let redeem = self.deed.materialize(&current.encode())?;
        self.sig_script(
            &self.deed_abi,
            "activate",
            vec![ArtifactValue::Bytes(name.as_bytes().to_vec()), ArtifactValue::Byte(owner_type), av_bytes32(owner)],
            redeem,
        )
    }

    /// `transfer` has a single lineage input, so it needs only the deed's own state.
    pub fn transfer_sig_script(
        &self,
        current: &DeedState,
        new_owner_type: u8,
        new_owner: &[u8; 32],
        witness: i64,
        sig: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let redeem = self.deed.materialize(&current.encode())?;
        self.sig_script(
            &self.deed_abi,
            "transfer",
            vec![ArtifactValue::Byte(new_owner_type), av_bytes32(new_owner), av_sig_array(sig), ArtifactValue::Int(witness)],
            redeem,
        )
    }

    /// `release`, the owner-consent arm of an exit, at seat 1.
    pub fn release_sig_script(&self, current: &DeedState, witness: i64, sig: Option<&[u8]>) -> Result<Vec<u8>> {
        let redeem = self.deed.materialize(&current.encode())?;
        self.sig_script(&self.deed_abi, "release", vec![av_sig_array(sig), ArtifactValue::Int(witness)], redeem)
    }

    /// `evict`, the maturity-consent arm at seat 1, under the `t_evict` age the builder encodes in `sequence`.
    pub fn evict_sig_script(&self, current: &DeedState) -> Result<Vec<u8>> {
        let redeem = self.deed.materialize(&current.encode())?;
        self.sig_script(&self.deed_abi, "evict", vec![], redeem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;

    #[test]
    fn a_manifest_whose_bytecode_misses_its_pin_is_refused() {
        assert!(Templates::from_manifest(&fixture::genesis()).is_ok());
        let mut g = fixture::genesis();
        g.deed_template_hash = "00".repeat(32);
        assert!(Templates::from_manifest(&g).err().unwrap().to_string().contains("pins"));
        let mut g = fixture::genesis();
        let contract = g.gap_abi.contracts.values_mut().next().unwrap();
        let last = contract.compiled.bytecode.len() - 1;
        contract.compiled.bytecode[last] ^= 1;
        assert!(Templates::from_manifest(&g).is_err(), "a changed byte hashes to nothing the manifest pins");
    }

    /// Offsets arrive from a manifest, so a hostile one is an error, never a panic.
    #[test]
    fn hostile_state_offsets_are_refused_without_a_panic() {
        let g = fixture::genesis();
        let artifact = &g.gap_abi.contracts.values().next().unwrap().compiled;
        let mut overflow = artifact.clone();
        overflow.state_span.offset = usize::MAX;
        assert!(Template::from_artifact(&overflow).is_err());
        let mut outside = artifact.clone();
        outside.state_span.offset = outside.bytecode.len();
        assert!(Template::from_artifact(&outside).is_err());
        let by_hand = Template { bytecode: vec![0; 4], state_start: 3, state_len: 4 };
        assert!(by_hand.materialize(&[0; 4]).is_err());
    }

    /// The ABI codec walks struct types recursively, and a tampered tag orphans an entrypoint.
    #[test]
    fn an_abi_off_the_known_shape_is_refused_before_the_codec_sees_it() {
        let mut g = fixture::genesis();
        let contract = g.gap_abi.contracts.values_mut().next().unwrap();
        contract.runtime_state.fields[0].ty = TypeArtifact::Struct { name: "DeedState".into() };
        assert!(Templates::from_manifest(&g).err().unwrap().to_string().contains("state field"));

        let mut g = fixture::genesis();
        let contract = g.deed_abi.contracts.values_mut().next().unwrap();
        contract.entries.get_mut("evict").unwrap().dispatch_tag = silverscript_abi::DispatchTag::from_hex("00000000").unwrap();
        assert!(Templates::from_manifest(&g).err().unwrap().to_string().contains("dispatch tag"));
    }
}
