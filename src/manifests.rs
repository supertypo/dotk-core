//! The manifest projections that a web client and a stateless reader are built with.

use crate::contracts::Templates;
use crate::params::Params;
use crate::watch::{Entrypoint, GenesisBinding, GenesisFile};
use serde::{Deserialize, Serialize};
use silverscript_abi::SilAbiArtifact;

/// The manifest subset a web client embeds at build time. Every field except the two ABI
/// artifacts is a trusted pin, and a client must refuse ABI bytecode that misses the pinned
/// hashes. Declaration order is the emitted order, which keeps the pins above the bytecode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebManifest {
    pub version: u32,
    pub network: String,
    pub registry_covenant_id: String,
    pub gap_template_hash: String,
    pub deed_template_hash: String,
    pub genesis_binding: GenesisBinding,
    pub gap_abi: SilAbiArtifact,
    pub deed_abi: SilAbiArtifact,
    pub params: Params,
}

/// The result must itself deserialize as a [`GenesisFile`], because a client loads it as one.
pub fn web_manifest(g: &GenesisFile) -> Result<WebManifest, String> {
    let missing = |what: &str| format!("the manifest carries no {what}, so it is not a usable deployment record");
    if g.network.is_empty() {
        return Err(missing("network"));
    }
    if g.registry_covenant_id.is_empty() {
        return Err(missing("registryCovenantId"));
    }
    if g.gap_template_hash.is_empty() || g.deed_template_hash.is_empty() {
        return Err(missing("template hash"));
    }
    Ok(WebManifest {
        version: g.version,
        network: g.network.clone(),
        registry_covenant_id: g.registry_covenant_id.clone(),
        gap_template_hash: g.gap_template_hash.clone(),
        deed_template_hash: g.deed_template_hash.clone(),
        genesis_binding: g.genesis_binding.clone().ok_or_else(|| missing("genesisBinding"))?,
        gap_abi: g.gap_abi.clone(),
        deed_abi: g.deed_abi.clone(),
        params: g.params.clone(),
    })
}

/// Projects a manifest onto [`WatchManifest`]. The dispatch tags and state spans come from
/// `templates`, never from the manifest's ABI artifacts.
pub fn watch_manifest(g: &GenesisFile, templates: &Templates) -> Result<WatchManifest, String> {
    let entrypoints = |set: &[Entrypoint]| {
        set.iter()
            .map(|e| WatchEntrypoint { name: e.name().to_string(), dispatch_tag: faster_hex::hex_string(&e.tag()), arity: e.arity() })
            .collect()
    };
    Ok(WatchManifest {
        version: g.version,
        network: g.network.clone(),
        registry_covenant_id: g.registry_covenant_id.clone(),
        gap: WatchTemplateAbi {
            template_hash: g.gap_template_hash.clone(),
            state_start: templates.gap.state_start,
            state_len: templates.gap.state_len,
            entrypoints: entrypoints(&Entrypoint::GAP),
        },
        deed: WatchTemplateAbi {
            template_hash: g.deed_template_hash.clone(),
            state_start: templates.deed.state_start,
            state_len: templates.deed.state_len,
            entrypoints: entrypoints(&Entrypoint::DEED),
        },
        params: g.params.clone(),
        // `authorized_outputs` carries the genesis redeem script, which is bytecode.
        genesis_binding: g
            .genesis_binding
            .clone()
            .map(|b| GenesisBinding { authorized_outputs: vec![], ..b })
            .ok_or_else(|| "the manifest carries no genesisBinding, so a reader could not recognize the genesis mint".to_string())?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatchTemplateAbi {
    pub template_hash: String,
    pub state_start: usize,
    pub state_len: usize,
    pub entrypoints: Vec<WatchEntrypoint>,
}

/// A decoder must refuse a sigscript whose push count is not `arity + 2` before it reads an
/// argument ([`Entrypoint::arity`]).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatchEntrypoint {
    pub name: String,
    pub dispatch_tag: String,
    pub arity: usize,
}

/// The manifest subset a stateless reader is built with, as JSON so that consumers in any
/// language embed identical bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WatchManifest {
    pub version: u32,
    pub network: String,
    pub registry_covenant_id: String,
    pub gap: WatchTemplateAbi,
    pub deed: WatchTemplateAbi,
    pub params: Params,
    /// Required because the genesis mint's input 0 carries no covenant id and no dispatch tag,
    /// so without it a reader cannot tell the mint from a decode failure.
    pub genesis_binding: GenesisBinding,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;

    /// The test deployment with its genesis binding filled in.
    fn bound() -> (Templates, GenesisFile) {
        let t = fixture::templates();
        let mut g = fixture::genesis();
        g.genesis_binding = Some(GenesisBinding::minted_over_genesis_gap(&t, fixture::outpoint(0x7a)).expect("binding"));
        (t, g)
    }

    /// Tags come from [`Entrypoint::tag`] and spans from the validated templates, never relayed
    /// from an unchecked field.
    #[test]
    fn the_watch_manifest_derives_its_tags_and_spans() {
        let (t, genesis) = bound();
        let w = watch_manifest(&genesis, &t).expect("watch manifest");

        assert_eq!(w.registry_covenant_id, genesis.registry_covenant_id);
        assert_eq!(w.gap.template_hash, genesis.gap_template_hash);
        assert_eq!(w.deed.template_hash, genesis.deed_template_hash);
        assert_eq!((w.gap.state_start, w.gap.state_len), (t.gap.state_start, t.gap.state_len));
        assert_eq!((w.deed.state_start, w.deed.state_len), (t.deed.state_start, t.deed.state_len));

        // Every entrypoint of both templates, and every tag equal to the one this crate derives.
        for (set, published) in [(Entrypoint::GAP.as_slice(), &w.gap), (Entrypoint::DEED.as_slice(), &w.deed)] {
            assert_eq!(published.entrypoints.len(), set.len());
            for (e, p) in set.iter().zip(&published.entrypoints) {
                assert_eq!(p.name, e.name());
                assert_eq!(p.dispatch_tag, faster_hex::hex_string(&e.tag()));
                assert_eq!(p.arity, e.arity(), "arity is a refusal rule, so a wrong one admits a malformed sigscript");
            }
        }
    }

    #[test]
    fn the_watch_manifest_refuses_a_manifest_without_its_genesis_binding() {
        let (t, mut genesis) = bound();
        genesis.genesis_binding = None;
        let why = watch_manifest(&genesis, &t).expect_err("a reader could not recognize the genesis mint");
        assert!(why.contains("genesisBinding"), "the error must name the missing field: {why}");
    }

    #[test]
    fn the_watch_manifest_is_a_small_fraction_of_the_full_one() {
        let (t, genesis) = bound();
        let full = serde_json::to_string(&genesis).expect("full");
        let watch = serde_json::to_string(&watch_manifest(&genesis, &t).expect("watch manifest")).expect("watch");
        assert!(!watch.contains("bytecode"), "the projection must carry no bytecode");
        assert!(!watch.contains("authorizedOutputs"), "nor the genesis redeem script, which is the bytecode by another name");
        assert!(watch.len() * 10 < full.len(), "watch {} bytes vs full {} bytes", watch.len(), full.len());
    }

    /// The web subset loads back as a manifest whose templates load, and it needs the genesis
    /// binding.
    #[test]
    fn the_web_manifest_keeps_the_pins_and_needs_the_binding() {
        let (_, genesis) = bound();
        let web = web_manifest(&genesis).expect("the test deployment projects onto the web subset");
        assert_eq!(web.deed_template_hash, genesis.deed_template_hash);
        assert_eq!(web.registry_covenant_id, genesis.registry_covenant_id);
        let back: GenesisFile =
            serde_json::from_str(&serde_json::to_string(&web).unwrap()).expect("the client loads the web manifest as a GenesisFile");
        Templates::from_manifest(&back).expect("and its pinned templates load");
        let mut bare = genesis;
        bare.genesis_binding = None;
        assert!(web_manifest(&bare).expect_err("accepted without a binding").contains("genesisBinding"));
    }
}
