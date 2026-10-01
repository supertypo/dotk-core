//! The dotk.name protocol: names, state codecs, cards, address derivation, registry transaction
//! decoding, transaction building and signing, the manifest projections, the classification of
//! a refused submission, and the pre-flight VM.

pub mod address;
pub mod assemble;
pub mod cards;
pub mod contracts;
pub mod fees;
#[cfg(feature = "test-fixture")]
pub mod harness;
pub mod intents;
pub mod manifests;
pub mod names;
#[cfg(feature = "node")]
pub mod net;
pub mod params;
pub mod registry;
pub mod reject;
pub mod sign;
pub mod state;
pub mod vm;
pub mod watch;

pub use assemble::{
    Amount, AssembledTx, DUST_SOMPI, FEE_CEILING, FundingUtxo, INSUFFICIENT_FUNDING, MASS_CEILING, MAX_FEE_SOMPI, assemble,
    assemble_payment, assemble_sweep, assemble_unfunded_evict, assemble_with_cards,
};
pub use contracts::{Template, Templates};
pub use fees::{
    CHANGE_TOO_SMALL, Market, MassOverrun, OVERPAY_CEILING_SOMPI, assemble_payment_with_auto_fee, assemble_sweep_with_auto_fee,
    assemble_unfunded_evict_with_auto_fee, assemble_with_auto_fee, assemble_with_cards_and_auto_fee, fee_mass, frontier_mass,
    full_block_headroom, mass_caps, mass_overrun, minimum_standard_fee, refuse_if_overweight, required_fee,
};
pub use intents::*;
pub use names::*;
pub use params::Params;
pub use reject::Rejection;
pub use state::{DeedState, GapState, OwnerType, Status};

/// A generated test deployment.
#[cfg(feature = "test-fixture")]
pub const TEST_GENESIS: &str = include_str!("../tests/fixtures/genesis.json");

/// blake2b-256 as the script engine's `OpBlake2b` computes it, for covenant ids and P2SH.
pub fn blake2b(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(blake2b_simd::Params::new().hash_length(32).hash(data).as_bytes());
    out
}

/// blake3-256, the KCC-1 hash and the script engine's `OpBlake3`, for name keys and claims.
pub fn blake3_32(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// KCC-1 `Key32(UTF8("PublicKeyHash"))`, the domain-separation key KCC-2 fixes for `P2PKHHash`.
pub const P2PKH_KEY32: [u8; 32] = {
    let mut k = [0u8; 32];
    let label = b"PublicKeyHash";
    let mut i = 0;
    while i < label.len() {
        k[i] = label[i];
        i += 1;
    }
    k
};

#[cfg(test)]
pub(crate) mod fixture {
    use crate::contracts::Templates;
    use crate::intents::{DeedUtxo, GapUtxo, Outpoint};
    use crate::state::{DeedState, GapState, OwnerType};

    pub const COVENANT_ID: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    pub fn genesis() -> crate::watch::GenesisFile {
        serde_json::from_str(include_str!("../tests/fixtures/genesis.json")).unwrap()
    }

    pub fn templates() -> Templates {
        Templates::from_manifest(&genesis()).unwrap()
    }

    pub fn outpoint(b: u8) -> Outpoint {
        Outpoint { transaction_id: faster_hex::hex_string(&[b; 32]), index: 0 }
    }

    /// An x-only key on the curve, because the builders refuse an owner that is not one.
    pub fn owner(seed: u8) -> [u8; 32] {
        secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[seed; 32]).unwrap().x_only_public_key().0.serialize()
    }

    pub fn gap(t: &Templates, lo: [u8; 32], hi: [u8; 32], b: u8) -> GapUtxo {
        GapUtxo { outpoint: outpoint(b), value: t.params.gap_value, state: GapState { lo, hi }, covenant_id: COVENANT_ID.into() }
    }

    pub fn active(t: &Templates, name: &str) -> (GapUtxo, DeedUtxo, GapUtxo) {
        let key = crate::names::key_of(name);
        let deed = DeedUtxo {
            outpoint: outpoint(0xa1),
            value: t.params.bond,
            state: DeedState::active(key, OwnerType::Pubkey, owner(5), crate::names::padded_name(name)),
            covenant_id: COVENANT_ID.into(),
        };
        (gap(t, crate::registry::KEY_MIN, key, 0xa0), deed, gap(t, key, crate::registry::KEY_MAX, 0xa2))
    }

    pub fn pending(t: &Templates, name: &str) -> (GapUtxo, DeedUtxo, GapUtxo) {
        let (pred, deed, succ) = active(t, name);
        let key = crate::names::key_of(name);
        let state = DeedState::pending(key, crate::names::claim_of(name, OwnerType::Pubkey, &owner(5)));
        (pred, DeedUtxo { value: t.params.bond + t.params.deposit, state, ..deed }, succ)
    }
}
