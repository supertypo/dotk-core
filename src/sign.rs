//! Owner signatures for the key-owned schemes. Kaspa txids exclude signature scripts, so a builder
//! assembles with a zero placeholder of the exact signature length and patches the real one in.

use anyhow::{Result, anyhow, bail, ensure};
use kaspa_addresses::{Prefix, Version};
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_ecdsa_signature_hash, calc_schnorr_signature_hash};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, UtxoEntry};
use kaspa_txscript::extract_script_pub_key_address;

use crate::state::OwnerType;

/// 64-byte schnorr signature ‖ sighash-type byte: the KCC-1 `sig` scalar that `checkSig` consumes.
pub const SIG_LEN: usize = 65;

pub const SIG_PLACEHOLDER: [u8; SIG_LEN] = [0u8; SIG_LEN];

/// A canonical funding signature script: push opcode `0x41` and the 65 bytes it pushes.
/// [`crate::fees`] prices unsigned funding inputs at exactly this length.
pub const FUNDING_SIG_SCRIPT_LEN: usize = 1 + SIG_LEN;

/// Schnorr-signs input `input_index` with SIGHASH_ALL. `entries` are the UTXO entries in input order.
pub fn schnorr_sign_input(
    tx: &Transaction,
    entries: &[UtxoEntry],
    input_index: usize,
    secret_key: &[u8; 32],
) -> Result<[u8; SIG_LEN]> {
    anyhow::ensure!(entries.len() == tx.inputs.len(), "entries/inputs length mismatch");
    anyhow::ensure!(input_index < tx.inputs.len(), "no input at {input_index}");
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    let hash = calc_schnorr_signature_hash(&populated, input_index, SIG_HASH_ALL, &reused);
    let msg = secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| anyhow!("sighash message: {e}"))?;
    let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, secret_key).map_err(|e| anyhow!("secret key: {e}"))?;
    let sig = keypair.sign_schnorr(msg);
    let mut out = [0u8; SIG_LEN];
    out[..64].copy_from_slice(sig.as_ref());
    out[64] = SIG_HASH_ALL.to_u8();
    Ok(out)
}

/// The SEC1 compressed public key. A `p2pk-ecdsa/v1` owner must come from
/// [`crate::address::owner_of`], because a parity paired with x by hand can name the negated key.
pub fn compressed_public_key(secret_key: &[u8; 32]) -> Result<[u8; 33]> {
    let key = secp256k1::SecretKey::from_slice(secret_key).map_err(|e| anyhow!("secret key: {e}"))?;
    Ok(key.public_key(secp256k1::SECP256K1).serialize())
}

/// The offset of push-65 followed by 65 zero bytes. No other sigscript field is 65 bytes wide.
fn placeholder_at(sig_script: &[u8]) -> Option<usize> {
    let needle = 1 + SIG_LEN;
    (0..sig_script.len().saturating_sub(needle - 1))
        .find(|&i| sig_script[i] == 0x41 && sig_script[i + 1..i + needle].iter().all(|&b| b == 0))
}

pub fn patch_placeholder_sig(sig_script: &mut [u8], sig: &[u8; SIG_LEN]) -> Result<()> {
    let at = placeholder_at(sig_script).ok_or_else(|| anyhow!("no placeholder signature found in sigscript"))?;
    sig_script[at + 1..at + 1 + SIG_LEN].copy_from_slice(sig);
    Ok(())
}

pub fn has_placeholder_sig(sig_script: &[u8]) -> bool {
    placeholder_at(sig_script).is_some()
}

/// The first 65-byte push of a wallet's signature script. Wallets lay out non-standard inputs
/// differently.
pub fn extract_sig_from_sig_script(sig_script: &[u8]) -> Result<[u8; SIG_LEN]> {
    let mut i = 0usize;
    while i < sig_script.len() {
        let op = sig_script[i] as usize;
        // Data pushes: direct, OP_PUSHDATA1 and OP_PUSHDATA2. A signature never needs OP_PUSHDATA4.
        let (len, data_at) = match op {
            1..=0x4b => (op, i + 1),
            0x4c if i + 1 < sig_script.len() => (sig_script[i + 1] as usize, i + 2),
            0x4d if i + 2 < sig_script.len() => (u16::from_le_bytes([sig_script[i + 1], sig_script[i + 2]]) as usize, i + 3),
            // A small-integer opcode, which `transfer` emits for a `newOwnerType` of 0x03 or 0x04.
            0x00 | 0x4f | 0x51..=0x60 => {
                i += 1;
                continue;
            }
            _ => break,
        };
        if data_at + len > sig_script.len() {
            break;
        }
        if len == SIG_LEN {
            let mut out = [0u8; SIG_LEN];
            out.copy_from_slice(&sig_script[data_at..data_at + SIG_LEN]);
            return Ok(out);
        }
        i = data_at + len;
    }
    Err(anyhow!("no 65-byte signature push found in wallet signature script"))
}

/// A wallet's signature for one input, or why it cannot be used. Only `SIGHASH_ALL` commits to every
/// output, and neither consensus nor the mempool refuses another type, so the change would be a
/// bearer value. The zero placeholder is refused, because an unsigning wallet hands it back unchanged.
pub fn accept_wallet_sig(sig_script: &[u8]) -> Result<[u8; SIG_LEN]> {
    let sig = extract_sig_from_sig_script(sig_script)?;
    ensure!(sig != SIG_PLACEHOLDER, "the wallet returned the unsigned placeholder, so it did not sign this input");
    let hash_type = sig[SIG_LEN - 1];
    ensure!(
        hash_type == SIG_HASH_ALL.to_u8(),
        "the wallet signed with sighash type {hash_type:#04x}, not SIGHASH_ALL ({:#04x}): a signature that \
         does not commit to every output leaves this transaction's change rewritable by anyone",
        SIG_HASH_ALL.to_u8()
    );
    Ok(sig)
}

/// A wallet's funding signature script, adopted whole. It must be the canonical
/// [`FUNDING_SIG_SCRIPT_LEN`] bytes the fee was priced at.
pub fn accept_funding_sig_script(sig_script: &[u8]) -> Result<[u8; SIG_LEN]> {
    ensure!(
        sig_script.len() == FUNDING_SIG_SCRIPT_LEN && sig_script[0] == 0x41,
        "the wallet returned a {}-byte signature script for a funding input rather than the canonical \
         {FUNDING_SIG_SCRIPT_LEN}-byte push of one signature: the fee was computed for the canonical form, \
         so this transaction would go out underpaying its own mass",
        sig_script.len()
    );
    accept_wallet_sig(sig_script)
}

/// Checks that `sig` signs input `input_index` under the key its UTXO pays to. Any other script is
/// refused, never passed unverified.
pub fn verify_input_sig(tx: &Transaction, entries: &[UtxoEntry], input_index: usize, sig: &[u8; SIG_LEN]) -> Result<()> {
    ensure!(entries.len() == tx.inputs.len(), "entries/inputs length mismatch");
    let entry = entries.get(input_index).ok_or_else(|| anyhow!("no input at {input_index}"))?;
    let addr = extract_script_pub_key_address(&entry.script_public_key, Prefix::Mainnet)
        .map_err(|e| anyhow!("input {input_index} does not pay to a standard address: {e}"))?;
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    match addr.version {
        Version::PubKey => {
            let hash = calc_schnorr_signature_hash(&populated, input_index, SIG_HASH_ALL, &reused);
            let msg =
                secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| anyhow!("sighash message: {e}"))?;
            let key = secp256k1::XOnlyPublicKey::from_slice(&addr.payload)
                .map_err(|e| anyhow!("input {input_index} pays to an unusable key: {e}"))?;
            let parsed =
                secp256k1::schnorr::Signature::from_slice(&sig[..64]).map_err(|e| anyhow!("malformed schnorr signature: {e}"))?;
            secp256k1::SECP256K1
                .verify_schnorr(&parsed, &msg, &key)
                .map_err(|e| anyhow!("the signature does not sign input {input_index} under the key it pays to: {e}"))
        }
        Version::PubKeyECDSA => {
            let hash = calc_ecdsa_signature_hash(&populated, input_index, SIG_HASH_ALL, &reused);
            let msg =
                secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| anyhow!("sighash message: {e}"))?;
            let key = secp256k1::PublicKey::from_slice(&addr.payload)
                .map_err(|e| anyhow!("input {input_index} pays to an unusable key: {e}"))?;
            let parsed =
                secp256k1::ecdsa::Signature::from_compact(&sig[..64]).map_err(|e| anyhow!("malformed ECDSA signature: {e}"))?;
            secp256k1::SECP256K1
                .verify_ecdsa(&msg, &parsed, &key)
                .map_err(|e| anyhow!("the signature does not sign input {input_index} under the key it pays to: {e}"))
        }
        other => bail!("input {input_index} pays to {other}, whose signature this build cannot verify"),
    }
}

/// Checks that `sig` signs input `input_index` for a deed's owner record, which the caller supplies
/// because a deed pays to P2SH. The flavor follows the scheme byte, as the covenant's does.
pub fn verify_owner_sig(
    tx: &Transaction,
    entries: &[UtxoEntry],
    input_index: usize,
    sig: &[u8; SIG_LEN],
    owner_type: OwnerType,
    owner: &[u8; 32],
) -> Result<()> {
    ensure!(entries.len() == tx.inputs.len(), "entries/inputs length mismatch");
    ensure!(input_index < tx.inputs.len(), "no input at {input_index}");
    ensure!(owner_type.needs_signature(), "a {owner_type:?} seat is approved by co-presence and carries no signature to verify");
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let reused = SigHashReusedValuesUnsync::new();
    match owner_type {
        OwnerType::Pubkey => {
            let hash = calc_schnorr_signature_hash(&populated, input_index, SIG_HASH_ALL, &reused);
            let msg =
                secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| anyhow!("sighash message: {e}"))?;
            let key =
                secp256k1::XOnlyPublicKey::from_slice(owner).map_err(|e| anyhow!("the owner record is not a curve point: {e}"))?;
            let parsed =
                secp256k1::schnorr::Signature::from_slice(&sig[..64]).map_err(|e| anyhow!("malformed schnorr signature: {e}"))?;
            secp256k1::SECP256K1
                .verify_schnorr(&parsed, &msg, &key)
                .map_err(|e| anyhow!("the signature does not authorize input {input_index} for this deed's owner: {e}"))
        }
        OwnerType::P2pkEcdsaEven | OwnerType::P2pkEcdsaOdd => {
            let hash = calc_ecdsa_signature_hash(&populated, input_index, SIG_HASH_ALL, &reused);
            let msg =
                secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| anyhow!("sighash message: {e}"))?;
            let compressed = owner_type.compressed_key(owner).ok_or_else(|| anyhow!("{owner_type:?} has no compressed key"))?;
            let key =
                secp256k1::PublicKey::from_slice(&compressed).map_err(|e| anyhow!("the owner record is not a curve point: {e}"))?;
            let parsed =
                secp256k1::ecdsa::Signature::from_compact(&sig[..64]).map_err(|e| anyhow!("malformed ECDSA signature: {e}"))?;
            secp256k1::SECP256K1
                .verify_ecdsa(&msg, &parsed, &key)
                .map_err(|e| anyhow!("the signature does not authorize input {input_index} for this deed's owner: {e}"))
        }
        other => bail!("scheme {other:?} cannot be verified as a signature"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionInput, TransactionOutpoint, TransactionOutput};

    /// `0x81` commits to every output too, but a wallet asked for SIGHASH_ALL did not answer with it.
    #[test]
    fn a_signature_that_does_not_commit_to_the_outputs_is_refused() {
        for hash_type in [0x02u8, 0x03, 0x81, 0x82, 0x83] {
            let mut sig = [7u8; SIG_LEN];
            sig[SIG_LEN - 1] = hash_type;
            let script = std::iter::once(0x41u8).chain(sig).collect::<Vec<_>>();
            let refused = accept_wallet_sig(&script).unwrap_err().to_string();
            assert!(refused.contains("SIGHASH_ALL"), "type {hash_type:#04x} was accepted: {refused}");
        }
        let unsigned = std::iter::once(0x41u8).chain(SIG_PLACEHOLDER).collect::<Vec<_>>();
        assert!(accept_wallet_sig(&unsigned).unwrap_err().to_string().contains("did not sign"));
    }

    #[test]
    fn only_the_canonical_funding_script_is_accepted() {
        let mut sig = [7u8; SIG_LEN];
        sig[SIG_LEN - 1] = SIG_HASH_ALL.to_u8();
        let canonical: Vec<u8> = std::iter::once(0x41u8).chain(sig).collect();
        assert_eq!(accept_funding_sig_script(&canonical).unwrap(), sig);
        assert_eq!(canonical.len(), FUNDING_SIG_SCRIPT_LEN);

        for wrong in [
            canonical.iter().copied().chain([0x51]).collect::<Vec<_>>(), // one opcode too many
            canonical[..canonical.len() - 1].to_vec(),                   // truncated
            vec![],                                                      // not signed at all
            std::iter::once(0x4cu8).chain([SIG_LEN as u8]).chain(sig).collect(), // PUSHDATA1 form
        ] {
            let refused = accept_funding_sig_script(&wrong).unwrap_err().to_string();
            assert!(refused.contains("canonical"), "{:?} was accepted: {refused}", wrong.len());
        }
    }

    /// A well-formed signature over another transaction passes every check except this one.
    #[test]
    fn a_signature_over_another_transaction_does_not_verify() {
        let secret = [0x2au8; 32];
        let key = compressed_public_key(&secret).unwrap();
        let mut script = vec![0x20u8];
        script.extend(&key[1..33]);
        script.push(0xac);
        let spk = ScriptPublicKey::from_vec(0, script);

        let build = |value: u64| {
            let input = TransactionInput::new_with_compute_budget(
                TransactionOutpoint::new(kaspa_consensus_core::Hash::from_bytes([7u8; 32]), 0),
                vec![],
                0,
                20,
            );
            let tx =
                Transaction::new(1, vec![input], vec![TransactionOutput::new(value, spk.clone())], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
            let entries = vec![UtxoEntry::new(1000, spk.clone(), 0, false, None)];
            (tx, entries)
        };

        let (tx, entries) = build(500);
        let sig = schnorr_sign_input(&tx, &entries, 0, &secret).unwrap();
        verify_input_sig(&tx, &entries, 0, &sig).expect("its own signature verifies");

        let (other, other_entries) = build(499);
        let elsewhere = schnorr_sign_input(&other, &other_entries, 0, &secret).unwrap();
        let refused = verify_input_sig(&tx, &entries, 0, &elsewhere).unwrap_err().to_string();
        assert!(refused.contains("does not sign input 0"), "{refused}");
    }

    #[test]
    fn an_unverifiable_funding_script_is_refused_rather_than_skipped() {
        let secret = [0x41u8; 32];
        let spk = ScriptPublicKey::from_vec(0, vec![0xaa, 0x20].into_iter().chain([0x11u8; 32]).chain([0x87]).collect::<Vec<_>>());
        let input = TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(kaspa_consensus_core::Hash::from_bytes([3u8; 32]), 0),
            vec![],
            0,
            20,
        );
        let tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(500, spk.clone())], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        let entries = vec![UtxoEntry::new(1000, spk, 0, false, None)];
        let sig = schnorr_sign_input(&tx, &entries, 0, &secret).unwrap();
        assert!(verify_input_sig(&tx, &entries, 0, &sig).is_err(), "a P2SH funding input cannot be verified and must not pass");
        assert!(schnorr_sign_input(&tx, &entries, 1, &secret).is_err(), "an index past the inputs is an error, not a panic");
    }

    #[test]
    fn the_placeholder_is_patched_in_place() {
        let mut sig_script = vec![0x20u8; 33];
        sig_script.push(0x41);
        sig_script.extend([0u8; SIG_LEN]);
        assert!(has_placeholder_sig(&sig_script));
        let sig = [0x09u8; SIG_LEN];
        patch_placeholder_sig(&mut sig_script, &sig).unwrap();
        assert!(!has_placeholder_sig(&sig_script));
        assert_eq!(extract_sig_from_sig_script(&sig_script[33..]).unwrap(), sig);
    }
}
