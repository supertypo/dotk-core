use serde::{Deserialize, Serialize};

pub const ZERO32: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Status {
    /// The commit: key is known, the name is not. The owner field carries the claim hash.
    Pending = 0x01,
    /// Registered. The owner field carries the KCC-2 authority, the name field the plaintext.
    Active = 0x02,
}

impl Status {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Pending),
            0x02 => Some(Self::Active),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
/// Authority scheme bytes: KCC-2 for `0x00`..`0x7f`, local schemes above. Every scheme must
/// round-trip to a Kaspa address or be a covenant id. `p2pk-ecdsa/v1` is local because a compressed
/// key is 33 bytes and the field is 32, so x sits in the field and the parity in the scheme byte's
/// low bit.
pub enum OwnerType {
    /// `p2pk-schnorr/v1`: an x-only schnorr key, approved by `checkSig`.
    Pubkey = 0x00,
    /// `p2sh/v1`: a script hash, approved by a co-present input at that P2SH address.
    ScriptHash = 0x03,
    /// `covenant-id/v1`: a KIP-20 covenant id, approved by a co-present lineage input.
    CovenantId = 0x04,
    /// `p2pk-ecdsa/v1` with odd y: the key's x under the SEC1 `0x03` prefix, approved by
    /// `checkSigEcdsa`.
    P2pkEcdsaOdd = 0x85,
    /// `p2pk-ecdsa/v1` with even y, under the SEC1 `0x02` prefix.
    P2pkEcdsaEven = 0x86,
}

impl OwnerType {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::Pubkey),
            0x03 => Some(Self::ScriptHash),
            0x04 => Some(Self::CovenantId),
            0x85 => Some(Self::P2pkEcdsaOdd),
            0x86 => Some(Self::P2pkEcdsaEven),
            _ => None,
        }
    }

    /// The `p2pk-ecdsa/v1` scheme a compressed key's SEC1 prefix stands for.
    pub fn p2pk_ecdsa(sec1_prefix: u8) -> Option<Self> {
        match sec1_prefix {
            0x02 => Some(Self::P2pkEcdsaEven),
            0x03 => Some(Self::P2pkEcdsaOdd),
            _ => None,
        }
    }

    /// The other parity, under which the same x names the twin point.
    pub fn parity_twin(self) -> Option<Self> {
        match self {
            Self::P2pkEcdsaEven => Some(Self::P2pkEcdsaOdd),
            Self::P2pkEcdsaOdd => Some(Self::P2pkEcdsaEven),
            _ => None,
        }
    }

    /// Whether `activate` can mint this scheme. Only an owner-signed `transfer` reaches the others.
    pub fn mintable(self) -> bool {
        self.needs_signature()
    }

    pub fn needs_signature(self) -> bool {
        matches!(self, Self::Pubkey | Self::P2pkEcdsaEven | Self::P2pkEcdsaOdd)
    }

    /// The SEC1 compressed key of an ECDSA owner, `0x02 | parity ‖ x`, as the covenant rebuilds it.
    pub fn compressed_key(self, x: &[u8; 32]) -> Option<[u8; 33]> {
        match self {
            Self::P2pkEcdsaEven | Self::P2pkEcdsaOdd => {
                let mut key = [0u8; 33];
                key[0] = 0x02 | (self as u8 & 0x01);
                key[1..].copy_from_slice(x);
                Some(key)
            }
            _ => None,
        }
    }
}

/// The open interval `(lo, hi)` of unregistered keyspace. It holds keys only, so every gap rebuilds
/// from the sorted live keys. One data push per field: 33 + 33 = 66 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GapState {
    pub lo: [u8; 32],
    pub hi: [u8; 32],
}

pub const GAP_STATE_LEN: usize = 66;

impl GapState {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GAP_STATE_LEN);
        push32(&mut out, &self.lo);
        push32(&mut out, &self.hi);
        debug_assert_eq!(out.len(), GAP_STATE_LEN);
        out
    }

    /// Checks every push opcode, because the bytes are untrusted.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != GAP_STATE_LEN {
            return Err(format!("gap state must be {GAP_STATE_LEN} bytes, got {}", bytes.len()));
        }
        Ok(Self { lo: take32(bytes, 0)?, hi: take32(bytes, 33)? })
    }

    /// Whether splitting this gap can register `key`.
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.lo < *key && *key < self.hi
    }
}

/// One self-contained UTXO per name, so an owner rebuilds the address and redeem from the name and
/// key alone. One layout, read by status: PENDING carries the claim in `owner` and a zero `name`,
/// ACTIVE carries the KCC-2 authority and the zero-padded bare name. Encoding: 2 + 33 + 2 + 33 + 33
/// = 103 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeedState {
    pub status: Status,
    pub key: [u8; 32],
    pub owner_type: OwnerType,
    pub owner: [u8; 32],
    pub name: [u8; 32],
}

pub const DEED_STATE_LEN: usize = 103;

impl DeedState {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DEED_STATE_LEN);
        push_byte(&mut out, self.status as u8);
        push32(&mut out, &self.key);
        push_byte(&mut out, self.owner_type as u8);
        push32(&mut out, &self.owner);
        push32(&mut out, &self.name);
        debug_assert_eq!(out.len(), DEED_STATE_LEN);
        out
    }

    /// Exactly what the gap covenant pins for a `split`.
    pub fn pending(key: [u8; 32], claim: [u8; 32]) -> Self {
        Self { status: Status::Pending, key, owner_type: OwnerType::Pubkey, owner: claim, name: ZERO32 }
    }

    pub fn active(key: [u8; 32], owner_type: OwnerType, owner: [u8; 32], name: [u8; 32]) -> Self {
        Self { status: Status::Active, key, owner_type, owner, name }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != DEED_STATE_LEN {
            return Err(format!("deed state must be {DEED_STATE_LEN} bytes, got {}", bytes.len()));
        }
        let status_byte = take_byte(bytes, 0)?;
        let status = Status::from_byte(status_byte).ok_or_else(|| format!("unknown status {status_byte:#04x}"))?;
        let owner_type_byte = take_byte(bytes, 35)?;
        let owner_type = OwnerType::from_byte(owner_type_byte).ok_or_else(|| format!("unknown owner type {owner_type_byte:#04x}"))?;
        Ok(Self { status, key: take32(bytes, 2)?, owner_type, owner: take32(bytes, 37)?, name: take32(bytes, 70)? })
    }

    /// The unpadded name, or empty for a PENDING deed or a corrupted field.
    pub fn bare_name(&self) -> String {
        crate::names::name_from_padded(&self.name).unwrap_or_default()
    }
}

fn push_byte(out: &mut Vec<u8>, b: u8) {
    out.push(0x01);
    out.push(b);
}

fn push32(out: &mut Vec<u8>, v: &[u8; 32]) {
    out.push(0x20);
    out.extend_from_slice(v);
}

fn take_byte(bytes: &[u8], at: usize) -> Result<u8, String> {
    if bytes[at] != 0x01 {
        return Err(format!("expected a 1-byte push at {at}, got opcode {:#04x}", bytes[at]));
    }
    Ok(bytes[at + 1])
}

fn take32(bytes: &[u8], at: usize) -> Result<[u8; 32], String> {
    if bytes[at] != 0x20 {
        return Err(format!("expected a 32-byte push at {at}, got opcode {:#04x}", bytes[at]));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[at + 1..at + 33]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A region without push opcodes, or with a status no template path writes, is not state.
    #[test]
    fn a_region_that_is_no_state_is_refused() {
        assert!(GapState::decode(&[0u8; GAP_STATE_LEN]).is_err());
        let mut zero_status = DeedState::pending([1u8; 32], [2u8; 32]).encode();
        zero_status[1] = 0x00;
        assert!(DeedState::decode(&zero_status).is_err());
    }
}
