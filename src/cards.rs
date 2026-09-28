//! Cards: a name's optional record set, a plain P2SH output minted at output 1 of the owner's `transfer`.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail, ensure};
use kaspa_addresses::{Address, Prefix, Version as AddrVersion};
use kaspa_txscript::script_builder::ScriptBuilder;
use serde::{Deserialize, Serialize};

use crate::address;
use crate::blake3_32;
use crate::intents::Outpoint;
use crate::names::{SubnameFault, validate_label};
use crate::sign::{SIG_LEN, SIG_PLACEHOLDER};
use crate::state::{DeedState, OwnerType, Status};

/// 0.5 KAS. The spend that sweeps a card reclaims it.
pub const CARD_VALUE: u64 = 50_000_000;
// The KIP-9 output floor. A card below it costs a transfer most of its storage mass budget.
const _: () = assert!(CARD_VALUE >= crate::params::MIN_OUTPUT_VALUE);

/// Bounds what a reader stores per name.
pub const CARD_BLOB_MAX: usize = 16 * 1024;

/// A sweep must push these four bytes, and a payload opens with them.
pub const CARD_MAGIC: [u8; 4] = *b"dotk";

pub const PAYLOAD_VERSION: u8 = 1;

/// `key ‖ records ‖ spender_type ‖ spender`.
pub const CARD_STATE_LEN: usize = 32 + 32 + 1 + 32;

/// Deserialization goes through [`CardState::new`], so no scheme without a key reaches a script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CardStateWire")]
pub struct CardState {
    /// `blake3(name)`.
    pub key: [u8; 32],
    /// `blake3(record blob)`.
    pub records: [u8; 32],
    /// Key-owned schemes only. Any key the owner controls, so a P2SH owner can carry a card.
    pub spender_type: OwnerType,
    /// The key's x, with an ECDSA parity in the scheme byte, as a deed stores its owner.
    pub spender: [u8; 32],
}

#[derive(Deserialize)]
struct CardStateWire {
    key: [u8; 32],
    records: [u8; 32],
    spender_type: OwnerType,
    spender: [u8; 32],
}

impl TryFrom<CardStateWire> for CardState {
    type Error = anyhow::Error;

    fn try_from(w: CardStateWire) -> Result<Self> {
        Self::new(w.key, w.records, w.spender_type, w.spender)
    }
}

impl CardState {
    pub fn new(key: [u8; 32], records: [u8; 32], spender_type: OwnerType, spender: [u8; 32]) -> Result<Self> {
        ensure!(spender_type.needs_signature(), "a card's spender is a key: scheme {:#04x} has none", spender_type as u8);
        ensure!(spender != [0u8; 32], "a card's spender is zero, which no key can satisfy");
        Ok(Self { key, records, spender_type, spender })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CARD_STATE_LEN);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.records);
        out.push(self.spender_type as u8);
        out.extend_from_slice(&self.spender);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() == CARD_STATE_LEN, "card state is {CARD_STATE_LEN} bytes, got {}", bytes.len());
        let spender_type = OwnerType::from_byte(bytes[64]).ok_or_else(|| anyhow!("unknown spender scheme {:#04x}", bytes[64]))?;
        Self::new(bytes[..32].try_into()?, bytes[32..64].try_into()?, spender_type, bytes[65..].try_into()?)
    }

    /// `<key> <records> OP_DROP OP_DROP <magic> OP_EQUALVERIFY <spender> OP_CHECKSIG`, with
    /// `OP_CHECKSIGECDSA` over the compressed key for an ECDSA spender.
    pub fn redeem_script(&self) -> Vec<u8> {
        let mut b = ScriptBuilder::new();
        b.add_data(&self.key).expect("a 32-byte push");
        b.add_data(&self.records).expect("a 32-byte push");
        b.add_op(kaspa_txscript::opcodes::codes::OpDrop).expect("an opcode");
        b.add_op(kaspa_txscript::opcodes::codes::OpDrop).expect("an opcode");
        b.add_data(&CARD_MAGIC).expect("a 4-byte push");
        b.add_op(kaspa_txscript::opcodes::codes::OpEqualVerify).expect("an opcode");
        match self.spender_type {
            OwnerType::Pubkey => {
                b.add_data(&self.spender).expect("a 32-byte push");
                b.add_op(kaspa_txscript::opcodes::codes::OpCheckSig).expect("an opcode");
            }
            _ => {
                let compressed = self.spender_type.compressed_key(&self.spender).expect("a card spender is a key");
                b.add_data(&compressed).expect("a 33-byte push");
                b.add_op(kaspa_txscript::opcodes::codes::OpCheckSigECDSA).expect("an opcode");
            }
        }
        b.drain()
    }

    /// The P2SH script public key, without the version prefix.
    pub fn spk(&self) -> Vec<u8> {
        kaspa_txscript::pay_to_script_hash_script(&self.redeem_script()).script().to_vec()
    }

    pub fn address(&self, prefix: Prefix) -> Address {
        let spk = self.spk();
        Address::new(prefix, AddrVersion::ScriptHash, &spk[2..34])
    }

    /// `<sig> <magic> <redeem>`. `None` leaves the zero placeholder for the signer to patch.
    pub fn sweep_sig_script(&self, sig: Option<&[u8; SIG_LEN]>) -> Vec<u8> {
        let mut b = ScriptBuilder::new();
        b.add_data(sig.unwrap_or(&SIG_PLACEHOLDER)).expect("a 65-byte push");
        b.add_data(&CARD_MAGIC).expect("a 4-byte push");
        b.add_data(&self.redeem_script()).expect("the redeem push");
        b.drain()
    }

    /// The card a signature script sweeps, or `None`. Only a byte-exact card sweep matches.
    pub fn swept_by(sig_script: &[u8]) -> Option<Self> {
        // `<0x41 sig(65)> <0x04 "dotk"> <OP_PUSHDATA1 len redeem>`, and the redeem opens
        // `<0x20 key(32)> <0x20 records(32)>` and closes `<push spender> <checksig>`.
        let sig: &[u8; SIG_LEN] = sig_script.get(1..1 + SIG_LEN)?.try_into().ok()?;
        let redeem = sig_script.get(1 + SIG_LEN + 1 + CARD_MAGIC.len() + 2..)?;
        let key: [u8; 32] = redeem.get(1..33)?.try_into().ok()?;
        let records: [u8; 32] = redeem.get(34..66)?.try_into().ok()?;
        let n = redeem.len();
        let (spender_type, spender) = match n {
            108 => (OwnerType::Pubkey, redeem.get(n - 33..n - 1)?),
            109 => (OwnerType::p2pk_ecdsa(*redeem.get(n - 34)?)?, redeem.get(n - 33..n - 1)?),
            _ => return None,
        };
        let state = Self::new(key, records, spender_type, spender.try_into().ok()?).ok()?;
        (state.sweep_sig_script(Some(sig)) == sig_script).then_some(state)
    }
}

pub fn records_of(blob: &[u8]) -> [u8; 32] {
    blake3_32(blob)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardMint {
    pub state: CardState,
    #[serde(with = "hex_bytes")]
    pub blob: Vec<u8>,
}

impl CardMint {
    /// A card for `next`, the deed after the minting transfer. A name in escrow carries no records.
    pub fn for_deed(next: &DeedState, blob: Vec<u8>, spender_type: OwnerType, spender: [u8; 32]) -> Result<Self> {
        ensure!(next.status == Status::Active, "a card is minted beside an ACTIVE deed");
        ensure!(next.owner_type != OwnerType::CovenantId, "a transfer to a covenant-id owner mints no card");
        ensure!(blob.len() <= CARD_BLOB_MAX, "record blob is {} bytes, over the {CARD_BLOB_MAX} byte cap", blob.len());
        // An off-curve spender locks the card's value forever.
        crate::address::check_payload(spender_type, &spender).map_err(|e| anyhow!("card spender: {e}"))?;
        Ok(Self { state: CardState::new(next.key, records_of(&blob), spender_type, spender)?, blob })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardInput {
    pub outpoint: Outpoint,
    pub value: u64,
    pub state: CardState,
}

/// The card a transaction mints at output 1, and the card inputs it sweeps.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardPlan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mint: Option<CardMint>,
    pub sweep: Vec<CardInput>,
}

/// `magic ‖ version ‖ state ‖ blob_len:u16 LE ‖ blob`, or empty without a mint.
pub fn encode_payload(mint: Option<&CardMint>) -> Result<Vec<u8>> {
    let Some(m) = mint else { return Ok(Vec::new()) };
    ensure!(m.blob.len() <= CARD_BLOB_MAX, "record blob is {} bytes, over the {CARD_BLOB_MAX} byte cap", m.blob.len());
    ensure!(m.state.records == records_of(&m.blob), "card state does not commit to its blob");
    let mut out = Vec::with_capacity(CARD_MAGIC.len() + 1 + CARD_STATE_LEN + 2 + m.blob.len());
    out.extend_from_slice(&CARD_MAGIC);
    out.push(PAYLOAD_VERSION);
    out.extend_from_slice(&m.state.encode());
    out.extend_from_slice(&(m.blob.len() as u16).to_le_bytes());
    out.extend_from_slice(&m.blob);
    Ok(out)
}

/// `None` without the card magic. Bytes after the blob are malformed, because a name holds one card.
pub fn decode_payload(payload: &[u8]) -> Result<Option<CardMint>> {
    if payload.len() < 5 || payload[..4] != CARD_MAGIC {
        return Ok(None);
    }
    ensure!(payload[4] == PAYLOAD_VERSION, "card payload version {} is not {PAYLOAD_VERSION}", payload[4]);
    let rest = &payload[5..];
    ensure!(rest.len() >= CARD_STATE_LEN + 2, "card payload truncated inside a state");
    let state = CardState::decode(&rest[..CARD_STATE_LEN])?;
    let len = u16::from_le_bytes([rest[CARD_STATE_LEN], rest[CARD_STATE_LEN + 1]]) as usize;
    ensure!(len <= CARD_BLOB_MAX, "record blob is {len} bytes, over the {CARD_BLOB_MAX} byte cap");
    let start = CARD_STATE_LEN + 2;
    ensure!(rest.len() >= start + len, "card payload truncated inside a blob");
    ensure!(rest.len() == start + len, "card payload carries {} bytes after its card", rest.len() - start - len);
    let blob = rest[start..start + len].to_vec();
    ensure!(state.records == records_of(&blob), "card state does not commit to the blob beside it");
    Ok(Some(CardMint { state, blob }))
}

/// The five reader rules, over what a node answered:
///
/// 1. A live UTXO sits at the card's address (`card_utxo`).
/// 2. That UTXO is output 1 of the transaction that created the deed's current UTXO.
/// 3. `blob` hashes to the card's `records`.
/// 4. `blob` is within [`CARD_BLOB_MAX`].
/// 5. The deed is ACTIVE and no covenant id owns it.
pub fn verify(deed: &crate::intents::DeedUtxo, card: &CardState, card_utxo: Option<&Outpoint>, blob: &[u8]) -> Result<()> {
    ensure!(deed.state.status == Status::Active, "rule 5: the deed is not ACTIVE, so no card speaks for it");
    ensure!(deed.state.owner_type != OwnerType::CovenantId, "rule 5: a name in escrow carries no records");
    ensure!(card.key == deed.state.key, "the card is for another name");
    let utxo = card_utxo.ok_or_else(|| anyhow!("rule 1: no live UTXO at the card's address"))?;
    ensure!(
        utxo.transaction_id == deed.outpoint.transaction_id && utxo.index == 1,
        "rule 2: the card is not output 1 of the transaction that created the deed's current UTXO"
    );
    ensure!(blob.len() <= CARD_BLOB_MAX, "rule 4: the blob is {} bytes, over the {CARD_BLOB_MAX} byte cap", blob.len());
    ensure!(records_of(blob) == card.records, "rule 3: the blob is not the one the card commits to");
    Ok(())
}

/// Text for ENSIP-5 values, a flag for keys such as `primary`, and the exact bytes of any other CBOR
/// item. The opaque JSON form is `{ "opaque": "<hex>" }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, from = "RecordValueWire")]
pub enum RecordValue {
    Text(String),
    Flag(bool),
    Opaque {
        #[serde(with = "hex_bytes")]
        opaque: Vec<u8>,
    },
}

/// The JSON shapes before conversion. The opaque form is a struct variant, because a newtype over hex
/// reads back as text.
#[derive(Deserialize)]
#[serde(untagged)]
enum RecordValueWire {
    Text(String),
    Flag(bool),
    Opaque {
        #[serde(with = "hex_bytes")]
        opaque: Vec<u8>,
    },
}

impl From<RecordValueWire> for RecordValue {
    fn from(wire: RecordValueWire) -> Self {
        match wire {
            RecordValueWire::Text(t) => RecordValue::Text(t),
            RecordValueWire::Flag(f) => RecordValue::Flag(f),
            RecordValueWire::Opaque { opaque } => RecordValue::carried(opaque),
        }
    }
}

impl RecordValue {
    /// Converts one UTF-8 text item or one flag byte. Anything else, a malformed value included,
    /// stays opaque for the encoder to judge.
    pub fn carried(bytes: Vec<u8>) -> Self {
        match bytes.first() {
            Some(0xf4) if bytes.len() == 1 => RecordValue::Flag(false),
            Some(0xf5) if bytes.len() == 1 => RecordValue::Flag(true),
            Some(b) if b >> 5 == 3 => {
                let mut c = Cursor { bytes: &bytes, at: 0 };
                match c.text() {
                    Ok(t) if c.at == bytes.len() => RecordValue::Text(t),
                    _ => RecordValue::Opaque { opaque: bytes },
                }
            }
            _ => RecordValue::Opaque { opaque: bytes },
        }
    }
}

/// A CBOR map with text keys: ENSIP-5 keys beside local ones such as `primary`.
pub type Records = BTreeMap<String, RecordValue>;

/// The local key that names an address's primary name.
pub const PRIMARY_KEY: &str = "primary";

/// The most containers a record value can nest. Every implementation must use this value.
pub const RECORD_DEPTH_MAX: usize = 8;

fn cbor_head(major: u8, n: usize, out: &mut Vec<u8>) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => {
            out.push(m | 24);
            out.push(n as u8);
        }
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
}

fn cbor_text(s: &str, out: &mut Vec<u8>) {
    cbor_head(3, s.len(), out);
    out.extend_from_slice(s.as_bytes());
}

/// RFC 8949 §4.2.1 deterministic encoding, so one set has one blob and one `records` hash.
pub fn encode_records(records: &Records) -> Result<Vec<u8>> {
    let mut entries: Vec<(Vec<u8>, &str, &RecordValue)> = records
        .iter()
        .map(|(k, v)| {
            let mut key = Vec::new();
            cbor_text(k, &mut key);
            (key, k.as_str(), v)
        })
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    cbor_head(5, entries.len(), &mut out);
    for (key, name, value) in entries {
        out.extend_from_slice(&key);
        match value {
            RecordValue::Text(s) => cbor_text(s, &mut out),
            RecordValue::Flag(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
            RecordValue::Opaque { opaque } => {
                check_opaque(opaque).with_context(|| format!("record {name:?}"))?;
                out.extend_from_slice(opaque);
            }
        }
    }
    ensure!(out.len() <= CARD_BLOB_MAX, "the record set encodes to {} bytes, over the {CARD_BLOB_MAX} byte cap", out.len());
    Ok(out)
}

/// An opaque value must be one well-formed item within the depth cap, and not a text or flag item,
/// which decodes as the typed variant.
pub fn check_opaque(bytes: &[u8]) -> Result<()> {
    ensure!(!bytes.is_empty(), "opaque value is empty");
    let mut c = Cursor { bytes, at: 0 };
    c.skip(0)?;
    ensure!(c.at == bytes.len(), "opaque value is not one CBOR item");
    let head = bytes[0];
    if head >> 5 == 3 {
        let mut c = Cursor { bytes, at: 0 };
        ensure!(c.text().is_err(), "opaque value holds a text item, which belongs in that form");
        bail!("opaque value holds text that is not UTF-8, which no record set can carry");
    }
    ensure!(head != 0xf4 && head != 0xf5, "opaque value holds a flag item, which belongs in that form");
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8> {
        let b = *self.bytes.get(self.at).ok_or_else(|| anyhow!("record blob truncated"))?;
        self.at += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.bytes.len()).ok_or_else(|| anyhow!("record blob truncated"))?;
        let s = &self.bytes[self.at..end];
        self.at = end;
        Ok(s)
    }

    /// A definite-length head with at most a 4-byte argument: the major type and its argument.
    fn head(&mut self) -> Result<(u8, usize)> {
        let b = self.byte()?;
        let (major, info) = (b >> 5, b & 0x1f);
        let n = match info {
            0..=23 => info as usize,
            24 => self.byte()? as usize,
            25 => u16::from_be_bytes(self.take(2)?.try_into()?) as usize,
            26 => u32::from_be_bytes(self.take(4)?.try_into()?) as usize,
            _ => bail!("record blob uses an unsupported CBOR head {b:#04x}"),
        };
        Ok((major, n))
    }

    fn text(&mut self) -> Result<String> {
        let (major, n) = self.head()?;
        ensure!(major == 3, "record key or value is not text");
        Ok(std::str::from_utf8(self.take(n)?).map_err(|_| anyhow!("record text is not UTF-8"))?.to_owned())
    }

    /// Skips one item by RFC 8949's table, refusing a container nested past `RECORD_DEPTH_MAX`.
    fn skip(&mut self, enclosing: usize) -> Result<()> {
        let b = self.byte()?;
        let (major, info) = (b >> 5, b & 0x1f);
        let unsupported = || anyhow!("record blob uses an unsupported CBOR head {b:#04x}");
        // No conforming encoder writes an 8-byte length under the blob cap.
        let argument = |c: &mut Self| -> Result<usize> {
            Ok(match info {
                0..=23 => info as usize,
                24 => c.byte()? as usize,
                25 => u16::from_be_bytes(c.take(2)?.try_into()?) as usize,
                26 => u32::from_be_bytes(c.take(4)?.try_into()?) as usize,
                27 if matches!(major, 0 | 1 | 6) => {
                    c.take(8)?;
                    0
                }
                _ => return Err(unsupported()),
            })
        };
        let deeper = |_: &mut Self| -> Result<usize> {
            ensure!(enclosing < RECORD_DEPTH_MAX, "record value nests too deep, past {RECORD_DEPTH_MAX} containers");
            Ok(enclosing + 1)
        };
        match major {
            0 | 1 => {
                argument(self)?;
            }
            2 | 3 => {
                let n = argument(self)?;
                self.take(n)?;
            }
            4 => {
                let n = argument(self)?;
                let inner = deeper(self)?;
                for _ in 0..n {
                    self.skip(inner)?;
                }
            }
            5 => {
                let n = argument(self)?;
                let inner = deeper(self)?;
                for _ in 0..n.saturating_mul(2) {
                    self.skip(inner)?;
                }
            }
            6 => {
                argument(self)?;
                let inner = deeper(self)?;
                self.skip(inner)?;
            }
            _ => match info {
                0..=23 => {}
                24 => {
                    // A simple value below 32 in the one-byte form is ill-formed (RFC 8949 §3.3).
                    ensure!(self.byte()? >= 0x20, "record blob uses an unsupported CBOR head {b:#04x}");
                }
                25 => {
                    self.take(2)?;
                }
                26 => {
                    self.take(4)?;
                }
                27 => {
                    self.take(8)?;
                }
                _ => return Err(unsupported()),
            },
        }
        Ok(())
    }
}

/// Accepts any well-formed map with text keys, and carries each value that is not text or a flag as
/// opaque.
pub fn decode_records(blob: &[u8]) -> Result<Records> {
    ensure!(blob.len() <= CARD_BLOB_MAX, "record blob is {} bytes, over the {CARD_BLOB_MAX} byte cap", blob.len());
    let mut c = Cursor { bytes: blob, at: 0 };
    let (major, n) = c.head()?;
    ensure!(major == 5, "record blob is not a CBOR map");
    let mut records = Records::new();
    for _ in 0..n {
        let key = c.text()?;
        // Text and flags are recognized only directly under the map. Inside a skipped item they
        // are bytes.
        let value = match c.bytes.get(c.at) {
            Some(0xf4) => {
                c.at += 1;
                RecordValue::Flag(false)
            }
            Some(0xf5) => {
                c.at += 1;
                RecordValue::Flag(true)
            }
            Some(b) if b >> 5 == 3 => RecordValue::Text(c.text()?),
            _ => {
                let start = c.at;
                c.skip(0)?;
                RecordValue::Opaque { opaque: blob[start..c.at].to_vec() }
            }
        };
        ensure!(records.insert(key.clone(), value).is_none(), "record key {key:?} appears twice");
    }
    ensure!(c.at == blob.len(), "record blob carries {} trailing bytes", blob.len() - c.at);
    Ok(records)
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&faster_hex::hex_string(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let mut v = vec![0u8; s.len() / 2];
        faster_hex::hex_decode(s.as_bytes(), &mut v).map_err(serde::de::Error::custom)?;
        Ok(v)
    }
}

pub const SUBNAME_PREFIX: &str = "sub:";

/// Runs the label rule, so no writer pays for an entry that no lookup reaches.
pub fn subname_key(label: &str) -> Result<String, SubnameFault> {
    validate_label(label)?;
    Ok(format!("{SUBNAME_PREFIX}{label}"))
}

/// The CBOR head `0x58 0x21`, the scheme byte and the 32-byte payload.
pub const SUBNAME_VALUE_LEN: usize = 2 + 1 + 32;

/// One 33-byte CBOR byte string: the scheme byte and the payload. It carries no network prefix, so no
/// card can name a payee on the wrong network. A covenant id is refused because no reader can pay one.
pub fn subname_value(owner_type: OwnerType, owner: &[u8; 32]) -> Result<RecordValue, SubnameFault> {
    if owner_type == OwnerType::CovenantId {
        return Err(SubnameFault::HeldByCovenant);
    }
    address::check_payload(owner_type, owner)?;
    let mut opaque = Vec::with_capacity(SUBNAME_VALUE_LEN);
    opaque.extend_from_slice(&[0x58, 0x21, owner_type as u8]);
    opaque.extend_from_slice(owner);
    Ok(RecordValue::Opaque { opaque })
}

/// The owner pair one stored entry names, or why it names none.
pub fn subname_pair(key: &str, value: &RecordValue) -> Result<(OwnerType, [u8; 32]), SubnameFault> {
    // A key without the prefix is a caller bug. The payload names the prefix, so the fault does
    // not read as a verdict on a label.
    let label =
        key.strip_prefix(SUBNAME_PREFIX).ok_or_else(|| SubnameFault::BadLabel(format!("{key} carries no {SUBNAME_PREFIX} prefix")))?;
    validate_label(label)?;
    let RecordValue::Opaque { opaque } = value else {
        return Err(SubnameFault::NotBytes);
    };
    let head = *opaque.first().ok_or(SubnameFault::NotBytes)?;
    if head >> 5 != 2 {
        return Err(SubnameFault::NotBytes);
    }
    // Exactly the head `0x58 0x21` and the pair, so every implementation agrees on one byte
    // comparison. The same bytes under a wider head are another shape.
    if opaque.len() != SUBNAME_VALUE_LEN || opaque[0] != 0x58 || opaque[1] != 0x21 {
        return Err(SubnameFault::BadLength);
    }
    let scheme = OwnerType::from_byte(opaque[2]).ok_or(SubnameFault::BadScheme)?;
    if scheme == OwnerType::CovenantId {
        return Err(SubnameFault::HeldByCovenant);
    }
    let payload: [u8; 32] = opaque[3..].try_into().expect("35 - 3 == 32");
    address::check_payload(scheme, &payload)?;
    Ok((scheme, payload))
}

/// The payee a label names on a card that [`verify`] passed. A parent that a covenant holds names
/// nothing.
pub fn subname_of(owner_type: OwnerType, records: &Records, label: &str, prefix: Prefix) -> Result<Option<Address>, SubnameFault> {
    if owner_type == OwnerType::CovenantId {
        return Err(SubnameFault::ParentInCovenant);
    }
    let key = subname_key(label)?;
    let Some(value) = records.get(&key) else {
        return Ok(None);
    };
    let (scheme, payload) = subname_pair(&key, value)?;
    Ok(Some(address::owner_address(prefix, scheme, &payload).expect("subname_pair refuses the one scheme with no address")))
}

/// Every `sub:` entry in map order with its verdict. Refused entries are listed, because a writer that
/// cannot see an entry destroys it or signs it unseen.
pub fn subnames(owner_type: OwnerType, records: &Records, prefix: Prefix) -> Vec<(String, Result<Address, SubnameFault>)> {
    records
        .iter()
        .filter(|(key, _)| key.starts_with(SUBNAME_PREFIX))
        .map(|(key, value)| {
            let verdict = if owner_type == OwnerType::CovenantId {
                Err(SubnameFault::ParentInCovenant)
            } else {
                subname_pair(key, value)
                    .map(|(s, p)| address::owner_address(prefix, s, &p).expect("subname_pair refuses the one scheme with no address"))
            };
            (key[SUBNAME_PREFIX.len()..].to_string(), verdict)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records() -> Records {
        let mut r = Records::new();
        r.insert("url".into(), RecordValue::Text("https://kaspa.org".into()));
        r.insert(PRIMARY_KEY.into(), RecordValue::Flag(true));
        r.insert("com.github".into(), RecordValue::Text("kaspanet".into()));
        r.insert("a".into(), RecordValue::Text("".into()));
        r
    }

    /// A wrong per-scheme offset misses a real sweep.
    #[test]
    fn a_sweep_sig_script_reads_back_the_card_it_spends() {
        let sig = [9u8; SIG_LEN];
        for (spender_type, spender) in
            [(OwnerType::Pubkey, [0x11u8; 32]), (OwnerType::P2pkEcdsaOdd, [0x22u8; 32]), (OwnerType::P2pkEcdsaEven, [0x33u8; 32])]
        {
            let state = CardState::new([1u8; 32], [2u8; 32], spender_type, spender).unwrap();
            assert_eq!(CardState::swept_by(&state.sweep_sig_script(Some(&sig))), Some(state));
        }
        assert_eq!(CardState::swept_by(&[0x41; 70]), None);
    }

    #[test]
    fn a_record_set_round_trips_and_encodes_deterministically() {
        let blob = encode_records(&records()).unwrap();
        assert_eq!(decode_records(&blob).unwrap(), records());
        // Shorter keys first, then bytewise: "a", "url", "primary", "com.github".
        assert_eq!(&blob[..2], &[0xa4, 0x61], "a four-entry map whose first key is the one-byte text");
        assert_eq!(blob, encode_records(&decode_records(&blob).unwrap()).unwrap());
    }

    #[test]
    fn a_blob_that_is_not_a_map_of_text_is_refused() {
        assert!(decode_records(&[0x80]).is_err(), "an array");
        assert!(decode_records(&[0xa1, 0x01, 0x61, 0x78]).is_err(), "an integer key");
        // An integer value is not refused: it is carried as one opaque item, byte for byte.
        let carried = decode_records(&[0xa1, 0x61, 0x78, 0x01]).unwrap();
        assert_eq!(carried.get("x"), Some(&RecordValue::Opaque { opaque: vec![0x01] }), "an integer value is opaque");
        assert_eq!(encode_records(&carried).unwrap(), [0xa1, 0x61, 0x78, 0x01], "and re-encodes identically");
        assert!(decode_records(&[0xa2, 0x61, 0x78, 0xf5, 0x61, 0x78, 0xf4]).is_err(), "a duplicate key");
        assert!(decode_records(&[0xa0, 0x00]).is_err(), "trailing bytes");
        assert!(decode_records(&[0xa1, 0x61]).is_err(), "truncated");
        assert_eq!(decode_records(&[0xa0]).unwrap(), Records::new(), "the empty map is a record set");
    }

    #[test]
    fn nesting_is_carried_to_the_depth_cap_and_refused_past_it() {
        for container in [0x81u8, 0xc6] {
            let mut at_cap = vec![0xa1, 0x61, 0x78];
            at_cap.extend(std::iter::repeat_n(container, RECORD_DEPTH_MAX));
            at_cap.push(0x01);
            let records = decode_records(&at_cap).unwrap();
            assert_eq!(encode_records(&records).unwrap(), at_cap, "{container:#04x} at the cap");

            let mut over = vec![0xa1, 0x61, 0x78];
            over.extend(std::iter::repeat_n(container, RECORD_DEPTH_MAX + 1));
            over.push(0x01);
            let why = format!("{:#}", decode_records(&over).unwrap_err());
            assert!(why.contains("too deep"), "{container:#04x} over the cap: {why}");

            let mut deep = Records::new();
            let mut item: Vec<u8> = std::iter::repeat_n(container, RECORD_DEPTH_MAX + 1).collect();
            item.push(0x01);
            deep.insert("x".into(), RecordValue::Opaque { opaque: item });
            let why = format!("{:#}", encode_records(&deep).unwrap_err());
            assert!(why.contains("too deep"), "encoder: {why}");
        }
    }

    #[test]
    fn the_encoder_refuses_an_opaque_value_it_cannot_carry() {
        let cases: [(&[u8], &str, &str); 7] = [
            (&[], "an empty value", "empty"),
            (&[0xff], "the break code", "unsupported CBOR head"),
            (&[0x82, 0x01], "a truncated item", "truncated"),
            (&[0x01, 0x02], "two items", "one CBOR item"),
            (&[0x61, 0x61], "a text item", "text item"),
            (&[0x61, 0xff], "text that is not UTF-8", "not UTF-8"),
            (&[0xf5], "a bare flag", "flag item"),
        ];
        for (bytes, what, class) in cases {
            let mut r = Records::new();
            r.insert("x".into(), RecordValue::Opaque { opaque: bytes.to_vec() });
            let why = format!("{:#}", encode_records(&r).unwrap_err());
            assert!(why.contains(class), "{what}: expected {class:?} in {why:?}");
        }
    }

    #[test]
    fn a_payload_round_trips_and_a_lying_one_is_refused() {
        let key = crate::names::key_of("kaspa");
        let next = DeedState::active(key, OwnerType::Pubkey, [7u8; 32], crate::names::padded_name("kaspa"));
        let blob = encode_records(&records()).unwrap();
        let mint = CardMint::for_deed(&next, blob.clone(), OwnerType::Pubkey, [7u8; 32]).unwrap();
        let payload = encode_payload(Some(&mint)).unwrap();
        assert_eq!(&payload[..5], b"dotk\x01");
        assert_eq!(decode_payload(&payload).unwrap(), Some(mint.clone()));
        assert_eq!(decode_payload(b"").unwrap(), None, "an empty payload is not a card payload");
        assert_eq!(decode_payload(b"hello world").unwrap(), None, "another payload is not ours");

        let mut tampered = payload.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(decode_payload(&tampered).is_err(), "a blob the state does not commit to");
        assert!(decode_payload(&payload[..payload.len() - 1]).is_err(), "a truncated blob");
        assert!(decode_payload(b"dotk\x01").is_err(), "a payload declaring no card");
        assert!(decode_payload(b"dotk\x02").is_err(), "a version this reader does not know");

        // A second card makes the payload malformed, so the reader takes neither card.
        let second = [&payload[..], &payload[5..]].concat();
        let why = decode_payload(&second).unwrap_err().to_string();
        assert!(why.contains("after its card"), "{why}");
        assert!(decode_payload(&[&payload[..], b"\x00"].concat()).is_err(), "a trailing byte is malformed too");

        assert!(encode_payload(None).unwrap().is_empty(), "no mint, no payload");
    }

    #[test]
    fn the_five_rules_each_refuse_what_they_are_for() {
        let key = crate::names::key_of("kaspa");
        let deed = crate::intents::DeedUtxo {
            outpoint: Outpoint { transaction_id: "aa".repeat(32), index: 0 },
            value: 1,
            state: DeedState::active(key, OwnerType::Pubkey, [7u8; 32], crate::names::padded_name("kaspa")),
            covenant_id: "cc".repeat(32),
        };
        let blob = encode_records(&records()).unwrap();
        let card = CardState::new(key, records_of(&blob), OwnerType::Pubkey, [7u8; 32]).unwrap();
        let live = Outpoint { transaction_id: "aa".repeat(32), index: 1 };
        verify(&deed, &card, Some(&live), &blob).expect("a card born beside the deed");

        let why = |r: Result<()>| r.unwrap_err().to_string();
        assert!(why(verify(&deed, &card, None, &blob)).starts_with("rule 1"));
        let stale = Outpoint { transaction_id: "bb".repeat(32), index: 1 };
        assert!(why(verify(&deed, &card, Some(&stale), &blob)).starts_with("rule 2"));
        let second = Outpoint { transaction_id: "aa".repeat(32), index: 2 };
        assert!(why(verify(&deed, &card, Some(&second), &blob)).starts_with("rule 2"), "another output of the same transaction");
        assert!(why(verify(&deed, &card, Some(&live), b"other")).starts_with("rule 3"));
        assert!(why(verify(&deed, &card, Some(&live), &vec![0; CARD_BLOB_MAX + 1])).starts_with("rule 4"));
        let pending = crate::intents::DeedUtxo { state: DeedState::pending(key, [9u8; 32]), ..deed.clone() };
        assert!(why(verify(&pending, &card, Some(&live), &blob)).starts_with("rule 5"));
        let escrow = crate::intents::DeedUtxo { state: DeedState { owner_type: OwnerType::CovenantId, ..deed.state }, ..deed.clone() };
        assert!(why(verify(&escrow, &card, Some(&live), &blob)).starts_with("rule 5"), "a name in escrow carries no records");
        let other = CardState::new([5u8; 32], records_of(&blob), OwnerType::Pubkey, [7u8; 32]).unwrap();
        assert!(why(verify(&deed, &other, Some(&live), &blob)).contains("another name"));
    }

    fn schnorr_x(secret: &[u8; 32]) -> [u8; 32] {
        secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, secret).unwrap().x_only_public_key().0.serialize()
    }

    /// A value built byte by byte, for the cases `subname_value` refuses to write.
    fn opaque_pair(scheme: u8, payload: &[u8; 32]) -> RecordValue {
        let mut opaque = vec![0x58, 0x21, scheme];
        opaque.extend_from_slice(payload);
        RecordValue::Opaque { opaque }
    }

    fn one_card(key: &str, value: RecordValue) -> Records {
        let mut r = Records::new();
        r.insert(key.to_string(), value);
        r
    }

    #[test]
    fn subname_of_names_the_fault_of_every_refused_value() {
        let x = schnorr_x(&[7u8; 32]);
        let mut short = vec![0x58, 0x20];
        short.extend_from_slice(&x);
        let cases: Vec<(RecordValue, &str, &str)> = vec![
            (RecordValue::Text("kaspa:qqq".into()), "not-bytes", "text, whatever it spells"),
            (RecordValue::Flag(true), "not-bytes", "a flag"),
            (RecordValue::Opaque { opaque: vec![0x18, 0x2a] }, "not-bytes", "an integer item"),
            (RecordValue::Opaque { opaque: short }, "bad-length", "a byte string of 32 bytes"),
            (opaque_pair(0xfe, &x), "bad-scheme", "a scheme byte nobody has proposed"),
            (opaque_pair(0x04, &x), "held-by-covenant", "a covenant id"),
            (opaque_pair(0x04, &[0u8; 32]), "held-by-covenant", "a covenant id over a zero payload, judged as the covenant id"),
            (opaque_pair(0x00, &[0u8; 32]), "zero-payload", "a zero payload under a key scheme"),
            (opaque_pair(0x00, &[0xffu8; 32]), "not-a-point", "a schnorr key that is no curve point"),
        ];
        for (value, tag, why) in cases {
            let records = one_card(&subname_key("bob").unwrap(), value);
            let fault = subname_of(OwnerType::Pubkey, &records, "bob", Prefix::Testnet).expect_err(why);
            assert_eq!(fault.tag(), tag, "{why}");
            assert_eq!(subnames(OwnerType::Pubkey, &records, Prefix::Testnet)[0].1.as_ref().unwrap_err().tag(), tag, "{why}");
        }
    }

    #[test]
    fn subname_pair_takes_one_item_shape_and_refuses_every_other_byte_string() {
        let x = schnorr_x(&[7u8; 32]);
        let key = subname_key("bob").unwrap();
        let with_head = |head: &[u8]| {
            let mut v = head.to_vec();
            v.push(0x00);
            v.extend_from_slice(&x);
            v
        };
        let mut indefinite = with_head(&[0x5f, 0x58, 0x21]);
        indefinite.push(0xff);
        let mut trailing = with_head(&[0x58, 0x21]);
        trailing.push(0x00);
        for (opaque, why) in [
            (with_head(&[0x59, 0x00, 0x21]), "a two-byte length head for a length one byte carries"),
            (with_head(&[0x5a, 0x00, 0x00, 0x00, 0x21]), "a four-byte length head"),
            (indefinite, "the indefinite-length head"),
            (trailing, "one trailing byte past the item"),
            (vec![0x58u8], "a head that carries no length"),
            (vec![0x58u8, 0x21], "a head that promises 33 bytes and carries none"),
            (vec![0x57u8; 24], "a short-form byte string"),
        ] {
            let fault = subname_pair(&key, &RecordValue::Opaque { opaque }).unwrap_err();
            assert_eq!(fault.tag(), "bad-length", "{why}");
        }
        assert_eq!(subname_pair(&key, &RecordValue::Opaque { opaque: vec![] }).unwrap_err().tag(), "not-bytes");
        let value = subname_value(OwnerType::Pubkey, &x).unwrap();
        let fault = subname_pair("url", &value).unwrap_err();
        assert_eq!(fault, SubnameFault::BadLabel(format!("url carries no {SUBNAME_PREFIX} prefix")));
        assert_eq!(fault.tag(), "bad-label");
        assert!(subname_pair(&key, &value).is_ok());
        let RecordValue::Opaque { opaque } = &value else { panic!("a subname value is a byte string") };
        assert_eq!(opaque.len(), SUBNAME_VALUE_LEN);
    }
}
