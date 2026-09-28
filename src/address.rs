//! P2SH addresses from covenant state. A gap's address depends on its interval alone and a deed's on
//! `(name, owner)` alone, so every client derives them without trusting anyone.

use anyhow::{Result, bail};
use kaspa_addresses::{Address, Prefix, Version as AddrVersion};

use crate::contracts::Template;
use crate::names::{SubnameFault, key_of, try_padded_name};
use crate::state::{DeedState, GapState, OwnerType, Status};

/// The most addresses a client puts in one `getUtxosByAddresses` request.
pub const PROBE_CHUNK: usize = 800;

pub fn prefix_for(network: &str) -> Result<Prefix> {
    Ok(match network {
        "mainnet" => Prefix::Mainnet,
        "testnet-10" | "testnet" => Prefix::Testnet,
        "simnet" => Prefix::Simnet,
        "devnet" => Prefix::Devnet,
        other => bail!("unknown network {other}"),
    })
}

/// `p2sh_spk` emits `0xaa 0x20 <hash> 0x87`, so the hash is at `[2..34]`.
fn p2sh_address(template: &Template, prefix: Prefix, state: &[u8]) -> Result<Address> {
    let spk = template.p2sh_spk(state)?;
    Ok(Address::new(prefix, AddrVersion::ScriptHash, &spk[2..34]))
}

pub fn gap_address(gap_template: &Template, prefix: Prefix, state: &GapState) -> Result<Address> {
    p2sh_address(gap_template, prefix, &state.encode())
}

pub fn deed_address(deed_template: &Template, prefix: Prefix, state: &DeedState) -> Result<Address> {
    p2sh_address(deed_template, prefix, &state.encode())
}

/// The KCC-2 owner record an address stands for: schnorr `p2pk-schnorr/v1` (0x00), ECDSA
/// `p2pk-ecdsa/v1` with the parity in the scheme byte (0x86 even, 0x85 odd), P2SH `p2sh/v1` (0x03).
/// `p2pkh-schnorr/v1` is unreachable on purpose, because a second form of a schnorr owner doubles
/// every probe.
pub fn owner_of(address: &Address) -> Result<(OwnerType, [u8; 32])> {
    match address.version {
        AddrVersion::PubKey | AddrVersion::ScriptHash => {
            let owner_type = if address.version == AddrVersion::PubKey { OwnerType::Pubkey } else { OwnerType::ScriptHash };
            let payload =
                <[u8; 32]>::try_from(address.payload.as_slice()).map_err(|_| anyhow::anyhow!("address payload is not 32 bytes"))?;
            Ok((owner_type, payload))
        }
        AddrVersion::PubKeyECDSA => {
            let key = <[u8; 33]>::try_from(address.payload.as_slice())
                .map_err(|_| anyhow::anyhow!("ECDSA address payload is not 33 bytes"))?;
            // Parity comes only from an address. With the wrong parity x names the negated point, so a
            // one-bit slip mints a deed no wallet can spend.
            let owner_type = OwnerType::p2pk_ecdsa(key[0])
                .ok_or_else(|| anyhow::anyhow!("ECDSA address payload has SEC1 prefix {:#04x}, expected 0x02 or 0x03", key[0]))?;
            Ok((owner_type, key[1..].try_into().expect("33 - 1 == 32")))
        }
    }
}

/// The ACTIVE deed address for a bare name and a raw owner scheme byte. Refuses an invalid name
/// instead of panicking.
pub fn deed_address_of(deed_template: &Template, prefix: Prefix, name: &str, owner_type: u8, owner: &[u8; 32]) -> Result<Address> {
    let ot = OwnerType::from_byte(owner_type).ok_or_else(|| anyhow::anyhow!("unknown owner type {owner_type}"))?;
    let padded = try_padded_name(name).map_err(|e| anyhow::anyhow!("{e}"))?;
    let state = DeedState { status: Status::Active, key: key_of(name), owner_type: ot, owner: *owner, name: padded };
    deed_address(deed_template, prefix, &state)
}

/// The inverse of [`owner_of`], or `None` for a covenant id.
pub fn owner_address(prefix: Prefix, owner_type: OwnerType, owner: &[u8; 32]) -> Option<Address> {
    match owner_type {
        OwnerType::Pubkey => Some(Address::new(prefix, AddrVersion::PubKey, owner)),
        OwnerType::ScriptHash => Some(Address::new(prefix, AddrVersion::ScriptHash, owner)),
        OwnerType::P2pkEcdsaEven | OwnerType::P2pkEcdsaOdd => {
            Some(Address::new(prefix, AddrVersion::PubKeyECDSA, &owner_type.compressed_key(owner)?))
        }
        OwnerType::CovenantId => None,
    }
}

/// Every test an owner payload must pass, as a deed owner or a subname payee. No scheme can satisfy
/// a zero payload, and the covenant cannot check that a key is a curve point, so an off-curve key
/// locks a deed and its bond forever. `CardState::new` keeps only the zero test, because readers
/// build card states from chain data.
pub fn check_payload(scheme: OwnerType, payload: &[u8; 32]) -> Result<(), SubnameFault> {
    if *payload == crate::state::ZERO32 {
        return Err(SubnameFault::ZeroPayload);
    }
    if !scheme.needs_signature() {
        return Ok(());
    }
    let on_curve = match scheme.compressed_key(payload) {
        Some(compressed) => secp256k1::PublicKey::from_slice(&compressed).map(|_| ()),
        None => secp256k1::XOnlyPublicKey::from_slice(payload).map(|_| ()),
    };
    on_curve.map_err(|e| SubnameFault::NotAPoint(e.to_string()))
}

/// Copied from `kaspa_addresses`, whose own table is private.
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The data-part length for `bytes` bytes of version and payload, checksum included.
fn data_len_for(bytes: usize) -> usize {
    bytes * 8 / 5 + usize::from(!bytes.is_multiple_of(5)) + 8
}

/// A Kaspa address from untrusted text. `Address::try_from` panics on a checksum-valid string of the
/// wrong payload length, so the version is read first and any other length refused.
pub fn parse(text: &str, prefix: Prefix) -> Result<Address, String> {
    let (got, data) = text.split_once(':').ok_or("the address carries no network prefix")?;
    if got != prefix.to_string() {
        return Err(format!("the address is for {got}, and this registry is on {prefix}"));
    }
    // The version byte spans the first two characters.
    let five = |i: usize| data.as_bytes().get(i).and_then(|c| BECH32_CHARSET.iter().position(|x| x == c));
    let (Some(hi), Some(lo)) = (five(0), five(1)) else {
        return Err("the address carries no version".to_string());
    };
    let version = AddrVersion::try_from(((hi << 3) | (lo >> 2)) as u8).map_err(|e| e.to_string())?;
    let want = data_len_for(1 + version.public_key_len());
    if data.len() != want {
        let kind = match version {
            AddrVersion::PubKey => "a schnorr",
            AddrVersion::PubKeyECDSA => "an ECDSA",
            AddrVersion::ScriptHash => "a P2SH",
        };
        return Err(format!("{kind} address carries {want} characters after the prefix, and this one carries {}", data.len()));
    }
    Address::try_from(text).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_addresses::Version as V;

    #[test]
    fn every_address_backed_scheme_round_trips() {
        let x = [0x11u8; 32];
        let compressed = OwnerType::P2pkEcdsaOdd.compressed_key(&x).unwrap();

        for addr in [
            Address::new(Prefix::Testnet, V::PubKey, &x),
            Address::new(Prefix::Testnet, V::ScriptHash, &x),
            Address::new(Prefix::Testnet, V::PubKeyECDSA, &compressed),
        ] {
            let (ot, owner) = owner_of(&addr).expect("every Kaspa address maps to a scheme");
            assert_eq!(owner_address(Prefix::Testnet, ot, &owner).as_ref(), Some(&addr), "{addr} did not round-trip");
        }
    }

    fn schnorr_x(secret: &[u8; 32]) -> [u8; 32] {
        secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, secret).unwrap().x_only_public_key().0.serialize()
    }

    fn ecdsa_pair(secret: &[u8; 32]) -> (OwnerType, [u8; 32]) {
        let key = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, secret).unwrap().public_key().serialize();
        (OwnerType::p2pk_ecdsa(key[0]).unwrap(), key[1..].try_into().unwrap())
    }

    #[test]
    fn check_payload_refuses_an_x_that_is_no_curve_point_under_every_key_scheme() {
        let off_curve = [0xffu8; 32];
        assert!(secp256k1::XOnlyPublicKey::from_slice(&off_curve).is_err(), "the fixture really is off the curve");
        for scheme in [OwnerType::Pubkey, OwnerType::P2pkEcdsaEven, OwnerType::P2pkEcdsaOdd] {
            let fault = check_payload(scheme, &off_curve).expect_err("a key scheme must refuse it");
            assert_eq!(fault.tag(), "not-a-point", "{scheme:?}");
        }
        // The two schemes that commit to a preimage take it, because no client can test one.
        for scheme in [OwnerType::ScriptHash, OwnerType::CovenantId] {
            assert_eq!(check_payload(scheme, &off_curve), Ok(()), "{scheme:?}");
        }
        assert_eq!(check_payload(OwnerType::Pubkey, &schnorr_x(&[7u8; 32])), Ok(()));
        let (scheme, x) = ecdsa_pair(&[9u8; 32]);
        assert_eq!(check_payload(scheme, &x), Ok(()));
        // The other parity of the same x is the twin point, which is on the curve too.
        assert_eq!(check_payload(scheme.parity_twin().unwrap(), &x), Ok(()));
    }

    /// Builds an address string by hand, for payloads no [`Address`] holds.
    fn encode_by_hand(prefix: Prefix, version: u8, payload: &[u8]) -> String {
        fn polymod(values: impl Iterator<Item = u8>) -> u64 {
            let mut c = 1u64;
            for d in values {
                let c0 = c >> 35;
                c = ((c & 0x07ffffffff) << 5) ^ (d as u64);
                for (bit, xor) in
                    [(0x01, 0x98f2bc8e61u64), (0x02, 0x79b76d99e2), (0x04, 0xf33e5fb3c4), (0x08, 0xae2eabe2a8), (0x10, 0x1e4f43e470)]
                {
                    if c0 & bit != 0 {
                        c ^= xor;
                    }
                }
            }
            c ^ 1
        }
        fn conv8to5(bytes: &[u8]) -> Vec<u8> {
            let mut out = vec![0u8; bytes.len() * 8 / 5 + usize::from(!bytes.len().is_multiple_of(5))];
            let (mut at, mut buff, mut bits) = (0usize, 0u16, 0u32);
            for b in bytes {
                buff = (buff << 8) | *b as u16;
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    out[at] = (buff >> bits) as u8 & 0x1f;
                    buff &= (1 << bits) - 1;
                    at += 1;
                }
            }
            if bits > 0 {
                out[at] = (buff << (5 - bits)) as u8 & 0x1f;
            }
            out
        }
        let name = prefix.to_string();
        let five = conv8to5(&[&[version][..], payload].concat());
        let sum = polymod(name.bytes().map(|c| c & 0x1f).chain([0u8]).chain(five.iter().copied()).chain([0u8; 8]));
        let data: String =
            five.iter().chain(conv8to5(&sum.to_be_bytes()[3..]).iter()).map(|c| BECH32_CHARSET[*c as usize] as char).collect();
        format!("{name}:{data}")
    }

    #[test]
    fn parse_refuses_another_network_and_a_wrong_length_without_a_panic() {
        let x = schnorr_x(&[7u8; 32]);
        let address = owner_address(Prefix::Mainnet, OwnerType::Pubkey, &x).unwrap().to_string();
        assert!(parse(&address, Prefix::Testnet).is_err(), "a mainnet address is not a testnet one");
        assert!(parse(&address, Prefix::Mainnet).is_ok());
        assert!(parse(&encode_by_hand(Prefix::Mainnet, 0, &x), Prefix::Mainnet).is_ok(), "the helper writes real addresses");
        assert!(parse("kaspa:", Prefix::Mainnet).is_err(), "no version at all");
        assert!(parse(&encode_by_hand(Prefix::Mainnet, 2, &[0x11u8; 32]), Prefix::Mainnet).is_err(), "version 2");
        // Checksum-valid strings whose payload length the address crate asserts on.
        assert!(
            parse(&encode_by_hand(Prefix::Mainnet, 0, &[0x11u8; 33]), Prefix::Mainnet).is_err(),
            "33 bytes under a 32-byte version"
        );
        assert!(parse(&encode_by_hand(Prefix::Mainnet, 0, &[0x11u8; 31]), Prefix::Mainnet).is_err(), "31 bytes");
        assert!(
            parse(&encode_by_hand(Prefix::Mainnet, 1, &[0x11u8; 32]), Prefix::Mainnet).is_err(),
            "32 bytes under the ECDSA version"
        );
    }

    /// The fixture's bit stream spells 0 to 31 in 5-bit groups, so each character pins its value.
    #[test]
    fn the_bech32_alphabet_is_the_one_the_address_crate_writes_in_its_own_order() {
        let mut buf = [0u8; 33];
        for value in 0u8..32 {
            for bit in 0..5u32 {
                if value & (1 << (4 - bit)) != 0 {
                    let at = value as usize * 5 + bit as usize;
                    buf[at / 8] |= 1 << (7 - at % 8);
                }
            }
        }
        assert_eq!(buf[0], AddrVersion::PubKey as u8, "the first eight bits must spell the version this fixture claims");
        let text = Address::new(Prefix::Testnet, AddrVersion::PubKey, &buf[1..]).to_string();
        let data = text.split_once(':').expect("an address carries its prefix").1;
        assert_eq!(&data.as_bytes()[..32], &BECH32_CHARSET[..], "the alphabet, value by value, in the order the encoder writes");
        assert_eq!(data.len(), data_len_for(33));
    }
}
