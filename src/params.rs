use serde::{Deserialize, Serialize};

/// Baked into the covenant templates, so different params make a different namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    /// Full scriptPublicKey (hex) that receives registration fees. Any script type.
    pub devfund_spk: String,
    /// Activation fee tiers by name byte length, in sompi.
    pub fee_1ch: u64,
    pub fee_2ch: u64,
    pub fee_3ch: u64,
    pub fee_4ch: u64,
    pub fee_5plus: u64,
    /// Value an ACTIVE deed holds (sompi), freed to the owner at release.
    pub bond: u64,
    /// Refundable posting funded at split (sompi). Activate releases it and eviction pays it to the devfund.
    pub deposit: u64,
    /// Value of every gap UTXO (sompi). A split funds one extra gap and the exit merge frees one.
    pub gap_value: u64,
    /// Relative DAA age after which a PENDING deed can be evicted.
    pub t_evict: u64,
}

/// The ceiling on every sompi-valued param: 10,000 KAS. The covenant charges an overstated tier
/// instead of refusing it, and template bytes freeze the params, so this check at load is the only
/// refusal.
pub const MAX_PARAM_VALUE: u64 = 1_000_000_000_000;

/// The ceiling on `t_evict`: `OP_CHECKSEQUENCEVERIFY` takes a 32-bit window.
pub const MAX_T_EVICT: u64 = u32::MAX as u64;

/// The floor on every param that becomes a standalone output value: 0.2 KAS. KIP-9 storage mass
/// grows as the inverse of an output's value, and a `split` below this floor exceeds the mass limit,
/// so no registration is possible again.
pub const MIN_OUTPUT_VALUE: u64 = 20_000_000;

impl Params {
    /// [`crate::contracts::Templates::from_manifest`] calls it, so no manifest reaches a builder with
    /// values out of range.
    pub fn validate(&self) -> Result<(), String> {
        if self.devfund_spk.is_empty() {
            return Err("devfund_spk is empty, so registration fees go to nothing".to_string());
        }
        self.devfund_spk_bytes().map_err(|e| format!("devfund_spk is not valid hex: {e}"))?;

        // A sompi-valued param missing from this table is unbounded at both edges.
        for (label, value) in [
            ("bond", self.bond),
            ("deposit", self.deposit),
            ("gap_value", self.gap_value),
            ("fee_1ch", self.fee_1ch),
            ("fee_2ch", self.fee_2ch),
            ("fee_3ch", self.fee_3ch),
            ("fee_4ch", self.fee_4ch),
            ("fee_5plus", self.fee_5plus),
        ] {
            if value < MIN_OUTPUT_VALUE {
                return Err(format!(
                    "{label} is {value}, below the {MIN_OUTPUT_VALUE} sompi (0.2 KAS) floor. It becomes a \
                     protocol output on its own, and KIP-9 storage mass scales as the inverse of an \
                     output's value, so a smaller one pushes a registration past the mempool mass limit \
                     and leaves the namespace permanently unusable"
                ));
            }
            if value > MAX_PARAM_VALUE {
                return Err(format!(
                    "{label} is {value}, above the {MAX_PARAM_VALUE} sompi (10,000 KAS) ceiling. Every \
                     amount a protocol transaction pays out comes from this table, and the covenant \
                     charges the registration fee it is given rather than refusing an overstated one, so \
                     a value this large is what a registrant would be asked to hand over"
                ));
            }
        }
        // An unsigned activate leaves deposit - fee to whoever rebuilds it. Tiers need not
        // descend, so the cheapest one is the bound.
        let cheapest = [self.fee_1ch, self.fee_2ch, self.fee_3ch, self.fee_4ch, self.fee_5plus].into_iter().min().unwrap_or_default();
        if self.deposit > cheapest {
            return Err(format!(
                "deposit is {}, above the cheapest registration fee of {cheapest} sompi. `activate` takes no \
                 signature and the covenant pins only the continuation and the fee output, so every \
                 registration would leave deposit - fee unattached in an unsigned transaction whose \
                 arguments are public in the mempool, for whoever rebuilds it first",
                self.deposit
            ));
        }

        // Zero is a weak policy but a valid one, so only the opcode bounds `t_evict`.
        if self.t_evict > MAX_T_EVICT {
            return Err(format!(
                "t_evict is {}, above the {MAX_T_EVICT} ceiling. It compiles to OP_CHECKSEQUENCEVERIFY \
                 behind a 0 <= v < 2^32 window check, so a larger maturity window is one the covenant \
                 compiler cannot express",
                self.t_evict
            ));
        }
        Ok(())
    }

    pub fn devfund_spk_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut v = vec![0u8; self.devfund_spk.len() / 2];
        faster_hex::hex_decode(self.devfund_spk.as_bytes(), &mut v)?;
        Ok(v)
    }

    /// The form SPK introspection returns, 2-byte big-endian version (0) ‖ script, which the covenant
    /// compares against.
    pub fn devfund_spk_versioned(&self) -> anyhow::Result<Vec<u8>> {
        let mut v = vec![0u8, 0u8];
        v.extend(self.devfund_spk_bytes()?);
        Ok(v)
    }

    pub fn fee_for_len(&self, len: usize) -> u64 {
        match len {
            1 => self.fee_1ch,
            2 => self.fee_2ch,
            3 => self.fee_3ch,
            4 => self.fee_4ch,
            _ => self.fee_5plus,
        }
    }

    pub fn fee_for_name(&self, name: &str) -> u64 {
        self.fee_for_len(name.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sane() -> Params {
        Params {
            devfund_spk: format!("20{}ac", "11".repeat(32)),
            fee_1ch: 500_000_000,
            fee_2ch: 500_000_000,
            fee_3ch: 300_000_000,
            fee_4ch: 200_000_000,
            fee_5plus: 200_000_000,
            deposit: 200_000_000,
            bond: 900_000_000,
            gap_value: 100_000_000,
            t_evict: 120,
        }
    }

    /// An unsigned `activate` leaves `deposit - fee` open to whoever rebuilds it first, so the
    /// deposit can never exceed the cheapest tier.
    #[test]
    fn the_deposit_never_exceeds_the_cheapest_registration_fee() {
        assert_eq!(sane().deposit, sane().fee_5plus);
        assert!(sane().validate().is_ok(), "a deposit at the cheapest tier is legal");
        assert!(Params { deposit: sane().fee_5plus - 1, ..sane() }.validate().is_ok(), "and anything below it");

        let over = Params { deposit: sane().fee_5plus + 1, ..sane() };
        let why = over.validate().expect_err("one sompi of surplus is still a surplus");
        assert!(why.contains("deposit"), "the refusal names the parameter: {why}");

        // The ladder need not descend, so the rule is against the cheapest tier wherever it sits.
        let inverted = Params { fee_3ch: sane().deposit - 1, ..sane() };
        assert!(inverted.validate().is_err(), "a tier below the deposit is refused wherever it sits on the ladder");
    }

    #[test]
    fn a_parameter_set_is_range_checked_before_anything_is_built_from_it() {
        assert!(sane().validate().is_ok());

        // Every sompi param, so a row deleted from `validate`'s table fails here.
        type Set = fn(&mut Params, u64);
        let valued: [(&str, Set); 8] = [
            ("bond", |p, v| p.bond = v),
            ("deposit", |p, v| p.deposit = v),
            ("gap_value", |p, v| p.gap_value = v),
            ("fee_1ch", |p, v| p.fee_1ch = v),
            ("fee_2ch", |p, v| p.fee_2ch = v),
            ("fee_3ch", |p, v| p.fee_3ch = v),
            ("fee_4ch", |p, v| p.fee_4ch = v),
            ("fee_5plus", |p, v| p.fee_5plus = v),
        ];
        let with = |set: Set, v: u64| {
            let mut p = sane();
            set(&mut p, v);
            p
        };

        for (label, set) in valued {
            assert!(with(set, MAX_PARAM_VALUE + 1).validate().is_err(), "{label} over the ceiling must be refused");
        }
        // The largest legal set leaves room for every protocol sum inside the covenant's i64.
        let maxed = Params {
            bond: MAX_PARAM_VALUE,
            deposit: MAX_PARAM_VALUE,
            gap_value: MAX_PARAM_VALUE,
            fee_1ch: MAX_PARAM_VALUE,
            fee_2ch: MAX_PARAM_VALUE,
            fee_3ch: MAX_PARAM_VALUE,
            fee_4ch: MAX_PARAM_VALUE,
            fee_5plus: MAX_PARAM_VALUE,
            ..sane()
        };
        assert!(maxed.validate().is_ok());
        let widest = maxed.bond.checked_add(maxed.deposit).and_then(|v| v.checked_add(2 * maxed.gap_value));
        assert!(widest.is_some_and(|v| v < i64::MAX as u64), "every sum stays inside the silverscript int");

        // Below the output floor, a registration exceeds the KIP-9 storage-mass limit.
        for under in [0u64, MIN_OUTPUT_VALUE - 1] {
            for (label, set) in valued {
                assert!(with(set, under).validate().is_err(), "{label} = {under} must be refused");
            }
        }
        // Exactly at the floor is legal. The deposit is lowered too, so it stays under every tier.
        for (label, set) in valued {
            let mut p = Params { deposit: MIN_OUTPUT_VALUE, ..sane() };
            set(&mut p, MIN_OUTPUT_VALUE);
            assert!(p.validate().is_ok(), "{label} = MIN_OUTPUT_VALUE must be accepted");
        }

        // `t_evict` is an age, bounded only by what its opcode can express.
        assert!(Params { t_evict: 0, ..sane() }.validate().is_ok());
        assert!(Params { t_evict: MAX_T_EVICT, ..sane() }.validate().is_ok());
        assert!(Params { t_evict: MAX_T_EVICT + 1, ..sane() }.validate().is_err(), "past the CSV window the compiler refuses");

        assert!(Params { devfund_spk: String::new(), ..sane() }.validate().is_err());
        assert!(Params { devfund_spk: "not hex".into(), ..sane() }.validate().is_err());
    }
}
