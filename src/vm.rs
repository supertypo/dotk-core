//! Local pre-flight: run a transaction's covenant inputs on the script engine that consensus
//! uses, with the same flags, before broadcast. The error names the input and the reason.

use anyhow::{Result, anyhow, ensure};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::{PopulatedTransaction, Transaction, UtxoEntry};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
use kaspa_txscript_errors::TxScriptError;

/// Execute one input with covenants enabled. The caller checks the index against the inputs
/// first, because the engine panics on an index out of range.
pub(crate) fn execute_input(
    populated: &PopulatedTransaction,
    cov_ctx: &CovenantsContext,
    input_index: usize,
) -> Result<(), TxScriptError> {
    let reused = SigHashReusedValuesUnsync::new();
    let sig_cache = Cache::new(10_000);
    let mut vm = TxScriptEngine::from_transaction_input(
        populated,
        &populated.tx.inputs[input_index],
        input_index,
        &populated.entries[input_index],
        EngineCtx::new(&sig_cache).with_reused(&reused).with_covenants_ctx(cov_ctx),
        EngineFlags { covenants_enabled: true, ..Default::default() },
    );
    vm.execute()
}

/// Execute `covenant_inputs` of `tx` against `entries`, the UTXO entries in input order.
pub fn preflight(tx: &Transaction, entries: &[UtxoEntry], covenant_inputs: &[usize]) -> Result<()> {
    ensure!(entries.len() == tx.inputs.len(), "entries/inputs length mismatch");
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let cov_ctx = CovenantsContext::from_tx(&populated).map_err(|e| anyhow!("covenant context: {e:?}"))?;
    for &idx in covenant_inputs {
        ensure!(idx < tx.inputs.len(), "no input at {idx}");
        execute_input(&populated, &cov_ctx, idx).map_err(|e| anyhow!("pre-flight VM failure on input {idx}: {e:?}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionInput, TransactionOutpoint, TransactionOutput};
    use kaspa_txscript::opcodes::codes::{OpFalse, OpTrue};

    fn one_input_tx(spk: Vec<u8>) -> (Transaction, Vec<UtxoEntry>) {
        let spk = ScriptPublicKey::from_vec(0, spk);
        let input =
            TransactionInput::new(TransactionOutpoint::new(kaspa_consensus_core::Hash::from_bytes([3u8; 32]), 0), vec![], 0, 1);
        let tx = Transaction::new(1, vec![input], vec![TransactionOutput::new(500, spk.clone())], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        (tx, vec![UtxoEntry::new(1000, spk, 0, false, None)])
    }

    #[test]
    fn the_engines_verdict_is_the_pre_flight_verdict() {
        let (tx, entries) = one_input_tx(vec![OpTrue]);
        preflight(&tx, &entries, &[0]).expect("an input that leaves true on the stack passes");
        let (tx, entries) = one_input_tx(vec![OpFalse]);
        let why = preflight(&tx, &entries, &[0]).unwrap_err().to_string();
        assert!(why.contains("input 0"), "the error names the input: {why}");
    }

    /// The covenant bindings are checked even when no input is executed.
    #[test]
    fn a_bad_covenant_binding_is_refused_with_no_input_executed() {
        use kaspa_consensus_core::tx::CovenantBinding;
        let (mut tx, entries) = one_input_tx(vec![OpTrue]);
        tx.outputs[0].covenant =
            Some(CovenantBinding { covenant_id: kaspa_consensus_core::Hash::from_bytes([1u8; 32]), authorizing_input: 7 });
        let why = preflight(&tx, &entries, &[]).unwrap_err().to_string();
        assert!(why.starts_with("covenant context"), "{why}");
    }

    /// A malformed call is refused before the engine, which panics on it.
    #[test]
    fn a_malformed_call_is_refused_rather_than_run() {
        let (tx, entries) = one_input_tx(vec![OpTrue]);
        assert!(preflight(&tx, &entries, &[1]).unwrap_err().to_string().contains("no input at 1"));
        assert!(preflight(&tx, &[], &[0]).unwrap_err().to_string().contains("length mismatch"));
    }
}
