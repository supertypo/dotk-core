//! What to do about a transaction the node refused: three outcomes of the mempool's taxonomy
//! (`kaspa_mining_errors::mempool::RuleError`), classified from its rendered message.

/// The verdict on a refused submission. `None` from [`Rejection::of`] means the failure was not
/// a mempool verdict, such as a dropped socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The node can accept the same bytes later: an orphan, an immature coinbase, a full mempool.
    /// Back off and re-offer the same bytes.
    Transient,
    /// The caller's view of its own coins is stale: the node has seen this transaction, or another
    /// of the caller's transactions spent the input. Rebuild against a fresh selection.
    Stale,
    /// The transaction is wrong and stays wrong: over a mass limit, or non-standard.
    Fatal,
}

impl Rejection {
    /// Classify by the mempool's rendered message, because wRPC returns `submitTransaction`
    /// failures as free text. The fragments come from `RuleError`'s `#[error(...)]` strings, and
    /// a test pins each one to the real `RuleError` value.
    pub fn of_message(msg: &str) -> Option<Self> {
        let has = |needle: &str| msg.contains(needle);
        // Fatal first, because the nested reason of a non-standard rejection can contain any other
        // fragment.
        if has("is larger than max allowed size of")
            || has("is not standard:")
            || has("impossible to have a matching UTXO entry")
            || has("due to incomputable storage mass")
        {
            return Some(Rejection::Fatal);
        }
        if has("already spent by transaction") || has("is already in the mempool") || has("already accepted by the consensus") {
            return Some(Rejection::Stale);
        }
        if has("is an orphan where orphan is disallowed")
            || has("lacking a matching UTXO entry")
            || has("spends an immature UTXO")
            || has("full with transactions with higher priority")
        {
            return Some(Rejection::Transient);
        }
        None
    }

    /// The same, over an error and its whole cause chain.
    pub fn of(e: &anyhow::Error) -> Option<Self> {
        Self::of_message(&format!("{e:#}"))
    }

    /// A stable one-word tag, for a caller that carries the verdict across an untyped boundary such
    /// as JavaScript.
    pub fn tag(self) -> &'static str {
        match self {
            Rejection::Transient => "transient",
            Rejection::Stale => "stale",
            Rejection::Fatal => "fatal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    /// Each verdict is checked against the rendered `RuleError` value, so an upstream rewording
    /// fails here.
    #[test]
    fn every_rejection_verdict_is_pinned_to_the_mempools_own_wording() {
        use kaspa_mining_errors::mempool::RuleError;
        let id = kaspa_consensus_core::tx::TransactionId::default();
        let outpoint = kaspa_consensus_core::tx::TransactionOutpoint::new(id, 0);
        let cap = 100_000;
        let cases: Vec<(RuleError, Option<Rejection>)> = vec![
            // Wait: the node can accept the input later.
            (RuleError::RejectDisallowedOrphan(id), Some(Rejection::Transient)),
            (RuleError::RejectMissingOutpoint, Some(Rejection::Transient)),
            (RuleError::RejectMempoolIsFull, Some(Rejection::Transient)),
            // Re-select: the caller's view of its coins is behind.
            (RuleError::RejectDoubleSpendInMempool(outpoint, id), Some(Rejection::Stale)),
            (RuleError::RejectDuplicate(id), Some(Rejection::Stale)),
            (RuleError::RejectAlreadyAccepted(id), Some(Rejection::Stale)),
            // Give up. The three
            // mass cases are ones `crate::fees::refuse_if_overweight` measures before a wallet is
            // asked to sign, so reaching this classifier means a node applied a limit this build
            // did not know about.
            (RuleError::RejectStorageMass(id, cap + 1, cap), Some(Rejection::Fatal)),
            (RuleError::RejectComputeMass(id, cap + 1, cap), Some(Rejection::Fatal)),
            (RuleError::RejectTransientMass(id, cap + 1, cap), Some(Rejection::Fatal)),
            (RuleError::RejectNonStandard(id, "dust".into()), Some(Rejection::Fatal)),
            (RuleError::RejectImpossibleOutpoint, Some(Rejection::Fatal)),
        ];
        for (rule, want) in cases {
            let rendered = rule.to_string();
            assert_eq!(Rejection::of(&anyhow!("submit failed: {rendered}")), want, "verdict for {rendered:?}");
        }
        // A fault that is not a mempool verdict at all stays unclassified.
        assert_eq!(Rejection::of(&anyhow!("WebSocket connection closed")), None);
    }

    /// A caller across an untyped boundary compares against these exact words.
    #[test]
    fn the_tags_are_stable() {
        assert_eq!(Rejection::Transient.tag(), "transient");
        assert_eq!(Rejection::Stale.tag(), "stale");
        assert_eq!(Rejection::Fatal.tag(), "fatal");
    }
}
