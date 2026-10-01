//! Rebuilds every gap from the live deed keys, and proves a set of observations complete.

use std::collections::BTreeSet;

use crate::state::{GapState, Status, ZERO32};

pub const KEY_MIN: [u8; 32] = [0u8; 32];
pub const KEY_MAX: [u8; 32] = [0xffu8; 32];

/// The facts per deed that nothing derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub status: Status,
    pub key: [u8; 32],
    pub claim: [u8; 32],
}

impl Entry {
    pub fn active(key: [u8; 32]) -> Self {
        Self { status: Status::Active, key, claim: ZERO32 }
    }

    pub fn pending(key: [u8; 32], claim: [u8; 32]) -> Self {
        Self { status: Status::Pending, key, claim }
    }
}

/// Sorted and deduplicated. A repeated key emits a `(k, k)` gap that fails [`partitions`].
pub fn deed_keys(entries: &[Entry]) -> Vec<[u8; 32]> {
    let mut keys: Vec<[u8; 32]> = entries.iter().map(|e| e.key).collect();
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// n deeds give the n + 1 gaps between them, and no deeds give the genesis gap.
pub fn derive_gaps(entries: &[Entry]) -> Vec<GapState> {
    let keys = deed_keys(entries);
    let mut lo = KEY_MIN;
    let mut out = Vec::with_capacity(keys.len() + 1);
    for key in keys {
        out.push(GapState { lo, hi: key });
        lo = key;
    }
    out.push(GapState { lo, hi: KEY_MAX });
    out
}

/// The partition invariant: sorted, the gaps run from `KEY_MIN` to `KEY_MAX` end to end, and their
/// seams are exactly `keys`. It proves completeness only over gaps a node confirmed. Over
/// [`derive_gaps`] of the same keys it is a tautology.
pub fn partitions(gaps: &[GapState], keys: &[[u8; 32]]) -> bool {
    let mut sorted: Vec<&GapState> = gaps.iter().collect();
    sorted.sort_by_key(|g| (g.lo, g.hi));
    let (Some(first), Some(last)) = (sorted.first(), sorted.last()) else {
        return false;
    };
    if first.lo != KEY_MIN || last.hi != KEY_MAX {
        return false;
    }
    // An empty open interval covers nothing, and the seam checks alone let it swallow a key.
    if sorted.iter().any(|g| g.lo >= g.hi) {
        return false;
    }
    let expected: BTreeSet<[u8; 32]> = keys.iter().copied().collect();
    let mut seams: BTreeSet<[u8; 32]> = BTreeSet::new();
    for w in sorted.windows(2) {
        if w[0].hi != w[1].lo || !expected.contains(&w[0].hi) {
            return false;
        }
        seams.insert(w[0].hi);
    }
    seams.len() == expected.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::key_of;

    fn entries(names: &[&str]) -> Vec<Entry> {
        names.iter().map(|n| Entry::active(key_of(n))).collect()
    }

    /// Every shape that hides a key must fail: an empty gap, a stray seam, a missing end.
    #[test]
    fn a_gap_set_that_hides_a_key_fails_the_partition() {
        let live = entries(&["kaspa", "alice"]);
        let keys = deed_keys(&live);
        let honest = derive_gaps(&live);
        assert!(partitions(&honest, &keys));
        assert!(partitions(&derive_gaps(&[]), &[]));

        let mut empty = honest.clone();
        empty.push(GapState { lo: keys[0], hi: keys[0] });
        assert!(!partitions(&empty, &keys));
        let mut stray_seam = honest.clone();
        stray_seam[0].hi = [0x01; 32];
        stray_seam[1].lo = [0x01; 32];
        assert!(!partitions(&stray_seam, &keys), "a seam that is no deed key");
        let mut short = honest.clone();
        short[0].lo[31] = 1;
        assert!(!partitions(&short, &keys), "no gap reaches KEY_MIN");
        let mut short = honest.clone();
        short[2].hi[31] = 0xfe;
        assert!(!partitions(&short, &keys), "no gap reaches KEY_MAX");
    }

    /// A known deed with no seam, as when a snapshot missed a registration.
    #[test]
    fn a_missing_key_fails_the_partition() {
        let live = entries(&["kaspa", "alice", "bob"]);
        let gaps = derive_gaps(&live[..2]);
        assert!(!partitions(&gaps, &deed_keys(&live)), "a key with no seam must not pass as complete");
    }
}
