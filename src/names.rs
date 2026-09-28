use crate::blake3_32;

pub const MAX_NAME_LEN: usize = 32;
/// Display only. The chain stores bare names.
pub const DISPLAY_SUFFIX: &str = ".k";

/// Trims, lowercases and strips one display suffix. It validates nothing.
pub fn normalize(input: &str) -> String {
    let s = input.trim().to_ascii_lowercase();
    s.strip_suffix(DISPLAY_SUFFIX).unwrap_or(&s).to_string()
}

/// The covenant's name rule: 1 to 32 bytes of a-z, 0-9 and hyphen, with no edge hyphen.
pub fn validate(name: &str) -> Result<(), String> {
    let b = name.as_bytes();
    // Charset first, or a non-ASCII name gets a misleading length error.
    if !b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-') {
        return Err("allowed characters: a-z, 0-9 and hyphen".to_string());
    }
    if b.is_empty() || b.len() > MAX_NAME_LEN {
        return Err(format!("name must be 1..={MAX_NAME_LEN} bytes on-chain"));
    }
    if b[0] == b'-' || b[b.len() - 1] == b'-' {
        return Err("name cannot start or end with a hyphen".to_string());
    }
    Ok(())
}

pub fn display(name: &str) -> String {
    format!("{name}{DISPLAY_SUFFIX}")
}

/// The KCC-1 key the keyspace is partitioned over.
pub fn key_of(name: &str) -> [u8; 32] {
    blake3_32(name.as_bytes())
}

/// `blake3(name ‖ ownerType ‖ owner)`. A copied commit with a swapped owner never activates, so
/// copying a pending claim steals nothing.
pub fn claim_of(name: &str, owner_type: crate::state::OwnerType, owner: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(name.len() + 33);
    buf.extend_from_slice(name.as_bytes());
    buf.push(owner_type as u8);
    buf.extend_from_slice(owner);
    blake3_32(&buf)
}

/// The bare name, zero-padded to 32 bytes. Untrusted input must use this form, because
/// [`padded_name`] panics.
pub fn try_padded_name(name: &str) -> Result<[u8; 32], String> {
    validate(name)?;
    let mut out = [0u8; 32];
    out[..name.len()].copy_from_slice(name.as_bytes());
    Ok(out)
}

pub fn padded_name(name: &str) -> [u8; 32] {
    try_padded_name(name).expect("padded_name on a name that failed validation; use try_padded_name for untrusted input")
}

/// Refuses non-zero bytes after the terminator, so a decoder never adopts a corrupted field.
pub fn name_from_padded(padded: &[u8; 32]) -> Result<String, String> {
    let len = padded.iter().position(|&b| b == 0).unwrap_or(32);
    if padded[len..].iter().any(|&b| b != 0) {
        return Err("padding contains non-zero bytes".to_string());
    }
    let name = std::str::from_utf8(&padded[..len]).map_err(|e| e.to_string())?.to_string();
    validate(&name)?;
    Ok(name)
}

/// Must match the covenant's `keyLt`: strict big-endian byte order.
pub fn key_lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a < b
}

/// The most bytes a subname label holds, dots included.
pub const LABEL_MAX: usize = 64;

/// Why an input or a stored entry names no subname. A tag never changes once it ships.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubnameFault {
    /// A dotted input that does not end in [`DISPLAY_SUFFIX`].
    NoSuffix,
    /// The parent fails [`validate`], or equals the suffix under a label.
    BadParent(String),
    /// A segment fails the label rule, or the label is empty or over the cap.
    BadLabel(String),
    /// A covenant id owns the parent, so the parent makes no claim.
    ParentInCovenant,
    /// The value is text, a flag, or an item that is not a byte string.
    NotBytes,
    /// A byte string that is not 33 bytes.
    BadLength,
    /// A scheme byte that names none of the owner schemes.
    BadScheme,
    /// Scheme `0x04`, which no reader supports as a payee.
    HeldByCovenant,
    /// A payload of 32 zero bytes, under any scheme that reaches the payload tests.
    ZeroPayload,
    /// A key scheme whose payload is not on the curve, with the library's words.
    NotAPoint(String),
}

impl SubnameFault {
    pub fn tag(&self) -> &'static str {
        match self {
            SubnameFault::NoSuffix => "no-suffix",
            SubnameFault::BadParent(_) => "bad-parent",
            SubnameFault::BadLabel(_) => "bad-label",
            SubnameFault::ParentInCovenant => "parent-in-covenant",
            SubnameFault::NotBytes => "not-bytes",
            SubnameFault::BadLength => "bad-length",
            SubnameFault::BadScheme => "bad-scheme",
            SubnameFault::HeldByCovenant => "held-by-covenant",
            SubnameFault::ZeroPayload => "zero-payload",
            SubnameFault::NotAPoint(_) => "not-a-point",
        }
    }
}

impl std::fmt::Display for SubnameFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubnameFault::NoSuffix => write!(f, "a dotted input must end in {DISPLAY_SUFFIX}"),
            SubnameFault::BadParent(p) if p.is_empty() => write!(f, "the parent is empty"),
            SubnameFault::BadParent(p) => write!(f, "the parent {p:?} cannot carry a subname"),
            SubnameFault::BadLabel(l) if l.is_empty() => write!(f, "the label is empty"),
            SubnameFault::BadLabel(l) => write!(f, "the label part {l:?} breaks the label rule"),
            SubnameFault::ParentInCovenant => write!(f, "a covenant holds the parent, so the parent claims nothing"),
            SubnameFault::NotBytes => write!(f, "the value is not a byte string"),
            SubnameFault::BadLength => write!(f, "the value is a byte string that is not 33 bytes"),
            SubnameFault::BadScheme => write!(f, "the value names no owner scheme"),
            SubnameFault::HeldByCovenant => write!(f, "a covenant id owns this entry, and no reader can pay one"),
            SubnameFault::ZeroPayload => write!(f, "the payload is 32 zero bytes"),
            SubnameFault::NotAPoint(e) => write!(f, "the payload is not a point on the curve ({e})"),
        }
    }
}

impl std::error::Error for SubnameFault {}

/// The one segment no label can hold, and the one name no parent under a label can be.
fn suffix_segment() -> &'static str {
    DISPLAY_SUFFIX.strip_prefix('.').unwrap_or(DISPLAY_SUFFIX)
}

/// One or more dot-separated segments, each a valid name other than the suffix segment, at most
/// [`LABEL_MAX`] bytes in all. It normalizes nothing, so every stored key is one a lookup can reach.
pub fn validate_label(label: &str) -> Result<(), SubnameFault> {
    if label.is_empty() {
        return Err(SubnameFault::BadLabel(String::new()));
    }
    if label.len() > LABEL_MAX {
        return Err(SubnameFault::BadLabel(label.to_string()));
    }
    for segment in label.split('.') {
        validate(segment).map_err(|_| SubnameFault::BadLabel(segment.to_string()))?;
        if segment == suffix_segment() {
            return Err(SubnameFault::BadLabel(segment.to_string()));
        }
    }
    Ok(())
}

/// The parent and the optional label a typed input names. With a dot the input must end in
/// [`DISPLAY_SUFFIX`], stripped once, and the last remaining dot divides the label from the parent.
/// The suffix segment cannot be a parent, or `alice.k.k` would read as `alice` under `k`.
pub fn split_subname(input: &str) -> Result<(String, Option<String>), SubnameFault> {
    let s = input.trim().to_ascii_lowercase();
    if !s.contains('.') {
        validate(&s).map_err(|_| SubnameFault::BadParent(s.clone()))?;
        return Ok((s, None));
    }
    let body = s.strip_suffix(DISPLAY_SUFFIX).ok_or(SubnameFault::NoSuffix)?;
    let Some((label, parent)) = body.rsplit_once('.') else {
        validate(body).map_err(|_| SubnameFault::BadParent(body.to_string()))?;
        return Ok((body.to_string(), None));
    };
    validate(parent).map_err(|_| SubnameFault::BadParent(parent.to_string()))?;
    if parent == suffix_segment() {
        return Err(SubnameFault::BadParent(parent.to_string()));
    }
    validate_label(label)?;
    Ok((parent.to_string(), Some(label.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suffix() -> &'static str {
        DISPLAY_SUFFIX.strip_prefix('.').unwrap()
    }

    #[test]
    fn the_name_rule_matches_the_covenant() {
        assert!(validate("a").is_ok());
        assert!(validate("a-b9").is_ok());
        assert!(validate("").is_err());
        assert!(validate("-a").is_err());
        assert!(validate("a-").is_err());
        assert!(validate("A").is_err());
        assert!(validate(&"a".repeat(33)).is_err());
    }

    #[test]
    fn split_subname_names_a_fault_for_every_input_that_reaches_nothing() {
        let doubled = format!("alice{}{}", DISPLAY_SUFFIX, DISPLAY_SUFFIX);
        let cases: Vec<(String, &str, &str)> = vec![
            ("bob.alice".to_string(), "no-suffix", "a dotted input without the suffix"),
            ("pay.example.com".to_string(), "no-suffix", "a domain is not a subname"),
            ("alice.".to_string(), "no-suffix", "a trailing dot is not the suffix"),
            (format!(".{}", suffix()), "bad-parent", "the empty parent"),
            (format!(".alice{DISPLAY_SUFFIX}"), "bad-label", "the empty label"),
            (doubled, "bad-parent", "the doubled suffix leaves the parent as the suffix"),
            (format!("bob.alice{DISPLAY_SUFFIX}{DISPLAY_SUFFIX}"), "bad-parent", "the same, under a two-part label"),
            ("".to_string(), "bad-parent", "nothing at all"),
        ];
        for (input, tag, why) in cases {
            let fault = split_subname(&input).expect_err(&format!("{input:?} must name nothing ({why})"));
            assert_eq!(fault.tag(), tag, "{input:?} ({why})");
        }
    }

    #[test]
    fn validate_label_holds_every_clause_of_the_label_rule() {
        let max = format!("{}.{}", "z".repeat(32), "z".repeat(31)); // 64 bytes with its dot
        let over = format!("{}.{}", "z".repeat(32), "z".repeat(32)); // 65
        assert_eq!(max.len(), LABEL_MAX);
        for ok in ["bob", "dev.team", "a.b.c.d.e", &"z".repeat(32), &max] {
            assert!(validate_label(ok).is_ok(), "{ok:?} must pass the label rule");
        }
        let bad: Vec<(String, &str)> = vec![
            ("Bob".to_string(), "the rule normalizes nothing"),
            ("-bob".to_string(), "the name rule refuses an edge hyphen"),
            ("a..b".to_string(), "an empty segment"),
            (suffix().to_string(), "the suffix alone"),
            (format!("a.{}", suffix()), "the suffix as the last segment"),
            (format!("{}.a", suffix()), "the suffix as the first segment"),
            ("z".repeat(33), "a 33-byte segment"),
            (String::new(), "an empty label"),
            (over.clone(), "65 bytes, one past LABEL_MAX"),
            ("a b".to_string(), "a space"),
        ];
        for (label, why) in bad {
            let fault = validate_label(&label).expect_err(&format!("{label:?} must fail ({why})"));
            assert_eq!(fault.tag(), "bad-label", "{label:?} ({why})");
        }
    }
}
