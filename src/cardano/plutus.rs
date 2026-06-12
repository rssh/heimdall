//! Shared Plutus-data encoding/decoding — the consensus-critical constructor-tag
//! and canonical-encoding rules in ONE place.
//!
//! Constructor tags: index `0..=6` → CBOR tag `121+i`; `7+` → tag `102` with an
//! explicit `any_constructor`. Fields and lists use the CANONICAL plutus-core
//! encoding: indefinite-length when non-empty, definite empty (`0x80`)
//! otherwise. Haskell plutus-core is encoding-insensitive, but the Rust uplc
//! evaluator (whisky / `aiken tx simulate`) compares and re-serialises
//! ENCODING-SENSITIVELY, so a non-canonical datum/redeemer fails simulation even
//! though a real node accepts it. Centralising the rule keeps it from drifting
//! across call sites — it previously lived in four copies, one of which was
//! missed.

use pallas_primitives::conway::Constr;
use pallas_primitives::{BigInt, BoundedBytes, MaybeIndefArray, PlutusData};

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Plutus `ByteArray`.
#[must_use]
pub fn bytes(b: &[u8]) -> PlutusData {
    PlutusData::BoundedBytes(BoundedBytes::from(b.to_vec()))
}

/// Plutus `Int`.
#[must_use]
pub fn int(n: i64) -> PlutusData {
    PlutusData::BigInt(BigInt::Int(n.into()))
}

/// Plutus `Int` from a `u64` (output indexes etc.). Rejects values above
/// `i64::MAX` rather than silently wrapping to a negative Int.
#[must_use]
pub fn int_from_u64(n: u64) -> PlutusData {
    int(i64::try_from(n).expect("integer exceeds i64::MAX"))
}

/// Canonical array encoding: indefinite-length when non-empty, definite empty.
fn canonical(items: Vec<PlutusData>) -> MaybeIndefArray<PlutusData> {
    if items.is_empty() {
        MaybeIndefArray::Def(items)
    } else {
        MaybeIndefArray::Indef(items)
    }
}

/// A Plutus `Constr` with constructor index `c`, canonically encoded.
#[must_use]
pub fn constr(c: u64, fields: Vec<PlutusData>) -> PlutusData {
    let (tag, any_constructor) = if c <= 6 {
        (121 + c, None)
    } else {
        (102, Some(c))
    };
    PlutusData::Constr(Constr {
        tag,
        any_constructor,
        fields: canonical(fields),
    })
}

/// A Plutus `List`, canonically encoded.
#[must_use]
pub fn array(items: Vec<PlutusData>) -> PlutusData {
    PlutusData::Array(canonical(items))
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlutusError {
    NotConstr,
    WrongConstructor {
        expected: u64,
        got: u64,
    },
    /// Field at index `usize` is missing.
    MissingField(usize),
    /// Field at index `usize` is not a `ByteArray`.
    NotBytes(usize),
    /// Field at index `usize` is not an `Int` (or exceeds `i64`).
    NotInt(usize),
}

impl std::fmt::Display for PlutusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConstr => write!(f, "expected Constr"),
            Self::WrongConstructor { expected, got } => {
                write!(f, "expected constructor {expected}, got {got}")
            }
            Self::MissingField(i) => write!(f, "missing field [{i}]"),
            Self::NotBytes(i) => write!(f, "field [{i}] is not a ByteArray"),
            Self::NotInt(i) => write!(f, "field [{i}] is not an Int (or exceeds i64)"),
        }
    }
}

impl std::error::Error for PlutusError {}

/// Constructor index + fields of a `Constr`, accepting BOTH the compact
/// tag-`121..=127` form and the general tag-`102`/`any_constructor` form (a node
/// accepts either, so decoders must too).
pub fn as_constr(data: &PlutusData) -> Result<(u64, &[PlutusData]), PlutusError> {
    let c = match data {
        PlutusData::Constr(c) => c,
        _ => return Err(PlutusError::NotConstr),
    };
    let ctor = match c.tag {
        121..=127 => c.tag - 121,
        102 => c.any_constructor.unwrap_or(u64::MAX),
        _ => return Err(PlutusError::NotConstr),
    };
    Ok((ctor, &c.fields))
}

/// Fields of a `Constr` whose constructor index is `expected`.
pub fn constr_fields(data: &PlutusData, expected: u64) -> Result<&[PlutusData], PlutusError> {
    let (ctor, fields) = as_constr(data)?;
    if ctor != expected {
        return Err(PlutusError::WrongConstructor {
            expected,
            got: ctor,
        });
    }
    Ok(fields)
}

/// The `ByteArray` field at index `i`.
pub fn field_bytes(fields: &[PlutusData], i: usize) -> Result<Vec<u8>, PlutusError> {
    match fields.get(i) {
        Some(PlutusData::BoundedBytes(b)) => Ok(b.clone().into()),
        Some(_) => Err(PlutusError::NotBytes(i)),
        None => Err(PlutusError::MissingField(i)),
    }
}

/// The `Int` field at index `i`. On-chain Ints are unbounded; anything
/// outside `i64` (including the big-integer CBOR forms) is rejected rather
/// than truncated — no bifrost datum legitimately carries such values.
pub fn field_int(fields: &[PlutusData], i: usize) -> Result<i64, PlutusError> {
    match fields.get(i) {
        Some(PlutusData::BigInt(BigInt::Int(n))) => {
            i64::try_from(i128::from(*n)).map_err(|_| PlutusError::NotInt(i))
        }
        Some(PlutusData::BigInt(_)) | Some(_) => Err(PlutusError::NotInt(i)),
        None => Err(PlutusError::MissingField(i)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pallas_codec::minicbor;

    #[test]
    fn constr_is_canonical() {
        // Non-empty fields → indefinite (d8 79 9f … ff); empty → definite (0x80).
        let nonempty = constr(0, vec![bytes(&[0xaa]), int(1)]);
        assert_eq!(
            hex::encode(minicbor::to_vec(&nonempty).unwrap()),
            "d8799f41aa01ff"
        );
        let empty = constr(0, vec![]);
        assert_eq!(hex::encode(minicbor::to_vec(&empty).unwrap()), "d87980");
    }

    #[test]
    fn constr_tag_mapping() {
        // index 0..=6 → tag 121+i; 7+ → tag 102 + any_constructor.
        for c in 0u64..=6 {
            let PlutusData::Constr(x) = constr(c, vec![]) else {
                panic!()
            };
            assert_eq!(x.tag, 121 + c);
            assert_eq!(x.any_constructor, None);
        }
        let PlutusData::Constr(x) = constr(7, vec![]) else {
            panic!()
        };
        assert_eq!(x.tag, 102);
        assert_eq!(x.any_constructor, Some(7));
    }

    #[test]
    fn array_is_canonical() {
        assert_eq!(
            hex::encode(minicbor::to_vec(&array(vec![int(1)])).unwrap()),
            "9f01ff"
        );
        assert_eq!(hex::encode(minicbor::to_vec(&array(vec![])).unwrap()), "80");
    }

    #[test]
    fn as_constr_accepts_both_tag_forms() {
        // tag 121 (compact) and tag 102/any_constructor=0 both decode to ctor 0.
        let compact = constr(0, vec![bytes(b"x")]);
        assert_eq!(as_constr(&compact).unwrap().0, 0);
        let general = PlutusData::Constr(Constr {
            tag: 102,
            any_constructor: Some(0),
            fields: MaybeIndefArray::Indef(vec![bytes(b"x")]),
        });
        assert_eq!(as_constr(&general).unwrap().0, 0);
        // a large constructor index round-trips via 102.
        assert_eq!(as_constr(&constr(9, vec![])).unwrap().0, 9);
    }

    #[test]
    fn decode_errors() {
        assert_eq!(as_constr(&bytes(b"x")).unwrap_err(), PlutusError::NotConstr);
        assert_eq!(
            constr_fields(&constr(1, vec![]), 0).unwrap_err(),
            PlutusError::WrongConstructor {
                expected: 0,
                got: 1
            }
        );
        let fields = [bytes(b"ok"), int(3)];
        assert_eq!(field_bytes(&fields, 0).unwrap(), b"ok");
        assert_eq!(
            field_bytes(&fields, 1).unwrap_err(),
            PlutusError::NotBytes(1)
        );
        assert_eq!(
            field_bytes(&fields, 5).unwrap_err(),
            PlutusError::MissingField(5)
        );
    }

    #[test]
    fn int_from_u64_guards_overflow() {
        assert_eq!(
            minicbor::to_vec(&int_from_u64(7)).unwrap(),
            minicbor::to_vec(&int(7)).unwrap()
        );
    }

    #[test]
    #[should_panic(expected = "exceeds i64::MAX")]
    fn int_from_u64_panics_above_i64_max() {
        let _ = int_from_u64(u64::MAX);
    }
}
