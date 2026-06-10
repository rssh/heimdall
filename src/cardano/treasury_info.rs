//! `treasury.ak` (`treasury_info`) state datum + the SPO-registration transition.
//!
//! This is the **roster/key oracle** datum — distinct from `treasury_datum.rs`,
//! which is the *treasury-movement* oracle (`Constr(0/1,[btc_tx])`). The
//! `treasury_info` UTxO carries:
//!
//! ```text
//! Constr(0, [ bifrost_identity_root, current_treasury_address,
//!             current_treasury_utxo_id, current_spos_frost_key ])   // all ByteArray
//! ```
//!
//! matching the Aiken `bifrost/types/treasury.ak` `TreasuryDatum`.
//!
//! `register_spo` (R1c) spends this UTxO to insert `bifrost_id_pk → pool_id`
//! into the `bifrost_identity_root` Merkle-Patricia-Forestry trie. This module
//! provides the heimdall-side machinery shared with K1 (bootstrap) and the
//! registry mint (R1): encode/decode the datum, encode the spend redeemer and
//! the on-chain proof, and compute the post-registration datum + the
//! `bifrost_identity_absence_proof` from the off-chain MPF trie ([`crate::cardano::mpf`]).
//!
//! NOTE: building/submitting the full register_spo Cardano tx (spending a live
//! `treasury_info` UTxO + the registry linked-list) is blocked on K1 — the
//! `treasury_info` validator is not deployed yet. The logic here is pure and
//! testable now.

use pallas_codec::minicbor;
use pallas_primitives::conway::Constr;
use pallas_primitives::{BigInt, BoundedBytes, MaybeIndefArray, PlutusData};

use crate::cardano::mpf;

/// The `treasury_info` state datum (`TreasuryDatum`). All fields are on-chain
/// `ByteArray`s; `bifrost_identity_root` is the 32-byte MPF root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreasuryInfoDatum {
    pub bifrost_identity_root: mpf::Hash,
    pub current_treasury_address: Vec<u8>,
    pub current_treasury_utxo_id: Vec<u8>,
    pub current_spos_frost_key: Vec<u8>,
}

#[derive(Debug)]
pub enum TreasuryInfoError {
    NotConstr,
    WrongConstructor(u64),
    FieldCount { expected: usize, got: usize },
    NotBytes(usize),
    BadRootLen(usize),
    /// The off-chain trie's root does not match `current.bifrost_identity_root`,
    /// so any proof generated from it would be rejected on-chain.
    RootMismatch,
    Mpf(mpf::MpfError),
}

impl std::fmt::Display for TreasuryInfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConstr => write!(f, "expected Constr"),
            Self::WrongConstructor(c) => write!(f, "unexpected constructor {c}"),
            Self::FieldCount { expected, got } => {
                write!(f, "expected {expected} field(s), got {got}")
            }
            Self::NotBytes(i) => write!(f, "field[{i}]: expected ByteArray"),
            Self::BadRootLen(n) => write!(f, "bifrost_identity_root must be 32 bytes, got {n}"),
            Self::RootMismatch => write!(f, "off-chain trie root != datum bifrost_identity_root"),
            Self::Mpf(e) => write!(f, "mpf: {e:?}"),
        }
    }
}

impl std::error::Error for TreasuryInfoError {}

// ---------------------------------------------------------------------------
// Plutus-data helpers (CBOR constructor tags 121.. = Constr 0.., 102 for 7+)
// ---------------------------------------------------------------------------

fn bytes(b: &[u8]) -> PlutusData {
    PlutusData::BoundedBytes(BoundedBytes::from(b.to_vec()))
}

fn int(n: i64) -> PlutusData {
    PlutusData::BigInt(BigInt::Int(n.into()))
}

/// A Plutus `Constr` with constructor index `c` (0..=6 → tag 121+c; 7+ → tag 102).
fn constr(c: u64, fields: Vec<PlutusData>) -> PlutusData {
    let (tag, any_constructor) = if c <= 6 { (121 + c, None) } else { (102, Some(c)) };
    PlutusData::Constr(Constr {
        tag,
        any_constructor,
        fields: MaybeIndefArray::Def(fields),
    })
}

/// Constr fields if `data` is a `Constr` with constructor index `expected`.
fn constr_fields(data: &PlutusData, expected: u64) -> Result<&[PlutusData], TreasuryInfoError> {
    let c = match data {
        PlutusData::Constr(c) => c,
        _ => return Err(TreasuryInfoError::NotConstr),
    };
    let ctor = match c.tag {
        121..=127 => c.tag - 121,
        102 => c.any_constructor.unwrap_or(u64::MAX),
        other => return Err(TreasuryInfoError::WrongConstructor(other)),
    };
    if ctor != expected {
        return Err(TreasuryInfoError::WrongConstructor(ctor));
    }
    Ok(&c.fields)
}

fn field_bytes(fields: &[PlutusData], i: usize) -> Result<Vec<u8>, TreasuryInfoError> {
    match fields.get(i) {
        Some(PlutusData::BoundedBytes(b)) => Ok(b.clone().into()),
        _ => Err(TreasuryInfoError::NotBytes(i)),
    }
}

// ---------------------------------------------------------------------------
// TreasuryDatum
// ---------------------------------------------------------------------------

impl TreasuryInfoDatum {
    /// Encode as `Constr(0, [root, address, utxo_id, frost_key])`.
    #[must_use]
    pub fn to_plutus_data(&self) -> PlutusData {
        constr(
            0,
            vec![
                bytes(&self.bifrost_identity_root),
                bytes(&self.current_treasury_address),
                bytes(&self.current_treasury_utxo_id),
                bytes(&self.current_spos_frost_key),
            ],
        )
    }

    /// CBOR bytes of the inline datum (for the continuing `treasury_info` output).
    #[must_use]
    pub fn to_cbor(&self) -> Vec<u8> {
        minicbor::to_vec(self.to_plutus_data()).expect("PlutusData CBOR encode")
    }

    pub fn from_plutus_data(data: &PlutusData) -> Result<Self, TreasuryInfoError> {
        let fields = constr_fields(data, 0)?;
        if fields.len() != 4 {
            return Err(TreasuryInfoError::FieldCount {
                expected: 4,
                got: fields.len(),
            });
        }
        let root_bytes = field_bytes(fields, 0)?;
        let bifrost_identity_root: mpf::Hash = root_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TreasuryInfoError::BadRootLen(root_bytes.len()))?;
        Ok(TreasuryInfoDatum {
            bifrost_identity_root,
            current_treasury_address: field_bytes(fields, 1)?,
            current_treasury_utxo_id: field_bytes(fields, 2)?,
            current_spos_frost_key: field_bytes(fields, 3)?,
        })
    }
}

/// Encode the `TreasurySpendRedeemer` for registration:
/// `Constr(0, [config_ref_input_index, new_root, new_address, new_utxo_id, new_frost_key])`.
/// `new` is the post-registration datum (only `bifrost_identity_root` differs).
#[must_use]
pub fn treasury_spend_redeemer(config_ref_input_index: i64, new: &TreasuryInfoDatum) -> PlutusData {
    constr(
        0,
        vec![
            int(config_ref_input_index),
            bytes(&new.bifrost_identity_root),
            bytes(&new.current_treasury_address),
            bytes(&new.current_treasury_utxo_id),
            bytes(&new.current_spos_frost_key),
        ],
    )
}

// ---------------------------------------------------------------------------
// MPF proof → Plutus data (the on-chain `Proof = List<ProofStep>`)
// ---------------------------------------------------------------------------

/// Encode an MPF proof as the on-chain `Proof` (a `List<ProofStep>`), for the
/// `SposRegistry.Register` redeemer's `bifrost_identity_absence_proof`.
#[must_use]
pub fn proof_to_plutus_data(proof: &mpf::Proof) -> PlutusData {
    let steps = proof.iter().map(step_to_plutus_data).collect();
    PlutusData::Array(MaybeIndefArray::Def(steps))
}

fn step_to_plutus_data(step: &mpf::ProofStep) -> PlutusData {
    match step {
        // Branch { skip, neighbors }
        mpf::ProofStep::Branch { skip, neighbors } => {
            constr(0, vec![int(*skip as i64), bytes(neighbors)])
        }
        // Fork { skip, neighbor }
        mpf::ProofStep::Fork { skip, neighbor } => {
            constr(1, vec![int(*skip as i64), neighbor_to_plutus_data(neighbor)])
        }
        // Leaf { skip, key, value }
        mpf::ProofStep::Leaf { skip, key, value } => {
            constr(2, vec![int(*skip as i64), bytes(key), bytes(value)])
        }
    }
}

fn neighbor_to_plutus_data(n: &mpf::Neighbor) -> PlutusData {
    // Neighbor { nibble, prefix, root }
    constr(
        0,
        vec![int(i64::from(n.nibble)), bytes(&n.prefix), bytes(&n.root)],
    )
}

// ---------------------------------------------------------------------------
// Registration transition
// ---------------------------------------------------------------------------

/// Compute the post-registration `treasury_info` datum and the
/// `bifrost_identity_absence_proof` for inserting `bifrost_id_pk → pool_id`.
///
/// `identity_trie` is the off-chain reconstruction of the current
/// `bifrost_identity_root` (built from the on-chain `spos_registry` linked
/// list, R1b). Only `bifrost_identity_root` changes; address / utxo_id /
/// frost_key are preserved (registration does not move the treasury or rekey).
///
/// On-chain, the registry's `Register` validator recomputes
/// `mpf.insert(old_root, bifrost_id_pk, pool_id, proof)` and requires the
/// treasury output datum to carry the result — so a mismatched off-chain trie
/// (caught here as `RootMismatch`) would otherwise produce a tx the validator
/// rejects.
pub fn apply_registration(
    current: &TreasuryInfoDatum,
    identity_trie: &mpf::Trie,
    bifrost_id_pk: &[u8],
    pool_id: &[u8],
) -> Result<(TreasuryInfoDatum, mpf::Proof), TreasuryInfoError> {
    if identity_trie.root_hash() != current.bifrost_identity_root {
        return Err(TreasuryInfoError::RootMismatch);
    }
    let absence_proof = identity_trie
        .prove_non_membership(bifrost_id_pk)
        .map_err(TreasuryInfoError::Mpf)?;
    let new_root =
        mpf::including(bifrost_id_pk, pool_id, &absence_proof).map_err(TreasuryInfoError::Mpf)?;
    let new_datum = TreasuryInfoDatum {
        bifrost_identity_root: new_root,
        current_treasury_address: current.current_treasury_address.clone(),
        current_treasury_utxo_id: current.current_treasury_utxo_id.clone(),
        current_spos_frost_key: current.current_spos_frost_key.clone(),
    };
    Ok((new_datum, absence_proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(n: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        (0..n)
            .map(|i| (format!("spo-{i}").into_bytes(), format!("pool-{i}").into_bytes()))
            .collect()
    }

    fn sample_datum(root: mpf::Hash) -> TreasuryInfoDatum {
        TreasuryInfoDatum {
            bifrost_identity_root: root,
            current_treasury_address: b"\x51\x20treasury-spk".to_vec(),
            current_treasury_utxo_id: b"btc-outpoint".to_vec(),
            current_spos_frost_key: vec![0xABu8; 32],
        }
    }

    #[test]
    fn datum_cbor_roundtrip() {
        let d = sample_datum([7u8; 32]);
        let cbor = d.to_cbor();
        let decoded: PlutusData = minicbor::decode(&cbor).unwrap();
        let d2 = TreasuryInfoDatum::from_plutus_data(&decoded).unwrap();
        assert_eq!(d, d2);
    }

    #[test]
    fn datum_rejects_bad_shape() {
        // wrong constructor
        let wrong = constr(1, vec![bytes(&[0u8; 32]), bytes(b""), bytes(b""), bytes(b"")]);
        assert!(matches!(
            TreasuryInfoDatum::from_plutus_data(&wrong),
            Err(TreasuryInfoError::WrongConstructor(1))
        ));
        // root not 32 bytes
        let short = constr(0, vec![bytes(&[0u8; 8]), bytes(b""), bytes(b""), bytes(b"")]);
        assert!(matches!(
            TreasuryInfoDatum::from_plutus_data(&short),
            Err(TreasuryInfoError::BadRootLen(8))
        ));
    }

    // The R1c core: the new datum's root is exactly the MPF insert of the new
    // SPO, and the returned absence proof verifies against both the old and new
    // roots (the on-chain registry validator does exactly this check).
    #[test]
    fn apply_registration_updates_root_and_yields_valid_proof() {
        let trie = mpf::Trie::from_pairs(&pairs(30)).unwrap();
        let current = sample_datum(trie.root_hash());

        let pk = b"new-bifrost-id-pk";
        let pool = b"new-pool-id";
        let (new_datum, proof) = apply_registration(&current, &trie, pk, pool).unwrap();

        // absence proof rebuilds the OLD root; inserting (pk -> pool) gives the NEW root.
        assert_eq!(
            mpf::excluding(pk, &proof).unwrap(),
            current.bifrost_identity_root
        );
        assert_eq!(
            mpf::including(pk, pool, &proof).unwrap(),
            new_datum.bifrost_identity_root
        );
        // only the root changed.
        assert_ne!(new_datum.bifrost_identity_root, current.bifrost_identity_root);
        assert_eq!(
            new_datum.current_treasury_address,
            current.current_treasury_address
        );
        assert_eq!(new_datum.current_spos_frost_key, current.current_spos_frost_key);
    }

    #[test]
    fn apply_registration_rejects_stale_trie_and_present_key() {
        let trie = mpf::Trie::from_pairs(&pairs(10)).unwrap();
        // datum root disagrees with the trie → RootMismatch.
        let stale = sample_datum([9u8; 32]);
        assert!(matches!(
            apply_registration(&stale, &trie, b"x", b"y"),
            Err(TreasuryInfoError::RootMismatch)
        ));
        // key already registered → KeyPresent surfaced as Mpf error.
        let current = sample_datum(trie.root_hash());
        assert!(matches!(
            apply_registration(&current, &trie, b"spo-0", b"pool-0"),
            Err(TreasuryInfoError::Mpf(mpf::MpfError::KeyPresent))
        ));
    }

    // The encoded proof is a CBOR-roundtrippable List<ProofStep> of the right length.
    #[test]
    fn proof_encodes_to_plutus_list() {
        let trie = mpf::Trie::from_pairs(&pairs(30)).unwrap();
        let proof = trie.prove_non_membership(b"absent-key").unwrap();
        let pd = proof_to_plutus_data(&proof);

        match &pd {
            PlutusData::Array(MaybeIndefArray::Def(steps)) => assert_eq!(steps.len(), proof.len()),
            other => panic!("expected Array, got {other:?}"),
        }
        // CBOR-encodes and decodes without error.
        let cbor = minicbor::to_vec(&pd).unwrap();
        let _back: PlutusData = minicbor::decode(&cbor).unwrap();

        // The spend redeemer also encodes.
        let current = sample_datum(trie.root_hash());
        let (new_datum, _) = apply_registration(&current, &trie, b"absent-key", b"pool").unwrap();
        let redeemer = treasury_spend_redeemer(0, &new_datum);
        let _cbor = minicbor::to_vec(redeemer).unwrap();
    }
}
