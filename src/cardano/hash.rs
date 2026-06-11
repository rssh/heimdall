//! Shared blake2b digest helpers (WI-007 P10).
//!
//! One place for the two digest widths Cardano uses, instead of each module
//! open-coding `Hasher::<N>`: 224-bit for key/script hashes (wallet payment
//! key hashes, `pool_id = blake2b_224(cold_vkey)`), 256-bit for MPF node
//! hashes and paths. (`blueprint::script_hash_v3` keeps its own incremental
//! hasher — it digests a domain prefix + script without concatenating.)

use pallas_crypto::hash::Hasher;

/// blake2b-224 (28 bytes) — Cardano key hashes, script hashes, pool ids.
#[must_use]
pub fn blake2b_224(data: &[u8]) -> [u8; 28] {
    *Hasher::<224>::hash(data)
}

/// blake2b-256 (32 bytes) — MPF node hashes and key paths.
#[must_use]
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    *Hasher::<256>::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pinned externally (python hashlib.blake2b(b'abc', digest_size=N)).
    #[test]
    fn digests_match_external_vectors() {
        assert_eq!(
            hex::encode(blake2b_224(b"abc")),
            "9bd237b02a29e43bdd6738afa5b53ff0eee178d6210b618e4511aec8"
        );
        assert_eq!(
            hex::encode(blake2b_256(b"abc")),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
    }
}
