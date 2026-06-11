//! register_spo R2: off-chain minimum-stake enforcement.
//!
//! The registry contract cannot read a pool's delegated stake (not
//! script-accessible), so SPOs enforce the threshold OFF-CHAIN: query the
//! pool's active stake and require it `>=` the protocol `min_stake` before
//! (a) building a register_spo tx and (b) admitting the SPO to the DKG
//! candidate set.
//!
//! `min_stake` is a protocol parameter — canonically the on-chain
//! `ConfigDatum.min_stake` ("Variables used offchain that must be
//! unquestionable"). Until heimdall reads the Config UTxO (WI-009-adjacent),
//! the threshold is supplied by the caller (`cardano.min_stake_lovelace`).
//!
//! The gate uses the epoch-snapshot `active_stake` (stable within an epoch),
//! NOT `live_stake`: every SPO checking the same candidate at the same epoch
//! boundary must reach the same verdict, and `live_stake` drifts intra-epoch.

use serde_json::Value;

/// A pool's stake (lovelace), from Blockfrost `/pools/{pool_id}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolStake {
    /// Stake active for the current epoch (the epoch-boundary snapshot) — the
    /// value the min-stake gate compares against.
    pub active_stake: u64,
    /// Current live delegation (informational; drifts within an epoch).
    pub live_stake: u64,
}

/// Outcome of a min-stake check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinStakeCheck {
    /// `active_stake >= threshold`.
    pub meets: bool,
    pub active_stake: u64,
    pub threshold: u64,
}

/// Whether a pool's active stake meets the `min_stake` threshold (both
/// lovelace). At-threshold passes (`>=`).
#[must_use]
pub fn check_min_stake(stake: &PoolStake, min_stake_lovelace: u64) -> MinStakeCheck {
    MinStakeCheck {
        meets: stake.active_stake >= min_stake_lovelace,
        active_stake: stake.active_stake,
        threshold: min_stake_lovelace,
    }
}

/// Parse a Blockfrost `/pools/{pool_id}` JSON body into [`PoolStake`]. Stake
/// fields are decimal-string lovelace.
fn parse_pool_stake(v: &Value) -> Result<PoolStake, String> {
    let field = |name: &str| -> Result<u64, String> {
        v.get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("pool: missing/non-string `{name}`"))?
            .parse::<u64>()
            .map_err(|e| format!("pool: bad `{name}`: {e}"))
    };
    Ok(PoolStake {
        active_stake: field("active_stake")?,
        live_stake: field("live_stake")?,
    })
}

/// Fetch a pool's stake from Blockfrost `/pools/{pool_id}`.
///
/// `pool_id` is the **bech32** pool id (`pool1…`); register_spo's 28-byte pool
/// key hash (`blake2b_224(cold_vkey)`) must be bech32-encoded with the `pool`
/// HRP before calling. A 404 means the pool is not registered (or retired).
pub async fn fetch_pool_stake(
    base_url: &str,
    project_id: &str,
    pool_id: &str,
) -> Result<PoolStake, String> {
    let url = format!("{base_url}/pools/{pool_id}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("pool request: {e}"))?;
    if resp.status().as_u16() == 404 {
        return Err(format!(
            "pool {pool_id} not found (not registered / retired?)"
        ));
    }
    if !resp.status().is_success() {
        return Err(format!(
            "pool http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: Value = resp.json().await.map_err(|e| format!("pool json: {e}"))?;
    parse_pool_stake(&v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_min_stake_uses_active_and_is_inclusive() {
        let stake = PoolStake {
            active_stake: 1_000_000,
            live_stake: 1_200_000,
        };
        assert!(check_min_stake(&stake, 1_000_000).meets); // at threshold → passes
        assert!(check_min_stake(&stake, 999_999).meets);
        assert!(!check_min_stake(&stake, 1_000_001).meets);

        // The gate keys on ACTIVE stake, never live (which can be inflated
        // intra-epoch); a low active stake fails regardless of live.
        let below = PoolStake {
            active_stake: 500,
            live_stake: u64::MAX,
        };
        let c = check_min_stake(&below, 1_000);
        assert!(!c.meets);
        assert_eq!(c.active_stake, 500);
        assert_eq!(c.threshold, 1_000);
    }

    #[test]
    fn parse_pool_stake_ok_and_rejects_bad() {
        let good = serde_json::json!({
            "pool_id": "pool1abc",
            "active_stake": "123456789",
            "live_stake": "200000000",
        });
        let s = parse_pool_stake(&good).unwrap();
        assert_eq!(s.active_stake, 123_456_789);
        assert_eq!(s.live_stake, 200_000_000);

        // missing field
        assert!(parse_pool_stake(&serde_json::json!({ "active_stake": "1" })).is_err());
        // non-numeric
        assert!(
            parse_pool_stake(&serde_json::json!({ "active_stake": "x", "live_stake": "1" }))
                .is_err()
        );
        // number instead of string (Blockfrost sends strings)
        assert!(
            parse_pool_stake(&serde_json::json!({ "active_stake": 1, "live_stake": 2 })).is_err()
        );
    }
}
