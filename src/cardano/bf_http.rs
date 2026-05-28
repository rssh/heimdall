//! Minimal raw-HTTP fetch of a Blockfrost-compatible `/addresses/{addr}/utxos`, tolerant of
//! backends (e.g. yaci-devkit) whose response omits fields the `blockfrost` crate's typed
//! `AddressUtxo` requires (notably `tx_index`). Only the fields heimdall actually uses are parsed.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct BfAmount {
    pub unit: String,
    pub quantity: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BfUtxo {
    pub tx_hash: String,
    pub output_index: u32,
    pub amount: Vec<BfAmount>,
    #[serde(default)]
    pub inline_datum: Option<String>,
}

/// Resolve the Blockfrost base URL: explicit `custom` (e.g. yaci's http://localhost:8080/api/v1),
/// else the public blockfrost.io URL implied by the project-id prefix.
pub fn base_url(project_id: &str, custom: Option<&str>) -> String {
    if let Some(u) = custom {
        return u.trim_end_matches('/').to_string();
    }
    if project_id.starts_with("mainnet") {
        "https://cardano-mainnet.blockfrost.io/api/v0".into()
    } else if project_id.starts_with("preview") {
        "https://cardano-preview.blockfrost.io/api/v0".into()
    } else {
        "https://cardano-preprod.blockfrost.io/api/v0".into()
    }
}

/// Fetch all UTxOs at `address` (paginated), leniently parsed.
pub async fn fetch_address_utxos(
    base_url: &str,
    project_id: &str,
    address: &str,
) -> Result<Vec<BfUtxo>, String> {
    let client = reqwest::Client::new();
    let mut all = Vec::new();
    let mut page = 1usize;
    loop {
        let url = format!("{base_url}/addresses/{address}/utxos?page={page}&count=100&order=asc");
        let resp = client
            .get(&url)
            .header("project_id", project_id)
            .send()
            .await
            .map_err(|e| format!("utxos request: {e}"))?;
        let status = resp.status();
        if status.as_u16() == 404 {
            break; // no UTxOs at this address
        }
        if !status.is_success() {
            return Err(format!(
                "utxos http {}: {}",
                status,
                resp.text().await.unwrap_or_default()
            ));
        }
        let batch: Vec<BfUtxo> = resp.json().await.map_err(|e| format!("utxos json: {e}"))?;
        let n = batch.len();
        all.extend(batch);
        if n < 100 {
            break;
        }
        page += 1;
    }
    Ok(all)
}

/// Fetch the network's live Plutus cost models (ordered int arrays) from
/// `/epochs/latest/parameters`, returned as `[PlutusV1, PlutusV2, PlutusV3]`.
///
/// whisky-common's hardcoded per-network cost models go stale (e.g. preprod's PlutusV3 grew
/// from 298 to 350 params), which makes the tx's script-integrity hash mismatch the ledger's
/// (`PPViewHashesDontMatch`). Passing these live arrays via `Network::Custom` fixes that.
pub async fn fetch_cost_models(base_url: &str, project_id: &str) -> Result<Vec<Vec<i64>>, String> {
    let url = format!("{base_url}/epochs/latest/parameters");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("project_id", project_id)
        .send()
        .await
        .map_err(|e| format!("parameters request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "parameters http {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ));
    }
    let v: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("parameters json: {e}"))?;
    // `cost_models_raw` gives each language as an ordered array of ints (the canonical order the
    // ledger hashes); `cost_models` is the named-map form. Prefer the raw arrays.
    let raw = v
        .get("cost_models_raw")
        .or_else(|| v.get("cost_models"))
        .ok_or_else(|| "parameters: no cost_models_raw/cost_models".to_string())?;
    let mut out = Vec::with_capacity(3);
    for lang in ["PlutusV1", "PlutusV2", "PlutusV3"] {
        let arr = raw
            .get(lang)
            .and_then(|x| x.as_array())
            .ok_or_else(|| format!("parameters: cost_models[{lang}] not an array"))?;
        let nums: Vec<i64> = arr
            .iter()
            .map(|n| {
                n.as_i64()
                    .ok_or_else(|| format!("cost_models[{lang}]: non-int entry"))
            })
            .collect::<Result<_, _>>()?;
        out.push(nums);
    }
    Ok(out)
}
