use serde::{de, Deserialize};

use bitcoin::hashes::hex::FromHex;
use magical_bitcoin_wallet::bitcoin;

fn deserialize_gait_path<'de, D>(deserializer: D) -> Result<Vec<u16>, D::Error>
where
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = Vec::<u8>::from_hex(&s).map_err(de::Error::custom)?;

    Ok(bytes
        .chunks_exact(2)
        .map(|i| i[1] as u16 | (i[0] as u16) << 8)
        .collect())
}

#[derive(Debug, Deserialize)]
pub struct AuthenticateSubaccount {
    pub has_txs: bool,
    pub name: String,
    pub pointer: u16,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticateLimits {
    pub is_fiat: bool,
    pub per_tx: u64,
    pub total: u64,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticateResponse {
    #[serde(deserialize_with = "deserialize_gait_path")]
    pub gait_path: Vec<u16>,
    pub earliest_key_creation_time: u64,
    pub limits: Option<AuthenticateLimits>,
    pub subaccounts: Vec<AuthenticateSubaccount>,
}

#[derive(Debug, Deserialize)]
pub struct VaultFundResponse {
    pub addr_type: String,
    pub branch: u16,
    pub pointer: u16,
    pub script: bitcoin::Script,
    pub subaccount: u16,
}

#[derive(Debug, Deserialize)]
pub struct SignTxResponse {
    pub new_limit: Option<AuthenticateLimits>,
    pub tx: String,
}
