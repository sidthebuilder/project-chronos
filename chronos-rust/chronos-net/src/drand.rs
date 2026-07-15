use serde::Deserialize;
use anyhow::Result;

#[derive(Deserialize, Debug)]
pub struct DrandBeacon {
    pub round: u64,
    pub randomness: String,
    pub signature: String,
}

pub struct DrandClient {
    base_url: String,
}

impl DrandClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
        }
    }

    pub async fn fetch_latest(&self) -> Result<DrandBeacon> {
        let url = format!("{}/public/latest", self.base_url);
        let client = reqwest::Client::new();
        let res = client.get(&url)
            .header("User-Agent", "project-chronos-rust/0.1.0")
            .send().await?
            .json::<DrandBeacon>().await?;
        
        // In prototype, we skip BLS12-381 signature verification 
        // to reduce compilation overhead.
        println!("[DRAND] Fetched beacon round {}", res.round);
        Ok(res)
    }
}
