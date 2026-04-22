use core::error::Error as StdError;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub(crate) struct RealityDocument<T> {
    pub reality: T,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RealityClientConfig {
    #[serde(alias = "password")]
    pub public_key: String,
    pub short_id: String,
    pub version: String,
    #[serde(default)]
    pub server_name: Option<String>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RealityFallbackRuleConfig {
    #[serde(default)]
    pub server_names: Vec<String>,
    #[serde(default)]
    pub alpns: Vec<String>,
    #[serde(default)]
    pub named_groups: Vec<String>,
    pub fallback_address: String,
    pub fallback_port: u16,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RealityServerConfig {
    pub private_key: String,
    pub short_id: String,
    pub version: String,
    #[serde(default)]
    pub server_names: Vec<String>,
    #[serde(default)]
    pub fallback_address: Option<String>,
    #[serde(default)]
    pub fallback_port: Option<u16>,
    #[serde(default)]
    pub fallback_rules: Vec<RealityFallbackRuleConfig>,
}

pub(crate) fn load_reality_document<T>(path: &Path) -> Result<RealityDocument<T>, Box<dyn StdError>>
where
    T: DeserializeOwned,
{
    let contents = fs::read_to_string(path)?;
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match extension.as_str() {
        "json" => Ok(serde_json::from_str(&contents)?),
        "toml" => Ok(toml::from_str(&contents)?),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unsupported REALITY config format for '{}'; use .json or .toml",
                path.display()
            ),
        )
        .into()),
    }
}
