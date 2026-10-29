use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetManifest {
    pub name: String,
    #[serde(rename = "bundleId")]
    pub bundle_id: String,
    pub executable: String,
    #[serde(rename = "minimumOS")]
    pub minimum_os: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(rename = "bundleDirectory")]
    pub bundle_directory: String,
    #[serde(rename = "bundleFiles")]
    pub bundle_files: Vec<String>,
    #[serde(rename = "sourceIPA", skip_serializing_if = "Option::is_none")]
    pub source_ipa: Option<String>,
}
