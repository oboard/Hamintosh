use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Architecture {
    Arm64,
    Arm64e,
    Other(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub name: String,
    pub vm_address: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub protection: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub path: String,
    pub current_version: u32,
    pub compatibility_version: u32,
    pub weak: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixupInfo {
    pub count: usize,
    pub chained_format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    pub count: usize,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub count: usize,
    pub symbols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosImage {
    pub path: PathBuf,
    pub bundle_id: String,
    pub bundle_name: String,
    pub executable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    pub arch: Architecture,
    pub minimum_os: String,
    pub sdk: String,
    pub segments: Vec<SegmentInfo>,
    pub dependencies: Vec<DependencyInfo>,
    pub fixups: FixupInfo,
    pub exports: ExportInfo,
    pub imports: ImportInfo,
}
