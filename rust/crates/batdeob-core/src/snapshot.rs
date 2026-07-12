//! Per-Windows-version environment snapshot, produced by
//! `rust/tools/extract-from-wim/extract.py`. The loader parses the JSON at
//! crate-init time (via once_cell) and exposes assoc / ftype / env / where
//! tables for the synth emulator and Environment baseline.

use crate::env::WinVer;
use once_cell::sync::Lazy;
use serde::Deserialize;
use std::collections::BTreeMap;

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
pub struct Snapshot {
    pub schema: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub source_build: Option<String>,
    #[serde(default)]
    pub ver: String,
    #[serde(default)]
    pub identity: BTreeMap<String, String>,
    #[serde(default)]
    pub assoc: BTreeMap<String, String>,
    #[serde(default)]
    pub ftype: BTreeMap<String, String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub r#where: BTreeMap<String, String>,
}

const WIN7_JSON: &str = include_str!("../data/win7.json");
const WIN10_JSON: &str = include_str!("../data/win10.json");
const WIN11_JSON: &str = include_str!("../data/win11.json");

static WIN7: Lazy<Option<Snapshot>> = Lazy::new(|| serde_json::from_str(WIN7_JSON).ok());
static WIN10: Lazy<Option<Snapshot>> = Lazy::new(|| serde_json::from_str(WIN10_JSON).ok());
static WIN11: Lazy<Option<Snapshot>> = Lazy::new(|| serde_json::from_str(WIN11_JSON).ok());

/// Get the snapshot for a given winver.
pub fn get(winver: WinVer) -> Option<&'static Snapshot> {
    match winver {
        WinVer::Win7 => WIN7.as_ref().or_else(|| WIN11.as_ref()),
        WinVer::Win10 => WIN10.as_ref().or_else(|| WIN11.as_ref()),
        WinVer::Win11 => WIN11.as_ref(),
    }
}
