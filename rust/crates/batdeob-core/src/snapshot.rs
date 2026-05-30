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

const WIN11_JSON: &str = include_str!("../data/win11.json");

static WIN11: Lazy<Option<Snapshot>> = Lazy::new(|| serde_json::from_str(WIN11_JSON).ok());

/// Get the snapshot for a given winver. We currently ship only the
/// Win11 dataset; Win7/Win10 callers fall through to it because
/// assoc/ftype tables are largely stable across recent versions, and
/// the Win11 snapshot carries entries (`Microsoft.PowerShellConsole.1`,
/// `Microsoft.PowerShellCmdletDefinitionXML.1`, …) that the FE
/// DOSfuscation `ftype^|findstr lCo` family of FOR /F gadgets keys
/// off. The bare hardcoded fallback in `synth.rs::synth_assoc` /
/// `synth_ftype` is missing these.
pub fn get(winver: WinVer) -> Option<&'static Snapshot> {
    match winver {
        WinVer::Win11 | WinVer::Win10 | WinVer::Win7 => WIN11.as_ref(),
    }
}
