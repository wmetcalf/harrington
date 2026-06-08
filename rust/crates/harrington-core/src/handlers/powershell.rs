//! PowerShell handler — captures -EncodedCommand / -Command into env.exec_ps1.
//!
//! Mirrors powershell.exe parameter binding for any unambiguous shorthand:
//! literal prefixes (`-Enc`, `-Encoded`) and CamelCase initials (`-Ec`,
//! `-Ex`, `-WindowS`, `-NoP`). The obfuscator-friendly variants all resolve
//! to the same canonical form here so the URL-extraction pipeline sees the
//! decoded payload regardless of which spelling the sample used.
#![allow(clippy::expect_used)]

use super::util::split_words;
use crate::env::{Environment, FsEntry};
use base64::Engine;

// (canonical_camel, takes_value). Listed in PowerShell.exe's canonical
// CamelCase so that initial-letter matching (`-Ec` -> EncodedCommand) can
// reconstruct the abbreviation rule.
const PS_FLAGS: &[(&str, bool)] = &[
    ("PSConsoleFile", true),
    ("Version", true),
    ("NoLogo", false),
    ("NoExit", false),
    ("Sta", false),
    ("Mta", false),
    ("NoProfile", false),
    ("NonInteractive", false),
    ("InputFormat", true),
    ("OutputFormat", true),
    ("WindowStyle", true),
    ("EncodedCommand", true),
    ("ConfigurationName", true),
    ("File", true),
    ("ExecutionPolicy", true),
    ("Command", true),
    ("SettingsFile", true),
    ("Help", false),
];

fn camel_initials(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// PowerShell.exe disambiguates a handful of prefix-ambiguous shortcuts via
/// internal precedence rather than erroring. These match the host's actual
/// behavior (and what malware relies on).
const SHORTCUT_OVERRIDES: &[(&str, &str)] = &[
    // `-e` is a prefix of both EncodedCommand and ExecutionPolicy; PS resolves
    // it to EncodedCommand (the encoded shortcut is the documented "-E").
    ("e", "EncodedCommand"),
    // `-co` is a prefix of both Command and ConfigurationName. The pre-rewrite
    // CMD_FLAG_RE accepted every prefix of `-command`; preserve that legacy
    // semantics so `powershell -co \"...\"` still routes through the
    // Command branch.
    ("co", "Command"),
];

/// Resolve a token like `-Ec`, `/W`, `-NoP` to its canonical powershell.exe
/// flag name (e.g. `EncodedCommand`). Returns `None` for non-flag tokens,
/// unknown flags, and ambiguous abbreviations not covered by an explicit
/// PS-precedence override.
pub(crate) fn canonical_ps_flag(token: &str) -> Option<&'static str> {
    let lower = token.to_ascii_lowercase();
    let stripped = lower
        .strip_prefix('/')
        .or_else(|| lower.strip_prefix('-'))?;
    if stripped.is_empty() {
        return None;
    }
    let mut prefix_hit: Option<&'static str> = None;
    let mut prefix_multi = false;
    let mut initials_hit: Option<&'static str> = None;
    let mut initials_multi = false;
    for (name, _) in PS_FLAGS {
        let name_lower = name.to_ascii_lowercase();
        if name_lower == stripped {
            // Exact match always wins.
            return Some(*name);
        }
        if name_lower.starts_with(stripped) {
            if prefix_hit.is_some() {
                prefix_multi = true;
            } else {
                prefix_hit = Some(*name);
            }
        }
        if camel_initials(name) == stripped {
            if initials_hit.is_some() {
                initials_multi = true;
            } else {
                initials_hit = Some(*name);
            }
        }
    }
    if prefix_multi {
        if let Some((_, override_to)) = SHORTCUT_OVERRIDES
            .iter()
            .find(|(prefix, _)| *prefix == stripped)
        {
            return Some(*override_to);
        }
    } else if let Some(hit) = prefix_hit {
        return Some(hit);
    }
    if !initials_multi {
        if let Some(hit) = initials_hit {
            return Some(hit);
        }
    }
    None
}

fn attached_ps_flag_value(token: &str) -> Option<(&'static str, &str)> {
    let stripped = token
        .strip_prefix('/')
        .or_else(|| token.strip_prefix('-'))?;
    let delimiter = stripped.find([':', '='])?;
    let flag = canonical_ps_flag(&token[..token.len() - stripped.len() + delimiter])?;
    let value = &stripped[delimiter + 1..];
    if value.is_empty() || !flag_takes_value(flag) {
        return None;
    }
    Some((flag, value))
}

fn flag_takes_value(flag: &str) -> bool {
    PS_FLAGS
        .iter()
        .find(|(name, _)| *name == flag)
        .map(|(_, v)| *v)
        .unwrap_or(false)
}

fn is_command_flag(flag: &str) -> bool {
    flag == "Command"
}
fn is_encoded_flag(flag: &str) -> bool {
    flag == "EncodedCommand"
}
fn is_file_flag(flag: &str) -> bool {
    flag == "File"
}

pub fn h_powershell(raw: &str, env: &mut Environment) {
    let tokens = split_words(raw);
    if tokens.is_empty() {
        return;
    }
    let mut i = 1usize;
    while i < tokens.len() {
        let t = &tokens[i];
        if let Some((flag, value)) = attached_ps_flag_value(t) {
            if is_encoded_flag(flag) {
                let s = collect_encoded_argument_with_prefix(value, &tokens[i + 1..]);
                if !s.is_empty() {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s) {
                        env.exec_ps1.push(decoded);
                    }
                }
                return;
            }
            if is_command_flag(flag) {
                let body = command_body_from_attached_value(value, &tokens[i + 1..]);
                let body = trim_nul_padding_body(&body);
                if !body.is_empty() {
                    record_downloadfile_side_effects(body, env);
                    env.exec_ps1.push(body.as_bytes().to_vec());
                }
                return;
            }
            if is_file_flag(flag) {
                return;
            }
            i += 1;
            continue;
        }
        match canonical_ps_flag(t) {
            Some(flag) if is_encoded_flag(flag) => {
                let s = collect_encoded_argument(&tokens[i + 1..]);
                if !s.is_empty() {
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(s) {
                        env.exec_ps1.push(decoded);
                    }
                }
                return;
            }
            Some(flag) if is_command_flag(flag) => {
                let body = tokens[i + 1..].join(" ");
                let body = body.trim();
                let body = body.trim_matches('"').trim_matches('\'');
                let body = trim_nul_padding_body(body);
                if !body.is_empty() {
                    record_downloadfile_side_effects(body, env);
                    env.exec_ps1.push(body.as_bytes().to_vec());
                }
                return;
            }
            Some(flag) if is_file_flag(flag) => return,
            Some(flag) => {
                i += if flag_takes_value(flag) { 2 } else { 1 };
                continue;
            }
            None => {}
        }
        i += 1;
    }
    // No -Command/-EncodedCommand/-File flag was found. The PowerShell command
    // is in the positional arguments. Skip PS-meta flags (and their values
    // when they take one) and push the remainder as the script body.
    let body = skip_ps_meta_flags(&tokens[1..]);
    let body = trim_nul_padding_body(&body);
    if !body.is_empty() {
        record_downloadfile_side_effects(body, env);
        env.exec_ps1.push(body.as_bytes().to_vec());
    }
}

fn record_downloadfile_side_effects(body: &str, env: &mut Environment) {
    for (src, dst) in crate::ps1_scan::ps_downloadfile_calls(body) {
        let Some(dst) = dst else {
            continue;
        };
        if !downloadfile_side_effect_content_supported(&src) {
            continue;
        }
        env.modified_filesystem
            .insert(dst.to_ascii_lowercase(), FsEntry::Download { src });
    }
}

fn downloadfile_side_effect_content_supported(src: &str) -> bool {
    src.to_ascii_lowercase().contains("ip-api.com/csv")
}

fn trim_nul_padding_body(body: &str) -> &str {
    const MIN_NUL_PADDING_BYTES: usize = 1024;

    let Some(first_nul) = body.as_bytes().iter().position(|&b| b == 0) else {
        return body;
    };
    let tail = &body[first_nul..];
    let nul_count = tail.as_bytes().iter().filter(|&&b| b == 0).count();
    if tail.len() >= MIN_NUL_PADDING_BYTES && nul_count * 100 >= tail.len() * 90 {
        body[..first_nul].trim_end()
    } else {
        body
    }
}

fn skip_ps_meta_flags(tokens: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        if attached_ps_flag_value(t).is_some() {
            i += 1;
            continue;
        }
        if let Some(flag) = canonical_ps_flag(t) {
            i += if flag_takes_value(flag) { 2 } else { 1 };
            continue;
        }
        out.push(t.clone());
        i += 1;
    }
    out.join(" ")
}

fn command_body_from_attached_value(value: &str, rest: &[String]) -> String {
    let first = strip_quotes(value);
    if rest.is_empty() {
        first.to_string()
    } else {
        let mut body = String::from(first);
        body.push(' ');
        body.push_str(&rest.join(" "));
        body.trim().trim_matches('"').trim_matches('\'').to_string()
    }
}

fn collect_encoded_argument_with_prefix(first: &str, rest: &[String]) -> String {
    let mut out = String::new();
    let first = strip_quotes(first);
    if first.is_empty() || !first.chars().all(is_base64_char) {
        return out;
    }
    out.push_str(first);
    if first.ends_with('=') {
        return out;
    }
    out.push_str(&collect_encoded_argument(rest));
    out
}

fn collect_encoded_argument(tokens: &[String]) -> String {
    let mut out = String::new();
    for token in tokens {
        let s = strip_quotes(token);
        if s.is_empty() || !s.chars().all(is_base64_char) {
            break;
        }
        out.push_str(s);
        if s.ends_with('=') {
            break;
        }
    }
    out
}

fn strip_quotes(s: &str) -> &str {
    s.trim().trim_matches(['"', '\''])
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn canonical_resolves_prefix_shorthand() {
        assert_eq!(canonical_ps_flag("-Enc"), Some("EncodedCommand"));
        assert_eq!(canonical_ps_flag("-Encoded"), Some("EncodedCommand"));
        assert_eq!(canonical_ps_flag("-NoP"), Some("NoProfile"));
        assert_eq!(canonical_ps_flag("-NonI"), Some("NonInteractive"));
        assert_eq!(canonical_ps_flag("-NoE"), Some("NoExit"));
        assert_eq!(canonical_ps_flag("-NoL"), Some("NoLogo"));
        assert_eq!(canonical_ps_flag("-Sta"), Some("Sta"));
        assert_eq!(canonical_ps_flag("-V"), Some("Version"));
        assert_eq!(canonical_ps_flag("/c"), Some("Command"));
        assert_eq!(canonical_ps_flag("-F"), Some("File"));
        assert_eq!(canonical_ps_flag("-W"), Some("WindowStyle"));
    }

    #[test]
    fn canonical_resolves_camelcase_initials() {
        // Initials like `Ec` come from EncodedCommand (E + C), and aren't a
        // literal prefix of any flag name — exercise the initials path.
        assert_eq!(canonical_ps_flag("-Ec"), Some("EncodedCommand"));
        assert_eq!(canonical_ps_flag("-Ep"), Some("ExecutionPolicy"));
        assert_eq!(canonical_ps_flag("-Ws"), Some("WindowStyle"));
        assert_eq!(canonical_ps_flag("-Np"), Some("NoProfile"));
        assert_eq!(canonical_ps_flag("-Ni"), Some("NonInteractive"));
        assert_eq!(canonical_ps_flag("-If"), Some("InputFormat"));
        assert_eq!(canonical_ps_flag("-Of"), Some("OutputFormat"));
        assert_eq!(canonical_ps_flag("-Cn"), Some("ConfigurationName"));
    }

    #[test]
    fn canonical_returns_none_for_ambiguous_or_unknown() {
        // `-No` is a prefix of NoProfile/NonInteractive/NoExit/NoLogo and
        // not an exact match — ambiguous, no override.
        assert_eq!(canonical_ps_flag("-No"), None);
        // Not a flag at all.
        assert_eq!(canonical_ps_flag("BypASs"), None);
        assert_eq!(canonical_ps_flag(""), None);
    }

    #[test]
    fn dash_e_resolves_to_encodedcommand_via_override() {
        // `-e` is prefix-ambiguous between EncodedCommand and ExecutionPolicy.
        // PS resolves it to EncodedCommand by internal precedence.
        assert_eq!(canonical_ps_flag("-e"), Some("EncodedCommand"));
        assert_eq!(canonical_ps_flag("/e"), Some("EncodedCommand"));
    }

    #[test]
    fn ex_resolves_to_executionpolicy_not_encodedcommand() {
        // `-Ex` is a literal prefix of -ExecutionPolicy and is also the
        // CamelCase abbreviation of `-ExecutionPolicy` (E+x lower = ex). It
        // must NOT match -EncodedCommand.
        assert_eq!(canonical_ps_flag("-Ex"), Some("ExecutionPolicy"));
        assert_eq!(canonical_ps_flag("-eX"), Some("ExecutionPolicy"));
    }

    #[test]
    fn dash_co_resolves_to_command_via_override() {
        // `-co` is prefix-ambiguous between Command and ConfigurationName.
        // Old CMD_FLAG_RE accepted -co / -com / -comm / -comma / -comman as
        // Command shortcuts; preserve that legacy via SHORTCUT_OVERRIDES.
        assert_eq!(canonical_ps_flag("-co"), Some("Command"));
        assert_eq!(canonical_ps_flag("/co"), Some("Command"));
        assert_eq!(canonical_ps_flag("-Co"), Some("Command"));
        // Longer prefixes are unambiguous via the prefix path and resolve
        // to Command without needing the override.
        assert_eq!(canonical_ps_flag("-com"), Some("Command"));
        assert_eq!(canonical_ps_flag("-Command"), Some("Command"));
    }
}
