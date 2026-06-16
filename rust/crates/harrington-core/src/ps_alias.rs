//! PowerShell alias expansion. Replaces common aliases with their
//! canonical cmdlet names for analyst readability and to ensure
//! URL-extraction regexes catch alias forms.

use once_cell::sync::Lazy;
use std::collections::HashMap;

// Source: PowerShell 5.1 default aliases (Get-Alias)
// https://learn.microsoft.com/en-us/powershell/scripting/learn/shell/using-aliases
const ALIAS_TABLE: &[(&str, &str)] = &[
    // Networking
    ("iwr", "Invoke-WebRequest"),
    ("irm", "Invoke-RestMethod"),
    ("wget", "Invoke-WebRequest"),
    ("curl", "Invoke-WebRequest"),
    ("tnc", "Test-NetConnection"),
    // Execution
    ("iex", "Invoke-Expression"),
    ("icm", "Invoke-Command"),
    ("ihy", "Invoke-History"),
    ("ii", "Invoke-Item"),
    // Item operations
    ("gi", "Get-Item"),
    ("gci", "Get-ChildItem"),
    ("ls", "Get-ChildItem"),
    ("dir", "Get-ChildItem"),
    ("ni", "New-Item"),
    ("si", "Set-Item"),
    ("ri", "Remove-Item"),
    ("rm", "Remove-Item"),
    ("rmdir", "Remove-Item"),
    ("del", "Remove-Item"),
    ("erase", "Remove-Item"),
    ("ci", "Copy-Item"),
    ("cp", "Copy-Item"),
    ("copy", "Copy-Item"),
    ("mi", "Move-Item"),
    ("mv", "Move-Item"),
    ("move", "Move-Item"),
    ("rni", "Rename-Item"),
    ("ren", "Rename-Item"),
    // Item property
    ("gp", "Get-ItemProperty"),
    ("sp", "Set-ItemProperty"),
    ("clp", "Clear-ItemProperty"),
    ("rp", "Remove-ItemProperty"),
    // Content
    ("gc", "Get-Content"),
    ("type", "Get-Content"),
    ("cat", "Get-Content"),
    ("sc", "Set-Content"),
    ("ac", "Add-Content"),
    ("clc", "Clear-Content"),
    // Variables
    ("gv", "Get-Variable"),
    ("sv", "Set-Variable"),
    ("nv", "New-Variable"),
    ("rv", "Remove-Variable"),
    // Location
    ("cd", "Set-Location"),
    ("chdir", "Set-Location"),
    ("sl", "Set-Location"),
    ("pwd", "Get-Location"),
    ("gl", "Get-Location"),
    ("popd", "Pop-Location"),
    ("pushd", "Push-Location"),
    // Output
    ("echo", "Write-Output"),
    ("write", "Write-Output"),
    // Object operations
    ("where", "Where-Object"),
    ("foreach", "ForEach-Object"),
    ("select", "Select-Object"),
    ("sort", "Sort-Object"),
    ("group", "Group-Object"),
    ("measure", "Measure-Object"),
    ("tee", "Tee-Object"),
    // Processes
    ("ps", "Get-Process"),
    ("gps", "Get-Process"),
    ("kill", "Stop-Process"),
    ("spps", "Stop-Process"),
    ("saps", "Start-Process"),
    ("start", "Start-Process"),
    // Services
    ("spsv", "Stop-Service"),
    ("gsv", "Get-Service"),
    ("sasv", "Start-Service"),
    ("ssv", "Set-Service"),
    // WMI / CIM
    ("gwmi", "Get-WmiObject"),
    ("gcim", "Get-CimInstance"),
    ("rwmi", "Remove-WmiObject"),
    // History
    ("h", "Get-History"),
    ("history", "Get-History"),
    // Modules
    ("ipmo", "Import-Module"),
    ("rmo", "Remove-Module"),
    ("gmo", "Get-Module"),
    // Misc
    ("clear", "Clear-Host"),
    ("cls", "Clear-Host"),
    ("man", "Get-Help"),
    ("help", "Get-Help"),
    ("gjb", "Get-Job"),
    ("rcjb", "Receive-Job"),
    // Type / member
    ("gm", "Get-Member"),
    ("gu", "Get-Unique"),
    // Conversion
    ("etsn", "Enter-PSSession"),
    ("rcv", "Receive-Job"),
];

static ALIAS_MAP: Lazy<HashMap<&'static str, &'static str>> =
    Lazy::new(|| ALIAS_TABLE.iter().copied().collect());

/// True when `text` has visible evidence of a PowerShell context: a
/// `powershell`/`pwsh` invocation literal, a PS-distinctive Verb-Noun
/// cmdlet, a `$`-sigil variable, a `::` static-member access, or a
/// networking-alias invocation at command position (`iex`, `iwr`, `irm`,
/// `wget`, `curl`). Used to gate alias expansion so we don't rewrite
/// CMD/batch tokens that share names with PS aliases (`start`, `cd`,
/// `dir`, `copy`, `del`, `cls`, ...). The alias-at-cmd-position case is
/// load-bearing for modern droppers — they often build a pure-alias
/// payload like `iex(iwr 'http://x')` with no `$`, no `::`, no
/// Verb-Noun, and no literal `powershell` substring.
pub fn looks_like_powershell(text: &str) -> bool {
    use regex::Regex;
    #[allow(clippy::expect_used)]
    static MARKERS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?ix)
              \b(?:powershell(?:\.exe)?|pwsh)\b
            | \$ [A-Za-z_] [A-Za-z0-9_:]*
            | \b(?:Get|Set|New|Remove|Invoke|Add|Clear|Copy|Move|Rename
                  |Out|Where|ForEach|Select|Sort|Group|Measure|Tee
                  |Import|Export|ConvertTo|ConvertFrom|Start|Stop|Enter|Exit
                  |Write|Read|Test|Format) - [A-Z][A-Za-z]+ \b
            | :: [A-Za-z_]
            | (?:^|[\s;|&(]) (?:iex|iwr|irm|ii|si|wget|curl|tnc|gwmi|gcim|rwmi|gps|gsv|sasv|ssv) (?:\s|$|[\(\;\&\|])
            ",
        )
        .expect("ps marker re")
    });
    MARKERS_RE.is_match(text)
}

/// Alias expansion gated by a PowerShell-context check. Returns the text
/// unchanged when `looks_like_powershell` says no.
pub fn expand_aliases_if_ps(text: &str) -> String {
    if !looks_like_powershell(text) {
        return text.to_string();
    }
    expand_aliases(text)
}

/// Replace standalone alias tokens with their canonical cmdlet names.
/// Word-boundary aware; case-insensitive match; preserves the rest verbatim.
pub fn expand_aliases(text: &str) -> String {
    use regex::Regex;
    // Match a PS token (word) at a position where it could be a command:
    // - start of input, OR
    // - after whitespace, `;`, `|`, `(`, `{`, `&`, or `\n`
    // Capture the lead char and the token.
    #[allow(clippy::expect_used)]
    static ALIAS_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r#"(?P<lead>^|[\s;|(){}&"'`])(?P<tok>[A-Za-z]+)\b"#).expect("alias re")
    });
    let mut out = String::with_capacity(text.len());
    let mut last_end = 0;
    let bytes = text.as_bytes();
    for caps in ALIAS_RE.captures_iter(text) {
        let m = match caps.get(0) {
            Some(m) => m,
            None => continue,
        };
        out.push_str(&text[last_end..m.start()]);
        if alias_match_inside_quoted_literal(text, m.start()) {
            out.push_str(&text[m.start()..m.end()]);
            last_end = m.end();
            continue;
        }
        let lead = caps.name("lead").map(|x| x.as_str()).unwrap_or("");
        let tok = caps.name("tok").map(|x| x.as_str()).unwrap_or("");
        let next = bytes.get(m.end()).copied();
        if next == Some(b':') {
            out.push_str(&text[m.start()..m.end()]);
            last_end = m.end();
            continue;
        }
        let quoted_single_token = matches!(lead.as_bytes().last(), Some(b'\'' | b'"' | b'`'))
            && next == lead.as_bytes().last().copied();
        let quoted_invocation_or_assignment = quoted_single_token
            && previous_non_ws_byte(bytes, m.start()).is_some_and(|b| matches!(b, b'&' | b'='));
        if quoted_single_token && !quoted_invocation_or_assignment {
            out.push_str(&text[m.start()..m.end()]);
            last_end = m.end();
            continue;
        }
        let is_cmdlet_head = matches!(next, Some(b'-'));
        let key = tok.to_ascii_lowercase();
        if key == "foreach" && is_foreach_language_statement(&text[m.end()..]) {
            out.push_str(&text[m.start()..m.end()]);
            last_end = m.end();
            continue;
        }
        if !is_cmdlet_head {
            if let Some(canonical) = ALIAS_MAP.get(key.as_str()) {
                out.push_str(lead);
                out.push_str(canonical);
                last_end = m.end();
                continue;
            }
        }
        out.push_str(&text[m.start()..m.end()]);
        last_end = m.end();
    }
    out.push_str(&text[last_end..]);
    out
}

fn alias_match_inside_quoted_literal(text: &str, pos: usize) -> bool {
    let mut idx = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while idx < pos {
        let Some(ch) = text[idx..].chars().next() else {
            break;
        };
        let next_idx = idx + ch.len_utf8();
        if in_single {
            if ch == '\'' {
                if text[next_idx..].starts_with('\'') {
                    idx = next_idx + 1;
                    continue;
                }
                in_single = false;
            }
            idx = next_idx;
            continue;
        }
        if in_double {
            if ch == '`' {
                let Some(escaped) = text[next_idx..].chars().next() else {
                    idx = next_idx;
                    continue;
                };
                idx = next_idx + escaped.len_utf8();
                continue;
            }
            if ch == '"' {
                in_double = false;
            }
            idx = next_idx;
            continue;
        }
        match ch {
            '\'' => in_single = true,
            '"' if !double_quote_starts_powershell_command_arg(text, idx) => in_double = true,
            '`' => {
                let Some(escaped) = text[next_idx..].chars().next() else {
                    idx = next_idx;
                    continue;
                };
                idx = next_idx + escaped.len_utf8();
                continue;
            }
            _ => {}
        }
        idx = next_idx;
    }
    in_single || in_double
}

fn double_quote_starts_powershell_command_arg(text: &str, quote_pos: usize) -> bool {
    let before = text[..quote_pos].trim_end();
    let Some(token) = before
        .rsplit(|ch: char| ch.is_whitespace() || matches!(ch, ';' | '|' | '&' | '('))
        .find(|part| !part.is_empty())
    else {
        return false;
    };
    matches!(
        token.to_ascii_lowercase().as_str(),
        "-c" | "-command" | "/c" | "/command"
    )
}

fn is_foreach_language_statement(after_token: &str) -> bool {
    let after = after_token.trim_start();
    after.starts_with('(')
}

fn previous_non_ws_byte(bytes: &[u8], pos: usize) -> Option<u8> {
    bytes
        .get(..pos)?
        .iter()
        .rev()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
}
