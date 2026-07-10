//! PowerShell alias expansion. Replaces common aliases with their
//! canonical cmdlet names for analyst readability and to ensure
//! URL-extraction regexes catch alias forms.

use once_cell::sync::Lazy;

const MAX_ALIAS_EXPANSION_BYTES: usize = 64 * 1024;
const MAX_ALIAS_EXPANSION_MATCHES: usize = 8192;

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
    // History
    ("h", "Get-History"),
    ("history", "Get-History"),
    // Modules
    ("ipmo", "Import-Module"),
    ("rmo", "Remove-Module"),
    ("gmo", "Get-Module"),
    ("gcm", "Get-Command"),
    ("gal", "Get-Alias"),
    // Misc
    ("clear", "Clear-Host"),
    ("cls", "Clear-Host"),
    ("man", "Get-Help"),
    ("help", "Get-Help"),
    ("gjb", "Get-Job"),
    ("rcjb", "Receive-Job"),
    // WMI / services
    ("gwmi", "Get-WmiObject"),
    ("rwmi", "Remove-WmiObject"),
    ("gcim", "Get-CimInstance"),
    ("gsv", "Get-Service"),
    ("sasv", "Start-Service"),
    ("ssv", "Set-Service"),
    // Type / member
    ("gm", "Get-Member"),
    ("gu", "Get-Unique"),
    // Conversion
    ("etsn", "Enter-PSSession"),
    ("rcv", "Receive-Job"),
];

/// True when `text` has visible evidence of a PowerShell context: a
/// `powershell`/`pwsh` invocation literal, a PS-distinctive Verb-Noun
/// cmdlet, a `$`-sigil variable, a `::` static-member access, or a
/// high-signal alias invocation at command position (`iex`, `iwr`, `irm`,
/// `wget`, `curl`, `tnc`, `ii`, `si`, WMI/service aliases). Used to gate alias expansion so we don't rewrite
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
            | (?:^|[\s;|&(]) (?:iex|iwr|irm|wget|curl|tnc|ii|si|gwmi|rwmi|gcim|gsv|sasv|ssv) (?:\s|$|[\(\;\&\|])
            ",
        )
        .expect("ps marker re")
    });
    MARKERS_RE.is_match(text)
}

/// Alias expansion gated by a PowerShell-context check. Returns the text
/// unchanged when `looks_like_powershell` says no.
pub fn expand_aliases_if_ps(text: &str) -> String {
    if text.len() > MAX_ALIAS_EXPANSION_BYTES {
        return text.to_string();
    }
    if !looks_like_powershell(text) {
        return text.to_string();
    }
    expand_aliases(text)
}

/// Replace standalone alias tokens with their canonical cmdlet names.
/// Word-boundary aware; case-insensitive match; preserves the rest verbatim.
pub fn expand_aliases(text: &str) -> String {
    if text.len() > MAX_ALIAS_EXPANSION_BYTES {
        return text.to_string();
    }
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
    let mut scan_pos = 0;
    let mut string_state = PsStringState::default();
    let mut matches_seen = 0usize;
    let bytes = text.as_bytes();
    for caps in ALIAS_RE.captures_iter(text) {
        matches_seen = matches_seen.saturating_add(1);
        if matches_seen > MAX_ALIAS_EXPANSION_MATCHES {
            break;
        }
        let m = match caps.get(0) {
            Some(m) => m,
            None => continue,
        };
        string_state.advance(text, scan_pos, m.start());
        scan_pos = m.start();
        if string_state.is_inside_string() {
            continue;
        }
        out.push_str(&text[last_end..m.start()]);
        let lead = caps.name("lead").map(|x| x.as_str()).unwrap_or("");
        let tok = caps.name("tok").map(|x| x.as_str()).unwrap_or("");
        let next = bytes.get(m.end()).copied();
        let is_cmdlet_head = matches!(next, Some(b'-' | b':'));
        if tok.eq_ignore_ascii_case("foreach") && is_foreach_language_statement(&text[m.end()..]) {
            out.push_str(&text[m.start()..m.end()]);
            last_end = m.end();
            continue;
        }
        if !is_cmdlet_head {
            if matches!(lead.as_bytes().first(), Some(b'\'' | b'"' | b'`')) && tok.len() == 1 {
                out.push_str(&text[m.start()..m.end()]);
                last_end = m.end();
                continue;
            }
            if let Some((_, canonical)) = ALIAS_TABLE
                .iter()
                .find(|(alias, _)| alias.eq_ignore_ascii_case(tok))
            {
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

#[derive(Default)]
struct PsStringState {
    in_single: bool,
    in_double: bool,
    double_is_command_arg: bool,
}

impl PsStringState {
    fn advance(&mut self, text: &str, from: usize, to: usize) {
        let bytes = text.as_bytes();
        let mut idx = from.min(bytes.len());
        let end = to.min(bytes.len());
        while idx < end {
            match bytes[idx] {
                b'\'' if !self.in_double => {
                    if self.in_single && bytes.get(idx + 1) == Some(&b'\'') {
                        idx += 2;
                        continue;
                    }
                    self.in_single = !self.in_single;
                }
                b'"' if !self.in_single => {
                    if self.in_double {
                        self.in_double = false;
                        self.double_is_command_arg = false;
                    } else {
                        self.in_double = true;
                        self.double_is_command_arg = is_powershell_command_arg(text, idx);
                    }
                }
                b'`' => {
                    idx += 1;
                }
                _ => {}
            }
            idx += 1;
        }
    }

    fn is_inside_string(&self) -> bool {
        self.in_single || (self.in_double && !self.double_is_command_arg)
    }
}

fn is_foreach_language_statement(after_token: &str) -> bool {
    let after = after_token.trim_start();
    after.starts_with('(')
}

fn is_powershell_command_arg(text: &str, quote_start: usize) -> bool {
    let prefix = text[..quote_start].trim_end();
    let Some(flag_start) = prefix.rfind(|ch: char| ch.is_ascii_whitespace()) else {
        return false;
    };
    let flag = &prefix[flag_start..].trim();
    if !matches!(
        flag.to_ascii_lowercase().as_str(),
        "-c" | "-command" | "/c" | "/command"
    ) {
        return false;
    }
    let before_flag = prefix[..flag_start].trim_end();
    before_flag
        .rsplit(|ch: char| ch.is_ascii_whitespace())
        .next()
        .is_some_and(|cmd| {
            let cmd = cmd
                .trim_matches(['"', '\''])
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or(cmd);
            let lower = cmd.to_ascii_lowercase();
            lower == "powershell"
                || lower == "powershell.exe"
                || lower == "pwsh"
                || lower == "pwsh.exe"
        })
}
