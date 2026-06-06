//! Per-command handlers and dispatch table.

use crate::env::Environment;

pub mod bitsadmin;
pub mod call;
pub mod certoc;
pub mod certreq;
pub mod certutil;
pub mod cmd;
pub mod copy;
pub mod cscript;
pub mod curl;
pub mod desktopimgdownldr;
pub mod echo;
pub mod extrac32;
pub mod for_cmd;
pub mod goto;
pub mod if_cmd;
pub mod mshta;
pub mod msiexec;
pub mod net;
pub mod passthrough;
pub mod powershell;
pub mod regsvr32;
pub mod rundll32;
pub mod set;
pub mod setlocal;
pub(crate) mod util;
pub mod wget;
pub mod wmic;

pub type Handler = fn(raw: &str, env: &mut Environment);

pub fn lookup(name: &str) -> Option<Handler> {
    let lower = name.to_ascii_lowercase();
    // Match the *basename* (after the last path separator, stripped of a
    // trailing `.exe`). Old logic used `ends_with("cmd")` which routed
    // `flashcmd.exe` → h_cmd which then failed CMD_RE silently. Exact-
    // match means a renamed-binary case is left for downstream callers to
    // detect explicitly rather than mis-dispatched to a parser that won't
    // understand it.
    let base = basename_no_ext(&lower);
    match base {
        "cmd" => return Some(cmd::h_cmd),
        "powershell" | "pwsh" => return Some(powershell::h_powershell),
        "curl" => return Some(curl::h_curl),
        "wget" | "get" => return Some(wget::h_wget),
        "msiexec" => return Some(msiexec::h_msiexec),
        "mshta" => return Some(mshta::h_mshta),
        "regsvr32" => return Some(regsvr32::h_regsvr32),
        "rundll32" => return Some(rundll32::h_rundll32),
        "certoc" => return Some(certoc::h_certoc),
        "certreq" => return Some(certreq::h_certreq),
        "certutil" => return Some(certutil::h_certutil),
        "desktopimgdownldr" => return Some(desktopimgdownldr::h_desktopimgdownldr),
        _ => {}
    }
    match lower.as_str() {
        "call" => Some(call::h_call),
        "set" => Some(set::h_set),
        "echo" => Some(echo::h_echo),
        "start" => Some(cmd::h_start),
        "net" => Some(net::h_net),
        "copy" => Some(copy::h_copy),
        "setlocal" => Some(setlocal::h_setlocal),
        "endlocal" => Some(setlocal::h_endlocal),
        "goto" => Some(goto::h_goto),
        "exit" => Some(goto::h_exit),
        "if" => Some(if_cmd::h_if),
        "for" => Some(for_cmd::h_for),
        "bitsadmin" => Some(bitsadmin::h_bitsadmin),
        "cscript" => Some(cscript::h_cscript),
        "extrac32" => Some(extrac32::h_extrac32),
        "wscript" => Some(cscript::h_wscript),
        "wmic" => Some(wmic::h_wmic),
        "del" => Some(passthrough::h_del),
        "cls" => Some(passthrough::h_cls),
        "timeout" => Some(passthrough::h_timeout),
        "reg" => Some(passthrough::h_reg),
        "attrib" => Some(passthrough::h_attrib),
        "mkdir" => Some(passthrough::h_mkdir),
        "md" => Some(passthrough::h_md),
        "move" => Some(passthrough::h_move),
        "rmdir" => Some(passthrough::h_rmdir),
        "rd" => Some(passthrough::h_rd),
        "taskkill" => Some(passthrough::h_taskkill),
        "tasklist" => Some(passthrough::h_tasklist),
        "schtasks" => Some(passthrough::h_schtasks),
        "sc" => Some(passthrough::h_sc),
        "ping" => Some(passthrough::h_ping),
        "xcopy" => Some(copy::h_xcopy),
        "title" => Some(passthrough::h_title),
        "pause" => Some(passthrough::h_pause),
        "color" => Some(passthrough::h_color),
        "doskey" => Some(passthrough::h_doskey),
        "chcp" => Some(passthrough::h_chcp),
        "ver" => Some(passthrough::h_ver),
        "whoami" => Some(passthrough::h_whoami),
        _ => None,
    }
}

/// Lowercased basename of a path-like command token, stripped of a
/// trailing `.exe`. Handles both `\` (Windows) and `/` (Unix) separators
/// plus quoted forms.
fn basename_no_ext(lower: &str) -> &str {
    let s = lower.trim_matches(['"', '\'']);
    let last_sep = s.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
    let base = &s[last_sep..];
    base.strip_suffix(".exe").unwrap_or(base)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod basename_tests {
    use super::basename_no_ext;

    #[test]
    fn strips_exe_and_directory() {
        assert_eq!(basename_no_ext("powershell"), "powershell");
        assert_eq!(basename_no_ext("powershell.exe"), "powershell");
        assert_eq!(
            basename_no_ext("c:\\windows\\system32\\powershell.exe"),
            "powershell"
        );
        assert_eq!(basename_no_ext("c:/windows/system32/cmd.exe"), "cmd");
    }

    #[test]
    fn renamed_binary_does_not_match_real_handler() {
        // Old behavior: `ends_with("cmd")` routed flashcmd.exe to h_cmd which
        // then failed silently. Now flashcmd is a distinct identifier and
        // gets no handler (returns None from lookup).
        assert_eq!(basename_no_ext("flashcmd.exe"), "flashcmd");
        assert_eq!(basename_no_ext("winhttpcmd"), "winhttpcmd");
        assert_eq!(basename_no_ext("\"runpowershell.exe\""), "runpowershell");
    }
}
