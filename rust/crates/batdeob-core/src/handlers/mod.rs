//! Per-command handlers and dispatch table.

use crate::env::Environment;

pub mod auto_elevate;
pub mod bitsadmin;
pub mod call;
pub mod certoc;
pub mod certreq;
pub mod certutil;
pub mod cmd;
pub mod cmstp;
pub mod copy;
pub mod cscript;
pub mod curl;
pub mod desktopimgdownldr;
pub mod echo;
pub mod esentutl;
pub mod extrac32;
pub mod for_cmd;
pub mod ftp;
pub mod goto;
pub mod hh;
pub mod if_cmd;
pub mod msconfig;
pub mod mshta;
pub mod msiexec;
pub mod net;
pub mod passthrough;
pub mod powershell;
pub mod regsvr32;
pub mod replace;
pub mod robocopy;
pub mod rundll32;
pub mod set;
pub mod setlocal;
pub mod url_launch;
pub(crate) mod util;
pub mod wget;
pub mod wmic;

pub type Handler = fn(raw: &str, env: &mut Environment);

pub fn lookup(name: &str) -> Option<Handler> {
    // Match the *basename* (after the last path separator, stripped of a
    // trailing `.exe`). Old logic used `ends_with("cmd")` which routed
    // `flashcmd.exe` → h_cmd which then failed CMD_RE silently. Exact-
    // match means a renamed-binary case is left for downstream callers to
    // detect explicitly rather than mis-dispatched to a parser that won't
    // understand it.
    let base = basename_no_ext(name);
    if [
        "computerdefaults",
        "eventvwr",
        "fodhelper",
        "sdclt",
        "wsreset",
    ]
    .iter()
    .any(|launcher| base.eq_ignore_ascii_case(launcher))
    {
        return Some(auto_elevate::h_auto_elevate);
    }
    if base.eq_ignore_ascii_case("cmd") {
        return Some(cmd::h_cmd);
    }
    if base.eq_ignore_ascii_case("powershell") || base.eq_ignore_ascii_case("pwsh") {
        return Some(powershell::h_powershell);
    }
    if base.eq_ignore_ascii_case("curl") {
        return Some(curl::h_curl);
    }
    if base.eq_ignore_ascii_case("wget") || base.eq_ignore_ascii_case("get") {
        return Some(wget::h_wget);
    }
    if base.eq_ignore_ascii_case("msiexec") {
        return Some(msiexec::h_msiexec);
    }
    if base.eq_ignore_ascii_case("mshta") {
        return Some(mshta::h_mshta);
    }
    if base.eq_ignore_ascii_case("msconfig") {
        return Some(msconfig::h_msconfig);
    }
    if base.eq_ignore_ascii_case("regsvr32") {
        return Some(regsvr32::h_regsvr32);
    }
    if base.eq_ignore_ascii_case("replace") {
        return Some(replace::h_replace);
    }
    if base.eq_ignore_ascii_case("robocopy") {
        return Some(robocopy::h_robocopy);
    }
    if base.eq_ignore_ascii_case("rundll32") {
        return Some(rundll32::h_rundll32);
    }
    if base.eq_ignore_ascii_case("certoc") {
        return Some(certoc::h_certoc);
    }
    if base.eq_ignore_ascii_case("certreq") {
        return Some(certreq::h_certreq);
    }
    if base.eq_ignore_ascii_case("certutil") {
        return Some(certutil::h_certutil);
    }
    if base.eq_ignore_ascii_case("cmstp") {
        return Some(cmstp::h_cmstp);
    }
    if base.eq_ignore_ascii_case("desktopimgdownldr") {
        return Some(desktopimgdownldr::h_desktopimgdownldr);
    }
    if base.eq_ignore_ascii_case("esentutl") {
        return Some(esentutl::h_esentutl);
    }
    if base.eq_ignore_ascii_case("ftp") {
        return Some(ftp::h_ftp);
    }
    if base.eq_ignore_ascii_case("hh") {
        return Some(hh::h_hh);
    }
    if [
        "brave", "chrome", "explorer", "firefox", "iexplore", "msedge", "opera",
    ]
    .iter()
    .any(|launcher| base.eq_ignore_ascii_case(launcher))
    {
        return Some(url_launch::h_url_launch);
    }
    if base.eq_ignore_ascii_case("call") {
        return Some(call::h_call);
    }
    if base.eq_ignore_ascii_case("set") {
        return Some(set::h_set);
    }
    if base.eq_ignore_ascii_case("echo") {
        return Some(echo::h_echo);
    }
    if base.eq_ignore_ascii_case("start") {
        return Some(cmd::h_start);
    }
    if base.eq_ignore_ascii_case("net") {
        return Some(net::h_net);
    }
    if base.eq_ignore_ascii_case("copy") {
        return Some(copy::h_copy);
    }
    if base.eq_ignore_ascii_case("setlocal") {
        return Some(setlocal::h_setlocal);
    }
    if base.eq_ignore_ascii_case("endlocal") {
        return Some(setlocal::h_endlocal);
    }
    if base.eq_ignore_ascii_case("goto") {
        return Some(goto::h_goto);
    }
    if base.eq_ignore_ascii_case("exit") {
        return Some(goto::h_exit);
    }
    if base.eq_ignore_ascii_case("if") {
        return Some(if_cmd::h_if);
    }
    if base.eq_ignore_ascii_case("for") {
        return Some(for_cmd::h_for);
    }
    if base.eq_ignore_ascii_case("bitsadmin") {
        return Some(bitsadmin::h_bitsadmin);
    }
    if base.eq_ignore_ascii_case("cscript") {
        return Some(cscript::h_cscript);
    }
    if base.eq_ignore_ascii_case("extrac32") {
        return Some(extrac32::h_extrac32);
    }
    if base.eq_ignore_ascii_case("wscript") {
        return Some(cscript::h_wscript);
    }
    if base.eq_ignore_ascii_case("wmic") {
        return Some(wmic::h_wmic);
    }
    if base.eq_ignore_ascii_case("psexec") {
        return Some(passthrough::h_psexec);
    }
    if base.eq_ignore_ascii_case("winrm") {
        return Some(passthrough::h_winrm);
    }
    if base.eq_ignore_ascii_case("winrs") {
        return Some(passthrough::h_winrs);
    }
    if base.eq_ignore_ascii_case("del") {
        return Some(passthrough::h_del);
    }
    if base.eq_ignore_ascii_case("cls") {
        return Some(passthrough::h_cls);
    }
    if base.eq_ignore_ascii_case("timeout") {
        return Some(passthrough::h_timeout);
    }
    if base.eq_ignore_ascii_case("reg") {
        return Some(passthrough::h_reg);
    }
    if base.eq_ignore_ascii_case("attrib") {
        return Some(passthrough::h_attrib);
    }
    if base.eq_ignore_ascii_case("mkdir") {
        return Some(passthrough::h_mkdir);
    }
    if base.eq_ignore_ascii_case("md") {
        return Some(passthrough::h_md);
    }
    if base.eq_ignore_ascii_case("move") {
        return Some(copy::h_move);
    }
    if base.eq_ignore_ascii_case("rmdir") {
        return Some(passthrough::h_rmdir);
    }
    if base.eq_ignore_ascii_case("rd") {
        return Some(passthrough::h_rd);
    }
    if base.eq_ignore_ascii_case("taskkill") {
        return Some(passthrough::h_taskkill);
    }
    if base.eq_ignore_ascii_case("tasklist") {
        return Some(passthrough::h_tasklist);
    }
    if base.eq_ignore_ascii_case("schtasks") {
        return Some(passthrough::h_schtasks);
    }
    if base.eq_ignore_ascii_case("sc") {
        return Some(passthrough::h_sc);
    }
    if base.eq_ignore_ascii_case("at") {
        return Some(passthrough::h_at);
    }
    if base.eq_ignore_ascii_case("runas") {
        return Some(passthrough::h_runas);
    }
    if base.eq_ignore_ascii_case("ping") {
        return Some(passthrough::h_ping);
    }
    if base.eq_ignore_ascii_case("xcopy") {
        return Some(copy::h_xcopy);
    }
    if base.eq_ignore_ascii_case("title") {
        return Some(passthrough::h_title);
    }
    if base.eq_ignore_ascii_case("pause") {
        return Some(passthrough::h_pause);
    }
    if base.eq_ignore_ascii_case("color") {
        return Some(passthrough::h_color);
    }
    if base.eq_ignore_ascii_case("doskey") {
        return Some(passthrough::h_doskey);
    }
    if base.eq_ignore_ascii_case("chcp") {
        return Some(passthrough::h_chcp);
    }
    if base.eq_ignore_ascii_case("ver") {
        return Some(passthrough::h_ver);
    }
    if base.eq_ignore_ascii_case("whoami") {
        return Some(passthrough::h_whoami);
    }
    None
}

/// Basename of a path-like command token, stripped of a trailing `.exe`.
/// Handles both `\` (Windows) and `/` (Unix) separators plus quoted forms.
fn basename_no_ext(name: &str) -> &str {
    let s = name.trim_matches(['"', '\'']);
    let last_sep = s.rfind(['\\', '/']).map(|i| i + 1).unwrap_or(0);
    let base = &s[last_sep..];
    let base = base.trim_end_matches('.');
    if base
        .as_bytes()
        .get(base.len().saturating_sub(4)..)
        .is_some_and(|tail| tail.len() == 4 && tail.eq_ignore_ascii_case(b".exe"))
    {
        &base[..base.len() - 4]
    } else {
        base
    }
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
        assert_eq!(basename_no_ext("powershell."), "powershell");
        assert_eq!(basename_no_ext("PoWeRsHeLl.ExE"), "PoWeRsHeLl");
        assert_eq!(basename_no_ext("óó1"), "óó1");
    }

    #[test]
    fn renamed_binary_does_not_match_real_handler() {
        // Old behavior: `ends_with("cmd")` routed flashcmd.exe to h_cmd which
        // then failed silently. Now flashcmd is a distinct identifier and
        // gets no handler (returns None from lookup).
        assert_eq!(basename_no_ext("flashcmd.exe"), "flashcmd");
        assert_eq!(basename_no_ext("winhttpcmd"), "winhttpcmd");
        assert_eq!(basename_no_ext("\"runpowershell.exe\""), "runpowershell");
        assert_eq!(basename_no_ext("\"runpowershell.exe.\""), "runpowershell");
    }
}
