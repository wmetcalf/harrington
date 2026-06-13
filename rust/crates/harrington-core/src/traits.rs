//! Typed IOC events emitted during deobfuscation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum Trait {
    // ---- existing (Python parity) ----
    Download {
        cmd: String,
        src: String,
        dst: Option<String>,
    },
    UrlLaunch {
        cmd: String,
        url: String,
    },
    UrlArgument {
        cmd: String,
        url: String,
    },
    UrlVariable {
        name: String,
        url: String,
        cmd: String,
    },
    RemoteConnect {
        cmd: String,
        host: String,
        port: u16,
    },
    RegistryUrl {
        cmd: String,
        value: String,
        url: String,
    },
    NetUse {
        cmd: String,
        info: NetUseInfo,
    },
    Lolbas {
        name: String,
        cmd: String,
    },
    CommandGrouping {
        cmd: String,
        normalized: String,
    },
    StartWithVar {
        cmd: String,
        normalized: String,
    },
    VarUsed {
        cmd: String,
        normalized: String,
        count: u32,
    },
    Mshta {
        cmd: String,
    },
    Rundll32 {
        cmd: String,
        url: Option<String>,
    },
    SetpFileRedirect {
        cmd: String,
        target: String,
    },
    WindowsUtilManip {
        cmd: String,
        src: String,
        dst: String,
    },
    ManipulatedExec {
        cmd: String,
        target: String,
    },
    ComplexOneLiner {
        line_count: u32,
    },
    OneLiner,
    EchoRedirect {
        content: Vec<u8>,
        target: String,
        append: bool,
    },
    SetlocalScope {
        enabled_delayed: bool,
    },
    DelayedExpansionUsed,
    NonUtf8Input,
    IterationCapped {
        command: String,
    },
    DepthCapped {
        command: String,
    },
    ChildScriptsCapped,
    TimeoutHit,

    // ---- placeholders used by later plans (B/C) ----
    Goto {
        from_line: usize,
        to_label: String,
    },
    GotoUnresolved {
        from_line: usize,
        to_label: String,
    },
    Subroutine {
        label: String,
        args: Vec<String>,
    },
    SelfExtract {
        method: String,
    },
    CertutilDecode {
        src: String,
        dst: String,
        src_resolved: bool,
    },
    CertutilDownload {
        url: String,
        dst: String,
    },
    BitsadminDownload {
        url: String,
        dst: String,
    },
    WmicProcessCreate {
        inner_cmd: String,
    },
    CscriptExec {
        src: String,
    },
    WscriptExec {
        src: String,
    },
    Arithmetic {
        expr: String,
        value: i32,
    },
    ArithmeticParseError {
        expr: String,
    },
    IfNotResolved {
        condition: String,
    },
    ForUnresolvedSource {
        pipeline: String,
    },
    GotoLoopCapped {
        label: String,
    },
    OutputCapped {
        bytes_at_cap: u64,
    },
    Extrac32 {
        src: String,
        dst: String,
        self_reference: bool,
    },
    AdminCommand {
        name: String,
        cmd: String,
    },
    /// Local account or group membership change. Examples:
    /// `net user <account> <password> /add` and
    /// `net localgroup Administrators <account> /add`.
    AccountModification {
        action: String,
        account: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group: Option<String>,
        command: String,
    },
    /// File or directory attribute changes used for concealment, such as
    /// `attrib +h +s payload.vbs`.
    FileConcealment {
        target: String,
        attributes: Vec<String>,
        command: String,
    },
    LineTruncated {
        original_len: u64,
    },
    /// Large high-Unicode text carrier, commonly used by PowerShell
    /// droppers that subtract a base codepoint to recover encrypted bytes.
    /// If `truncated` is true, recovery may be impossible because the
    /// carrier was already capped before Harrington received it.
    HighUnicodePayload {
        char_count: u64,
        truncated: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        byte_carrier_base: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        byte_count: Option<u64>,
    },
    TraitsCapped {
        capped_kind: String,
        total: u64,
        kept: u64,
    },
    RegQuery {
        key: String,
        value: Option<String>,
    },
    DirListing {
        path: String,
        flags: Vec<String>,
    },
    RecursiveAnalysis {
        dst: String,
        depth: u32,
    },
    /// A `goto` cycle visited the same source line more times than the
    /// elision threshold. Subsequent visits still execute their handlers
    /// (so IOCs aren't lost) but their text is no longer appended to the
    /// deob output, which keeps `:watchdog \n goto watchdog`-style
    /// infinite loops from filling the 4 MiB output cap with repeated
    /// copies.
    GotoLoopElided {
        line_index: u32,
        visits_before_elision: u32,
    },
    DownloadInDeobText {
        src: String,
        line_hint: String,
    },
    UncWebDavC2 {
        host: String,
        port: String,
        share_path: String,
        command: String,
        /// Microsoft-style http(s):// URL derived from the UNC form.
        /// `\\host@port\davwwwroot\file` -> `http://host:port/file`,
        /// `\\host@SSL\davwwwroot\file` -> `https://host/file`.
        #[serde(default, skip_serializing_if = "String::is_empty")]
        http_url: String,
    },
    MultiStageEncryptedDropper {
        marker: String,
        b64_length: u32,
        has_aes_cbc: bool,
        has_gzip_stage: bool,
        reads_self_lines: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        aes_key_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        aes_iv_b64: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        assemblies_recovered: Option<u32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        nested_aes: Vec<NestedAesKey>,
    },
    /// `Start-Process … -Verb RunAs` invocation — the script is asking
    /// Windows to relaunch a target as administrator (UAC prompt). Common
    /// in droppers that need elevation to write to Startup/Program Files
    /// or to run elevated payloads. The `target` is the FilePath (or first
    /// positional arg) and `args` is the -ArgumentList contents if any.
    SelfElevation {
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        args: Option<String>,
    },
    /// Registry-based persistence: `reg add HKCU\…\Run` (Run / RunOnce /
    /// RunServices / Explorer\Run / Winlogon\Userinit etc.) writes the
    /// dropper's command to a Windows autorun hive. Surfaces as a clear
    /// IOC so analysts can flag persistence behaviour without grepping
    /// the deob text.
    Persistence {
        hive: String,
        key: String,
        value_name: String,
        command: String,
    },
    /// Windows shortcut materialized by script code, such as
    /// `WScript.Shell.CreateShortcut(...).Save`. This captures the link
    /// target without treating it as already executed.
    ShortcutCreated {
        path: String,
        target: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        arguments: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        working_directory: Option<String>,
    },
    /// Windows Defender / AV evasion behaviour. Examples:
    ///   `Add-MpPreference -ExclusionPath 'X'`
    ///   `Set-MpPreference -DisableRealtimeMonitoring $true`
    ///   `Set-MpPreference -SubmitSamplesConsent 2`
    ///   `sc stop WinDefend`
    /// `action` is a short identifier (`exclusion-path`,
    /// `setmp-disablerealtimemonitoring`, `sc-stop`, etc.); `target` is
    /// the path / option value being excluded/set / service name.
    DefenderEvasion {
        action: String,
        target: String,
    },
    /// `[Reflection.Assembly]::Load($bytes)` — loads a .NET assembly
    /// from a byte array entirely in memory, bypassing disk write and
    /// (often) AV scanning. The defining behaviour of the
    /// SOSTENER/banglabillboard family and most .NET-based loaders
    /// (DonutLoader, SilentTrinity, Covenant, etc.). `variant` captures
    /// which Load overload was called (`Load`, `LoadFile`, `LoadFrom`,
    /// `ReflectionOnlyLoad`).
    InMemoryAssemblyLoad {
        variant: String,
    },
    /// Lateral movement / remote execution attempt. Examples:
    ///   `psexec \\<host> ...`
    ///   `wmic /node:<host> process call create ...`
    ///   `winrm invoke ...`  /  `Invoke-Command -ComputerName <host>`
    ///   `schtasks /create /s <host> ...`
    /// `tool` is the binary/cmdlet used; `target_host` is the destination.
    LateralMovement {
        tool: String,
        target_host: String,
    },
    /// Anti-recovery / ransomware preparation. Examples:
    ///   `vssadmin delete shadows /all /quiet`
    ///   `wmic shadowcopy delete`
    ///   `bcdedit /set recoveryenabled no`
    ///   `bcdedit /set bootstatuspolicy ignoreallfailures`
    ///   `wbadmin delete catalog -quiet`
    AntiRecovery {
        action: String,
    },
    /// Evidence cleanup / anti-forensics. Examples:
    ///   `wevtutil cl Security`
    ///   `fsutil usn deletejournal /d C:`
    ///   `del /s /q C:\Windows\Prefetch\*.*`
    ///   `reg delete ...\Explorer\UserAssist`
    EvidenceCleanup {
        action: String,
        target: String,
        command: String,
    },
    /// Network / IP discovery probe. Examples:
    ///   `nslookup <host>`
    ///   `Resolve-DnsName <host>`
    ///   `ping -n 1 <ip>` (non-loopback)
    ///   `curl/wget <ip-discovery-host>` (ipify, checkip.dyndns, ip-api)
    /// `probe_kind` is `dns-lookup` / `host-probe` / `ip-discovery`;
    /// `target` is the host/IP/URL being queried.
    NetworkProbe {
        probe_kind: String,
        target: String,
    },
    /// System enumeration / account discovery. Examples:
    ///   `net user`  /  `net group`  /  `net localgroup administrators`
    ///   `whoami /priv`  /  `whoami /groups`
    ///   `query session`  /  `quser`
    ///   `Get-LocalUser`  /  `Get-NetUser` (PowerView)
    Enumeration {
        enum_kind: String,
        command: String,
    },
    /// Credential access — lsass dumping, Mimikatz invocations, browser
    /// credential paths, well-known credential-theft tool refs.
    /// MITRE T1003 (OS Credential Dumping), T1555 (Credentials from
    /// Password Stores).
    CredentialAccess {
        technique: String,
        target: String,
    },
    /// Process injection — VirtualAllocEx + WriteProcessMemory +
    /// CreateRemoteThread chain, NtMapViewOfSection, or PowerShell
    /// Win32 API P/Invoke for injection. MITRE T1055.
    ProcessInjection {
        api: String,
    },
    /// User-input capture — keylogging (GetAsyncKeyState/SetWindowsHookEx),
    /// clipboard hijacking (Get/Set-Clipboard, OpenClipboard), screenshot
    /// (CopyFromScreen, Graphics.CopyFromScreen). MITRE T1056.
    InputCapture {
        capture_kind: String,
    },
    /// File-extension marker associated with ransomware families
    /// (`.locked`, `.encrypted`, `.wcry`, `.ryuk`, `.conti`, `.lockbit`,
    /// `.makop`, `.dharma`). Strong ransomware indicator when combined
    /// with AntiRecovery.
    RansomFileExtension {
        extension: String,
    },
    /// WinRM / WMI remote execution (separate from psexec/Invoke-Command
    /// which are LateralMovement). `winrm invoke`, `Invoke-WmiMethod`,
    /// `Set-WmiInstance -ComputerName`.
    RemoteExec {
        tool: String,
        target_host: String,
    },
    /// Remote-access backdoor setup: enabling RDP/Terminal Server,
    /// opening the Remote Desktop firewall rule, or hiding a local
    /// account under Winlogon\SpecialAccounts\UserList.
    RemoteAccess {
        technique: String,
        target: String,
        command: String,
    },
    /// Inline shellcode marker — typed as `[byte[]]` array or `\x90\x90...`
    /// NOP sled, or named `shellcode` variable. Surfaces shellcode-
    /// staging behaviour. MITRE T1027 (Obfuscated Files).
    ShellcodeMarker {
        evidence: String,
    },
    /// UAC bypass technique. Common forms:
    /// - fodhelper / eventvwr / sdclt / computerdefaults / wsreset
    ///   (auto-elevating Windows binaries triggered after a registry
    ///   hijack of `HKCU\Software\Classes\...\Shell\Open\command`)
    /// - cmstp /au with INF payload
    /// - msconfig /4
    /// - COM elevation via ICMLuaUtil/IColorDataProxy
    ///
    /// MITRE T1548.002 (Bypass User Account Control).
    UacBypass {
        technique: String,
    },
    /// `sc create` service installation — registers a Windows service
    /// for persistence or privilege escalation. MITRE T1543.003.
    /// `service_name` is the name, `bin_path` is the command (or
    /// empty if not parseable).
    ServiceInstall {
        service_name: String,
        bin_path: String,
    },
    /// PowerShell `Start-Sleep -Seconds N` pattern indicating a beacon
    /// loop / sleep-then-callback C2 cadence. MITRE T1102 (Web Service)
    /// / T1029 (Scheduled Transfer). `seconds` is the sleep duration.
    BeaconSleep {
        seconds: u32,
    },
    /// Non-script binary input masquerading as a script — the file is
    /// `MZ` (PE), `MSCF` (CAB), `PK\x03\x04` (ZIP), `Rar!` (RAR),
    /// `7z\xbc\xaf'\x1c` (7z), or LNK shortcut, but the extension says
    /// `.bat`/`.cmd`/`.ps1`/etc. so a delivery vector tricks the user
    /// into double-clicking it (the OS dispatches by magic bytes, not
    /// extension). `format` is one of `pe` / `cab` / `zip` / `rar` /
    /// `7z` / `lnk` / `pdf` / `image`. CLI dumps the bytes verbatim to
    /// `<out_dir>/<sha>.<format>` so analysts can recover the real file.
    DisguisedBinary {
        format: String,
        size: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NestedAesKey {
    pub key_b64: String,
    pub iv_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[non_exhaustive]
pub struct NetUseInfo {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devicename: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
