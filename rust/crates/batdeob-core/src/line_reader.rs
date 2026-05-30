//! Read logical lines from a batch script. A logical line is one or more
//! physical lines joined by a trailing unescaped caret `^`.

/// Decode bytes and split into logical lines, joining caret-continuations.
/// Uses UTF-8 when the input is valid UTF-8; otherwise falls back to
/// Latin-1 (each byte becomes its own char), preserving distinct high-byte
/// values that the cp1252/Latin-1 high-byte var-name obfuscators
/// (Factura, ae8c… families) use as char-cipher keys. `from_utf8_lossy`
/// would collapse every invalid byte to U+FFFD, making distinct var
/// names like `%<0xC1>%` and `%<0xC2>%` resolve to the SAME key.
pub fn read_logical_lines(input: &[u8]) -> Vec<String> {
    // Strip BOMs and detect UTF-16LE. Two distinct cases appear in the wild:
    //   1. Real UTF-16LE batch files (rare but exist) — every other byte is
    //      NUL when the source is ASCII. Decode as UTF-16LE.
    //   2. ASCII batch files with a spurious `0xFF 0xFE` prefix (CMD ignores
    //      the bad BOM and reads the ASCII body normally). `file` mis-labels
    //      these as "Unicode text, UTF-16". Just drop the BOM and continue.
    // Without either fix, ASCII-after-bad-BOM passes our UTF-8 check (the BOM
    // bytes are invalid UTF-8) and falls into Latin-1, leaving the leading
    // `ÿþ` glyph as the first chars of the script — harmless but ugly. UTF-16LE
    // proper, though, comes out as alternating ASCII + NUL chars and our lex
    // can't process it at all.
    let (input, _) = if input.starts_with(&[0xFF, 0xFE]) {
        (&input[2..], true)
    } else if input.starts_with(&[0xFE, 0xFF]) {
        // UTF-16BE BOM — rare; treat the body as opaque Latin-1 (Vec<char> from
        // each byte) for the same reason we Latin-1 high-byte cp1252 files.
        (&input[2..], false)
    } else if input.starts_with(&[0xEF, 0xBB, 0xBF]) {
        (&input[3..], false)
    } else {
        (input, false)
    };
    let utf16_decoded: Option<String> = if input.len() >= 4 && input.len() % 2 == 0 {
        // Real UTF-16LE? Every odd-indexed byte should be NUL for an
        // ASCII-only payload. Allow some non-NUL high bytes (extended chars).
        let sample = input.len().min(2048);
        let pairs = sample / 2;
        let nul_hi = input[..sample]
            .chunks_exact(2)
            .filter(|p| p[1] == 0)
            .count();
        if pairs > 0 && nul_hi * 100 / pairs >= 80 {
            let units: Vec<u16> = input
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16(&units).ok()
        } else {
            None
        }
    } else {
        None
    };
    let text: std::borrow::Cow<'_, str> = if let Some(s) = utf16_decoded {
        std::borrow::Cow::Owned(s)
    } else {
        match std::str::from_utf8(input) {
            Ok(s) => std::borrow::Cow::Borrowed(s),
            Err(_) => std::borrow::Cow::Owned(input.iter().map(|&b| b as char).collect()),
        }
    };
    let mut out: Vec<String> = Vec::new();
    let mut accum = String::new();
    for raw in text.split_inclusive('\n') {
        // strip trailing \n and optional \r
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(prefix) = line.strip_suffix('^') {
            accum.push_str(prefix);
        } else {
            accum.push_str(line);
            out.push(std::mem::take(&mut accum));
        }
    }
    if !accum.is_empty() {
        out.push(accum);
    }
    out
}
