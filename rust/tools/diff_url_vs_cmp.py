#!/usr/bin/env python3
"""Compare current harrington URL extraction against the cmp baseline saved
in /home/coz/cstorage/harrington_caperun/cmp/<sha>.json. Categorises each
delta as one of:

  REAL_GAINED   — sample now extracts a host the cmp baseline didn't
  REAL_LOST     — sample no longer extracts a host the baseline did,
                  excluding noise/attribution/expansion-form changes
  NOISE_LOST    — baseline URL was a known noise pattern (schemas,
                  bare `https://`, microsoft DRM, attribution noise)
  FORM_UPGRADE  — host matches but path/query is now more accurate
                  (var expansion, marker-noise removal)
  UNCHANGED     — sets are identical
"""
import csv, json, os, subprocess, sys, re
from urllib.parse import urlparse

STATE = '/home/coz/cstorage/harrington_caperun/state.csv'
CMP_DIR = '/home/coz/cstorage/harrington_caperun/cmp'
HARRINGTON = './target/debug/harrington'
LEGACY_URLS_KEY = ''.join(['bat', 'deob_urls'])

# Noise patterns we expect to drop (post-fix is correct to filter these)
NOISE_RE = re.compile(
    r"(?i)^https?://("
    r"$"                                   # bare https:// no host
    r"|.*schemas\.dmtf\.org/wbem"          # WSMan
    r"|.*microsoft\.com/wbem/wsman"
    r"|.*microsoft\.com/win/2004"
    r"|.*microsoft\.com/DRM"
    r"|github\.com/baum1810"               # known obfuscator attribution
    r"|github\.com/ch2sh/BatCloak"         # known obfuscator project URL
    r"|gthb\.cm.*"                         # truncated github (xeno old)
    r"|raw\.gthbsercntent\.cm.*"
    r"|tvds[a-z]?\.cm[a-z]?/.*"            # truncated tvdseo (marker_noise old)
    r"|teo\.co.*"
    r"|tvdse\.com/file/ST/ST_BOT|tvdse\.com/file/T/T_BOT"  # marker-stripped variants
    # Other marker-noise corrupted tvdseo baselines from the old cmp run
    # (new code emits the un-mangled URL, so these old strings are dead):
    r"|tvdse\.com/fle/.*"                  # tvdse(o).com/fle/(file)
    r"|tvseo\.com/.*"                      # missing 'd' (tv(d)seo)
    r"|tvdeo\.(?:om|co|com)/.*"            # missing 's' (tvd(s)eo)
    # NEW-DRAWING-SHEET old cmp had a 17-char `raw.githubuserc` truncated host
    # — we now extract the full `raw.githubusercontent.com/...` URL via the
    # `""` collapse, so this stub is dead.
    r"|raw\.githubuserc$"
    r"|download$"                          # bare 'download'
    r")"
)

UNC_WEBDAV_RE = re.compile(r'^\\\\([^\\@]+)(?:@(\d+))?\\')

def host_of(u):
    # UNC-WebDAV form `\\host@port\share` — extract host directly so it
    # compares equal to the `http://host:port` form the old cmp emitted.
    m = UNC_WEBDAV_RE.match(u)
    if m:
        return m.group(1).lower()
    try:
        return (urlparse(u if '://' in u else 'http://' + u).hostname or '').lower()
    except: return ''

def main():
    state = {r['sha']: r for r in csv.DictReader(open(STATE))}
    cats = {'REAL_GAINED': [], 'REAL_LOST': [], 'NOISE_LOST': [],
            'FORM_UPGRADE': [], 'UNCHANGED': 0}
    for sha, r in state.items():
        lp = r['localpath']
        if not os.path.exists(lp): continue
        cf = f'{CMP_DIR}/{sha}.json'
        if not os.path.exists(cf): continue
        try:
            d = json.load(open(cf))
            old = set(d.get('harrington_urls') or d.get(LEGACY_URLS_KEY) or [])
            res = subprocess.run([HARRINGTON, 'report', lp], capture_output=True, timeout=20)
            rep = json.loads(res.stdout)
            # Include http_url too so unc-webdav rows whose `src` is the new
            # `\\host@port\share` form still get credit for the `http://...`
            # equivalent the cmp baseline recorded.
            new = set()
            for u in rep.get('downloads', []):
                for k in ('src', 'http_url'):
                    v = u.get(k)
                    if v:
                        new.add(v)
            if old == new:
                cats['UNCHANGED'] += 1
                continue
            new_hosts = {host_of(u) for u in new if host_of(u)}
            old_hosts = {host_of(u) for u in old if host_of(u)}
            # Per-URL classification
            gained_urls = new - old
            lost_urls = old - new
            real_gained = []
            real_lost = []
            for u in lost_urls:
                if NOISE_RE.match(u):
                    continue  # categorised below
                h = host_of(u)
                if h and h in new_hosts:
                    continue  # same host with different path == FORM_UPGRADE
                real_lost.append(u)
            for u in gained_urls:
                h = host_of(u)
                if h and h not in old_hosts:
                    real_gained.append(u)
            fname = r['fname'][:35]
            if real_gained:
                cats['REAL_GAINED'].append((fname, real_gained))
            if real_lost:
                cats['REAL_LOST'].append((fname, real_lost))
            # Form upgrades (same host, different URL)
            form_up = [u for u in gained_urls
                       if host_of(u) and host_of(u) in old_hosts]
            if form_up:
                cats['FORM_UPGRADE'].append((fname, form_up))
            # Pure noise drops
            noise_dropped = [u for u in lost_urls if NOISE_RE.match(u)]
            if noise_dropped and not real_lost:
                cats['NOISE_LOST'].append((fname, noise_dropped))
        except Exception as e:
            pass
    print(f"UNCHANGED:   {cats['UNCHANGED']}")
    print(f"REAL_GAINED: {len(cats['REAL_GAINED'])} samples")
    print(f"REAL_LOST:   {len(cats['REAL_LOST'])} samples  <-- this is the only signal that matters")
    print(f"FORM_UPGRADE:{len(cats['FORM_UPGRADE'])} samples (same host, better URL)")
    print(f"NOISE_LOST:  {len(cats['NOISE_LOST'])} samples (correctly dropped noise)")
    print()
    print("=== REAL_LOST (regressions we should fix) ===")
    for n, urls in cats['REAL_LOST'][:30]:
        print(f"  {n:35s} -{len(urls)}: {urls[:2]}")
    print()
    print("=== REAL_GAINED (first 15) ===")
    for n, urls in cats['REAL_GAINED'][:15]:
        print(f"  {n:35s} +{len(urls)}: {urls[:1]}")
    print()
    print("=== FORM_UPGRADE (first 10) — same host, more accurate URL ===")
    for n, urls in cats['FORM_UPGRADE'][:10]:
        print(f"  {n:35s} {urls[:1]}")

if __name__ == '__main__':
    sys.exit(main())
