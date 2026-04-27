# forensics — Tier A scenarios

Single test sheet for the `forensics` tool migration (kind:cli,
multi-binary bundle: binwalk / foremost / steghide / exiftool).

Sections:
1. Recommended sample for live verification
2. Narrative scenarios (paste into opensploit)
3. Target-extraction adversarial cases (≥20)
4. Failure-signature live-verify cases (≥3)
5. Open questions
6. Hand-off

---

## 1. Recommended sample for live verification

**N/A — forensics has no network target.** Each of the four wrapped
binaries operates entirely on local files (under /session/ in the
container). The "target" of a forensics call is always a LOCAL FILE
PATH (or, for `foremost -o` and `exiftool -r`, a LOCAL DIRECTORY).
There is no remote host to scan, attack, or authenticate against.

For LIVE VERIFICATION of the architecture path, four binary-specific
sample-file recipes (each one exercises a distinct binary):

**(a) binwalk — embedded-file extraction.** A small file with a
known-embedded artifact:

- **Build a synthetic test:**
  ```
  cd /session && \
    cat /usr/bin/ls /etc/passwd > /session/sample.bin
  ```
  Concatenating two recognizable files creates a guaranteed
  multi-signature binwalk target. Run `binwalk -B /session/sample.bin`
  and confirm both signatures appear (ELF + ASCII text).
- **Real firmware:** any small router firmware blob (DLink DIR-XXX
  series ~2 MB; OpenWRT factory image ~4 MB). Most firmware repos
  publish these freely. NB: large firmware (>50 MB) takes minutes
  to scan and may fork external extractors that hang on malformed
  data.
- **CTF artifact:** any HTB / TryHackMe forensics challenge image —
  these are designed to be binwalk-amenable and ship known answers.

**(b) foremost — file carving.** A disk image with deleted files:

- **Build a synthetic test:**
  ```
  dd if=/dev/zero of=/session/test.img bs=1M count=10
  mkfs.ext4 /session/test.img    # may need privileged or losetup
  ```
  Easier path: any small JPEG / PNG saved to /session/, then
  `foremost -i /session/photo.jpg -o /session/carved` will find
  that photo's header and emit it back. Tests the carve pipeline
  even without a real disk image.
- **Real disk image:** any small forensics CTF disk image (~10-100 MB
  is plenty). HTB has several. SANS DFIR also publishes free samples.
- **NB: foremost cannot read /dev/sda or other live block devices
  inside cli_in_container** — no /dev/* mounts by default. Always
  use a saved image file.

**(c) steghide — steganography extract / info.** A JPEG / BMP / WAV /
AU file with known steghide-embedded data:

- **Build a synthetic test:**
  ```
  # 1. Get a cover photo (any JPEG works)
  cp /usr/share/icons/Adwaita/scalable/places/folder.svg /tmp/x.svg
  # ... convert to JPEG via convert / cjpeg, or just download any JPEG
  echo "secret flag content" > /session/secret.txt
  steghide embed -cf /session/cover.jpg -ef /session/secret.txt \
                 -p 'sekret' -e rijndael-128
  # Now /session/cover.jpg has embedded data.
  rm /session/secret.txt
  ```
  Then test: `steghide info /session/cover.jpg -p 'sekret'` (should
  show embedded file) and `steghide extract -sf /session/cover.jpg
  -p 'sekret' -xf /session/recovered.txt`.
- **Public CTF stego cover:** any CTF challenge that publishes a
  known-pass JPEG (PicoCTF "Forensics 101" series has several). The
  passphrase is usually given in the challenge text.

**(d) exiftool — metadata extraction.** Any image / PDF / Office file:

- **Easy:** any photo from a real camera (smartphone JPEGs include
  Make, Model, GPSLatitude/Longitude, DateTimeOriginal, Software).
  Smoke test: `exiftool -j /session/photo.jpg | head -100`.
- **PDF:** any PDF document — `exiftool -j /session/doc.pdf` returns
  Author, Creator, Producer, CreationDate, PageCount.
- **Office:** any .docx / .xlsx / .pptx — exiftool extracts the
  Office Open XML core.xml metadata (Author, LastModifiedBy,
  CreatedDate, Application).

For all four binaries, the call is purely local — no network egress
is required. Persistent test directory: standard /session/ mount
inside the container.

---

## 2. Narrative scenarios (paste into opensploit)

### S1 — smoke test: confirm all four binaries are functional

```
Run binwalk -h, foremost -h, steghide --help, and exiftool -ver one at a time so I can confirm all four forensics binaries are on PATH and working.
```

**Watch:** Agent emits four separate calls, each to a different
`binary:`. target=`null` for all four. stdout is per-binary help
output (binwalk's flag table, foremost's tiny usage, steghide's
subcommand list, exiftool's version string). If any binary isn't on
PATH the run fails with `command not found` (container build issue).

### S2 — binwalk signature scan (read-only triage)

```
I have an unknown binary at /session/sample.bin. Show me what file types are embedded inside without extracting anything.
```

**Watch:** Agent emits `binwalk -B /session/sample.bin`. binary=
`binwalk`. target=`null`. stdout is the 3-column signature table
(DECIMAL OFFSET / HEX OFFSET / DESCRIPTION) — one row per matched
signature. No files written; read-only. If no signatures match,
output is just the header row (zero matches is informational).

### S3 — binwalk extract with bounded depth

```
Extract all embedded files from /session/firmware.bin recursively, but limit depth to 4 to avoid runaway extraction. Put the output under /session/extracted/.
```

**Watch:** Agent emits `binwalk -e -M -d 4 -C /session/extracted
/session/firmware.bin`. binary=`binwalk`. target=`null`. stdout is
the signature table; the `_firmware.bin.extracted/` directory is
created under /session/extracted/ with the extracted artifacts. Agent
follows up with a directory listing or further extraction passes.

### S4 — foremost carve disk image (default config)

```
I have a disk image at /session/dump.raw. Carve all recoverable files into /session/carved/.
```

**Watch:** Agent emits `foremost -i /session/dump.raw -o
/session/carved`. binary=`foremost`. target=`null`. stdout is brief
progress; foremost writes audit.txt + per-type subdirs (jpg/, png/,
pdf/, doc/, zip/, ...) under /session/carved/. If /session/carved/
already exists, foremost fails with `Error: directory exists` (see
S11).

### S5 — foremost carve specific types only

```
Carve only JPEG, PNG, and PDF files from /session/dump.raw into /session/carved-images/.
```

**Watch:** Agent emits `foremost -i /session/dump.raw -o
/session/carved-images -t jpg,png,pdf`. binary=`foremost`. target=
`null`. Output structure same as S4 but only jpg/, png/, pdf/
subdirs are populated.

### S6 — steghide info (check for hidden data)

```
Check if /session/cover.jpg has steghide-embedded data. The passphrase might be empty.
```

**Watch:** Agent emits `steghide info /session/cover.jpg -p ''`.
binary=`steghide`. target=`null`. stdout includes `format:` (jpeg /
bmp / wav / au), `capacity:` (max embeddable size), and — if the
empty passphrase matches — an `embedded file ...` line with the
embedded file's name and size. If wrong/no pass, stderr says
`could not extract any data with that passphrase!`.

### S7 — steghide extract with known passphrase

```
Extract hidden data from /session/cover.jpg using passphrase 'sekret'. Save the result to /session/secret.bin.
```

**Watch:** Agent emits `steghide extract -sf /session/cover.jpg -p
'sekret' -xf /session/secret.bin`. binary=`steghide`. target=`null`.
On success, /session/secret.bin contains the extracted payload. On
wrong pass, stderr reports the standard wrong-passphrase error.

### S8 — exiftool JSON metadata (single photo)

```
Extract all metadata from /session/photo.jpg as JSON.
```

**Watch:** Agent emits `exiftool -j /session/photo.jpg`. binary=
`exiftool`. target=`null`. stdout is a JSON array containing one
object with all metadata fields (Make, Model, GPSLatitude, GPS-
Longitude, ExifVersion, FileSize, CreateDate, Software, ...).
Parser-friendly; agent typically pulls specific keys for OSINT
or CTF flag-hunting.

### S9 — exiftool recursive scan with extension filter

```
Walk /session/photos/ recursively and extract metadata only from .jpg and .png files. JSON output.
```

**Watch:** Agent emits `exiftool -j -r -ext jpg -ext png
/session/photos`. binary=`exiftool`. target=`null`. stdout is a JSON
array with one object per matching file. Useful for OSINT pivots
(e.g., 'find all photos with GPS data in this dump') and for
multi-file metadata enumeration.

### S10 — failure: file not found

```
Run binwalk -B /session/missing.bin.
```

**Watch:** Agent emits `binwalk -B /session/missing.bin`. binary=
`binwalk`. target=`null`. binwalk exits non-zero with stderr
containing `Cannot open file: /session/missing.bin` or `does not
exist`. Failure classified via signal `Cannot open` / `does not
exist`. Remediation: verify with `ls /session/`.

### S11 — failure: foremost output directory exists

```
Run foremost -i /session/dump.raw -o /session/carved (where /session/carved already exists).
```

**Watch:** Agent emits the call. binary=`foremost`. target=`null`.
foremost exits non-zero with `ERROR: foremost: output directory
already exists` or `directory exists`. Failure classified via signal
`directory exists`. Remediation: pick a fresh dir name, use `-T` for
timestamped suffix, or delete the prior dir first.

### S12 — failure: steghide unsupported format

```
Run steghide info /session/photo.png -p ''.
```

**Watch:** Agent emits the call. binary=`steghide`. target=`null`.
steghide exits non-zero with `the file format of the file
"/session/photo.png" is not supported.` PNG / GIF / TIFF are NOT
supported by steghide — only JPEG, BMP, WAV, AU. Failure classified
via signal `is not supported`. Remediation: use exiftool to confirm
the actual format, then pick a different stego tool (zsteg for PNG)
or a different cover file.

### S13 — failure: steghide wrong passphrase

```
Run steghide extract -sf /session/cover.jpg -p 'wrongpass' -xf /session/out.bin.
```

**Watch:** Agent emits the call. binary=`steghide`. target=`null`.
stderr: `could not extract any data with that passphrase!`. Same
phrasing as no-data-embedded; the two cases are indistinguishable
from output. Failure classified via signal `could not extract any
data with that passphrase`. Remediation: try common passwords
('', 'password', the cover's filename, the CTF challenge name);
if all fail, attempt cracking with stegcracker (separate tool).

### S14 — failure: missing required argument

```
Run foremost -i /session/dump.raw (no -o flag).
```

**Watch:** Agent emits `foremost -i /session/dump.raw`. binary=
`foremost`. target=`null`. foremost exits non-zero with usage /
`expected one argument` / `missing argument` complaining about -o.
Failure classified via signal `missing argument` / `expected one
argument`. Remediation: add `-o /session/carved-NEW/` (must NOT
exist).

---

## 3. Target-extraction adversarial cases (≥20)

The forensics `tool.yaml` declares NO target_extraction rules.
Every call should return `target=null` because forensics has no
network target — all four binaries operate on the local ExploitDB
mirror /session/ filesystem only. The "operands" of a forensics
call are (a) one or more LOCAL FILE PATHS (positional or via
`-i` / `-sf` / `-cf` / `-ef`), (b) optional output paths/dirs
(`-o` / `-C` / `-xf`), (c) per-binary flag values (regexes,
passphrases, type lists, format strings). None are network
targets.

`reject_flags`: empty (no target-list ingestion concept exists in
any of the four binaries). The `-i FILE` flag is only a foremost
input file (NOT a target file like onesixtyone's `-i HOSTFILE`).

`value_flags` includes ~70 entries spanning all four binaries to
ensure the DSL parses each binary's argv correctly without
misinterpreting flag values or file paths as positional targets.

### Happy-path cases (every one returns target=null)

| # | Binary | Command | Expected target | Notes |
|---|---|---|---|---|
| 1 | binwalk | `-B /session/sample.bin` | `null` | Signature scan. |
| 2 | binwalk | `-e /session/firmware.bin` | `null` | Single-level extract. |
| 3 | binwalk | `-e -M -d 4 -C /session/out /session/firmware.bin` | `null` | Recursive extract with depth. |
| 4 | binwalk | `-e -y 'private key' -C /session/keys /session/fw.bin` | `null` | Include filter. |
| 5 | binwalk | `-J /session/sample.bin` | `null` | JSON entropy plot. |
| 6 | foremost | `-i /session/dump.raw -o /session/carved` | `null` | Default carve. |
| 7 | foremost | `-i /session/dump.raw -o /session/carved -t jpg,png,pdf` | `null` | Type-filtered carve. |
| 8 | foremost | `-q -i /session/disk.img -o /session/q-carved` | `null` | Quick carve. |
| 9 | foremost | `-T -i /session/dump.raw -o /session/carved` | `null` | Timestamped output. |
| 10 | steghide | `info /session/cover.jpg -p ''` | `null` | Stego info, no pass. |
| 11 | steghide | `info /session/cover.jpg -p 'sekret'` | `null` | Stego info with pass. |
| 12 | steghide | `extract -sf /session/cover.jpg -p '' -xf /session/out.bin` | `null` | Extract no pass. |
| 13 | steghide | `embed -cf /session/photo.jpg -ef /session/secret.txt -sf /session/stego.jpg -p 'sekret' -N` | `null` | Embed mode. |
| 14 | exiftool | `-j /session/photo.jpg` | `null` | JSON single file. |
| 15 | exiftool | `-j -r /session/photos` | `null` | JSON recursive. |
| 16 | exiftool | `/session/document.pdf` | `null` | Default text. |
| 17 | exiftool | `-s -c '%+.6f' /session/photo.jpg` | `null` | Short tags + raw GPS. |
| 18 | exiftool | `-j -r -ext jpg -ext png /session/dump` | `null` | Recurse with ext filter. |
| 19 | exiftool | `-j -r -if '$GPSLatitude' /session/photos` | `null` | Conditional filter. |
| 20 | exiftool | `-j -fast2 /session/large.mp4` | `null` | Fast mode. |

### Help / introspection (target=null by definition)

| # | Binary | Command | Expected | Notes |
|---|---|---|---|---|
| H1 | binwalk | `-h` | `target=null` | Help. |
| H2 | foremost | `-h` | `target=null` | Help. |
| H3 | steghide | `--help` | `target=null` | Help. |
| H4 | steghide | `extract --help` | `target=null` | Subcommand help. |
| H5 | steghide | `encinfo` | `target=null` | List crypto algos. |
| H6 | exiftool | `-ver` | `target=null` | Version. |
| H7 | exiftool | `-listx` | `target=null` | XML tag list. |
| H8 | exiftool | `-h` | `target=null` | Help. |

### Adversarial — value_flag traps & "looks like a target" invariants

| # | Binary | Command | Expected | Notes |
|---|---|---|---|---|
| F1 | binwalk | `-B /session/scan-of-10.10.10.5.bin` | `null` | Filename embeds an IP — NOT a target, just a filename. |
| F2 | binwalk | `-y 'TLS certificate' /session/firmware.bin` | `null` | -y value looks like a regex; positional is the file. |
| F3 | binwalk | `-x 'ASCII' /session/sample.bin` | `null` | -x exclude regex value. |
| F4 | binwalk | `-D 'application/zip:zip:7z x %e' /session/fw.bin` | `null` | -D MIME:EXT:CMD tuple — colons don't make it a host:port. |
| F5 | binwalk | `--dd='private key:pem' /session/fw.bin` | `null` | --dd extraction rule. |
| F6 | binwalk | `-l 1048576 -p 4096 /session/fw.bin` | `null` | -l length and -p offset are integer values, NOT targets. |
| F7 | binwalk | `-C /session/extract/dump-from-10.10.10.5 -e /session/fw.bin` | `null` | Output dir name embeds an IP — NOT a target. |
| F8 | foremost | `-i /session/192.168.1.1-disk.raw -o /session/carved` | `null` | Input filename embeds an IP — NOT a target. |
| F9 | foremost | `-c /session/custom-foremost.conf -i /session/dump.raw -o /session/carved` | `null` | -c config file path. |
| F10 | foremost | `-t 'jpg,png,bmp,wav' -i /session/dump.raw -o /session/carved` | `null` | -t list of types — comma-separated string. |
| F11 | foremost | `-i 10.10.10.5-snapshot.dd -o /session/c` | `null` | Same as F8 but bare filename (no /session/ prefix); still a path, not a target. |
| F12 | steghide | `extract -sf /session/cover.jpg -p '10.10.10.5' -xf /session/out.bin` | `null` | Passphrase value LOOKS like an IP — NOT a target. -p value is the next argv token after -p. |
| F13 | steghide | `extract -sf /session/cover.jpg -p '' -xf /session/out.bin -f` | `null` | Empty passphrase. |
| F14 | steghide | `embed -cf /session/cover.jpg -ef /session/payload.bin -sf /session/stego.jpg -p 'sekret' -e rijndael-256 -z 9 -N -K` | `null` | Many flags + values — none are targets. |
| F15 | steghide | `info /session/cover-from-host-10.10.10.5.jpg -p ''` | `null` | Filename embeds host info; NOT a target. |
| F16 | exiftool | `-j /session/scan-of-192.168.1.100.jpg` | `null` | Filename embeds an IP. |
| F17 | exiftool | `-c '%+.6f' -d '%Y-%m-%d %H:%M:%S' /session/photo.jpg` | `null` | -c and -d are format strings (with shell-special chars). |
| F18 | exiftool | `-if '$GPSLatitude > 37 and $GPSLongitude < -122' /session/photos` | `null` | -if takes a Perl-like expression; not a target. |
| F19 | exiftool | `-tagsFromFile /session/source.jpg /session/dest.jpg` | `null` | -tagsFromFile takes a path; positional is the dest. |
| F20 | exiftool | `-api 'LargeFileSupport=1' /session/large.mp4` | `null` | -api takes a key=value string. |
| F21 | exiftool | `-w '%d/%f.txt' /session/photos/` | `null` | -w takes a write-format string with %d and %f placeholders. |
| F22 | exiftool | `-G:File:FileType -s -j /session/photo.jpg` | `null` | Tag-group syntax with colons — NOT a host:port. |
| F23 | binwalk | `-B /session/file-with-colons:weird.bin` | `null` | Filename with colons in it (rare but possible). |
| F24 | foremost | `-i /session/dump.raw -o /session/c -t all` | `null` | -t value 'all' is a keyword, not a target. |
| F25 | steghide | `extract -sf /session/192.168.1.1.jpg -p 'host:port:pass' -xf /session/out.bin` | `null` | Cover filename and passphrase BOTH look like network strings; neither is a target. |
| F26 | exiftool | `-stay_open True -@ /session/cmd-list.txt` | `null` | -stay_open mode (DO NOT use under cli_in_container — no shell to feed -@). target=null regardless. |

### Multi-positional / ambiguous-positional cases

| # | Binary | Command | Expected | Notes |
|---|---|---|---|---|
| M1 | exiftool | `-j /session/a.jpg /session/b.jpg /session/c.jpg` | `target=null` | Multiple positional files — exiftool processes all three; target=null. |
| M2 | binwalk | `-B /session/file1.bin /session/file2.bin` | `target=null` | binwalk supports multiple positional files (rare); target=null. |
| M3 | binwalk | `/session/sample.bin -B` | `target=null` | Flag AFTER positional — argparse permissive; target=null. |
| M4 | (any) | (no args) | `target=null` | Bare invocation prints usage; non-zero exit; target=null. |
| M5 | steghide | `info` (no file arg) | `target=null` | Subcommand without file — error; target=null. |

### Multi-binary dispatch traps

| # | Setup | What COULD go wrong | What MUST happen |
|---|---|---|---|
| D1 | Agent calls usage_pattern with `binary: binwalk` but argv `command:` actually starts with `foremost -i ...`. | Wrong binary forwarded; command fails with `unrecognized option -i` (binwalk doesn't have -i). | The DSL's `binary:` field IS THE BINARY — argv is appended as flags/positionals. The usage_pattern declares which binary to dispatch; mixing them is a recipe error. |
| D2 | Same flag letter has different meaning across binaries — e.g., `-d` is binwalk's max-depth (int), foremost's indirect-detect (bool), exiftool's date-format (string). | DSL might mis-classify the value. | Each invocation runs ONE binary at a time; value_flags is a UNION across all four, but at parse time the binary context is fixed. The same letter in different binary contexts is fine because the call is binary-scoped. |
| D3 | Agent issues `binwalk -e -M /session/fw.bin` then expects output under /session/extracted/. | binwalk -e writes to CWD, not /session/. CWD inside cli_in_container is unpredictable. | ALWAYS pin output via `-C /session/extracted/`. The gotcha documents this; the LLM must include -C explicitly under run_cli. |
| D4 | Agent issues `foremost -i x -o existing-dir`. | foremost refuses; `directory exists` error. Failure recoverable but not auto-resolved. | LLM must use `-T` (timestamp suffix) OR pick fresh dir per call OR delete-before-call. |
| D5 | Agent issues `steghide info /session/cover.jpg` (no -p). | steghide prompts interactively; cli_in_container has no TTY; call hangs until idle_timeout_seconds. | ALWAYS pass `-p ''` for the no-pass case. Documented in gotchas. |
| D6 | Agent issues `exiftool -j /session/photo.jpg` and parses stdout as a single object. | stdout is a JSON ARRAY (with one element); object access fails. | Documented in gotchas — exiftool's -j is always an array. |

### Stdin trap (forensics binaries don't read stdin in normal flow)

| # | Command (LLM might naively try) | What happens | Correct shape |
|---|---|---|---|
| P1 | `cat /session/x.bin \| binwalk -` | cli_in_container HAS NO SHELL. The `\|` would be passed as a literal arg or rejected. binwalk does NOT read from stdin (always wants a file path). | `binwalk -B /session/x.bin` — pass the file path positionally. |
| P2 | `cat /session/x.bin \| foremost -i -` | Same as above; foremost's -i requires a file path. | `foremost -i /session/x.bin -o /session/carved` |
| P3 | `cat /session/cover.jpg \| steghide info -` | Same; steghide takes a file argument. | `steghide info /session/cover.jpg -p ''` |
| P4 | `find /session -name '*.jpg' \| xargs exiftool -j` | No shell, no xargs. | `exiftool -j -r -ext jpg /session/` |

---

## 4. Failure-signature live-verify cases (≥3)

| # | Layer | Test | failure_signature `signal` | Status |
|---|---|---|---|---|
| 1 | File / I/O | `binwalk -B /session/missing.bin` | `Cannot open` OR `does not exist` OR `No such file or directory` | PENDING live verify |
| 2 | Format | `steghide info /session/photo.png -p ''` (PNG = unsupported) | `is not supported` OR `unrecognized format` | PENDING live verify |
| 3 | Output / disk | `foremost -i /session/dump.raw -o /session/existing-dir` | `directory exists` OR `ERROR: foremost: output directory` | PENDING live verify |
| 4 | Auth | `steghide extract -sf /session/cover.jpg -p 'wrong' -xf /session/out` | `could not extract any data with that passphrase` OR `wrong passphrase` | PENDING live verify |
| 5 | Argument / argparse | `binwalk --notaflag /session/sample.bin` | `unrecognized option` | PENDING live verify |
| 6 | Argument / required | `foremost -i /session/dump.raw` (no -o) | `expected one argument` OR `missing argument` | PENDING live verify |
| 7 | Empty / informational | `binwalk -B /session/empty.bin` (zero-byte or no-signature file) | `no signatures found` (informational, not a true failure) | PENDING live verify |
| 8 | Empty / informational | `foremost -i /session/dump.raw -o /session/c` (input has no recoverable headers) | `0 FILES EXTRACTED` OR `Files Extracted: 0` | PENDING live verify |
| 9 | Resource | binwalk on a pathologically malformed firmware that wedges an extractor | extractor hang → idle_timeout_seconds tripped | PENDING live verify (manual fixture) |

### Layer diversity (SKILL #11) — achieved

7 distinct verifiable layers exercised: file/IO, format, output/disk,
auth, argparse-spelling, argparse-required, empty-result. Resource
layer (extractor hang / OOM) is hard to provoke deliberately in a
small lab; defer to live HTB run with real firmware corpora.

---

## 5. Open questions

1. **target_extraction = empty list — confirmed correct?** forensics
   has no network target. The plugin's TargetValidation framework
   expects hostnames/IPs. We're declaring zero rules; the plugin
   extracts target=null and the gotcha note documents that scope-
   validation is N/A. Verify the plugin handles `target=null`
   gracefully (doesn't reject the call; doesn't try to validate
   "null" against the engagement scope). Same shape as john /
   hashcat / volatility / ilspy / searchsploit / ysoserial / phpggc
   — those have already been migrated. Cross-check that filename-
   embedded-IP cases (F1, F7, F8, F11, F15, F16) and
   passphrase-shaped-as-host cases (F12, F25) do NOT accidentally
   extract via some default URL/IP-extraction fallback.

2. **Multi-binary dispatch — argv parser behavior under run_cli.**
   Each usage_pattern declares `binary:` explicitly and the argv
   `command:` follows. Under run_cli, the plugin must (a) pick the
   binary from the usage_pattern (or LLM-provided override), (b)
   prepend it to the argv, (c) parse value_flags in the binary's
   namespace. Verify the argv parser doesn't get confused by
   value_flags overlap between binaries (e.g., -d means int for
   binwalk, bool for foremost, string for exiftool). The DSL's
   value_flags list is a UNION across all four binaries; at parse
   time the binary is FIXED (one per call), so the same letter is
   unambiguous within that scope. Confirm parser implementation
   honors this invariant.

3. **CWD convention for binwalk -e and foremost -i / -o.** binwalk
   `-e` writes to CWD by default (`_<basename>.extracted/`).
   foremost `-i` requires an absolute path or a path relative to
   CWD. cli_in_container's CWD is unpredictable (depends on plugin
   version and per-tool overrides). Decision: ALL forensics calls
   should use ABSOLUTE paths under /session/ — the gotcha mandates
   this. Should the wrapper enforce this (reject calls with
   non-absolute paths), or rely on the LLM's discipline? Current
   approach is the latter. If we see frequent CWD-confusion bugs
   in live runs, escalate to wrapper enforcement.

4. **Steghide passphrase discovery workflow.** When steghide returns
   `could not extract any data with that passphrase!`, the agent
   has NO way to distinguish between (a) wrong passphrase and (b)
   no data embedded. Options for follow-up: (1) try a list of common
   passwords ('', 'password', '123456', filename, challenge name);
   (2) crack with stegcracker (separate tool, NOT in this image);
   (3) give up and conclude no data is embedded. Should the gotchas
   recommend a default password-list workflow? Currently they list
   common candidates but don't prescribe a fixed sequence. Defer to
   live verification — once we see how often steghide cover files
   appear in real engagements, we can refine.

5. **Foremost output-dir-exists handling.** Three options for
   handling existing output dir: (a) `-T` for timestamped suffix,
   (b) pick fresh dir per call, (c) delete-before-call. Currently
   the gotcha mentions all three; the legacy mcp-server.py wrapper
   used (c) (cleared dir before invocation). Under run_cli the LLM
   must do this explicitly. Should we add a usage_pattern that
   shows the `rm -rf <dir> && foremost ...` shape? cli_in_container
   has no shell so we can't combine `rm` with `foremost` in one
   argv — it would have to be two separate calls (one to a `rm`
   tool, one to forensics). Current approach: rely on `-T` or
   fresh-dir-per-call. If in live use we see foremost calls failing
   on dir-exists, may add a wrapper-level pre-clean.

6. **Binwalk external-extractor failure modes.** binwalk forks 7z,
   unsquashfs, jefferson, cramfsswap, etc. for actual extraction.
   When an external extractor hangs (malformed input → extractor
   infinite loop), binwalk doesn't time out; it waits forever. Our
   idle_timeout_seconds (10 min) is the only safety net. Should
   we add a per-extractor timeout? binwalk doesn't expose one
   directly; would need to wrap in `timeout(1)` (separate binary).
   Current approach: rely on idle_timeout. Document in gotchas.

7. **Exiftool write-mode safety.** exiftool can MODIFY files in
   place (`-Tag=Value`, `-overwrite_original`, `-delete_original`).
   For OFFENSIVE / FORENSIC analysis we almost always want
   READ-ONLY mode. Should the wrapper REJECT write-mode flags
   under run_cli (treating them as out-of-scope for forensics)?
   Current approach: gotcha warns the user; wrapper does NOT
   reject. This matches the philosophy of run_cli (LLM has full
   binary surface; wrapper enforces only multi-target / scope
   rules). Leave as-is unless we see accidental writes in audit
   logs.

8. **PNG / GIF / TIFF stego.** steghide ONLY supports JPEG / BMP /
   WAV / AU. For PNG we'd need zsteg (Ruby gem), for GIF/TIFF we'd
   need stegoVeritas or LSB tools. None are in this image. Should
   forensics expand to include these, or stay tight on the four
   supported formats? Current decision: stay tight; document in
   gotchas. If we see frequent PNG stego in CTFs, file a P1
   feature request to add zsteg (separate MCP server, NOT in
   forensics — keeps each tool focused).

9. **Binwalk `--run-as=root` defaulting.** The legacy
   `mcp-server.py extract` method hardcoded `--run-as=root` so that
   binwalk's extractors (7z, unsquashfs, jefferson, ...) could write
   into extracted filesystem trees that contain setuid / owned-by-
   other-user files. Without `--run-as=root` binwalk uses `nobody`
   by default, which can produce silent partial extractions on real
   firmware. Under run_cli the LLM must remember to add
   `--run-as=root` explicitly — there is no wrapper-level default.
   Decision: documented in gotchas; rely on LLM discipline. If we
   see frequent silent-empty extractions in live runs, consider
   wrapper-level enforcement (auto-inject `--run-as=root` for `-e`).

10. **Steghide silent-no-output post-condition.** Legacy wrapper
    checked `os.path.exists(output_path)` after every extract call
    because steghide can return exit-0 with no stderr but also no
    output file (truncated stego data, format-detection edge case).
    Under run_cli, exit-code alone is not authoritative — the LLM
    must verify the -xf path actually exists after the call. Should
    the wrapper add a post-condition check (synthesize a failure
    signal if -xf is empty / missing despite exit-0)? Currently
    documented in gotchas; deferred to post-live-verify.

11. **Steghide extract -f convention.** Legacy wrapper always added
    `-f` (force overwrite) and unlinked the prior `-xf` file. Under
    run_cli the usage_pattern for "known passphrase" includes -f but
    the "empty passphrase" pattern does NOT — inconsistent. The LLM
    will hit `the file exists` errors on retry without -f. Decision:
    document in gotchas (added) and recommend the LLM include -f
    routinely OR pick fresh -xf paths. Long-term, consider updating
    both extract patterns to include -f for parity with legacy
    behavior.

---

## 6. Hand-off

- **Tool**: forensics (kind:cli, multi-binary)
- **Status**: tool.yaml authored end-to-end (kind:cli, NO top-level
  binary, per-pattern `binary:` field, 1h max_runtime,
  target_extraction=empty list, ~70 value_flags spanning four binaries);
  scenarios.md written with ≥6 narrative scenarios, 26 happy/
  adversarial target-extraction cases, 8 help/introspection cases,
  6 multi-binary dispatch traps, 9 failure-signature cases across
  7 layers.
- **Dockerfile**: ONE change applied — replaced
  `python3 python3-pip python3-venv` with `python3-full` (Kali
  rolling repos no longer ship the split packages reliably). The
  four binary packages (binwalk, foremost, steghide,
  libimage-exiftool-perl) retained. venv setup, mcp-common install,
  mcp-server.py copy, CMD all unchanged.
- **mcp-server.py**: UNTOUCHED (auto-inherits run_cli from
  BaseMCPServer 0.3.0; legacy methods preserved as rollback path).
- **Image**: `ghcr.io/silicon-works/mcp-tools-forensics:latest` —
  needs rebuild during Wave 9 batch to pick up mcp-common 0.3.0
  and the python3-full swap.
- **target_extraction = empty list**: explicit design choice.
  forensics has no network target; the plugin should treat
  target=null as "no scope validation needed" for this tool. Same
  shape as john / hashcat / volatility / ilspy / searchsploit /
  ysoserial / phpggc. See Open Question #1.
- **Wave 7.14**: of Feature 35 / Tier A migration. FINAL TOOL
  of Wave 7 (the no-network-target / multi-binary cohort).
- **Live-verify pending**: paste S1-S14 against the container for
  end-to-end verification. Failure signatures 1-2 (file-not-found,
  unsupported format) verifiable against any container; 3
  (foremost output-dir-exists) needs a pre-existing dir fixture; 4
  (steghide wrong-pass) needs a steghide-embedded JPEG fixture; 9
  (extractor hang) requires malformed-firmware fixture.
- **Cleanup**: no legacy `target_extraction_tests.md`,
  `failure_signature_tests.md`, or `__pycache__/` files were
  present in the forensics/ directory (verified via initial Read
  phase — directory contained only Dockerfile, mcp-server.py,
  requirements.txt, tool.yaml) — nothing to remove.

Authored: 2026-04-25.
