# Modern TSS Checker

A pure-Python rewrite of [tihmstar/tsschecker](https://github.com/tihmstar/tsschecker) — the tool for checking Apple's TSS (Trusted Software Service) firmware signing status and saving SHSH2 blobs.

**Zero native dependencies.** The original requires autotools, libcurl, libplist, libfragmentzip, libirecovery, and libgeneral — all of which need to be compiled from source and frequently break on newer systems. This rewrite needs only Python and one pip package.

---

## What It Does

When Apple releases a new iOS version, they typically stop signing older versions within a few weeks. Once a version is unsigned, devices cannot be restored to it through normal means. SHSH2 blobs are personalized cryptographic tickets that were issued by Apple's TSS server while a firmware was still being signed. With a saved blob, some restore flows can use it to restore to that version even after Apple stops signing it.

This tool:

- Checks whether Apple is currently signing a given firmware version for a given device
- Lists all known firmware versions for a device and shows which are currently signed
- Saves SHSH2 blobs by sending a personalized request to Apple's TSS server using your device's ECID and boot nonce
- Supports the full original tsschecker command-line interface

---

## Requirements

- Python 3.8 or newer
- The `requests` library (only external dependency)

```
pip install requests
```

or:

```
pip install -r requirements.txt
```

---

## Installation

```
git clone https://github.com/rhcp011235/Modern_TSS_Checker.git
cd Modern_TSS_Checker
pip install -r requirements.txt
python tsschecker.py --help
```

No compilation. No `./configure`. No system libraries.

---

## Quick Start

```
# Check if iOS 26.3 is being signed for iPhone 17 Pro Max
python tsschecker.py -d iPhone18,2 -i 26.3

# List all known iOS versions for a device and signing status
python tsschecker.py -d iPhone14,2 --list-versions

# Check the latest available firmware
python tsschecker.py -d iPhone16,2 --latest

# Save SHSH2 blobs (older devices using a nonce generator)
python tsschecker.py -d iPhone8,4 -i 15.8 \
  -e 0xABCDEF1234567890 \
  -g 0xbd34a880be0b53f3 \
  -s ./blobs/

# Save SHSH2 blobs (A10 and newer, real APNonce required)
python tsschecker.py -d iPhone14,2 -i 26.3 \
  -e 0xABCDEF1234567890 \
  -N c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2 \
  -s ./blobs/
```

---

## All Flags

### Device Selection

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-d` | `--device` | Device identifier, e.g. `iPhone14,2` |
| `-B` | `--boardconfig` | Board config string, e.g. `d63ap` (alternative to `-d`) |

### Firmware Selection

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-i` | `--ios` | Firmware version, e.g. `16.7.8` |
| `-Z` | `--buildid` | Build ID, e.g. `20H330` (alternative to `-i`) |
| `-m` | `--build-manifest` | Path to a local `BuildManifest.plist` |
| `-l` | `--latest` | Use the most recent public firmware |
| `-o` | `--ota` | Check OTA signing instead of full restore (IPSW) |
| | `--beta` | Request ticket for a beta firmware |

### Security / Nonces

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-e` | `--ecid` | Device ECID in hex (`0x...`) or decimal |
| `-g` | `--generator` | Nonce generator hex value (A9 and below) |
| `-N` | `--apnonce` | APNonce in hex (overrides generator) |
| `-S` | `--sepnonce` | SepNonce in hex (random if omitted) |

### Baseband

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-b` | `--baseband` | `0` = include BB if available (default), `1` = skip, `2` = BB only |
| | `--no-baseband` | Skip baseband ticket (same as `-b 1`) |
| | `--bbsnum` | Baseband SNUM in hex |

### Output / Saving

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-s` | `--save` | Directory to save SHSH2 blob (defaults to current dir if flag given without argument) |
| | `--print-tss-request` | Print the TSS request XML and exit without sending |
| | `--print-tss-response` | Print the raw TSS response body |
| `-u` | `--update-install` | Request an update ticket instead of erase/restore |
| `-V` | `--variant` | Override the restore variant string explicitly |

### Listing

| Flag | Long Form | Description |
|------|-----------|-------------|
| | `--list-devices` | Print all known devices and exit |
| | `--list-versions` | List all firmware versions for a device with signing status |
| | `--list-builds` | Same as `--list-versions` but also shows build IDs |

### Advanced

| Flag | Long Form | Description |
|------|-----------|-------------|
| | `--components` | Comma-separated list of components to include in the request |
| | `--raw` | Send a raw file directly to the TSS server |
| `-c` | `--cache` | Cache firmware API responses (repeat for higher level) |
| `-v` | `--verbose` | Show TSS endpoint attempts, response details, etc. |

---

## Examples

```
# Check multiple versions for a device
python tsschecker.py -d iPhone15,2 --list-versions

# Use a build ID instead of version number
python tsschecker.py -d iPhone14,2 -Z 22G91

# Use a local BuildManifest.plist (no network for manifest fetch)
python tsschecker.py -d iPhone10,3 -m /path/to/BuildManifest.plist

# Print the TSS request XML to see exactly what would be sent
python tsschecker.py -d iPhone14,2 -i 17.5.1 --print-tss-request

# Check OTA signing
python tsschecker.py -d iPhone15,2 -i 17.5 -o

# List all known devices
python tsschecker.py --list-devices

# Verbose output (shows which TSS endpoint responded, status codes, etc.)
python tsschecker.py -d iPhone14,2 -i 26.3 -v
```

---

## Nonce Notes by Chip Generation

### A9 and Below (iPhone 6s and older)

The APNonce is a deterministic hash of the generator value. You can set the generator on your device and the nonce is reproducible:

```
python tsschecker.py -d iPhone8,4 -i 15.8 \
  -e 0xABCDEF1234567890 \
  -g 0xbd34a880be0b53f3 \
  -s ./blobs/
```

Common generator values used by jailbreak tools:
- `0xbd34a880be0b53f3` (Chimera, Electra)
- `0x1111111111111111` (unc0ver)

### A10 and Newer (iPhone 7 and newer)

The APNonce is UID-derived on-device and cannot be predicted from a generator alone. You must read the actual boot nonce from your device while it is in DFU or recovery mode:

```
# Read nonce via irecovery (device in DFU)
irecovery -q | grep NONC

# Then provide it to the tool
python tsschecker.py -d iPhone9,3 -i 16.7.8 \
  -e 0xABCDEF1234567890 \
  -N <nonce-from-irecovery> \
  -s ./blobs/
```

Jailbreak tools such as palera1n and Sideloadly can also expose the device's current boot nonce.

For **signing-status checks only** (no blob saving), you do not need a real nonce. The tool generates a random nonce automatically, which is sufficient to query signing status on A10 through A16.

### A17 Pro and Newer (iPhone 15 Pro and newer)

See the section below on hardware attestation.

---

## Hardware Attestation (A17 Pro / iPhone 15 Pro and Newer)

Starting with the A17 Pro chip (CPID 0x8130, iPhone 15 Pro/Pro Max), Apple's TSS server requires a hardware-level attestation proof for all signing requests — including simple signing-status queries. This proof is a cryptographic signature generated by the device's Secure Enclave during a restore operation. It cannot be synthesized without physical hardware.

Without valid hardware attestation, Apple's TSS server returns `STATUS=69` for any request from these devices, regardless of what fields are included in the request.

Affected chips and devices:

| Chip | CPID | Devices |
|------|------|---------|
| A17 Pro | 0x8130 | iPhone 15 Pro, iPhone 15 Pro Max |
| A18 Pro | 0x8140 | iPhone 16 Pro, iPhone 16 Pro Max |
| A19 Pro | 0x8150 | iPhone 17 Pro, iPhone 17 Pro Max |

For these devices, this tool automatically falls back to the IPSW.me signing-status API, which maintains accurate signing data by querying Apple's servers through legitimate restore flows. The result is accurate for the purposes of knowing whether Apple is currently signing a firmware.

Blob saving for attestation-required devices still requires a real device with a proper hardware-derived nonce and attestation bundle, which the restore toolchain (`idevicerestore`, `futurerestore`) handles during an actual restore session.

---

## How It Works

### TSS Protocol

Apple's TSS server accepts HTTP POST requests containing an XML plist body. The request includes device identifiers (CPID, BDID, ECID), a boot nonce (APNonce), and a list of firmware components from the `BuildManifest.plist` with their digests. Apple responds with either a signed ticket (the SHSH2 blob) or an error code.

The response format is URL-encoded key-value pairs:
```
STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=<plist data>
```

`STATUS=0` means the firmware is being signed and the ticket was issued. `STATUS=94` typically means the firmware is no longer being signed.

This tool implements the same TSS protocol as the original C implementation: identical request plist structure, the same six Apple TSS endpoints with round-robin retry (up to 10 attempts), and the same HTTP headers including `User-Agent: InetURL/1.0`.

### BuildManifest Extraction (FragmentZip)

`BuildManifest.plist` is a small file (~100 KB) embedded inside the full IPSW, which can be 8+ GB. Downloading the entire IPSW just to get the manifest would be impractical.

This tool implements HTTP Range requests to download only the bytes needed:

1. Fetch the last 65 KB of the IPSW to locate the End-of-Central-Directory record
2. Parse the ZIP64 EOCD chain to find the Central Directory offset
3. Download only the Central Directory to find the manifest's local file header offset
4. Download only the manifest's compressed data and decompress it

This is the same technique used by the original `libfragmentzip`, reimplemented entirely in Python using `struct`, `zlib`, and `requests`. Modern IPSW files exceed 4 GB and require full ZIP64 support, including 64-bit offsets in both the EOCD locator and central directory extra fields.

### Device Database

Device information (chip ID, board ID, board config) is fetched from the IPSW.me v4 API and cached locally at `~/.cache/tsschecker/` for 7 days. No bundled device database is needed, and the list stays current automatically.

The IPSW.me API endpoint used: `https://api.ipsw.me/v4`

### Signing Request Construction

The `BuildManifest.plist` contains one `BuildIdentity` per device variant (Erase/Update/Recovery). For each firmware component:

1. The component is included only if `Info.Personalize` is not explicitly `False`
2. `RestoreRequestRules` are evaluated against the device's production/security mode conditions to determine which fields (`EPRO`, `ESEC`) to include
3. The component's `Digest` (and `PartialDigest` if present) are taken from the manifest
4. Hardware-variant-specific patch groups (`Savage,*`, `Yonkers,*`, `JasmineIR1,*`) are excluded from AP requests — including all variants simultaneously causes the server to reject the request

---

## Comparison with the Original

| Feature | tihmstar/tsschecker | This Tool |
|---------|---------------------|-----------|
| Build system | autotools + make | none |
| Native libraries | libcurl, libplist, libfragmentzip, libirecovery, libgeneral | none |
| Language | C++ | Python |
| HTTP client | libcurl | requests |
| ZIP extraction | libfragmentzip | pure Python (struct + zlib) |
| Plist parsing | libplist | plistlib (stdlib) |
| Device database | bundled static list | IPSW.me API (live + cached) |
| A17 Pro+ devices | not supported / returns wrong result | falls back to IPSW.me signing status |
| CLI flags | full set | full set (compatible) |

---

## File Structure

```
tsschecker.py        Main CLI entry point
requirements.txt     pip dependencies (just: requests)
lib/
  __init__.py
  devices.py         Device info from IPSW.me API with local cache
  ipsw.py            IPSW.me firmware API + FragmentZip implementation
  manifest.py        BuildManifest.plist parser and component extractor
  tss.py             TSS client (request builder, sender, response parser)
```

---

## Credits

Protocol research and original implementation: [tihmstar/tsschecker](https://github.com/tihmstar/tsschecker)

Device and firmware data: [IPSW.me](https://ipsw.me)
