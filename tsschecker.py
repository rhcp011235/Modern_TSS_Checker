#!/usr/bin/env python3
"""
tsschecker – Python rewrite of tihmstar/tsschecker

Checks Apple's TSS signing status for iOS / iPadOS / tvOS / watchOS firmware.
Can also save SHSH2 blobs when provided with a device ECID and valid nonce.

Zero native dependencies. Requirements: pip install requests
"""

import sys
import os
import argparse
import plistlib
import secrets

# Suppress urllib3 InsecureRequestWarning (we intentionally hit direct IPs)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Path setup – allow running from any directory
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lib import devices as devdb
from lib import ipsw as ipswapi
from lib import manifest as mf
from lib import tss as tsslib


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tsschecker",
        description=(
            "Check Apple TSS signing status for iOS/iPadOS/tvOS/watchOS firmware.\n"
            "Pure-Python rewrite — no native dependencies required."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Check if iOS 16.7.8 is still signed for iPhone 10,3
  tsschecker.py -d iPhone10,3 -i 16.7.8

  # Check all versions for a device
  tsschecker.py -d iPhone14,2 --list-versions

  # Save SHSH blobs (requires real ECID; A12+ also requires --apnonce)
  tsschecker.py -d iPhone11,8 -i 16.7 -e 0xABCDEF1234567890 -s ./blobs/

  # Use a local BuildManifest.plist
  tsschecker.py -d iPhone10,3 -m /path/to/BuildManifest.plist -e 0x1234

  # Check OTA signing status
  tsschecker.py -d iPhone14,2 --list-versions -o

NONCE NOTES:
  A9 and below: use -g 0xbd34a880be0b53f3 (Chimera/Electra generator)
                or -g 0x1111111111111111 (unc0ver generator)
  A10+:         use --apnonce <hex> with the boot nonce from your device.
                On A12+ the nonce is UID-derived; you must read it directly
                from the device (e.g. via palera1n, Sideloadly, or irecovery).
""",
    )

    # Device selection
    dev = p.add_argument_group("device selection")
    dev.add_argument("-d", "--device",      metavar="IDENTIFIER",
                     help="Device identifier (e.g. iPhone14,2)")
    dev.add_argument("-B", "--boardconfig", metavar="BOARDCONFIG",
                     help="Board config (e.g. d63ap) – alternative to -d")

    # Firmware selection
    fw = p.add_argument_group("firmware selection")
    fw.add_argument("-i", "--ios",         metavar="VERSION",
                    help="iOS/firmware version (e.g. 16.7.8)")
    fw.add_argument("-Z", "--buildid",     metavar="BUILDID",
                    help="Build ID (e.g. 20H330) – alternative to -i")
    fw.add_argument("-m", "--build-manifest", metavar="PATH",
                    help="Use a local BuildManifest.plist instead of downloading")
    fw.add_argument("-l", "--latest",      action="store_true",
                    help="Use the latest public firmware version")
    fw.add_argument("-o", "--ota",         action="store_true",
                    help="Check OTA signing instead of full restore (IPSW)")
    fw.add_argument("--beta",              action="store_true",
                    help="Request ticket for beta firmware")

    # Security / nonces
    sec = p.add_argument_group("security / nonces")
    sec.add_argument("-e", "--ecid",       metavar="ECID",
                     help="Device ECID in hex (0x…) or decimal")
    sec.add_argument("-g", "--generator",  metavar="GENERATOR",
                     help="Nonce generator in hex (e.g. 0xbd34a880be0b53f3)")
    sec.add_argument("-N", "--apnonce",    metavar="HEX",
                     help="ApNonce in hex (overrides --generator)")
    sec.add_argument("-S", "--sepnonce",   metavar="HEX",
                     help="SepNonce in hex (random if omitted)")

    # Baseband
    bb = p.add_argument_group("baseband")
    bb.add_argument("-b", "--baseband",    metavar="0|1|2", type=int, default=0,
                    choices=[0, 1, 2],
                    help="0=include baseband if available (default), "
                         "1=skip baseband, 2=baseband only")
    bb.add_argument("--no-baseband",       action="store_true",
                    help="Skip baseband ticket (same as -b 1)")
    bb.add_argument("--bbsnum",            metavar="HEX",
                     help="Baseband SNUM in hex (required for baseband blobs on some devices)")

    # Output
    out = p.add_argument_group("output / saving")
    out.add_argument("-s", "--save",       metavar="DIR", nargs="?", const=".",
                     help="Save SHSH2 blob to directory (default: current dir)")
    out.add_argument("--print-tss-request",  action="store_true",
                     help="Print TSS request XML and exit")
    out.add_argument("--print-tss-response", action="store_true",
                     help="Print raw TSS response body")
    out.add_argument("-u", "--update-install", action="store_true",
                     help="Request update ticket instead of erase/restore ticket")
    out.add_argument("-V", "--variant",    metavar="VARIANT",
                     help="Explicit restore variant string")

    # Listing / info
    lst = p.add_argument_group("listing")
    lst.add_argument("--list-devices",     action="store_true",
                     help="List all known devices and exit")
    lst.add_argument("--list-versions",    action="store_true",
                     help="List all known firmware versions for a device")
    lst.add_argument("--list-builds",      action="store_true",
                     help="List all known build IDs for a device")

    # Advanced
    adv = p.add_argument_group("advanced")
    adv.add_argument("--components",       metavar="COMP1,COMP2",
                     help="Comma-separated list of components to include")
    adv.add_argument("--raw",              metavar="FILE",
                     help="Send a raw file directly to the TSS server")
    adv.add_argument("-c", "--cache",      action="count", default=0,
                     help="Cache firmware API responses (repeat for higher cache level)")
    adv.add_argument("-v", "--verbose",    action="store_true",
                     help="Verbose output")

    return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_ecid(ecid_str: str) -> int:
    s = ecid_str.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def print_devices(device_list) -> None:
    # Group by device type
    groups: dict = {}
    for d in device_list:
        prefix = "".join(c for c in d.identifier if c.isalpha())
        groups.setdefault(prefix, []).append(d)

    type_order = ["iPhone", "iPad", "iPod", "AppleTV", "Watch", "AudioAccessory", ""]
    shown = set()
    for prefix in type_order:
        if prefix not in groups:
            continue
        shown.add(prefix)
        for d in sorted(groups[prefix], key=lambda x: x.identifier):
            board = f" [{d.boardconfig}]" if d.boardconfig else ""
            print(f"  {d.identifier:<20}  {d.name}{board}")

    for prefix, devs in groups.items():
        if prefix in shown:
            continue
        for d in sorted(devs, key=lambda x: x.identifier):
            board = f" [{d.boardconfig}]" if d.boardconfig else ""
            print(f"  {d.identifier:<20}  {d.name}{board}")


def print_versions(firmwares, show_builds: bool = False) -> None:
    if not firmwares:
        print("  (no firmware data available)")
        return
    for fw in sorted(firmwares, key=lambda f: f.version):
        signed = "[SIGNED]   " if fw.signed else "[unsigned] "
        build  = f"  ({fw.buildid})" if show_builds else ""
        print(f"  {signed}  {fw.version}{build}")


# ---------------------------------------------------------------------------
# Core check logic
# ---------------------------------------------------------------------------

def do_check(args, device, firmware_url: str, fw_version: str, fw_buildid: str,
             manifest_data: dict, ecid: int, apnonce: bytes, sepnonce: bytes,
             requested_components=None, fw_signed=None) -> bool:
    """
    Perform a single TSS check against the given BuildManifest data.
    Returns True if signed.

    fw_signed: pre-fetched IPSW.me signing status (used as fallback for
               RestoreAttestationMode >= 4 devices where direct TSS requires
               hardware attestation and will return STATUS=69 without it).
    """
    # Determine CPID / BDID – prefer manifest over API (more accurate)
    cpid = device.cpid if device else 0
    bdid = device.bdid if device else 0
    boardconfig = device.boardconfig if device else None

    # Variant / restore type
    restore_type = "Update" if args.update_install else "Erase"
    variant = args.variant or None

    # Find the correct BuildIdentity
    identity = None
    if cpid and bdid:
        identity = mf.find_identity(
            manifest_data, cpid, bdid,
            boardconfig=boardconfig,
            restore_type=restore_type,
            variant=variant,
            ota=args.ota,
        )
    if identity is None and boardconfig:
        identity = mf.find_identity_by_board(
            manifest_data, boardconfig,
            restore_type=restore_type,
            variant=variant,
            ota=args.ota,
        )
    if identity is None:
        # Fallback: try the first identity (works when only one device in manifest)
        identities = manifest_data.get("BuildIdentities", [])
        if identities:
            identity = identities[0]
            if args.verbose:
                print("[!] Could not match exact identity — using first available")
        else:
            print("[ERROR] No BuildIdentities found in manifest", file=sys.stderr)
            return False

    # (CPID/BDID from identity resolved below after img4 detection)

    # Pull CPID/BDID from the identity if we still don't have them
    if not cpid:
        cpid = mf.get_cpid(identity)
    if not bdid:
        bdid = mf.get_bdid(identity)

    # IMG4 is determined by chip family (A7/0x8960 and newer)
    img4 = devdb.is_img4(cpid) if cpid else True

    # Nonce type
    nonce_kind = devdb.nonce_type(cpid) if cpid else devdb.NONCE_SHA384

    # Attestation mode check — A17 Pro (CPID 0x8130) and newer require hardware
    # attestation for TSS.  Without a real device-derived nonce/attestation bundle,
    # Apple's server returns STATUS=69 regardless of what we send.  Fall back to
    # the IPSW.me signing status which is accurate and requires no hardware.
    attest_mode = mf.get_restore_attestation_mode(identity)
    needs_hardware_attestation = (attest_mode >= 4)

    if needs_hardware_attestation and not args.print_tss_request:
        # Only skip TSS if we're NOT saving blobs (blob save needs real hardware anyway)
        wants_save = (args.save is not None and ecid != 0)
        if not wants_save:
            if fw_signed is not None:
                if args.verbose:
                    print(
                        f"[i] RestoreAttestationMode={attest_mode}: this chip requires "
                        f"hardware attestation for TSS (A17 Pro / 0x8130+). "
                        f"Using IPSW.me signing status."
                    )
                else:
                    print(
                        f"[i] Device uses hardware attestation (A17 Pro+); "
                        f"using IPSW.me signing status."
                    )
                return fw_signed
            else:
                # No IPSW.me status available (e.g. local manifest) — warn and try TSS
                print(
                    f"[!] RestoreAttestationMode={attest_mode}: this chip (A17 Pro+) "
                    f"requires hardware attestation. Direct TSS will likely return "
                    f"STATUS=69. Provide a real --apnonce and --ecid for accurate results.",
                    file=sys.stderr,
                )

    # Build nonces if not provided
    if not apnonce:
        if args.generator:
            apnonce = tsslib.generator_to_nonce(args.generator, nonce_kind)
        else:
            apnonce = tsslib.random_nonce(nonce_kind)
    if not sepnonce:
        sepnonce = secrets.token_bytes(20)

    # Build TSS request
    baseband_mode = args.baseband
    if args.no_baseband:
        baseband_mode = 1

    req = tsslib.TSSRequest(cpid=cpid, bdid=bdid, ecid=ecid)
    req.set_nonce(apnonce, sepnonce)
    req.set_img4(img4)

    # UniqueBuildID — may live at the top level of the BuildIdentity in newer firmwares
    ubid = identity.get("UniqueBuildID")
    if isinstance(ubid, bytes):
        req.set_unique_build_id(ubid)

    if baseband_mode != 2:  # not BB-only
        comps = mf.extract_ap_components(
            identity,
            img4=img4,
            skip_baseband=(baseband_mode == 1),
            requested_components=(
                requested_components.split(",") if requested_components else None
            ),
        )
        req.add_ap_components(comps)

    if baseband_mode != 1:  # not no-BB
        bb_comps = mf.extract_baseband_components(identity, img4=img4)
        if bb_comps:
            bb_info = devdb.get_baseband_info(device.identifier) if device else None
            if bb_info:
                bbgcid, snum_len = bb_info
                if args.bbsnum:
                    bbsnum = tsslib.parse_hex_bytes(args.bbsnum)
                else:
                    bbsnum = secrets.token_bytes(snum_len)
                req.add_baseband_components(bb_comps, bbgcid=bbgcid, bbsnum=bbsnum)
            elif args.verbose:
                print("[i] No baseband info for this device — skipping baseband")

    if args.print_tss_request:
        req.print_request()
        return True

    # Send
    signed, response = req.send(verbose=args.verbose)

    if args.print_tss_response:
        print(response)

    if signed:
        blob = tsslib.extract_shsh_blob(response)
        if args.save is not None and blob:
            save_dir = args.save or "."
            os.makedirs(save_dir, exist_ok=True)
            filename = tsslib.shsh2_filename(
                device.identifier if device else "unknown",
                ecid, fw_version, fw_buildid, apnonce,
            )
            path = os.path.join(save_dir, filename)
            if isinstance(blob, dict):
                with open(path, "wb") as f:
                    plistlib.dump(blob, f)
            else:
                with open(path, "wb") as f:
                    f.write(blob if isinstance(blob, bytes) else blob.encode())
            print(f"[+] Saved blob → {path}")

    return signed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Listing: devices
    # ------------------------------------------------------------------
    if args.list_devices:
        print("Fetching device list…")
        try:
            all_devs = devdb.get_all_devices()
            print_devices(all_devs)
        except Exception as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1
        return 0

    # ------------------------------------------------------------------
    # Resolve device
    # ------------------------------------------------------------------
    device = None
    if args.device:
        if args.verbose:
            print(f"[i] Looking up device {args.device}…")
        device = devdb.get_device(args.device, no_cache=(args.cache == 0))
        if device is None:
            print(f"[ERROR] Unknown device: {args.device}", file=sys.stderr)
            return 1
    elif args.boardconfig:
        if args.verbose:
            print(f"[i] Looking up board config {args.boardconfig}…")
        device = devdb.get_device_by_board(args.boardconfig, no_cache=(args.cache == 0))
        if device is None:
            print(f"[ERROR] No device found for board config: {args.boardconfig}", file=sys.stderr)
            return 1
    elif not args.build_manifest and not args.raw:
        parser.error("Specify a device with -d / --device or -B / --boardconfig")

    # ------------------------------------------------------------------
    # Listing: versions / builds
    # ------------------------------------------------------------------
    if args.list_versions or args.list_builds:
        if not device:
            parser.error("-d / --device required for --list-versions / --list-builds")
        identifier = device.identifier
        try:
            fws = ipswapi.get_firmwares(identifier, ota=args.ota)
        except Exception as exc:
            print(f"[ERROR] Could not fetch firmware list: {exc}", file=sys.stderr)
            return 1

        if not fws:
            print(f"No firmware versions found for {identifier}")
            return 0

        print(f"Firmware versions for {identifier} ({device.name}):")
        print_versions(fws, show_builds=args.list_builds)
        return 0

    # ------------------------------------------------------------------
    # Raw file mode
    # ------------------------------------------------------------------
    if args.raw:
        print(f"[i] Sending raw file: {args.raw}")
        try:
            with open(args.raw, "rb") as f:
                payload = f.read()
        except OSError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1

        import requests as _req
        session = _req.Session()
        session.verify = False
        for url in tsslib.TSS_URLS:
            try:
                resp = session.post(url, data=payload, headers=tsslib.TSS_HEADERS, timeout=30)
                print(resp.text)
                return 0
            except Exception:
                continue
        print("[ERROR] All TSS endpoints failed", file=sys.stderr)
        return 1

    # ------------------------------------------------------------------
    # Parse optional user-supplied values
    # ------------------------------------------------------------------
    ecid = 0
    if args.ecid:
        try:
            ecid = parse_ecid(args.ecid)
        except ValueError:
            print(f"[ERROR] Invalid ECID: {args.ecid}", file=sys.stderr)
            return 1

    apnonce:  bytes = b""
    sepnonce: bytes = b""
    if args.apnonce:
        try:
            apnonce = tsslib.parse_hex_bytes(args.apnonce)
        except ValueError:
            print(f"[ERROR] Invalid apnonce hex: {args.apnonce}", file=sys.stderr)
            return 1
    if args.sepnonce:
        try:
            sepnonce = tsslib.parse_hex_bytes(args.sepnonce)
        except ValueError:
            print(f"[ERROR] Invalid sepnonce hex: {args.sepnonce}", file=sys.stderr)
            return 1

    # ------------------------------------------------------------------
    # Load or fetch BuildManifest
    # ------------------------------------------------------------------
    manifest_data  = None
    fw_version     = ""
    fw_buildid     = ""
    firmware_url   = ""
    fw_signed_ipsw = None  # bool or None — IPSW.me signing status (fallback for A17 Pro+)

    if args.build_manifest:
        # Local file
        if args.verbose:
            print(f"[i] Loading local BuildManifest: {args.build_manifest}")
        try:
            manifest_data = mf.load(args.build_manifest)
        except Exception as exc:
            print(f"[ERROR] Could not load BuildManifest: {exc}", file=sys.stderr)
            return 1
        fw_version  = mf.get_product_version(manifest_data)
        fw_buildid  = mf.get_product_build_version(manifest_data)

    else:
        # Fetch from IPSW.me
        if not device:
            parser.error("Device must be specified with -d or -B")

        identifier = device.identifier
        fw = None
        no_cache = (args.cache == 0)

        if args.latest:
            if args.verbose:
                print(f"[i] Fetching latest firmware for {identifier}…")
            fw = ipswapi.get_latest_firmware(identifier, ota=args.ota)
        elif args.ios:
            if args.verbose:
                print(f"[i] Looking up iOS {args.ios} for {identifier}…")
            fw = ipswapi.get_firmware_by_version(identifier, args.ios, ota=args.ota)
        elif args.buildid:
            if args.verbose:
                print(f"[i] Looking up build {args.buildid} for {identifier}…")
            fw = ipswapi.get_firmware_by_buildid(identifier, args.buildid, ota=args.ota)
        else:
            parser.error(
                "Specify a firmware version with -i / --ios, -Z / --buildid, "
                "or use --latest"
            )

        if fw is None:
            print(
                f"[ERROR] Firmware not found for {identifier} "
                f"version={args.ios or ''} build={args.buildid or ''}",
                file=sys.stderr,
            )
            return 1

        fw_version      = fw.version
        fw_buildid      = fw.buildid
        firmware_url    = fw.url
        fw_signed_ipsw  = fw.signed  # capture IPSW.me signing status for fallback

        print(f"[i] Firmware: {fw_version} ({fw_buildid}) for {identifier} ({device.name})")

        if args.verbose:
            print(f"[i] Downloading BuildManifest from {firmware_url}…")
        else:
            print(f"[i] Fetching BuildManifest… (no full IPSW download)")

        try:
            raw_manifest = ipswapi.download_build_manifest(firmware_url)
            manifest_data = plistlib.loads(raw_manifest)
        except Exception as exc:
            print(f"[ERROR] Could not fetch BuildManifest: {exc}", file=sys.stderr)
            return 1

    # ------------------------------------------------------------------
    # Check signing status
    # ------------------------------------------------------------------
    print(f"[i] Sending TSS request to Apple…")

    signed = do_check(
        args=args,
        device=device,
        firmware_url=firmware_url,
        fw_version=fw_version,
        fw_buildid=fw_buildid,
        manifest_data=manifest_data,
        ecid=ecid,
        apnonce=apnonce,
        sepnonce=sepnonce,
        requested_components=args.components,
        fw_signed=fw_signed_ipsw,
    )

    if signed:
        print(f"\n[+] {fw_version} ({fw_buildid}) IS being signed for "
              f"{device.identifier if device else 'device'} ✓")
        return 0
    else:
        print(f"\n[-] {fw_version} ({fw_buildid}) is NOT being signed for "
              f"{device.identifier if device else 'device'} ✗")
        return 1


if __name__ == "__main__":
    sys.exit(main())
