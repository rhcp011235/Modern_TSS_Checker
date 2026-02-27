#!/usr/bin/env python3
"""
tsschecker_GUI.py — Self-contained Apple-style TSS Checker GUI

All library code is inlined. No subprocess calls. Single file.
Only external dependency: pip install requests

PyInstaller build commands:
  macOS (.app):   pyinstaller --onefile --windowed --name "TSS Checker" tsschecker_GUI.py
  Windows (.exe): pyinstaller --onefile --windowed --name "TSS Checker" tsschecker_GUI.py
  Linux:          pyinstaller --onefile --name tsschecker-gui tsschecker_GUI.py
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import sys, os, json, plistlib, secrets, hashlib, uuid, struct, zlib
import time, queue, threading, dataclasses, contextlib
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import filedialog, messagebox

# ── third-party ───────────────────────────────────────────────────────────────
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    _r = tk.Tk(); _r.withdraw()
    messagebox.showerror("Missing Dependency",
        "The 'requests' package is required.\n\nInstall it with:\n  pip install requests")
    sys.exit(1)


# ═════════════════════════════════════════════════════════════════════════════
# INLINED: Shared cache helpers
# ═════════════════════════════════════════════════════════════════════════════

_CACHE_DIR      = Path(os.path.expanduser("~/.cache/tsschecker"))
_DEV_CACHE_TTL  = 86400 * 7   # 7 days
_ADB_INDEX_TTL  = 3600  * 2   # 2 hours
_ADB_ENTRY_TTL  = 3600  * 4   # 4 hours
IPSW_ME_BASE    = "https://api.ipsw.me/v4"
APPLEDB_BASE    = "https://api.appledb.dev"


def _cache_path(key: str) -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return _CACHE_DIR / f"{key}.json"

def _load_cache(key: str, ttl: int = _DEV_CACHE_TTL):
    p = _cache_path(key)
    if p.exists():
        try:
            data = json.loads(p.read_text())
            if time.time() - data.get("ts", 0) < ttl:
                return data.get("v")
        except Exception:
            pass
    return None

def _save_cache(key: str, value) -> None:
    _cache_path(key).write_text(json.dumps({"ts": time.time(), "v": value}))


# ═════════════════════════════════════════════════════════════════════════════
# INLINED: devices.py
# ═════════════════════════════════════════════════════════════════════════════

NONCE_NONE   = "none"
NONCE_SHA1   = "sha1"
NONCE_SHA256 = "sha256"
NONCE_SHA384 = "sha384"

_CPID_NO_NONCE: set = {0x8900, 0x8720}
_CPID_SHA1: set = {
    0x8920, 0x8922, 0x8930, 0x8940, 0x8942, 0x8945, 0x8947,
    0x8950, 0x8955, 0x8960, 0x7000, 0x7001, 0x7002, 0x8000, 0x8003,
}
_CPID_SHA256: set = {0x8130, 0x8140, 0x8150}
_CPID_IMG3: set = {
    0x8900, 0x8720, 0x8920, 0x8922, 0x8930,
    0x8940, 0x8942, 0x8945, 0x8947, 0x8950, 0x8955,
}

BASEBAND_DB: Dict[str, tuple] = {
    "iPhone4,1":  (257801984,  20),
    "iPhone5,1":  (2315222105, 20), "iPhone5,2":  (2315222105, 20),
    "iPhone5,3":  (3554432823, 20), "iPhone5,4":  (3554432823, 20),
    "iPhone6,1":  (3554432823, 20), "iPhone6,2":  (3554432823, 20),
    "iPhone7,1":  (3840776546, 16), "iPhone7,2":  (3840776546, 16),
    "iPhone8,1":  (3840776546, 16), "iPhone8,2":  (3840776546, 16),
    "iPhone8,4":  (3840776546, 16),
    "iPhone9,1":  (3840776546, 16), "iPhone9,2":  (3840776546, 16),
    "iPhone9,3":  (3840776546, 16), "iPhone9,4":  (3840776546, 16),
    "iPhone10,1": (3840776546, 16), "iPhone10,2": (3840776546, 16),
    "iPhone10,3": (3840776546, 16), "iPhone10,4": (3840776546, 16),
    "iPhone10,5": (3840776546, 16), "iPhone10,6": (3840776546, 16),
    "iPad2,2": (2315222105, 20), "iPad2,3": (2315222105, 20),
    "iPad2,6": (2315222105, 20), "iPad2,7": (2315222105, 20),
    "iPad3,2": (2315222105, 20), "iPad3,3": (2315222105, 20),
    "iPad3,5": (3554432823, 20), "iPad3,6": (3554432823, 20),
    "iPad4,2": (3554432823, 20), "iPad4,3": (3554432823, 20),
    "iPad4,5": (3554432823, 20), "iPad4,6": (3554432823, 20),
    "iPad4,8": (3554432823, 20), "iPad4,9": (3554432823, 20),
    "iPad5,2": (3840776546, 16), "iPad5,4": (3840776546, 16),
    "iPad6,4": (3840776546, 16), "iPad6,8": (3840776546, 16),
    "iPad7,2": (3840776546, 16), "iPad7,4": (3840776546, 16),
}


@dataclasses.dataclass
class Device:
    identifier: str
    name: str
    boardconfig: str
    cpid: int = 0
    bdid: int = 0
    platform: str = ""


def _dev_nonce_type(cpid: int) -> str:
    if cpid in _CPID_NO_NONCE:  return NONCE_NONE
    if cpid in _CPID_SHA1:      return NONCE_SHA1
    if cpid in _CPID_SHA256:    return NONCE_SHA256
    return NONCE_SHA384

def _dev_is_img4(cpid: int) -> bool:
    return cpid not in _CPID_IMG3

def _dev_from_dict(d: dict) -> Device:
    return Device(
        identifier  = d.get("identifier", ""),
        name        = d.get("name", ""),
        boardconfig = d.get("boardconfig") or d.get("board") or "",
        cpid        = int(d.get("cpid") or 0),
        bdid        = int(d.get("bdid") or 0),
        platform    = d.get("platform", ""),
    )

def dev_get_all(no_cache: bool = False) -> List[Device]:
    if not no_cache:
        cached = _load_cache("all_devices")
        if cached:
            return [_dev_from_dict(d) for d in cached]
    resp = requests.get(f"{IPSW_ME_BASE}/devices", timeout=20)
    resp.raise_for_status()
    raw = resp.json()
    _save_cache("all_devices", raw)
    return [_dev_from_dict(d) for d in raw]

def dev_get(identifier: str, no_cache: bool = False) -> Optional[Device]:
    key = f"device_{identifier}"
    if not no_cache:
        cached = _load_cache(key)
        if cached:
            return _dev_from_dict(cached)
    try:
        resp = requests.get(f"{IPSW_ME_BASE}/device/{identifier}", timeout=20)
        resp.raise_for_status()
        raw = resp.json()
        _save_cache(key, raw)
        return _dev_from_dict(raw)
    except requests.HTTPError:
        return None

def dev_get_by_board(boardconfig: str, no_cache: bool = False) -> Optional[Device]:
    bc = boardconfig.lower()
    for d in dev_get_all(no_cache=no_cache):
        if d.boardconfig.lower() == bc:
            return dev_get(d.identifier, no_cache=no_cache)
    return None

def dev_get_baseband_info(identifier: str):
    return BASEBAND_DB.get(identifier)


# ═════════════════════════════════════════════════════════════════════════════
# INLINED: ipsw.py  (FragmentZip + firmware API)
# ═════════════════════════════════════════════════════════════════════════════

class FragmentZipError(Exception):
    pass

class FragmentZip:
    def __init__(self, url: str, session=None):
        self.url = url
        self._s  = session or requests.Session()
        self._s.headers.update({"User-Agent": "tsschecker/python"})
        self._file_size = self._get_file_size()

    def _get_file_size(self) -> int:
        resp = self._s.head(self.url, timeout=20, allow_redirects=True)
        resp.raise_for_status()
        size = resp.headers.get("Content-Length")
        if not size:
            resp = self._s.get(self.url, headers={"Range": "bytes=0-0"}, timeout=20)
            cr = resp.headers.get("Content-Range", "")
            if "/" in cr:
                size = cr.split("/")[-1]
        if not size:
            raise FragmentZipError("Cannot determine remote file size")
        return int(size)

    def _range_get(self, start: int, end: int) -> bytes:
        resp = self._s.get(self.url, headers={"Range": f"bytes={start}-{end}"}, timeout=60)
        if resp.status_code not in (200, 206):
            raise FragmentZipError(f"Range request failed: HTTP {resp.status_code}")
        return resp.content

    def _find_eocd(self) -> tuple:
        tail_size = min(65557, self._file_size)
        data = self._range_get(self._file_size - tail_size, self._file_size - 1)
        pos = data.rfind(b"PK\x05\x06")
        if pos == -1:
            raise FragmentZipError("EOCD signature not found")
        if len(data) - pos < 22:
            raise FragmentZipError("Truncated EOCD record")
        _, _, _, _, _, cd_size, cd_offset, _ = struct.unpack_from("<IHHHHIIH", data, pos)
        if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            return self._find_eocd64(data, pos)
        return int(cd_offset), int(cd_size)

    def _find_eocd64(self, tail_data: bytes, eocd_pos: int) -> tuple:
        loc_pos = eocd_pos - 20
        if loc_pos < 0 or tail_data[loc_pos:loc_pos+4] != b"PK\x06\x07":
            raise FragmentZipError("ZIP64 EOCD locator not found")
        _, _, eocd64_offset, _ = struct.unpack_from("<IIqI", tail_data, loc_pos)
        eocd64_data = self._range_get(eocd64_offset, eocd64_offset + 55)
        if eocd64_data[:4] != b"PK\x06\x06":
            raise FragmentZipError("ZIP64 EOCD signature mismatch")
        (_, _, _, _, _, _, _, _, cd_size, cd_offset) = struct.unpack_from("<IqHHIIqqqq", eocd64_data)
        return int(cd_offset), int(cd_size)

    def _parse_central_directory(self, cd_offset: int, cd_size: int) -> Dict[str, dict]:
        cd_data = self._range_get(cd_offset, cd_offset + cd_size - 1)
        entries: Dict[str, dict] = {}
        pos = 0
        while pos < len(cd_data):
            if cd_data[pos:pos+4] != b"PK\x01\x02":
                break
            if len(cd_data) - pos < 46:
                break
            (_, _, _, _, compress_method, _, _, _, compressed_size, uncompressed_size,
             fname_len, extra_len, comment_len, _, _, _, local_header_offset,
            ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", cd_data, pos)
            fname_start = pos + 46
            extra_start = fname_start + fname_len
            filename = cd_data[fname_start:fname_start+fname_len].decode("utf-8", errors="replace")
            if (compressed_size == 0xFFFFFFFF or uncompressed_size == 0xFFFFFFFF
                    or local_header_offset == 0xFFFFFFFF):
                compressed_size, uncompressed_size, local_header_offset = \
                    self._parse_zip64_extra(
                        cd_data[extra_start:extra_start+extra_len],
                        compressed_size, uncompressed_size, local_header_offset)
            pos = extra_start + extra_len + comment_len
            entries[filename] = {"compress_method": compress_method,
                                 "compressed_size": compressed_size,
                                 "local_header_offset": local_header_offset}
        return entries

    @staticmethod
    def _parse_zip64_extra(extra: bytes, cs: int, us: int, lh: int) -> tuple:
        i = 0
        while i + 4 <= len(extra):
            hid, dsz = struct.unpack_from("<HH", extra, i); i += 4
            blk = extra[i:i+dsz]; i += dsz
            if hid != 0x0001:
                continue
            bp = 0
            if us == 0xFFFFFFFF and bp+8 <= len(blk):
                us = struct.unpack_from("<q", blk, bp)[0]; bp += 8
            if cs == 0xFFFFFFFF and bp+8 <= len(blk):
                cs = struct.unpack_from("<q", blk, bp)[0]; bp += 8
            if lh == 0xFFFFFFFF and bp+8 <= len(blk):
                lh = struct.unpack_from("<q", blk, bp)[0]
            break
        return cs, us, lh

    def _read_local_data_offset(self, lh_offset: int) -> int:
        hdr = self._range_get(lh_offset, lh_offset + 29)
        if hdr[:4] != b"PK\x03\x04":
            raise FragmentZipError("Local file header signature mismatch")
        fname_len = struct.unpack_from("<H", hdr, 26)[0]
        extra_len = struct.unpack_from("<H", hdr, 28)[0]
        return lh_offset + 30 + fname_len + extra_len

    def read_file(self, filename: str) -> bytes:
        cd_offset, cd_size = self._find_eocd()
        entries = self._parse_central_directory(cd_offset, cd_size)
        target = None
        for candidate in (filename, f"AssetData/boot/{filename}"):
            if candidate in entries:
                target = candidate; break
        if target is None:
            raise FragmentZipError(f"'{filename}' not found in remote ZIP")
        entry = entries[target]
        data_off = self._read_local_data_offset(entry["local_header_offset"])
        compressed = self._range_get(data_off, data_off + entry["compressed_size"] - 1)
        method = entry["compress_method"]
        if method == 0:  return compressed
        if method == 8:  return zlib.decompress(compressed, -15)
        raise FragmentZipError(f"Unsupported compression method {method}")


class Firmware:
    def __init__(self, d: dict):
        self.version:  str  = d.get("version", "")
        self.buildid:  str  = d.get("buildid", "")
        self.url:      str  = d.get("url", "")
        self.signed:   bool = d.get("signed", False)
        self.filesize: int  = d.get("filesize", 0)

def fw_get_all(identifier: str, ota: bool = False) -> List[Firmware]:
    endpoint = "ota" if ota else "ipsw"
    resp = requests.get(f"{IPSW_ME_BASE}/device/{identifier}?type={endpoint}", timeout=20)
    resp.raise_for_status()
    data = resp.json()
    return [Firmware(f) for f in (data.get("firmwares") or data.get("otas") or [])]

def fw_get_latest(identifier: str, ota: bool = False) -> Optional[Firmware]:
    fws = fw_get_all(identifier, ota=ota)
    if not fws: return None
    def _vk(fw):
        try: return tuple(int(x) for x in fw.version.split("."))
        except: return (0,)
    return max(fws, key=_vk)

def fw_get_by_version(identifier: str, version: str, ota: bool = False) -> Optional[Firmware]:
    for fw in fw_get_all(identifier, ota=ota):
        if fw.version == version: return fw
    return None

def fw_get_by_buildid(identifier: str, buildid: str, ota: bool = False) -> Optional[Firmware]:
    for fw in fw_get_all(identifier, ota=ota):
        if fw.buildid.lower() == buildid.lower(): return fw
    return None

def fw_download_manifest(ipsw_url: str) -> bytes:
    return FragmentZip(ipsw_url).read_file("BuildManifest.plist")


# ═════════════════════════════════════════════════════════════════════════════
# INLINED: manifest.py
# ═════════════════════════════════════════════════════════════════════════════

_DEFAULT_CONDITIONS = {
    "ApRequiresImage4": True,
    "ApRawProductionMode": True, "ApCurrentProductionMode": True,
    "ApRawSecurityMode": True,   "ApCurrentSecurityMode": True,
    "ApProductionMode": True,    "ApSecurityMode": True,
    "ApDemotionPolicyOverride": False, "ApInRomDFU": False,
}

def _mf_parse_int(value) -> int:
    if isinstance(value, int): return value
    if isinstance(value, str): return int(value, 16) if value.startswith("0x") else int(value)
    return 0

def mf_load(path_or_bytes) -> dict:
    if isinstance(path_or_bytes, str):
        with open(path_or_bytes, "rb") as f: raw = f.read()
    else:
        raw = path_or_bytes
    return plistlib.loads(raw)

def mf_find_identity(manifest: dict, cpid: int, bdid: int, boardconfig=None,
                     restore_type="Erase", variant=None, ota=False) -> Optional[dict]:
    if variant is None:
        variant_hint = "OTA" if ota else ("Upgrade" if restore_type.lower()=="update" else "Erase")
    else:
        variant_hint = variant
    candidates = []
    for identity in manifest.get("BuildIdentities", []):
        if _mf_parse_int(identity.get("ApChipID",0)) != cpid: continue
        if _mf_parse_int(identity.get("ApBoardID",0)) != bdid: continue
        info = identity.get("Info", {})
        id_board = info.get("DeviceClass","").lower()
        if boardconfig and id_board and id_board != boardconfig.lower(): continue
        candidates.append(identity)
    if not candidates: return None
    for c in candidates:
        if variant_hint.lower() in c.get("Info",{}).get("Variant","").lower(): return c
    return candidates[0]

def mf_find_identity_by_board(manifest: dict, boardconfig: str,
                               restore_type="Erase", variant=None, ota=False) -> Optional[dict]:
    bc = boardconfig.lower()
    hint = variant or ("Upgrade" if restore_type.lower()=="update" else "Erase")
    candidates = [i for i in manifest.get("BuildIdentities",[])
                  if i.get("Info",{}).get("DeviceClass","").lower() == bc]
    if not candidates: return None
    for c in candidates:
        if hint.lower() in c.get("Info",{}).get("Variant","").lower(): return c
    return candidates[0]

def _mf_eval_rules(rules: list, conditions: dict) -> dict:
    applied: dict = {}
    for rule in rules:
        if all(conditions.get(k)==v for k,v in rule.get("Conditions",{}).items()):
            applied.update(rule.get("Actions",{}))
    return applied

def mf_extract_ap_components(identity: dict, img4=True, conditions=None,
                              requested_components=None, skip_baseband=True) -> Dict[str,dict]:
    conds = dict(_DEFAULT_CONDITIONS)
    conds["ApRequiresImage4"] = img4
    if conditions: conds.update(conditions)
    result: Dict[str,dict] = {}
    for name, comp in identity.get("Manifest",{}).items():
        if not isinstance(comp, dict): continue
        if (name.startswith("Bb") or name=="BasebandFirmware") and skip_baseband: continue
        if name.startswith("AVISP1,") or name.startswith("AudioAP1,"): continue
        if name.startswith("Savage,"): continue
        if requested_components and name not in requested_components: continue
        if comp.get("Info",{}).get("Personalize") is False: continue
        entry: dict = {}
        if "Trusted" in comp: entry["Trusted"] = comp["Trusted"]
        entry.update(_mf_eval_rules(comp.get("Info",{}).get("RestoreRequestRules",[]), conds))
        if "Digest" in comp:        entry["Digest"]        = comp["Digest"]
        if "PartialDigest" in comp: entry["PartialDigest"] = comp["PartialDigest"]
        result[name] = entry
    return result

def mf_extract_baseband_components(identity: dict, img4=True, conditions=None) -> Dict[str,dict]:
    conds = dict(_DEFAULT_CONDITIONS)
    conds["ApRequiresImage4"] = img4
    if conditions: conds.update(conditions)
    result: Dict[str,dict] = {}
    for name, comp in identity.get("Manifest",{}).items():
        if not isinstance(comp, dict): continue
        if not (name.startswith("Bb") or name=="BasebandFirmware"): continue
        entry: dict = {}
        entry.update(_mf_eval_rules(comp.get("Info",{}).get("RestoreRequestRules",[]), conds))
        if "Digest" in comp:        entry["Digest"]        = comp["Digest"]
        if "PartialDigest" in comp: entry["PartialDigest"] = comp["PartialDigest"]
        result[name] = entry
    return result

def mf_get_copro_info(identity: dict) -> List[dict]:
    manifest_components = identity.get("Manifest", {})
    found, seen = [], set()
    for name in manifest_components:
        for prefix in ("AVISP1", "AudioAP1"):
            if prefix not in seen and name.startswith(prefix + ","):
                found.append({"prefix": prefix,
                              "chip_id":  _mf_parse_int(identity.get(f"{prefix},ChipID",0)),
                              "board_id": _mf_parse_int(identity.get(f"{prefix},BoardID",0))})
                seen.add(prefix); break
    return found

def mf_extract_copro_components(identity: dict, prefix: str, img4=True, conditions=None) -> Dict[str,dict]:
    conds = dict(_DEFAULT_CONDITIONS)
    conds["ApRequiresImage4"] = img4
    if conditions: conds.update(conditions)
    pfx = prefix + ","
    result: Dict[str,dict] = {}
    for name, comp in identity.get("Manifest",{}).items():
        if not isinstance(comp, dict) or not name.startswith(pfx): continue
        entry: dict = {}
        entry.update(_mf_eval_rules(comp.get("Info",{}).get("RestoreRequestRules",[]), conds))
        if "Trusted" in comp: entry["Trusted"] = comp["Trusted"]
        if "Digest" in comp:
            entry["Digest"] = comp["Digest"]
        elif entry.get("Trusted"):
            entry["Digest"] = b""
        if "PartialDigest" in comp: entry["PartialDigest"] = comp["PartialDigest"]
        result[name] = entry
    return result

def mf_get_product_version(m: dict) -> str:   return m.get("ProductVersion","")
def mf_get_build_version(m: dict) -> str:     return m.get("ProductBuildVersion","")
def mf_get_cpid(identity: dict) -> int:       return _mf_parse_int(identity.get("ApChipID",0))
def mf_get_bdid(identity: dict) -> int:       return _mf_parse_int(identity.get("ApBoardID",0))
def mf_get_attest_mode(identity: dict) -> int:
    return int(identity.get("Info",{}).get("RestoreAttestationMode",0))


# ═════════════════════════════════════════════════════════════════════════════
# INLINED: tss.py
# ═════════════════════════════════════════════════════════════════════════════

TSS_CLIENT_VERSION = "libauthinstall-698.0.5"
TSS_MAX_TRIES      = 10
TSS_URLS = [
    "https://gs.apple.com/TSS/controller?action=2",
    "http://gs.apple.com/TSS/controller?action=2",
    "https://17.111.103.65/TSS/controller?action=2",
    "https://17.111.103.15/TSS/controller?action=2",
    "http://17.111.103.65/TSS/controller?action=2",
    "http://17.111.103.15/TSS/controller?action=2",
]
TSS_HEADERS = {
    "Cache-Control": "no-cache",
    "Content-type":  'text/xml; charset="utf-8"',
    "Expect":        "",
    "User-Agent":    "InetURL/1.0",
    "Connection":    "close",
}

def _tss_platform() -> str:
    if sys.platform == "darwin":        return "mac"
    if sys.platform.startswith("win"):  return "windows"
    return "linux"

def tss_random_nonce(nonce_type: str) -> bytes:
    if nonce_type == "sha1":   return secrets.token_bytes(20)
    if nonce_type == "sha256": return secrets.token_bytes(32)
    if nonce_type == "sha384": return secrets.token_bytes(48)
    return b""

def tss_parse_hex_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith(("0x","0X")): h = h[2:]
    return bytes.fromhex(h)

def tss_generator_to_nonce(generator_hex: str, nonce_type: str) -> bytes:
    gen = tss_parse_hex_bytes(generator_hex)
    if nonce_type == "sha1":   return hashlib.sha1(gen).digest()
    if nonce_type == "sha256": return hashlib.sha256(gen).digest()
    if nonce_type == "sha384": return hashlib.sha384(gen).digest()
    return b""


class TSSRequest:
    def __init__(self, cpid: int, bdid: int, ecid: int = 0):
        self._cpid = cpid; self._bdid = bdid; self._ecid = ecid
        self._plist: Dict[str,Any] = {}
        self._apnonce = b""; self._sepnonce = b""
        self._plist.update({
            "@Locality": "en_US", "@HostPlatformInfo": _tss_platform(),
            "@VersionInfo": TSS_CLIENT_VERSION, "@UUID": str(uuid.uuid4()).upper(),
            "ApProductionMode": True, "ApChipID": cpid,
            "ApBoardID": bdid, "ApECID": ecid, "ApSecurityDomain": 1,
        })

    def set_nonce(self, apnonce: bytes, sepnonce: bytes) -> None:
        self._apnonce = apnonce; self._sepnonce = sepnonce
        if apnonce:  self._plist["ApNonce"]  = apnonce
        if sepnonce: self._plist["SepNonce"] = sepnonce

    def set_img4(self, img4: bool = True) -> None:
        if img4:
            self._plist["@ApImg4Ticket"] = True
            self._plist["ApSecurityMode"] = True
            self._plist["UID_MODE"] = False
        else:
            self._plist["@APTicket"] = True

    def set_unique_build_id(self, ubid: bytes) -> None:
        if ubid: self._plist["UniqueBuildID"] = ubid

    def add_ap_components(self, components: Dict[str,Any]) -> None:
        for name, entry in components.items():
            if isinstance(entry, (bytes, dict)):
                self._plist[name] = entry

    def add_baseband_components(self, components: Dict[str,Any], bbgcid: int, bbsnum: bytes) -> None:
        self._plist["BbGoldCertId"] = bbgcid
        self._plist["BbSNUM"]       = bbsnum
        bb_entry: dict = {}
        for name, entry in components.items():
            if name == "BasebandFirmware":
                bb_entry = dict(entry) if isinstance(entry, dict) else {}
            elif isinstance(entry, dict):
                self._plist[name] = entry
        if bb_entry: self._plist["BasebandFirmware"] = bb_entry

    def add_copro_ticket(self, components: Dict[str,Any], prefix: str,
                         chip_id: int, board_id: int, ecid: int, nonce: bytes) -> None:
        self._plist["@BBTicket"] = True
        self._plist[f"@{prefix},Ticket"] = True
        if chip_id:  self._plist[f"{prefix},ChipID"]  = chip_id
        if board_id: self._plist[f"{prefix},BoardID"] = board_id
        self._plist[f"{prefix},ECID"]           = ecid
        self._plist[f"{prefix},Nonce"]          = nonce
        self._plist[f"{prefix},ProductionMode"] = True
        self._plist[f"{prefix},SecurityDomain"] = 1
        self._plist[f"{prefix},SecurityMode"]   = True
        for name, entry in components.items():
            if isinstance(entry, (dict, bytes)): self._plist[name] = entry

    def build_xml(self) -> bytes:
        return plistlib.dumps(self._plist, fmt=plistlib.FMT_XML, sort_keys=False)

    def send(self, verbose: bool = False, treat_69_as_signed: bool = False) -> Tuple[bool, str]:
        payload = self.build_xml()
        session = requests.Session(); session.verify = False
        for attempt in range(TSS_MAX_TRIES):
            url = TSS_URLS[attempt % len(TSS_URLS)]
            try:
                if verbose: print(f"[TSS] Attempt {attempt+1}/{TSS_MAX_TRIES} → {url}")
                resp = session.post(url, data=payload, headers=TSS_HEADERS, timeout=30)
                status, message = _tss_parse_response(resp.text)
                if verbose: print(f"[TSS] STATUS={status} MESSAGE={message}")
                signed = (status == 0) or (treat_69_as_signed and status == 69)
                return signed, resp.text
            except requests.RequestException as exc:
                if verbose: print(f"[TSS] Failed ({exc}), retrying…")
        return False, ""


def _tss_parse_response(body: str) -> Tuple[int, str]:
    status, message = -1, ""
    for token in body.split("&"):
        if token.startswith("STATUS="):
            try: status = int(token[7:].strip())
            except ValueError: pass
        elif token.startswith("MESSAGE="):
            message = token[8:].strip()
    return status, message

def tss_extract_shsh_blob(response_body: str) -> Optional[bytes]:
    for token in response_body.split("&"):
        if token.startswith("REQUEST_STRING="):
            plist_str = token[len("REQUEST_STRING="):]
            try:    return plistlib.loads(plist_str.encode("utf-8"))
            except: return plist_str.encode("utf-8")
    return None

def tss_shsh2_filename(product_type: str, ecid: int, version: str,
                       buildid: str, apnonce: bytes) -> str:
    ecid_str  = f"0x{ecid:X}" if ecid else "0x0"
    nonce_hex = apnonce.hex() if apnonce else "0"*40
    return f"{product_type}_{ecid_str}_{version}-{buildid}_{nonce_hex}.shsh2"


# ═════════════════════════════════════════════════════════════════════════════
# INLINED: appledb.py
# ═════════════════════════════════════════════════════════════════════════════

_IOS_MAJOR_TO_PREFIX = {15:"19", 16:"20", 17:"21", 18:"22", 26:"23"}

def _adb_os_type(identifier: str) -> str:
    if identifier.startswith("RealityDevice"):  return "visionOS"
    if identifier.startswith("AudioAccessory"): return "HomePod Software"
    if identifier.startswith("AppleTV"):        return "tvOS"
    if identifier.startswith("Watch"):          return "watchOS"
    return "iOS"

class AppleDBFirmware:
    def __init__(self, buildid: str, entry: dict, identifier: str = ""):
        self.buildid   = buildid
        self.version   = entry.get("version", "")
        self.beta      = bool(entry.get("beta", False))
        self.device_map = entry.get("deviceMap", [])
        signed_raw = entry.get("signed", False)
        self.signed = (identifier in signed_raw) if isinstance(signed_raw, list) else bool(signed_raw)
        self.url = ""; self.url_type = ""
        self._extract_url(entry.get("sources",[]), identifier)

    def _extract_url(self, sources: list, identifier: str) -> None:
        for src in sources:
            if src.get("type") != "ipsw": continue
            if identifier and src.get("deviceMap") and identifier not in src.get("deviceMap",[]): continue
            url = self._best_link(src.get("links",[]))
            if url: self.url = url; self.url_type = "ipsw"; return
        for src in sources:
            if src.get("type") != "ota" or src.get("prerequisiteBuild"): continue
            if identifier and src.get("deviceMap") and identifier not in src.get("deviceMap",[]): continue
            url = self._best_link(src.get("links",[]))
            if url: self.url = url; self.url_type = "ota"; return

    @staticmethod
    def _best_link(links: list) -> str:
        if not links: return ""
        preferred = next((l for l in links if l.get("preferred") and l.get("active")), None)
        active    = next((l for l in links if l.get("active")), None)
        return (preferred or active or links[0]).get("url","")

def _adb_fetch_entry(os_type: str, buildid: str) -> Optional[dict]:
    try:
        resp = requests.get(f"{APPLEDB_BASE}/ios/{quote(os_type)};{quote(buildid)}.json", timeout=15)
        if resp.status_code == 200: return resp.json()
    except Exception: pass
    return None

def _adb_get_index(os_type: str) -> List[str]:
    safe = os_type.replace(" ","_")
    cached = _load_cache(f"adb_index_{safe}", ttl=_ADB_INDEX_TTL)
    if cached: return cached
    resp = requests.get(f"{APPLEDB_BASE}/ios/{quote(os_type)}/index.json", timeout=20)
    resp.raise_for_status()
    data = resp.json()
    _save_cache(f"adb_index_{safe}", data)
    return data

def adb_get_by_buildid(buildid: str, identifier: str = "") -> Optional[AppleDBFirmware]:
    os_type = _adb_os_type(identifier) if identifier else "iOS"
    safe = os_type.replace(" ","_")
    cached = _load_cache(f"adb_build_{safe}_{buildid}", ttl=_ADB_ENTRY_TTL)
    if cached is not None: return AppleDBFirmware(buildid, cached, identifier)
    entry = _adb_fetch_entry(os_type, buildid)
    if entry is None: return None
    _save_cache(f"adb_build_{safe}_{buildid}", entry)
    return AppleDBFirmware(buildid, entry, identifier)

def adb_search_by_version(version: str, identifier: str = "") -> List[AppleDBFirmware]:
    os_type = _adb_os_type(identifier) if identifier else "iOS"
    safe = os_type.replace(" ","_")
    cache_key = f"adb_search_{safe}_{version}_{identifier}"
    cached = _load_cache(cache_key, ttl=_ADB_INDEX_TTL)
    if cached is not None:
        return [AppleDBFirmware(bid, entry, identifier) for bid, entry in cached]
    build_prefix = None
    try:
        major = int(version.split(".")[0])
        build_prefix = _IOS_MAJOR_TO_PREFIX.get(major)
    except (ValueError, IndexError): pass
    index = _adb_get_index(os_type)
    pfx = os_type + ";"
    candidates = [k[len(pfx):] for k in index
                  if k.startswith(pfx) and "sim" not in k and "SDK" not in k
                  and (not build_prefix or k[len(pfx):].startswith(build_prefix))]
    if not candidates: return []
    matched = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_adb_fetch_entry, os_type, bid): bid for bid in candidates}
        for future in as_completed(futures):
            bid = futures[future]; entry = future.result()
            if entry is None: continue
            v = entry.get("version","")
            if not (v == version or v.startswith(version+" ") or v.startswith(version+".")): continue
            dev_map = entry.get("deviceMap",[])
            if identifier and dev_map and identifier not in dev_map: continue
            matched.append((bid, entry))
    matched.sort(key=lambda t: t[0], reverse=True)
    _save_cache(cache_key, matched)
    return [AppleDBFirmware(bid, entry, identifier) for bid, entry in matched]

def adb_get_latest(version: str, identifier: str = "") -> Optional[AppleDBFirmware]:
    results = adb_search_by_version(version, identifier=identifier)
    return results[0] if results else None


# ═════════════════════════════════════════════════════════════════════════════
# TSS CHECK LOGIC
# ═════════════════════════════════════════════════════════════════════════════

def parse_ecid(ecid_str: str) -> int:
    s = ecid_str.strip()
    if s.lower().startswith("0x"): return int(s, 16)
    if any(c in s.upper() for c in "ABCDEF"): return int(s, 16)
    return int(s)


@dataclasses.dataclass
class CheckArgs:
    device:              str            = ""
    boardconfig:         str            = ""
    ios:                 str            = ""
    buildid:             str            = ""
    build_manifest:      str            = ""
    latest:              bool           = False
    ota:                 bool           = False
    beta:                bool           = False
    url:                 str            = ""
    ecid:                str            = ""
    generator:           str            = ""
    apnonce:             str            = ""
    sepnonce:            str            = ""
    baseband:            int            = 0
    no_baseband:         bool           = False
    bbsnum:              str            = ""
    save:                Optional[str]  = None
    print_tss_request:   bool           = False
    print_tss_response:  bool           = False
    update_install:      bool           = False
    variant:             str            = ""
    components:          str            = ""
    verbose:             bool           = False


def _do_check(args: CheckArgs, device, firmware_url: str, fw_version: str,
              fw_buildid: str, manifest_data: dict, ecid: int,
              apnonce: bytes, sepnonce: bytes, fw_signed=None) -> Optional[bool]:
    """Core TSS check. Returns True/False/None (None = attested, firmware signed but no blob)."""
    cpid = device.cpid if device else 0
    bdid = device.bdid if device else 0
    boardconfig = device.boardconfig if device else None
    restore_type = "Update" if args.update_install else "Erase"
    variant = args.variant or None

    identity = None
    if cpid and bdid:
        identity = mf_find_identity(manifest_data, cpid, bdid,
                                    boardconfig=boardconfig, restore_type=restore_type,
                                    variant=variant, ota=args.ota)
    if identity is None and boardconfig:
        identity = mf_find_identity_by_board(manifest_data, boardconfig,
                                             restore_type=restore_type, variant=variant, ota=args.ota)
    if identity is None:
        identities = manifest_data.get("BuildIdentities", [])
        if identities:
            identity = identities[0]
            if args.verbose: print("[!] Could not match exact identity — using first available")
        else:
            print("[ERROR] No BuildIdentities found in manifest")
            return False

    if not cpid: cpid = mf_get_cpid(identity)
    if not bdid: bdid = mf_get_bdid(identity)

    img4       = _dev_is_img4(cpid) if cpid else True
    nonce_kind = _dev_nonce_type(cpid) if cpid else NONCE_SHA384
    attest_mode = mf_get_attest_mode(identity)
    needs_hw_attest = (attest_mode >= 4)
    wants_save = (args.save is not None and ecid != 0)

    if needs_hw_attest and wants_save:
        print(f"[!] RestoreAttestationMode={attest_mode}: blob saving requires "
              f"hardware SE attestation (A17 Pro+).")

    if not apnonce:
        if args.generator:
            apnonce = tss_generator_to_nonce(args.generator, nonce_kind)
        else:
            apnonce = tss_random_nonce(nonce_kind)
    if not sepnonce and img4:
        sepnonce = secrets.token_bytes(20)

    baseband_mode = args.baseband
    if args.no_baseband: baseband_mode = 1

    req = TSSRequest(cpid=cpid, bdid=bdid, ecid=ecid)
    req.set_nonce(apnonce, sepnonce)
    req.set_img4(img4)
    ubid = identity.get("UniqueBuildID")
    if isinstance(ubid, bytes): req.set_unique_build_id(ubid)

    skip_bb_for_anon = (ecid == 0)
    if baseband_mode != 2:
        comps = mf_extract_ap_components(
            identity, img4=img4,
            skip_baseband=(baseband_mode==1 or skip_bb_for_anon),
            requested_components=(args.components.split(",") if args.components else None),
        )
        req.add_ap_components(comps)

    if baseband_mode != 1 and not skip_bb_for_anon and img4:
        bb_comps = mf_extract_baseband_components(identity, img4=img4)
        if bb_comps:
            bb_info = dev_get_baseband_info(device.identifier) if device else None
            if bb_info:
                bbgcid, snum_len = bb_info
                bbsnum = tss_parse_hex_bytes(args.bbsnum) if args.bbsnum else secrets.token_bytes(snum_len)
                req.add_baseband_components(bb_comps, bbgcid=bbgcid, bbsnum=bbsnum)

    for copro in mf_get_copro_info(identity):
        copro_comps = mf_extract_copro_components(identity, copro["prefix"], img4=img4)
        if copro_comps:
            if args.verbose:
                print(f"[i] Adding {copro['prefix']} co-processor ticket")
            req.add_copro_ticket(copro_comps, prefix=copro["prefix"],
                                 chip_id=copro["chip_id"], board_id=copro["board_id"],
                                 ecid=ecid, nonce=secrets.token_bytes(20))

    if args.print_tss_request:
        print(req.build_xml().decode("utf-8"))
        return True

    treat_69 = needs_hw_attest and not wants_save
    signed, response = req.send(verbose=args.verbose, treat_69_as_signed=treat_69)

    if not response and fw_signed is not None:
        if args.verbose: print("[i] TSS unreachable; falling back to cached signing status.")
        return fw_signed

    if args.print_tss_response: print(response)

    if wants_save and needs_hw_attest and not signed and "STATUS=69" in response:
        return None

    if signed:
        blob = tss_extract_shsh_blob(response)
        if args.save is not None and blob:
            save_dir = args.save or "."
            os.makedirs(save_dir, exist_ok=True)
            filename = tss_shsh2_filename(
                device.identifier if device else "unknown",
                ecid, fw_version, fw_buildid, apnonce)
            path = os.path.join(save_dir, filename)
            if isinstance(blob, dict):
                with open(path, "wb") as f: plistlib.dump(blob, f)
            else:
                with open(path, "wb") as f: f.write(blob if isinstance(blob, bytes) else blob.encode())
            print(f"[+] Saved blob → {path}")

    return signed


def run_check(args: CheckArgs) -> int:
    """Full pipeline: device → firmware → manifest → TSS → print results. Returns exit code."""
    ecid = 0
    if args.ecid:
        try:    ecid = parse_ecid(args.ecid)
        except: print(f"[ERROR] Invalid ECID: {args.ecid}"); return 1

    apnonce:  bytes = b""
    sepnonce: bytes = b""
    if args.apnonce:
        try:    apnonce  = tss_parse_hex_bytes(args.apnonce)
        except: print(f"[ERROR] Invalid apnonce hex: {args.apnonce}"); return 1
    if args.sepnonce:
        try:    sepnonce = tss_parse_hex_bytes(args.sepnonce)
        except: print(f"[ERROR] Invalid sepnonce hex: {args.sepnonce}"); return 1

    device = None
    if args.device:
        print(f"[i] Looking up device {args.device}…")
        device = dev_get(args.device, no_cache=False)
        if device is None:
            print(f"[ERROR] Unknown device: {args.device}"); return 1
    elif args.boardconfig:
        device = dev_get_by_board(args.boardconfig, no_cache=False)
        if device is None:
            print(f"[ERROR] No device for board config: {args.boardconfig}"); return 1
    elif not args.build_manifest:
        print("[ERROR] Specify a device with -d or board config"); return 1

    manifest_data  = None
    fw_version     = ""
    fw_buildid     = ""
    firmware_url   = ""
    fw_signed_ipsw = None

    if args.build_manifest:
        try:
            manifest_data = mf_load(args.build_manifest)
            fw_version    = mf_get_product_version(manifest_data)
            fw_buildid    = mf_get_build_version(manifest_data)
        except Exception as exc:
            print(f"[ERROR] Could not load BuildManifest: {exc}"); return 1

    elif args.url:
        firmware_url = args.url
        print(f"[i] Fetching BuildManifest from provided URL…")
        try:
            raw = fw_download_manifest(firmware_url)
            manifest_data = plistlib.loads(raw)
            fw_version = mf_get_product_version(manifest_data)
            fw_buildid = mf_get_build_version(manifest_data)
        except Exception as exc:
            print(f"[ERROR] Could not fetch BuildManifest from URL: {exc}"); return 1
        if device and fw_version:
            try:
                fw_meta = fw_get_by_version(device.identifier, fw_version, ota=args.ota)
                if fw_meta: fw_signed_ipsw = fw_meta.signed
            except Exception: pass
        if device:
            print(f"[i] Firmware: {fw_version} ({fw_buildid}) for {device.identifier} ({device.name})")

    else:
        if not device:
            print("[ERROR] Device must be specified"); return 1
        identifier = device.identifier
        use_ota = args.ota or args.beta
        fw = None

        if args.latest:
            print(f"[i] Fetching latest firmware for {identifier}…")
            fw = fw_get_latest(identifier, ota=use_ota)
        elif args.ios:
            fw = fw_get_by_version(identifier, args.ios, ota=use_ota)
            if fw is None and args.beta:
                fw = fw_get_by_version(identifier, args.ios, ota=True)
        elif args.buildid:
            fw = fw_get_by_buildid(identifier, args.buildid, ota=use_ota)
            if fw is None and args.beta:
                fw = fw_get_by_buildid(identifier, args.buildid, ota=True)
        else:
            print("[ERROR] Specify a firmware version, build ID, or use Latest"); return 1

        if fw is None:
            if not args.beta:
                print(f"[ERROR] Firmware not found for {identifier} "
                      f"version={args.ios or ''} build={args.buildid or ''} "
                      f"(try beta or provide a direct URL)")
                return 1
            print("[i] Searching appledb.dev for beta firmware…")
            try:
                afw = adb_get_by_buildid(args.buildid, identifier) if args.buildid else \
                      adb_get_latest(args.ios, identifier) if args.ios else None
            except Exception as exc:
                print(f"[ERROR] appledb.dev lookup failed: {exc}"); return 1
            if afw is None:
                print(f"[ERROR] Firmware not found in IPSW.me or appledb.dev"); return 1
            fw_version = afw.version; fw_buildid = afw.buildid; fw_signed_ipsw = afw.signed
            beta_note = " [beta]" if afw.beta else ""
            print(f"[i] Firmware: {fw_version} ({fw_buildid}){beta_note} "
                  f"for {identifier} ({device.name}) [appledb.dev]")
            if afw.url_type == "ipsw":
                firmware_url = afw.url
                print(f"[i] Fetching BuildManifest from beta IPSW…")
                try:
                    manifest_data = plistlib.loads(fw_download_manifest(firmware_url))
                except Exception as exc:
                    print(f"[ERROR] Could not fetch BuildManifest: {exc}"); return 1
            elif afw.url and not afw.url.lower().endswith(".aea"):
                print(f"[i] OTA source is .zip — fetching BuildManifest…")
                try:
                    manifest_data = plistlib.loads(fw_download_manifest(afw.url))
                    firmware_url = afw.url
                except Exception:
                    print(f"[i] Falling back to appledb.dev signing status.")
                    result = afw.signed
                    if result: print(f"\n[+] {fw_version} ({fw_buildid}) IS being signed for {identifier} ✓")
                    else:      print(f"\n[-] {fw_version} ({fw_buildid}) is NOT being signed for {identifier} ✗")
                    return 0 if result else 1
            else:
                print(f"[i] OTA-only{beta_note}: reporting appledb.dev signing status.")
                result = afw.signed
                if result: print(f"\n[+] {fw_version} ({fw_buildid}) IS being signed for {identifier} ✓")
                else:      print(f"\n[-] {fw_version} ({fw_buildid}) is NOT being signed for {identifier} ✗")
                return 0 if result else 1
        else:
            fw_version = fw.version; fw_buildid = fw.buildid
            firmware_url = fw.url;  fw_signed_ipsw = fw.signed
            print(f"[i] Firmware: {fw_version} ({fw_buildid}) for {identifier} ({device.name})")
            print(f"[i] Fetching BuildManifest… (no full IPSW download)")
            try:
                manifest_data = plistlib.loads(fw_download_manifest(firmware_url))
            except Exception as exc:
                print(f"[ERROR] Could not fetch BuildManifest: {exc}"); return 1

    print(f"[i] Sending TSS request to Apple…")
    signed = _do_check(
        args=args, device=device, firmware_url=firmware_url,
        fw_version=fw_version, fw_buildid=fw_buildid,
        manifest_data=manifest_data, ecid=ecid,
        apnonce=apnonce, sepnonce=sepnonce, fw_signed=fw_signed_ipsw,
    )
    dev_id = device.identifier if device else "device"
    if signed:
        print(f"\n[+] {fw_version} ({fw_buildid}) IS being signed for {dev_id} ✓")
        return 0
    elif signed is None:
        print(f"\n[!] {fw_version} ({fw_buildid}) IS being signed for {dev_id}, "
              f"but blob requires hardware SE attestation (A17 Pro+).")
        return 2
    else:
        print(f"\n[-] {fw_version} ({fw_buildid}) is NOT being signed for {dev_id} ✗")
        return 1


def run_list_versions(identifier: str, beta: bool = False, ota: bool = False) -> int:
    use_ota = ota or beta
    try:
        fws = fw_get_all(identifier, ota=use_ota)
        if beta and not ota:
            ota_fws = fw_get_all(identifier, ota=True)
            seen = {f.buildid for f in fws}
            for f in ota_fws:
                if f.buildid not in seen: fws.append(f)
    except Exception as exc:
        print(f"[ERROR] Could not fetch firmware list: {exc}"); return 1
    if not fws:
        print(f"No firmware versions found for {identifier}"); return 0
    kind = "OTA/beta" if use_ota else "IPSW"
    print(f"Firmware versions for {identifier} [{kind}]:")
    for fw in sorted(fws, key=lambda f: f.version):
        signed = "[SIGNED]   " if fw.signed else "[unsigned] "
        print(f"  {signed}  {fw.version}  ({fw.buildid})")
    return 0


def run_list_devices() -> int:
    print("Fetching device list…")
    try:
        all_devs = dev_get_all()
    except Exception as exc:
        print(f"[ERROR] {exc}"); return 1
    groups: Dict[str,list] = {}
    for d in all_devs:
        prefix = "".join(c for c in d.identifier if c.isalpha())
        groups.setdefault(prefix, []).append(d)
    order = ["iPhone","iPad","iPod","AppleTV","Watch","AudioAccessory","RealityDevice",""]
    shown: set = set()
    for prefix in order:
        if prefix not in groups: continue
        shown.add(prefix)
        for d in sorted(groups[prefix], key=lambda x: x.identifier):
            board = f" [{d.boardconfig}]" if d.boardconfig else ""
            print(f"  {d.identifier:<22}  {d.name}{board}")
    for prefix, devs in groups.items():
        if prefix in shown: continue
        for d in sorted(devs, key=lambda x: x.identifier):
            board = f" [{d.boardconfig}]" if d.boardconfig else ""
            print(f"  {d.identifier:<22}  {d.name}{board}")
    return 0


# ═════════════════════════════════════════════════════════════════════════════
# GUI
# ═════════════════════════════════════════════════════════════════════════════

# ── Apple design tokens ───────────────────────────────────────────────────────
BG             = "#fbfbfd"
SURFACE        = "#ffffff"
SURFACE_RAISED = "#f5f5f7"
BORDER         = "#d2d2d7"
BORDER_LIGHT   = "#e8e8ed"
TEXT1          = "#1d1d1f"
TEXT2          = "#6e6e73"
TEXT3          = "#86868b"
BLUE           = "#0071e3"
BLUE_DARK      = "#0064cc"
GREEN          = "#1a7f37"
GREEN_DARK     = "#166d30"
RED            = "#c1121f"
ORANGE         = "#b45309"

if sys.platform == "darwin":
    UI = ""; MONO = "Menlo"
elif sys.platform == "win32":
    UI = "Segoe UI"; MONO = "Consolas"
else:
    UI = "DejaVu Sans"; MONO = "DejaVu Sans Mono"

def F(size, bold=False, mono=False):
    return (MONO if mono else UI, size, "bold" if bold else "normal")


# ── Cross-platform colored button (Frame+Label — bypasses macOS native rendering)
def _Btn(parent, text, cmd, bg=SURFACE_RAISED, fg=TEXT1, bold=False, padx=16, pady=8):
    _DARK = {BLUE: BLUE_DARK, GREEN: GREEN_DARK, BG: SURFACE_RAISED, SURFACE_RAISED: BORDER}
    dark = _DARK.get(bg, bg)
    f = tk.Frame(parent, bg=bg, cursor="hand2")
    lbl = tk.Label(f, text=text, bg=bg, fg=fg, font=F(13, bold=bold), padx=padx, pady=pady)
    lbl.pack()
    def _enter(e): f.config(bg=dark);  lbl.config(bg=dark)
    def _leave(e): f.config(bg=bg);    lbl.config(bg=bg)
    def _click(e): cmd()
    for w in (f, lbl):
        w.bind("<Enter>",    _enter)
        w.bind("<Leave>",    _leave)
        w.bind("<Button-1>", _click)
    return f


def _rule(parent, color=BORDER_LIGHT, padx=0, pady=8):
    tk.Frame(parent, bg=color, height=1).pack(fill="x", padx=padx, pady=pady)


def _card(parent, pady_bottom=12):
    wrap  = tk.Frame(parent, bg=BORDER_LIGHT)
    wrap.pack(fill="x", pady=(0, pady_bottom))
    inner = tk.Frame(wrap, bg=SURFACE)
    inner.pack(fill="x", padx=1, pady=1)
    return inner


class _Field(tk.Frame):
    """Labelled flat entry with optional placeholder text."""
    def __init__(self, parent, label, var, hint="", mono=False, placeholder="", **kw):
        super().__init__(parent, bg=SURFACE, **kw)
        self._var = var; self._placeholder = placeholder; self._has_ph = False
        if label:
            tk.Label(self, text=label, font=F(12), bg=SURFACE, fg=TEXT1).pack(anchor="w")
        self.entry = tk.Entry(
            self, textvariable=var, font=F(13, mono=mono),
            bg=SURFACE_RAISED, fg=TEXT1,
            disabledbackground=SURFACE_RAISED, disabledforeground=TEXT3,
            readonlybackground=SURFACE_RAISED,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=BLUE, insertbackground=TEXT1,
        )
        self.entry.pack(fill="x", ipady=6, ipadx=8, pady=(3,0))
        if hint:
            tk.Label(self, text=hint, font=F(11), bg=SURFACE, fg=TEXT3).pack(anchor="w", pady=(3,0))
        if placeholder:
            self._show_placeholder()
            self.entry.bind("<FocusIn>",  self._on_focus_in)
            self.entry.bind("<FocusOut>", self._on_focus_out)

    def _show_placeholder(self):
        self.entry.delete(0,"end"); self.entry.insert(0, self._placeholder)
        self.entry.config(fg=TEXT3); self._has_ph = True

    def _on_focus_in(self, _):
        if self._has_ph: self.entry.delete(0,"end"); self.entry.config(fg=TEXT1); self._has_ph = False

    def _on_focus_out(self, _):
        if not self.entry.get(): self._show_placeholder()

    def get(self):
        return "" if self._has_ph else self._var.get().strip()


# ── Queue writer: routes print() to the GUI output queue ─────────────────────
class _QueueWriter:
    def __init__(self, q: queue.Queue):
        self._q = q; self._buf = ""
    def write(self, text: str):
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            self._q.put(line + "\n")
    def flush(self):
        if self._buf: self._q.put(self._buf); self._buf = ""
    def isatty(self): return False


# ── Main window ───────────────────────────────────────────────────────────────
class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("TSS Checker")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(640, 780)
        self.geometry("760x980")
        self._running = False
        self._out_queue: queue.Queue = queue.Queue()
        self._build()
        self._poll_queue()

    # ── Layout ───────────────────────────────────────────────────────────────

    def _build(self):
        self._build_header()
        self._build_form()
        self._build_buttons()
        self._build_output()

    def _build_header(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=24, pady=(24,0))
        tk.Label(hdr, text="TSS Checker",
                 font=F(22, bold=True), bg=BG, fg=TEXT1).pack(anchor="w")
        tk.Label(hdr, text="Check Apple signing status  ·  Save SHSH2 blobs",
                 font=F(13), bg=BG, fg=TEXT2).pack(anchor="w", pady=(2,0))
        _rule(self, padx=24, pady=(14,0))

    def _build_form(self):
        wrap = tk.Frame(self, bg=BG)
        wrap.pack(fill="x", padx=24, pady=(14,0))

        # ── Device ───────────────────────────────────────────────────────────
        tk.Label(wrap, text="DEVICE", font=F(10), bg=BG, fg=TEXT3).pack(anchor="w", pady=(0,5))
        dev_pad = tk.Frame(_card(wrap), bg=SURFACE)
        dev_pad.pack(fill="x", padx=16, pady=14)

        self.device_var = tk.StringVar()
        self._device_field = _Field(
            dev_pad, "Identifier", self.device_var,
            hint='e.g. iPhone14,2 · iPad13,8 · Watch7,3 · AppleTV14,1',
            placeholder="iPhone14,2",
        )
        self._device_field.pack(fill="x")

        # ── Firmware ─────────────────────────────────────────────────────────
        tk.Label(wrap, text="FIRMWARE", font=F(10), bg=BG, fg=TEXT3).pack(anchor="w", pady=(8,5))
        fw_pad = tk.Frame(_card(wrap), bg=SURFACE)
        fw_pad.pack(fill="x", padx=16, pady=14)

        self.fw_mode = tk.StringVar(value="latest")
        radio_row = tk.Frame(fw_pad, bg=SURFACE)
        radio_row.pack(fill="x", pady=(0,8))
        for label, val in [("Latest","latest"),("By Version","version"),("By Build ID","build")]:
            tk.Radiobutton(
                radio_row, text=label, variable=self.fw_mode, value=val,
                font=F(13), bg=SURFACE, fg=TEXT1, selectcolor=SURFACE,
                activebackground=SURFACE, activeforeground=TEXT1,
                command=self._fw_mode_changed,
            ).pack(side="left", padx=(0,18))

        self.fw_val_var = tk.StringVar()
        self._fw_entry = tk.Entry(
            fw_pad, textvariable=self.fw_val_var,
            font=F(13), bg=SURFACE_RAISED, fg=TEXT3,
            disabledbackground=SURFACE_RAISED, disabledforeground=TEXT3,
            readonlybackground=SURFACE_RAISED,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=BLUE,
            insertbackground=TEXT1, state="disabled",
        )
        self._fw_entry.pack(fill="x", ipady=6, ipadx=8)
        self._fw_entry.insert(0, "Select Latest above, or choose By Version / By Build ID")

        self._fw_hint = tk.Label(fw_pad, text="", font=F(11), bg=SURFACE, fg=TEXT3)
        self._fw_hint.pack(anchor="w", pady=(3,0))

        _rule(fw_pad, pady=10)
        opt_row = tk.Frame(fw_pad, bg=SURFACE)
        opt_row.pack(fill="x")
        self.beta_var = tk.BooleanVar()
        self.ota_var  = tk.BooleanVar()
        for label, var in [("Include betas", self.beta_var), ("OTA only", self.ota_var)]:
            tk.Checkbutton(
                opt_row, text=label, variable=var,
                font=F(12), bg=SURFACE, fg=TEXT2, selectcolor=SURFACE,
                activebackground=SURFACE, activeforeground=TEXT1,
            ).pack(side="left", padx=(0,20))

        # ── Blob saving ──────────────────────────────────────────────────────
        tk.Label(wrap, text="BLOB SAVING  (optional — leave blank to just check signing)",
                 font=F(10), bg=BG, fg=TEXT3).pack(anchor="w", pady=(8,5))
        blob_pad = tk.Frame(_card(wrap, pady_bottom=0), bg=SURFACE)
        blob_pad.pack(fill="x", padx=16, pady=14)

        self.ecid_var = tk.StringVar()
        self._ecid_field = _Field(
            blob_pad, "ECID", self.ecid_var, mono=True,
            hint="Found in iTunes or Finder · 0x hex, plain hex, or decimal",
            placeholder="e.g. 0xAABBCCDDEEFF0011",
        )
        self._ecid_field.pack(fill="x")

        _rule(blob_pad, pady=10)
        self.gen_var = tk.StringVar()
        self._gen_field = _Field(
            blob_pad, "Generator  (A9 and older — makes blobs reusable with futurerestore)",
            self.gen_var, mono=True, placeholder="e.g. 0x1111111111111111",
        )
        self._gen_field.pack(fill="x")

        _rule(blob_pad, pady=10)
        tk.Label(blob_pad, text="Save blobs to", font=F(12), bg=SURFACE, fg=TEXT1).pack(anchor="w")
        save_row = tk.Frame(blob_pad, bg=SURFACE)
        save_row.pack(fill="x", pady=(3,0))
        self.save_var = tk.StringVar()
        tk.Entry(
            save_row, textvariable=self.save_var,
            font=F(13, mono=True), bg=SURFACE_RAISED, fg=TEXT3,
            disabledbackground=SURFACE_RAISED, readonlybackground=SURFACE_RAISED,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=BLUE, insertbackground=TEXT1,
        ).pack(side="left", fill="x", expand=True, ipady=6, ipadx=8)
        _Btn(save_row, "Browse…", self._browse_dir,
             bg=SURFACE_RAISED, fg=TEXT1, padx=12, pady=6).pack(side="left", padx=(8,0))

    def _build_buttons(self):
        row = tk.Frame(self, bg=BG)
        row.pack(fill="x", padx=24, pady=16)

        _Btn(row, "Check Signing",  self._do_check,         bg=BLUE,           fg="white", bold=True).pack(side="left", padx=(0,8))
        _Btn(row, "Save Blob",      self._do_save,          bg=GREEN,          fg="white", bold=True).pack(side="left", padx=(0,16))
        _Btn(row, "List Versions",  self._do_list_versions, bg=BG,             fg=BLUE,    padx=8, pady=8).pack(side="left", padx=(0,4))
        _Btn(row, "All Devices",    self._do_list_devices,  bg=BG,             fg=BLUE,    padx=8, pady=8).pack(side="left", padx=(0,4))

    def _build_output(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", padx=24, pady=(0,5))
        tk.Label(hdr, text="OUTPUT", font=F(10), bg=BG, fg=TEXT3).pack(side="left")
        self._status = tk.Label(hdr, text="", font=F(12), bg=BG, fg=TEXT2)
        self._status.pack(side="left", padx=(10,0))
        _Btn(hdr, "Clear", self._clear, bg=BG, fg=TEXT2, padx=6, pady=0).pack(side="right")

        wrap = tk.Frame(self, bg=BORDER_LIGHT)
        wrap.pack(fill="both", expand=True, padx=24, pady=(0,24))
        inner = tk.Frame(wrap, bg=SURFACE)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        sb = tk.Scrollbar(inner, bg=SURFACE_RAISED)
        sb.pack(side="right", fill="y")
        self._out = tk.Text(
            inner, font=F(12, mono=True), bg=SURFACE, fg=TEXT1,
            relief="flat", bd=10, wrap="word", state="disabled",
            selectbackground=SURFACE_RAISED, yscrollcommand=sb.set,
        )
        self._out.pack(fill="both", expand=True)
        sb.config(command=self._out.yview)
        self._out.tag_config("signed",   foreground=GREEN,  font=F(12, bold=True, mono=True))
        self._out.tag_config("unsigned", foreground=RED,    font=F(12, bold=True, mono=True))
        self._out.tag_config("info",     foreground=BLUE)
        self._out.tag_config("warn",     foreground=ORANGE)
        self._out.tag_config("dim",      foreground=TEXT3,  font=F(11, mono=True))
        self._out.tag_config("tbl",      foreground=TEXT2,  font=F(11, mono=True))

    # ── Queue polling (drains output from worker thread) ─────────────────────

    def _poll_queue(self):
        try:
            while True:
                line = self._out_queue.get_nowait()
                self._append_colored(line)
        except queue.Empty:
            pass
        self.after(50, self._poll_queue)

    # ── Firmware mode toggle ──────────────────────────────────────────────────

    def _fw_mode_changed(self):
        mode = self.fw_mode.get()
        if mode == "latest":
            self._fw_entry.config(state="disabled", fg=TEXT3)
            self._fw_entry.delete(0,"end")
            self._fw_entry.insert(0,"Select Latest above, or choose By Version / By Build ID")
            self._fw_hint.config(text="")
        else:
            self._fw_entry.config(state="normal", fg=TEXT1)
            self._fw_entry.delete(0,"end")
            self._fw_hint.config(text="e.g. 17.5.1 · 18.3.2" if mode=="version" else "e.g. 21F90 · 22D82")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _browse_dir(self):
        d = filedialog.askdirectory(title="Select folder to save SHSH2 blobs")
        if d: self.save_var.set(d)

    def _get_device(self) -> Optional[str]:
        v = self._device_field.get()
        if not v:
            messagebox.showerror("Device Required",
                "Enter a device identifier (e.g. iPhone14,2).\n\n"
                "Click  All Devices  to browse every supported identifier.")
            return None
        return v

    def _build_args(self, for_save: bool = False) -> Optional[CheckArgs]:
        device = self._get_device()
        if not device: return None

        args = CheckArgs(device=device, beta=self.beta_var.get(), ota=self.ota_var.get())

        mode = self.fw_mode.get()
        if mode == "latest":
            args.latest = True
        elif mode == "version":
            v = self.fw_val_var.get().strip()
            if not v: messagebox.showerror("Version Required","Enter a version, e.g. 17.5.1"); return None
            args.ios = v
        else:
            b = self.fw_val_var.get().strip()
            if not b: messagebox.showerror("Build ID Required","Enter a build ID, e.g. 21F90"); return None
            args.buildid = b

        if for_save:
            ecid = self._ecid_field.get()
            if not ecid:
                messagebox.showerror("ECID Required",
                    "An ECID is required to save a blob.\n\n"
                    "Where to find it:\n"
                    "  • Connect your device to Mac/PC\n"
                    "  • Open iTunes or Finder, click your device\n"
                    "  • Click the serial number — it cycles to ECID\n\n"
                    "Formats: 0xAABBCCDDEEFF0011  ·  AABBCCDDEEFF0011  ·  decimal")
                return None
            args.ecid = ecid
            gen = self._gen_field.get()
            if gen: args.generator = gen
            save_dir = self.save_var.get().strip() or "."
            args.save = save_dir

        return args

    # ── Actions ──────────────────────────────────────────────────────────────

    def _do_check(self):
        args = self._build_args(for_save=False)
        if args: self._run(lambda: run_check(args))

    def _do_save(self):
        args = self._build_args(for_save=True)
        if args: self._run(lambda: run_check(args))

    def _do_list_versions(self):
        device = self._get_device()
        if device:
            self._run(lambda: run_list_versions(device, beta=self.beta_var.get(), ota=self.ota_var.get()))

    def _do_list_devices(self):
        self._run(run_list_devices)

    # ── Runner (non-blocking, redirects stdout to output widget) ─────────────

    def _run(self, fn):
        if self._running: return
        self._running = True
        self._clear()
        self._set_status("Running…", TEXT2)

        def worker():
            writer = _QueueWriter(self._out_queue)
            try:
                with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
                    rc = fn()
                ok = (rc == 0)
            except Exception as exc:
                writer.write(f"\n[ERROR] {exc}\n")
                writer.flush()
                ok = False
            finally:
                self._running = False
                colour = GREEN if ok else TEXT2
                self.after(0, lambda: self._set_status("Done", colour))

        threading.Thread(target=worker, daemon=True).start()

    # ── Output helpers ────────────────────────────────────────────────────────

    def _append_colored(self, line: str):
        s = line.rstrip()
        lo = s.lower()
        if "[+]" in s or "✓" in s or "is being signed" in lo:
            tag = "signed"
        elif "[-]" in s or "✗" in s or "not being signed" in lo:
            tag = "unsigned"
        elif "[error]" in lo or s.startswith("Error"):
            tag = "unsigned"
        elif "[!]" in s or "warn" in lo or "attestation" in lo:
            tag = "warn"
        elif "[i]" in s:
            tag = "info"
        elif any(c in s for c in "┌┬┐├┼┤└┴┘│─"):
            tag = "tbl"
        else:
            tag = None
        self._out.config(state="normal")
        self._out.insert("end", line, tag or "")
        self._out.see("end")
        self._out.config(state="disabled")

    def _append(self, text: str, tag=None):
        self._out.config(state="normal")
        self._out.insert("end", text, tag or "")
        self._out.see("end")
        self._out.config(state="disabled")

    def _clear(self):
        self._out.config(state="normal")
        self._out.delete("1.0","end")
        self._out.config(state="disabled")
        self._set_status("", TEXT2)

    def _set_status(self, text: str, colour=TEXT2):
        self.after(0, lambda: self._status.config(text=text, fg=colour))


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
