"""
Device database backed by the IPSW.me v4 API with local disk cache.

Provides:
  - Device identifier → CPID / BDID / boardconfig
  - Board config → device identifier
  - Nonce type per CPID (none / sha1 / sha256 / sha384)
  - Static baseband table (BBGCID + SNUM length)
"""

import os
import json
import time
import requests
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List

IPSW_ME_BASE = "https://api.ipsw.me/v4"
CACHE_DIR = Path(os.path.expanduser("~/.cache/tsschecker"))
CACHE_TTL = 86400 * 7  # 7 days

# ---------------------------------------------------------------------------
# Nonce type mapping by Apple chip ID (CPID)
# ---------------------------------------------------------------------------
NONCE_NONE   = "none"
NONCE_SHA1   = "sha1"    # 20 bytes  – A5..A9 / some older chips
NONCE_SHA256 = "sha256"  # 32 bytes  – A17 Pro+ (0x8130 and up)
NONCE_SHA384 = "sha384"  # 48 bytes  – A10..A16 (0x8010..0x8120)

_CPID_NO_NONCE: set = {0x8900, 0x8720}
_CPID_SHA1: set = {
    0x8920, 0x8922, 0x8930, 0x8940, 0x8942, 0x8945, 0x8947,
    0x8950, 0x8955, 0x8960, 0x7000, 0x7001, 0x7002, 0x8000, 0x8003,
}
# A17 Pro (0x8130), A18 Pro (0x8140), A19 Pro (0x8150) — confirmed 32-byte nonces
# from real irecovery output: NONC is 64 hex chars = 32 bytes on these chips.
_CPID_SHA256: set = {0x8130, 0x8140, 0x8150}
# Everything else (0x8010..0x8120) → sha384

# IMG3 chips: pre-A7 (A4, A5, A5X, A6, A6X and older)
# IMG4 chips: A7 (0x8960) and everything newer
_CPID_IMG3: set = {
    0x8900, 0x8720,  # very old, no nonce
    0x8920, 0x8922,  # A4
    0x8930,          # A5
    0x8940, 0x8942, 0x8945, 0x8947,  # A5 variants / A5X
    0x8950,          # A6
    0x8955,          # A6X
}

# ---------------------------------------------------------------------------
# Baseband static table  { identifier: (bbgcid, snum_len) }
# ---------------------------------------------------------------------------
BASEBAND_DB = {
    # iPhones with Qualcomm/Intel baseband
    "iPhone4,1":  (257801984,  20),  # 4S
    "iPhone5,1":  (2315222105, 20),  # 5  (GSM)
    "iPhone5,2":  (2315222105, 20),  # 5  (CDMA)
    "iPhone5,3":  (3554432823, 20),  # 5c (GSM)
    "iPhone5,4":  (3554432823, 20),  # 5c (CDMA)
    "iPhone6,1":  (3554432823, 20),  # 5s (GSM)
    "iPhone6,2":  (3554432823, 20),  # 5s (CDMA)
    "iPhone7,1":  (3840776546, 16),  # 6 Plus
    "iPhone7,2":  (3840776546, 16),  # 6
    "iPhone8,1":  (3840776546, 16),  # 6s
    "iPhone8,2":  (3840776546, 16),  # 6s Plus
    "iPhone8,4":  (3840776546, 16),  # SE (1st gen)
    "iPhone9,1":  (3840776546, 16),  # 7
    "iPhone9,2":  (3840776546, 16),  # 7 Plus
    "iPhone9,3":  (3840776546, 16),  # 7
    "iPhone9,4":  (3840776546, 16),  # 7 Plus
    "iPhone10,1": (3840776546, 16),  # 8
    "iPhone10,2": (3840776546, 16),  # 8 Plus
    "iPhone10,3": (3840776546, 16),  # X
    "iPhone10,4": (3840776546, 16),  # 8
    "iPhone10,5": (3840776546, 16),  # 8 Plus
    "iPhone10,6": (3840776546, 16),  # X
    # Cellular iPads
    "iPad2,2":  (2315222105, 20),
    "iPad2,3":  (2315222105, 20),
    "iPad2,6":  (2315222105, 20),
    "iPad2,7":  (2315222105, 20),
    "iPad3,2":  (2315222105, 20),
    "iPad3,3":  (2315222105, 20),
    "iPad3,5":  (3554432823, 20),
    "iPad3,6":  (3554432823, 20),
    "iPad4,2":  (3554432823, 20),
    "iPad4,3":  (3554432823, 20),
    "iPad4,5":  (3554432823, 20),
    "iPad4,6":  (3554432823, 20),
    "iPad4,8":  (3554432823, 20),
    "iPad4,9":  (3554432823, 20),
    "iPad5,2":  (3840776546, 16),
    "iPad5,4":  (3840776546, 16),
    "iPad6,4":  (3840776546, 16),
    "iPad6,8":  (3840776546, 16),
    "iPad7,2":  (3840776546, 16),
    "iPad7,4":  (3840776546, 16),
}


@dataclass
class Device:
    identifier: str
    name: str
    boardconfig: str
    cpid: int = 0
    bdid: int = 0
    platform: str = ""


# ---------------------------------------------------------------------------
# Internal cache helpers
# ---------------------------------------------------------------------------

def _cache_path(key: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{key}.json"


def _load_cache(key: str):
    p = _cache_path(key)
    if p.exists():
        try:
            data = json.loads(p.read_text())
            if time.time() - data.get("ts", 0) < CACHE_TTL:
                return data.get("v")
        except Exception:
            pass
    return None


def _save_cache(key: str, value) -> None:
    _cache_path(key).write_text(json.dumps({"ts": time.time(), "v": value}))


def _device_from_dict(d: dict) -> Device:
    # IPSW.me returns cpid/bdid as ints; older API versions may omit them
    cpid = d.get("cpid") or 0
    bdid = d.get("bdid") or 0
    # Some responses use "board" instead of "boardconfig"
    board = d.get("boardconfig") or d.get("board") or ""
    return Device(
        identifier=d.get("identifier", ""),
        name=d.get("name", ""),
        boardconfig=board,
        cpid=int(cpid),
        bdid=int(bdid),
        platform=d.get("platform", ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def nonce_type(cpid: int) -> str:
    """Return the nonce type for a given chip ID."""
    if cpid in _CPID_NO_NONCE:
        return NONCE_NONE
    if cpid in _CPID_SHA1:
        return NONCE_SHA1
    if cpid in _CPID_SHA256:
        return NONCE_SHA256
    return NONCE_SHA384


def is_img4(cpid: int) -> bool:
    """True if the chip uses the IMG4 signing format (A7 / 0x8960 and newer)."""
    return cpid not in _CPID_IMG3


def get_all_devices(no_cache: bool = False) -> List[Device]:
    """Return all known devices from IPSW.me (cached)."""
    if not no_cache:
        cached = _load_cache("all_devices")
        if cached:
            return [_device_from_dict(d) for d in cached]

    resp = requests.get(f"{IPSW_ME_BASE}/devices", timeout=20)
    resp.raise_for_status()
    raw = resp.json()
    _save_cache("all_devices", raw)
    return [_device_from_dict(d) for d in raw]


def get_device(identifier: str, no_cache: bool = False) -> Optional[Device]:
    """Fetch detailed device info (including CPID/BDID) from IPSW.me."""
    key = f"device_{identifier}"
    if not no_cache:
        cached = _load_cache(key)
        if cached:
            return _device_from_dict(cached)

    try:
        resp = requests.get(f"{IPSW_ME_BASE}/device/{identifier}", timeout=20)
        resp.raise_for_status()
        raw = resp.json()
        _save_cache(key, raw)
        return _device_from_dict(raw)
    except requests.HTTPError:
        return None


def get_device_by_board(boardconfig: str, no_cache: bool = False) -> Optional[Device]:
    """Find a device by its board configuration string (e.g. 'd221ap')."""
    bc = boardconfig.lower()
    for d in get_all_devices(no_cache=no_cache):
        if d.boardconfig.lower() == bc:
            return get_device(d.identifier, no_cache=no_cache)
    return None


def get_baseband_info(identifier: str):
    """Return (bbgcid, snum_len) or None if the device has no external baseband."""
    return BASEBAND_DB.get(identifier)
