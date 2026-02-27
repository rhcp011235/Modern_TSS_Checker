"""
AppleDB API wrapper for beta firmware lookup.

AppleDB (https://appledb.dev) tracks all Apple firmware including betas,
while IPSW.me only tracks public releases.  Used as a fallback when
IPSW.me does not have a firmware version.

Search strategy for version lookups:
  - Each iOS major marketing version maps to a 2-digit build ID prefix
    (e.g. iOS 26.x → "23").  We fetch the build index (36 KB), filter
    to candidates by prefix, then concurrently fetch matching entries.
  - Build IDs (e.g. "23E5207q") can be looked up directly.
"""

import json
import os
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote
from typing import Optional, List

APPLEDB_BASE = "https://api.appledb.dev"
CACHE_DIR = Path(os.path.expanduser("~/.cache/tsschecker"))
CACHE_TTL_INDEX = 3600 * 2   # 2 hours (index changes as new betas land)
CACHE_TTL_ENTRY = 3600 * 4   # 4 hours per build entry


# ---------------------------------------------------------------------------
# OS type detection
# ---------------------------------------------------------------------------

def _os_type_for_identifier(identifier: str) -> str:
    """
    Map a device identifier prefix to the appledb.dev osStr used in index/entry URLs.
    Mirrors the PHP _adb_os_type() function in appledb_api.php.
    """
    if identifier.startswith("RealityDevice"):  return "visionOS"
    if identifier.startswith("AudioAccessory"): return "HomePod Software"
    if identifier.startswith("AppleTV"):        return "tvOS"
    if identifier.startswith("Watch"):          return "watchOS"
    return "iOS"


# Maps iOS major marketing version → 2-digit build-ID prefix.
# The build prefix increments with each internal iOS release regardless of
# the marketing name (iOS jumped from 18 → 26 but the prefix only went 22 → 23).
# Add new entries here when a new iOS major ships.
_IOS_MAJOR_TO_BUILD_PREFIX = {
    15: "19",
    16: "20",
    17: "21",
    18: "22",
    26: "23",
}


# ---------------------------------------------------------------------------
# Public data class
# ---------------------------------------------------------------------------

class AppleDBFirmware:
    """A single firmware entry from appledb.dev."""

    def __init__(self, buildid: str, entry: dict, identifier: str = ""):
        self.buildid:   str  = buildid
        self.version:   str  = entry.get("version", "")
        self.beta:      bool = bool(entry.get("beta", False))
        self.device_map: list = entry.get("deviceMap", [])

        # Signing status — appledb returns bool OR list of device identifiers
        signed_raw = entry.get("signed", False)
        if isinstance(signed_raw, list):
            self.signed = (identifier in signed_raw) if identifier else bool(signed_raw)
        else:
            self.signed = bool(signed_raw)

        # Best download URL for this device (IPSW preferred over OTA)
        self.url:      str = ""
        self.url_type: str = ""   # "ipsw" or "ota"
        self._extract_url(entry.get("sources", []), identifier)

    def _extract_url(self, sources: list, identifier: str) -> None:
        # 1. IPSW source (regular ZIP — FragmentZip can read it)
        for src in sources:
            if src.get("type") != "ipsw":
                continue
            if not self._device_match(src, identifier):
                continue
            url = self._best_link(src.get("links", []))
            if url:
                self.url = url
                self.url_type = "ipsw"
                return

        # 2. Full OTA (no prerequisiteBuild) — .aea (iOS) or .zip (HomePod/tvOS/watchOS)
        for src in sources:
            if src.get("type") != "ota":
                continue
            if src.get("prerequisiteBuild"):
                continue   # skip delta OTAs
            if not self._device_match(src, identifier):
                continue
            url = self._best_link(src.get("links", []))
            if url:
                self.url = url
                self.url_type = "ota"
                return

    @staticmethod
    def _device_match(src: dict, identifier: str) -> bool:
        dev_map = src.get("deviceMap", [])
        return not (identifier and dev_map and identifier not in dev_map)

    @staticmethod
    def _best_link(links: list) -> str:
        if not links:
            return ""
        preferred = next(
            (l for l in links if l.get("preferred") and l.get("active")), None
        )
        active = next((l for l in links if l.get("active")), None)
        link = preferred or active or links[0]
        return link.get("url", "")

    def __repr__(self) -> str:
        signed_str = "SIGNED" if self.signed else "unsigned"
        beta_str   = " [beta]" if self.beta else ""
        return f"<AppleDBFirmware {self.version} ({self.buildid}){beta_str} [{signed_str}]>"


# ---------------------------------------------------------------------------
# Internal cache helpers
# ---------------------------------------------------------------------------

def _cache_path(key: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"appledb_{key}.json"


def _load_cache(key: str, ttl: int = CACHE_TTL_ENTRY):
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


# ---------------------------------------------------------------------------
# Low-level fetchers
# ---------------------------------------------------------------------------

def _fetch_entry(os_type: str, buildid: str) -> Optional[dict]:
    """Fetch one build entry from appledb.dev.  Returns None on failure."""
    try:
        resp = requests.get(
            f"{APPLEDB_BASE}/ios/{quote(os_type)};{quote(buildid)}.json", timeout=15
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return None


def _get_index(os_type: str = "iOS") -> List[str]:
    """Fetch (and cache) the build key index for a given OS type from appledb.dev."""
    safe = os_type.replace(" ", "_")
    cached = _load_cache(f"index_{safe}", ttl=CACHE_TTL_INDEX)
    if cached:
        return cached

    resp = requests.get(f"{APPLEDB_BASE}/ios/{quote(os_type)}/index.json", timeout=20)
    resp.raise_for_status()
    data = resp.json()
    _save_cache(f"index_{safe}", data)
    return data


# ---------------------------------------------------------------------------
# Version matching
# ---------------------------------------------------------------------------

def _version_matches(entry_version: str, search_version: str) -> bool:
    """
    Match an appledb version string against a user-supplied version.

    appledb uses:
      "26.4 (a)"  – beta 1
      "26.4 (b)"  – beta 2
      "26.4"      – release
      "26.4.1"    – point release

    We accept the search string "26.4" matching all of the above.
    """
    v = entry_version.strip()
    return (
        v == search_version
        or v.startswith(search_version + " ")
        or v.startswith(search_version + ".")
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_firmware_by_buildid(
    buildid: str, identifier: str = ""
) -> Optional[AppleDBFirmware]:
    """
    Look up a specific build ID in appledb.dev.

    Automatically selects the correct OS type from the device identifier
    (visionOS, HomePod Software, tvOS, watchOS, or iOS).
    Returns None if the build is not in the appledb database.
    """
    os_type = _os_type_for_identifier(identifier) if identifier else "iOS"
    safe_os = os_type.replace(" ", "_")
    safe_id = buildid.replace("/", "_")
    cached = _load_cache(f"build_{safe_os}_{safe_id}")
    if cached is not None:
        return AppleDBFirmware(buildid, cached, identifier)

    entry = _fetch_entry(os_type, buildid)
    if entry is None:
        return None

    _save_cache(f"build_{safe_os}_{safe_id}", entry)
    return AppleDBFirmware(buildid, entry, identifier)


def search_by_version(
    version: str,
    identifier: str = "",
    build_prefix: Optional[str] = None,
) -> List[AppleDBFirmware]:
    """
    Search appledb.dev for all builds matching a version string.

    version:      user-supplied version, e.g. "26.4"
    identifier:   device identifier for URL/signing filtering
    build_prefix: 2-digit prefix to limit candidates (auto-inferred from
                  version if not supplied)

    Returns a list sorted newest-first.  Empty list if nothing found.
    """
    os_type = _os_type_for_identifier(identifier) if identifier else "iOS"
    safe_os = os_type.replace(" ", "_")

    cache_key = f"search_{safe_os}_{version}_{identifier}"
    cached_entries = _load_cache(cache_key, ttl=CACHE_TTL_INDEX)
    if cached_entries is not None:
        return [AppleDBFirmware(bid, entry, identifier)
                for bid, entry in cached_entries]

    # Infer build prefix from the major version number.
    # The build prefix scheme is shared across all OS types (22 = 18.x, 23 = 26.x).
    if build_prefix is None:
        try:
            major = int(version.split(".")[0])
            build_prefix = _IOS_MAJOR_TO_BUILD_PREFIX.get(major)
        except (ValueError, IndexError):
            pass

    index = _get_index(os_type)
    prefix_str = os_type + ";"  # e.g. "HomePod Software;" or "iOS;"

    # Filter index to plausible candidates
    candidates: List[str] = []
    for key in index:
        if not key.startswith(prefix_str):
            continue
        build_id = key[len(prefix_str):]
        if "sim" in build_id or "SDK" in build_id:
            continue
        if build_prefix and not build_id.startswith(build_prefix):
            continue
        candidates.append(build_id)

    if not candidates:
        return []

    # Concurrently fetch all candidates and filter by version + device
    matched: list = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_fetch_entry, os_type, bid): bid for bid in candidates}
        for future in as_completed(futures):
            build_id = futures[future]
            entry = future.result()
            if entry is None:
                continue
            if not _version_matches(entry.get("version", ""), version):
                continue
            dev_map = entry.get("deviceMap", [])
            if identifier and dev_map and identifier not in dev_map:
                continue
            matched.append((build_id, entry))

    # Sort newest-first by build ID (lexicographic is a reasonable proxy)
    matched.sort(key=lambda t: t[0], reverse=True)

    _save_cache(cache_key, matched)
    return [AppleDBFirmware(bid, entry, identifier) for bid, entry in matched]


def get_latest_build(
    version: str,
    identifier: str = "",
) -> Optional[AppleDBFirmware]:
    """Return the most recent build for a given version, or None."""
    results = search_by_version(version, identifier=identifier)
    return results[0] if results else None
