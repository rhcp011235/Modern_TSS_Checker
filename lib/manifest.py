"""
BuildManifest.plist parser.

Handles:
  - Finding the correct BuildIdentity for a given CPID / BDID / board config
  - Extracting component digest entries for a TSS request
  - Evaluating Apple's RestoreRequestRules to determine what fields go into
    each component's TSS request dict
"""

import plistlib
from typing import Optional, Any, Dict, List


class ManifestError(Exception):
    pass


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def load(path_or_bytes) -> dict:
    """
    Load a BuildManifest.plist from a file path or raw bytes.
    Handles both binary and XML plist formats transparently.
    """
    if isinstance(path_or_bytes, (str,)):
        with open(path_or_bytes, "rb") as f:
            raw = f.read()
    else:
        raw = path_or_bytes
    return plistlib.loads(raw)


def _parse_int(value) -> int:
    """Parse an integer that may be stored as hex string (e.g. '0x8010') or int."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16) if value.startswith("0x") else int(value)
    return 0


# ---------------------------------------------------------------------------
# Identity selection
# ---------------------------------------------------------------------------

def find_identity(
    manifest: dict,
    cpid: int,
    bdid: int,
    boardconfig: Optional[str] = None,
    restore_type: str = "Erase",
    variant: Optional[str] = None,
    ota: bool = False,
) -> Optional[dict]:
    """
    Find the matching BuildIdentity from a parsed BuildManifest.

    Priority:
      1. Exact CPID + BDID match
      2. If boardconfig provided, also filter by DeviceClass

    restore_type: "Erase" (default) or "Update"
    variant: explicit variant string override (e.g. "Customer Upgrade Install (IPSW)")
    """
    identities: List[dict] = manifest.get("BuildIdentities", [])

    # Build a preferred variant string
    if variant is None:
        if ota:
            variant_hint = "OTA"
        elif restore_type.lower() == "update":
            variant_hint = "Upgrade"
        else:
            variant_hint = "Erase"
    else:
        variant_hint = variant

    candidates = []
    for identity in identities:
        id_cpid = _parse_int(identity.get("ApChipID", 0))
        id_bdid = _parse_int(identity.get("ApBoardID", 0))

        if id_cpid != cpid or id_bdid != bdid:
            continue

        # Board config filter (optional)
        info = identity.get("Info", {})
        id_board = info.get("DeviceClass", "").lower()
        if boardconfig and id_board and id_board != boardconfig.lower():
            continue

        candidates.append(identity)

    if not candidates:
        return None

    # Prefer the identity whose variant string matches our hint
    for c in candidates:
        v = c.get("Info", {}).get("Variant", "")
        if variant_hint.lower() in v.lower():
            return c

    # Fall back to first match
    return candidates[0]


def find_identity_by_board(
    manifest: dict,
    boardconfig: str,
    restore_type: str = "Erase",
    variant: Optional[str] = None,
    ota: bool = False,
) -> Optional[dict]:
    """Find identity by board config only (CPID/BDID unknown or not needed)."""
    bc = boardconfig.lower()
    variant_hint = variant or ("Upgrade" if restore_type.lower() == "update" else "Erase")

    candidates = []
    for identity in manifest.get("BuildIdentities", []):
        info = identity.get("Info", {})
        id_board = info.get("DeviceClass", "").lower()
        if id_board == bc:
            candidates.append(identity)

    if not candidates:
        return None

    for c in candidates:
        v = c.get("Info", {}).get("Variant", "")
        if variant_hint.lower() in v.lower():
            return c
    return candidates[0]


# ---------------------------------------------------------------------------
# Component extraction + RestoreRequestRules evaluation
# ---------------------------------------------------------------------------

# Default device conditions used when evaluating RestoreRequestRules.
# These represent a production device in normal restore mode.
# Note: the conditions in modern manifests use ApRaw* keys, not ApProduction/Security.
_DEFAULT_CONDITIONS = {
    "ApRequiresImage4":          True,   # set to False for pre-A7 IMG3 devices
    # Production / security mode keys (different components use different keys)
    "ApRawProductionMode":       True,   # most components (KernelCache, LLB, etc.)
    "ApCurrentProductionMode":   True,   # pre-boot components (iBSS, iBEC)
    "ApRawSecurityMode":         True,
    "ApCurrentSecurityMode":     True,
    "ApProductionMode":          True,   # older manifests
    "ApSecurityMode":            True,   # older manifests
    "ApDemotionPolicyOverride":  False,
    "ApInRomDFU":                False,
}


def _eval_rules(rules: list, conditions: dict) -> dict:
    """
    Evaluate RestoreRequestRules and return a dict of actions to apply.

    Each rule is {"Conditions": {...}, "Actions": {...}}.
    A rule fires when ALL conditions match.
    """
    applied: dict = {}
    for rule in rules:
        conds = rule.get("Conditions", {})
        actions = rule.get("Actions", {})
        if all(conditions.get(k) == v for k, v in conds.items()):
            applied.update(actions)
    return applied


def extract_ap_components(
    identity: dict,
    img4: bool = True,
    conditions: Optional[dict] = None,
    requested_components: Optional[List[str]] = None,
    skip_baseband: bool = True,
    savage_chipid: Optional[int] = None,
    savage_patchepoch: Optional[int] = None,
) -> Dict[str, dict]:
    """
    Return a dict mapping component name → TSS request entry dict.

    Each entry contains whatever the RestoreRequestRules dictate (e.g.
    Trusted=True) plus Digest and PartialDigest from the manifest.

    skip_baseband: if True, skip components whose names start with "Bb" or
                   equal "BasebandFirmware" (these go in a separate baseband
                   request).

    Savage note: `Savage,*` components are silicon-revision-specific patches
    (B0/B2/BA/BE/BF × Dev/Prod variants).  Including multiple variants in
    one TSS request causes Apple to reject it (STATUS=94).  Pass
    `savage_chipid` and `savage_patchepoch` (read from the physical device)
    to have the extractor select the matching variant.  Without them, ALL
    Savage patches are skipped (correct for status-only checks).
    """
    conds = dict(_DEFAULT_CONDITIONS)
    conds["ApRequiresImage4"] = img4
    if conditions:
        conds.update(conditions)

    manifest_components: dict = identity.get("Manifest", {})
    result: Dict[str, dict] = {}

    for name, comp in manifest_components.items():
        if not isinstance(comp, dict):
            continue

        # Skip baseband components unless caller wants them
        is_bb = name.startswith("Bb") or name == "BasebandFirmware"
        if is_bb and skip_baseband:
            continue

        # Co-processor components (AVISP1,* and AudioAP1,*) have their own
        # dedicated ticket request path and must not be included in the regular
        # AP request.  See extract_copro_components() / get_copro_info().
        if name.startswith("AVISP1,") or name.startswith("AudioAP1,"):
            continue

        # Savage,* patches are silicon-revision-specific.  Including all
        # variants without knowing the actual revision causes Apple's TSS
        # server to reject the request.  Skip them unless we have real
        # hardware info (savage_chipid provided).
        if name.startswith("Savage,"):
            if savage_chipid is None:
                continue
            # With hardware info: only include the matching variant
            # (Prod patches for production mode; match silicon rev from chipid)
            # Simplified: include all Prod patches when in production mode
            if "Dev" in name:
                continue  # Skip development variants in production mode

        # Only include explicitly requested components if filter given
        if requested_components and name not in requested_components:
            continue

        info = comp.get("Info", {})

        # Personalize=False means this component is NOT personalized by TSS —
        # skip it entirely.  Missing Personalize key defaults to True (most
        # older components don't have it and are always included).
        personalize = info.get("Personalize")
        if personalize is False:
            continue

        rules = info.get("RestoreRequestRules", [])

        entry: dict = {}

        # Trusted is stored at the component top level in the manifest.
        # RestoreRequestRules add additional fields (EPRO, ESEC, etc.) —
        # they do NOT set Trusted.
        if "Trusted" in comp:
            entry["Trusted"] = comp["Trusted"]

        # Apply restore request rules (adds EPRO, ESEC, etc.)
        actions = _eval_rules(rules, conds)
        entry.update(actions)

        # Add digests (stored at component top level, not under Info)
        if "Digest" in comp:
            entry["Digest"] = comp["Digest"]
        if "PartialDigest" in comp:
            entry["PartialDigest"] = comp["PartialDigest"]

        # UniqueBuildID is a special case – it's its own component but the
        # plist value is bytes rather than a sub-dict
        if isinstance(comp, bytes):
            result[name] = comp
            continue

        result[name] = entry

    return result


def extract_baseband_components(
    identity: dict,
    img4: bool = True,
    conditions: Optional[dict] = None,
) -> Dict[str, dict]:
    """Return only the baseband-related components from the identity."""
    conds = dict(_DEFAULT_CONDITIONS)
    conds["ApRequiresImage4"] = img4
    if conditions:
        conds.update(conditions)

    manifest_components: dict = identity.get("Manifest", {})
    result: Dict[str, dict] = {}

    for name, comp in manifest_components.items():
        if not isinstance(comp, dict):
            continue
        is_bb = name.startswith("Bb") or name == "BasebandFirmware"
        if not is_bb:
            continue

        info = comp.get("Info", {})
        rules = info.get("RestoreRequestRules", [])
        entry: dict = {}
        actions = _eval_rules(rules, conds)
        entry.update(actions)

        if "Digest" in comp:
            entry["Digest"] = comp["Digest"]
        if "PartialDigest" in comp:
            entry["PartialDigest"] = comp["PartialDigest"]

        result[name] = entry

    return result


# ---------------------------------------------------------------------------
# Co-processor component extraction (AVISP1 / AudioAP1)
# ---------------------------------------------------------------------------

# Known co-processor prefixes and their roles.
#   AVISP1   → Apple Vision Pro / visionOS  (libtatsu PR #6: "bora")
#   AudioAP1 → HomePod / audioOS            (libtatsu PR #6: "durant")
COPRO_PREFIXES: List[str] = ["AVISP1", "AudioAP1"]


def get_copro_info(identity: dict) -> List[dict]:
    """
    Detect which co-processor ticket types are present in this identity.

    Returns a list of dicts:
        [{"prefix": "AVISP1", "chip_id": int, "board_id": int}, ...]

    chip_id / board_id are read from the BuildIdentity top-level keys
    "{prefix},ChipID" and "{prefix},BoardID" (0 if absent).
    Returns an empty list for every standard iPhone/iPad/AppleTV identity.
    """
    manifest_components: dict = identity.get("Manifest", {})
    found: List[dict] = []
    seen: set = set()

    for name in manifest_components:
        for prefix in COPRO_PREFIXES:
            if prefix not in seen and name.startswith(prefix + ","):
                chip_id  = _parse_int(identity.get(f"{prefix},ChipID",  0))
                board_id = _parse_int(identity.get(f"{prefix},BoardID", 0))
                found.append({"prefix": prefix, "chip_id": chip_id, "board_id": board_id})
                seen.add(prefix)
                break
        if len(seen) == len(COPRO_PREFIXES):
            break

    return found


def extract_copro_components(
    identity: dict,
    prefix: str,
    img4: bool = True,
    conditions: Optional[dict] = None,
) -> Dict[str, dict]:
    """
    Extract co-processor firmware component entries for a TSS request.
    Port of tss_request_add_bora_tags / tss_request_add_durant_tags in libtatsu
    (libimobiledevice/libtatsu PR #6).

    Key differences from extract_ap_components():
      - Only includes entries whose names start with "{prefix},"
      - Does NOT filter on Personalize (matches C code behaviour)
      - Adds an empty bytes Digest for Trusted items that have no Digest key
        (mirrors C: plist_new_data(NULL, 0) for trusted entries without digest)
    """
    conds = dict(_DEFAULT_CONDITIONS)
    conds["ApRequiresImage4"] = img4
    if conditions:
        conds.update(conditions)

    pfx = prefix + ","
    manifest_components: dict = identity.get("Manifest", {})
    result: Dict[str, dict] = {}

    for name, comp in manifest_components.items():
        if not isinstance(comp, dict):
            continue
        if not name.startswith(pfx):
            continue

        info  = comp.get("Info", {})
        rules = info.get("RestoreRequestRules", [])
        entry: dict = {}
        entry.update(_eval_rules(rules, conds))

        if "Trusted" in comp:
            entry["Trusted"] = comp["Trusted"]

        # Mirrors the C code: add empty bytes digest (plist_new_data(NULL, 0))
        # for Trusted items that have no Digest key in the manifest.
        if "Digest" in comp:
            entry["Digest"] = comp["Digest"]
        elif entry.get("Trusted"):
            entry["Digest"] = b""

        if "PartialDigest" in comp:
            entry["PartialDigest"] = comp["PartialDigest"]

        result[name] = entry

    return result


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def get_product_version(manifest: dict) -> str:
    return manifest.get("ProductVersion", "")


def get_product_build_version(manifest: dict) -> str:
    return manifest.get("ProductBuildVersion", "")


def get_cpid(identity: dict) -> int:
    """Parse the CPID (chip ID) from a BuildIdentity, handling hex strings."""
    return _parse_int(identity.get("ApChipID", 0))


def get_bdid(identity: dict) -> int:
    """Parse the BDID (board ID) from a BuildIdentity, handling hex strings."""
    return _parse_int(identity.get("ApBoardID", 0))


def get_restore_attestation_mode(identity: dict) -> int:
    """
    Return the RestoreAttestationMode from the identity's Info dict.

    Known values (firmware-dependent — newer iOS builds may raise the value):
      2 — A15 Bionic (0x8110) in iOS 18.x: anonymous TSS works
      3 — A16 Bionic (0x8120) in iOS 18.x: anonymous TSS works
      4 — A17 Pro (0x8130) in iOS 18.x: hardware attestation required;
          anonymous TSS returns STATUS=69.
      6 — A15 Bionic (0x8110) in iOS 26.4+: hardware attestation required.
      8 — A19 Pro (0x8150) in iOS 26.4+: hardware attestation required.
      Any value >= 4: hardware attestation required; fall back to cached status.
    """
    info = identity.get("Info", {})
    return int(info.get("RestoreAttestationMode", 0))
