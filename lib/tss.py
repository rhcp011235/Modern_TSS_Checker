"""
TSS (Apple Trusted Software Service) client.

Matches the original tsschecker behaviour:
  - Exact same plist key names and structure
  - Same six Apple TSS endpoints with round-robin retry (up to 10 attempts)
  - Same HTTP headers  (User-Agent: InetURL/1.0, Content-type: text/xml, …)
  - Same response parsing (STATUS=0 → signed)
"""

import os
import plistlib
import secrets
import hashlib
import uuid
import sys
from typing import Optional, Dict, Any, Tuple

import requests

# ---------------------------------------------------------------------------
# Constants – mirror originals exactly
# ---------------------------------------------------------------------------

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

_HOST_PLATFORM = sys.platform  # "darwin" / "linux" / "win32"

def _host_platform_str() -> str:
    if sys.platform == "darwin":
        return "mac"
    if sys.platform.startswith("win"):
        return "windows"
    return "linux"


# ---------------------------------------------------------------------------
# Nonce helpers
# ---------------------------------------------------------------------------

def random_nonce(nonce_type: str) -> bytes:
    """Generate a random nonce of the correct length for signing-status checks."""
    if nonce_type == "sha1":
        return secrets.token_bytes(20)
    if nonce_type == "sha256":
        return secrets.token_bytes(32)
    if nonce_type == "sha384":
        return secrets.token_bytes(48)
    return b""  # NONCE_NONE


def parse_hex_bytes(hex_str: str) -> bytes:
    """Parse a hex string (with or without 0x prefix) into bytes."""
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


def generator_to_nonce(generator_hex: str, nonce_type: str) -> bytes:
    """
    Derive the ApNonce from a generator value (used by jailbreaks like unc0ver).

    On A9 and below the nonce IS the generator (SHA1 of generator bytes).
    On A10+ nonces are device-specific (UID-derived); the generator alone is
    insufficient — the real nonce must be read from the device.  We still hash
    here so the request is structurally correct for status-checking purposes.
    """
    gen_bytes = parse_hex_bytes(generator_hex)
    if nonce_type == "sha1":
        return hashlib.sha1(gen_bytes).digest()   # 20 bytes
    if nonce_type == "sha256":
        return hashlib.sha256(gen_bytes).digest() # 32 bytes
    if nonce_type == "sha384":
        return hashlib.sha384(gen_bytes).digest() # 48 bytes
    return b""


# ---------------------------------------------------------------------------
# TSS request builder
# ---------------------------------------------------------------------------

class TSSRequest:
    """
    Builds and sends a TSS signing-status request.

    Usage:
        req = TSSRequest(cpid=0x8015, bdid=4, ecid=0x1234ABCD)
        req.set_nonce(apnonce_bytes, sepnonce_bytes)
        req.add_ap_components(components_dict, img4=True)
        signed, response_str = req.send()
    """

    def __init__(self, cpid: int, bdid: int, ecid: int = 0):
        self._cpid  = cpid
        self._bdid  = bdid
        self._ecid  = ecid
        self._plist: Dict[str, Any] = {}
        self._apnonce:  bytes = b""
        self._sepnonce: bytes = b""
        self._build_standard_values()

    # -----------------------------------------------------------------------
    # Standard metadata (identical to original setStandardValues)
    # -----------------------------------------------------------------------

    def _build_standard_values(self) -> None:
        self._plist["@Locality"]        = "en_US"
        self._plist["@HostPlatformInfo"] = _host_platform_str()
        self._plist["@VersionInfo"]     = TSS_CLIENT_VERSION
        self._plist["@UUID"]            = str(uuid.uuid4()).upper()
        self._plist["ApProductionMode"] = True
        self._plist["ApChipID"]         = self._cpid
        self._plist["ApBoardID"]        = self._bdid
        self._plist["ApECID"]           = self._ecid
        self._plist["ApSecurityDomain"] = 1
        self._plist["ApSecurityMode"]   = True
        self._plist["UID_MODE"]         = False

    # -----------------------------------------------------------------------
    # Nonce
    # -----------------------------------------------------------------------

    def set_nonce(self, apnonce: bytes, sepnonce: bytes) -> None:
        self._apnonce  = apnonce
        self._sepnonce = sepnonce
        if apnonce:
            self._plist["ApNonce"]  = apnonce
        if sepnonce:
            self._plist["SepNonce"] = sepnonce

    # -----------------------------------------------------------------------
    # IMG4 / IMG3 ticket flag
    # -----------------------------------------------------------------------

    def set_img4(self, img4: bool = True) -> None:
        if img4:
            self._plist["@ApImg4Ticket"] = True
        else:
            self._plist["@APTicket"] = True

    # -----------------------------------------------------------------------
    # Optional: UniqueBuildID
    # -----------------------------------------------------------------------

    def set_unique_build_id(self, ubid: bytes) -> None:
        """Add UniqueBuildID from the top level of the BuildIdentity (if present)."""
        if ubid:
            self._plist["UniqueBuildID"] = ubid

    # -----------------------------------------------------------------------
    # AP (application processor) firmware components
    # -----------------------------------------------------------------------

    def add_ap_components(self, components: Dict[str, Any]) -> None:
        """
        Add AP firmware component entries (Digest, PartialDigest, Trusted, …).
        `components` is the dict returned by manifest.extract_ap_components().
        """
        for name, entry in components.items():
            if isinstance(entry, bytes):
                # UniqueBuildID and similar top-level bytes values
                self._plist[name] = entry
            elif isinstance(entry, dict):
                self._plist[name] = entry

    # -----------------------------------------------------------------------
    # Baseband components
    # -----------------------------------------------------------------------

    def add_baseband_components(
        self,
        components: Dict[str, Any],
        bbgcid: int,
        bbsnum: bytes,
    ) -> None:
        """
        Add baseband firmware components plus the GoldCertId and SNUM fields
        required by the TSS server.
        """
        self._plist["BbGoldCertId"] = bbgcid
        self._plist["BbSNUM"]       = bbsnum

        # Baseband firmware entry
        bb_entry: Dict[str, Any] = {}
        for name, entry in components.items():
            if name == "BasebandFirmware":
                bb_entry = dict(entry) if isinstance(entry, dict) else {}
            else:
                if isinstance(entry, dict):
                    self._plist[name] = entry

        if bb_entry:
            self._plist["BasebandFirmware"] = bb_entry

    # -----------------------------------------------------------------------
    # Plist serialisation
    # -----------------------------------------------------------------------

    def build_plist_dict(self) -> dict:
        """Return the raw Python dict that represents the TSS request plist."""
        return dict(self._plist)

    def build_xml(self) -> bytes:
        """Serialise to XML plist bytes (what we POST to Apple)."""
        return plistlib.dumps(self._plist, fmt=plistlib.FMT_XML, sort_keys=False)

    def print_request(self) -> None:
        """Pretty-print the request XML to stdout."""
        print(self.build_xml().decode("utf-8"))

    # -----------------------------------------------------------------------
    # Sending
    # -----------------------------------------------------------------------

    def send(self, verbose: bool = False) -> Tuple[bool, str]:
        """
        Send the TSS request to Apple's servers.

        Returns:
            (signed: bool, response_body: str)

        signed=True  → firmware IS still being signed (STATUS=0)
        signed=False → firmware is NOT signed, or an error occurred
        """
        payload = self.build_xml()

        session = requests.Session()
        # Disable SSL verification for the direct IP fallbacks (no valid cert
        # for those; original tsschecker does the same by not verifying certs)
        session.verify = False

        for attempt in range(TSS_MAX_TRIES):
            url = TSS_URLS[attempt % len(TSS_URLS)]
            try:
                if verbose:
                    print(f"[TSS] Attempt {attempt + 1}/{TSS_MAX_TRIES} → {url}")
                resp = session.post(
                    url,
                    data=payload,
                    headers=TSS_HEADERS,
                    timeout=30,
                )
                body = resp.text
                status_code, message = _parse_tss_response(body)
                if verbose:
                    print(f"[TSS] STATUS={status_code} MESSAGE={message}")
                return status_code == 0, body
            except requests.RequestException as exc:
                if verbose:
                    print(f"[TSS] Request failed ({exc}), retrying…")

        return False, ""


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_tss_response(body: str) -> Tuple[int, str]:
    """
    Parse the raw TSS response string.

    The response is NOT a plist — it is URL-encoded key=value pairs like:
        STATUS=0&MESSAGE=SUCCESS&REQUEST_STRING=...
    or
        STATUS=94&MESSAGE=This firmware version is no longer being signed.
    """
    status  = -1
    message = ""

    for token in body.split("&"):
        if token.startswith("STATUS="):
            try:
                status = int(token[len("STATUS="):].strip())
            except ValueError:
                pass
        elif token.startswith("MESSAGE="):
            message = token[len("MESSAGE="):].strip()

    return status, message


def extract_shsh_blob(response_body: str) -> Optional[bytes]:
    """
    Extract the SHSH2 blob bytes from a successful TSS response.

    The REQUEST_STRING field contains the plist blob that gets saved as .shsh2.
    """
    for token in response_body.split("&"):
        if token.startswith("REQUEST_STRING="):
            plist_str = token[len("REQUEST_STRING="):]
            try:
                return plistlib.loads(plist_str.encode("utf-8"))
            except Exception:
                return plist_str.encode("utf-8")
    return None


# ---------------------------------------------------------------------------
# SHSH2 file naming
# ---------------------------------------------------------------------------

def shsh2_filename(
    product_type: str,
    ecid: int,
    version: str,
    buildid: str,
    apnonce: bytes,
) -> str:
    """
    Generate the canonical .shsh2 filename used by the original tsschecker:
      <ProductType>_0x<ECID>_<Version>-<BuildID>_<APNonce-hex>.shsh2
    """
    ecid_str  = f"0x{ecid:X}" if ecid else "0x0"
    nonce_hex = apnonce.hex() if apnonce else "0" * 40
    return f"{product_type}_{ecid_str}_{version}-{buildid}_{nonce_hex}.shsh2"
