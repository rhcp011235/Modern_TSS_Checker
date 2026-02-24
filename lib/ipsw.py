"""
IPSW.me firmware API wrapper + pure-Python FragmentZip.

FragmentZip downloads only the bytes needed to extract a single file from a
remote ZIP (the IPSW) using HTTP Range requests — exactly what libfragmentzip
does but without any native compilation.
"""

import struct
import zlib
import plistlib
import requests
from typing import Optional, List, Dict, Any

IPSW_ME_BASE = "https://api.ipsw.me/v4"

# ---------------------------------------------------------------------------
# FragmentZip – HTTP Range-based ZIP extraction
# ---------------------------------------------------------------------------

class FragmentZipError(Exception):
    pass


class FragmentZip:
    """
    Download a single file from a remote ZIP without fetching the whole thing.

    Uses three HTTP Range requests:
      1. Tail of file → locate End of Central Directory (EOCD)
      2. Central directory → find the target file entry
      3. Local file header + compressed data → decompress and return
    """

    def __init__(self, url: str, session: Optional[requests.Session] = None):
        self.url = url
        self._s = session or requests.Session()
        self._s.headers.update({"User-Agent": "tsschecker/python"})
        self._file_size = self._get_file_size()

    def _get_file_size(self) -> int:
        resp = self._s.head(self.url, timeout=20, allow_redirects=True)
        resp.raise_for_status()
        size = resp.headers.get("Content-Length")
        if not size:
            # Fall back to a GET with Range 0-0 and look at Content-Range
            resp = self._s.get(self.url, headers={"Range": "bytes=0-0"}, timeout=20)
            cr = resp.headers.get("Content-Range", "")
            # Content-Range: bytes 0-0/TOTAL
            if "/" in cr:
                size = cr.split("/")[-1]
        if not size:
            raise FragmentZipError("Cannot determine remote file size (server may not support Range requests)")
        return int(size)

    def _range_get(self, start: int, end: int) -> bytes:
        """Inclusive byte range request."""
        headers = {"Range": f"bytes={start}-{end}"}
        resp = self._s.get(self.url, headers=headers, timeout=60)
        if resp.status_code not in (200, 206):
            raise FragmentZipError(f"Range request failed: HTTP {resp.status_code}")
        return resp.content

    def _find_eocd(self) -> tuple:
        """
        Returns (cd_offset, cd_size).

        Handles both standard ZIP and ZIP64 (required for IPSWs > 4 GB).

        ZIP64 detection: the regular EOCD cd_offset field = 0xFFFFFFFF
        signals that the real values are in the ZIP64 EOCD record, which
        is located via the ZIP64 EOCD locator just before the regular EOCD.
        """
        tail_size = min(65557, self._file_size)
        data = self._range_get(self._file_size - tail_size, self._file_size - 1)

        # Find regular EOCD (scan from end, skip backwards over comment)
        eocd_sig = b"PK\x05\x06"
        pos = data.rfind(eocd_sig)
        if pos == -1:
            raise FragmentZipError("EOCD signature not found — not a valid ZIP")
        if len(data) - pos < 22:
            raise FragmentZipError("Truncated EOCD record")

        # EOCD: Sig(4) DiskNum(2) StartDisk(2) DiskEntries(2) TotalEntries(2)
        #        CDSize(4) CDOffset(4) CommentLen(2)
        _, _, _, _, _, cd_size, cd_offset, _ = struct.unpack_from("<IHHHHIIH", data, pos)

        # ZIP64 marker: values are 0xFFFFFFFF when the actual data is in EOCD64
        if cd_offset == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            return self._find_eocd64(data, pos)

        return int(cd_offset), int(cd_size)

    def _find_eocd64(self, tail_data: bytes, eocd_pos: int) -> tuple:
        """
        Parse the ZIP64 End-of-Central-Directory record.

        Layout (relative to end of file):
          [ZIP64 EOCD record]  PK\x06\x06
          [ZIP64 EOCD locator] PK\x06\x07  ← 20 bytes before the regular EOCD
          [regular EOCD]       PK\x05\x06
        """
        loc_sig = b"PK\x06\x07"
        # ZIP64 locator is 20 bytes and sits directly before the regular EOCD
        loc_pos = eocd_pos - 20
        if loc_pos < 0 or tail_data[loc_pos:loc_pos + 4] != loc_sig:
            raise FragmentZipError(
                "ZIP64 EOCD locator not found — cannot parse ZIP64 IPSW"
            )

        # Locator: Sig(4) DiskWithEOCD64(4) OffsetOfEOCD64(8) TotalDisks(4)
        _, _, eocd64_offset, _ = struct.unpack_from("<IIqI", tail_data, loc_pos)

        # Download the ZIP64 EOCD record (56 bytes exactly for the fixed part)
        eocd64_data = self._range_get(eocd64_offset, eocd64_offset + 55)
        if eocd64_data[:4] != b"PK\x06\x06":
            raise FragmentZipError("ZIP64 EOCD record signature mismatch")

        # ZIP64 EOCD fixed part layout (56 bytes):
        #   Sig(4) RecordSize(8) VerMadeBy(2) VerNeeded(2)
        #   DiskNum(4) DiskWithCD(4) DiskEntries(8) TotalEntries(8)
        #   CDSize(8) CDOffset(8)
        (_, _, _, _, _, _, _, _, cd_size, cd_offset) = struct.unpack_from(
            "<IqHHIIqqqq", eocd64_data
        )
        return int(cd_offset), int(cd_size)

    def _parse_central_directory(self, cd_offset: int, cd_size: int) -> Dict[str, dict]:
        """
        Download and parse central directory; return {filename: entry_dict}.
        Handles ZIP64 extra fields where 32-bit values overflow to 0xFFFFFFFF.
        """
        cd_data = self._range_get(cd_offset, cd_offset + cd_size - 1)

        entries: Dict[str, dict] = {}
        pos = 0
        while pos < len(cd_data):
            if cd_data[pos : pos + 4] != b"PK\x01\x02":
                break
            if len(cd_data) - pos < 46:
                break

            (
                _sig, _ver_made, _ver_need, _flags, compress_method,
                _mod_time, _mod_date, _crc32,
                compressed_size, uncompressed_size,
                fname_len, extra_len, comment_len,
                _disk_start, _int_attr, _ext_attr, local_header_offset,
            ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", cd_data, pos)

            header_end = pos + 46
            fname_start = header_end
            extra_start = fname_start + fname_len

            filename = cd_data[fname_start : fname_start + fname_len].decode(
                "utf-8", errors="replace"
            )

            # Parse ZIP64 extra field if any 32-bit field signals overflow
            if (
                compressed_size   == 0xFFFFFFFF
                or uncompressed_size == 0xFFFFFFFF
                or local_header_offset == 0xFFFFFFFF
            ):
                compressed_size, uncompressed_size, local_header_offset = (
                    self._parse_zip64_extra(
                        cd_data[extra_start : extra_start + extra_len],
                        compressed_size,
                        uncompressed_size,
                        local_header_offset,
                    )
                )

            pos = extra_start + extra_len + comment_len

            entries[filename] = {
                "compress_method":     compress_method,
                "compressed_size":     compressed_size,
                "uncompressed_size":   uncompressed_size,
                "local_header_offset": local_header_offset,
            }

        return entries

    @staticmethod
    def _parse_zip64_extra(
        extra_data: bytes,
        compressed_size: int,
        uncompressed_size: int,
        local_header_offset: int,
    ) -> tuple:
        """
        Scan the extra field block for the ZIP64 extension (header id 0x0001)
        and replace any 0xFFFFFFFF sentinel values with the real 64-bit values.
        """
        i = 0
        while i + 4 <= len(extra_data):
            header_id, data_size = struct.unpack_from("<HH", extra_data, i)
            i += 4
            block = extra_data[i : i + data_size]
            i += data_size

            if header_id != 0x0001:
                continue

            # ZIP64 extra fields appear in this order (only if original was 0xFFFFFFFF):
            #   uncompressed_size (8 bytes) if original == 0xFFFFFFFF
            #   compressed_size   (8 bytes) if original == 0xFFFFFFFF
            #   local_header_offset (8 bytes) if original == 0xFFFFFFFF
            bpos = 0
            if uncompressed_size == 0xFFFFFFFF and bpos + 8 <= len(block):
                uncompressed_size = struct.unpack_from("<q", block, bpos)[0]
                bpos += 8
            if compressed_size == 0xFFFFFFFF and bpos + 8 <= len(block):
                compressed_size = struct.unpack_from("<q", block, bpos)[0]
                bpos += 8
            if local_header_offset == 0xFFFFFFFF and bpos + 8 <= len(block):
                local_header_offset = struct.unpack_from("<q", block, bpos)[0]
            break

        return compressed_size, uncompressed_size, local_header_offset

    def _read_local_data_offset(self, local_header_offset: int) -> int:
        """Parse local file header to find where the actual data starts."""
        # Local header: Sig(4) VerNeeded(2) Flags(2) Method(2) MTime(2) MDate(2)
        #               CRC32(4) CompSz(4) UncompSz(4) FNameLen(2) ExtraLen(2)
        header = self._range_get(local_header_offset, local_header_offset + 29)
        if header[:4] != b"PK\x03\x04":
            raise FragmentZipError("Local file header signature mismatch")
        fname_len  = struct.unpack_from("<H", header, 26)[0]
        extra_len  = struct.unpack_from("<H", header, 28)[0]
        return local_header_offset + 30 + fname_len + extra_len

    def read_file(self, filename: str) -> bytes:
        """
        Download and return the decompressed contents of *filename* from the
        remote ZIP.  Raises FragmentZipError if the file is not found.
        """
        cd_offset, cd_size = self._find_eocd()
        entries = self._parse_central_directory(cd_offset, cd_size)

        # Try plain filename, then OTA sub-path
        target = None
        for candidate in (filename, f"AssetData/boot/{filename}"):
            if candidate in entries:
                target = candidate
                break
        if target is None:
            raise FragmentZipError(f"'{filename}' not found in remote ZIP")

        entry = entries[target]
        data_offset = self._read_local_data_offset(entry["local_header_offset"])
        compressed  = self._range_get(
            data_offset, data_offset + entry["compressed_size"] - 1
        )

        method = entry["compress_method"]
        if method == 0:
            return compressed                       # stored – no compression
        if method == 8:
            return zlib.decompress(compressed, -15) # deflate (raw, no header)
        raise FragmentZipError(f"Unsupported compression method {method}")


# ---------------------------------------------------------------------------
# IPSW.me firmware API
# ---------------------------------------------------------------------------

class Firmware:
    def __init__(self, d: dict):
        self.version: str  = d.get("version", "")
        self.buildid: str  = d.get("buildid", "")
        self.url: str      = d.get("url", "")
        self.signed: bool  = d.get("signed", False)
        self.filesize: int = d.get("filesize", 0)
        self.sha1sum: str  = d.get("sha1sum", "")
        self.md5sum: str   = d.get("md5sum", "")

    def __repr__(self):
        status = "SIGNED" if self.signed else "unsigned"
        return f"<Firmware {self.version} ({self.buildid}) [{status}]>"


def get_firmwares(identifier: str, ota: bool = False) -> List[Firmware]:
    """Return all firmwares (or OTA updates) for a device from IPSW.me."""
    endpoint = "ota" if ota else "ipsw"
    resp = requests.get(
        f"{IPSW_ME_BASE}/device/{identifier}?type={endpoint}", timeout=20
    )
    resp.raise_for_status()
    data = resp.json()
    fw_list = data.get("firmwares") or data.get("otas") or []
    return [Firmware(f) for f in fw_list]


def get_latest_firmware(identifier: str, ota: bool = False) -> Optional[Firmware]:
    """Return the most recent (highest-version) firmware for a device."""
    fws = get_firmwares(identifier, ota=ota)
    if not fws:
        return None
    # Sort by iOS version numerically
    def _ver_key(fw: Firmware):
        try:
            return tuple(int(x) for x in fw.version.split("."))
        except ValueError:
            return (0,)
    return max(fws, key=_ver_key)


def get_firmware_by_version(identifier: str, version: str, ota: bool = False) -> Optional[Firmware]:
    for fw in get_firmwares(identifier, ota=ota):
        if fw.version == version:
            return fw
    return None


def get_firmware_by_buildid(identifier: str, buildid: str, ota: bool = False) -> Optional[Firmware]:
    for fw in get_firmwares(identifier, ota=ota):
        if fw.buildid.lower() == buildid.lower():
            return fw
    return None


def download_build_manifest(ipsw_url: str) -> bytes:
    """
    Extract and return the raw bytes of BuildManifest.plist from a remote IPSW
    using HTTP Range requests (no full download required).
    """
    fz = FragmentZip(ipsw_url)
    return fz.read_file("BuildManifest.plist")


def parse_build_manifest_from_url(ipsw_url: str) -> Any:
    """Download and parse BuildManifest.plist from a remote IPSW URL."""
    raw = download_build_manifest(ipsw_url)
    return plistlib.loads(raw)
