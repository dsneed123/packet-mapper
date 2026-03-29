"""IP geolocation using MaxMind GeoLite2 (primary) with ip-api.com fallback."""

import ipaddress
import logging
import os
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_GEO_CACHE: dict[str, "GeoLocation"] = {}

# Path to the GeoLite2-City database; override with GEOIP_DB_PATH env var
_DB_PATH = Path(os.environ.get("GEOIP_DB_PATH", "GeoLite2-City.mmdb"))

# MaxMind download URL (requires a free license key from maxmind.com)
_MAXMIND_DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz"
)

_db_reader = None
_db_attempted = False  # avoids re-attempting a failed open on every lookup


@dataclass
class GeoLocation:
    ip: str
    lat: float
    lon: float
    city: str = ""
    country: str = ""
    isp: str = ""
    is_private: bool = False

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "lat": self.lat,
            "lon": self.lon,
            "city": self.city,
            "country": self.country,
            "isp": self.isp,
            "is_private": self.is_private,
        }


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True


def _try_download_db() -> bool:
    """Download GeoLite2-City.mmdb using MAXMIND_LICENSE_KEY env var. Returns True on success."""
    key = os.environ.get("MAXMIND_LICENSE_KEY", "")
    if not key:
        logger.debug(
            "GeoLite2 database not found. Set MAXMIND_LICENSE_KEY to enable auto-download "
            "(free key at maxmind.com). Falling back to ip-api.com."
        )
        return False

    url = _MAXMIND_DOWNLOAD_URL.format(key=key)
    logger.info("Downloading GeoLite2-City database...")
    try:
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()

        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            for chunk in resp.iter_content(chunk_size=8192):
                tmp.write(chunk)
            tmp_path = tmp.name

        try:
            with tarfile.open(tmp_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("GeoLite2-City.mmdb"):
                        f = tar.extractfile(member)
                        if f:
                            _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
                            _DB_PATH.write_bytes(f.read())
                        break
        finally:
            os.unlink(tmp_path)

        logger.info("GeoLite2-City database saved to %s", _DB_PATH)
        return _DB_PATH.exists()

    except Exception as exc:
        logger.warning("Failed to download GeoLite2 database: %s", exc)
        return False


def _get_db_reader():
    """Return a geoip2 Reader for _DB_PATH, downloading the DB on first run if needed."""
    global _db_reader, _db_attempted

    if _db_reader is not None:
        return _db_reader
    if _db_attempted:
        return None

    _db_attempted = True

    try:
        import geoip2.database
    except ImportError:
        logger.debug("geoip2 package not installed; falling back to ip-api.com")
        return None

    if not _DB_PATH.exists():
        if not _try_download_db():
            return None

    try:
        _db_reader = geoip2.database.Reader(str(_DB_PATH))
        logger.info("Loaded GeoLite2-City database from %s", _DB_PATH)
        return _db_reader
    except Exception as exc:
        logger.warning("Failed to open GeoLite2 database at %s: %s", _DB_PATH, exc)
        return None


def _lookup_geoip2(ip: str) -> Optional[GeoLocation]:
    """Look up IP in the local GeoLite2 database."""
    reader = _get_db_reader()
    if reader is None:
        return None
    try:
        record = reader.city(ip)
        return GeoLocation(
            ip=ip,
            lat=record.location.latitude or 0.0,
            lon=record.location.longitude or 0.0,
            city=record.city.name or "",
            country=record.country.name or "",
        )
    except Exception as exc:
        logger.debug("GeoLite2 lookup failed for %s: %s", ip, exc)
        return None


def _lookup_ipapi(ip: str, timeout: int = 3) -> Optional[GeoLocation]:
    """Look up IP via ip-api.com (fallback)."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,lat,lon,city,country,isp"},
            timeout=timeout,
        )
        data = resp.json()
        if data.get("status") == "success":
            return GeoLocation(
                ip=ip,
                lat=data["lat"],
                lon=data["lon"],
                city=data.get("city", ""),
                country=data.get("country", ""),
                isp=data.get("isp", ""),
            )
    except Exception as exc:
        logger.debug("ip-api.com lookup failed for %s: %s", ip, exc)
    return None


def lookup(ip: str, timeout: int = 3) -> Optional[GeoLocation]:
    """Return geolocation for an IP, using a local cache.

    Tries MaxMind GeoLite2 database first; falls back to ip-api.com if the
    database is unavailable.
    """
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    if is_private(ip):
        loc = GeoLocation(ip=ip, lat=0.0, lon=0.0, is_private=True)
        _GEO_CACHE[ip] = loc
        return loc

    loc = _lookup_geoip2(ip) or _lookup_ipapi(ip, timeout=timeout)
    if loc:
        _GEO_CACHE[ip] = loc
    return loc
