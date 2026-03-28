"""IP geolocation using ip-api.com (free, no key required)."""

import ipaddress
import logging
from dataclasses import dataclass, field
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


def lookup(ip: str, timeout: int = 3) -> Optional[GeoLocation]:
    """Return geolocation for an IP, using a local cache."""
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    if is_private(ip):
        loc = GeoLocation(ip=ip, lat=0.0, lon=0.0, is_private=True)
        _GEO_CACHE[ip] = loc
        return loc

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,lat,lon,city,country,isp"},
            timeout=timeout,
        )
        data = resp.json()
        if data.get("status") == "success":
            loc = GeoLocation(
                ip=ip,
                lat=data["lat"],
                lon=data["lon"],
                city=data.get("city", ""),
                country=data.get("country", ""),
                isp=data.get("isp", ""),
            )
            _GEO_CACHE[ip] = loc
            return loc
    except Exception as exc:
        logger.debug("Geo lookup failed for %s: %s", ip, exc)

    return None
