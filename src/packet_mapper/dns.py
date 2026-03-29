"""Reverse DNS lookup with in-process cache."""

import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)

_DNS_CACHE: dict[str, Optional[str]] = {}


def reverse_lookup(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Return the PTR hostname for *ip*, using a local cache.

    Returns None if the lookup fails or if the PTR record is the IP itself.
    """
    if ip in _DNS_CACHE:
        return _DNS_CACHE[ip]

    hostname = None
    prev_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyaddr(ip)
        candidate = result[0]
        if candidate != ip:
            hostname = candidate
    except OSError as exc:
        logger.debug("Reverse DNS failed for %s: %s", ip, exc)
    finally:
        socket.setdefaulttimeout(prev_timeout)

    _DNS_CACHE[ip] = hostname
    return hostname
