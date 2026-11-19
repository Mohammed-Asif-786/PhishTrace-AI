from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path

import requests

from .config import GEOLOCATION_RETRIES, GEOLOCATION_TIMEOUT, GEOLOCATION_URL

LOGGER = logging.getLogger(__name__)
CACHE_DIR = Path(__file__).resolve().parent.parent / ".cache"
CACHE_DIR.mkdir(exist_ok=True)


@dataclass
class GeoResult:
    ip: str
    resolved: bool
    hostname: str = ""
    city: str = ""
    region: str = ""
    country: str = ""
    latitude: float | None = None
    longitude: float | None = None
    asn: str = ""
    org: str = ""
    timestamp: str = ""


_memory_cache: dict[str, GeoResult] = {}


def _cache_path(ip: str) -> Path:
    safe = ip.replace(":", "_").replace("/", "_")
    return CACHE_DIR / f"{safe}.json"


def _read_cache(ip: str) -> GeoResult | None:
    if ip in _memory_cache:
        return _memory_cache[ip]
    path = _cache_path(ip)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        result = GeoResult(**data)
        _memory_cache[ip] = result
        return result
    except (json.JSONDecodeError, OSError, TypeError):
        LOGGER.warning("Invalid geolocation cache entry for %s", ip)
        return None


def _write_cache(result: GeoResult) -> None:
    try:
        _cache_path(result.ip).write_text(
            json.dumps(result.__dict__, ensure_ascii=False), encoding="utf-8"
        )
    except OSError:
        LOGGER.warning("Could not write geolocation cache for %s", result.ip)
    _memory_cache[result.ip] = result


def lookup_ip(ip: str, timestamp: str = "", session: requests.Session | None = None) -> GeoResult:
    cached = _read_cache(ip)
    if cached:
        cached.timestamp = timestamp
        return cached
    http = session or requests
    for attempt in range(GEOLOCATION_RETRIES + 1):
        try:
            response = http.get(GEOLOCATION_URL.format(ip=ip), timeout=GEOLOCATION_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            if not data.get("success", True):
                break
            connection = data.get("connection") or {}
            result = GeoResult(
                ip=ip,
                resolved=True,
                hostname=data.get("hostname") or "",
                city=data.get("city") or "",
                region=data.get("region") or "",
                country=data.get("country") or "",
                latitude=data.get("latitude"),
                longitude=data.get("longitude"),
                asn=str(connection.get("asn") or data.get("asn") or ""),
                org=connection.get("org") or data.get("org") or "",
                timestamp=timestamp,
            )
            _write_cache(result)
            return result
        except (requests.RequestException, ValueError, KeyError) as exc:
            LOGGER.warning("Geolocation lookup failed for %s: %s", ip, type(exc).__name__)
            if attempt < GEOLOCATION_RETRIES:
                time.sleep(0.1)
    unresolved = GeoResult(ip=ip, resolved=False, timestamp=timestamp)
    _write_cache(unresolved)
    return unresolved
