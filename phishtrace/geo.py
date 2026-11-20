from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
import ipaddress
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
NEGATIVE_CACHE_TTL_SECONDS = 60 * 60
GEOLOCATION_PROVIDERS = (
    "https://ipwho.is/{ip}",
    "https://get.geojs.io/v1/ip/geo/{ip}.json",
    "https://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,org,as,query",
    "https://ipapi.co/{ip}/json/",
)


def _cache_path(ip: str) -> Path:
    safe = ip.replace(":", "_").replace("/", "_")
    return CACHE_DIR / f"{safe}.json"


def _read_cache(ip: str) -> GeoResult | None:
    if ip in _memory_cache and _memory_cache[ip].resolved:
        return _memory_cache[ip]
    path = _cache_path(ip)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        result = GeoResult(**data)
        age = time.time() - path.stat().st_mtime
        if not result.resolved and age >= NEGATIVE_CACHE_TTL_SECONDS:
            return None
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
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        return GeoResult(ip=ip, resolved=False, timestamp=timestamp)
    if not parsed_ip.is_global:
        return GeoResult(ip=ip, resolved=False, timestamp=timestamp)

    cached = _read_cache(ip)
    if cached:
        cached.timestamp = timestamp
        return cached
    http = session or requests
    for provider in GEOLOCATION_PROVIDERS:
        try:
            response = http.get(
                provider.format(ip=ip),
                timeout=GEOLOCATION_TIMEOUT,
                headers={"User-Agent": "PhishTrace-AI/1.0"},
            )
            response.raise_for_status()
            data = response.json()
            if data.get("success") is False or data.get("status") == "fail":
                raise ValueError("geolocation provider returned no result")

            connection = data.get("connection") or {}
            latitude = data.get("latitude", data.get("lat"))
            longitude = data.get("longitude", data.get("lon"))
            if latitude is not None:
                latitude = float(latitude)
            if longitude is not None:
                longitude = float(longitude)
            result = GeoResult(
                ip=ip,
                resolved=True,
                hostname=data.get("hostname") or "",
                city=data.get("city") or "",
                region=data.get("region") or data.get("regionName") or "",
                country=data.get("country") or "",
                latitude=latitude,
                longitude=longitude,
                asn=str(connection.get("asn") or data.get("asn") or data.get("as") or ""),
                org=connection.get("org") or data.get("org") or data.get("isp") or data.get("organization_name") or "",
                timestamp=timestamp,
            )
            if result.latitude is None or result.longitude is None:
                raise ValueError("geolocation provider returned no coordinates")
            _write_cache(result)
            return result
        except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
            LOGGER.warning(
                "Geolocation lookup failed for %s via %s: %s",
                ip,
                provider,
                type(exc).__name__,
            )
    unresolved = GeoResult(ip=ip, resolved=False, timestamp=timestamp)
    _write_cache(unresolved)
    return unresolved
