from unittest.mock import Mock

from phishtrace.geo import lookup_ip


class FakeResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "success": True,
            "city": "Mountain View",
            "country": "United States",
            "latitude": 37.4,
            "longitude": -122.1,
            "connection": {"asn": 15169, "org": "Google LLC"},
        }


def test_geo_lookup_resolves_mock_result():
    session = Mock()
    session.get.return_value = FakeResponse()
    result = lookup_ip("8.8.8.8", "2026-11-19", session=session)
    assert result.resolved
    assert result.city == "Mountain View"


def test_geo_lookup_unreachable_is_unresolved():
    import requests
    session = Mock()
    session.get.side_effect = requests.ConnectionError("offline")
    result = lookup_ip("1.1.1.1", session=session)
    assert not result.resolved


def test_geo_lookup_rejects_private_address():
    session = Mock()
    result = lookup_ip("10.0.0.1", session=session)
    assert not result.resolved
    session.get.assert_not_called()


class FailingResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {"success": False}


class IpApiResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "status": "success",
            "country": "United States",
            "regionName": "California",
            "city": "San Francisco",
            "lat": 37.7749,
            "lon": -122.4194,
            "org": "Test Network",
        }


def test_geo_lookup_falls_back_after_provider_failure():
    session = Mock()
    session.get.side_effect = [FailingResponse(), IpApiResponse()]
    result = lookup_ip("4.2.2.2", session=session)
    assert result.resolved
    assert result.city == "San Francisco"
    assert session.get.call_count == 2
