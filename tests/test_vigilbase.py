"""Vigilbase: free security checks (security headers, email security). Every route is free, so the
whole file is platform-servable at $0; GET /tools is the key probe (bad key → 401)."""
from __future__ import annotations

from treg import oauth_providers as P
from treg.domain.catalog import store as cs


def test_every_vigilbase_route_is_free_and_platform_eligible():
    cat = cs.load()
    eps = [e for e in cat.endpoints if e["provider"] == "vigilbase"]
    assert eps
    for ep in eps:
        assert ep["cost"]["type"] == "free", ep["id"]
        assert ep["cost"]["value"] == 0, ep["id"]
        if ep.get("kind") == "account":
            continue
        assert cat.platform_eligible(ep), ep["id"]


def test_vigilbase_key_rides_in_a_header_and_probes_the_free_catalog():
    p = P.REGISTRY["vigilbase"]
    assert p.auth_kind == "key"
    assert p.token_location == "header"
    assert p.token_header == "X-Api-Key" and p.token_format == "{secret}"
    assert p.probe_path == "/tools"
