from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
import ipaddress
import logging
import unittest
from unittest.mock import AsyncMock, patch

from app.proxy.decoder import decode_secret, canonical_secret
from app.proxy.identity import make_variant_id
from app.proxy.network import UnsafeTarget, resolve_public_addresses, validate_public_ip
from app.proxy.probe_engine import ProbeEngine
from app.proxy.selection_service import evidence_for, select_proxies
from app.db.probes import parse_agents_config, validate_observation

CORE = "00112233445566778899aabbccddeeff"
NOW = 2000


def observation(**values):
    return dict(outcome="success", level="auth_key", checked_at=1900, valid_until=2200,
                network_key="us-oregon", country="US", access_type="datacenter", network_epoch="a",
                resolved_ip="8.8.8.8", ip_family="ipv4", client_profile_id="tdlib-test", dc_id=2, **values)


def row(name="a", ip="8.8.8.8", **values):
    return {"id": name, "host": f"{name}.example.com", "port": 443, "secret": CORE,
            "observations": [{**observation(), "resolved_ip": ip}], **values}


class CanonicalTests(unittest.TestCase):
    def test_plain_prefix_is_not_a_transport_prefix(self):
        for prefix in ("ee", "dd"):
            secret = prefix + CORE[2:]
            self.assertEqual(decode_secret(secret).generation, "plain")

    def test_formats_share_identity_but_different_keys_do_not(self):
        raw = bytes.fromhex("ee" + CORE + b"example.com".hex())
        encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        self.assertEqual(canonical_secret(encoded), raw.hex())
        self.assertEqual(make_variant_id("EXAMPLE.com.",443,encoded), make_variant_id("example.com",443,raw.hex()))
        self.assertNotEqual(make_variant_id("example.com",443,CORE), make_variant_id("example.com",443,"ff"*16))
        self.assertEqual(len(make_variant_id("example.com",443,CORE)),32)

    def test_invalid_secrets_and_targets(self):
        for secret in ("", "ee"+CORE, "dd"+CORE+"00", "garbage", None):
            self.assertFalse(decode_secret(secret).is_valid)
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1", "64:ff9b::7f00:1"):
            with self.subTest(ip=ip), self.assertRaises(UnsafeTarget):
                validate_public_ip(ip)


class EvidenceTests(unittest.TestCase):
    def test_expiry_and_engine_errors_do_not_renew_success(self):
        value = row()
        value["observations"].append({**observation(), "checked_at":1990,"outcome":"engine_error","valid_until":None})
        self.assertEqual(evidence_for(value,now=NOW)["status"],"verified")
        self.assertEqual(evidence_for(value,now=2300)["status"],"stale")

    def test_new_failure_in_same_context_replaces_success(self):
        value = row()
        value["observations"].append({**observation(),"checked_at":1950,"outcome":"auth_key_failed","valid_until":None})
        self.assertIsNone(select_proxies([value],now=NOW).proxy)

    def test_tcp_and_cover_success_do_not_verify_mtproto(self):
        for level in ("tcp","faketls","tls_cover"):
            value = row(observations=[{**observation(),"level":level}])
            self.assertIsNone(select_proxies([value],now=NOW).proxy)

    def test_cover_failure_does_not_cancel_authenticated_result(self):
        value = row()
        value["observations"].append({**observation(),"level":"tls_cover","checked_at":1950,"outcome":"failed"})
        self.assertEqual(select_proxies([value],now=NOW).status,"verified")

    def test_same_network_has_priority_over_oregon(self):
        us = row("us")
        ru = row("ru", "1.1.1.1", observations=[{**observation(),"country":"RU","access_type":"home","network_key":"home-ru","resolved_ip":"1.1.1.1"}])
        selected = select_proxies([us,ru],network="home-ru",now=NOW)
        self.assertEqual(selected.proxy["id"],"ru")
        self.assertIn("РФ",selected.proxy["evidence"]["coverage_label"])

    def test_wrong_network_cannot_cancel_other_network_success(self):
        value = row()
        value["observations"].append({**observation(),"network_key":"ru-mobile","country":"RU","access_type":"mobile",
                                      "outcome":"auth_key_failed","checked_at":1950})
        self.assertEqual(select_proxies([value],network="unknown",now=NOW).status,"verified")
        self.assertIsNone(select_proxies([value],network="ru-mobile",now=NOW).proxy)

    def test_reserves_are_not_same_endpoint_or_subnet(self):
        first, duplicate, backup = row("a"),row("b","8.8.8.9"),row("c","1.1.1.1")
        selected=select_proxies([first,duplicate,backup],now=NOW)
        self.assertEqual(len(selected.proxies),2)

    def test_strict_filter_and_no_fabricated_geography(self):
        value=row(category="RU")
        self.assertIsNone(select_proxies([value],region="RU",now=NOW).proxy)
        self.assertIsNone(select_proxies([value],proxy_type="FakeTLS",now=NOW).proxy)

    def test_changed_dns_address_does_not_inherit_success(self):
        self.assertIsNone(select_proxies([row(resolved_ips=["1.1.1.1"])],now=NOW).proxy)

    def test_oregon_dns_does_not_hide_russian_peer(self):
        value = row(resolved_ips=["1.1.1.1"], observations=[{**observation(), "country":"RU",
                    "network_key":"ru-home", "access_type":"home", "resolved_ip":"8.8.8.8"}])
        self.assertEqual(select_proxies([value], now=NOW).status, "verified")

    def test_sort_uses_measured_duration_within_coverage_tier(self):
        slow, fast = row("slow"), row("fast", "1.1.1.1")
        slow["observations"][0]["duration_ms"] = 1000
        fast["observations"][0]["duration_ms"] = 50
        self.assertEqual(select_proxies([slow, fast], sort_by="ping", now=NOW).proxy["id"], "fast")

    def test_pin_does_not_bypass_validity(self):
        self.assertIsNone(select_proxies([row(admin_recommended=True)],now=2500).proxy)


class AsyncBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_dns_rebinding_is_rejected_before_connect(self):
        records=[(2,1,6,"",("8.8.8.8",443)),(2,1,6,"",("127.0.0.1",443))]
        with patch.object(asyncio.get_running_loop(),"getaddrinfo",AsyncMock(return_value=records)):
            with self.assertRaises(UnsafeTarget):
                await resolve_public_addresses("public.example.com",443)

    async def test_missing_native_engine_is_unknown(self):
        engine=ProbeEngine(library_path="missing-test-library-does-not-exist")
        value=await engine.check("example.com",443,CORE)
        self.assertEqual(value.outcome,"unsupported_checker")
        self.assertIsNone(value.valid_until)

    async def test_native_engine_starts_without_an_account(self):
        engine=ProbeEngine()
        try:
            self.assertTrue(await engine.initialize())
            self.assertNotEqual(engine.status.get("engine_version"),"unknown")
            result=await engine.check("127.0.0.1",443,CORE)
            self.assertEqual(result.outcome,"unsafe_target")
            self.assertIsNone(result.valid_until)
        finally:
            await engine.close()


class AgentInputTests(unittest.TestCase):
    def test_no_implicit_enrollment_or_weak_tokens(self):
        self.assertEqual(parse_agents_config("[]"),[])
        for raw in ('{}','[{"id":"x","token":"weak"}]'):
            with self.assertRaises(ValueError): parse_agents_config(raw)

    def test_tcp_cannot_be_submitted_as_success(self):
        with self.assertRaises(ValueError):
            validate_observation({"outcome":"success","level":"tcp","checked_at":datetime.now(timezone.utc).isoformat()})


if __name__ == "__main__":
    unittest.main()
