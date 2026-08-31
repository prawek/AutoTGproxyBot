"""Real PostgreSQL tests, opt-in with TEST_DATABASE_URL; isolated schema per test."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
import unittest
import uuid

import asyncpg

from app.db.schema import ProxyRepository, UserRepository
from app.db.probes import ProbeRepository, validate_observation
from app.proxy.identity import make_variant_id
from app.proxy.probe_engine import ProbeResult
from app.proxy.selection_service import select_proxies

CORE = "00112233445566778899aabbccddeeff"


class SerializedProbeResultTests(unittest.TestCase):
    def test_actual_success_serialization_accepts_null_error(self):
        result = ProbeResult("success", checked_at=datetime.now(timezone.utc).isoformat(),
                             duration_ms=100, resolved_ip="8.8.8.8", ip_family="ipv4")
        normalized = validate_observation(result.to_dict())
        self.assertEqual(normalized["outcome"], "success")
        self.assertEqual(normalized["error_code"], "")

    def test_unknown_result_preserves_unknown_optional_fields(self):
        result = ProbeResult("unsupported_checker", level="none", checked_at=datetime.now(timezone.utc).isoformat())
        normalized = validate_observation(result.to_dict())
        self.assertIsNone(normalized["valid_until"])
        self.assertEqual(normalized["resolved_ip"], "")

    def test_mismatched_family_is_rejected(self):
        result = ProbeResult("success", checked_at=datetime.now(timezone.utc).isoformat(),
                             duration_ms=100, resolved_ip="8.8.8.8", ip_family="ipv6")
        with self.assertRaises(ValueError):
            validate_observation(result.to_dict())


@unittest.skipUnless(os.getenv("TEST_DATABASE_URL"), "Requires isolated test PostgreSQL")
class PostgresProbeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.dsn = os.environ["TEST_DATABASE_URL"]
        self.schema = "proxy_check_" + uuid.uuid4().hex[:16]
        conn = await asyncpg.connect(self.dsn)
        try:
            await conn.execute('CREATE SCHEMA "' + self.schema + '"')
        finally:
            await conn.close()
        self.pool = await asyncpg.create_pool(self.dsn, min_size=1,max_size=5,server_settings={"search_path":self.schema})
        self.proxies, self.users, self.probes = ProxyRepository(self.pool),UserRepository(self.pool),ProbeRepository(self.pool)
        await self.proxies.migrate()
        await self.users.migrate()
        await self.proxies.migrate()  # Repeat migration must be idempotent.
        self.variant=make_variant_id("8.8.8.8",443,CORE)
        await self.proxies.upsert_many([{"host":"8.8.8.8","port":443,"secret":CORE,"generation":"plain"}])
        await self.probes.configure_agents_from_env(json.dumps([{"id":"test-agent","token":"a"*48,"country":"RU","network_key":"home-test","access_type":"home"}]))
        self.agent=await self.probes.authenticate("a"*48)
        await self.probes.heartbeat(self.agent,{"healthy":True,"network_epoch":"epoch-1","engine_name":"tdlib"})

    async def asyncTearDown(self):
        await self.pool.close()
        conn=await asyncpg.connect(self.dsn)
        try:
            await conn.execute('DROP SCHEMA "' + self.schema + '" CASCADE')
        finally:
            await conn.close()

    async def claim(self):
        await self.probes.enqueue(self.variant,"test-agent")
        return (await self.probes.claim(self.agent,limit=1))[0]

    def result(self,job):
        return {"job_id":job["id"],"attempt_id":job["attempt_id"],"lease_token":job["lease_token"],"result":{
            "outcome":"success","level":"auth_key","checked_at":datetime.now(timezone.utc).isoformat(),
            "duration_ms":100,"dc_id":2,"resolved_ip":"8.8.8.8","ip_family":"ipv4",
            "engine_name":"tdlib","engine_version":"test","client_profile_id":"test"}}

    async def test_concurrent_claims_and_duplicate_results(self):
        self.assertTrue(await self.probes.enqueue(self.variant,"test-agent"))
        self.assertFalse(await self.probes.enqueue(self.variant,"test-agent"))
        first,second=await asyncio.gather(self.probes.claim(self.agent),self.probes.claim(self.agent))
        self.assertEqual(len(first)+len(second),1)
        job=(first or second)[0]
        body=self.result(job)
        self.assertFalse((await self.probes.complete(self.agent,body))["duplicate"])
        self.assertTrue((await self.probes.complete(self.agent,body))["duplicate"])
        async with self.pool.acquire() as conn:
            self.assertEqual(await conn.fetchval("SELECT COUNT(*) FROM probe_observations"),1)
        snapshot=await self.proxies.get_selection_snapshot()
        self.assertEqual(snapshot[0]["observations"][0]["country"],"ru")

    async def test_replaced_lease_rejects_old_result(self):
        job=await self.claim()
        async with self.pool.acquire() as conn:
            await conn.execute("UPDATE probe_jobs SET lease_until=NOW()-INTERVAL '1 second' WHERE id=$1",job["id"])
        replacement=(await self.probes.claim(self.agent))[0]
        self.assertNotEqual(job["attempt_id"],replacement["attempt_id"])
        with self.assertRaises(ValueError): await self.probes.complete(self.agent,self.result(job))
        self.assertTrue((await self.probes.complete(self.agent,self.result(replacement)))["ok"])

    async def test_epoch_change_rejects_inflight_measurement(self):
        job=await self.claim()
        await self.probes.heartbeat(self.agent,{"healthy":True,"network_epoch":"epoch-2"})
        with self.assertRaises(ValueError): await self.probes.complete(self.agent,self.result(job))
        # Old leases stop occupying slots immediately after an explicit route change.
        self.assertEqual(await self.probes.schedule_once(),1)
        replacement=(await self.probes.claim(self.agent,limit=1))[0]
        self.assertEqual(replacement["network_epoch"],"epoch-2")

    async def test_epoch_change_excludes_old_proof_and_allows_recheck(self):
        job=await self.claim()
        await self.probes.complete(self.agent,self.result(job))
        self.assertIn(self.variant,await self.probes.latest_observations([self.variant]))
        await self.probes.heartbeat(self.agent,{"healthy":True,"network_epoch":"epoch-2"})
        self.assertEqual(await self.probes.latest_observations([self.variant]),{})
        self.assertEqual(await self.probes.schedule_once(),1)
        async with self.pool.acquire() as conn:
            self.assertEqual(await conn.fetchval("SELECT COUNT(*) FROM probe_observations"),1)

    async def test_revocation_excludes_remote_proof_but_preserves_local(self):
        job=await self.claim()
        await self.probes.complete(self.agent,self.result(job))
        local=self.result(job)["result"]
        local["variant_id"]=self.variant
        await self.probes.record_local_observation(local)
        self.assertEqual(len((await self.probes.latest_observations([self.variant]))[self.variant]),2)
        await self.probes.configure_agents_from_env("[]")
        latest=(await self.probes.latest_observations([self.variant]))[self.variant]
        self.assertEqual([value["agent_id"] for value in latest],["oregon"])
        async with self.pool.acquire() as conn:
            self.assertEqual(await conn.fetchval("SELECT COUNT(*) FROM probe_observations"),2)

    async def test_configured_network_change_excludes_old_proof(self):
        job=await self.claim()
        await self.probes.complete(self.agent,self.result(job))
        await self.probes.configure_agents_from_env(json.dumps([{"id":"test-agent","token":"a"*48,
            "country":"US","network_key":"home-test","access_type":"home"}]))
        await self.probes.heartbeat(self.agent,{"healthy":True,"network_epoch":"epoch-1"})
        self.assertEqual(await self.probes.latest_observations([self.variant]),{})
        self.assertEqual(await self.probes.schedule_once(),1)

    async def test_agent_revocation_and_scheduler(self):
        self.assertEqual(await self.probes.schedule_once(),1)
        self.assertEqual(await self.probes.schedule_once(),0)
        await self.probes.configure_agents_from_env("[]")
        self.assertIsNone(await self.probes.authenticate("a"*48))
        self.assertEqual(await self.probes.claim(self.agent),[])

    async def test_variant_identity_and_tombstone(self):
        await self.proxies.upsert_many([{"host":"8.8.8.8","port":443,"secret":"ff"*16,"generation":"plain"}])
        self.assertEqual(len(await self.proxies.get_selection_snapshot()),2)
        await self.proxies.delete_by_ids([self.variant])
        await self.proxies.upsert_many([{"host":"8.8.8.8","port":443,"secret":CORE,"generation":"plain"}])
        self.assertEqual(len(await self.proxies.get_selection_snapshot()),1)

    async def test_local_measurement_preserves_discovery_age_and_dns_metadata(self):
        async with self.pool.acquire() as conn:
            original=await conn.fetchval("UPDATE proxies SET last_seen_at=NOW()-INTERVAL '2 hours' WHERE id=$1 RETURNING last_seen_at",self.variant)
        result=ProbeResult("success",checked_at=datetime.now(timezone.utc).isoformat(),duration_ms=100,
                           resolved_ip="8.8.8.8",ip_family="ipv4").to_dict()
        result.update(variant_id=self.variant,resolved_ips=["8.8.8.8","8.8.4.4"])
        await self.proxies.record_observation(result)
        snapshot=await self.proxies.get_selection_snapshot()
        self.assertEqual(snapshot[0]["last_seen_at"],original)
        self.assertEqual(snapshot[0]["resolved_ips"],["8.8.8.8","8.8.4.4"])
        self.assertEqual(select_proxies(snapshot).status,"verified")
        # A fresh discovery must not clear the separately persisted checker facts.
        await self.proxies.upsert_many([{"host":"8.8.8.8","port":443,"secret":CORE,"generation":"plain"}])
        rediscovered=(await self.proxies.get_selection_snapshot())[0]
        self.assertEqual(rediscovered["probe_state"],"success")
        self.assertEqual(rediscovered["resolved_ips"],["8.8.8.8","8.8.4.4"])

    async def test_admin_filters_and_pin_require_current_evidence(self):
        async with self.pool.acquire() as conn:
            await conn.execute("UPDATE proxies SET is_alive=TRUE WHERE id=$1",self.variant)
        rows,total=await self.proxies.list_proxies(alive_only=True)
        self.assertEqual((rows,total),([],0))
        self.assertIsNone(await self.proxies.set_admin_recommendation(self.variant,True))
        job=await self.claim()
        await self.probes.complete(self.agent,self.result(job))
        rows,total=await self.proxies.list_proxies(alive_only=True)
        self.assertEqual(total,1)
        self.assertEqual(rows[0]["evidence"]["probe_country"],"ru")
        self.assertTrue(await self.proxies.set_admin_recommendation(self.variant,True))
        stats=await self.proxies.stats()
        self.assertEqual((stats["total"],stats["catalog_sampled"],stats["alive"],stats["ru"]),(1,1,1,1))
        await self.proxies.delete_by_ids([self.variant])
        rows,total=await self.proxies.list_proxies(alive_only=True)
        self.assertEqual((rows,total),([],0))
        rows,total=await self.proxies.list_proxies(alive_only=False)
        self.assertEqual(rows[0]["evidence"]["status"],"blocked")
        self.assertIsNone(await self.proxies.set_admin_recommendation(self.variant,True))
        self.assertTrue(await self.proxies.set_admin_recommendation(self.variant,False))
        self.assertEqual((await self.proxies.stats())["blocked"],1)

    async def test_registration_and_session_epoch(self):
        await self.users.upsert_user(123,username="tg_owner")
        with self.assertRaises(ValueError): await self.users.register_existing_telegram_user("tg_owner","password12345")
        user=await self.users.create_web_user("web_user","password12345")
        self.assertLess(user["telegram_id"],0)
        await self.users.set_credentials(user["telegram_id"],"web_user","new-password123")
        refreshed=await self.users.get_user(user["telegram_id"])
        self.assertGreater(refreshed["session_version"],user["session_version"])
        self.assertIsNone(await self.users.login_user("web_user","password12345"))
        self.assertTrue(await self.users.login_user("web_user","new-password123"))

    async def test_concurrent_start_does_not_replace_generated_password(self):
        await self.users.upsert_user(998877, username="start_race")
        credentials = await asyncio.gather(*(self.users.ensure_credentials(998877) for _ in range(2)))
        issued = [(login, password) for login, password in credentials if password]
        self.assertEqual(len(issued), 1)
        self.assertTrue(await self.users.login_user(*issued[0]))

    async def test_snapshot_retains_fresh_proof_with_limited_capacity(self):
        from app.proxy.probe_engine import ProbeResult
        await self.proxies.record_observation({**ProbeResult("success", checked_at=datetime.now(timezone.utc).isoformat(),
            resolved_ip="8.8.8.8", ip_family="ipv4", duration_ms=10).to_dict(), "variant_id":self.variant})
        await self.proxies.upsert_many([{"host":"1.1.1.1", "port":443, "secret":CORE}])
        # With equal source ages a fresh confirmation must survive a small limit.
        async with self.pool.acquire() as conn:
            await conn.execute("UPDATE proxies SET last_seen_at=NOW()")
        self.assertEqual((await self.proxies.get_selection_snapshot(limit=1))[0]["id"], self.variant)

    async def test_positive_telegram_identity_cannot_be_transferred(self):
        await self.users.upsert_user(123,username="owner")
        await self.users.set_credentials(123,"owner","password12345")
        self.assertFalse(await self.users.link_tg_to_existing(456,"owner","password12345"))


if __name__ == "__main__": unittest.main()
