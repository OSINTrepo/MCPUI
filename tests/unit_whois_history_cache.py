"""Повторные и параллельные запросы не покупают одну историю WHOIS заново."""
import asyncio
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "servers"))
from common import whois_history_cache as CACHE


ACCOUNT = "a-private-account-key-for-unit-tests"
PROVIDER = "WhoisXML"


def payload(domain="example.com", rows=24):
    return {"domain": domain, "source": PROVIDER, "records_count": rows,
            "records": [{"registrant": f"Организация {index}",
                         "audit": {"createdDate": f"2026-09-{index + 1:02d}"},
                         "nameServers": ["ns.example.com"], "status": ["ok"]}
                        for index in range(rows)]}


def another_client():
    spec = importlib.util.spec_from_file_location("another_history_cache_client", Path(CACHE.__file__))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HistoryCache(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.environment = patch.dict(os.environ, {"WHOIS_HISTORY_CACHE_DIR": self.directory.name,
                                                   "WHOIS_HISTORY_CACHE_TTL_SECONDS": "86400"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    async def call(self, fetch, *, account=ACCOUNT, domain="example.com", force=False, module=CACHE):
        return await module.get_history(domain, PROVIDER, account, fetch, force_refresh=force)

    async def test_persistence_exact_payload_private_files_and_original_freshness(self):
        body = payload()
        fetch = AsyncMock(return_value=body)
        first = await self.call(fetch)
        second = await self.call(fetch, module=another_client())
        self.assertEqual(first["cache"]["status"], "miss")
        self.assertEqual(second["cache"]["status"], "hit")
        self.assertEqual(first["cache"]["fetched_at"], second["cache"]["fetched_at"])
        self.assertEqual(first["cache"]["expires_at"], second["cache"]["expires_at"])
        self.assertEqual({k: v for k, v in second.items() if k != "cache"}, body)
        fetch.assert_awaited_once()
        # Изменение ответа клиентом не влияет на следующего читателя.
        second["records"][0]["registrant"] = "changed by caller"
        self.assertEqual((await self.call(fetch))["records"], body["records"])
        for path in Path(self.directory.name).rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertNotIn(ACCOUNT, path.read_text())
            else:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    async def test_different_wrapper_modules_share_one_cold_purchase(self):
        async def paid_fetch():
            await asyncio.sleep(0.15)
            return payload()
        fetch = AsyncMock(side_effect=paid_fetch)
        results = await asyncio.gather(self.call(fetch), self.call(fetch, module=another_client()),
                                       self.call(fetch))
        fetch.assert_awaited_once()
        self.assertEqual(sorted(r["cache"]["status"] for r in results), ["hit", "hit", "miss"])
        self.assertTrue(all(r["records_count"] == 24 for r in results))

    async def test_two_processes_share_one_cold_purchase(self):
        script = """
import asyncio, json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from common.whois_history_cache import get_history
async def fetch():
    with open(os.environ['PURCHASE_LOG'], 'a') as stream:
        stream.write('purchase\\n')
    await asyncio.sleep(0.25)
    return {'domain': 'example.com', 'source': 'WhoisXML', 'records_count': 1,
            'records': [{'registrant': 'Cross-process organization'}]}
async def main():
    result = await get_history('example.com', 'WhoisXML', 'cross-process-private-key', fetch)
    print(json.dumps(result))
asyncio.run(main())
"""
        environment = {**os.environ, "PURCHASE_LOG": str(Path(self.directory.name) / "purchases.txt")}
        processes = await asyncio.gather(*[
            asyncio.create_subprocess_exec(sys.executable, "-c", script, str(ROOT / "servers"),
                                           env=environment, stdout=asyncio.subprocess.PIPE,
                                           stderr=asyncio.subprocess.PIPE)
            for _ in range(2)
        ])
        output = await asyncio.gather(*(process.communicate() for process in processes))
        for process, (stdout, stderr) in zip(processes, output):
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertEqual(json.loads(stdout)["records_count"], 1)
        self.assertEqual(Path(environment["PURCHASE_LOG"]).read_text().splitlines(), ["purchase"])

    async def test_canonical_idna_domain_deduplicates_case_and_trailing_dot(self):
        body = payload("xn--e1afmkfd.xn--p1ai")
        fetch = AsyncMock(return_value=body)
        first = await self.call(fetch, domain="ПРИМЕР.РФ.")
        second = await self.call(fetch, domain="xn--e1afmkfd.xn--p1ai")
        self.assertEqual(second["cache"]["status"], "hit")
        self.assertEqual(first["records"], second["records"])
        fetch.assert_awaited_once()

    def test_invalid_hostnames_raise_value_error(self):
        for domain in (None, "", "https://example.com", "example.com/path", "bad_.com", "-bad.com"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                CACHE.canonical_domain(domain)

    async def test_account_keys_are_isolated(self):
        fetch = AsyncMock(return_value=payload())
        await self.call(fetch)
        different = await self.call(fetch, account="a-different-private-account-key")
        self.assertEqual(different["cache"]["status"], "miss")
        self.assertEqual(fetch.await_count, 2)

    async def test_provider_names_are_isolated(self):
        fetch = AsyncMock(return_value=payload())
        await self.call(fetch)
        other_body = {**payload(), "source": "Whoxy"}
        other = AsyncMock(return_value=other_body)
        result = await CACHE.get_history("example.com", "Whoxy", ACCOUNT, other)
        self.assertEqual(result["cache"]["status"], "miss")
        other.assert_awaited_once()

    async def test_expired_history_is_refetched_without_stale_fallback(self):
        fetch = AsyncMock(return_value=payload())
        with patch.object(CACHE.time, "time", return_value=1000000):
            first = await self.call(fetch)
        with patch.object(CACHE.time, "time", return_value=1086401):
            fetch.side_effect = RuntimeError("provider unavailable")
            with self.assertRaises(RuntimeError):
                await self.call(fetch)
            fetch.side_effect = None
            fetch.return_value = payload(rows=25)
            result = await self.call(fetch)
        self.assertEqual(result["cache"]["status"], "miss")
        self.assertNotEqual(result["cache"]["fetched_at"], first["cache"]["fetched_at"])
        self.assertEqual(result["records_count"], 25)
        self.assertEqual(fetch.await_count, 3)

    async def test_ttl_reduction_invalidates_previously_fresh_history(self):
        fetch = AsyncMock(return_value=payload())
        with patch.object(CACHE.time, "time", return_value=1000000):
            await self.call(fetch)
        with patch.dict(os.environ, {"WHOIS_HISTORY_CACHE_TTL_SECONDS": "60"}), \
                patch.object(CACHE.time, "time", return_value=1000061):
            result = await self.call(fetch)
        self.assertEqual(result["cache"]["status"], "miss")
        self.assertEqual(fetch.await_count, 2)

    async def test_empty_history_has_at_most_one_hour_ttl(self):
        fetch = AsyncMock(return_value=payload(rows=0))
        with patch.object(CACHE.time, "time", return_value=1000000):
            first = await self.call(fetch)
        self.assertEqual(first["cache"]["ttl_seconds"], 3600)
        with patch.object(CACHE.time, "time", return_value=1003599):
            self.assertEqual((await self.call(fetch))["cache"]["status"], "hit")
        with patch.object(CACHE.time, "time", return_value=1003601):
            self.assertEqual((await self.call(fetch))["cache"]["status"], "miss")
        self.assertEqual(fetch.await_count, 2)

    async def test_errors_incomplete_and_secret_containing_responses_are_not_persisted(self):
        invalid = [
            {"domain": "example.com", "error": "quota exhausted", "error_type": "quota_exhausted"},
            {**payload(), "provider_errors": [{"error": "fallback failed"}]},
            {**payload(), "records_count": 999},
            {**payload(), "truncated": True},
            {**payload(), "source": "Whoxy"},
            {**payload(), "records": [None] * 24},
            {**payload(), "debug": ACCOUNT},
        ]
        for body in invalid:
            with self.subTest(body=body.get("error_type", body.get("records_count"))):
                fetch = AsyncMock(return_value=body)
                await self.call(fetch)
                result = await self.call(fetch)
                self.assertEqual(result["cache"]["status"], "unavailable")
                self.assertEqual(fetch.await_count, 2)
                self.assertEqual(list(Path(self.directory.name).rglob("*.json")), [])

    async def test_unavailable_cache_fetches_once_and_reports_unavailability(self):
        fetch = AsyncMock(return_value=payload())
        with patch.object(CACHE, "_paths", side_effect=PermissionError("not writable")):
            result = await self.call(fetch)
        self.assertEqual(result["records_count"], 24)
        self.assertEqual(result["cache"]["status"], "unavailable")
        self.assertEqual(result["cache"]["reason"], "storage_unavailable")
        fetch.assert_awaited_once()

    async def test_write_failure_does_not_repeat_paid_fetch(self):
        fetch = AsyncMock(return_value=payload())
        with patch.object(CACHE, "_write", side_effect=OSError("disk full")):
            result = await self.call(fetch)
        fetch.assert_awaited_once()
        self.assertEqual(result["cache"]["status"], "unavailable")

    async def test_provider_oserror_is_not_confused_with_cache_failure(self):
        fetch = AsyncMock(side_effect=OSError("provider connection lost"))
        with self.assertRaises(OSError):
            await self.call(fetch)
        fetch.assert_awaited_once()
        self.assertEqual(list(Path(self.directory.name).rglob("*.json")), [])

    async def test_corrupt_json_and_count_mismatch_trigger_refetch(self):
        fetch = AsyncMock(return_value=payload())
        await self.call(fetch)
        file = next(Path(self.directory.name).rglob("*.json"))
        file.write_text("{bad json")
        self.assertEqual((await self.call(fetch))["cache"]["status"], "miss")
        entry = json.loads(file.read_text())
        entry["payload"]["records_count"] = 999
        file.write_text(json.dumps(entry))
        self.assertEqual((await self.call(fetch))["cache"]["status"], "miss")
        self.assertEqual(fetch.await_count, 3)

    async def test_explicit_refresh_and_concurrent_refresh_deduplication(self):
        async def paid_fetch():
            await asyncio.sleep(0.1)
            return payload()
        fetch = AsyncMock(side_effect=paid_fetch)
        original = await self.call(fetch)
        refreshed, reused = await asyncio.gather(self.call(fetch, force=True),
                                                self.call(fetch, force=True, module=another_client()))
        self.assertEqual(fetch.await_count, 2)
        self.assertEqual(sorted([refreshed["cache"]["status"], reused["cache"]["status"]]), ["hit", "refresh"])
        self.assertNotEqual(original["cache"]["fetched_at"], refreshed["cache"]["fetched_at"])
        self.assertEqual(refreshed["cache"]["fetched_at"], reused["cache"]["fetched_at"])

    async def test_client_cancellation_keeps_paid_fetch_and_saves_result(self):
        started, finish = asyncio.Event(), asyncio.Event()
        async def paid_fetch():
            started.set()
            await finish.wait()
            return payload()
        fetch = AsyncMock(side_effect=paid_fetch)
        client = asyncio.create_task(self.call(fetch))
        await started.wait()
        client.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await client
        finish.set()
        second = await self.call(fetch)
        self.assertEqual(second["cache"]["status"], "hit")
        fetch.assert_awaited_once()

    async def test_seed_preserves_original_date_and_never_overwrites_newer(self):
        original_time = datetime.fromtimestamp(time.time() - 120, timezone.utc).isoformat()
        seeded = await CACHE.seed_history("example.com", PROVIDER, ACCOUNT,
                                          fetched_at=original_time, payload=payload())
        self.assertIsNotNone(seeded)
        self.assertGreaterEqual(seeded["age_seconds"], 120)
        fetch = AsyncMock(return_value=payload(rows=25))
        result = await self.call(fetch)
        fetch.assert_not_awaited()
        self.assertEqual(CACHE._timestamp(result["cache"]["fetched_at"]), CACHE._timestamp(original_time))
        older_time = datetime.fromtimestamp(time.time() - 240, timezone.utc).isoformat()
        await CACHE.seed_history("example.com", PROVIDER, ACCOUNT,
                                 fetched_at=older_time, payload=payload(rows=10))
        self.assertEqual((await self.call(fetch))["records_count"], 24)

    async def test_seed_rejects_expired_future_and_failed_history(self):
        for timestamp, body in [
            (time.time() - 86401, payload()), (time.time() + 60, payload()),
            (time.time() - 60, {**payload(), "error": "incomplete"}),
        ]:
            seeded = await CACHE.seed_history("example.com", PROVIDER, ACCOUNT,
                                              fetched_at=datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
                                              payload=body)
            self.assertIsNone(seeded)
        self.assertEqual(list(Path(self.directory.name).rglob("*.json")), [])

    async def test_disabled_ttl_never_reads_or_writes_cache(self):
        fetch = AsyncMock(return_value=payload())
        with patch.dict(os.environ, {"WHOIS_HISTORY_CACHE_TTL_SECONDS": "0"}):
            for _ in range(2):
                result = await self.call(fetch)
                self.assertEqual(result["cache"]["reason"], "disabled")
        self.assertEqual(fetch.await_count, 2)
        self.assertEqual(list(Path(self.directory.name).rglob("*.json")), [])


if __name__ == "__main__":
    unittest.main()
