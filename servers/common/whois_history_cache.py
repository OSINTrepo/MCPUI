"""Общий дисковый кэш оплаченной истории WHOIS без хранения API-ключей.

Блокировка действует на пару провайдер/аккаунт и домен между процессами.
При отмене вызывающего запроса уже начатая покупка завершается и сохраняется.
"""
from __future__ import annotations

import asyncio
import copy
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Awaitable, Callable


DEFAULT_TTL_SECONDS = 86400
EMPTY_TTL_SECONDS = 3600
DEFAULT_CACHE_DIR = "/var/cache/osint/whois-history"
_PENDING: set[asyncio.Task] = set()
_FAILURE_FIELDS = ("error", "error_type", "provider_errors", "partial", "truncated", "incomplete")


def canonical_domain(domain: str) -> str:
    """Один ключ для ASCII/IDNA, регистра букв и конечной точки DNS."""
    if not isinstance(domain, str):
        raise ValueError("invalid domain")
    value = domain.strip().rstrip(".").encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if len(value) > 253 or not value or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("invalid domain")
    return value


def _ttl(payload: dict | None = None) -> float:
    try:
        result = float(os.getenv("WHOIS_HISTORY_CACHE_TTL_SECONDS", str(DEFAULT_TTL_SECONDS)))
        if not math.isfinite(result):
            raise ValueError
    except ValueError:
        result = float(DEFAULT_TTL_SECONDS)
    result = max(0.0, result)
    if payload is not None and payload.get("records_count") == 0:
        result = min(result, EMPTY_TTL_SECONDS)
    return result


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp(value: str | datetime) -> float:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
    if not isinstance(parsed, datetime) or parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.timestamp()


def _paths(domain: str, provider: str, account_key: str) -> tuple[Path, Path]:
    root = Path(os.getenv("WHOIS_HISTORY_CACHE_DIR", DEFAULT_CACHE_DIR))
    provider_hash = hashlib.sha256(provider.strip().casefold().encode()).hexdigest()
    account_hash = hashlib.sha256(account_key.encode()).hexdigest()
    directory = root / provider_hash / account_hash
    # Все уровни собственного каталога приватны; ключ существует только в памяти.
    for path in (root, root / provider_hash, directory):
        if path.is_symlink():
            raise OSError("cache directory is a symbolic link")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    name = hashlib.sha256(domain.encode()).hexdigest()
    return directory / (name + ".json"), directory / (name + ".lock")


async def _lock(path: Path) -> int:
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EINTR):
                    raise
                await asyncio.sleep(0.05)
    except BaseException:
        os.close(fd)
        raise


def _cacheable(payload: object, domain: str, provider: str, account_key: str) -> bool:
    if not isinstance(payload, dict) or any(payload.get(field) for field in _FAILURE_FIELDS):
        return False
    records = payload.get("records")
    count = payload.get("records_count")
    if not isinstance(records, list) or type(count) is not int or count != len(records):
        return False
    if any(not isinstance(record, dict) for record in records):
        return False
    try:
        if canonical_domain(payload.get("domain", "")) != domain:
            return False
        if payload.get("source", "").strip().casefold() != provider.strip().casefold():
            return False
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return False
    # Не записываем даже случайно попавший в успешный ответ секрет.
    return not account_key or account_key not in encoded


def _read(path: Path, domain: str, provider: str, account_key: str, now: float) -> dict | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            entry = json.load(stream)
        if not isinstance(entry, dict) or entry.get("version") != 1:
            return None
        payload = entry.get("payload")
        if not _cacheable(payload, domain, provider, account_key):
            return None
        fetched_at = _timestamp(entry["fetched_at"])
        expires_at = _timestamp(entry["expires_at"])
        stored_ttl = float(entry["ttl_seconds"])
        if not math.isfinite(stored_ttl) or stored_ttl <= 0 or fetched_at > now:
            return None
        if abs(expires_at - fetched_at - stored_ttl) > 0.001:
            return None
        effective_ttl = min(stored_ttl, _ttl(payload))
        if now >= fetched_at + effective_ttl:
            return None
        # Уменьшение настройки TTL распространяется и на сохранённые ответы.
        return {**entry, "ttl_seconds": effective_ttl, "expires_at": _iso(fetched_at + effective_ttl)}
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        return None


def _write(path: Path, entry: dict) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=path.name + ".", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            json.dump(entry, stream, ensure_ascii=False, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _entry(payload: dict, fetched_at: float) -> dict:
    ttl = _ttl(payload)
    safe_payload = copy.deepcopy(payload)
    safe_payload.pop("cache", None)
    return {"version": 1, "payload": safe_payload, "fetched_at": _iso(fetched_at),
            "expires_at": _iso(fetched_at + ttl), "ttl_seconds": ttl}


def _result(entry: dict, status: str, *, reason: str | None = None) -> dict:
    result = copy.deepcopy(entry["payload"])
    result["cache"] = {"status": status, "fetched_at": entry["fetched_at"],
                       "expires_at": entry["expires_at"],
                       "age_seconds": max(0.0, time.time() - _timestamp(entry["fetched_at"])),
                       "ttl_seconds": entry["ttl_seconds"]}
    if reason:
        result["cache"]["reason"] = reason
    return result


async def _fresh(fetch: Callable[[], Awaitable[dict]], status: str, *, reason: str | None = None) -> dict:
    payload = await fetch()
    if not isinstance(payload, dict):
        raise TypeError("history fetch must return a dictionary")
    return _result(_entry(payload, time.time()), status, reason=reason)


async def _get_history(domain: str, provider: str, account_key: str,
                       fetch: Callable[[], Awaitable[dict]], force_refresh: bool,
                       started_at: float) -> dict:
    if _ttl() <= 0:
        return await _fresh(fetch, "unavailable", reason="disabled")
    try:
        canonical = canonical_domain(domain)
    except (AttributeError, UnicodeError, ValueError):
        return await _fresh(fetch, "unavailable", reason="invalid_domain")
    if not account_key or not provider.strip():
        return await _fresh(fetch, "unavailable", reason="missing_cache_scope")
    try:
        path, lock_path = _paths(canonical, provider, account_key)
        fd = await _lock(lock_path)
    except OSError:
        return await _fresh(fetch, "unavailable", reason="storage_unavailable")
    try:
        try:
            entry = _read(path, canonical, provider, account_key, time.time())
        except OSError:
            return await _fresh(fetch, "unavailable", reason="storage_unavailable")
        if entry is not None and (not force_refresh or _timestamp(entry["fetched_at"]) >= started_at):
            return _result(entry, "hit")
        # Ошибки fetch не перехватываем и не повторяем: покупка могла уже пройти.
        payload = await fetch()
        if not isinstance(payload, dict):
            raise TypeError("history fetch must return a dictionary")
        entry = _entry(payload, time.time())
        if not _cacheable(payload, canonical, provider, account_key):
            return _result(entry, "unavailable", reason="response_not_cacheable")
        try:
            _write(path, entry)
        except (OSError, ValueError, TypeError):
            return _result(entry, "unavailable", reason="storage_unavailable")
        return _result(entry, "refresh" if force_refresh else "miss")
    finally:
        os.close(fd)  # flock освобождается вместе с файловым дескриптором.


async def get_history(domain: str, provider: str, account_key: str,
                      fetch: Callable[[], Awaitable[dict]], force_refresh: bool = False) -> dict:
    """Получить полный ответ; повторные покупки объединяются общей блокировкой.

    fetch не получает аргументов и возвращает нормализованный dict. TTL и каталог
    читаются из окружения при каждом обращении. force_refresh обновляет историю,
    но одновременно начавшиеся обновления используют одну завершённую покупку.
    """
    task = asyncio.create_task(_get_history(domain, provider, account_key, fetch,
                                           force_refresh, time.time()))
    _PENDING.add(task)
    def completed(finished: asyncio.Task) -> None:
        _PENDING.discard(finished)
        if not finished.cancelled():
            finished.exception()  # Получаем отказ и при отменённом внешнем клиенте.
    task.add_done_callback(completed)
    return await asyncio.shield(task)


async def seed_history(domain: str, provider: str, account_key: str, *, fetched_at: str | datetime,
                       payload: dict) -> dict | None:
    """Импортировать уже оплаченную историю с исходной датой, без сетевого запроса.

    Возвращает метаданные импортированного/более свежего ответа либо None, если
    ответ просрочен, некорректен или хранилище недоступно. Секрет не сохраняется.
    """
    try:
        canonical = canonical_domain(domain)
        timestamp = _timestamp(fetched_at)
    except (AttributeError, UnicodeError, ValueError, TypeError, OverflowError):
        return None
    now = time.time()
    if (not account_key or not provider.strip()
            or not _cacheable(payload, canonical, provider, account_key)
            or timestamp > now or timestamp + _ttl(payload) <= now):
        return None
    try:
        path, lock_path = _paths(canonical, provider, account_key)
        fd = await _lock(lock_path)
    except OSError:
        return None
    try:
        try:
            # Ожидание другой покупки могло занять весь оставшийся TTL импорта.
            if timestamp + _ttl(payload) <= time.time():
                return None
            existing = _read(path, canonical, provider, account_key, time.time())
            if existing is not None and _timestamp(existing["fetched_at"]) >= timestamp:
                return _result(existing, "hit")["cache"]
            entry = _entry(payload, timestamp)
            _write(path, entry)
            return _result(entry, "hit")["cache"]
        except (OSError, ValueError, TypeError):
            return None
    finally:
        os.close(fd)
