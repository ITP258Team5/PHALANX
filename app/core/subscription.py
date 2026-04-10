"""
Phalanx Subscription Manager

Validates user authentication and subscription status against the
Phalanx cloud API. Implements the lifecycle:

  ACTIVE → GRACE_PERIOD (7 days) → LAPSED

Refactored to use core.database (subscription_state table) instead
of a standalone JSON file.
"""

import asyncio
import hashlib
import logging
import time
from enum import Enum
from pathlib import Path
from typing import Optional

import aiohttp

import config
from core.database import get_connection, transaction

logger = logging.getLogger("phalanx.subscription")


class SubStatus(str, Enum):
    ACTIVE = "active"
    GRACE = "grace"
    LAPSED = "lapsed"
    UNKNOWN = "unknown"
    NOT_AUTHENTICATED = "not_authenticated"


class SubscriptionManager:
    """
    Manages user authentication state and subscription status.

    State is persisted in the subscription_state table so everything
    lives in one SQLite file. The device can boot and function even
    if the cloud API is temporarily unreachable.
    """

    def __init__(self):
        self._cache: dict[str, str] = {}
        self._load_state()

    # ── State persistence via subscription_state table ──

    def _load_state(self):
        """Load all key-value pairs from subscription_state into memory."""
        try:
            conn = get_connection()
            rows = conn.execute("SELECT key, value FROM subscription_state").fetchall()
            self._cache = {r["key"]: r["value"] for r in rows}
        except Exception:
            self._cache = {}

        # Ensure device serial is set
        if "device_serial" not in self._cache:
            self._set("device_serial", self._detect_device_serial())

    def _get(self, key: str, default: str = "") -> str:
        return self._cache.get(key, default)

    def _set(self, key: str, value: str):
        self._cache[key] = value
        now = time.time()
        conn = get_connection()
        conn.execute(
            """INSERT INTO subscription_state (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value,
                   updated_at = excluded.updated_at""",
            (key, value, now),
        )
        conn.commit()

    def _set_many(self, pairs: dict[str, str]):
        """Batch-set multiple keys in one transaction."""
        now = time.time()
        self._cache.update(pairs)
        conn = get_connection()
        with transaction(conn):
            for key, value in pairs.items():
                conn.execute(
                    """INSERT INTO subscription_state (key, value, updated_at)
                       VALUES (?, ?, ?)
                       ON CONFLICT(key) DO UPDATE SET
                           value = excluded.value,
                           updated_at = excluded.updated_at""",
                    (key, value, now),
                )

    @staticmethod
    def _detect_device_serial() -> str:
        """Derive a stable device ID from hardware."""
        try:
            cpuinfo = Path("/proc/cpuinfo").read_text()
            for line in cpuinfo.splitlines():
                if line.strip().startswith("Serial"):
                    serial = line.split(":")[1].strip()
                    return hashlib.sha256(serial.encode()).hexdigest()[:16]
        except Exception:
            pass
        try:
            mac = Path("/sys/class/net/eth0/address").read_text().strip()
            return hashlib.sha256(mac.encode()).hexdigest()[:16]
        except Exception:
            return "unknown-device"

    # ── Public properties ──

    @property
    def status(self) -> SubStatus:
        raw = self._get("status", SubStatus.NOT_AUTHENTICATED.value)
        try:
            return SubStatus(raw)
        except ValueError:
            return SubStatus.NOT_AUTHENTICATED

    @property
    def is_authenticated(self) -> bool:
        return bool(self._get("session_token"))

    @property
    def is_subscription_active(self) -> bool:
        return self.status in (SubStatus.ACTIVE, SubStatus.GRACE)

    @property
    def days_until_freeze(self) -> Optional[int]:
        if self.status != SubStatus.GRACE:
            return None
        grace_start = float(self._get("grace_started", "0"))
        elapsed = (time.time() - grace_start) / 86400
        remaining = config.SUBSCRIPTION_GRACE_PERIOD - elapsed
        return max(0, int(remaining))

    @property
    def user_id(self) -> Optional[str]:
        uid = self._get("user_id")
        return uid if uid else None

    @property
    def device_serial(self) -> str:
        return self._get("device_serial", "unknown")

    # ── Auth flow ──

    async def authenticate(self, email: str, password: str) -> dict:
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            ) as session:
                async with session.post(
                    f"{config.SUBSCRIPTION_API_URL}/auth/login",
                    json={
                        "email": email,
                        "password": password,
                        "device_serial": self.device_serial,
                    },
                ) as resp:
                    data = await resp.json()

                    if resp.status == 200 and data.get("success"):
                        self._set_many({
                            "user_id": data["user_id"],
                            "session_token": data["token"],
                            "status": SubStatus.ACTIVE.value,
                            "expires_at": str(data.get("expires_at", 0)),
                            "last_check": str(time.time()),
                            "grace_started": "0",
                        })
                        logger.info("User %s authenticated successfully", data["user_id"])
                        return {"success": True, "message": "Signed in successfully"}

                    return {
                        "success": False,
                        "message": data.get("error", "Authentication failed"),
                    }

        except Exception as e:
            logger.error("Authentication request failed: %s", e)
            return {
                "success": False,
                "message": "Could not reach Phalanx servers. Please check your connection.",
            }

    async def check_subscription(self) -> SubStatus:
        if not self.is_authenticated:
            return SubStatus.NOT_AUTHENTICATED

        now = time.time()
        last_check = float(self._get("last_check", "0"))
        if now - last_check < config.SUBSCRIPTION_CHECK_INTERVAL:
            return self.status

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            ) as session:
                async with session.get(
                    f"{config.SUBSCRIPTION_API_URL}/subscription/status",
                    headers={"Authorization": f"Bearer {self._get('session_token')}"},
                    params={"device_serial": self.device_serial},
                ) as resp:
                    self._set("last_check", str(now))

                    if resp.status == 401:
                        self._set_many({
                            "session_token": "",
                            "status": SubStatus.NOT_AUTHENTICATED.value,
                        })
                        return SubStatus.NOT_AUTHENTICATED

                    if resp.status == 200:
                        data = await resp.json()
                        new_status = data.get("status", "unknown")

                        if new_status == "active":
                            self._set_many({
                                "status": SubStatus.ACTIVE.value,
                                "expires_at": str(data.get("expires_at", 0)),
                                "grace_started": "0",
                            })

                        elif new_status == "expired":
                            if self.status == SubStatus.ACTIVE:
                                self._set_many({
                                    "status": SubStatus.GRACE.value,
                                    "grace_started": str(now),
                                })
                                logger.warning("Subscription expired, grace period started")
                            elif self.status == SubStatus.GRACE:
                                grace_start = float(self._get("grace_started", "0"))
                                grace_elapsed = (now - grace_start) / 86400
                                if grace_elapsed > config.SUBSCRIPTION_GRACE_PERIOD:
                                    self._set("status", SubStatus.LAPSED.value)
                                    logger.warning("Grace period ended, blocklists frozen")

                        elif new_status == "cancelled":
                            self._set("status", SubStatus.LAPSED.value)
                            logger.info("Subscription cancelled by provider")

                        return self.status

        except Exception as e:
            logger.error("Subscription check failed: %s", e)

        return self.status

    def logout(self):
        self._set_many({
            "user_id": "",
            "session_token": "",
            "status": SubStatus.NOT_AUTHENTICATED.value,
            "expires_at": "0",
        })
        logger.info("User logged out")

    def get_status_summary(self) -> dict:
        return {
            "authenticated": self.is_authenticated,
            "user_id": self.user_id,
            "status": self.status.value,
            "subscription_active": self.is_subscription_active,
            "days_until_freeze": self.days_until_freeze,
            "device_serial": self.device_serial,
        }
