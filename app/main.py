#!/usr/bin/env python3
"""
Project Phalanx — Main Entry Point

Boots all subsystems:
  0. Run database migrations
  1. Load cached blocklists (instant startup, may be empty on first boot)
  2. Fetch fresh blocklists immediately (don't wait for timer)
  3. Start DNS proxy
  4. Start background loops (monitor, subscription, blocklist refresh)
  5. Start API server for GUI

Designed to run under systemd on a Raspberry Pi 4.
"""

import asyncio
import logging
import signal
import sys

from aiohttp import web

import config
from core.database import migrate, close as close_db
from core.blocklist import BlocklistManager
from core.dns_proxy import start_dns_server
from core.monitor import TrafficMonitor
from core.subscription import SubscriptionManager
from api.server import create_app

# ── Logging ──

config.LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(config.LOG_DIR / "phalanx.log", mode="a"),
    ],
)
logger = logging.getLogger("phalanx")


class PhalanxDaemon:
    """Main application orchestrator."""

    def __init__(self):
        self.subscription = None
        self.blocklist = None
        self.monitor = None
        self._dns_transport = None
        self._dns_protocol = None
        self._shutdown_event = asyncio.Event()

    async def start(self):
        logger.info("=" * 50)
        logger.info("Project Phalanx starting up")
        logger.info("=" * 50)

        # Ensure directories exist
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        config.BLOCKLIST_DIR.mkdir(parents=True, exist_ok=True)

        # 0. Run database migrations
        migrate()
        logger.info("Database ready")

        # Initialize components
        self.subscription = SubscriptionManager()
        self.blocklist = BlocklistManager()
        self.monitor = TrafficMonitor()
        logger.info("Device serial: %s", self.subscription.device_serial)

        # 1. Load cached blocklists from disk (instant, may be empty)
        self.blocklist.load_cached()
        logger.info("Cached blocklist loaded: %d domains", self.blocklist.domain_count)

        # 2. Fetch fresh blocklists NOW (don't wait for the timer)
        #    Free lists always update; subscription lists update if active.
        try:
            is_active = self.subscription.is_subscription_active
            results = await self.blocklist.update(subscription_active=is_active)
            logger.info("Initial blocklist fetch: %s", results)
        except Exception as e:
            logger.error("Initial blocklist fetch failed (using cached): %s", e)

        logger.info("Active blocklist: %d domains", self.blocklist.domain_count)

        # 3. Start DNS proxy
        try:
            self._dns_transport, self._dns_protocol = await start_dns_server(
                blocklist=self.blocklist.active_set,
                traffic_callback=self.monitor.record_query,
            )
        except PermissionError:
            logger.error(
                "Cannot bind to port %d — run as root or use: "
                "sudo setcap cap_net_bind_service=+ep $(which python3)",
                config.DNS_LISTEN_PORT,
            )
            return
        except OSError as e:
            logger.error("DNS server failed to start: %s", e)
            return

        # 4. Start background loops
        asyncio.create_task(self._monitor_loop())
        asyncio.create_task(self._subscription_loop())
        asyncio.create_task(self._blocklist_update_loop())
        asyncio.create_task(self._baseline_loop())

        # 5. Start API server
        app = create_app(self.subscription, self.blocklist, self.monitor)
        app["dns_protocol"] = self._dns_protocol
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, config.API_HOST, config.API_PORT)
        await site.start()
        logger.info("API server running on http://%s:%d", config.API_HOST, config.API_PORT)

        logger.info("Phalanx is ready. Blocking %d domains.", self.blocklist.domain_count)

        # Wait for shutdown signal
        await self._shutdown_event.wait()
        logger.info("Shutting down...")

        # Cleanup
        if self._dns_transport:
            self._dns_transport.close()
        await runner.cleanup()
        close_db()

    async def _monitor_loop(self):
        """Periodically flush traffic stats to disk."""
        while not self._shutdown_event.is_set():
            await asyncio.sleep(config.MONITOR_BATCH_INTERVAL)
            try:
                await self.monitor.flush_batch()
            except Exception as e:
                logger.error("Monitor flush error: %s", e)

    async def _subscription_loop(self):
        """Periodically check subscription status."""
        while not self._shutdown_event.is_set():
            await asyncio.sleep(config.SUBSCRIPTION_CHECK_INTERVAL)
            try:
                status = await self.subscription.check_subscription()
                logger.info("Subscription status: %s", status.value)
            except Exception as e:
                logger.error("Subscription check error: %s", e)

    async def _blocklist_update_loop(self):
        """Periodically refresh blocklists (initial fetch already done in start())."""
        while not self._shutdown_event.is_set():
            await asyncio.sleep(config.BLOCKLIST_UPDATE_INTERVAL)
            try:
                is_active = self.subscription.is_subscription_active
                results = await self.blocklist.update(subscription_active=is_active)
                logger.info("Blocklist refresh: %s", results)

                # Hot-swap the DNS proxy's blocklist reference
                if self._dns_protocol:
                    self._dns_protocol.blocklist = self.blocklist.active_set

            except Exception as e:
                logger.error("Blocklist update error: %s", e)

    async def _baseline_loop(self):
        """Rebuild device behavioral baselines every few hours."""
        await asyncio.sleep(300)
        while not self._shutdown_event.is_set():
            try:
                await self.monitor.rebuild_baselines()
            except Exception as e:
                logger.error("Baseline rebuild error: %s", e)
            await asyncio.sleep(config.MONITOR_BASELINE_WINDOW * 3600 / 4)

    def handle_signal(self):
        self._shutdown_event.set()


def main():
    daemon = PhalanxDaemon()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, daemon.handle_signal)

    try:
        loop.run_until_complete(daemon.start())
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
        logger.info("Phalanx stopped.")


if __name__ == "__main__":
    main()
