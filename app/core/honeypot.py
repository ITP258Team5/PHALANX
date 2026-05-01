"""
Phalanx Honeypot Listener

Runs fake network services (SSH, HTTP, Telnet, FTP) on configurable ports.
When an attacker connects, every interaction is logged to the database:
connection opens, authentication attempts, commands, payloads, and closes.

Each fake service:
  - Accepts TCP connections
  - Sends a realistic banner
  - Captures credentials and payloads
  - Creates a session record + per-event log entries
  - Auto-classifies severity based on behavior
  - Triggers alerts for high/critical sessions via DB trigger

All listeners run on the main asyncio event loop — no extra threads.
"""

import asyncio
import logging
import time
from typing import Optional

from core.database import get_connection, transaction

logger = logging.getLogger("phalanx.honeypot")


# ── Service definitions ──

SERVICES = {
    "ssh": {
        "port": 22,       # Standard SSH port — catches real attackers
        "banner": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
        "protocol": "TCP",
    },
    "telnet": {
        "port": 23,       # Standard telnet
        "banner": b"\r\nLogin: ",
        "protocol": "TCP",
    },
    "http": {
        "port": 8888,
        "banner": None,
        "protocol": "TCP",
    },
    "ftp": {
        "port": 21,       # Standard FTP
        "banner": b"220 FTP server ready.\r\n",
        "protocol": "TCP",
    },
}

# Severity escalation thresholds
BRUTE_FORCE_THRESHOLD = 3     # auth attempts before escalating to 'high'
CRITICAL_THRESHOLD = 8        # auth attempts before 'critical'


class HoneypotSession:
    """Tracks a single attacker connection."""

    def __init__(self, session_id: int, attacker_ip: str, attacker_port: int,
                 decoy_ip: str, decoy_port: int, service: str):
        self.session_id = session_id
        self.attacker_ip = attacker_ip
        self.attacker_port = attacker_port
        self.decoy_ip = decoy_ip
        self.decoy_port = decoy_port
        self.service = service
        self.started_at = time.time()
        self.auth_attempts = 0
        self.events: list[dict] = []

    @property
    def severity(self) -> str:
        if self.auth_attempts >= CRITICAL_THRESHOLD:
            return "critical"
        if self.auth_attempts >= BRUTE_FORCE_THRESHOLD:
            return "high"
        if self.auth_attempts > 0:
            return "medium"
        return "low"

    @property
    def attack_class(self) -> str:
        if self.auth_attempts >= BRUTE_FORCE_THRESHOLD:
            return "brute_force"
        if self.auth_attempts > 0:
            return "credential_harvest"
        if any(e["event_type"] == "banner_grab" for e in self.events):
            return "recon"
        if any(e["event_type"] == "port_scan_probe" for e in self.events):
            return "scan"
        return "recon"


def _create_session(attacker_ip: str, attacker_port: int,
                    decoy_ip: str, decoy_port: int, service: str) -> int:
    """Create a honeypot session record and return its ID."""
    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO honeypot_sessions
           (attacker_ip, attacker_port, decoy_ip, decoy_port, protocol,
            started_at, severity, service_emulated, attack_class)
           VALUES (?, ?, ?, ?, 'TCP', ?, 'low', ?, 'recon')""",
        (attacker_ip, attacker_port, decoy_ip, decoy_port,
         time.time(), service),
    )
    conn.commit()
    return cursor.lastrowid


def _log_event(session_id: int, event_type: str, username: str = None,
               password: str = None, auth_result: str = None,
               payload: str = None, payload_bytes: bytes = None):
    """Log a single event within a honeypot session."""
    conn = get_connection()
    size = len(payload_bytes) if payload_bytes else (len(payload.encode()) if payload else None)
    conn.execute(
        """INSERT INTO honeypot_log
           (session_id, timestamp, event_type, username, password_raw,
            auth_result, decoded_payload, raw_payload, payload_size_bytes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (session_id, time.time(), event_type, username, password,
         auth_result, payload, payload_bytes, size),
    )
    conn.commit()


def _close_session(session: HoneypotSession):
    """Finalize a session with duration and final severity."""
    now = time.time()
    duration = (now - session.started_at) * 1000
    conn = get_connection()
    conn.execute(
        """UPDATE honeypot_sessions
           SET ended_at = ?, duration_ms = ?, severity = ?, attack_class = ?
           WHERE id = ?""",
        (now, duration, session.severity, session.attack_class, session.session_id),
    )
    conn.commit()


def _get_local_ip() -> str:
    """Get the Pi's local IP for the decoy_ip field."""
    try:
        import subprocess
        result = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3)
        return result.stdout.strip().split()[0]
    except Exception:
        return "127.0.0.1"


# ── SSH Honeypot ──

class SSHHoneypotProtocol(asyncio.Protocol):
    """
    Fake SSH server. Sends an OpenSSH banner, then captures
    credentials from the SSH protocol handshake. Since we don't
    implement real SSH crypto, we capture the raw bytes and look
    for plaintext password patterns in the auth exchange.
    """

    def __init__(self, decoy_ip: str, port: int):
        self.decoy_ip = decoy_ip
        self.port = port
        self.transport = None
        self.session: Optional[HoneypotSession] = None
        self._buffer = b""

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        attacker_ip = peername[0] if peername else "unknown"
        attacker_port = peername[1] if peername else 0

        session_id = _create_session(attacker_ip, attacker_port,
                                      self.decoy_ip, self.port, "ssh")
        self.session = HoneypotSession(session_id, attacker_ip, attacker_port,
                                        self.decoy_ip, self.port, "ssh")

        _log_event(session_id, "connection_open")
        logger.info("HONEYPOT SSH: Connection from %s:%d", attacker_ip, attacker_port)

        # Send SSH banner
        transport.write(SERVICES["ssh"]["banner"])

    def data_received(self, data: bytes):
        if not self.session:
            return

        self._buffer += data

        # Try to extract credentials from SSH protocol data
        # Real SSH uses encrypted auth, but many bots send plaintext
        # or we can capture the username from the protocol envelope
        decoded = data.decode("utf-8", errors="replace")

        # Look for common patterns in the raw data
        if any(keyword in decoded.lower() for keyword in ["password", "login", "user"]):
            self.session.auth_attempts += 1
            # Extract what we can — even partial data is useful
            _log_event(
                self.session.session_id, "auth_attempt",
                payload=decoded[:256],
                auth_result="denied",
            )
            logger.info("HONEYPOT SSH: Auth attempt from %s (attempt #%d)",
                        self.session.attacker_ip, self.session.auth_attempts)

            # Send fake auth failure
            self.transport.write(b"Permission denied.\r\n")

            if self.session.auth_attempts >= 10:
                self.transport.write(b"Too many authentication failures.\r\n")
                self.transport.close()
                return
        else:
            # Log as generic payload/banner grab
            _log_event(
                self.session.session_id, "banner_grab",
                payload=decoded[:512],
                payload_bytes=data[:512],
            )

    def connection_lost(self, exc):
        if self.session:
            _log_event(self.session.session_id, "connection_close")
            _close_session(self.session)
            logger.info("HONEYPOT SSH: Session %d closed (%s, %d auth attempts, severity=%s)",
                        self.session.session_id, self.session.attacker_ip,
                        self.session.auth_attempts, self.session.severity)


# ── Telnet Honeypot ──

class TelnetHoneypotProtocol(asyncio.Protocol):
    """
    Fake Telnet server. Prompts for login/password and captures
    every attempt. Telnet is plaintext so we get clean credentials.
    """

    def __init__(self, decoy_ip: str, port: int):
        self.decoy_ip = decoy_ip
        self.port = port
        self.transport = None
        self.session: Optional[HoneypotSession] = None
        self._state = "wait_username"
        self._username = ""

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        attacker_ip = peername[0] if peername else "unknown"
        attacker_port = peername[1] if peername else 0

        session_id = _create_session(attacker_ip, attacker_port,
                                      self.decoy_ip, self.port, "telnet")
        self.session = HoneypotSession(session_id, attacker_ip, attacker_port,
                                        self.decoy_ip, self.port, "telnet")

        _log_event(session_id, "connection_open")
        logger.info("HONEYPOT Telnet: Connection from %s:%d", attacker_ip, attacker_port)

        transport.write(b"\r\nPhalanx Gateway\r\n\r\nLogin: ")

    def data_received(self, data: bytes):
        if not self.session:
            return

        text = data.decode("utf-8", errors="replace").strip()
        if not text:
            return

        if self._state == "wait_username":
            self._username = text[:64]
            self._state = "wait_password"
            self.transport.write(b"Password: ")

        elif self._state == "wait_password":
            password = text[:64]
            self.session.auth_attempts += 1

            _log_event(
                self.session.session_id, "auth_attempt",
                username=self._username,
                password=password,
                auth_result="denied",
            )
            logger.info("HONEYPOT Telnet: %s tried %s/%s",
                        self.session.attacker_ip, self._username, password)

            self.transport.write(b"\r\nLogin incorrect\r\n\r\nLogin: ")
            self._username = ""
            self._state = "wait_username"

            if self.session.auth_attempts >= 10:
                self.transport.write(b"\r\nToo many failures. Disconnecting.\r\n")
                self.transport.close()

    def connection_lost(self, exc):
        if self.session:
            _log_event(self.session.session_id, "connection_close")
            _close_session(self.session)
            logger.info("HONEYPOT Telnet: Session %d closed (severity=%s)",
                        self.session.session_id, self.session.severity)


# ── HTTP Honeypot ──

class HTTPHoneypotProtocol(asyncio.Protocol):
    """
    Fake HTTP server. Returns a generic page for GET requests and
    logs all request paths, headers, and POST bodies. Catches
    bots scanning for .env files, admin panels, and exploits.
    """

    def __init__(self, decoy_ip: str, port: int):
        self.decoy_ip = decoy_ip
        self.port = port
        self.transport = None
        self.session: Optional[HoneypotSession] = None

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        attacker_ip = peername[0] if peername else "unknown"
        attacker_port = peername[1] if peername else 0

        session_id = _create_session(attacker_ip, attacker_port,
                                      self.decoy_ip, self.port, "http")
        self.session = HoneypotSession(session_id, attacker_ip, attacker_port,
                                        self.decoy_ip, self.port, "http")

        _log_event(session_id, "connection_open")
        logger.info("HONEYPOT HTTP: Connection from %s:%d", attacker_ip, attacker_port)

    def data_received(self, data: bytes):
        if not self.session:
            return

        decoded = data.decode("utf-8", errors="replace")
        first_line = decoded.split("\r\n")[0] if decoded else ""

        # Classify the request
        event_type = "banner_grab"
        if "/.env" in decoded or "/wp-admin" in decoded or "/phpmyadmin" in decoded:
            event_type = "recon"
        elif "POST" in first_line:
            event_type = "payload_sent"

        _log_event(
            self.session.session_id, event_type,
            payload=decoded[:1024],
            payload_bytes=data[:1024],
        )

        logger.info("HONEYPOT HTTP: %s → %s", self.session.attacker_ip, first_line[:100])

        # Send a fake response
        body = b"<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>"
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.52 (Ubuntu)\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        self.transport.write(response)

        # Close after response (HTTP/1.0 style)
        self.transport.close()

    def connection_lost(self, exc):
        if self.session:
            _log_event(self.session.session_id, "connection_close")
            _close_session(self.session)


# ── FTP Honeypot ──

class FTPHoneypotProtocol(asyncio.Protocol):
    """
    Fake FTP server. Accepts USER/PASS commands and logs credentials.
    """

    def __init__(self, decoy_ip: str, port: int):
        self.decoy_ip = decoy_ip
        self.port = port
        self.transport = None
        self.session: Optional[HoneypotSession] = None
        self._username = ""

    def connection_made(self, transport):
        self.transport = transport
        peername = transport.get_extra_info("peername")
        attacker_ip = peername[0] if peername else "unknown"
        attacker_port = peername[1] if peername else 0

        session_id = _create_session(attacker_ip, attacker_port,
                                      self.decoy_ip, self.port, "ftp")
        self.session = HoneypotSession(session_id, attacker_ip, attacker_port,
                                        self.decoy_ip, self.port, "ftp")

        _log_event(session_id, "connection_open")
        logger.info("HONEYPOT FTP: Connection from %s:%d", attacker_ip, attacker_port)

        transport.write(b"220 FTP server ready.\r\n")

    def data_received(self, data: bytes):
        if not self.session:
            return

        text = data.decode("utf-8", errors="replace").strip()
        if not text:
            return

        parts = text.split(" ", 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        if cmd == "USER":
            self._username = arg[:64]
            self.transport.write(b"331 Password required.\r\n")

        elif cmd == "PASS":
            self.session.auth_attempts += 1
            _log_event(
                self.session.session_id, "auth_attempt",
                username=self._username,
                password=arg[:64],
                auth_result="denied",
            )
            logger.info("HONEYPOT FTP: %s tried %s/%s",
                        self.session.attacker_ip, self._username, arg[:32])
            self.transport.write(b"530 Login incorrect.\r\n")

            if self.session.auth_attempts >= 10:
                self.transport.write(b"421 Too many failures.\r\n")
                self.transport.close()

        elif cmd == "QUIT":
            self.transport.write(b"221 Goodbye.\r\n")
            self.transport.close()

        else:
            _log_event(self.session.session_id, "command_exec", payload=text[:256])
            self.transport.write(b"530 Please login first.\r\n")

    def connection_lost(self, exc):
        if self.session:
            _log_event(self.session.session_id, "connection_close")
            _close_session(self.session)


# ── Protocol factory map ──

PROTOCOL_MAP = {
    "ssh": SSHHoneypotProtocol,
    "telnet": TelnetHoneypotProtocol,
    "http": HTTPHoneypotProtocol,
    "ftp": FTPHoneypotProtocol,
}


# ── Lifecycle ──

async def start_honeypot(
    services: dict = None,
    decoy_ip: str = None,
) -> list[tuple]:
    """
    Start all configured honeypot listeners.
    Returns list of (transport, service_name) tuples.
    """
    services = services or SERVICES
    decoy_ip = decoy_ip or _get_local_ip()
    loop = asyncio.get_running_loop()
    listeners = []

    for service_name, config in services.items():
        protocol_class = PROTOCOL_MAP.get(service_name)
        if not protocol_class:
            logger.warning("No protocol handler for service '%s'", service_name)
            continue

        port = config["port"]

        try:
            server = await loop.create_server(
                lambda svc=service_name, p=port: PROTOCOL_MAP[svc](decoy_ip, p),
                "0.0.0.0",
                port,
            )
            listeners.append((server, service_name))
            logger.info("HONEYPOT: %s listening on port %d", service_name.upper(), port)

        except OSError as e:
            logger.error("HONEYPOT: Failed to start %s on port %d: %s",
                        service_name, port, e)

    if listeners:
        logger.info("HONEYPOT: %d services active on %s", len(listeners), decoy_ip)
    else:
        logger.warning("HONEYPOT: No services started")

    return listeners


def get_honeypot_stats() -> dict:
    """Get honeypot statistics from the database."""
    try:
        conn = get_connection()

        total_sessions = conn.execute(
            "SELECT COUNT(*) FROM honeypot_sessions"
        ).fetchone()[0]

        active_sessions = conn.execute(
            "SELECT COUNT(*) FROM honeypot_sessions WHERE ended_at IS NULL"
        ).fetchone()[0]

        unique_attackers = conn.execute(
            "SELECT COUNT(DISTINCT attacker_ip) FROM honeypot_sessions"
        ).fetchone()[0]

        critical_count = conn.execute(
            "SELECT COUNT(*) FROM honeypot_sessions WHERE severity IN ('high', 'critical')"
        ).fetchone()[0]

        total_auth = conn.execute(
            "SELECT COUNT(*) FROM honeypot_log WHERE event_type = 'auth_attempt'"
        ).fetchone()[0]

        # Recent sessions (last 50)
        sessions = conn.execute(
            """SELECT id, attacker_ip, attacker_port, decoy_port,
                      service_emulated, attack_class, severity,
                      started_at, ended_at, duration_ms, was_blocked
               FROM honeypot_sessions
               ORDER BY started_at DESC LIMIT 50"""
        ).fetchall()

        # Recent events (last 100)
        events = conn.execute(
            """SELECT l.session_id, l.timestamp, l.event_type,
                      l.username, l.password_raw, l.auth_result,
                      l.decoded_payload, s.attacker_ip
               FROM honeypot_log l
               JOIN honeypot_sessions s ON s.id = l.session_id
               ORDER BY l.timestamp DESC LIMIT 100"""
        ).fetchall()

        # Top credentials
        top_creds = conn.execute(
            """SELECT username, password_raw, COUNT(*) as attempts
               FROM honeypot_log
               WHERE event_type = 'auth_attempt' AND username IS NOT NULL
               GROUP BY username, password_raw
               ORDER BY attempts DESC LIMIT 20"""
        ).fetchall()

        # Per-service breakdown
        services = conn.execute(
            """SELECT service_emulated, COUNT(*) as count,
                      SUM(CASE WHEN severity IN ('high','critical') THEN 1 ELSE 0 END) as high_count
               FROM honeypot_sessions
               WHERE service_emulated IS NOT NULL
               GROUP BY service_emulated
               ORDER BY count DESC"""
        ).fetchall()

        return {
            "total_sessions": total_sessions,
            "active_sessions": active_sessions,
            "unique_attackers": unique_attackers,
            "critical_count": critical_count,
            "total_auth_attempts": total_auth,
            "sessions": [dict(r) for r in sessions],
            "events": [dict(r) for r in events],
            "top_credentials": [dict(r) for r in top_creds],
            "services": [dict(r) for r in services],
        }

    except Exception as e:
        logger.error("Failed to get honeypot stats: %s", e)
        return {
            "total_sessions": 0, "active_sessions": 0,
            "unique_attackers": 0, "critical_count": 0,
            "total_auth_attempts": 0, "sessions": [],
            "events": [], "top_credentials": [], "services": [],
        }
