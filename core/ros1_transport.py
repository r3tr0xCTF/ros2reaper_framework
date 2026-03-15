#!/usr/bin/env python3
"""
ros1_transport.py — Minimal TCPROS Publisher
=============================================
Implements just enough of the TCPROS wire protocol to act as a
publisher and inject serialized messages to any ROS1 subscriber.

TCPROS connection flow (publisher side):
  1. Publisher registers with rosmaster (handled by ros1_master.py)
  2. Subscriber connects to publisher's TCP socket
  3. Subscriber sends connection header  (key=value pairs, length-prefixed)
  4. Publisher replies with its own connection header
  5. Publisher sends messages as: <4-byte LE length><payload>

Message serialisation for supported types:
  geometry_msgs/Twist   — 6 × float64 LE  (48 bytes)
  sensor_msgs/LaserScan — header + scan params + float32 arrays
  std_msgs/String       — uint32 length + UTF-8 bytes

Author: Gh057x
"""

import math
import socket
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Known MD5 checksums (must match exactly what ROS1 nodes expect)
# ---------------------------------------------------------------------------

ROS1_MD5: Dict[str, str] = {
    "geometry_msgs/Twist":    "9f195f881246fdfa2798d1d3eebca84a",
    "sensor_msgs/LaserScan":  "90c7ef2dc6895d81024acba2ac42f369",
    "nav_msgs/Odometry":      "cd5e73d190d741a2f92e81eda573aca7",
    "std_msgs/String":        "992ce8a1687cec8c8bd883ec73ca41d1",
    "std_msgs/Bool":          "8b94c1b53db61fb6aed406028ad6332a",
}

# Minimal message definitions (only what's needed for the header exchange)
ROS1_MSG_DEF: Dict[str, str] = {
    "geometry_msgs/Twist":
        "geometry_msgs/Vector3 linear\ngeometry_msgs/Vector3 angular\n",
    "sensor_msgs/LaserScan":
        "std_msgs/Header header\nfloat32 angle_min\nfloat32 angle_max\n"
        "float32 angle_increment\nfloat32 time_increment\nfloat32 scan_time\n"
        "float32 range_min\nfloat32 range_max\nfloat32[] ranges\nfloat32[] intensities\n",
    "std_msgs/String":
        "string data\n",
    "std_msgs/Bool":
        "bool data\n",
}


# ---------------------------------------------------------------------------
# TCPROS wire-format helpers
# ---------------------------------------------------------------------------

class TCPROSSerializer:
    """Static helpers for TCPROS framing and ROS1 message serialisation."""

    # --- Connection header ---

    @staticmethod
    def serialize_connection_header(
        callerid: str,
        topic: str,
        msg_type: str,
        md5sum: str,
        latching: bool = False,
    ) -> bytes:
        """
        Build a TCPROS connection header.

        Format: <uint32 total_len> [ <uint32 field_len> <key=value> ... ]
        """
        fields = {
            "callerid":           callerid,
            "topic":              topic,
            "type":               msg_type,
            "md5sum":             md5sum,
            "message_definition": ROS1_MSG_DEF.get(msg_type, ""),
            "latching":           "1" if latching else "0",
        }
        encoded_fields = b"".join(
            struct.pack("<I", len(kv)) + kv.encode()
            for k, v in fields.items()
            for kv in [f"{k}={v}"]
        )
        return struct.pack("<I", len(encoded_fields)) + encoded_fields

    @staticmethod
    def parse_connection_header(data: bytes) -> Dict[str, str]:
        """Parse a received TCPROS connection header into a dict."""
        result: Dict[str, str] = {}
        if len(data) < 4:
            return result
        total_len = struct.unpack_from("<I", data, 0)[0]
        offset = 4
        end = 4 + total_len
        while offset < end and offset + 4 <= len(data):
            field_len = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if offset + field_len > len(data):
                break
            field = data[offset: offset + field_len].decode(errors="replace")
            offset += field_len
            if "=" in field:
                k, _, v = field.partition("=")
                result[k.strip()] = v
        return result

    @staticmethod
    def frame_message(payload: bytes) -> bytes:
        """Wrap a serialised payload with the 4-byte LE length prefix."""
        return struct.pack("<I", len(payload)) + payload

    # --- Message serialisation ---

    @staticmethod
    def serialize_twist(
        lx: float = 0.0, ly: float = 0.0, lz: float = 0.0,
        ax: float = 0.0, ay: float = 0.0, az: float = 0.0,
    ) -> bytes:
        """Serialise geometry_msgs/Twist as 6 × float64 little-endian."""
        return struct.pack("<6d", lx, ly, lz, ax, ay, az)

    @staticmethod
    def serialize_laser_scan_blind(
        num_readings: int = 360,
        range_max: float = 3.5,
    ) -> bytes:
        """
        Serialise a sensor_msgs/LaserScan where all ranges are 0.0
        (simulates a completely blinded LIDAR sensor).
        """
        now_sec = int(time.time())
        now_nsec = 0
        frame_id = b"base_scan\x00"
        frame_id_padded = struct.pack("<I", len(frame_id)) + frame_id

        # std_msgs/Header: seq(u32) + stamp(u32+u32) + frame_id(string)
        header = struct.pack("<III", 0, now_sec, now_nsec) + frame_id_padded

        angle_min       = -math.pi
        angle_max       =  math.pi
        angle_increment = (2 * math.pi) / num_readings
        scan_params = struct.pack(
            "<7f",
            angle_min, angle_max, angle_increment,
            0.0,            # time_increment
            0.1,            # scan_time
            0.12,           # range_min
            range_max,
        )

        # float32[] ranges  — all 0.0 (blinded)
        ranges_data = (
            struct.pack("<I", num_readings)
            + struct.pack(f"<{num_readings}f", *([0.0] * num_readings))
        )
        # float32[] intensities — empty
        intensities_data = struct.pack("<I", 0)

        return header + scan_params + ranges_data + intensities_data

    @staticmethod
    def serialize_string(s: str) -> bytes:
        """Serialise std_msgs/String."""
        encoded = s.encode("utf-8")
        return struct.pack("<I", len(encoded)) + encoded


# ---------------------------------------------------------------------------
# TCPROS publisher server
# ---------------------------------------------------------------------------

class TCPROSPublisher:
    """
    Minimal TCP server that speaks just enough TCPROS to push messages
    to any subscriber that connects.

    Usage:
        pub = TCPROSPublisher("/cmd_vel", "geometry_msgs/Twist")
        local_ip, port = pub.start("0.0.0.0")   # or specific interface IP
        # … register (local_ip, port) with rosmaster …
        pub.send_message(TCPROSSerializer.serialize_twist(2.0, 0, 0, 0, 0, 1.5))
        pub.stop()
    """

    def __init__(
        self,
        topic: str,
        msg_type: str,
        caller_id: str = "/ros2reaper_pub",
        verbose: bool = False,
    ):
        self.topic = topic
        self.msg_type = msg_type
        self.caller_id = caller_id
        self.verbose = verbose

        self._md5 = ROS1_MD5.get(msg_type, "*")
        self._sock: Optional[socket.socket] = None
        self._clients: List[socket.socket] = []
        self._clients_lock = threading.Lock()
        self._accept_thread: Optional[threading.Thread] = None
        self._running = False

    # ------------------------------------------------------------------

    def start(self, bind_ip: str = "0.0.0.0", bind_port: int = 0) -> Tuple[str, int]:
        """
        Bind the TCP server socket and start accepting connections.
        Returns (bound_ip, bound_port) to pass to rosmaster.register_publisher().
        """
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_ip, bind_port))
        self._sock.listen(10)
        self._running = True

        actual_ip, actual_port = self._sock.getsockname()
        if actual_ip in ("0.0.0.0", ""):
            # Resolve to a routable IP
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                actual_ip = s.getsockname()[0]
                s.close()
            except Exception:
                actual_ip = "127.0.0.1"

        self._accept_thread = threading.Thread(
            target=self._accept_loop, daemon=True
        )
        self._accept_thread.start()

        if self.verbose:
            print(f"[*] TCPROS publisher listening on {actual_ip}:{actual_port} "
                  f"for {self.topic}")
        return actual_ip, actual_port

    def stop(self):
        """Stop the publisher and close all client connections."""
        self._running = False
        with self._clients_lock:
            for c in self._clients:
                try:
                    c.close()
                except Exception:
                    pass
            self._clients.clear()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def send_message(self, payload: bytes):
        """Send a serialised message to all connected subscribers."""
        framed = TCPROSSerializer.frame_message(payload)
        dead = []
        with self._clients_lock:
            for c in list(self._clients):
                try:
                    c.sendall(framed)
                except Exception:
                    dead.append(c)
            for c in dead:
                self._clients.remove(c)

    # ------------------------------------------------------------------
    # Internal

    def _accept_loop(self):
        self._sock.settimeout(1.0)
        while self._running:
            try:
                conn, addr = self._sock.accept()
                if self.verbose:
                    print(f"[+] TCPROS subscriber connected from {addr}")
                t = threading.Thread(
                    target=self._handle_client, args=(conn,), daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_client(self, conn: socket.socket):
        """Perform the TCPROS handshake, then add to active client list."""
        try:
            conn.settimeout(5.0)
            # Read subscriber header
            raw_len = conn.recv(4)
            if len(raw_len) < 4:
                conn.close()
                return
            total = struct.unpack_from("<I", raw_len)[0]
            data = b""
            while len(data) < total:
                chunk = conn.recv(total - len(data))
                if not chunk:
                    break
                data += chunk

            sub_header = TCPROSSerializer.parse_connection_header(raw_len + data)
            if self.verbose:
                print(f"[*] TCPROS handshake: callerid={sub_header.get('callerid')}")

            # Send publisher header back
            reply = TCPROSSerializer.serialize_connection_header(
                callerid=self.caller_id,
                topic=self.topic,
                msg_type=self.msg_type,
                md5sum=self._md5,
            )
            conn.sendall(reply)
            conn.settimeout(None)

            with self._clients_lock:
                self._clients.append(conn)
        except Exception as exc:
            if self.verbose:
                print(f"[-] TCPROS handshake error: {exc}")
            try:
                conn.close()
            except Exception:
                pass
