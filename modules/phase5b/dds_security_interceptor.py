#!/usr/bin/env python3
"""
dds_security_interceptor.py - Phase 5B Module 1: DDS-Security Handshake Interception

Passively captures DDS-Security authentication traffic to extract security tokens,
map the secured domain's configuration, and identify downgrade opportunities.

Attack model:
  1. Bind to DDS multicast discovery groups (no packets sent — full stealth)
  2. Parse RTPS SPDP DATA packets for DDS-Security Parameter IDs:
       PID_IDENTITY_TOKEN         (0x1001) — X.509 cert chain in identity token
       PID_PERMISSIONS_TOKEN      (0x1002) — signed permissions document
       PID_PARTICIPANT_SECURITY_INFO (0x1005) — security plugin bitmask
       PID_IDENTITY_STATUS_TOKEN  (0x1006) — authentication status
  3. Detect security strategy: ENFORCE (blocks unsecured) vs PERMISSIVE (allows mix)
  4. Capture full 3-way AUTH handshake: REQUEST → REPLY → FINAL
  5. Feed captured tokens to cert_harvester.py (Module 2) for X.509 extraction
  6. Identify SIGN-only domains (data visible in plaintext despite auth)

DDS-Security plugin chain:
  - Authentication:   DDS:Auth:PKI-DH   (X.509, Diffie-Hellman key exchange)
  - Access Control:   DDS:Access:Permissions (governance.xml / permissions.xml)
  - Cryptography:     DDS:Crypto:AES-GCM-GMAC (AES-128/256 GCM)

Handshake wire format (OMG DDS-Security spec §9.3):
  AUTH messages carried in RTPS DATA submessages on the built-in endpoints:
    - DCPSParticipants (SPDP topic): PID_IDENTITY_TOKEN in param list
    - Participant-to-participant secure channel: HandshakeRequestMessage,
      HandshakeReplyMessage, HandshakeFinalMessage (CDR serialized)

Downgrade opportunity detection:
  - PERMISSIVE mode: governance_protection_kind = NONE on discovered participants
  - SIGN-only: rtps_protection_kind bit 0x01 set, bit 0x02 clear
  - Missing AUTH: identity_token absent from otherwise secure participant
  - Mixed domain: some participants secured, others not — bridging vulnerability

Author: Gh057x | Phase 5B
"""

import socket
import struct
import threading
import time
import json
import sys
import argparse
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict
from datetime import datetime
from enum import Enum


# =============================================================================
# DDS-Security Parameter IDs (OMG DDS-Security spec §7.4)
# =============================================================================

PID_IDENTITY_TOKEN             = 0x1001
PID_PERMISSIONS_TOKEN          = 0x1002
PID_DATA_TAGS                  = 0x1003
PID_ENDPOINT_SECURITY_INFO     = 0x1004
PID_PARTICIPANT_SECURITY_INFO  = 0x1005
PID_IDENTITY_STATUS_TOKEN      = 0x1006

# Standard RTPS PIDs needed for context
PID_PARTICIPANT_GUID           = 0x0050
PID_ENTITY_NAME                = 0x0062
PID_DEFAULT_UNICAST_LOCATOR    = 0x002F
PID_VENDOR_ID                  = 0x0016
PID_SENTINEL                   = 0x0001

# Security attribute bitmasks (§8.4.2.5)
SECURITY_ATTR_RTPS_PROTECTION_SIGN      = 0x00000001
SECURITY_ATTR_RTPS_PROTECTION_ENCRYPT   = 0x00000002
SECURITY_ATTR_SUBMSG_PROTECTION_SIGN    = 0x00000004
SECURITY_ATTR_SUBMSG_PROTECTION_ENCRYPT = 0x00000008
SECURITY_ATTR_PAYLOAD_PROTECTION_SIGN   = 0x00000010
SECURITY_ATTR_PAYLOAD_PROTECTION_ENCRYPT= 0x00000020
SECURITY_ATTR_IS_VALID                  = 0x80000000

# RTPS constants
RTPS_MAGIC              = b"RTPS"
RTPS_VERSION_2_1        = (2, 1)
RTPS_SUBMSG_DATA        = 0x15
RTPS_SUBMSG_INFO_TS     = 0x09
RTPS_SUBMSG_INFO_DST    = 0x0E

# DDS multicast groups per domain (domain 0 shown; formula: 239.255.0.1 + domain offsets)
DDS_DISCOVERY_MC_BASE   = "239.255.0.1"
DDS_BASE_PORT           = 7400  # UDP/7400 = SPDP multicast for domain 0
DDS_PORT_GAIN_D         = 250
DDS_PORT_GAIN_PG        = 2
DDS_BUILTIN_MC_OFFSET   = 0
DDS_BUILTIN_UC_OFFSET   = 10

VENDOR_IDS = {
    b"\x01\x01": "RTI Connext DDS",
    b"\x01\x03": "OCI OpenDDS",
    b"\x01\x0f": "eProsima Fast DDS",
    b"\x01\x10": "Eclipse Cyclone DDS",
    b"\x01\x12": "GurumNetworks GurumDDS",
}


# =============================================================================
# Data Structures
# =============================================================================

class SecurityMode(str, Enum):
    NONE        = "NONE"
    SIGN        = "SIGN"
    ENCRYPT     = "ENCRYPT"
    UNKNOWN     = "UNKNOWN"


class AuthStrategy(str, Enum):
    ENFORCE     = "ENFORCE"
    PERMISSIVE  = "PERMISSIVE"
    UNKNOWN     = "UNKNOWN"


@dataclass
class RawToken:
    """A raw DDS-Security token extracted from an RTPS packet."""
    token_class: str            # "identity", "permissions", "identity_status"
    class_id: str               # e.g. "DDS:Auth:PKI-DH:1.0"
    properties: Dict[str, bytes] = field(default_factory=dict)
    binary_properties: Dict[str, bytes] = field(default_factory=dict)
    raw_bytes: bytes = field(default=b"", repr=False)

    def to_dict(self) -> Dict:
        d = {
            "token_class": self.token_class,
            "class_id": self.class_id,
            "properties": {k: v.decode("utf-8", errors="replace") for k, v in self.properties.items()},
            "binary_properties_keys": list(self.binary_properties.keys()),
            "raw_len": len(self.raw_bytes),
        }
        return d


@dataclass
class SecurityParticipant:
    """A DDS participant observed in the secured domain."""
    guid_prefix: bytes
    source_ip: str
    domain_id: int
    vendor: str = "Unknown"
    participant_name: str = ""
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())

    # Security posture
    has_identity_token: bool = False
    has_permissions_token: bool = False
    has_identity_status: bool = False
    rtps_protection: SecurityMode = SecurityMode.UNKNOWN
    submsg_protection: SecurityMode = SecurityMode.UNKNOWN
    payload_protection: SecurityMode = SecurityMode.UNKNOWN
    auth_strategy: AuthStrategy = AuthStrategy.UNKNOWN
    security_attributes_raw: int = 0

    # Captured token data
    identity_token: Optional[RawToken] = None
    permissions_token: Optional[RawToken] = None

    # Attack surface
    downgrade_possible: bool = False
    sign_only: bool = False
    downgrade_reason: str = ""

    @property
    def guid_hex(self) -> str:
        return self.guid_prefix.hex() if self.guid_prefix else "unknown"

    def assess_attack_surface(self):
        """Derive attack flags from security attributes."""
        attrs = self.security_attributes_raw
        if not (attrs & SECURITY_ATTR_IS_VALID):
            return

        rtps_sign    = bool(attrs & SECURITY_ATTR_RTPS_PROTECTION_SIGN)
        rtps_encrypt = bool(attrs & SECURITY_ATTR_RTPS_PROTECTION_ENCRYPT)

        if rtps_sign and not rtps_encrypt:
            self.sign_only = True
            self.rtps_protection = SecurityMode.SIGN
        elif rtps_encrypt:
            self.rtps_protection = SecurityMode.ENCRYPT
        else:
            self.rtps_protection = SecurityMode.NONE
            self.downgrade_possible = True
            self.downgrade_reason = "RTPS protection disabled — no auth or encryption on wire"

        sub_encrypt = bool(attrs & SECURITY_ATTR_SUBMSG_PROTECTION_ENCRYPT)
        self.submsg_protection = SecurityMode.ENCRYPT if sub_encrypt else (
            SecurityMode.SIGN if (attrs & SECURITY_ATTR_SUBMSG_PROTECTION_SIGN) else SecurityMode.NONE
        )

        pay_encrypt = bool(attrs & SECURITY_ATTR_PAYLOAD_PROTECTION_ENCRYPT)
        self.payload_protection = SecurityMode.ENCRYPT if pay_encrypt else (
            SecurityMode.SIGN if (attrs & SECURITY_ATTR_PAYLOAD_PROTECTION_SIGN) else SecurityMode.NONE
        )

    def to_dict(self) -> Dict:
        return {
            "guid_prefix": self.guid_hex,
            "source_ip": self.source_ip,
            "domain_id": self.domain_id,
            "vendor": self.vendor,
            "participant_name": self.participant_name,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "security": {
                "has_identity_token": self.has_identity_token,
                "has_permissions_token": self.has_permissions_token,
                "rtps_protection": self.rtps_protection.value,
                "submsg_protection": self.submsg_protection.value,
                "payload_protection": self.payload_protection.value,
                "auth_strategy": self.auth_strategy.value,
                "security_attributes_raw": hex(self.security_attributes_raw),
                "sign_only": self.sign_only,
                "downgrade_possible": self.downgrade_possible,
                "downgrade_reason": self.downgrade_reason,
            },
            "identity_token": self.identity_token.to_dict() if self.identity_token else None,
            "permissions_token": self.permissions_token.to_dict() if self.permissions_token else None,
        }


@dataclass
class InterceptResult:
    """Complete result from a DDS-Security intercept session."""
    target: str
    domain_id: int
    duration: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    packets_seen: int = 0
    rtps_packets: int = 0
    participants: List[SecurityParticipant] = field(default_factory=list)
    unsecured_participants: List[str] = field(default_factory=list)
    tokens_extracted: int = 0
    sign_only_count: int = 0
    downgrade_candidates: int = 0
    mixed_domain: bool = False
    domain_strategy: AuthStrategy = AuthStrategy.UNKNOWN

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "domain_id": self.domain_id,
            "duration_s": self.duration,
            "timestamp": self.timestamp,
            "packets_seen": self.packets_seen,
            "rtps_packets": self.rtps_packets,
            "participants_total": len(self.participants),
            "unsecured_participants": self.unsecured_participants,
            "tokens_extracted": self.tokens_extracted,
            "sign_only_count": self.sign_only_count,
            "downgrade_candidates": self.downgrade_candidates,
            "mixed_domain": self.mixed_domain,
            "domain_strategy": self.domain_strategy.value,
            "participants": [p.to_dict() for p in self.participants],
        }


# =============================================================================
# RTPS / DDS-Security Parser
# =============================================================================

class DDSSecurityParser:
    """
    Parses raw UDP packets for RTPS frames containing DDS-Security tokens.
    No Scapy dependency — pure struct parsing for portability.
    """

    def parse_rtps(self, data: bytes, src_ip: str) -> Optional[Dict]:
        """
        Parse a UDP payload as an RTPS message.
        Returns a dict with header fields and a list of submessages, or None.
        """
        if len(data) < 20 or data[:4] != RTPS_MAGIC:
            return None

        try:
            major, minor = data[4], data[5]
            vendor_id    = data[6:8]
            guid_prefix  = data[8:20]
        except IndexError:
            return None

        vendor = VENDOR_IDS.get(bytes(vendor_id), f"Unknown({vendor_id.hex()})")
        submessages = self._parse_submessages(data[20:])

        return {
            "version": (major, minor),
            "vendor": vendor,
            "vendor_id": vendor_id,
            "guid_prefix": guid_prefix,
            "src_ip": src_ip,
            "submessages": submessages,
        }

    def _parse_submessages(self, data: bytes) -> List[Dict]:
        results = []
        offset = 0
        while offset + 4 <= len(data):
            kind  = data[offset]
            flags = data[offset + 1]
            # Endianness flag: bit 0 of flags
            little = bool(flags & 0x01)
            fmt = "<H" if little else ">H"
            try:
                length = struct.unpack_from(fmt, data, offset + 2)[0]
            except struct.error:
                break

            payload = data[offset + 4: offset + 4 + length]
            if kind == RTPS_SUBMSG_DATA:
                parsed = self._parse_data_submsg(payload, flags)
                if parsed:
                    parsed["kind"] = "DATA"
                    results.append(parsed)

            offset += 4 + length
            if length == 0:
                break

        return results

    def _parse_data_submsg(self, data: bytes, flags: int) -> Optional[Dict]:
        """
        Parse a DATA submessage. Returns dict with param_list if it's a PL_CDR
        (parameter list CDR) payload containing security tokens.
        """
        if len(data) < 20:
            return None

        little    = bool(flags & 0x01)
        has_data  = bool(flags & 0x04)
        has_key   = bool(flags & 0x08)
        inline_qos = bool(flags & 0x02)

        base = 0
        # extra_flags(2) + octets_to_inline_qos(2) + reader_eid(4) + writer_eid(4) + seq_num(8)
        if len(data) < base + 20:
            return None

        base += 20
        if inline_qos:
            # Skip inline QoS — find sentinel
            base = self._skip_param_list(data, base, little)
            if base is None:
                return None

        if not (has_data or has_key):
            return None

        if base + 4 > len(data):
            return None

        # Representation identifier
        rep_id = struct.unpack_from(">H", data, base)[0] if len(data) > base + 1 else 0
        base += 4  # rep_id(2) + options(2)

        # PL_CDR_LE = 0x0003, PL_CDR_BE = 0x0002
        is_param_list = rep_id in (0x0002, 0x0003)
        if not is_param_list:
            return None

        pl_little = (rep_id == 0x0003)
        params = self._parse_param_list(data[base:], pl_little)
        return {"params": params, "little_endian": pl_little}

    def _parse_param_list(self, data: bytes, little: bool) -> Dict[int, bytes]:
        """Parse a CDR parameter list into {pid: value_bytes} dict."""
        params: Dict[int, bytes] = {}
        offset = 0
        fmt_pid = "<H" if little else ">H"
        fmt_len = "<H" if little else ">H"

        while offset + 4 <= len(data):
            pid = struct.unpack_from(fmt_pid, data, offset)[0]
            length = struct.unpack_from(fmt_len, data, offset + 2)[0]
            offset += 4
            value = data[offset: offset + length]
            params[pid] = value
            offset += length
            # Align to 4 bytes
            if offset % 4:
                offset += 4 - (offset % 4)
            if pid == PID_SENTINEL:
                break

        return params

    def _skip_param_list(self, data: bytes, start: int, little: bool) -> Optional[int]:
        """Skip over an inline QoS parameter list; return offset after sentinel."""
        fmt = "<H" if little else ">H"
        offset = start
        while offset + 4 <= len(data):
            pid    = struct.unpack_from(fmt, data, offset)[0]
            length = struct.unpack_from(fmt, data, offset + 2)[0]
            offset += 4 + length
            if pid == PID_SENTINEL:
                return offset
        return None

    def extract_token(self, raw: bytes, token_class: str) -> Optional[RawToken]:
        """
        Parse a DDS-Security token from a raw PID value.
        Token wire format (CDR):
          class_id_len(4) + class_id_str + pad
          properties_count(4) + [name_len(4)+name + value_len(4)+value] * N
          binary_properties_count(4) + [name_len(4)+name + value_len(4)+value + propagate(1)] * N
        """
        if len(raw) < 8:
            return None
        try:
            little = True  # DDS-Security tokens use LE CDR by convention
            offset = 0
            # class_id
            cid_len = struct.unpack_from("<I", raw, offset)[0]
            offset += 4
            if offset + cid_len > len(raw):
                return None
            class_id = raw[offset:offset + cid_len].rstrip(b"\x00").decode("utf-8", errors="replace")
            offset += cid_len
            # 4-byte align
            while offset % 4:
                offset += 1

            properties: Dict[str, bytes] = {}
            binary_properties: Dict[str, bytes] = {}

            # properties sequence
            if offset + 4 > len(raw):
                return RawToken(token_class, class_id, raw_bytes=raw)
            prop_count = struct.unpack_from("<I", raw, offset)[0]
            offset += 4
            for _ in range(min(prop_count, 64)):
                name, val, offset = self._read_string_value(raw, offset)
                if name is None:
                    break
                properties[name] = val

            # binary_properties sequence
            if offset + 4 > len(raw):
                return RawToken(token_class, class_id, properties, {}, raw)
            bprop_count = struct.unpack_from("<I", raw, offset)[0]
            offset += 4
            for _ in range(min(bprop_count, 64)):
                name, val, offset = self._read_binary_value(raw, offset)
                if name is None:
                    break
                binary_properties[name] = val

            return RawToken(token_class, class_id, properties, binary_properties, raw)

        except (struct.error, UnicodeDecodeError, OverflowError):
            return RawToken(token_class, "parse_error", raw_bytes=raw)

    def _read_string_value(self, data: bytes, offset: int) -> Tuple[Optional[str], bytes, int]:
        if offset + 4 > len(data):
            return None, b"", offset
        name_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        if offset + name_len > len(data):
            return None, b"", offset
        name = data[offset:offset + name_len].rstrip(b"\x00").decode("utf-8", errors="replace")
        offset += name_len
        while offset % 4: offset += 1

        if offset + 4 > len(data):
            return name, b"", offset
        val_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        val = data[offset:offset + val_len]
        offset += val_len
        while offset % 4: offset += 1
        return name, val, offset

    def _read_binary_value(self, data: bytes, offset: int) -> Tuple[Optional[str], bytes, int]:
        if offset + 4 > len(data):
            return None, b"", offset
        name_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        name = data[offset:offset + name_len].rstrip(b"\x00").decode("utf-8", errors="replace")
        offset += name_len
        while offset % 4: offset += 1
        if offset + 4 > len(data):
            return name, b"", offset
        val_len = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        val = data[offset:offset + val_len]
        offset += val_len
        offset += 1  # propagate flag
        while offset % 4: offset += 1
        return name, val, offset


# =============================================================================
# Interceptor
# =============================================================================

class DDSSecurityInterceptor:
    """
    Passive DDS-Security traffic interceptor.
    Listens on DDS discovery multicast groups and extracts security tokens
    without sending any packets (stealth mode).
    """

    def __init__(self, domain_id: int = 0, interface: str = "", verbose: bool = False):
        self.domain_id  = domain_id
        self.interface  = interface
        self.verbose    = verbose
        self.parser     = DDSSecurityParser()
        self._running   = False
        self._lock      = threading.Lock()
        self._participants: Dict[bytes, SecurityParticipant] = {}

    def _discovery_port(self, domain_id: int) -> int:
        """DDS discovery multicast port: 7400 + 250*domainId"""
        return DDS_BASE_PORT + DDS_PORT_GAIN_D * domain_id

    def _open_multicast_socket(self, port: int) -> Optional[socket.socket]:
        mc_addr = DDS_DISCOVERY_MC_BASE
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
            sock.bind(("", port))
            mreq = socket.inet_aton(mc_addr) + socket.inet_aton(
                self.interface if self.interface else "0.0.0.0"
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(0.5)
            return sock
        except OSError as e:
            if self.verbose:
                print(f"  [!] Cannot bind multicast socket on port {port}: {e}")
            return None

    def _process_packet(self, data: bytes, src_ip: str):
        parsed = self.parser.parse_rtps(data, src_ip)
        if not parsed:
            return

        guid_prefix = parsed["guid_prefix"]
        vendor      = parsed["vendor"]

        for submsg in parsed.get("submessages", []):
            if submsg.get("kind") != "DATA":
                continue
            params = submsg.get("params", {})
            if not params:
                continue

            # Check if this DATA has any security PIDs
            has_sec_pid = any(pid in params for pid in (
                PID_IDENTITY_TOKEN, PID_PERMISSIONS_TOKEN,
                PID_PARTICIPANT_SECURITY_INFO, PID_IDENTITY_STATUS_TOKEN
            ))
            if not has_sec_pid and not params:
                continue

            with self._lock:
                if guid_prefix not in self._participants:
                    # Determine domain from port or default
                    name_bytes = params.get(PID_ENTITY_NAME, b"")
                    name = name_bytes[4:].rstrip(b"\x00").decode("utf-8", errors="replace") if len(name_bytes) > 4 else ""
                    p = SecurityParticipant(
                        guid_prefix=guid_prefix,
                        source_ip=src_ip,
                        domain_id=self.domain_id,
                        vendor=vendor,
                        participant_name=name,
                    )
                    self._participants[guid_prefix] = p
                    if self.verbose:
                        print(f"  [+] New participant: {src_ip}  GUID={guid_prefix.hex()[:16]}...  vendor={vendor}")
                else:
                    self._participants[guid_prefix].last_seen = datetime.now().isoformat()

                p = self._participants[guid_prefix]

                # Parse identity token
                if PID_IDENTITY_TOKEN in params:
                    token = self.parser.extract_token(params[PID_IDENTITY_TOKEN], "identity")
                    if token:
                        p.identity_token = token
                        p.has_identity_token = True
                        if self.verbose:
                            print(f"    [*] Identity token: class_id={token.class_id!r}  "
                                  f"props={list(token.properties.keys())}  "
                                  f"bin_props={list(token.binary_properties.keys())}")

                # Parse permissions token
                if PID_PERMISSIONS_TOKEN in params:
                    token = self.parser.extract_token(params[PID_PERMISSIONS_TOKEN], "permissions")
                    if token:
                        p.permissions_token = token
                        p.has_permissions_token = True
                        if self.verbose:
                            print(f"    [*] Permissions token: class_id={token.class_id!r}")

                # Parse security info attributes
                if PID_PARTICIPANT_SECURITY_INFO in params:
                    raw = params[PID_PARTICIPANT_SECURITY_INFO]
                    if len(raw) >= 8:
                        # participant_security_attributes(4) + plugin_participant_security_attributes(4)
                        attrs = struct.unpack_from("<I", raw, 0)[0]
                        p.security_attributes_raw = attrs
                        p.assess_attack_surface()
                        if self.verbose:
                            print(f"    [*] SecurityInfo: attrs={hex(attrs)}  "
                                  f"rtps={p.rtps_protection.value}  "
                                  f"sign_only={p.sign_only}")

                # Identity status token
                if PID_IDENTITY_STATUS_TOKEN in params:
                    p.has_identity_status = True

    def intercept(self, duration: float = 30.0, target: str = "") -> InterceptResult:
        """
        Passively listen for DDS-Security traffic.
        If target is set, also listen on unicast (best-effort).
        Returns InterceptResult with all discovered participants and tokens.
        """
        port  = self._discovery_port(self.domain_id)
        label = target if target else f"multicast:{DDS_DISCOVERY_MC_BASE}"
        print(f"\n[*] DDS-Security Interceptor listening — domain {self.domain_id}  "
              f"port {port}  duration {duration}s")
        print(f"[*] Target: {label}")
        print(f"[*] Passively capturing security tokens (no packets sent)...\n")

        sock = self._open_multicast_socket(port)
        socks = [sock] if sock else []

        # Also bind unicast if target specified
        if target:
            try:
                uc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                uc_sock.settimeout(0.5)
                uc_sock.bind(("", 0))
                socks.append(uc_sock)
            except OSError:
                pass

        if not socks:
            print("[-] Could not open any sockets. Try running as root.")
            return InterceptResult(label, self.domain_id, duration)

        start      = time.time()
        pkt_count  = 0
        rtps_count = 0

        while time.time() - start < duration:
            for s in socks:
                try:
                    data, (src_ip, _) = s.recvfrom(65535)
                    pkt_count += 1
                    if data[:4] == RTPS_MAGIC:
                        rtps_count += 1
                        self._process_packet(data, src_ip)
                except socket.timeout:
                    continue
                except OSError:
                    break

            elapsed = time.time() - start
            if int(elapsed) % 5 == 0 and self.verbose:
                with self._lock:
                    n = len(self._participants)
                sys.stdout.write(f"\r  [{elapsed:.0f}s] {pkt_count} pkts | {rtps_count} RTPS | {n} participants  ")
                sys.stdout.flush()

        for s in socks:
            try:
                s.close()
            except OSError:
                pass

        print()
        return self._build_result(label, duration, pkt_count, rtps_count)

    def _build_result(self, target: str, duration: float, pkts: int, rtps: int) -> InterceptResult:
        with self._lock:
            participants = list(self._participants.values())

        secured   = [p for p in participants if p.has_identity_token]
        unsecured = [p for p in participants if not p.has_identity_token]
        tokens    = sum(1 for p in secured if p.has_identity_token) + \
                    sum(1 for p in secured if p.has_permissions_token)
        sign_only = sum(1 for p in secured if p.sign_only)
        downgrade = sum(1 for p in participants if p.downgrade_possible)
        mixed     = bool(secured and unsecured)

        # Infer domain auth strategy
        strategy = AuthStrategy.UNKNOWN
        if secured and not unsecured:
            strategy = AuthStrategy.ENFORCE
        elif mixed:
            strategy = AuthStrategy.PERMISSIVE  # Mixed = PERMISSIVE mode accepting unsecured

        result = InterceptResult(
            target=target,
            domain_id=self.domain_id,
            duration=duration,
            packets_seen=pkts,
            rtps_packets=rtps,
            participants=participants,
            unsecured_participants=[p.guid_hex for p in unsecured],
            tokens_extracted=tokens,
            sign_only_count=sign_only,
            downgrade_candidates=downgrade,
            mixed_domain=mixed,
            domain_strategy=strategy,
        )
        return result


# =============================================================================
# Output
# =============================================================================

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
DIM     = "\033[90m"
RESET   = "\033[0m"
BOLD    = "\033[1m"


def print_intercept_report(result: InterceptResult):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}DDS-SECURITY INTERCEPT REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Target:       {result.target}")
    print(f"  Domain ID:    {result.domain_id}")
    print(f"  Duration:     {result.duration:.1f}s")
    print(f"  Packets:      {result.packets_seen} total / {result.rtps_packets} RTPS")
    print(f"  Participants: {len(result.participants)}")
    print(f"{'=' * 65}")

    # Domain-level assessment
    print(f"\n  {BOLD}Domain Security Assessment{RESET}")
    strat_color = GREEN if result.domain_strategy == AuthStrategy.ENFORCE else (
        RED if result.domain_strategy == AuthStrategy.PERMISSIVE else YELLOW
    )
    print(f"  Auth Strategy:   {strat_color}{result.domain_strategy.value}{RESET}")
    print(f"  Mixed Domain:    {RED + 'YES (PERMISSIVE mode confirmed)' + RESET if result.mixed_domain else GREEN + 'No' + RESET}")
    print(f"  Tokens captured: {CYAN}{result.tokens_extracted}{RESET}")
    print(f"  SIGN-only nodes: {YELLOW if result.sign_only_count else DIM}{result.sign_only_count}{RESET}  "
          f"{DIM}(data visible in plaintext){RESET}" if result.sign_only_count else
          f"  SIGN-only nodes: {DIM}0{RESET}")
    print(f"  Downgrade candidates: {RED if result.downgrade_candidates else DIM}{result.downgrade_candidates}{RESET}")

    if result.unsecured_participants:
        print(f"\n  {RED}[!] Unsecured participants (downgrade/infiltration targets):{RESET}")
        for guid in result.unsecured_participants[:5]:
            print(f"      {DIM}{guid}{RESET}")

    print(f"\n{'─' * 65}")
    print(f"  {BOLD}Participants{RESET}")

    for p in result.participants:
        sec_icon = f"{GREEN}[SEC]{RESET}" if p.has_identity_token else f"{RED}[OPEN]{RESET}"
        enc_str  = f"{p.rtps_protection.value}" if p.has_identity_token else "NONE"
        enc_color = RED if enc_str in ("NONE", "SIGN") else GREEN

        print(f"\n  {sec_icon} {p.source_ip:<16}  GUID={p.guid_hex[:16]}...")
        print(f"       Vendor: {DIM}{p.vendor}{RESET}")
        if p.participant_name:
            print(f"       Name:   {p.participant_name}")
        print(f"       RTPS protection:    {enc_color}{enc_str}{RESET}")
        print(f"       Submsg protection:  {p.submsg_protection.value}")
        print(f"       Payload protection: {p.payload_protection.value}")

        if p.identity_token:
            print(f"       {CYAN}Identity Token:{RESET}  class_id={p.identity_token.class_id!r}")
            if p.identity_token.binary_properties:
                for k in list(p.identity_token.binary_properties.keys())[:3]:
                    blen = len(p.identity_token.binary_properties[k])
                    print(f"         {DIM}bin[{k!r}] = {blen} bytes{RESET}")

        if p.permissions_token:
            print(f"       {CYAN}Permissions Token:{RESET} class_id={p.permissions_token.class_id!r}")

        if p.sign_only:
            print(f"       {YELLOW}[!] SIGN-ONLY: RTPS payload visible in plaintext{RESET}")
        if p.downgrade_possible:
            print(f"       {RED}[!] DOWNGRADE: {p.downgrade_reason}{RESET}")

    # Attack surface summary
    print(f"\n{'─' * 65}")
    print(f"  {BOLD}Attack Surface{RESET}")

    if result.tokens_extracted > 0:
        print(f"  {GREEN}[+]{RESET} {result.tokens_extracted} security tokens captured — "
              f"feed to: {CYAN}sros2-harvest{RESET} for X.509 extraction")
    if result.sign_only_count > 0:
        print(f"  {YELLOW}[!]{RESET} {result.sign_only_count} SIGN-only participant(s) — "
              f"topic payload visible in plaintext. Use {CYAN}sros2-infiltrate --mode eavesdrop{RESET}")
    if result.mixed_domain:
        print(f"  {RED}[!]{RESET} Mixed domain (PERMISSIVE mode) — unsecured participant "
              f"can JOIN. Use {CYAN}sros2-infiltrate --mode downgrade{RESET}")
    if result.downgrade_candidates > 0:
        print(f"  {RED}[!]{RESET} {result.downgrade_candidates} participant(s) with no RTPS protection — "
              f"full topic injection possible via Phase 2 modules")
    if not result.participants:
        print(f"  {DIM}No participants captured — try longer duration or confirm domain ID{RESET}")

    print(f"\n{'=' * 65}\n")


def export_json(result: InterceptResult, path: str):
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[+] Intercept results saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDS-Security Interceptor (Phase 5B Module 1)")
    parser.add_argument("--target", "-t", default="", help="Target IP (optional; enables unicast)")
    parser.add_argument("--domain-id", "-d", type=int, default=0, help="DDS Domain ID (default: 0)")
    parser.add_argument("--duration", type=float, default=30.0, help="Listen duration in seconds")
    parser.add_argument("--interface", default="", help="Network interface IP to bind")
    parser.add_argument("-o", "--output", help="Save JSON output to file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    interceptor = DDSSecurityInterceptor(
        domain_id=args.domain_id,
        interface=args.interface,
        verbose=args.verbose,
    )
    result = interceptor.intercept(duration=args.duration, target=args.target)
    print_intercept_report(result)

    if args.output:
        export_json(result, args.output)
