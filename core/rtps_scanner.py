#!/usr/bin/env python3
"""
rtps_scanner.py - RTPS/DDS Network Discovery Scanner
======================================================
Active and passive scanner for discovering DDS participants on a network.

Techniques:
1. SPDP Probe — Craft and send RTPS SPDP discovery packets to multicast/unicast
2. Port Scan — Check for DDS-specific ports across domain ID ranges
3. Passive Sniff — Listen for RTPS traffic on multicast groups

Author: Gh057x
"""

import socket
import struct
import time
import json
import os
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from core.rtps_parser import (
    RTPSParser, DDSParticipant, DDSPortCalculator,
    RTPS_MAGIC, VendorId, ENTITYID_SPDP_BUILTIN_WRITER,
    ENTITYID_SPDP_BUILTIN_READER, ENTITYID_PARTICIPANT,
)


# =============================================================================
# SPDP Probe Builder
# =============================================================================

class SPDPProbeBuilder:
    """
    Crafts RTPS SPDP (Simple Participant Discovery Protocol) probe packets.
    
    An SPDP probe is a legitimate discovery message that asks DDS participants
    to announce themselves. This is how DDS works by design — no exploit needed.
    """

    # Our fake GUID prefix for probes (identifiable for forensics)
    PROBE_GUID_PREFIX = bytes([
        0xDE, 0xAD, 0xBE, 0xEF,  # Distinctive marker
        0x52, 0x32, 0x52,         # "R2R" (ROS2Reaper)
        0x00, 0x00, 0x00, 0x00, 0x01  # Instance
    ])

    @classmethod
    def build_spdp_probe(cls, domain_id: int = 0, participant_id: int = 0,
                          guid_prefix: bytes = None) -> bytes:
        """
        Build a minimal SPDP discovery probe packet.
        
        This mimics what a legitimate DDS participant sends to discover
        other participants in the domain. The response reveals:
        - Participant GUIDs
        - Vendor/version info
        - Network locators
        - Whether DDS-Security is enabled
        - Participant names (often reveals ROS 2 node names)
        """
        if guid_prefix is None:
            guid_prefix = cls.PROBE_GUID_PREFIX

        packet = bytearray()

        # --- RTPS Header (20 bytes) ---
        packet.extend(RTPS_MAGIC)          # Protocol
        packet.append(0x02)                 # Version Major
        packet.append(0x04)                 # Version Minor (2.4 = modern)
        packet.extend(b"\x01\x0F")          # Vendor ID: pose as eProsima Fast DDS
        packet.extend(guid_prefix)          # GUID Prefix (12 bytes)

        # --- INFO_DST Submessage (optional, helps routing) ---
        # Skip for multicast probes

        # --- DATA Submessage containing SPDP ParticipantData ---
        data_submsg = cls._build_spdp_data_submessage(
            domain_id, participant_id, guid_prefix
        )
        packet.extend(data_submsg)

        return bytes(packet)

    @classmethod
    def _build_spdp_data_submessage(cls, domain_id: int, participant_id: int,
                                      guid_prefix: bytes) -> bytes:
        """Build a DATA submessage with minimal SPDP participant data"""
        submsg = bytearray()

        # Build the serialized data payload first (parameter list)
        serialized_data = cls._build_participant_data_params(
            domain_id, participant_id, guid_prefix
        )

        # CDR encapsulation header (little-endian CDR1)
        cdr_header = b"\x00\x01\x00\x00"  # LE CDR, 0 options

        payload = bytearray()
        # Extra flags (2 bytes)
        payload.extend(b"\x00\x00")
        # Octets to inline QoS (2 bytes) — no inline QoS
        payload.extend(struct.pack("<H", 16))  # octets to next field after this = reader+writer+seqnum
        # Reader Entity ID (4 bytes) — SPDP built-in reader
        payload.extend(ENTITYID_SPDP_BUILTIN_READER)
        # Writer Entity ID (4 bytes) — SPDP built-in writer
        payload.extend(ENTITYID_SPDP_BUILTIN_WRITER)
        # Sequence Number (8 bytes)
        payload.extend(struct.pack("<II", 0, 1))  # seq_num_high=0, seq_num_low=1
        # CDR header + serialized data
        payload.extend(cdr_header)
        payload.extend(serialized_data)

        # --- Submessage Header (4 bytes) ---
        submsg.append(0x15)  # DATA submessage kind
        submsg.append(0x05)  # Flags: little-endian (0x01) + data present (0x04)
        submsg.extend(struct.pack("<H", len(payload)))  # Length
        submsg.extend(payload)

        # Pad to 4-byte alignment
        while len(submsg) % 4 != 0:
            submsg.append(0x00)

        return bytes(submsg)

    @classmethod
    def _build_participant_data_params(cls, domain_id: int, participant_id: int,
                                         guid_prefix: bytes) -> bytes:
        """Build the parameter list for SPDP participant data"""
        params = bytearray()

        # Protocol Version
        params.extend(cls._param(0x0015, bytes([0x02, 0x04, 0x00, 0x00])))

        # Vendor ID (eProsima Fast DDS)
        params.extend(cls._param(0x0016, bytes([0x01, 0x0F, 0x00, 0x00])))

        # Domain ID
        params.extend(cls._param(0x000F, struct.pack("<I", domain_id)))

        # Participant Lease Duration (100 seconds)
        params.extend(cls._param(0x0002, struct.pack("<II", 100, 0)))

        # Builtin Endpoint Set (announce we have discovery endpoints)
        endpoint_set = 0x3F  # Standard builtin endpoints
        params.extend(cls._param(0x0058, struct.pack("<I", endpoint_set)))

        # Default Unicast Locator (will be filled by receiver)
        # We use 0.0.0.0:0 as placeholder
        locator = bytearray(24)
        struct.pack_into("<I", locator, 0, 1)    # kind = UDPv4 (little-endian CDR)
        struct.pack_into("<I", locator, 4, 0)    # port = 0
        # address bytes left as 0
        params.extend(cls._param(0x0031, bytes(locator)))

        # Participant Name (PID_ENTITY_NAME = 0x0062)
        name = f"ros2reaper_probe_{participant_id}"
        name_bytes = name.encode("utf-8") + b"\x00"
        name_data = struct.pack("<I", len(name_bytes)) + name_bytes
        while len(name_data) % 4 != 0:
            name_data += b"\x00"
        params.extend(cls._param(0x0062, name_data))

        # PID_SENTINEL (terminates parameter list)
        params.extend(struct.pack("<HH", 0x0001, 0x0000))

        return bytes(params)

    @staticmethod
    def _param(pid: int, value: bytes) -> bytes:
        """Build a single RTPS parameter (PID + length + value, 4-byte aligned)"""
        # Pad value to 4-byte boundary
        padded = bytearray(value)
        while len(padded) % 4 != 0:
            padded.append(0x00)
        return struct.pack("<HH", pid, len(padded)) + bytes(padded)


# =============================================================================
# Scanner
# =============================================================================

@dataclass
class ScanResult:
    """Results from a single scan operation"""
    scan_type: str
    timestamp: str
    target: str
    domain_id: int
    participants: List[DDSParticipant] = field(default_factory=list)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    duration_sec: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "target": self.target,
            "domain_id": self.domain_id,
            "participants_found": len(self.participants),
            "participants": [p.to_dict() for p in self.participants],
            "open_ports": self.open_ports,
            "errors": self.errors,
            "duration_sec": round(self.duration_sec, 2),
        }


class RTPSScanner:
    """
    Network scanner for DDS/RTPS participant discovery.
    
    Supports:
    - Active SPDP probing (multicast and unicast)
    - DDS port scanning across domain ID ranges
    - Passive RTPS traffic capture
    """

    # RTPS multicast groups
    SPDP_MULTICAST_IPV4 = "239.255.0.1"
    DEFAULT_TIMEOUT = 3.0
    DEFAULT_MAX_WORKERS = 20

    def __init__(self, timeout: float = DEFAULT_TIMEOUT,
                 max_workers: int = DEFAULT_MAX_WORKERS,
                 verbose: bool = False):
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.parser = RTPSParser()
        self._discovered_lock = Lock()
        self._discovered: Dict[str, DDSParticipant] = {}  # guid_hex -> participant

    def _log(self, msg: str, level: str = "INFO"):
        """Internal logging"""
        if self.verbose or level in ("WARNING", "ERROR"):
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] [{level}] {msg}")

    # ----- Active Discovery: SPDP Probe -----

    def spdp_probe(self, target: str = None, domain_id: int = 0,
                    timeout: float = None) -> List[DDSParticipant]:
        """
        Send an SPDP discovery probe and collect responses.
        
        Args:
            target: IP address to probe (None = multicast)
            domain_id: DDS domain ID to probe
            timeout: Response wait time in seconds
            
        Returns:
            List of discovered DDSParticipant objects
        """
        if timeout is None:
            timeout = self.timeout

        probe = SPDPProbeBuilder.build_spdp_probe(domain_id=domain_id)
        port = DDSPortCalculator.discovery_multicast(domain_id)

        if target is None:
            target = self.SPDP_MULTICAST_IPV4
            self._log(f"Sending SPDP probe to multicast {target}:{port} (domain {domain_id})")
        else:
            self._log(f"Sending SPDP probe to {target}:{port} (domain {domain_id})")

        participants = []

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)

            # For multicast, set TTL
            if target == self.SPDP_MULTICAST_IPV4:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

            # Send probe
            sock.sendto(probe, (target, port))
            self._log(f"Probe sent ({len(probe)} bytes), waiting {timeout}s for responses...")

            # Also probe unicast discovery ports
            for pid in range(5):
                unicast_port = DDSPortCalculator.discovery_unicast(domain_id, pid)
                if target != self.SPDP_MULTICAST_IPV4:
                    try:
                        sock.sendto(probe, (target, unicast_port))
                    except Exception:
                        pass

            # Collect responses
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                    source_ip, source_port = addr

                    if not RTPSParser.is_rtps(data):
                        continue

                    participant = RTPSParser.extract_participant(
                        data, source_ip=source_ip, source_port=source_port
                    )

                    if participant:
                        guid_hex = participant.guid_prefix_hex()
                        # Skip our own probes
                        if participant.guid_prefix == SPDPProbeBuilder.PROBE_GUID_PREFIX:
                            continue

                        with self._discovered_lock:
                            if guid_hex not in self._discovered:
                                self._discovered[guid_hex] = participant
                                participants.append(participant)
                                self._log(
                                    f"[+] Discovered: {participant.vendor_name} "
                                    f"at {source_ip}:{source_port} "
                                    f"(name={participant.participant_name}, "
                                    f"security={participant.has_security})"
                                )

                except socket.timeout:
                    break
                except Exception as e:
                    self._log(f"Error receiving: {e}", "WARNING")
                    break

            sock.close()

        except PermissionError:
            self._log("Permission denied — try running with sudo for raw socket access", "ERROR")
        except Exception as e:
            self._log(f"SPDP probe error: {e}", "ERROR")

        self._log(f"SPDP probe complete: {len(participants)} participants discovered")
        return participants

    # ----- Port Scanning -----

    def port_scan(self, target: str, domain_ids: List[int] = None,
                   max_participants: int = 3) -> Dict[str, List[int]]:
        """
        Scan for DDS ports on a target host across domain ID range.
        
        Uses calculated DDS ports (not random) based on RTPS spec.
        """
        if domain_ids is None:
            domain_ids = list(range(0, 11))  # Domains 0-10

        ports = DDSPortCalculator.ports_for_domain_range(
            domain_ids[0], domain_ids[-1], max_participants
        )

        self._log(f"Scanning {target} for {len(ports)} DDS ports "
                   f"(domains {domain_ids[0]}-{domain_ids[-1]})")

        open_ports = []

        def check_port(port: int) -> Optional[int]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.0)
                # Send a minimal RTPS probe
                probe = SPDPProbeBuilder.build_spdp_probe()
                sock.sendto(probe, (target, port))
                try:
                    data, _ = sock.recvfrom(65535)
                    if RTPSParser.is_rtps(data):
                        sock.close()
                        return port
                except socket.timeout:
                    pass
                sock.close()
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(check_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    port_info = DDSPortCalculator.identify_port(result)
                    info_str = ""
                    if port_info:
                        info_str = f" (domain={port_info['domain_id']}, type={port_info['type']})"
                    self._log(f"[+] Open DDS port: {target}:{result}{info_str}")
                    open_ports.append(result)

        return {target: sorted(open_ports)}

    # ----- Network Scan -----

    def network_scan(self, network: str, domain_id: int = 0,
                      timeout: float = None) -> ScanResult:
        """
        Scan an entire network for DDS participants.
        
        Combines:
        1. Multicast SPDP probe (finds all participants on the LAN)
        2. Unicast SPDP probes to each host
        3. DDS port scanning on responsive hosts
        
        Args:
            network: CIDR notation (e.g., "192.168.1.0/24")
            domain_id: DDS domain to probe
            timeout: Per-host timeout
        """
        start_time = time.time()
        result = ScanResult(
            scan_type="network_scan",
            timestamp=datetime.now().isoformat(),
            target=network,
            domain_id=domain_id,
        )

        self._log(f"Starting network scan: {network} (domain {domain_id})")

        # Phase 1: Multicast probe
        self._log("Phase 1: Multicast SPDP discovery...")
        multicast_results = self.spdp_probe(domain_id=domain_id, timeout=timeout)
        result.participants.extend(multicast_results)

        # Phase 2: Unicast probe to each host
        try:
            net = ipaddress.ip_network(network, strict=False)
            hosts = [str(h) for h in net.hosts()]
        except ValueError as e:
            result.errors.append(f"Invalid network: {e}")
            return result

        self._log(f"Phase 2: Unicast SPDP probes to {len(hosts)} hosts...")

        def probe_host(host: str) -> List[DDSParticipant]:
            return self.spdp_probe(target=host, domain_id=domain_id, timeout=1.5)

        with ThreadPoolExecutor(max_workers=min(self.max_workers, 50)) as executor:
            futures = {executor.submit(probe_host, h): h for h in hosts}
            for future in as_completed(futures):
                try:
                    host_results = future.result()
                    for p in host_results:
                        guid_hex = p.guid_prefix_hex()
                        with self._discovered_lock:
                            if guid_hex not in self._discovered:
                                self._discovered[guid_hex] = p
                                result.participants.append(p)
                except Exception as e:
                    host = futures[future]
                    result.errors.append(f"Error probing {host}: {e}")

        result.duration_sec = time.time() - start_time
        self._log(
            f"Network scan complete: {len(result.participants)} participants found "
            f"in {result.duration_sec:.1f}s"
        )

        return result

    # ----- Passive Listener -----

    def passive_listen(self, domain_id: int = 0, duration: float = 30.0,
                        interface: str = None) -> List[DDSParticipant]:
        """
        Passively listen for RTPS traffic on the SPDP multicast group.
        
        This is completely passive — no packets are sent.
        Useful for stealth reconnaissance.
        """
        port = DDSPortCalculator.discovery_multicast(domain_id)
        multicast_group = self.SPDP_MULTICAST_IPV4
        participants = []

        self._log(f"Passive listening on {multicast_group}:{port} for {duration}s...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", port))

            # Join multicast group
            mreq = struct.pack(
                "4s4s",
                socket.inet_aton(multicast_group),
                socket.inet_aton("0.0.0.0")
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(2.0)

            deadline = time.time() + duration

            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                    source_ip, source_port = addr

                    if not RTPSParser.is_rtps(data):
                        continue

                    participant = RTPSParser.extract_participant(
                        data, source_ip=source_ip, source_port=source_port
                    )

                    if participant:
                        guid_hex = participant.guid_prefix_hex()
                        with self._discovered_lock:
                            if guid_hex not in self._discovered:
                                self._discovered[guid_hex] = participant
                                participants.append(participant)
                                self._log(
                                    f"[+] Heard: {participant.vendor_name} "
                                    f"from {source_ip}:{source_port} "
                                    f"(name={participant.participant_name})"
                                )

                except socket.timeout:
                    continue
                except Exception as e:
                    self._log(f"Listen error: {e}", "WARNING")

            # Leave multicast group
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            sock.close()

        except PermissionError:
            self._log("Permission denied — try running with sudo", "ERROR")
        except Exception as e:
            self._log(f"Passive listen error: {e}", "ERROR")

        self._log(f"Passive listen complete: {len(participants)} participants heard")
        return participants

    # ----- Utility -----

    def get_all_discovered(self) -> List[DDSParticipant]:
        """Return all participants discovered across all scan methods"""
        with self._discovered_lock:
            return list(self._discovered.values())

    def clear_discovered(self):
        """Reset the discovered participants cache"""
        with self._discovered_lock:
            self._discovered.clear()

    def export_results(self, filepath: str, result: ScanResult = None):
        """Export scan results to JSON"""
        if result:
            data = result.to_dict()
        else:
            data = {
                "timestamp": datetime.now().isoformat(),
                "total_participants": len(self._discovered),
                "participants": [p.to_dict() for p in self.get_all_discovered()],
            }

        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        self._log(f"Results exported to {filepath}")
