#!/usr/bin/env python3
"""
mavlink_discovery.py - Phase 7: MAVLink Endpoint Discovery & Fingerprinting

Discovers MAVLink-speaking endpoints on the network (autopilots, GCS, companion
computers, telemetry radios). Identifies autopilot type (ArduPilot, PX4, generic),
vehicle class (rover, copter, plane, sub), and firmware version.

MAVLink is the de-facto protocol for UGV/UAV communication. It runs over
UDP (14550/14540), TCP (5760/5762), and serial links. The protocol is
unauthenticated by default — MAVLink v2 signing is optional and rarely enabled.

Standard ports:
  - UDP/14550 : GCS ↔ Autopilot (default QGroundControl / MAVProxy listen)
  - UDP/14540 : SITL / offboard companion link (PX4 default)
  - UDP/5760  : Legacy GCS link (MAVProxy)
  - TCP/5762  : MAVProxy TCP output
  - UDP/14580 : Secondary GCS link

Attack surface mapped:
  - Endpoint enumeration (IP, port, protocol version)
  - Autopilot fingerprinting (ArduPilot/PX4/generic, firmware version)
  - Vehicle type identification (rover, copter, plane, submarine, etc.)
  - MAVLink v1 vs v2 detection
  - Signing status check (v2 message signing enabled/disabled)
  - Component enumeration (autopilot, camera, gimbal, companion)

Author  : Gh057x
Phase   : 7 — MAVLink / Autopilot Security
Requires: pymavlink
"""

import socket
import struct
import time
import json
import sys
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import ipaddress


# ============================================================================
# MAVLink Constants
# ============================================================================

MAVLINK_STX_V1 = 0xFE
MAVLINK_STX_V2 = 0xFD

MAVLINK_DEFAULT_PORTS = [14550, 14540, 5760, 5762, 14580]

MAV_AUTOPILOT = {
    0: "Generic",
    1: "Reserved",
    2: "Slugs",
    3: "ArduPilotMega",
    4: "OpenPilot",
    5: "Generic WP Only",
    6: "Generic Mission Full",
    7: "Invalid",
    8: "PPZ",
    9: "UDB",
    10: "FP",
    11: "PX4",
    12: "SMACCMPILOT",
    13: "AutoQuad",
    14: "Armazila",
    15: "Aerob",
    16: "ASLUAV",
    17: "SmartAP",
    18: "AirRails",
    19: "Reflex",
}

MAV_TYPE = {
    0: "Generic",
    1: "Fixed Wing",
    2: "Quadrotor",
    3: "Coaxial Helicopter",
    4: "Helicopter",
    5: "Antenna Tracker",
    6: "GCS",
    7: "Airship",
    8: "Free Balloon",
    9: "Rocket",
    10: "Ground Rover",
    11: "Surface Boat",
    12: "Submarine",
    13: "Hexarotor",
    14: "Octorotor",
    15: "Tricopter",
    16: "Flapping Wing",
    17: "Kite",
    18: "Onboard Controller",
    19: "VTOL Tiltrotor",
    20: "VTOL Tailsitter",
    26: "Gimbal",
    27: "ADSB",
    28: "Parafoil",
    29: "Dodecarotor",
    30: "Camera",
    31: "Charging Station",
    32: "FLARM",
    33: "Servo",
    34: "ODID",
    35: "Decarotor",
    36: "Battery",
    37: "Parachute",
    38: "Log",
    39: "OSD",
    40: "IMU",
    41: "GPS",
    42: "Winch",
    43: "Generic Multirotor",
    44: "Illuminator",
}

MAV_STATE = {
    0: "UNINIT",
    1: "BOOT",
    2: "CALIBRATING",
    3: "STANDBY",
    4: "ACTIVE",
    5: "CRITICAL",
    6: "EMERGENCY",
    7: "POWEROFF",
    8: "FLIGHT_TERMINATION",
}

MAV_MODE_FLAG = {
    0x01: "CUSTOM_MODE_ENABLED",
    0x02: "TEST_ENABLED",
    0x04: "AUTO_ENABLED",
    0x08: "GUIDED_ENABLED",
    0x10: "STABILIZE_ENABLED",
    0x20: "HIL_ENABLED",
    0x40: "MANUAL_INPUT_ENABLED",
    0x80: "SAFETY_ARMED",
}

MAVLINK_MSG_ID_HEARTBEAT = 0
MAVLINK_MSG_ID_AUTOPILOT_VERSION = 148
MAVLINK_MSG_ID_COMMAND_LONG = 76
MAV_CMD_REQUEST_AUTOPILOT_CAPABILITIES = 520


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class MAVLinkComponent:
    """A MAVLink component on a system (autopilot, camera, gimbal, etc.)"""
    system_id: int
    component_id: int
    component_type: str = "unknown"
    last_heartbeat: float = 0

    def to_dict(self):
        return {
            "system_id": self.system_id,
            "component_id": self.component_id,
            "component_type": self.component_type,
            "last_heartbeat": datetime.fromtimestamp(self.last_heartbeat).isoformat() if self.last_heartbeat else None,
        }


@dataclass
class MAVLinkEndpoint:
    """Represents a discovered MAVLink endpoint"""
    ip: str
    port: int
    protocol: str = "udp"
    mavlink_version: int = 0
    system_id: int = 0
    component_id: int = 0
    autopilot_type: str = "unknown"
    autopilot_type_id: int = -1
    vehicle_type: str = "unknown"
    vehicle_type_id: int = -1
    system_state: str = "unknown"
    base_mode: int = 0
    custom_mode: int = 0
    is_armed: bool = False
    signing_enabled: bool = False
    firmware_version: str = ""
    firmware_hash: str = ""
    board_version: int = 0
    capabilities: int = 0
    capability_flags: List[str] = field(default_factory=list)
    components: List[MAVLinkComponent] = field(default_factory=list)
    response_time_ms: float = 0
    last_seen: float = field(default_factory=time.time)
    raw_heartbeat: Optional[bytes] = field(default=None, repr=False)

    def to_dict(self):
        d = {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "mavlink_version": self.mavlink_version,
            "system_id": self.system_id,
            "component_id": self.component_id,
            "autopilot_type": self.autopilot_type,
            "vehicle_type": self.vehicle_type,
            "system_state": self.system_state,
            "is_armed": self.is_armed,
            "signing_enabled": self.signing_enabled,
            "firmware_version": self.firmware_version,
            "board_version": self.board_version,
            "capabilities": hex(self.capabilities) if self.capabilities else "0x0",
            "capability_flags": self.capability_flags,
            "components": [c.to_dict() for c in self.components],
            "response_time_ms": round(self.response_time_ms, 2),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
        }
        if self.firmware_hash:
            d["firmware_hash"] = self.firmware_hash
        return d


@dataclass
class DiscoveryResult:
    """Container for a full discovery scan"""
    scan_type: str = ""
    target: str = ""
    ports_scanned: List[int] = field(default_factory=list)
    endpoints: List[MAVLinkEndpoint] = field(default_factory=list)
    duration_sec: float = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "module": "mavlink_discovery",
            "timestamp": datetime.now().isoformat(),
            "scan_type": self.scan_type,
            "target": self.target,
            "ports_scanned": self.ports_scanned,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "duration_sec": round(self.duration_sec, 2),
            "errors": self.errors,
            "summary": {
                "total_endpoints": len(self.endpoints),
                "autopilots": len([e for e in self.endpoints if e.autopilot_type != "GCS"]),
                "gcs_stations": len([e for e in self.endpoints if e.vehicle_type == "GCS"]),
                "armed": len([e for e in self.endpoints if e.is_armed]),
                "signing_enabled": len([e for e in self.endpoints if e.signing_enabled]),
                "v1_only": len([e for e in self.endpoints if e.mavlink_version == 1]),
                "v2": len([e for e in self.endpoints if e.mavlink_version == 2]),
            },
        }


# ============================================================================
# MAVLink v1/v2 Packet Builder (no pymavlink dependency for probes)
# ============================================================================

class MAVLinkProbe:
    """Build minimal MAVLink heartbeat probes without pymavlink"""

    @staticmethod
    def build_heartbeat_v1(system_id: int = 255, component_id: int = 0) -> bytes:
        """
        Build a MAVLink v1 HEARTBEAT packet.

        v1 format (8-byte header + 9-byte heartbeat payload + 2-byte checksum):
          0xFE | payload_len | seq | sys_id | comp_id | msg_id | payload... | ckA | ckB
        """
        payload = struct.pack("<IBBBBB",
            0,          # custom_mode (uint32)
            6,          # type: MAV_TYPE_GCS
            0,          # autopilot: generic
            0,          # base_mode
            0,          # system_status
            3,          # mavlink_version (v1)
        )
        header = struct.pack("<BBBBB",
            len(payload),   # payload length
            0,              # sequence
            system_id,
            component_id,
            MAVLINK_MSG_ID_HEARTBEAT,
        )
        msg = header + payload
        crc = MAVLinkProbe._crc16(msg, extra_crc=50)
        return bytes([MAVLINK_STX_V1]) + msg + struct.pack("<H", crc)

    @staticmethod
    def build_heartbeat_v2(system_id: int = 255, component_id: int = 0) -> bytes:
        """
        Build a MAVLink v2 HEARTBEAT packet.

        v2 format (10-byte header + payload + 2-byte checksum):
          0xFD | payload_len | incompat_flags | compat_flags | seq |
          sys_id | comp_id | msg_id(3 bytes LE) | payload... | ckA | ckB
        """
        payload = struct.pack("<IBBBBB",
            0,          # custom_mode
            6,          # type: MAV_TYPE_GCS
            0,          # autopilot: generic
            0,          # base_mode
            0,          # system_status
            3,          # mavlink_version
        )
        msg_id_bytes = struct.pack("<I", MAVLINK_MSG_ID_HEARTBEAT)[:3]
        header = struct.pack("<BBBBB",
            len(payload),
            0,              # incompat_flags
            0,              # compat_flags
            0,              # sequence
            system_id,
        )
        header += struct.pack("<B", component_id) + msg_id_bytes
        msg = header + payload
        crc = MAVLinkProbe._crc16(msg, extra_crc=50)
        return bytes([MAVLINK_STX_V2]) + msg + struct.pack("<H", crc)

    @staticmethod
    def _crc16(data: bytes, extra_crc: int = 0) -> int:
        """X.25 CRC used by MAVLink"""
        crc = 0xFFFF
        for byte in data:
            tmp = byte ^ (crc & 0xFF)
            tmp ^= (tmp << 4) & 0xFF
            crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
            crc &= 0xFFFF
        # Extra CRC byte (message-specific seed)
        tmp = extra_crc ^ (crc & 0xFF)
        tmp ^= (tmp << 4) & 0xFF
        crc = (crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)
        crc &= 0xFFFF
        return crc


# ============================================================================
# MAVLink Response Parser
# ============================================================================

class MAVLinkParser:
    """Parse incoming MAVLink packets"""

    @staticmethod
    def parse_packet(data: bytes) -> Optional[Dict]:
        """
        Parse a MAVLink v1 or v2 packet from raw bytes.
        Returns dict with header fields and raw payload, or None.
        """
        if not data:
            return None

        stx = data[0]

        if stx == MAVLINK_STX_V1 and len(data) >= 8:
            return MAVLinkParser._parse_v1(data)
        elif stx == MAVLINK_STX_V2 and len(data) >= 12:
            return MAVLinkParser._parse_v2(data)

        return None

    @staticmethod
    def _parse_v1(data: bytes) -> Optional[Dict]:
        payload_len = data[1]
        if len(data) < 6 + payload_len + 2:
            return None
        return {
            "version": 1,
            "payload_len": payload_len,
            "sequence": data[2],
            "system_id": data[3],
            "component_id": data[4],
            "message_id": data[5],
            "payload": data[6:6 + payload_len],
            "signing": False,
        }

    @staticmethod
    def _parse_v2(data: bytes) -> Optional[Dict]:
        payload_len = data[1]
        incompat_flags = data[2]
        if len(data) < 10 + payload_len + 2:
            return None
        msg_id = data[7] | (data[8] << 8) | (data[9] << 16)
        signed = bool(incompat_flags & 0x01)
        return {
            "version": 2,
            "payload_len": payload_len,
            "incompat_flags": incompat_flags,
            "compat_flags": data[3],
            "sequence": data[4],
            "system_id": data[5],
            "component_id": data[6],
            "message_id": msg_id,
            "payload": data[10:10 + payload_len],
            "signing": signed,
        }

    @staticmethod
    def parse_heartbeat(payload: bytes) -> Optional[Dict]:
        """Parse HEARTBEAT message payload (msg_id 0)"""
        if len(payload) < 9:
            return None
        custom_mode, mav_type, autopilot, base_mode, system_status, mav_version = \
            struct.unpack("<IBBBBB", payload[:9])
        return {
            "custom_mode": custom_mode,
            "type": mav_type,
            "type_name": MAV_TYPE.get(mav_type, f"Unknown({mav_type})"),
            "autopilot": autopilot,
            "autopilot_name": MAV_AUTOPILOT.get(autopilot, f"Unknown({autopilot})"),
            "base_mode": base_mode,
            "system_status": system_status,
            "state_name": MAV_STATE.get(system_status, f"Unknown({system_status})"),
            "mavlink_version": mav_version,
            "armed": bool(base_mode & 0x80),
            "mode_flags": [name for bit, name in MAV_MODE_FLAG.items() if base_mode & bit],
        }


# ============================================================================
# MAVLink Endpoint Scanner
# ============================================================================

class MAVLinkScanner:
    """Discover and fingerprint MAVLink endpoints"""

    def __init__(self, timeout: float = 3.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.endpoints: Dict[Tuple[str, int], MAVLinkEndpoint] = {}

    def probe_udp(self, ip: str, port: int) -> Optional[MAVLinkEndpoint]:
        """
        Probe a single UDP endpoint for MAVLink.

        Sends both v1 and v2 heartbeats, listens for response.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            probe_v2 = MAVLinkProbe.build_heartbeat_v2()
            probe_v1 = MAVLinkProbe.build_heartbeat_v1()

            start = time.time()
            sock.sendto(probe_v2, (ip, port))
            sock.sendto(probe_v1, (ip, port))

            endpoint = None
            deadline = time.time() + self.timeout

            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    elapsed = (time.time() - start) * 1000

                    pkt = MAVLinkParser.parse_packet(data)
                    if not pkt:
                        continue

                    if pkt["message_id"] != MAVLINK_MSG_ID_HEARTBEAT:
                        continue

                    hb = MAVLinkParser.parse_heartbeat(pkt["payload"])
                    if not hb:
                        continue

                    endpoint = MAVLinkEndpoint(
                        ip=ip,
                        port=port,
                        protocol="udp",
                        mavlink_version=pkt["version"],
                        system_id=pkt["system_id"],
                        component_id=pkt["component_id"],
                        autopilot_type=hb["autopilot_name"],
                        autopilot_type_id=hb["autopilot"],
                        vehicle_type=hb["type_name"],
                        vehicle_type_id=hb["type"],
                        system_state=hb["state_name"],
                        base_mode=hb["base_mode"],
                        custom_mode=hb["custom_mode"],
                        is_armed=hb["armed"],
                        signing_enabled=pkt.get("signing", False),
                        response_time_ms=elapsed,
                        last_seen=time.time(),
                        raw_heartbeat=data,
                    )

                    if self.verbose:
                        print(f"  [+] {ip}:{port} → {hb['autopilot_name']} "
                              f"({hb['type_name']}) v{pkt['version']} "
                              f"sys={pkt['system_id']} "
                              f"{'ARMED' if hb['armed'] else 'DISARMED'} "
                              f"({elapsed:.1f}ms)")

                    # Keep listening briefly for additional components
                    comp = MAVLinkComponent(
                        system_id=pkt["system_id"],
                        component_id=pkt["component_id"],
                        component_type=hb["type_name"],
                        last_heartbeat=time.time(),
                    )
                    endpoint.components.append(comp)

                except socket.timeout:
                    break

            return endpoint

        except OSError as e:
            if self.verbose:
                print(f"  [-] {ip}:{port} → error: {e}")
            return None
        finally:
            sock.close()

    def probe_tcp(self, ip: str, port: int) -> Optional[MAVLinkEndpoint]:
        """Probe a TCP endpoint for MAVLink"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            start = time.time()
            sock.connect((ip, port))
            elapsed_connect = (time.time() - start) * 1000

            probe_v2 = MAVLinkProbe.build_heartbeat_v2()
            sock.sendall(probe_v2)

            data = b""
            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= 12:
                        break
                except socket.timeout:
                    break

            if not data:
                # Some endpoints stream heartbeats without a probe
                pass

            pkt = MAVLinkParser.parse_packet(data)
            if not pkt or pkt["message_id"] != MAVLINK_MSG_ID_HEARTBEAT:
                return None

            hb = MAVLinkParser.parse_heartbeat(pkt["payload"])
            if not hb:
                return None

            return MAVLinkEndpoint(
                ip=ip,
                port=port,
                protocol="tcp",
                mavlink_version=pkt["version"],
                system_id=pkt["system_id"],
                component_id=pkt["component_id"],
                autopilot_type=hb["autopilot_name"],
                autopilot_type_id=hb["autopilot"],
                vehicle_type=hb["type_name"],
                vehicle_type_id=hb["type"],
                system_state=hb["state_name"],
                base_mode=hb["base_mode"],
                custom_mode=hb["custom_mode"],
                is_armed=hb["armed"],
                signing_enabled=pkt.get("signing", False),
                response_time_ms=elapsed_connect,
                last_seen=time.time(),
                raw_heartbeat=data,
            )

        except (OSError, ConnectionRefusedError):
            return None
        finally:
            sock.close()

    def scan_host(self, ip: str, ports: List[int] = None,
                  protocols: List[str] = None) -> List[MAVLinkEndpoint]:
        """Scan a single host across MAVLink ports"""
        if ports is None:
            ports = MAVLINK_DEFAULT_PORTS
        if protocols is None:
            protocols = ["udp", "tcp"]

        discovered = []
        for port in ports:
            if "udp" in protocols:
                ep = self.probe_udp(ip, port)
                if ep:
                    self.endpoints[(ip, port)] = ep
                    discovered.append(ep)
            if "tcp" in protocols:
                ep = self.probe_tcp(ip, port)
                if ep:
                    self.endpoints[(ip, port)] = ep
                    discovered.append(ep)

        return discovered

    def scan_network(self, cidr: str, ports: List[int] = None,
                     threads: int = 20) -> DiscoveryResult:
        """Scan a CIDR range for MAVLink endpoints"""
        if ports is None:
            ports = MAVLINK_DEFAULT_PORTS

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            return DiscoveryResult(errors=[f"Invalid CIDR: {e}"])

        hosts = [str(h) for h in network.hosts()]
        result = DiscoveryResult(
            scan_type="network",
            target=cidr,
            ports_scanned=ports,
        )

        if self.verbose:
            print(f"[*] Scanning {len(hosts)} hosts × {len(ports)} ports...")

        start = time.time()

        def _scan_one(ip):
            return self.scan_host(ip, ports=ports, protocols=["udp"])

        with ThreadPoolExecutor(max_workers=threads) as pool:
            for endpoints in pool.map(_scan_one, hosts):
                result.endpoints.extend(endpoints)

        result.duration_sec = time.time() - start
        return result

    def passive_listen(self, port: int = 14550, duration: float = 30.0,
                       bind_ip: str = "0.0.0.0") -> DiscoveryResult:
        """
        Passively listen for MAVLink traffic — no probes sent.
        Useful for detecting active autopilots / GCS on the network.
        """
        result = DiscoveryResult(
            scan_type="passive",
            target=f"{bind_ip}:{port}",
            ports_scanned=[port],
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)

        try:
            sock.bind((bind_ip, port))
            if self.verbose:
                print(f"[*] Passive listen on {bind_ip}:{port} for {duration}s...")

            start = time.time()
            seen = set()

            while time.time() - start < duration:
                try:
                    data, (src_ip, src_port) = sock.recvfrom(4096)
                    key = (src_ip, src_port)

                    pkt = MAVLinkParser.parse_packet(data)
                    if not pkt:
                        continue

                    if pkt["message_id"] == MAVLINK_MSG_ID_HEARTBEAT and key not in seen:
                        seen.add(key)
                        hb = MAVLinkParser.parse_heartbeat(pkt["payload"])
                        if not hb:
                            continue

                        ep = MAVLinkEndpoint(
                            ip=src_ip,
                            port=src_port,
                            protocol="udp",
                            mavlink_version=pkt["version"],
                            system_id=pkt["system_id"],
                            component_id=pkt["component_id"],
                            autopilot_type=hb["autopilot_name"],
                            autopilot_type_id=hb["autopilot"],
                            vehicle_type=hb["type_name"],
                            vehicle_type_id=hb["type"],
                            system_state=hb["state_name"],
                            base_mode=hb["base_mode"],
                            custom_mode=hb["custom_mode"],
                            is_armed=hb["armed"],
                            signing_enabled=pkt.get("signing", False),
                            last_seen=time.time(),
                        )
                        result.endpoints.append(ep)

                        if self.verbose:
                            print(f"  [+] {src_ip}:{src_port} → "
                                  f"{hb['autopilot_name']} ({hb['type_name']})")

                except socket.timeout:
                    continue

            result.duration_sec = time.time() - start

        finally:
            sock.close()

        return result


# ============================================================================
# Reporting
# ============================================================================

def print_discovery_report(result: DiscoveryResult):
    """Pretty-print discovery results (ros2reaper style)"""
    if not result.endpoints:
        print("\n[-] No MAVLink endpoints discovered")
        if result.errors:
            for e in result.errors:
                print(f"    [!] {e}")
        return

    print(f"\n\033[92m[+] Discovered {len(result.endpoints)} MAVLink endpoint(s)\033[0m")
    print(f"    Scan: {result.scan_type} | Target: {result.target} | "
          f"Duration: {result.duration_sec:.1f}s\n")

    for i, ep in enumerate(result.endpoints, 1):
        armed_str = "\033[91mARMED\033[0m" if ep.is_armed else "\033[92mDISARMED\033[0m"
        sign_str = "\033[92mSIGNED\033[0m" if ep.signing_enabled else "\033[91mUNSIGNED\033[0m"
        ver_str = f"v{ep.mavlink_version}"

        print(f"  [{i}] {ep.ip}:{ep.port}/{ep.protocol}")
        print(f"      Autopilot:  {ep.autopilot_type}")
        print(f"      Vehicle:    {ep.vehicle_type}")
        print(f"      System ID:  {ep.system_id} | Component: {ep.component_id}")
        print(f"      MAVLink:    {ver_str} | Signing: {sign_str}")
        print(f"      State:      {ep.system_state} | {armed_str}")
        if ep.firmware_version:
            print(f"      Firmware:   {ep.firmware_version}")
        if ep.response_time_ms:
            print(f"      Response:   {ep.response_time_ms:.1f}ms")
        if ep.components:
            comp_str = ", ".join(f"{c.component_type}(id={c.component_id})"
                                for c in ep.components)
            print(f"      Components: {comp_str}")
        print()

    # Summary
    s = result.to_dict()["summary"]
    print(f"  {'─' * 50}")
    print(f"  Summary: {s['total_endpoints']} endpoints | "
          f"{s['autopilots']} autopilots | {s['gcs_stations']} GCS")
    print(f"           {s['armed']} armed | "
          f"{s['signing_enabled']} signed | "
          f"{s['v1_only']} v1-only | {s['v2']} v2")
    print()


def export_json(result: DiscoveryResult, output_file: str):
    """Export results to JSON"""
    with open(output_file, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    print(f"[+] Results exported to {output_file}")


# ============================================================================
# CLI (standalone + framework integration)
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 7: MAVLink endpoint discovery and fingerprinting"
    )
    parser.add_argument("-t", "--target", help="Target IP address")
    parser.add_argument("-n", "--network", help="CIDR range to scan")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=None,
                        help=f"Ports to scan (default: {MAVLINK_DEFAULT_PORTS})")
    parser.add_argument("--passive", action="store_true",
                        help="Passive listen mode (no probes)")
    parser.add_argument("--listen-port", type=int, default=14550,
                        help="Port to listen on in passive mode (default: 14550)")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    scanner = MAVLinkScanner(timeout=args.timeout, verbose=args.verbose)

    if args.passive:
        result = scanner.passive_listen(port=args.listen_port, duration=args.duration)
    elif args.network:
        result = scanner.scan_network(args.network, ports=args.ports, threads=args.threads)
    elif args.target:
        endpoints = scanner.scan_host(args.target, ports=args.ports)
        result = DiscoveryResult(
            scan_type="host",
            target=args.target,
            ports_scanned=args.ports or MAVLINK_DEFAULT_PORTS,
            endpoints=endpoints,
        )
    else:
        parser.print_help()
        return

    print_discovery_report(result)

    if args.output:
        export_json(result, args.output)


if __name__ == "__main__":
    main()
