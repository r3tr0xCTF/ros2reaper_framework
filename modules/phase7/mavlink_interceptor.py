#!/usr/bin/env python3
"""
mavlink_interceptor.py - Phase 7: MAVLink Traffic Interception & Analysis

Passive capture and decode of MAVLink traffic. Extracts GPS tracks,
telemetry streams (battery, attitude, RC channels), and identifies
message patterns for behavioral profiling.

No packets are injected — stealth mode. Useful for mapping the
communication topology and extracting operational intelligence
before active exploitation.

Attack surface mapped:
  - Full message decode and classification
  - GPS track extraction (breadcrumb trail of vehicle positions)
  - Telemetry harvesting (battery, attitude, RC input, sensor data)
  - Communication pattern analysis (which systems talk to which)
  - MAVLink signing detection (v2 signature presence)

Author  : Gh057x
Phase   : 7 — MAVLink / Autopilot Security
Requires: (none — raw socket only; pymavlink optional for deep decode)
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
from collections import defaultdict

from modules.phase7.mavlink_discovery import (
    MAVLinkParser, MAVLinkEndpoint, MAV_TYPE, MAV_AUTOPILOT, MAV_STATE,
    MAVLINK_STX_V1, MAVLINK_STX_V2,
)


# ============================================================================
# MAVLink Message IDs (common subset)
# ============================================================================

MSG_NAMES = {
    0: "HEARTBEAT",
    1: "SYS_STATUS",
    2: "SYSTEM_TIME",
    4: "PING",
    5: "CHANGE_OPERATOR_CONTROL",
    6: "CHANGE_OPERATOR_CONTROL_ACK",
    11: "SET_MODE",
    20: "PARAM_REQUEST_READ",
    21: "PARAM_REQUEST_LIST",
    22: "PARAM_VALUE",
    23: "PARAM_SET",
    24: "GPS_RAW_INT",
    25: "GPS_STATUS",
    26: "SCALED_IMU",
    27: "RAW_IMU",
    28: "RAW_PRESSURE",
    29: "SCALED_PRESSURE",
    30: "ATTITUDE",
    31: "ATTITUDE_QUATERNION",
    32: "LOCAL_POSITION_NED",
    33: "GLOBAL_POSITION_INT",
    34: "RC_CHANNELS_SCALED",
    35: "RC_CHANNELS_RAW",
    36: "SERVO_OUTPUT_RAW",
    37: "MISSION_REQUEST_PARTIAL_LIST",
    38: "MISSION_WRITE_PARTIAL_LIST",
    39: "MISSION_ITEM",
    40: "MISSION_REQUEST",
    41: "MISSION_SET_CURRENT",
    42: "MISSION_CURRENT",
    43: "MISSION_REQUEST_LIST",
    44: "MISSION_COUNT",
    45: "MISSION_CLEAR_ALL",
    46: "MISSION_ITEM_REACHED",
    47: "MISSION_ACK",
    48: "SET_GPS_GLOBAL_ORIGIN",
    49: "GPS_GLOBAL_ORIGIN",
    50: "PARAM_MAP_RC",
    51: "MISSION_REQUEST_INT",
    54: "SAFETY_SET_ALLOWED_AREA",
    55: "SAFETY_ALLOWED_AREA",
    61: "ATTITUDE_QUATERNION_COV",
    62: "NAV_CONTROLLER_OUTPUT",
    63: "GLOBAL_POSITION_INT_COV",
    64: "LOCAL_POSITION_NED_COV",
    65: "RC_CHANNELS",
    66: "REQUEST_DATA_STREAM",
    67: "DATA_STREAM",
    69: "MANUAL_CONTROL",
    70: "RC_CHANNELS_OVERRIDE",
    73: "MISSION_ITEM_INT",
    74: "VFR_HUD",
    75: "COMMAND_INT",
    76: "COMMAND_LONG",
    77: "COMMAND_ACK",
    81: "MANUAL_SETPOINT",
    82: "SET_ATTITUDE_TARGET",
    83: "ATTITUDE_TARGET",
    84: "SET_POSITION_TARGET_LOCAL_NED",
    85: "POSITION_TARGET_LOCAL_NED",
    86: "SET_POSITION_TARGET_GLOBAL_INT",
    87: "POSITION_TARGET_GLOBAL_INT",
    89: "LOCAL_POSITION_NED_SYSTEM_GLOBAL_OFFSET",
    90: "HIL_STATE",
    91: "HIL_CONTROLS",
    92: "HIL_RC_INPUTS_RAW",
    100: "OPTICAL_FLOW",
    101: "GLOBAL_VISION_POSITION_ESTIMATE",
    102: "VISION_POSITION_ESTIMATE",
    103: "VISION_SPEED_ESTIMATE",
    104: "VICON_POSITION_ESTIMATE",
    105: "HIGHRES_IMU",
    106: "OPTICAL_FLOW_RAD",
    107: "HIL_SENSOR",
    108: "SIM_STATE",
    109: "RADIO_STATUS",
    110: "FILE_TRANSFER_PROTOCOL",
    111: "TIMESYNC",
    112: "CAMERA_TRIGGER",
    113: "HIL_GPS",
    114: "HIL_OPTICAL_FLOW",
    115: "HIL_STATE_QUATERNION",
    116: "SCALED_IMU2",
    117: "LOG_REQUEST_LIST",
    118: "LOG_ENTRY",
    119: "LOG_REQUEST_DATA",
    120: "LOG_DATA",
    121: "LOG_ERASE",
    122: "LOG_REQUEST_END",
    123: "GPS_INJECT_DATA",
    124: "GPS2_RAW",
    125: "POWER_STATUS",
    126: "SERIAL_CONTROL",
    127: "GPS_RTK",
    128: "GPS2_RTK",
    129: "SCALED_IMU3",
    130: "DATA_TRANSMISSION_HANDSHAKE",
    131: "ENCAPSULATED_DATA",
    132: "DISTANCE_SENSOR",
    133: "TERRAIN_REQUEST",
    134: "TERRAIN_DATA",
    135: "TERRAIN_CHECK",
    136: "TERRAIN_REPORT",
    137: "SCALED_PRESSURE2",
    138: "ATT_POS_MOCAP",
    139: "SET_ACTUATOR_CONTROL_TARGET",
    140: "ACTUATOR_CONTROL_TARGET",
    141: "ALTITUDE",
    142: "RESOURCE_REQUEST",
    143: "SCALED_PRESSURE3",
    144: "FOLLOW_TARGET",
    146: "CONTROL_SYSTEM_STATE",
    147: "BATTERY_STATUS",
    148: "AUTOPILOT_VERSION",
    149: "LANDING_TARGET",
    230: "ESTIMATOR_STATUS",
    231: "WIND_COV",
    232: "GPS_INPUT",
    233: "GPS_RTCM_DATA",
    234: "HIGH_LATENCY",
    241: "VIBRATION",
    242: "HOME_POSITION",
    245: "EXTENDED_SYS_STATE",
    246: "ADSB_VEHICLE",
    247: "COLLISION",
    248: "V2_EXTENSION",
    249: "MEMORY_VECT",
    250: "DEBUG_VECT",
    251: "NAMED_VALUE_FLOAT",
    252: "NAMED_VALUE_INT",
    253: "STATUSTEXT",
    254: "DEBUG",
    256: "SETUP_SIGNING",
    300: "PROTOCOL_VERSION",
}

MSG_CATEGORIES = {
    "telemetry": {0, 1, 24, 26, 27, 30, 32, 33, 74, 105, 125, 141, 147},
    "gps": {24, 33, 48, 49, 123, 124, 127, 128, 232},
    "mission": {37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 51, 73},
    "command": {11, 69, 70, 75, 76, 77},
    "rc": {34, 35, 65, 70},
    "sensor": {26, 27, 28, 29, 105, 116, 129, 132, 137, 143},
    "system": {0, 1, 2, 4, 109, 148, 253},
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class GPSPoint:
    """A single GPS position reading"""
    timestamp: float
    system_id: int
    lat: float
    lon: float
    alt: float
    relative_alt: float = 0
    vx: float = 0
    vy: float = 0
    vz: float = 0
    hdg: int = 0

    def to_dict(self):
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "system_id": self.system_id,
            "lat": self.lat,
            "lon": self.lon,
            "alt_m": self.alt,
            "heading_cdeg": self.hdg,
        }


@dataclass
class MessageStats:
    """Statistics for a single message type"""
    msg_id: int
    msg_name: str
    count: int = 0
    first_seen: float = 0
    last_seen: float = 0
    sources: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    def rate_hz(self) -> float:
        span = self.last_seen - self.first_seen
        if span <= 0:
            return 0
        return self.count / span

    def to_dict(self):
        return {
            "msg_id": self.msg_id,
            "msg_name": self.msg_name,
            "count": self.count,
            "rate_hz": round(self.rate_hz(), 2),
            "sources": dict(self.sources),
        }


@dataclass
class InterceptResult:
    """Full interception session result"""
    bind_ip: str = "0.0.0.0"
    bind_port: int = 14550
    duration_sec: float = 0
    total_packets: int = 0
    total_bytes: int = 0
    systems_seen: Dict[int, str] = field(default_factory=dict)
    message_stats: Dict[int, MessageStats] = field(default_factory=dict)
    gps_track: List[GPSPoint] = field(default_factory=list)
    signing_detected: bool = False
    signed_packet_count: int = 0
    v1_count: int = 0
    v2_count: int = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "module": "mavlink_interceptor",
            "timestamp": datetime.now().isoformat(),
            "bind": f"{self.bind_ip}:{self.bind_port}",
            "duration_sec": round(self.duration_sec, 2),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "systems_seen": self.systems_seen,
            "message_stats": {k: v.to_dict() for k, v in
                              sorted(self.message_stats.items(),
                                     key=lambda x: x[1].count, reverse=True)},
            "gps_track_points": len(self.gps_track),
            "gps_track": [g.to_dict() for g in self.gps_track[-100:]],
            "signing_detected": self.signing_detected,
            "signed_packets": self.signed_packet_count,
            "v1_packets": self.v1_count,
            "v2_packets": self.v2_count,
            "errors": self.errors,
        }


# ============================================================================
# Interceptor
# ============================================================================

class MAVLinkInterceptor:
    """Passive MAVLink traffic capture and analysis"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def capture(self, port: int = 14550, duration: float = 30.0,
                bind_ip: str = "0.0.0.0") -> InterceptResult:
        """
        Passively capture MAVLink traffic on a UDP port.
        No packets are sent — pure interception.
        """
        result = InterceptResult(
            bind_ip=bind_ip,
            bind_port=port,
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)

        try:
            sock.bind((bind_ip, port))
            if self.verbose:
                print(f"[*] Intercepting MAVLink on {bind_ip}:{port} "
                      f"for {duration}s (no packets sent)...")

            start = time.time()

            while time.time() - start < duration:
                try:
                    data, (src_ip, src_port) = sock.recvfrom(4096)
                    result.total_bytes += len(data)

                    self._process_packet(data, src_ip, src_port, result)

                except socket.timeout:
                    continue

            result.duration_sec = time.time() - start

        except OSError as e:
            result.errors.append(str(e))
        finally:
            sock.close()

        return result

    def _process_packet(self, data: bytes, src_ip: str, src_port: int,
                        result: InterceptResult):
        """Process a single captured packet"""
        offset = 0
        while offset < len(data):
            # Find next MAVLink start byte
            while offset < len(data):
                if data[offset] in (MAVLINK_STX_V1, MAVLINK_STX_V2):
                    break
                offset += 1

            if offset >= len(data):
                break

            pkt = MAVLinkParser.parse_packet(data[offset:])
            if not pkt:
                offset += 1
                continue

            result.total_packets += 1
            now = time.time()

            # Version tracking
            if pkt["version"] == 1:
                result.v1_count += 1
            else:
                result.v2_count += 1

            # Signing detection
            if pkt.get("signing"):
                result.signing_detected = True
                result.signed_packet_count += 1

            # System tracking
            sys_id = pkt["system_id"]
            if sys_id not in result.systems_seen:
                result.systems_seen[sys_id] = f"{src_ip}:{src_port}"
                if self.verbose:
                    print(f"  [+] New system: ID={sys_id} from {src_ip}:{src_port}")

            # Message stats
            msg_id = pkt["message_id"]
            if msg_id not in result.message_stats:
                result.message_stats[msg_id] = MessageStats(
                    msg_id=msg_id,
                    msg_name=MSG_NAMES.get(msg_id, f"MSG_{msg_id}"),
                    first_seen=now,
                )
            stats = result.message_stats[msg_id]
            stats.count += 1
            stats.last_seen = now
            stats.sources[sys_id] += 1

            # GPS extraction (GLOBAL_POSITION_INT = msg 33)
            if msg_id == 33 and len(pkt["payload"]) >= 28:
                self._extract_gps(pkt, sys_id, result)

            # Heartbeat tracking
            if msg_id == 0:
                hb = MAVLinkParser.parse_heartbeat(pkt["payload"])
                if hb:
                    type_name = hb["type_name"]
                    result.systems_seen[sys_id] = f"{src_ip}:{src_port} ({type_name})"

            # Advance past this packet
            if pkt["version"] == 1:
                pkt_len = 6 + pkt["payload_len"] + 2
            else:
                pkt_len = 10 + pkt["payload_len"] + 2
                if pkt.get("signing"):
                    pkt_len += 13
            offset += pkt_len

    def _extract_gps(self, pkt: Dict, sys_id: int, result: InterceptResult):
        """Extract GPS position from GLOBAL_POSITION_INT (msg 33)"""
        payload = pkt["payload"]
        if len(payload) < 28:
            return

        time_boot_ms, lat, lon, alt, relative_alt, vx, vy, vz, hdg = \
            struct.unpack("<IiiiihhHH"[:10], payload[:28])

        # Only record if we have a valid position
        if lat == 0 and lon == 0:
            return

        point = GPSPoint(
            timestamp=time.time(),
            system_id=sys_id,
            lat=lat / 1e7,
            lon=lon / 1e7,
            alt=alt / 1000.0,
            relative_alt=relative_alt / 1000.0,
            vx=vx / 100.0,
            vy=vy / 100.0,
            vz=vz / 100.0,
            hdg=hdg,
        )
        result.gps_track.append(point)


# ============================================================================
# Reporting
# ============================================================================

def print_intercept_report(result: InterceptResult):
    """Pretty-print interception results"""
    print(f"\n{'=' * 60}")
    print(f"  MAVLink INTERCEPTION — {result.bind_ip}:{result.bind_port}")
    print(f"  Duration: {result.duration_sec:.1f}s | "
          f"Packets: {result.total_packets} | "
          f"Bytes: {result.total_bytes}")
    print(f"{'=' * 60}")

    if not result.total_packets:
        print("\n  [-] No MAVLink traffic captured")
        return

    # Protocol version breakdown
    sign_str = "\033[91mDETECTED\033[0m" if result.signing_detected else "\033[93mNOT SEEN\033[0m"
    print(f"\n  \033[96mPROTOCOL\033[0m")
    print(f"    MAVLink v1: {result.v1_count} packets")
    print(f"    MAVLink v2: {result.v2_count} packets")
    print(f"    Signing:    {sign_str} ({result.signed_packet_count} signed)")

    # Systems
    print(f"\n  \033[96mSYSTEMS ({len(result.systems_seen)})\033[0m")
    for sys_id, addr in sorted(result.systems_seen.items()):
        print(f"    System {sys_id:3d} → {addr}")

    # Top messages
    print(f"\n  \033[96mMESSAGE TYPES (top 20)\033[0m")
    sorted_msgs = sorted(result.message_stats.values(),
                         key=lambda m: m.count, reverse=True)
    for m in sorted_msgs[:20]:
        cat = ""
        for cat_name, cat_ids in MSG_CATEGORIES.items():
            if m.msg_id in cat_ids:
                cat = f" [{cat_name}]"
                break
        print(f"    {m.msg_name:35s} {m.count:6d}  ({m.rate_hz():6.1f} Hz){cat}")

    # GPS track
    if result.gps_track:
        print(f"\n  \033[96mGPS TRACK ({len(result.gps_track)} points)\033[0m")
        first = result.gps_track[0]
        last = result.gps_track[-1]
        print(f"    First: {first.lat:.7f}, {first.lon:.7f} @ {first.alt:.1f}m")
        print(f"    Last:  {last.lat:.7f}, {last.lon:.7f} @ {last.alt:.1f}m")

        # Show unique systems with GPS
        gps_systems = set(g.system_id for g in result.gps_track)
        print(f"    Systems with GPS: {sorted(gps_systems)}")

    print(f"\n{'=' * 60}\n")


def export_json(result: InterceptResult, output_file: str):
    """Export results to JSON"""
    with open(output_file, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    print(f"[+] Interception data exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 7: MAVLink passive traffic interception"
    )
    parser.add_argument("-p", "--port", type=int, default=14550,
                        help="UDP port to listen on (default: 14550)")
    parser.add_argument("--bind", default="0.0.0.0",
                        help="Bind IP (default: 0.0.0.0)")
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    interceptor = MAVLinkInterceptor(verbose=args.verbose)
    result = interceptor.capture(port=args.port, duration=args.duration,
                                  bind_ip=args.bind)
    print_intercept_report(result)

    if args.output:
        export_json(result, args.output)


if __name__ == "__main__":
    main()
