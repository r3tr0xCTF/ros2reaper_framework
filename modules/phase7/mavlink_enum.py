#!/usr/bin/env python3
"""
mavlink_enum.py - Phase 7: MAVLink Autopilot Enumeration

Deep enumeration of MAVLink autopilots: parameters, firmware version,
capabilities, mission waypoints, home position, geofence, and rally points.

Uses pymavlink for reliable MAVLink v2 communication with proper message
routing and parameter protocol handling.

Attack surface mapped:
  - Full parameter dump (thousands of config values exposed)
  - Firmware version / git hash extraction
  - Capability flags (what the autopilot supports)
  - Mission waypoint extraction (planned routes)
  - Home position extraction (launch / RTL location)
  - Geofence configuration
  - Rally points

Author  : Gh057x
Phase   : 7 — MAVLink / Autopilot Security
Requires: pymavlink
"""

import time
import json
import sys
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime


# ============================================================================
# MAVLink Capability Flags (MAV_PROTOCOL_CAPABILITY)
# ============================================================================

CAPABILITY_FLAGS = {
    1:       "MISSION_FLOAT",
    2:       "PARAM_FLOAT",
    4:       "MISSION_INT",
    8:       "COMMAND_INT",
    16:      "PARAM_ENCODE_BYTEWISE",
    32:      "FTP",
    64:      "SET_ATTITUDE_TARGET",
    128:     "SET_POSITION_TARGET_LOCAL_NED",
    256:     "SET_POSITION_TARGET_GLOBAL_INT",
    512:     "TERRAIN",
    1024:    "RESERVED3",
    2048:    "FLIGHT_TERMINATION",
    4096:    "COMPASS_CALIBRATION",
    8192:    "MAVLINK2",
    16384:   "MISSION_FENCE",
    32768:   "MISSION_RALLY",
    65536:   "RESERVED2",
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class ParamValue:
    """A single MAVLink parameter"""
    name: str
    value: float
    type: int = 0
    index: int = 0

    def to_dict(self):
        return {"name": self.name, "value": self.value, "index": self.index}


@dataclass
class Waypoint:
    """A mission waypoint"""
    seq: int
    frame: int
    command: int
    command_name: str = ""
    current: bool = False
    autocontinue: bool = True
    param1: float = 0
    param2: float = 0
    param3: float = 0
    param4: float = 0
    x: float = 0   # lat or local x
    y: float = 0   # lon or local y
    z: float = 0   # alt or local z

    def to_dict(self):
        return {
            "seq": self.seq,
            "frame": self.frame,
            "command": self.command,
            "command_name": self.command_name,
            "current": self.current,
            "lat": self.x,
            "lon": self.y,
            "alt": self.z,
            "params": [self.param1, self.param2, self.param3, self.param4],
        }


@dataclass
class FirmwareInfo:
    """Autopilot firmware details"""
    version_major: int = 0
    version_minor: int = 0
    version_patch: int = 0
    version_string: str = ""
    git_hash: str = ""
    os_version: str = ""
    board_version: int = 0
    vendor_id: int = 0
    product_id: int = 0
    uid: int = 0
    capabilities: int = 0
    capability_names: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "version": self.version_string or f"{self.version_major}.{self.version_minor}.{self.version_patch}",
            "git_hash": self.git_hash,
            "board_version": self.board_version,
            "vendor_id": hex(self.vendor_id),
            "product_id": hex(self.product_id),
            "uid": hex(self.uid) if self.uid else "0x0",
            "capabilities": hex(self.capabilities),
            "capability_names": self.capability_names,
        }


@dataclass
class HomePosition:
    """Home / launch position"""
    latitude: float = 0
    longitude: float = 0
    altitude: float = 0

    def to_dict(self):
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude_m": self.altitude,
        }


@dataclass
class EnumResult:
    """Full enumeration result"""
    target: str = ""
    port: int = 14550
    system_id: int = 0
    firmware: Optional[FirmwareInfo] = None
    params: List[ParamValue] = field(default_factory=list)
    mission: List[Waypoint] = field(default_factory=list)
    home: Optional[HomePosition] = None
    fence_points: int = 0
    rally_points: int = 0
    duration_sec: float = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "module": "mavlink_enum",
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "port": self.port,
            "system_id": self.system_id,
            "firmware": self.firmware.to_dict() if self.firmware else None,
            "params": {p.name: p.value for p in self.params},
            "param_count": len(self.params),
            "mission": [w.to_dict() for w in self.mission],
            "mission_count": len(self.mission),
            "home": self.home.to_dict() if self.home else None,
            "fence_points": self.fence_points,
            "rally_points": self.rally_points,
            "duration_sec": round(self.duration_sec, 2),
            "errors": self.errors,
        }


# MAVLink command IDs for waypoints
MAV_CMD_NAMES = {
    16: "NAV_WAYPOINT",
    17: "NAV_LOITER_UNLIM",
    18: "NAV_LOITER_TURNS",
    19: "NAV_LOITER_TIME",
    20: "NAV_RETURN_TO_LAUNCH",
    21: "NAV_LAND",
    22: "NAV_TAKEOFF",
    23: "NAV_LAND_LOCAL",
    24: "NAV_TAKEOFF_LOCAL",
    25: "NAV_FOLLOW",
    30: "NAV_CONTINUE_AND_CHANGE_ALT",
    31: "NAV_LOITER_TO_ALT",
    32: "DO_FOLLOW",
    33: "DO_FOLLOW_REPOSITION",
    34: "DO_ORBIT",
    80: "NAV_ROI",
    81: "NAV_PATHPLANNING",
    82: "NAV_SPLINE_WAYPOINT",
    84: "NAV_VTOL_TAKEOFF",
    85: "NAV_VTOL_LAND",
    92: "NAV_GUIDED_ENABLE",
    93: "NAV_DELAY",
    94: "NAV_PAYLOAD_PLACE",
    95: "NAV_LAST",
    112: "CONDITION_DELAY",
    113: "CONDITION_CHANGE_ALT",
    114: "CONDITION_DISTANCE",
    115: "CONDITION_YAW",
    159: "CONDITION_LAST",
    176: "DO_SET_MODE",
    177: "DO_JUMP",
    178: "DO_CHANGE_SPEED",
    179: "DO_SET_HOME",
    180: "DO_SET_PARAMETER",
    181: "DO_SET_RELAY",
    182: "DO_REPEAT_RELAY",
    183: "DO_SET_SERVO",
    184: "DO_REPEAT_SERVO",
    185: "DO_FLIGHTTERMINATION",
    189: "DO_LAND_START",
    190: "DO_RALLY_LAND",
    191: "DO_GO_AROUND",
    192: "DO_REPOSITION",
    193: "DO_PAUSE_CONTINUE",
    194: "DO_SET_REVERSE",
    195: "DO_SET_ROI_LOCATION",
    196: "DO_SET_ROI_WPNEXT_OFFSET",
    197: "DO_SET_ROI_NONE",
    200: "DO_CONTROL_VIDEO",
    201: "DO_SET_ROI",
    203: "DO_DIGICAM_CONFIGURE",
    204: "DO_DIGICAM_CONTROL",
    205: "DO_MOUNT_CONFIGURE",
    206: "DO_MOUNT_CONTROL",
    207: "DO_SET_CAM_TRIGG_DIST",
    208: "DO_FENCE_ENABLE",
    209: "DO_PARACHUTE",
    210: "DO_MOTOR_TEST",
    211: "DO_INVERTED_FLIGHT",
    220: "DO_GRIPPER",
    223: "DO_AUTOTUNE_ENABLE",
    300: "PREFLIGHT_CALIBRATION",
    400: "PREFLIGHT_STORAGE",
    410: "PREFLIGHT_REBOOT_SHUTDOWN",
}


# ============================================================================
# Enumerator
# ============================================================================

class MAVLinkEnumerator:
    """Deep enumeration of MAVLink autopilots via pymavlink"""

    def __init__(self, verbose: bool = False, timeout: float = 10.0):
        self.verbose = verbose
        self.timeout = timeout
        self.conn = None

    def connect(self, target: str, port: int = 14550,
                protocol: str = "udp") -> bool:
        """Establish MAVLink connection via pymavlink"""
        try:
            from pymavlink import mavutil
        except ImportError:
            print("[!] pymavlink required: pip install pymavlink")
            return False

        if protocol == "tcp":
            conn_str = f"tcp:{target}:{port}"
        else:
            conn_str = f"udpin:{target}:{port}"

        try:
            self.conn = mavutil.mavlink_connection(
                conn_str,
                source_system=255,
                source_component=0,
            )
            if self.verbose:
                print(f"[*] Connecting to {conn_str}...")

            self.conn.wait_heartbeat(timeout=self.timeout)
            if self.verbose:
                sys_id = self.conn.target_system
                comp_id = self.conn.target_component
                print(f"[+] Heartbeat received: sys={sys_id} comp={comp_id}")

            return True

        except Exception as e:
            if self.verbose:
                print(f"[-] Connection failed: {e}")
            return False

    def enumerate(self, target: str, port: int = 14550,
                  protocol: str = "udp") -> EnumResult:
        """Run full enumeration against a MAVLink endpoint"""
        result = EnumResult(target=target, port=port)
        start = time.time()

        if not self.connect(target, port, protocol):
            result.errors.append("Connection failed")
            return result

        result.system_id = self.conn.target_system

        # Firmware / capabilities
        fw = self._get_firmware_info()
        if fw:
            result.firmware = fw

        # Parameters
        params = self._get_all_params()
        result.params = params

        # Mission
        mission = self._get_mission()
        result.mission = mission

        # Home position
        home = self._get_home_position()
        if home:
            result.home = home

        result.duration_sec = time.time() - start

        if self.conn:
            self.conn.close()

        return result

    def _get_firmware_info(self) -> Optional[FirmwareInfo]:
        """Request AUTOPILOT_VERSION for firmware details and capabilities"""
        try:
            from pymavlink import mavutil
        except ImportError:
            return None

        try:
            self.conn.mav.command_long_send(
                self.conn.target_system,
                self.conn.target_component,
                mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE,
                0,
                148,  # AUTOPILOT_VERSION
                0, 0, 0, 0, 0, 0,
            )

            msg = self.conn.recv_match(type="AUTOPILOT_VERSION",
                                        blocking=True, timeout=self.timeout)
            if not msg:
                return None

            fw_ver = msg.flight_sw_version
            major = (fw_ver >> 24) & 0xFF
            minor = (fw_ver >> 16) & 0xFF
            patch = (fw_ver >> 8) & 0xFF

            git_bytes = bytes(msg.flight_custom_version[:8])
            git_hash = git_bytes.hex().rstrip("0") or "0"

            caps = msg.capabilities
            cap_names = [name for bit, name in CAPABILITY_FLAGS.items() if caps & bit]

            info = FirmwareInfo(
                version_major=major,
                version_minor=minor,
                version_patch=patch,
                version_string=f"{major}.{minor}.{patch}",
                git_hash=git_hash,
                board_version=msg.board_version,
                vendor_id=msg.vendor_id,
                product_id=msg.product_id,
                uid=msg.uid if hasattr(msg, "uid") else 0,
                capabilities=caps,
                capability_names=cap_names,
            )

            if self.verbose:
                print(f"[+] Firmware: {info.version_string} (git: {git_hash})")
                print(f"    Board: {msg.board_version} | "
                      f"Caps: {', '.join(cap_names[:5])}")

            return info

        except Exception as e:
            if self.verbose:
                print(f"[-] Firmware info failed: {e}")
            return None

    def _get_all_params(self) -> List[ParamValue]:
        """Request and collect all parameters"""
        params = []

        try:
            self.conn.mav.param_request_list_send(
                self.conn.target_system,
                self.conn.target_component,
            )

            if self.verbose:
                print("[*] Requesting parameter list...")

            total = None
            deadline = time.time() + self.timeout * 3

            while time.time() < deadline:
                msg = self.conn.recv_match(type="PARAM_VALUE",
                                            blocking=True, timeout=2.0)
                if not msg:
                    break

                p = ParamValue(
                    name=msg.param_id.rstrip('\x00') if isinstance(msg.param_id, str)
                         else msg.param_id.decode('utf-8', errors='ignore').rstrip('\x00'),
                    value=msg.param_value,
                    type=msg.param_type,
                    index=msg.param_index,
                )
                params.append(p)

                if total is None:
                    total = msg.param_count

                if total and len(params) >= total:
                    break

            if self.verbose:
                print(f"[+] Received {len(params)}/{total or '?'} parameters")

        except Exception as e:
            if self.verbose:
                print(f"[-] Param fetch failed: {e}")

        return params

    def _get_mission(self) -> List[Waypoint]:
        """Download the current mission (waypoint list)"""
        waypoints = []

        try:
            from pymavlink import mavutil

            self.conn.mav.mission_request_list_send(
                self.conn.target_system,
                self.conn.target_component,
            )

            msg = self.conn.recv_match(type="MISSION_COUNT",
                                        blocking=True, timeout=self.timeout)
            if not msg:
                return waypoints

            count = msg.count
            if self.verbose:
                print(f"[*] Mission has {count} waypoints")

            for i in range(count):
                self.conn.mav.mission_request_int_send(
                    self.conn.target_system,
                    self.conn.target_component,
                    i,
                )
                wp_msg = self.conn.recv_match(type="MISSION_ITEM_INT",
                                               blocking=True, timeout=self.timeout)
                if not wp_msg:
                    wp_msg = self.conn.recv_match(type="MISSION_ITEM",
                                                   blocking=True, timeout=self.timeout)
                if not wp_msg:
                    break

                lat = wp_msg.x / 1e7 if hasattr(wp_msg, "x") and abs(wp_msg.x) > 1000 else wp_msg.x
                lon = wp_msg.y / 1e7 if hasattr(wp_msg, "y") and abs(wp_msg.y) > 1000 else wp_msg.y

                wp = Waypoint(
                    seq=wp_msg.seq,
                    frame=wp_msg.frame,
                    command=wp_msg.command,
                    command_name=MAV_CMD_NAMES.get(wp_msg.command, f"CMD_{wp_msg.command}"),
                    current=bool(wp_msg.current),
                    autocontinue=bool(wp_msg.autocontinue),
                    param1=wp_msg.param1,
                    param2=wp_msg.param2,
                    param3=wp_msg.param3,
                    param4=wp_msg.param4,
                    x=lat,
                    y=lon,
                    z=wp_msg.z,
                )
                waypoints.append(wp)

            # ACK the mission transfer
            self.conn.mav.mission_ack_send(
                self.conn.target_system,
                self.conn.target_component,
                0,  # MAV_MISSION_ACCEPTED
            )

            if self.verbose:
                print(f"[+] Downloaded {len(waypoints)} waypoints")

        except Exception as e:
            if self.verbose:
                print(f"[-] Mission download failed: {e}")

        return waypoints

    def _get_home_position(self) -> Optional[HomePosition]:
        """Request the home / launch position"""
        try:
            from pymavlink import mavutil

            self.conn.mav.command_long_send(
                self.conn.target_system,
                self.conn.target_component,
                mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE,
                0,
                242,  # HOME_POSITION
                0, 0, 0, 0, 0, 0,
            )

            msg = self.conn.recv_match(type="HOME_POSITION",
                                        blocking=True, timeout=self.timeout)
            if not msg:
                return None

            home = HomePosition(
                latitude=msg.latitude / 1e7,
                longitude=msg.longitude / 1e7,
                altitude=msg.altitude / 1000.0,
            )

            if self.verbose:
                print(f"[+] Home: {home.latitude:.6f}, {home.longitude:.6f} "
                      f"@ {home.altitude:.1f}m")

            return home

        except Exception as e:
            if self.verbose:
                print(f"[-] Home position failed: {e}")
            return None


# ============================================================================
# Security-Relevant Parameter Checks
# ============================================================================

SECURITY_PARAMS = {
    "SYSID_THISMAV": "System ID — predictable IDs make spoofing trivial",
    "SYSID_MYGCS": "Authorized GCS system ID — often left at default 255",
    "BRD_SERIAL_NUM": "Board serial number — hardware fingerprint",
    "ARMING_CHECK": "Arming safety checks — disabled (0) = dangerous",
    "FS_THR_ENABLE": "Throttle failsafe — disabled = no RTL on signal loss",
    "FS_GCS_ENABLE": "GCS failsafe — disabled = no reaction to GCS loss",
    "FS_ACTION": "Failsafe action — what happens on failure",
    "FENCE_ENABLE": "Geofence — disabled = no boundary enforcement",
    "FENCE_ACTION": "Geofence breach action",
    "FENCE_RADIUS": "Geofence radius in meters",
    "FENCE_ALT_MAX": "Geofence max altitude",
    "RC_OVERRIDE_TIME": "RC override timeout — how long injected RC lasts",
    "SERIAL0_PROTOCOL": "Serial 0 protocol — MAVLink version",
    "SERIAL1_PROTOCOL": "Serial 1 protocol",
    "SERIAL2_PROTOCOL": "Serial 2 protocol",
    "LOG_BACKEND_TYPE": "Logging backend — can reveal data exfil paths",
    "LOG_DISARMED": "Log while disarmed — forensic evidence",
    "GPS_TYPE": "GPS type — spoofing implications",
    "GPS_TYPE2": "Secondary GPS — redundancy check",
    "BATT_MONITOR": "Battery monitor type",
    "GND_ALT_OFFSET": "Ground altitude offset — can mask true altitude",
}


def analyze_security_params(params: List[ParamValue]) -> List[Dict]:
    """Analyze parameters for security issues"""
    findings = []
    param_dict = {p.name: p.value for p in params}

    # Check arming safety
    arming = param_dict.get("ARMING_CHECK", 1)
    if arming == 0:
        findings.append({
            "severity": "CRITICAL",
            "param": "ARMING_CHECK",
            "value": 0,
            "issue": "All arming safety checks disabled — vehicle can arm in unsafe conditions",
        })

    # Check failsafes
    for fs_param in ["FS_THR_ENABLE", "FS_GCS_ENABLE"]:
        val = param_dict.get(fs_param, 1)
        if val == 0:
            findings.append({
                "severity": "HIGH",
                "param": fs_param,
                "value": 0,
                "issue": f"Failsafe disabled — no automatic safety response on signal loss",
            })

    # Check geofence
    fence = param_dict.get("FENCE_ENABLE", 0)
    if fence == 0:
        findings.append({
            "severity": "MEDIUM",
            "param": "FENCE_ENABLE",
            "value": 0,
            "issue": "Geofence disabled — no boundary enforcement",
        })

    # Check system ID defaults
    sysid = param_dict.get("SYSID_THISMAV", 1)
    if sysid == 1:
        findings.append({
            "severity": "MEDIUM",
            "param": "SYSID_THISMAV",
            "value": 1,
            "issue": "Default system ID (1) — easily spoofed / predicted",
        })

    gcsid = param_dict.get("SYSID_MYGCS", 255)
    if gcsid == 255:
        findings.append({
            "severity": "LOW",
            "param": "SYSID_MYGCS",
            "value": 255,
            "issue": "Default GCS ID (255) — any GCS can command this vehicle",
        })

    # Check RC override timeout
    rc_timeout = param_dict.get("RC_OVERRIDE_TIME", 0)
    if rc_timeout == 0 or rc_timeout > 10:
        findings.append({
            "severity": "HIGH",
            "param": "RC_OVERRIDE_TIME",
            "value": rc_timeout,
            "issue": "RC override has no timeout or excessive timeout — "
                     "injected RC commands persist indefinitely",
        })

    return findings


# ============================================================================
# Reporting
# ============================================================================

def print_enum_report(result: EnumResult):
    """Pretty-print enumeration results"""
    print(f"\n{'=' * 60}")
    print(f"  MAVLink ENUMERATION — {result.target}:{result.port}")
    print(f"  System ID: {result.system_id} | Duration: {result.duration_sec:.1f}s")
    print(f"{'=' * 60}")

    if result.firmware:
        fw = result.firmware
        print(f"\n  \033[96mFIRMWARE\033[0m")
        print(f"    Version:   {fw.version_string}")
        print(f"    Git Hash:  {fw.git_hash}")
        print(f"    Board:     {fw.board_version}")
        if fw.capability_names:
            print(f"    Caps:      {', '.join(fw.capability_names)}")

    if result.params:
        print(f"\n  \033[96mPARAMETERS ({len(result.params)})\033[0m")

        # Show security-relevant params first
        sec_params = {p.name: p for p in result.params if p.name in SECURITY_PARAMS}
        if sec_params:
            print(f"\n    Security-relevant:")
            for name, p in sorted(sec_params.items()):
                desc = SECURITY_PARAMS.get(name, "")
                print(f"      {name:25s} = {p.value:>10.2f}  # {desc}")

        # Param analysis
        findings = analyze_security_params(result.params)
        if findings:
            print(f"\n    \033[91mSecurity Findings ({len(findings)}):\033[0m")
            for f in findings:
                sev_color = "\033[91m" if f["severity"] in ("CRITICAL", "HIGH") else "\033[93m"
                print(f"      {sev_color}[{f['severity']}]\033[0m {f['param']}={f['value']}: {f['issue']}")

    if result.mission:
        print(f"\n  \033[96mMISSION ({len(result.mission)} waypoints)\033[0m")
        for wp in result.mission:
            current = " ◀" if wp.current else ""
            print(f"    [{wp.seq:3d}] {wp.command_name:25s} "
                  f"lat={wp.x:11.6f} lon={wp.y:11.6f} alt={wp.z:7.1f}{current}")

    if result.home:
        h = result.home
        print(f"\n  \033[96mHOME POSITION\033[0m")
        print(f"    Latitude:  {h.latitude:.7f}")
        print(f"    Longitude: {h.longitude:.7f}")
        print(f"    Altitude:  {h.altitude:.1f}m")

    if result.errors:
        print(f"\n  \033[91mErrors:\033[0m")
        for e in result.errors:
            print(f"    - {e}")

    print(f"\n{'=' * 60}\n")


def export_json(result: EnumResult, output_file: str):
    """Export results to JSON"""
    with open(output_file, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    print(f"[+] Enumeration exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 7: MAVLink autopilot deep enumeration"
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP (autopilot or GCS relay)")
    parser.add_argument("-p", "--port", type=int, default=14550)
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    enumerator = MAVLinkEnumerator(verbose=args.verbose, timeout=args.timeout)
    result = enumerator.enumerate(args.target, port=args.port,
                                   protocol=args.protocol)
    print_enum_report(result)

    if args.output:
        export_json(result, args.output)


if __name__ == "__main__":
    main()
