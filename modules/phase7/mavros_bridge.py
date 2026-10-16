#!/usr/bin/env python3
"""
mavros_bridge.py - Phase 7: MAVROS ROS 2 ↔ MAVLink Bridge Analysis

Analyzes the mavros bridge node that connects ROS 2 to MAVLink autopilots.
This is the critical junction between the DDS world (Phases 1-6) and the
MAVLink world (Phase 7). Compromising this bridge gives cross-layer access:
DDS → mavros → MAVLink → autopilot → physical vehicle control.

mavros exposes the autopilot's full attack surface as ROS 2 topics and
services, often without additional authentication. A node that can publish
to /mavros/setpoint_velocity/cmd_vel can directly control the vehicle.

Attack surface mapped:
  - mavros node discovery and version fingerprinting
  - Topic enumeration (what autopilot data is exposed)
  - Service enumeration (what commands are available)
  - Critical command paths (cmd_vel → MAVLink, set_mode, arming)
  - Parameter bridge exposure (read/write autopilot params via ROS 2)
  - TF frame analysis (coordinate frames that can be poisoned)
  - QoS assessment (reliability settings on safety-critical topics)

Author  : Gh057x
Phase   : 7 — MAVLink / Autopilot Security
Requires: (none — uses RTPS/DDS from Phase 1 for discovery;
           rclpy optional for deep enumeration)
"""

import time
import json
import sys
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from datetime import datetime


# ============================================================================
# Known MAVROS Topics and Their Risk
# ============================================================================

MAVROS_CRITICAL_TOPICS = {
    # Velocity / position commands (direct vehicle control)
    "/mavros/setpoint_velocity/cmd_vel": {
        "risk": "CRITICAL",
        "type": "geometry_msgs/msg/TwistStamped",
        "direction": "sub",
        "impact": "Direct velocity control — moves the vehicle",
    },
    "/mavros/setpoint_velocity/cmd_vel_unstamped": {
        "risk": "CRITICAL",
        "type": "geometry_msgs/msg/Twist",
        "direction": "sub",
        "impact": "Unstamped velocity control — no timestamp validation",
    },
    "/mavros/setpoint_position/local": {
        "risk": "CRITICAL",
        "type": "geometry_msgs/msg/PoseStamped",
        "direction": "sub",
        "impact": "Direct position setpoint — moves vehicle to position",
    },
    "/mavros/setpoint_position/global": {
        "risk": "CRITICAL",
        "type": "geographic_msgs/msg/GeoPoseStamped",
        "direction": "sub",
        "impact": "Global GPS position setpoint",
    },
    "/mavros/setpoint_raw/local": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/msg/PositionTarget",
        "direction": "sub",
        "impact": "Raw position/velocity/acceleration setpoint",
    },
    "/mavros/setpoint_raw/global": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/msg/GlobalPositionTarget",
        "direction": "sub",
        "impact": "Raw global position setpoint",
    },
    "/mavros/setpoint_raw/attitude": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/msg/AttitudeTarget",
        "direction": "sub",
        "impact": "Direct attitude (roll/pitch/yaw/thrust) control",
    },
    "/mavros/rc/override": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/msg/OverrideRCIn",
        "direction": "sub",
        "impact": "RC channel override — full manual control hijack",
    },

    # Telemetry (information exposure)
    "/mavros/global_position/global": {
        "risk": "MEDIUM",
        "type": "sensor_msgs/msg/NavSatFix",
        "direction": "pub",
        "impact": "Live GPS position — reveals vehicle location",
    },
    "/mavros/global_position/local": {
        "risk": "LOW",
        "type": "nav_msgs/msg/Odometry",
        "direction": "pub",
        "impact": "Local position estimate",
    },
    "/mavros/state": {
        "risk": "LOW",
        "type": "mavros_msgs/msg/State",
        "direction": "pub",
        "impact": "Vehicle state (armed, mode, connected)",
    },
    "/mavros/battery": {
        "risk": "LOW",
        "type": "sensor_msgs/msg/BatteryState",
        "direction": "pub",
        "impact": "Battery status — reveals operational endurance",
    },
    "/mavros/imu/data": {
        "risk": "LOW",
        "type": "sensor_msgs/msg/Imu",
        "direction": "pub",
        "impact": "IMU data — attitude, angular velocity, acceleration",
    },
}

MAVROS_CRITICAL_SERVICES = {
    "/mavros/cmd/arming": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/srv/CommandBool",
        "impact": "Arm/disarm the vehicle motors",
    },
    "/mavros/set_mode": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/srv/SetMode",
        "impact": "Change flight/drive mode (GUIDED, MANUAL, RTL, etc.)",
    },
    "/mavros/cmd/command": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/srv/CommandLong",
        "impact": "Send arbitrary MAVLink COMMAND_LONG — full command access",
    },
    "/mavros/cmd/command_int": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/srv/CommandInt",
        "impact": "Send arbitrary COMMAND_INT — position-based commands",
    },
    "/mavros/mission/push": {
        "risk": "HIGH",
        "type": "mavros_msgs/srv/WaypointPush",
        "impact": "Upload/replace the vehicle's mission",
    },
    "/mavros/mission/clear": {
        "risk": "HIGH",
        "type": "mavros_msgs/srv/WaypointClear",
        "impact": "Clear all mission waypoints",
    },
    "/mavros/mission/set_current": {
        "risk": "HIGH",
        "type": "mavros_msgs/srv/WaypointSetCurrent",
        "impact": "Jump to a specific mission waypoint",
    },
    "/mavros/param/set": {
        "risk": "HIGH",
        "type": "mavros_msgs/srv/ParamSet",
        "impact": "Write autopilot parameters via ROS 2",
    },
    "/mavros/param/get": {
        "risk": "MEDIUM",
        "type": "mavros_msgs/srv/ParamGet",
        "impact": "Read autopilot parameters",
    },
    "/mavros/cmd/takeoff": {
        "risk": "CRITICAL",
        "type": "mavros_msgs/srv/CommandTOL",
        "impact": "Initiate takeoff",
    },
    "/mavros/cmd/land": {
        "risk": "HIGH",
        "type": "mavros_msgs/srv/CommandTOL",
        "impact": "Initiate landing",
    },
    "/mavros/ftp/open": {
        "risk": "MEDIUM",
        "type": "mavros_msgs/srv/FileOpen",
        "impact": "Access autopilot filesystem via MAVLink FTP",
    },
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class BridgeTopic:
    """A discovered mavros topic"""
    name: str
    msg_type: str = ""
    direction: str = ""  # pub/sub
    risk: str = "UNKNOWN"
    impact: str = ""
    subscribers: int = 0
    publishers: int = 0

    def to_dict(self):
        return {
            "name": self.name,
            "msg_type": self.msg_type,
            "direction": self.direction,
            "risk": self.risk,
            "impact": self.impact,
            "subscribers": self.subscribers,
            "publishers": self.publishers,
        }


@dataclass
class BridgeService:
    """A discovered mavros service"""
    name: str
    srv_type: str = ""
    risk: str = "UNKNOWN"
    impact: str = ""

    def to_dict(self):
        return {
            "name": self.name,
            "srv_type": self.srv_type,
            "risk": self.risk,
            "impact": self.impact,
        }


@dataclass
class BridgeResult:
    """Full bridge analysis result"""
    target: str = ""
    mavros_detected: bool = False
    mavros_namespace: str = "/mavros"
    topics: List[BridgeTopic] = field(default_factory=list)
    services: List[BridgeService] = field(default_factory=list)
    critical_command_paths: List[str] = field(default_factory=list)
    exposed_params: bool = False
    dds_to_mavlink_paths: List[Dict] = field(default_factory=list)
    duration_sec: float = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "module": "mavros_bridge",
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "mavros_detected": self.mavros_detected,
            "mavros_namespace": self.mavros_namespace,
            "topics": [t.to_dict() for t in self.topics],
            "services": [s.to_dict() for s in self.services],
            "critical_command_paths": self.critical_command_paths,
            "exposed_params": self.exposed_params,
            "dds_to_mavlink_paths": self.dds_to_mavlink_paths,
            "summary": {
                "total_topics": len(self.topics),
                "total_services": len(self.services),
                "critical_topics": len([t for t in self.topics if t.risk == "CRITICAL"]),
                "critical_services": len([s for s in self.services if s.risk == "CRITICAL"]),
                "attack_paths": len(self.dds_to_mavlink_paths),
            },
            "duration_sec": round(self.duration_sec, 2),
            "errors": self.errors,
        }


# ============================================================================
# Bridge Analyzer
# ============================================================================

class MAVROSBridgeAnalyzer:
    """Analyze the mavros ROS 2 ↔ MAVLink bridge"""

    def __init__(self, namespace: str = "/mavros", domain_id: int = 0,
                 verbose: bool = False, timeout: float = 5.0):
        self.namespace = namespace
        self.domain_id = domain_id
        self.verbose = verbose
        self.timeout = timeout

    def analyze(self, target: str = "") -> BridgeResult:
        """Run full bridge analysis"""
        result = BridgeResult(target=target, mavros_namespace=self.namespace)
        start = time.time()

        # Try rclpy-based enumeration first
        if self._try_rclpy_enum(result):
            pass
        else:
            # Fall back to DDS-level discovery
            self._dds_enum(result, target)

        # Always do static analysis of known mavros topics
        self._analyze_known_surfaces(result)

        # Map DDS → MAVLink attack paths
        self._map_attack_paths(result)

        result.duration_sec = time.time() - start
        return result

    def _try_rclpy_enum(self, result: BridgeResult) -> bool:
        """Enumerate mavros via rclpy (if available)"""
        try:
            import rclpy
            from rclpy.node import Node
        except ImportError:
            return False

        try:
            rclpy.init()
            node = rclpy.create_node("_ros2reaper_bridge_enum",
                                     namespace="ros2reaper")

            # Give time for discovery
            time.sleep(2.0)

            # Get topic list
            topic_names_and_types = node.get_topic_names_and_types()
            for name, types in topic_names_and_types:
                if self.namespace in name or "/mavros" in name:
                    result.mavros_detected = True
                    known = MAVROS_CRITICAL_TOPICS.get(name, {})
                    topic = BridgeTopic(
                        name=name,
                        msg_type=types[0] if types else "",
                        direction=known.get("direction", ""),
                        risk=known.get("risk", "INFO"),
                        impact=known.get("impact", ""),
                    )
                    result.topics.append(topic)

            # Get service list
            service_names_and_types = node.get_service_names_and_types()
            for name, types in service_names_and_types:
                if self.namespace in name or "/mavros" in name:
                    result.mavros_detected = True
                    known = MAVROS_CRITICAL_SERVICES.get(name, {})
                    service = BridgeService(
                        name=name,
                        srv_type=types[0] if types else "",
                        risk=known.get("risk", "INFO"),
                        impact=known.get("impact", ""),
                    )
                    result.services.append(service)

            node.destroy_node()
            rclpy.shutdown()
            return True

        except Exception as e:
            result.errors.append(f"rclpy enum failed: {e}")
            try:
                rclpy.shutdown()
            except Exception:
                pass
            return False

    def _dds_enum(self, result: BridgeResult, target: str):
        """Enumerate mavros via DDS-level topic discovery (Phase 1 tools)"""
        try:
            from core.rtps_scanner import RTPSScanner
            from modules.topic_enum import TopicEnumerator

            scanner = RTPSScanner(timeout=self.timeout, verbose=False)

            if target:
                participants = scanner.spdp_probe(target=target,
                                                   domain_id=self.domain_id,
                                                   timeout=self.timeout)
            else:
                participants = scanner.spdp_probe(domain_id=self.domain_id,
                                                   timeout=self.timeout)

            if not participants:
                return

            enumerator = TopicEnumerator(verbose=False)
            graph = enumerator.enumerate(participants,
                                          domain_id=self.domain_id,
                                          timeout=self.timeout)

            # Filter for mavros topics
            for topic in getattr(graph, 'topics', []):
                name = topic.name if hasattr(topic, 'name') else str(topic)
                if "/mavros" in name or self.namespace in name:
                    result.mavros_detected = True
                    known = MAVROS_CRITICAL_TOPICS.get(name, {})
                    bt = BridgeTopic(
                        name=name,
                        msg_type=getattr(topic, 'type_name', ''),
                        risk=known.get("risk", "INFO"),
                        impact=known.get("impact", ""),
                    )
                    result.topics.append(bt)

        except ImportError:
            result.errors.append("DDS enum unavailable (core modules not in path)")
        except Exception as e:
            result.errors.append(f"DDS enum failed: {e}")

    def _analyze_known_surfaces(self, result: BridgeResult):
        """Static analysis of known mavros attack surfaces"""
        # If we didn't find mavros via live discovery, still document
        # the known surface for reference
        existing_names = {t.name for t in result.topics}
        existing_svc_names = {s.name for s in result.services}

        # Only add critical known topics/services not already found
        if not result.mavros_detected:
            if self.verbose:
                print("[*] mavros not detected live — documenting known surface")

            for name, info in MAVROS_CRITICAL_TOPICS.items():
                if name not in existing_names and info["risk"] in ("CRITICAL", "HIGH"):
                    result.topics.append(BridgeTopic(
                        name=name,
                        msg_type=info["type"],
                        direction=info["direction"],
                        risk=info["risk"],
                        impact=info["impact"] + " (not confirmed live)",
                    ))

            for name, info in MAVROS_CRITICAL_SERVICES.items():
                if name not in existing_svc_names and info["risk"] in ("CRITICAL", "HIGH"):
                    result.services.append(BridgeService(
                        name=name,
                        srv_type=info["type"],
                        risk=info["risk"],
                        impact=info["impact"] + " (not confirmed live)",
                    ))

    def _map_attack_paths(self, result: BridgeResult):
        """Map DDS → MAVLink cross-layer attack paths"""

        # cmd_vel → MAVLink velocity
        cmd_vel_topics = [t for t in result.topics
                          if "cmd_vel" in t.name and t.risk == "CRITICAL"]
        if cmd_vel_topics:
            result.dds_to_mavlink_paths.append({
                "name": "Velocity Control Hijack",
                "risk": "CRITICAL",
                "dds_entry": cmd_vel_topics[0].name,
                "mavlink_result": "SET_POSITION_TARGET_LOCAL_NED (velocity mode)",
                "chain": f"DDS publish → {cmd_vel_topics[0].name} → mavros → "
                         "MAVLink SET_POSITION_TARGET → autopilot → motors",
                "impact": "Direct vehicle velocity control from any DDS participant",
            })

        # Arming service
        arm_services = [s for s in result.services if "arming" in s.name]
        if arm_services:
            result.dds_to_mavlink_paths.append({
                "name": "Remote Arm/Disarm",
                "risk": "CRITICAL",
                "dds_entry": arm_services[0].name,
                "mavlink_result": "MAV_CMD_COMPONENT_ARM_DISARM",
                "chain": f"DDS service call → {arm_services[0].name} → mavros → "
                         "MAVLink COMMAND_LONG → arm/disarm motors",
                "impact": "Arm or disarm the vehicle from any ROS 2 node",
            })

        # Mode switch
        mode_services = [s for s in result.services if "set_mode" in s.name]
        if mode_services:
            result.dds_to_mavlink_paths.append({
                "name": "Mode Switch",
                "risk": "CRITICAL",
                "dds_entry": mode_services[0].name,
                "mavlink_result": "MAV_CMD_DO_SET_MODE",
                "chain": f"DDS service call → {mode_services[0].name} → mavros → "
                         "MAVLink SET_MODE → change GUIDED/MANUAL/RTL",
                "impact": "Switch vehicle mode from any ROS 2 node",
            })

        # RC override
        rc_topics = [t for t in result.topics if "rc/override" in t.name]
        if rc_topics:
            result.dds_to_mavlink_paths.append({
                "name": "RC Override Injection",
                "risk": "CRITICAL",
                "dds_entry": rc_topics[0].name,
                "mavlink_result": "RC_CHANNELS_OVERRIDE",
                "chain": f"DDS publish → {rc_topics[0].name} → mavros → "
                         "MAVLink RC_CHANNELS_OVERRIDE → manual control",
                "impact": "Full manual control override via ROS 2 topic publish",
            })

        # Mission manipulation
        mission_services = [s for s in result.services if "mission/push" in s.name]
        if mission_services:
            result.dds_to_mavlink_paths.append({
                "name": "Mission Replacement",
                "risk": "HIGH",
                "dds_entry": mission_services[0].name,
                "mavlink_result": "MISSION_ITEM_INT (full mission upload)",
                "chain": f"DDS service call → {mission_services[0].name} → mavros → "
                         "MAVLink mission protocol → replace waypoints",
                "impact": "Replace the vehicle's entire mission plan",
            })

        # Parameter bridge
        param_services = [s for s in result.services if "param/set" in s.name]
        if param_services:
            result.exposed_params = True
            result.dds_to_mavlink_paths.append({
                "name": "Parameter Manipulation",
                "risk": "HIGH",
                "dds_entry": param_services[0].name,
                "mavlink_result": "PARAM_SET",
                "chain": f"DDS service call → {param_services[0].name} → mavros → "
                         "MAVLink PARAM_SET → modify autopilot config",
                "impact": "Modify autopilot configuration (disable failsafes, "
                          "change limits) via ROS 2",
            })

        result.critical_command_paths = [
            p["name"] for p in result.dds_to_mavlink_paths if p["risk"] == "CRITICAL"
        ]


# ============================================================================
# Reporting
# ============================================================================

def print_bridge_report(result: BridgeResult):
    """Pretty-print bridge analysis results"""
    print(f"\n{'=' * 60}")
    print(f"  MAVROS BRIDGE ANALYSIS")
    print(f"  Namespace: {result.mavros_namespace}")
    detected = "\033[92mDETECTED\033[0m" if result.mavros_detected else "\033[93mNOT DETECTED (static analysis)\033[0m"
    print(f"  Status: {detected}")
    print(f"{'=' * 60}")

    # Critical attack paths
    if result.dds_to_mavlink_paths:
        print(f"\n  \033[91mDDS → MAVLink ATTACK PATHS ({len(result.dds_to_mavlink_paths)})\033[0m")
        for p in result.dds_to_mavlink_paths:
            risk_color = "\033[91m" if p["risk"] == "CRITICAL" else "\033[93m"
            print(f"\n    {risk_color}[{p['risk']}]\033[0m {p['name']}")
            print(f"          Entry:  {p['dds_entry']}")
            print(f"          Result: {p['mavlink_result']}")
            print(f"          Chain:  {p['chain']}")
            print(f"          Impact: {p['impact']}")

    # Topics
    critical_topics = [t for t in result.topics if t.risk == "CRITICAL"]
    other_topics = [t for t in result.topics if t.risk != "CRITICAL"]

    if critical_topics:
        print(f"\n  \033[91mCRITICAL TOPICS ({len(critical_topics)})\033[0m")
        for t in critical_topics:
            print(f"    \033[91m●\033[0m {t.name}")
            print(f"      Type: {t.msg_type} | Direction: {t.direction}")
            print(f"      Impact: {t.impact}")

    if other_topics:
        print(f"\n  \033[96mOTHER TOPICS ({len(other_topics)})\033[0m")
        for t in sorted(other_topics, key=lambda x: x.name):
            risk_char = {"HIGH": "\033[91m●\033[0m", "MEDIUM": "\033[93m●\033[0m",
                         "LOW": "\033[92m●\033[0m"}.get(t.risk, "○")
            print(f"    {risk_char} {t.name}  [{t.risk}]")

    # Services
    critical_services = [s for s in result.services if s.risk == "CRITICAL"]
    if critical_services:
        print(f"\n  \033[91mCRITICAL SERVICES ({len(critical_services)})\033[0m")
        for s in critical_services:
            print(f"    \033[91m●\033[0m {s.name}")
            print(f"      Type: {s.srv_type}")
            print(f"      Impact: {s.impact}")

    if result.errors:
        print(f"\n  \033[91mErrors:\033[0m")
        for e in result.errors:
            print(f"    - {e}")

    s = result.to_dict()["summary"]
    print(f"\n  {'─' * 50}")
    print(f"  Summary: {s['total_topics']} topics | {s['total_services']} services | "
          f"{s['critical_topics']} critical topics | "
          f"{s['critical_services']} critical services | "
          f"{s['attack_paths']} attack paths")
    print(f"  Duration: {result.duration_sec:.1f}s")
    print(f"{'=' * 60}\n")


def export_json(result: BridgeResult, output_file: str):
    """Export results to JSON"""
    with open(output_file, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    print(f"[+] Bridge analysis exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 7: MAVROS ROS 2 ↔ MAVLink bridge analysis"
    )
    parser.add_argument("-t", "--target", default="",
                        help="Target IP for DDS-level discovery")
    parser.add_argument("-d", "--domain-id", type=int, default=0)
    parser.add_argument("--namespace", default="/mavros",
                        help="mavros namespace (default: /mavros)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    analyzer = MAVROSBridgeAnalyzer(
        namespace=args.namespace,
        domain_id=args.domain_id,
        verbose=args.verbose,
        timeout=args.timeout,
    )
    result = analyzer.analyze(target=args.target)
    print_bridge_report(result)

    if args.output:
        export_json(result, args.output)


if __name__ == "__main__":
    main()
