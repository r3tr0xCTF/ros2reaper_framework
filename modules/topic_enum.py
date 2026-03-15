#!/usr/bin/env python3
"""
topic_enum.py - ROS 2 Topic/Service/Node Enumeration
======================================================
Enumerates ROS 2 topics, services, actions, and node information
by parsing SEDP (Simple Endpoint Discovery Protocol) messages.

SEDP is the mechanism DDS uses to announce which topics each participant
publishes/subscribes to, including the topic names, types, and QoS settings.
This is all available without authentication when DDS-Security is disabled.

Author: Gh057x
"""

import socket
import struct
import time
import json
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from core.rtps_parser import (
    RTPSParser, DDSParticipant, DDSPortCalculator,
    SubmessageKind, ParameterId,
    ENTITYID_SEDP_BUILTIN_PUB_READER, ENTITYID_SEDP_BUILTIN_PUB_WRITER,
    ENTITYID_SEDP_BUILTIN_SUB_READER, ENTITYID_SEDP_BUILTIN_SUB_WRITER,
)


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ROS2Endpoint:
    """Represents a discovered ROS 2 endpoint (publisher or subscriber)"""
    participant_guid: str
    entity_guid: Optional[str] = None
    topic_name: Optional[str] = None
    type_name: Optional[str] = None
    endpoint_type: str = "unknown"  # "publisher" or "subscriber"
    qos_reliability: Optional[str] = None  # "RELIABLE" or "BEST_EFFORT"
    qos_durability: Optional[str] = None   # "VOLATILE", "TRANSIENT_LOCAL", etc.
    source_ip: Optional[str] = None

    def is_ros2_topic(self) -> bool:
        """Check if this endpoint looks like a ROS 2 topic"""
        if not self.topic_name:
            return False
        # ROS 2 topics have patterns: rt/<topic>, rq/<service>, rr/<service>, ra/<action>
        ros2_prefixes = ("rt/", "rq/", "rr/", "ra/", "ros_discovery_info")
        return any(self.topic_name.startswith(p) for p in ros2_prefixes)

    def clean_topic_name(self) -> str:
        """Strip ROS 2 DDS prefixes to get the actual ROS 2 topic name"""
        if not self.topic_name:
            return ""
        # rt/ = regular topic, rq/ = service request, rr/ = service reply
        # ra/ = action
        for prefix in ("rt/", "rq/", "rr/", "ra/"):
            if self.topic_name.startswith(prefix):
                return self.topic_name[len(prefix):]
        return self.topic_name

    def get_ros2_type(self) -> Optional[str]:
        """Extract the ROS 2 message type from the DDS type name"""
        if not self.type_name:
            return None
        # DDS type names look like: "geometry_msgs::msg::dds_::Twist_"
        # Convert to ROS 2 format: "geometry_msgs/msg/Twist"
        parts = self.type_name.replace("::", "/").replace("dds_/", "").rstrip("_")
        # Clean up double slashes
        while "//" in parts:
            parts = parts.replace("//", "/")
        return parts.strip("/")

    def to_dict(self) -> Dict:
        return {
            "participant_guid": self.participant_guid,
            "topic_name": self.topic_name,
            "clean_name": self.clean_topic_name(),
            "type_name": self.type_name,
            "ros2_type": self.get_ros2_type(),
            "endpoint_type": self.endpoint_type,
            "is_ros2": self.is_ros2_topic(),
            "qos_reliability": self.qos_reliability,
            "qos_durability": self.qos_durability,
            "source_ip": self.source_ip,
        }


@dataclass
class ROS2Graph:
    """Complete ROS 2 computational graph extracted from DDS discovery"""
    timestamp: str = ""
    domain_id: int = 0
    participants: Dict[str, DDSParticipant] = field(default_factory=dict)
    endpoints: List[ROS2Endpoint] = field(default_factory=list)

    # Derived views
    topics: Dict[str, Dict] = field(default_factory=dict)
    services: Dict[str, Dict] = field(default_factory=dict)
    actions: Dict[str, Dict] = field(default_factory=dict)
    nodes: Dict[str, Dict] = field(default_factory=dict)

    def build_graph(self):
        """Build the ROS 2 graph from discovered endpoints"""
        self.topics.clear()
        self.services.clear()
        self.actions.clear()

        for ep in self.endpoints:
            if not ep.topic_name:
                continue

            clean_name = ep.clean_topic_name()
            ros2_type = ep.get_ros2_type()

            # Categorize by ROS 2 convention
            if ep.topic_name.startswith("rt/"):
                # Regular topic
                if clean_name not in self.topics:
                    self.topics[clean_name] = {
                        "name": clean_name,
                        "type": ros2_type,
                        "publishers": [],
                        "subscribers": [],
                    }
                if ep.endpoint_type == "publisher":
                    self.topics[clean_name]["publishers"].append(ep.participant_guid)
                else:
                    self.topics[clean_name]["subscribers"].append(ep.participant_guid)

            elif ep.topic_name.startswith("rq/") or ep.topic_name.startswith("rr/"):
                # Service (request/reply)
                # Strip _Request_ or _Response_ suffix
                svc_name = clean_name
                for suffix in ("/_service_event", "/Request", "/Response"):
                    svc_name = svc_name.replace(suffix, "")

                if svc_name not in self.services:
                    self.services[svc_name] = {
                        "name": svc_name,
                        "type": ros2_type,
                        "servers": [],
                        "clients": [],
                    }
                if ep.topic_name.startswith("rr/"):
                    self.services[svc_name]["servers"].append(ep.participant_guid)
                else:
                    self.services[svc_name]["clients"].append(ep.participant_guid)

            elif ep.topic_name.startswith("ra/"):
                # Action
                action_name = clean_name.split("/")[0] if "/" in clean_name else clean_name
                if action_name not in self.actions:
                    self.actions[action_name] = {
                        "name": action_name,
                        "type": ros2_type,
                        "servers": [],
                        "clients": [],
                    }

        # Build node list from participants
        for guid, participant in self.participants.items():
            self.nodes[guid] = {
                "guid": guid,
                "name": participant.participant_name,
                "vendor": participant.vendor_name,
                "source_ip": participant.source_ip,
                "has_security": participant.has_security,
            }

    def get_security_critical_topics(self) -> List[str]:
        """Identify topics that are security-critical for robotics"""
        critical_patterns = [
            "cmd_vel", "velocity", "twist",     # Motion commands
            "joint", "trajectory",               # Joint control
            "nav", "goal", "path", "plan",       # Navigation
            "scan", "lidar", "laser",            # Sensors
            "camera", "image", "depth",          # Vision
            "odom", "pose", "tf",                # Localization
            "map", "costmap",                    # Mapping
            "gripper", "grasp",                  # Manipulation
            "estop", "emergency", "safety",      # Safety systems
            "diagnostics", "battery",            # System status
        ]

        critical = []
        for topic_name in self.topics:
            name_lower = topic_name.lower()
            for pattern in critical_patterns:
                if pattern in name_lower:
                    critical.append(topic_name)
                    break

        return critical

    def to_dict(self) -> Dict:
        self.build_graph()
        critical = self.get_security_critical_topics()

        return {
            "timestamp": self.timestamp,
            "domain_id": self.domain_id,
            "summary": {
                "total_participants": len(self.participants),
                "total_endpoints": len(self.endpoints),
                "total_topics": len(self.topics),
                "total_services": len(self.services),
                "total_actions": len(self.actions),
                "security_critical_topics": len(critical),
            },
            "nodes": self.nodes,
            "topics": self.topics,
            "services": self.services,
            "actions": self.actions,
            "security_critical_topics": critical,
        }


# =============================================================================
# Enumerator
# =============================================================================

class TopicEnumerator:
    """
    Enumerates ROS 2 topics, services, and actions from DDS discovery.
    
    Uses SEDP (Simple Endpoint Discovery Protocol) to discover what
    each DDS participant publishes and subscribes to. This reveals
    the complete ROS 2 computational graph.
    """

    # SEDP uses these multicast ports (same calculation as SPDP but different endpoints)
    SEDP_TIMEOUT = 5.0

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.parser = RTPSParser()

    def enumerate(self, participants: List[DDSParticipant],
                   domain_id: int = 0, timeout: float = None) -> ROS2Graph:
        """
        Enumerate all endpoints from discovered participants.
        
        Strategy:
        1. For each participant, connect to their SEDP unicast locators
        2. Listen for SEDP publication/subscription announcements
        3. Parse endpoint data (topic names, types, QoS)
        4. Build the ROS 2 computational graph
        """
        if timeout is None:
            timeout = self.SEDP_TIMEOUT

        graph = ROS2Graph(
            timestamp=datetime.now().isoformat(),
            domain_id=domain_id,
        )

        for p in participants:
            graph.participants[p.guid_prefix_hex()] = p

        self._log(f"Enumerating endpoints for {len(participants)} participant(s)...")

        # Listen on SEDP multicast for endpoint announcements
        # SEDP announcements are sent on the user traffic ports
        endpoints = self._listen_for_sedp(domain_id, timeout)
        graph.endpoints.extend(endpoints)

        # Also try direct unicast probing of each participant
        for p in participants:
            direct_endpoints = self._probe_participant_sedp(p, domain_id, timeout=2.0)
            graph.endpoints.extend(direct_endpoints)

        graph.build_graph()

        self._log(
            f"Enumeration complete: {len(graph.topics)} topics, "
            f"{len(graph.services)} services, {len(graph.actions)} actions"
        )

        return graph

    def _listen_for_sedp(self, domain_id: int, timeout: float) -> List[ROS2Endpoint]:
        """Listen on DDS user multicast for SEDP endpoint announcements"""
        endpoints = []
        port = DDSPortCalculator.user_multicast(domain_id)

        self._log(f"Listening for SEDP on port {port} for {timeout}s...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", port))

            # Join multicast
            mreq = struct.pack(
                "4s4s",
                socket.inet_aton("239.255.0.1"),
                socket.inet_aton("0.0.0.0")
            )
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            sock.settimeout(1.0)

            deadline = time.time() + timeout

            while time.time() < deadline:
                try:
                    data, addr = sock.recvfrom(65535)
                    source_ip = addr[0]

                    if not RTPSParser.is_rtps(data):
                        continue

                    # Parse for SEDP data
                    new_endpoints = self._extract_endpoints_from_packet(data, source_ip)
                    endpoints.extend(new_endpoints)

                except socket.timeout:
                    continue

            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
            sock.close()

        except Exception as e:
            self._log(f"SEDP listen error: {e}", "WARNING")

        return endpoints

    def _probe_participant_sedp(self, participant: DDSParticipant,
                                  domain_id: int,
                                  timeout: float = 2.0) -> List[ROS2Endpoint]:
        """Probe a specific participant for SEDP data"""
        endpoints = []

        # Try metatraffic unicast locators first, then regular unicast
        target_locators = participant.metatraffic_unicast or participant.unicast_locators
        if not target_locators:
            return endpoints

        for locator in target_locators[:2]:  # Try first 2 locators
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)

                # Send a minimal probe to trigger SEDP response
                # We reuse the SPDP probe — participants will respond with full discovery data
                from core.rtps_scanner import SPDPProbeBuilder
                probe = SPDPProbeBuilder.build_spdp_probe(domain_id=domain_id)
                sock.sendto(probe, (locator.address, locator.port))

                deadline = time.time() + timeout
                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(65535)
                        if RTPSParser.is_rtps(data):
                            new_endpoints = self._extract_endpoints_from_packet(data, addr[0])
                            endpoints.extend(new_endpoints)
                    except socket.timeout:
                        break

                sock.close()

            except Exception as e:
                self._log(f"SEDP probe to {locator} failed: {e}", "WARNING")

        return endpoints

    def _extract_endpoints_from_packet(self, data: bytes,
                                         source_ip: str) -> List[ROS2Endpoint]:
        """Extract ROS 2 endpoint info from an RTPS packet containing SEDP data"""
        endpoints = []
        header = RTPSParser.parse_header(data)
        if not header:
            return endpoints

        guid_prefix = header.guid_prefix.hex(".")
        submessages = RTPSParser.parse_submessages(data)

        for submsg in submessages:
            if submsg.kind != SubmessageKind.DATA:
                continue

            if len(submsg.data) < 20:
                continue

            writer_entity_id = submsg.data[8:12]

            # Check if this is SEDP publication or subscription data
            is_pub_sedp = writer_entity_id == ENTITYID_SEDP_BUILTIN_PUB_WRITER
            is_sub_sedp = writer_entity_id == ENTITYID_SEDP_BUILTIN_SUB_WRITER

            if not (is_pub_sedp or is_sub_sedp):
                continue

            endpoint_type = "publisher" if is_pub_sedp else "subscriber"

            # Extract parameter list from DATA submessage
            # Skip fixed DATA header (20 bytes) + CDR encapsulation (4 bytes)
            param_offset = 24
            if param_offset >= len(submsg.data):
                continue

            params = RTPSParser.parse_parameter_list(
                submsg.data[param_offset:],
                submsg.is_little_endian()
            )

            ep = ROS2Endpoint(
                participant_guid=guid_prefix,
                endpoint_type=endpoint_type,
                source_ip=source_ip,
            )

            for param in params:
                if param.pid == ParameterId.PID_TOPIC_NAME and isinstance(param.value, str):
                    ep.topic_name = param.value
                elif param.pid == ParameterId.PID_TYPE_NAME and isinstance(param.value, str):
                    ep.type_name = param.value
                elif param.pid == ParameterId.PID_ENDPOINT_GUID and isinstance(param.value, str):
                    ep.entity_guid = param.value
                elif param.pid == ParameterId.PID_RELIABILITY:
                    if isinstance(param.value, bytes) and len(param.value) >= 4:
                        rel = struct.unpack("<I", param.value[:4])[0]
                        ep.qos_reliability = "RELIABLE" if rel == 2 else "BEST_EFFORT"
                elif param.pid == ParameterId.PID_DURABILITY:
                    if isinstance(param.value, bytes) and len(param.value) >= 4:
                        dur = struct.unpack("<I", param.value[:4])[0]
                        dur_names = {0: "VOLATILE", 1: "TRANSIENT_LOCAL",
                                     2: "TRANSIENT", 3: "PERSISTENT"}
                        ep.qos_durability = dur_names.get(dur, f"UNKNOWN({dur})")

            if ep.topic_name:
                endpoints.append(ep)
                if self.verbose:
                    self._log(
                        f"  [{endpoint_type[:3].upper()}] {ep.topic_name} "
                        f"({ep.get_ros2_type() or 'unknown type'})"
                    )

        return endpoints

    def _log(self, msg: str, level: str = "INFO"):
        if self.verbose or level in ("WARNING", "ERROR"):
            print(f"[{level}] {msg}")


# =============================================================================
# Output Formatter
# =============================================================================

def print_ros2_graph(graph: ROS2Graph):
    """Pretty-print the ROS 2 computational graph"""
    graph.build_graph()

    print(f"\n{'=' * 60}")
    print(f"  ROS 2 COMPUTATIONAL GRAPH")
    print(f"{'=' * 60}")
    print(f"  Domain:     {graph.domain_id}")
    print(f"  Nodes:      {len(graph.nodes)}")
    print(f"  Topics:     {len(graph.topics)}")
    print(f"  Services:   {len(graph.services)}")
    print(f"  Actions:    {len(graph.actions)}")

    # Topics
    if graph.topics:
        print(f"\n  \033[96m── Topics ──\033[0m")
        for name, info in sorted(graph.topics.items()):
            pubs = len(info.get("publishers", []))
            subs = len(info.get("subscribers", []))
            type_str = info.get("type", "?")
            print(f"    {name}")
            print(f"      Type: {type_str} | Pubs: {pubs} | Subs: {subs}")

    # Services
    if graph.services:
        print(f"\n  \033[93m── Services ──\033[0m")
        for name, info in sorted(graph.services.items()):
            print(f"    {name}")
            print(f"      Type: {info.get('type', '?')}")

    # Actions
    if graph.actions:
        print(f"\n  \033[92m── Actions ──\033[0m")
        for name, info in sorted(graph.actions.items()):
            print(f"    {name}")

    # Security-critical topics
    critical = graph.get_security_critical_topics()
    if critical:
        print(f"\n  \033[91m── Security-Critical Topics ({len(critical)}) ──\033[0m")
        for topic in critical:
            print(f"    ⚠️  {topic}")

    print(f"\n{'=' * 60}\n")
