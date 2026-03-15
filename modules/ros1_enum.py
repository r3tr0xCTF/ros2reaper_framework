#!/usr/bin/env python3
"""
ros1_enum.py — ROS1 Node Graph Discovery & Fingerprinting
==========================================================
Enumerates a ROS1 deployment by querying the rosmaster XML-RPC API:
  - All nodes, their published/subscribed topics, and their services
  - Full topic graph with type information
  - Complete parameter server dump
  - ROS distro / version fingerprint from standard params

No packets are crafted — this is pure XML-RPC introspection via the
unauthenticated rosmaster API (port 11311 by default).

Author: Gh057x
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.ros1_master import ROS1MasterClient, ROS1MasterError


# ---------------------------------------------------------------------------
# Security-critical topic patterns (cmd injection / sensor spoofing targets)
# ---------------------------------------------------------------------------

SECURITY_CRITICAL_TOPICS = {
    "/cmd_vel",
    "/move_base_simple/goal",
    "/initialpose",
    "/joy",
    "/mobile_base/commands/velocity",
    "/scan",
    "/odom",
    "/tf",
    "/arm/command",
    "/gripper/command",
    "/emergency_stop",
    "/robot_enable",
}

EOL_DISTROS = {
    "kinetic":  "EOL May 2019",
    "lunar":    "EOL May 2019",
    "melodic":  "EOL May 2023",
    "noetic":   "EOL May 2025",
}


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ROS1Node:
    """A discovered ROS1 node with its graph connections."""
    name: str
    uri: str                          # http://host:port/
    host: Optional[str] = None
    port: Optional[int] = None
    topics_pub: List[str] = field(default_factory=list)
    topics_sub: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        result: Dict[str, Any] = {
            "name": self.name,
            "uri": self.uri,
            "topics_pub": self.topics_pub,
            "topics_sub": self.topics_sub,
            "services": self.services,
        }
        if self.host:
            result["host"] = self.host
        if self.port:
            result["port"] = self.port
        return result


@dataclass
class ROS1Topic:
    """A ROS1 topic with its publishers, subscribers, and type info."""
    name: str
    type_name: Optional[str] = None
    publishers: List[str] = field(default_factory=list)    # node names
    subscribers: List[str] = field(default_factory=list)
    is_security_critical: bool = False

    def to_dict(self) -> Dict:
        result: Dict[str, Any] = {
            "name": self.name,
            "publishers": self.publishers,
            "subscribers": self.subscribers,
            "security_critical": self.is_security_critical,
        }
        if self.type_name:
            result["type"] = self.type_name
        return result


@dataclass
class ROS1System:
    """Complete snapshot of a ROS1 deployment."""
    master_uri: str
    timestamp: str
    ros_distro: Optional[str] = None
    ros_version: Optional[str] = None
    nodes: List[ROS1Node] = field(default_factory=list)
    topics: List[ROS1Topic] = field(default_factory=list)
    services: Dict[str, List[str]] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "master_uri": self.master_uri,
            "timestamp": self.timestamp,
            "ros_distro": self.ros_distro,
            "ros_version": self.ros_version,
            "node_count": len(self.nodes),
            "topic_count": len(self.topics),
            "service_count": len(self.services),
            "nodes": [n.to_dict() for n in self.nodes],
            "topics": [t.to_dict() for t in self.topics],
            "services": self.services,
            "parameters": self.parameters,
        }


# ---------------------------------------------------------------------------
# Enumerator
# ---------------------------------------------------------------------------

class ROS1Enumerator:
    """
    Enumerate a ROS1 deployment via the unauthenticated rosmaster API.

    Example:
        enum = ROS1Enumerator(verbose=True)
        system = enum.enumerate("192.168.1.10")
        print(f"Found {len(system.nodes)} nodes")
    """

    def __init__(self, verbose: bool = False, timeout: float = 5.0):
        self.verbose = verbose
        self.timeout = timeout
        self._system: Optional[ROS1System] = None

    def _log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}")

    def enumerate(self, target: str, port: int = 11311) -> ROS1System:
        """
        Connect to the rosmaster at target:port and enumerate the full
        node graph, topic types, and parameter server.

        Returns a ROS1System regardless of how much data was obtained.
        """
        master = ROS1MasterClient(
            host=target,
            port=port,
            timeout=self.timeout,
        )

        system = ROS1System(
            master_uri=f"http://{target}:{port}/",
            timestamp=datetime.now().isoformat(),
        )

        self._log(f"Connecting to rosmaster at {target}:{port}")

        if not master.is_reachable():
            self._log(f"rosmaster at {target}:{port} did not respond")
            self._system = system
            return system

        self._log(f"rosmaster reachable (PID={master.get_pid()})")

        # --- System state (publishers / subscribers / services) ---
        try:
            publishers, subscribers, services = master.get_system_state()
        except ROS1MasterError as exc:
            self._log(f"getSystemState failed: {exc}")
            self._system = system
            return system

        # Build topic → {publishers, subscribers} index
        topic_pubs: Dict[str, List[str]] = {}
        topic_subs: Dict[str, List[str]] = {}

        for topic, nodes in publishers:
            topic_pubs.setdefault(topic, []).extend(nodes)
        for topic, nodes in subscribers:
            topic_subs.setdefault(topic, []).extend(nodes)

        # --- Topic types ---
        self._log("Fetching topic types...")
        type_map = master.get_topic_types()

        # --- Build node index ---
        self._log("Building node graph...")
        node_map: Dict[str, ROS1Node] = {}

        all_nodes: set = set()
        for topic, nodes in publishers + subscribers:
            all_nodes.update(nodes)
        for svc, nodes in services:
            all_nodes.update(nodes)

        for node_name in sorted(all_nodes):
            uri = master.lookup_node(node_name) or ""
            host, node_port = ROS1MasterClient.parse_host_port(uri)
            node_map[node_name] = ROS1Node(
                name=node_name,
                uri=uri,
                host=host,
                port=node_port,
            )

        for topic, nodes in publishers:
            for n in nodes:
                if n in node_map:
                    node_map[n].topics_pub.append(topic)

        for topic, nodes in subscribers:
            for n in nodes:
                if n in node_map:
                    node_map[n].topics_sub.append(topic)

        for svc, nodes in services:
            for n in nodes:
                if n in node_map:
                    node_map[n].services.append(svc)

        system.nodes = list(node_map.values())

        # --- Build topic list ---
        all_topics = set(list(topic_pubs.keys()) + list(topic_subs.keys()))
        for topic_name in sorted(all_topics):
            t = ROS1Topic(
                name=topic_name,
                type_name=type_map.get(topic_name),
                publishers=topic_pubs.get(topic_name, []),
                subscribers=topic_subs.get(topic_name, []),
                is_security_critical=topic_name in SECURITY_CRITICAL_TOPICS,
            )
            system.topics.append(t)

        # --- Service map ---
        system.services = {svc: list(nodes) for svc, nodes in services}

        # --- Parameter server ---
        self._log("Dumping parameter server...")
        params = master.get_param("/")
        if params and isinstance(params, dict):
            system.parameters = params
        else:
            # Fall back to name-by-name fetch
            names = master.get_param_names()
            for name in names:
                val = master.get_param(name)
                system.parameters[name] = val

        # --- Fingerprint ROS distro from params ---
        system.ros_distro = (
            system.parameters.get("/rosdistro", "")
            or system.parameters.get("rosdistro", "")
        )
        if isinstance(system.ros_distro, str):
            system.ros_distro = system.ros_distro.strip()
        else:
            system.ros_distro = None

        system.ros_version = (
            system.parameters.get("/rosversion", "")
            or system.parameters.get("rosversion", "")
        )
        if isinstance(system.ros_version, str):
            system.ros_version = system.ros_version.strip()
        else:
            system.ros_version = None

        self._log(
            f"Enumeration complete — {len(system.nodes)} nodes, "
            f"{len(system.topics)} topics, {len(system.services)} services, "
            f"{len(system.parameters)} params"
        )

        self._system = system
        return system

    def export_results(self, filepath: str):
        """Export the last enumeration result to a JSON file."""
        if not self._system:
            print("[!] No enumeration results to export")
            return
        data = {
            "tool": "ROS2Reaper",
            "module": "ros1_enum",
            "timestamp": self._system.timestamp,
            "result": self._system.to_dict(),
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[*] ROS1 enumeration saved to {filepath}")
