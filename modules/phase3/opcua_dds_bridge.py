#!/usr/bin/env python3
"""
opcua_dds_bridge.py — OPC UA / DDS Bridge Attack Surface Analyzer
==================================================================
ROS2Reaper Phase 3 Module

Detects and analyzes hosts running both DDS and OPC UA (the dominant ICS
data exchange protocol), characterizes the bridge attack surface, and
generates PoC attack scenarios for crossing from the DDS domain into the
OPC UA namespace.

Why this matters:
    OPC UA ↔ DDS bridges are increasingly common in Industry 4.0 deployments.
    The OMG DDS-OPC UA Gateway specification defines a standard mapping, and
    multiple vendor implementations exist (RTI, Unified Automation, Eclipse
    Milo). A compromised DDS participant can write to bridged OPC UA nodes,
    potentially reaching SCADA historians, HMIs, and physical actuation.

OPC UA default port: 4840 (TCP)
DDS discovery port:  7400+ (UDP)

Author  : Gh057x
Phase   : 3 — ICS/OT Bridge
Requires: opcua OR asyncua (optional, degrades gracefully), scapy

Usage:
    python3 opcua_dds_bridge.py --target 10.0.0.5
    python3 opcua_dds_bridge.py --cidr 192.168.1.0/24 --deep
    python3 opcua_dds_bridge.py --target 10.0.0.5 --enumerate-nodes
    python3 opcua_dds_bridge.py --target 10.0.0.5 --output bridge_report.json
"""

import socket
import struct
import time
import json
import argparse
import sys
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress

# OPC UA support is optional — degrade gracefully if not installed
try:
    from opcua import Client as OpcuaClient, ua
    OPCUA_AVAILABLE = True
except ImportError:
    try:
        from asyncua.sync import Client as OpcuaClient
        import asyncua.ua as ua
        OPCUA_AVAILABLE = True
    except ImportError:
        OPCUA_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

OPCUA_PORTS     = [4840, 4843, 48010, 4841, 4855]   # 4843=TLS, 48010=ANSI/ISA
DDS_DISC_PORTS  = [7400, 7410, 7650, 7660, 8650, 8660]
MODBUS_PORTS    = [502, 503]
DNP3_PORTS      = [20000, 19999]
MQTT_PORTS      = [1883, 8883]
ETHERCAT_PORTS  = [34980]
PROFINET_PORTS  = [34962, 34963, 34964]

# OPC UA Hello message (minimal, to confirm OPC UA is listening)
OPCUA_HELLO = (
    b"HELF"            # MessageType: HEL
    b"\x00"            # Reserved
    b"\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00"  # MessageSize 28
    b"\x00\x00\x00\x00"  # ProtocolVersion: 0
    b"\x00\x00\x08\x00"  # ReceiveBufferSize: 512K
    b"\x00\x00\x08\x00"  # SendBufferSize: 512K
    b"\x00\x00\x10\x00"  # MaxMessageSize: 1M
    b"\x00\x00\x00\x00"  # MaxChunkCount: 0 (unlimited)
    b"\x00\x00\x00\x00"  # EndpointUrl length: 0 (empty)
)

# OPC UA Known Namespace URIs — signals for ICS vendor bridge implementations
OPCUA_ICS_NAMESPACES = {
    "urn:opcfoundation.org:DDS":              "OMG DDS-OPC UA Gateway (official)",
    "urn:rti.com:dds:":                       "RTI Connext DDS-OPC UA bridge",
    "urn:unified-automation.com":             "Unified Automation OPC UA SDK",
    "urn:eclipse.org:milo":                   "Eclipse Milo (open-source OPC UA)",
    "urn:prosysopc.com":                      "Prosys OPC UA SDK",
    "urn:factoryTalk":                        "Rockwell FactoryTalk (Automation)",
    "urn:siemens.com:WinCC":                  "Siemens WinCC SCADA",
    "urn:indusoft.com":                       "AVEVA InduSoft",
    "urn:kepware.com":                        "Kepware KEPServerEX",
    "urn:osisoft.com:PI":                     "OSIsoft PI System (historian)",
    "urn:inductive-automation.com":           "Ignition SCADA (Inductive Automation)",
    "urn:EUROCONTROL.int":                    "EUROCONTROL ATC system",
    "urn:GE.com:Predix":                      "GE Predix Industrial IoT",
}

# Bridge attack scenarios — maps DDS topic patterns to OPC UA node impact
BRIDGE_ATTACK_SCENARIOS = [
    {
        "id":           "BRIDGE-001",
        "name":         "DDS→OPC UA Setpoint Injection",
        "description":  (
            "Write a malicious value to a DDS topic that is bridged to an OPC UA "
            "Variable node representing a process setpoint (temperature, pressure, "
            "flow rate). The OPC UA server propagates the write to the SCADA historian "
            "or directly to the PLC controlling the physical process."
        ),
        "dds_topic_pattern": r"/(setpoint|sp_|set_|control_value)",
        "opcua_node_type":   "Variable (Double/Float)",
        "impact":            "Physical process manipulation via setpoint override",
        "cvss":              "9.1",
        "mitre_ics":         "T0831 — Manipulation of Control",
    },
    {
        "id":           "BRIDGE-002",
        "name":         "DDS→OPC UA Alarm Suppression",
        "description":  (
            "Inject DDS messages to force-clear an alarm topic that is bridged to "
            "an OPC UA AlarmCondition node. Operators lose visibility into the fault "
            "condition while the underlying process fault persists."
        ),
        "dds_topic_pattern": r"/(alarm|alert|fault|safety)",
        "opcua_node_type":   "AlarmCondition / EventType",
        "impact":            "Operational visibility loss, safety system bypass",
        "cvss":              "8.6",
        "mitre_ics":         "T0878 — Alarm Suppression",
    },
    {
        "id":           "BRIDGE-003",
        "name":         "DDS→OPC UA Historian Poisoning",
        "description":  (
            "Inject manipulated process data into DDS topics feeding the OPC UA "
            "historian bridge. Corrupts long-term trend data, forensic records, and "
            "compliance logs without triggering real-time alarms."
        ),
        "dds_topic_pattern": r"/(measurement|reading|trend|process_value)",
        "opcua_node_type":   "Variable (with History)",
        "impact":            "Audit log corruption, compliance record manipulation",
        "cvss":              "7.5",
        "mitre_ics":         "T0832 — Manipulation of View",
    },
    {
        "id":           "BRIDGE-004",
        "name":         "OPC UA→DDS Command Replay (Reverse Bridge)",
        "description":  (
            "Subscribe on the DDS side to a topic bridged from OPC UA Method calls. "
            "Capture legitimate operator commands and replay them out-of-sequence or "
            "at an unexpected time to cause process state confusion."
        ),
        "dds_topic_pattern": r"/(cmd_|command|request|method)",
        "opcua_node_type":   "Method",
        "impact":            "Process command replay, state machine confusion",
        "cvss":              "7.2",
        "mitre_ics":         "T0828 — Loss of Control",
    },
    {
        "id":           "BRIDGE-005",
        "name":         "DDS Participant → OPC UA Server DoS via Bridge Flood",
        "description":  (
            "Flood a DDS topic with high-frequency updates. The bridge translates each "
            "DDS sample into an OPC UA subscription notification, overwhelming the OPC UA "
            "server's subscription queue and causing legitimate client disconnections."
        ),
        "dds_topic_pattern": r".*",   # any bridged topic
        "opcua_node_type":   "Any subscribed Variable",
        "impact":            "OPC UA server DoS, HMI disconnection, operator blind spot",
        "cvss":              "7.5",
        "mitre_ics":         "T0814 — Denial of Control",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class OpcuaEndpoint:
    """Discovered OPC UA endpoint on a host."""
    host:             str
    port:             int
    tls:              bool               = False
    server_uri:       str                = ""
    namespaces:       list               = field(default_factory=list)
    endpoints:        list               = field(default_factory=list)
    security_modes:   list               = field(default_factory=list)   # None/Sign/SignEncrypt
    anonymous_allowed: bool              = False
    vendor_known:     bool               = False
    vendor_name:      str                = ""
    bridge_indicators: list             = field(default_factory=list)
    node_count:       int                = 0
    sample_nodes:     list               = field(default_factory=list)


@dataclass
class BridgeHostReport:
    """Full analysis report for a host running both DDS and OPC UA."""
    ip:                   str
    scan_time:            str            = field(default_factory=lambda: datetime.now().isoformat())
    dds_ports_open:       list           = field(default_factory=list)
    opcua_ports_open:     list           = field(default_factory=list)
    other_ics_protocols:  dict           = field(default_factory=dict)
    opcua_detail:         Optional[dict] = None
    bridge_confirmed:     bool           = False
    bridge_evidence:      list           = field(default_factory=list)
    applicable_scenarios: list           = field(default_factory=list)
    risk_level:           str            = "UNKNOWN"
    findings:             list           = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNER (lightweight, no nmap dependency)
# ─────────────────────────────────────────────────────────────────────────────

class PortChecker:
    """Fast TCP/UDP port availability checker."""

    @staticmethod
    def tcp_open(ip: str, port: int, timeout: float = 2.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return r == 0
        except OSError:
            return False

    @staticmethod
    def udp_probe(ip: str, port: int, payload: bytes = b"\x00\x00",
                  timeout: float = 2.0) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(payload, (ip, port))
            s.recvfrom(256)
            s.close()
            return True
        except socket.timeout:
            # UDP timeout ≠ closed — port may be open (no response)
            return True   # optimistic for DDS UDP
        except (ConnectionRefusedError, OSError):
            return False


# ─────────────────────────────────────────────────────────────────────────────
# OPC UA PROBER
# ─────────────────────────────────────────────────────────────────────────────

class OpcuaProber:
    """
    Connects to OPC UA servers and enumerates endpoints, namespaces,
    security modes, and optionally the address space for bridge indicators.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def hello_probe(self, ip: str, port: int) -> bool:
        """
        Send an OPC UA HEL message and check for ACK (ACKF).
        Does not require the opcua library — raw TCP.
        Confirms OPC UA is running without establishing a full session.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.sendall(OPCUA_HELLO)
            resp = sock.recv(256)
            sock.close()
            return resp[:3] == b"ACK"
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def enumerate_endpoint(self, ip: str, port: int) -> Optional[OpcuaEndpoint]:
        """
        Full OPC UA endpoint enumeration using the opcua/asyncua library.
        Extracts server URI, namespaces, security modes, anonymous access.
        """
        if not OPCUA_AVAILABLE:
            return None

        endpoint = OpcuaEndpoint(host=ip, port=port, tls=(port == 4843))
        url = f"opc.tcp://{ip}:{port}"

        try:
            client = OpcuaClient(url)
            client.connect_timeout = self.timeout

            # Get endpoints without connecting (no auth needed)
            endpoints = client.get_endpoints()
            endpoint.endpoints = [str(e.EndpointUrl) for e in endpoints]

            # Analyze security policies
            for ep in endpoints:
                mode = ep.SecurityMode
                if hasattr(mode, "name"):
                    mode = mode.name
                endpoint.security_modes.append(str(mode))
                if ep.SecurityMode == 1:   # None
                    endpoint.anonymous_allowed = True

            # Connect anonymously if allowed
            if endpoint.anonymous_allowed:
                client.set_security_string("None")
                client.connect()

                # Server URI from root node
                try:
                    srv_uri = client.get_server_node().get_browse_name()
                    endpoint.server_uri = str(srv_uri)
                except Exception:
                    pass

                # Namespace table
                try:
                    ns_array = client.get_namespace_array()
                    endpoint.namespaces = ns_array

                    # Check for known bridge/vendor namespaces
                    for ns in ns_array:
                        for known_ns, vendor_name in OPCUA_ICS_NAMESPACES.items():
                            if known_ns.lower() in ns.lower():
                                endpoint.bridge_indicators.append(
                                    f"Namespace match: {ns} → {vendor_name}"
                                )
                                endpoint.vendor_known = True
                                endpoint.vendor_name  = vendor_name
                except Exception:
                    pass

                client.disconnect()

        except Exception as e:
            # Connection errors are expected for secured servers
            pass

        # Check bridge indicators in endpoint URLs
        for ep_url in endpoint.endpoints:
            ep_lower = ep_url.lower()
            if any(k in ep_lower for k in ["dds", "rtps", "ros", "bridge"]):
                endpoint.bridge_indicators.append(f"Bridge keyword in endpoint URL: {ep_url}")

        return endpoint

    def enumerate_nodes(self, ip: str, port: int, max_nodes: int = 200) -> list:
        """
        Browse the OPC UA address space for DDS-bridged node indicators.
        Only called in --deep mode. Requires anonymous access.
        """
        if not OPCUA_AVAILABLE:
            return []

        nodes = []
        url   = f"opc.tcp://{ip}:{port}"

        try:
            client = OpcuaClient(url)
            client.set_security_string("None")
            client.connect()

            root     = client.get_root_node()
            objects  = client.get_objects_node()

            def browse(node, depth=0):
                if depth > 3 or len(nodes) >= max_nodes:
                    return
                try:
                    children = node.get_children()
                    for child in children:
                        try:
                            bn   = child.get_browse_name()
                            name = str(bn.Name)
                            nodes.append({
                                "node_id":   str(child.nodeid),
                                "name":      name,
                                "depth":     depth,
                                "is_dds_bridge_candidate": any(
                                    kw in name.lower()
                                    for kw in ["dds", "topic", "ros", "rtps",
                                               "participant", "domain"]
                                ),
                            })
                            browse(child, depth + 1)
                        except Exception:
                            pass
                except Exception:
                    pass

            browse(objects)
            client.disconnect()

        except Exception:
            pass

        return nodes


# ─────────────────────────────────────────────────────────────────────────────
# BRIDGE ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class BridgeAnalyzer:
    """
    Correlates DDS presence with OPC UA presence on the same host and
    produces a bridge attack surface report with applicable scenarios.
    """

    def analyze(self, ip: str, dds_ports: list, opcua_endpoint: Optional[OpcuaEndpoint],
                other_protocols: dict) -> BridgeHostReport:
        report = BridgeHostReport(
            ip                  = ip,
            dds_ports_open      = dds_ports,
            opcua_ports_open    = [opcua_endpoint.port] if opcua_endpoint else [],
            other_ics_protocols = other_protocols,
        )

        if not dds_ports or not opcua_endpoint:
            report.risk_level = "LOW" if not dds_ports else "MEDIUM"
            return report

        # Both DDS and OPC UA present — bridge candidate
        report.bridge_evidence.append(
            f"DDS ports {dds_ports} and OPC UA port {opcua_endpoint.port} open on same host"
        )

        if opcua_endpoint.bridge_indicators:
            report.bridge_confirmed = True
            report.bridge_evidence.extend(opcua_endpoint.bridge_indicators)

        # Security assessment
        if opcua_endpoint.anonymous_allowed:
            report.findings.append({
                "id":     "BRIDGE-SEC-001",
                "title":  "OPC UA Anonymous Access Enabled",
                "detail": f"OPC UA server at {ip}:{opcua_endpoint.port} allows unauthenticated connections.",
                "cvss":   "8.6",
                "cwe":    "CWE-306",
            })

        if "None" in opcua_endpoint.security_modes:
            report.findings.append({
                "id":     "BRIDGE-SEC-002",
                "title":  "OPC UA No-Security Mode Active",
                "detail": "OPC UA endpoint accepts SecurityMode=None (no encryption/signing).",
                "cvss":   "7.5",
                "cwe":    "CWE-319",
            })

        if opcua_endpoint.vendor_known:
            report.findings.append({
                "id":     "BRIDGE-SEC-003",
                "title":  f"Known DDS-OPC UA Bridge Implementation: {opcua_endpoint.vendor_name}",
                "detail": (
                    f"Namespace evidence confirms {opcua_endpoint.vendor_name} bridge. "
                    f"DDS domain manipulation can propagate directly to OPC UA nodes."
                ),
                "cvss":   "9.0",
                "cwe":    "CWE-441",
            })

        # Applicable attack scenarios
        report.applicable_scenarios = BRIDGE_ATTACK_SCENARIOS.copy()

        # Risk level
        has_critical = any(
            float(f.get("cvss", "0")) >= 9.0 for f in report.findings
        )
        has_high = any(
            float(f.get("cvss", "0")) >= 7.5 for f in report.findings
        )
        if has_critical or report.bridge_confirmed:
            report.risk_level = "CRITICAL"
        elif has_high:
            report.risk_level = "HIGH"
        else:
            report.risk_level = "MEDIUM"

        return report


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class OpcuaDDSBridgeScanner:
    """
    Top-level scanner: for each target, checks for DDS and OPC UA coexistence,
    probes OPC UA endpoints, and generates bridge attack surface reports.
    """

    def __init__(self, args):
        self.args      = args
        self.checker   = PortChecker()
        self.prober    = OpcuaProber(timeout=args.timeout)
        self.analyzer  = BridgeAnalyzer()
        self.results   = []

    def scan_host(self, ip: str) -> Optional[BridgeHostReport]:
        """Scan a single host for DDS + OPC UA bridge surface."""

        # Check DDS ports (UDP)
        dds_open = []
        for port in DDS_DISC_PORTS:
            if self.checker.udp_probe(ip, port):
                dds_open.append(port)

        # Check OPC UA ports (TCP)
        opcua_open = []
        for port in OPCUA_PORTS:
            if self.checker.tcp_open(ip, port):
                opcua_open.append(port)

        # Skip hosts with neither
        if not dds_open and not opcua_open:
            return None

        print(f"  [+] {ip} | DDS:{dds_open} | OPC-UA:{opcua_open}")

        # OPC UA hello probe on open ports
        opcua_endpoint = None
        for port in opcua_open:
            if self.prober.hello_probe(ip, port):
                print(f"      OPC UA confirmed on {port} (HEL/ACK)")
                if OPCUA_AVAILABLE:
                    opcua_endpoint = self.prober.enumerate_endpoint(ip, port)
                    if self.args.enumerate_nodes and opcua_endpoint:
                        nodes = self.prober.enumerate_nodes(ip, port)
                        opcua_endpoint.sample_nodes = nodes[:50]
                        opcua_endpoint.node_count   = len(nodes)
                break

        # Other ICS protocols
        other_protocols = {}
        if self.args.deep:
            for proto, ports in [
                ("Modbus",   MODBUS_PORTS),
                ("DNP3",     DNP3_PORTS),
                ("MQTT",     MQTT_PORTS),
                ("EtherCAT", ETHERCAT_PORTS),
                ("PROFINET", PROFINET_PORTS),
            ]:
                open_p = [p for p in ports if self.checker.tcp_open(ip, p)]
                if open_p:
                    other_protocols[proto] = open_p

        report = self.analyzer.analyze(ip, dds_open, opcua_endpoint, other_protocols)
        return report

    def run(self) -> list:
        targets = []

        if self.args.target:
            targets = [self.args.target]
        elif self.args.cidr:
            network = ipaddress.ip_network(self.args.cidr, strict=False)
            targets = [str(h) for h in network.hosts()]
            print(f"[*] Sweeping {self.args.cidr} ({len(targets)} hosts)")

        print(f"\n{'='*60}")
        print("  ROS2Reaper :: Phase 3 — OPC UA/DDS Bridge Scanner")
        print(f"{'='*60}\n")

        if not OPCUA_AVAILABLE:
            print("[!] opcua/asyncua not installed — running port-level detection only")
            print("[!] Install with: pip install opcua  OR  pip install asyncua\n")

        with ThreadPoolExecutor(max_workers=self.args.threads) as pool:
            futures = {pool.submit(self.scan_host, ip): ip for ip in targets}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)

        self._print_summary()
        return self.results

    def _print_summary(self):
        print(f"\n{'='*60}")
        print("  BRIDGE SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"  Hosts with DDS+OPC UA : {sum(1 for r in self.results if r.dds_ports_open and r.opcua_ports_open)}")
        print(f"  Bridge confirmed      : {sum(1 for r in self.results if r.bridge_confirmed)}")
        print(f"  Critical risk hosts   : {sum(1 for r in self.results if r.risk_level == 'CRITICAL')}")

        crit = [r for r in self.results if r.risk_level == "CRITICAL"]
        if crit:
            print(f"\n  ⚠  CRITICAL BRIDGE HOSTS:")
            for r in crit:
                print(f"    {r.ip}")
                for finding in r.findings:
                    print(f"      → [{finding['id']}] {finding['title']} (CVSS {finding['cvss']})")
                if r.bridge_confirmed:
                    print(f"      → Bridge CONFIRMED — {len(r.applicable_scenarios)} attack scenarios applicable")

        print(f"\n  Applicable attack scenarios (any bridge host):")
        for s in BRIDGE_ATTACK_SCENARIOS:
            print(f"    [{s['id']}] {s['name']} — CVSS {s['cvss']}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ROS2Reaper Phase 3 — OPC UA / DDS Bridge Attack Surface Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 opcua_dds_bridge.py --target 10.0.0.5
    python3 opcua_dds_bridge.py --cidr 192.168.1.0/24
    python3 opcua_dds_bridge.py --target 10.0.0.5 --enumerate-nodes
    python3 opcua_dds_bridge.py --cidr 10.52.32.0/24 --deep --output bridge.json
        """
    )
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target", help="Single target IP")
    tgt.add_argument("--cidr",   help="CIDR range to scan")

    p.add_argument("--timeout",         type=float, default=3.0)
    p.add_argument("--threads",         type=int,   default=30)
    p.add_argument("--deep",            action="store_true",
                   help="Probe additional ICS protocols (Modbus, DNP3, MQTT…)")
    p.add_argument("--enumerate-nodes", action="store_true", dest="enumerate_nodes",
                   help="Browse OPC UA address space for DDS bridge node indicators")
    p.add_argument("--output",          metavar="FILE", help="Write JSON report to file")
    return p.parse_args()


def main():
    args    = parse_args()
    scanner = OpcuaDDSBridgeScanner(args)
    results = scanner.run()

    if args.output:
        out = [r.to_dict() for r in results]
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2)
        print(f"[+] Report saved → {args.output}")


if __name__ == "__main__":
    main()
