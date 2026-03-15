#!/usr/bin/env python3
"""
ros1_audit.py — ROS1 Security Configuration Auditor
=====================================================
Analyses a ROS1System snapshot (from ros1_enum.py) and produces a
structured AuditReport using the same finding/severity types as the
SROS2 auditor — keeping report output consistent across ROS versions.

Checks:
  ROS1-001  CRITICAL  Unauthenticated rosmaster (structural, always present)
  ROS1-002  HIGH      No transport encryption (TCPROS is always plaintext)
  ROS1-003  HIGH      Security-critical topics exposed (cmd_vel, scan, etc.)
  ROS1-004  HIGH      Sensitive data in parameter server
  ROS1-005  HIGH      Nodes accept unauthenticated remote shutdown
  ROS1-006  MEDIUM    EOL ROS distro (melodic/noetic/kinetic)
  ROS1-007  MEDIUM    Nodes in global namespace (/)
  ROS1-008  LOW       /robot_description (URDF) exposed in param server
  ROS1-009  INFO      /rosout aggregation point active

Author: Gh057x
"""

import re
from typing import List

from modules.sros2_audit import AuditFinding, AuditReport, Severity
from modules.ros1_enum import ROS1System, EOL_DISTROS, SECURITY_CRITICAL_TOPICS


# Parameter key patterns considered sensitive
_SENSITIVE_PATTERNS = re.compile(
    r"(password|passwd|token|secret|api.?key|credential|private.?key|cert|auth)",
    re.IGNORECASE,
)


class ROS1Auditor:
    """
    Security auditor for ROS1 deployments.

    Works from a ROS1System object returned by ROS1Enumerator.enumerate().
    Does not require live network access.

    Example:
        system = ROS1Enumerator().enumerate("192.168.1.10")
        auditor = ROS1Auditor()
        report = auditor.audit(system)
        print_audit_report(report)          # reuses sros2_audit printer
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def audit(self, system: ROS1System) -> AuditReport:
        """Run all checks and return a populated AuditReport."""
        report = AuditReport(
            target=system.master_uri,
            timestamp=system.timestamp,
            participants_audited=len(system.nodes),
        )

        self._check_unauthenticated_master(system, report)
        self._check_no_encryption(system, report)
        self._check_critical_topics(system, report)
        self._check_sensitive_params(system, report)
        self._check_remote_shutdown(system, report)
        self._check_eol_distro(system, report)
        self._check_global_namespace(system, report)
        self._check_urdf_exposed(system, report)
        self._check_rosout(system, report)

        report.generate_summary()
        return report

    # ------------------------------------------------------------------
    # Checks
    # ------------------------------------------------------------------

    def _check_unauthenticated_master(self, system: ROS1System, report: AuditReport):
        """ROS1-001: rosmaster provides no authentication."""
        report.add_finding(AuditFinding(
            check_id="ROS1-001",
            title="Unauthenticated rosmaster API",
            severity=Severity.CRITICAL,
            description=(
                f"The ROS1 Master at {system.master_uri} requires no authentication. "
                "Any host with network access can enumerate all nodes, topics, services, "
                "and parameters, register fake publishers/subscribers, and remotely "
                "shut down any node. This is a fundamental design limitation of ROS1 "
                "with no built-in mitigation."
            ),
            evidence=(
                f"rosmaster reachable at {system.master_uri} — "
                f"{len(system.nodes)} node(s) enumerated without credentials"
            ),
            remediation=(
                "Isolate the ROS network using VLANs or a dedicated physical network. "
                "Apply host-based firewall rules to restrict port 11311 to trusted hosts. "
                "Consider migrating to ROS2 with SROS2 for cryptographic authentication."
            ),
        ))

    def _check_no_encryption(self, system: ROS1System, report: AuditReport):
        """ROS1-002: TCPROS has no encryption."""
        report.add_finding(AuditFinding(
            check_id="ROS1-002",
            title="No transport encryption (TCPROS is plaintext)",
            severity=Severity.HIGH,
            description=(
                "All ROS1 topic data is transmitted over TCPROS in cleartext with no "
                "encryption or integrity protection. Any network observer can read all "
                "sensor data, log all robot commands, and inject arbitrary messages "
                "without detection. There is no per-message signing in standard ROS1."
            ),
            remediation=(
                "Use a VPN (WireGuard, IPSec) or TLS tunnel for all ROS network segments. "
                "For sensor/command confidentiality, consider ROS2 with DDS-Security "
                "ENCRYPT mode."
            ),
        ))

    def _check_critical_topics(self, system: ROS1System, report: AuditReport):
        """ROS1-003: Security-critical topics with active publishers."""
        critical = [
            t for t in system.topics
            if t.is_security_critical and t.publishers
        ]
        if not critical:
            return

        names = [t.name for t in critical]
        report.add_finding(AuditFinding(
            check_id="ROS1-003",
            title=f"{len(critical)} security-critical topic(s) actively published",
            severity=Severity.HIGH,
            description=(
                f"The following topics control robot motion or sensor perception and have "
                f"active publishers. An attacker can inject into any of these via TCPROS "
                f"without authentication: {', '.join(names)}"
            ),
            evidence="; ".join(
                f"{t.name} — pubs: {t.publishers}" for t in critical[:5]
            ),
            remediation=(
                "Implement ROS1 message signing (rosauth / rosbridge_server auth). "
                "Restrict publisher access using network-level controls. "
                "Monitor for unexpected publisher registrations on critical topics."
            ),
        ))

    def _check_sensitive_params(self, system: ROS1System, report: AuditReport):
        """ROS1-004: Sensitive data in parameter server."""
        sensitive_keys: List[str] = []

        def _walk(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    path = f"{prefix}/{k}" if prefix else f"/{k}"
                    if _SENSITIVE_PATTERNS.search(k):
                        sensitive_keys.append(path)
                    _walk(v, path)

        _walk(system.parameters)

        if sensitive_keys:
            report.add_finding(AuditFinding(
                check_id="ROS1-004",
                title=f"Potentially sensitive parameter(s) exposed on parameter server",
                severity=Severity.HIGH,
                description=(
                    f"{len(sensitive_keys)} parameter name(s) match patterns suggesting "
                    "credentials, tokens, or private keys are stored in the parameter server, "
                    "which is readable by any host with network access to rosmaster."
                ),
                evidence=f"Keys: {', '.join(sensitive_keys[:10])}",
                remediation=(
                    "Do not store secrets in the ROS parameter server. "
                    "Use environment variables, vault solutions (HashiCorp Vault), "
                    "or ROS2 with parameter encryption."
                ),
            ))

    def _check_remote_shutdown(self, system: ROS1System, report: AuditReport):
        """ROS1-005: Nodes expose unauthenticated XMLRPC shutdown API."""
        node_count = len(system.nodes)
        if node_count == 0:
            return

        report.add_finding(AuditFinding(
            check_id="ROS1-005",
            title=f"{node_count} node(s) accept unauthenticated remote shutdown",
            severity=Severity.HIGH,
            description=(
                f"Every ROS1 node exposes an XMLRPC API that includes a shutdown() "
                f"method. Any host that can reach the node's XMLRPC port can terminate "
                f"the node immediately with no authentication. With the node URI obtained "
                f"from rosmaster.lookupNode(), this is a one-call remote kill."
            ),
            evidence=f"Nodes: {', '.join(n.name for n in system.nodes[:10])}",
            remediation=(
                "Restrict XMLRPC node ports using host firewall rules. "
                "Monitor for unexpected calls to the shutdown endpoint. "
                "ROS2 with SROS2 eliminates this attack vector."
            ),
        ))

    def _check_eol_distro(self, system: ROS1System, report: AuditReport):
        """ROS1-006: End-of-life ROS distribution."""
        distro = (system.ros_distro or "").lower().strip()
        if not distro:
            return

        if distro in EOL_DISTROS:
            status = EOL_DISTROS[distro]
            report.add_finding(AuditFinding(
                check_id="ROS1-006",
                title=f"End-of-life ROS1 distribution: {distro}",
                severity=Severity.MEDIUM,
                description=(
                    f"The target is running ROS1 {distro} ({status}). "
                    "No security patches or bug fixes will be released for this "
                    "distribution. Known vulnerabilities will remain unpatched."
                ),
                evidence=f"ros_distro={distro}, ros_version={system.ros_version}",
                remediation=(
                    "Migrate to ROS2 (Humble LTS or Jazzy LTS). "
                    "If ROS1 is required, update to the latest Noetic packages "
                    "and implement compensating network controls."
                ),
            ))
        else:
            # Still worth flagging that it's ROS1 at all
            report.add_finding(AuditFinding(
                check_id="ROS1-006",
                title=f"ROS1 distribution in use: {distro}",
                severity=Severity.MEDIUM,
                description=(
                    f"Target is running ROS1 {distro}. "
                    "ROS1 lacks the security architecture of ROS2 (DDS-Security, "
                    "SROS2) and all ROS1 distros will eventually reach EOL."
                ),
                evidence=f"ros_distro={distro}",
                remediation="Plan migration to ROS2 with SROS2 for long-term security.",
            ))

    def _check_global_namespace(self, system: ROS1System, report: AuditReport):
        """ROS1-007: Nodes registered in the global namespace."""
        global_nodes = [
            n for n in system.nodes
            if n.name.count("/") == 1  # exactly "/<name>" — no sub-namespace
        ]
        if len(global_nodes) > len(system.nodes) // 2:
            report.add_finding(AuditFinding(
                check_id="ROS1-007",
                title="Majority of nodes in global namespace",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(global_nodes)} of {len(system.nodes)} node(s) are registered "
                    "in the global (/) namespace with no sub-namespacing. This makes it "
                    "trivial for an attacker to predict topic names and register "
                    "conflicting publishers or subscribers."
                ),
                evidence=f"Global nodes: {', '.join(n.name for n in global_nodes[:8])}",
                remediation=(
                    "Use ROS namespacing (e.g. /robot1/cmd_vel) to logically isolate "
                    "subsystems and reduce topic collision attack surface."
                ),
            ))

    def _check_urdf_exposed(self, system: ROS1System, report: AuditReport):
        """ROS1-008: /robot_description URDF exposed."""
        has_urdf = (
            "/robot_description" in system.parameters
            or "robot_description" in system.parameters
        )
        if has_urdf:
            report.add_finding(AuditFinding(
                check_id="ROS1-008",
                title="/robot_description (URDF) exposed on parameter server",
                severity=Severity.LOW,
                description=(
                    "The robot's full URDF model is available on the parameter server. "
                    "URDF files contain detailed physical specifications (joint limits, "
                    "link dimensions, sensor placement) that aid attacker planning for "
                    "physical-world attacks."
                ),
                evidence="Parameter /robot_description present",
                remediation=(
                    "Restrict parameter server access to the ROS network segment. "
                    "Consider whether the full URDF needs to be published globally."
                ),
            ))

    def _check_rosout(self, system: ROS1System, report: AuditReport):
        """ROS1-009: /rosout log aggregation topic active."""
        rosout_topics = [
            t for t in system.topics
            if t.name in ("/rosout", "/rosout_agg")
        ]
        if rosout_topics:
            report.add_finding(AuditFinding(
                check_id="ROS1-009",
                title="/rosout log aggregation topic is active",
                severity=Severity.INFO,
                description=(
                    "The /rosout topic aggregates log messages from all nodes. "
                    "An attacker can subscribe to /rosout to passively harvest "
                    "debug output, error messages, and operational intelligence "
                    "without sending any traffic."
                ),
                evidence=f"Topics: {', '.join(t.name for t in rosout_topics)}",
                remediation=(
                    "Restrict /rosout access using network controls. "
                    "Avoid logging sensitive data (IPs, credentials, waypoints) "
                    "through the ROS logging system."
                ),
            ))
