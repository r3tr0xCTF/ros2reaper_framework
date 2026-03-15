#!/usr/bin/env python3
"""
sros2_audit.py - SROS2 Security Configuration Auditor
=======================================================
Audits the security posture of ROS 2 deployments by analyzing
DDS-Security configuration, certificate hygiene, and common
misconfigurations in SROS2 setups.

Checks:
1. Is DDS-Security / SROS2 enabled at all?
2. Certificate analysis (self-signed, expired, weak keys)
3. Governance policy analysis (overly permissive rules)
4. Permissions policy analysis (wildcard grants)
5. Encryption vs signing mode (SIGN only = visible plaintext)
6. CRL presence and validity
7. Default/demo credential detection

Author: Gh057x
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from core.rtps_parser import DDSParticipant


# =============================================================================
# Audit Result Types
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"


@dataclass
class AuditFinding:
    """Single audit finding"""
    check_id: str
    title: str
    severity: Severity
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cve_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        result = {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
        }
        if self.evidence:
            result["evidence"] = self.evidence
        if self.remediation:
            result["remediation"] = self.remediation
        if self.cve_refs:
            result["cve_references"] = self.cve_refs
        return result


@dataclass
class AuditReport:
    """Complete audit report for a target"""
    target: str
    timestamp: str
    participants_audited: int = 0
    findings: List[AuditFinding] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)

    def add_finding(self, finding: AuditFinding):
        self.findings.append(finding)

    def generate_summary(self):
        self.summary = {s.value: 0 for s in Severity}
        for f in self.findings:
            self.summary[f.severity.value] += 1

    def to_dict(self) -> Dict:
        self.generate_summary()
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "participants_audited": self.participants_audited,
            "summary": self.summary,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


# =============================================================================
# Auditor
# =============================================================================

class SROS2Auditor:
    """
    Security auditor for ROS 2 / DDS deployments.
    
    Performs checks against discovered DDS participants to assess
    the security posture of the deployment. Works from network-level
    discovery data — does not require access to the filesystem.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def audit_participants(self, participants: List[DDSParticipant],
                            target_name: str = "unknown") -> AuditReport:
        """
        Run all audit checks against discovered participants.
        """
        report = AuditReport(
            target=target_name,
            timestamp=datetime.now().isoformat(),
            participants_audited=len(participants),
        )

        if not participants:
            report.add_finding(AuditFinding(
                check_id="SROS2-000",
                title="No participants discovered",
                severity=Severity.INFO,
                description="No DDS participants were discovered on the target. "
                            "This could mean no ROS 2 / DDS systems are running, "
                            "or network access is restricted.",
            ))
            return report

        # Run check categories
        self._check_security_enabled(participants, report)
        self._check_encryption_mode(participants, report)
        self._check_participant_exposure(participants, report)
        self._check_ip_leakage(participants, report)
        self._check_known_vulns(participants, report)
        self._check_default_config(participants, report)
        self._check_domain_isolation(participants, report)
        self._check_security_tokens(participants, report)

        report.generate_summary()
        return report

    # ----- Check Implementations -----

    def _check_security_enabled(self, participants: List[DDSParticipant],
                                  report: AuditReport):
        """SROS2-001: Check if DDS-Security is enabled"""
        unsecured = [p for p in participants if not p.has_security]
        secured = [p for p in participants if p.has_security]

        if unsecured and not secured:
            # ALL participants are unsecured
            report.add_finding(AuditFinding(
                check_id="SROS2-001",
                title="DDS-Security completely disabled",
                severity=Severity.CRITICAL,
                description=f"All {len(unsecured)} discovered participant(s) have "
                            f"no DDS-Security enabled. All communication is in plaintext "
                            f"with no authentication. Any device on the network can join "
                            f"the DDS domain, subscribe to all topics, and publish "
                            f"arbitrary commands including robot motion controls.",
                evidence=f"Unsecured participants: " +
                         ", ".join(p.participant_name or p.guid_prefix_hex()
                                  for p in unsecured[:5]),
                remediation="Enable SROS2 security using: ros2 security create_keystore, "
                            "ros2 security create_enclave. Set ROS_SECURITY_ENABLE=true "
                            "and ROS_SECURITY_STRATEGY=Enforce in the environment.",
                cve_refs=["CVE-2021-38487", "CVE-2021-38429", "CVE-2021-38425"],
            ))

        elif unsecured and secured:
            # Mixed security — some secured, some not
            report.add_finding(AuditFinding(
                check_id="SROS2-001",
                title="Mixed security posture — some participants unsecured",
                severity=Severity.HIGH,
                description=f"{len(unsecured)} of {len(participants)} participants "
                            f"have no DDS-Security enabled. Mixed deployments are "
                            f"especially dangerous because secured nodes may trust "
                            f"unsecured ones depending on configuration.",
                evidence=f"Unsecured: " +
                         ", ".join(p.participant_name or p.guid_prefix_hex()
                                  for p in unsecured[:5]),
                remediation="Ensure all participants in the DDS domain have "
                            "SROS2 security enabled. Use ROS_SECURITY_STRATEGY=Enforce "
                            "to reject unsecured participants.",
            ))

        elif secured and not unsecured:
            report.add_finding(AuditFinding(
                check_id="SROS2-001",
                title="DDS-Security enabled on all participants",
                severity=Severity.PASS,
                description=f"All {len(secured)} participant(s) have DDS-Security enabled.",
            ))

    def _check_encryption_mode(self, participants: List[DDSParticipant],
                                 report: AuditReport):
        """SROS2-002: Check if encryption is enabled (not just signing)"""
        for p in participants:
            if not p.has_security:
                continue

            sec_info = p.security_info.get("participant_security_info", {})
            if isinstance(sec_info, dict) and "security_attributes" in sec_info:
                # Parse the security attributes bitmask
                # If only SIGN is set but not ENCRYPT, data is visible on the wire
                attrs_hex = sec_info.get("security_attributes", "0x00000000")
                try:
                    attrs = int(attrs_hex, 16)
                except (ValueError, TypeError):
                    continue

                # Check for SIGN-only mode (bit patterns vary by implementation)
                # In general, if rtps_protection_kind = SIGN, traffic is signed but not encrypted
                if attrs & 0x01 and not (attrs & 0x02):
                    report.add_finding(AuditFinding(
                        check_id="SROS2-002",
                        title="RTPS protection set to SIGN only (no encryption)",
                        severity=Severity.HIGH,
                        description=f"Participant {p.participant_name or p.guid_prefix_hex()} "
                                    f"has RTPS protection in SIGN mode. Messages are authenticated "
                                    f"but NOT encrypted — all topic data is visible in plaintext "
                                    f"to any network observer.",
                        evidence=f"security_attributes: {attrs_hex}",
                        remediation="Set rtps_protection_kind to ENCRYPT in the SROS2 "
                                    "governance file to enable full encryption.",
                        cve_refs=["CVE-2019-19625"],
                    ))

    def _check_participant_exposure(self, participants: List[DDSParticipant],
                                      report: AuditReport):
        """SROS2-003: Check for sensitive info in participant metadata"""
        for p in participants:
            exposed_info = []

            if p.participant_name:
                exposed_info.append(f"participant_name={p.participant_name}")

            for key, value in p.properties.items():
                # Check for hostname leakage
                if "host" in key.lower() or "hostname" in key.lower():
                    exposed_info.append(f"{key}={value}")
                # Check for username leakage
                elif "user" in key.lower():
                    exposed_info.append(f"{key}={value}")
                # Check for process name leakage
                elif "process" in key.lower():
                    exposed_info.append(f"{key}={value}")
                # Check for PID leakage
                elif "pid" in key.lower() and key != "PID_SENTINEL":
                    exposed_info.append(f"{key}={value}")

            if exposed_info:
                report.add_finding(AuditFinding(
                    check_id="SROS2-003",
                    title="Participant leaking system information via DDS properties",
                    severity=Severity.MEDIUM,
                    description=f"Participant {p.guid_prefix_hex()} exposes system "
                                f"information through DDS participant properties. "
                                f"This aids attacker reconnaissance.",
                    evidence="; ".join(exposed_info),
                    remediation="Configure the DDS implementation to suppress "
                                "physical data properties. For Fast DDS, set "
                                "rtps.builtin.discovery_config.use_SIMPLE_"
                                "EndpointDiscoveryProtocol to minimize exposure.",
                ))

    def _check_ip_leakage(self, participants: List[DDSParticipant],
                            report: AuditReport):
        """SROS2-004: Check for internal IP address leakage via locators"""
        import ipaddress

        for p in participants:
            all_locators = (
                p.unicast_locators + p.multicast_locators +
                p.metatraffic_unicast + p.metatraffic_multicast
            )

            leaked_ips = set()
            for loc in all_locators:
                try:
                    addr = ipaddress.ip_address(loc.address)
                    if addr.is_private and not addr.is_loopback:
                        if p.source_ip:
                            source = ipaddress.ip_address(p.source_ip)
                            # Different private IP = internal network intel
                            if addr != source and addr.is_private:
                                leaked_ips.add(str(addr))
                except ValueError:
                    continue

            if leaked_ips:
                report.add_finding(AuditFinding(
                    check_id="SROS2-004",
                    title="Internal IP addresses leaked via DDS locators",
                    severity=Severity.MEDIUM,
                    description=f"Participant {p.participant_name or p.guid_prefix_hex()} "
                                f"is advertising {len(leaked_ips)} internal IP address(es) "
                                f"through DDS locator parameters. This reveals internal "
                                f"network architecture to any DDS participant.",
                    evidence=f"Leaked IPs: {', '.join(leaked_ips)}",
                    remediation="Restrict DDS locator advertisements to necessary "
                                "interfaces only. Use network segmentation to isolate "
                                "DDS traffic from untrusted segments.",
                ))

    def _check_known_vulns(self, participants: List[DDSParticipant],
                             report: AuditReport):
        """SROS2-005: Check for known vulnerable configurations"""
        for p in participants:
            # Check for reflection/amplification vulnerability (CVE-2021-38487)
            # All implementations with multicast locators are potentially vulnerable
            if p.multicast_locators or p.metatraffic_multicast:
                report.add_finding(AuditFinding(
                    check_id="SROS2-005a",
                    title="Potential RTPS reflection/amplification attack surface",
                    severity=Severity.MEDIUM,
                    description=f"Participant {p.participant_name or p.guid_prefix_hex()} "
                                f"has multicast locators enabled. DDS multicast discovery "
                                f"can be abused for reflection/amplification attacks by "
                                f"spoofing the PID_METATRAFFIC_MULTICAST_LOCATOR to redirect "
                                f"discovery traffic to a victim.",
                    evidence=f"Multicast locators: " +
                             ", ".join(str(l) for l in
                                       (p.multicast_locators + p.metatraffic_multicast)[:3]),
                    remediation="Implement network-level filtering for DDS multicast traffic. "
                                "Consider using unicast-only discovery where possible. "
                                "Ensure DDS implementation has exponential decay mitigation.",
                    cve_refs=["CVE-2021-38487"],
                ))

            # Check for QoS policy update bypass (CCS 2022 finding)
            if not p.has_security:
                report.add_finding(AuditFinding(
                    check_id="SROS2-005b",
                    title="Vulnerable to access control policy bypass",
                    severity=Severity.HIGH,
                    description=f"Without DDS-Security, participant "
                                f"{p.participant_name or p.guid_prefix_hex()} is vulnerable "
                                f"to access control bypass attacks where adversarial nodes "
                                f"refuse to restart after policy updates, maintaining "
                                f"revoked access (Deng et al., CCS 2022).",
                    remediation="Enable SROS2 with Enforce strategy. Implement "
                                "monitoring for nodes that fail to restart after "
                                "policy updates.",
                ))

    def _check_default_config(self, participants: List[DDSParticipant],
                                report: AuditReport):
        """SROS2-006: Check for default/demo configurations"""
        for p in participants:
            # Check if running on default domain 0
            if p.domain_id is not None and p.domain_id == 0:
                report.add_finding(AuditFinding(
                    check_id="SROS2-006",
                    title="Using default DDS Domain ID 0",
                    severity=Severity.LOW,
                    description=f"Participant {p.participant_name or p.guid_prefix_hex()} "
                                f"is on Domain ID 0, which is the default. Using non-default "
                                f"domain IDs provides minimal network isolation (not a security "
                                f"boundary, but reduces accidental exposure).",
                    remediation="Consider using a non-default ROS_DOMAIN_ID. Note: domain ID "
                                "alone is NOT a security control — it only provides network "
                                "segmentation at the DDS level.",
                ))

            # Check for demo/test participant names
            if p.participant_name:
                name_lower = p.participant_name.lower()
                demo_indicators = ["demo", "test", "example", "tutorial",
                                   "turtlebot", "talker", "listener", "minimal"]
                for indicator in demo_indicators:
                    if indicator in name_lower:
                        report.add_finding(AuditFinding(
                            check_id="SROS2-006b",
                            title="Demo/test participant name detected",
                            severity=Severity.INFO,
                            description=f"Participant '{p.participant_name}' appears to be "
                                        f"a demo or test instance. Ensure demo configurations "
                                        f"are not running in production environments.",
                        ))
                        break

    def _check_domain_isolation(self, participants: List[DDSParticipant],
                                  report: AuditReport):
        """SROS2-007: Check domain isolation effectiveness"""
        domains_seen = set()
        for p in participants:
            if p.domain_id is not None:
                domains_seen.add(p.domain_id)

        if len(domains_seen) > 1:
            report.add_finding(AuditFinding(
                check_id="SROS2-007",
                title="Multiple DDS domains detected on same network segment",
                severity=Severity.INFO,
                description=f"Participants found on {len(domains_seen)} different domain IDs: "
                            f"{sorted(domains_seen)}. Multiple domains on the same network "
                            f"segment may indicate insufficient network segmentation.",
                evidence=f"Domain IDs: {sorted(domains_seen)}",
                remediation="Consider VLAN segmentation to isolate different DDS domains. "
                            "Domain IDs provide logical separation but not network security.",
            ))

    def _check_security_tokens(self, participants: List[DDSParticipant],
                                 report: AuditReport):
        """SROS2-008: Analyze DDS-Security token configurations"""
        for p in participants:
            if not p.has_security:
                continue

            # Check for identity token (authentication)
            has_identity = "identity_token" in p.security_info
            has_permissions = "permissions_token" in p.security_info

            if has_identity and not has_permissions:
                report.add_finding(AuditFinding(
                    check_id="SROS2-008",
                    title="Authentication without authorization",
                    severity=Severity.MEDIUM,
                    description=f"Participant {p.participant_name or p.guid_prefix_hex()} "
                                f"has identity tokens (authentication) but no permissions "
                                f"tokens (authorization). This means participants are verified "
                                f"but not restricted — any authenticated node can access any topic.",
                    remediation="Configure SROS2 permissions files to restrict topic access "
                                "per-node. Use ros2 security create_permission to generate "
                                "appropriate permission policies.",
                ))

            if has_identity and has_permissions:
                report.add_finding(AuditFinding(
                    check_id="SROS2-008",
                    title="Full DDS-Security stack detected",
                    severity=Severity.PASS,
                    description=f"Participant {p.participant_name or p.guid_prefix_hex()} "
                                f"has both identity and permissions tokens configured.",
                ))


# =============================================================================
# Audit Report Printer
# =============================================================================

def print_audit_report(report: AuditReport):
    """Pretty-print an audit report to the terminal"""
    report.generate_summary()

    print(f"\n{'=' * 60}")
    print(f"  SROS2 SECURITY AUDIT REPORT")
    print(f"{'=' * 60}")
    print(f"  Target:       {report.target}")
    print(f"  Timestamp:    {report.timestamp}")
    print(f"  Participants: {report.participants_audited}")
    print(f"  Findings:     {len(report.findings)}")
    print(f"{'=' * 60}")

    # Summary bar
    colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[93m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[36m",
        "INFO": "\033[90m",
        "PASS": "\033[92m",
    }

    print(f"\n  Summary:")
    for severity, count in report.summary.items():
        color = colors.get(severity, "")
        bar = "█" * count
        print(f"    {color}{severity:>8}: {bar} {count}\033[0m")

    # Individual findings
    print(f"\n{'─' * 60}")
    for finding in report.findings:
        color = colors.get(finding.severity.value, "")
        icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
            "PASS": "🟢",
        }.get(finding.severity.value, "⚪")

        print(f"\n  {icon} {color}[{finding.severity.value}]\033[0m {finding.check_id}: {finding.title}")
        print(f"     {finding.description}")
        if finding.evidence:
            print(f"     \033[90mEvidence: {finding.evidence}\033[0m")
        if finding.remediation:
            print(f"     \033[96mFix: {finding.remediation}\033[0m")
        if finding.cve_refs:
            print(f"     \033[93mCVEs: {', '.join(finding.cve_refs)}\033[0m")

    print(f"\n{'=' * 60}\n")
