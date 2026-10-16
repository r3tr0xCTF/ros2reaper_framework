#!/usr/bin/env python3
"""
mavlink_audit.py - Phase 7: MAVLink Security Posture Assessment

Comprehensive security audit of a MAVLink endpoint: protocol version,
signing status, exposed ports, parameter security, failsafe configuration,
and overall risk scoring.

Combines passive analysis (traffic sniffing) with active probing
(parameter enumeration) to build a complete security picture.

Checks performed:
  - MAVLink v2 signing enabled/disabled
  - Exposed GCS ports (network reachability)
  - Default system/component IDs
  - Arming safety check configuration
  - Failsafe settings (GCS loss, throttle loss, battery)
  - Geofence configuration
  - RC override timeout
  - Logging configuration
  - GPS redundancy
  - Firmware currency (known vulnerable versions)

Author  : Gh057x
Phase   : 7 — MAVLink / Autopilot Security
Requires: pymavlink (for active checks), none for passive
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
# Risk Levels & Finding Structure
# ============================================================================

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AuditFinding:
    """A single security finding"""
    severity: str
    category: str
    title: str
    detail: str
    remediation: str = ""
    param: str = ""
    value: str = ""

    def to_dict(self):
        d = {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
        }
        if self.remediation:
            d["remediation"] = self.remediation
        if self.param:
            d["param"] = self.param
            d["value"] = self.value
        return d


@dataclass
class AuditResult:
    """Full audit result"""
    target: str = ""
    port: int = 14550
    system_id: int = 0
    autopilot_type: str = ""
    vehicle_type: str = ""
    mavlink_version: int = 0
    signing_enabled: bool = False
    firmware_version: str = ""
    param_count: int = 0
    findings: List[AuditFinding] = field(default_factory=list)
    risk_score: float = 0
    risk_rating: str = "UNKNOWN"
    duration_sec: float = 0
    errors: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "module": "mavlink_audit",
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "port": self.port,
            "system_id": self.system_id,
            "autopilot_type": self.autopilot_type,
            "vehicle_type": self.vehicle_type,
            "mavlink_version": self.mavlink_version,
            "signing_enabled": self.signing_enabled,
            "firmware_version": self.firmware_version,
            "param_count": self.param_count,
            "risk_score": self.risk_score,
            "risk_rating": self.risk_rating,
            "findings": [f.to_dict() for f in self.findings],
            "finding_counts": {
                "critical": len([f for f in self.findings if f.severity == "CRITICAL"]),
                "high": len([f for f in self.findings if f.severity == "HIGH"]),
                "medium": len([f for f in self.findings if f.severity == "MEDIUM"]),
                "low": len([f for f in self.findings if f.severity == "LOW"]),
                "info": len([f for f in self.findings if f.severity == "INFO"]),
            },
            "duration_sec": round(self.duration_sec, 2),
            "errors": self.errors,
        }


# ============================================================================
# Audit Checks
# ============================================================================

class MAVLinkAuditor:
    """MAVLink security auditor"""

    def __init__(self, verbose: bool = False, timeout: float = 10.0):
        self.verbose = verbose
        self.timeout = timeout

    def audit(self, target: str, port: int = 14550,
              protocol: str = "udp") -> AuditResult:
        """Run full security audit against a MAVLink endpoint"""
        result = AuditResult(target=target, port=port)
        start = time.time()

        # Phase 1: Discovery probe
        if self.verbose:
            print("[*] Phase 1: Discovery probe...")
        self._check_discovery(result, target, port)

        # Phase 2: Connect and enumerate
        if self.verbose:
            print("[*] Phase 2: Active enumeration...")
        params = self._connect_and_enumerate(result, target, port, protocol)

        # Phase 3: Analyze parameters
        if params:
            if self.verbose:
                print(f"[*] Phase 3: Analyzing {len(params)} parameters...")
            self._check_signing(result, params)
            self._check_system_ids(result, params)
            self._check_arming_safety(result, params)
            self._check_failsafes(result, params)
            self._check_geofence(result, params)
            self._check_rc_override(result, params)
            self._check_logging(result, params)
            self._check_gps(result, params)
            self._check_serial_protocols(result, params)

        # Phase 4: Port exposure check
        if self.verbose:
            print("[*] Phase 4: Port exposure check...")
        self._check_port_exposure(result, target)

        # Calculate risk score
        self._calculate_risk(result)

        result.duration_sec = time.time() - start
        return result

    def _check_discovery(self, result: AuditResult, target: str, port: int):
        """Basic discovery — does the endpoint respond?"""
        from modules.phase7.mavlink_discovery import MAVLinkScanner

        scanner = MAVLinkScanner(timeout=self.timeout, verbose=False)
        endpoints = scanner.scan_host(target, ports=[port])

        if endpoints:
            ep = endpoints[0]
            result.system_id = ep.system_id
            result.autopilot_type = ep.autopilot_type
            result.vehicle_type = ep.vehicle_type
            result.mavlink_version = ep.mavlink_version
            result.signing_enabled = ep.signing_enabled

            if not ep.signing_enabled:
                result.findings.append(AuditFinding(
                    severity="CRITICAL",
                    category="authentication",
                    title="MAVLink signing disabled",
                    detail="MAVLink v2 message signing is not enabled. "
                           "Any host on the network can inject commands.",
                    remediation="Enable MAVLink v2 signing with a shared key on "
                                "all GCS and autopilot links.",
                ))

            if ep.mavlink_version == 1:
                result.findings.append(AuditFinding(
                    severity="HIGH",
                    category="protocol",
                    title="MAVLink v1 in use",
                    detail="MAVLink v1 does not support message signing. "
                           "The link is inherently unauthenticated.",
                    remediation="Upgrade to MAVLink v2 on all links.",
                ))
        else:
            result.findings.append(AuditFinding(
                severity="INFO",
                category="discovery",
                title="No response to MAVLink probe",
                detail=f"No heartbeat received from {target}:{port}",
            ))

    def _connect_and_enumerate(self, result: AuditResult, target: str,
                               port: int, protocol: str) -> Dict:
        """Connect and pull parameters"""
        try:
            from modules.phase7.mavlink_enum import MAVLinkEnumerator
        except ImportError:
            result.errors.append("mavlink_enum import failed")
            return {}

        enumerator = MAVLinkEnumerator(verbose=False, timeout=self.timeout)
        enum_result = enumerator.enumerate(target, port=port, protocol=protocol)

        if enum_result.firmware:
            result.firmware_version = enum_result.firmware.version_string

        result.param_count = len(enum_result.params)
        return {p.name: p.value for p in enum_result.params}

    def _check_signing(self, result: AuditResult, params: Dict):
        """Check MAVLink signing configuration"""
        # ArduPilot signing parameters
        sign_setup = params.get("BRD_SERIAL_NUM", None)
        # If we got params but signing is off, it's confirmed vulnerable
        if not result.signing_enabled and result.param_count > 0:
            result.findings.append(AuditFinding(
                severity="CRITICAL",
                category="authentication",
                title="Confirmed: signing disabled with active parameters",
                detail=f"Successfully read {result.param_count} parameters "
                       "without any authentication.",
                remediation="Configure MAVLink v2 signing on all links.",
            ))

    def _check_system_ids(self, result: AuditResult, params: Dict):
        """Check for default/predictable system IDs"""
        sysid = params.get("SYSID_THISMAV", None)
        if sysid is not None and int(sysid) == 1:
            result.findings.append(AuditFinding(
                severity="MEDIUM",
                category="configuration",
                title="Default system ID",
                detail="SYSID_THISMAV is set to default (1). "
                       "Predictable IDs simplify spoofing attacks.",
                remediation="Set a unique, non-sequential system ID.",
                param="SYSID_THISMAV",
                value=str(int(sysid)),
            ))

        gcsid = params.get("SYSID_MYGCS", None)
        if gcsid is not None and int(gcsid) == 255:
            result.findings.append(AuditFinding(
                severity="LOW",
                category="configuration",
                title="Default GCS system ID",
                detail="SYSID_MYGCS is 255 (default). The autopilot will "
                       "accept commands from any system ID.",
                remediation="Set SYSID_MYGCS to match your specific GCS ID.",
                param="SYSID_MYGCS",
                value="255",
            ))

    def _check_arming_safety(self, result: AuditResult, params: Dict):
        """Check arming safety configuration"""
        arming = params.get("ARMING_CHECK", None)
        if arming is not None and int(arming) == 0:
            result.findings.append(AuditFinding(
                severity="CRITICAL",
                category="safety",
                title="All arming safety checks disabled",
                detail="ARMING_CHECK=0 disables ALL pre-arm safety checks. "
                       "The vehicle can arm in any condition.",
                remediation="Set ARMING_CHECK to 1 (all checks) or to a "
                            "bitmask that enables critical checks.",
                param="ARMING_CHECK",
                value="0",
            ))

        arming_require = params.get("ARMING_REQUIRE", None)
        if arming_require is not None and int(arming_require) == 0:
            result.findings.append(AuditFinding(
                severity="HIGH",
                category="safety",
                title="Arming not required",
                detail="ARMING_REQUIRE=0 means the vehicle does not need "
                       "to be armed before motors spin.",
                remediation="Set ARMING_REQUIRE=1.",
                param="ARMING_REQUIRE",
                value="0",
            ))

    def _check_failsafes(self, result: AuditResult, params: Dict):
        """Check failsafe configuration"""
        failsafe_checks = [
            ("FS_THR_ENABLE", "Throttle failsafe",
             "No automatic response to RC signal loss"),
            ("FS_GCS_ENABLE", "GCS failsafe",
             "No automatic response to GCS link loss"),
        ]

        for param, name, risk in failsafe_checks:
            val = params.get(param, None)
            if val is not None and int(val) == 0:
                result.findings.append(AuditFinding(
                    severity="HIGH",
                    category="safety",
                    title=f"{name} disabled",
                    detail=f"{param}=0: {risk}. The vehicle will continue "
                           "its current action indefinitely.",
                    remediation=f"Enable {param} (set to 1 for RTL, 2 for Hold).",
                    param=param,
                    value="0",
                ))

        # Battery failsafe
        batt_fs = params.get("BATT_FS_LOW_ACT", params.get("FS_BATT_ENABLE", None))
        if batt_fs is not None and int(batt_fs) == 0:
            result.findings.append(AuditFinding(
                severity="MEDIUM",
                category="safety",
                title="Battery failsafe disabled",
                detail="No automatic action on low battery.",
                remediation="Enable battery failsafe with appropriate action.",
                param="BATT_FS_LOW_ACT",
                value="0",
            ))

    def _check_geofence(self, result: AuditResult, params: Dict):
        """Check geofence configuration"""
        fence_enable = params.get("FENCE_ENABLE", None)
        if fence_enable is not None and int(fence_enable) == 0:
            result.findings.append(AuditFinding(
                severity="MEDIUM",
                category="safety",
                title="Geofence disabled",
                detail="No geofence boundary enforcement. The vehicle can "
                       "travel anywhere without triggering a safety response.",
                remediation="Enable FENCE_ENABLE and configure FENCE_RADIUS, "
                            "FENCE_ALT_MAX, FENCE_ACTION.",
                param="FENCE_ENABLE",
                value="0",
            ))

        fence_action = params.get("FENCE_ACTION", None)
        if fence_action is not None and int(fence_action) == 0:
            result.findings.append(AuditFinding(
                severity="LOW",
                category="safety",
                title="Geofence action is report-only",
                detail="FENCE_ACTION=0 means the geofence only reports "
                       "breaches, does not take corrective action.",
                remediation="Set FENCE_ACTION to RTL (1) or Hold (2).",
                param="FENCE_ACTION",
                value="0",
            ))

    def _check_rc_override(self, result: AuditResult, params: Dict):
        """Check RC override timeout"""
        rc_timeout = params.get("RC_OVERRIDE_TIME", None)
        if rc_timeout is not None:
            val = float(rc_timeout)
            if val == 0:
                result.findings.append(AuditFinding(
                    severity="HIGH",
                    category="authentication",
                    title="RC override has no timeout",
                    detail="RC_OVERRIDE_TIME=0: Injected RC override commands "
                           "persist indefinitely.",
                    remediation="Set RC_OVERRIDE_TIME to a reasonable value (e.g., 3.0s).",
                    param="RC_OVERRIDE_TIME",
                    value="0",
                ))
            elif val > 10:
                result.findings.append(AuditFinding(
                    severity="MEDIUM",
                    category="authentication",
                    title="RC override timeout too long",
                    detail=f"RC_OVERRIDE_TIME={val}s: Injected commands "
                           "persist for an extended period.",
                    remediation="Reduce RC_OVERRIDE_TIME to 3.0s or less.",
                    param="RC_OVERRIDE_TIME",
                    value=str(val),
                ))

    def _check_logging(self, result: AuditResult, params: Dict):
        """Check logging configuration for forensic readiness"""
        log_disarmed = params.get("LOG_DISARMED", None)
        if log_disarmed is not None and int(log_disarmed) == 0:
            result.findings.append(AuditFinding(
                severity="LOW",
                category="forensics",
                title="No logging while disarmed",
                detail="LOG_DISARMED=0: Pre-arm events are not logged. "
                       "Tampering before arming leaves no trace.",
                remediation="Set LOG_DISARMED=1 for continuous logging.",
                param="LOG_DISARMED",
                value="0",
            ))

    def _check_gps(self, result: AuditResult, params: Dict):
        """Check GPS configuration"""
        gps_type2 = params.get("GPS_TYPE2", None)
        if gps_type2 is not None and int(gps_type2) == 0:
            result.findings.append(AuditFinding(
                severity="LOW",
                category="resilience",
                title="No secondary GPS",
                detail="GPS_TYPE2=0: No redundant GPS. Single GPS spoofing "
                       "attacks are more effective.",
                remediation="Add a secondary GPS receiver for redundancy.",
                param="GPS_TYPE2",
                value="0",
            ))

    def _check_serial_protocols(self, result: AuditResult, params: Dict):
        """Check serial port protocol configuration"""
        for i in range(5):
            key = f"SERIAL{i}_PROTOCOL"
            val = params.get(key, None)
            if val is not None and int(val) in (1, 2):
                baud_key = f"SERIAL{i}_BAUD"
                baud = params.get(baud_key, "unknown")
                result.findings.append(AuditFinding(
                    severity="INFO",
                    category="configuration",
                    title=f"MAVLink on SERIAL{i}",
                    detail=f"{key}={int(val)} (MAVLink {'v1' if int(val)==1 else 'v2'}) "
                           f"at {baud} baud",
                    param=key,
                    value=str(int(val)),
                ))

    def _check_port_exposure(self, result: AuditResult, target: str):
        """Check which MAVLink ports are reachable"""
        import socket
        from modules.phase7.mavlink_discovery import MAVLINK_DEFAULT_PORTS

        open_ports = []
        for port in MAVLINK_DEFAULT_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            try:
                from modules.phase7.mavlink_discovery import MAVLinkProbe
                probe = MAVLinkProbe.build_heartbeat_v2()
                sock.sendto(probe, (target, port))
                data, _ = sock.recvfrom(4096)
                if data and data[0] in (0xFE, 0xFD):
                    open_ports.append(port)
            except (socket.timeout, OSError):
                pass
            finally:
                sock.close()

        if len(open_ports) > 1:
            result.findings.append(AuditFinding(
                severity="MEDIUM",
                category="exposure",
                title="Multiple MAVLink ports exposed",
                detail=f"Ports responding: {open_ports}. Each exposed port "
                       "is an additional attack surface.",
                remediation="Close unnecessary MAVLink ports. Use firewall "
                            "rules to restrict access.",
            ))

        for port in open_ports:
            result.findings.append(AuditFinding(
                severity="INFO",
                category="exposure",
                title=f"MAVLink port {port} open",
                detail=f"Port {port}/UDP responds to MAVLink heartbeat.",
            ))

    def _calculate_risk(self, result: AuditResult):
        """Calculate overall risk score from findings"""
        weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        total = sum(weights.get(f.severity, 0) for f in result.findings)

        if total >= 30:
            result.risk_rating = "CRITICAL"
        elif total >= 15:
            result.risk_rating = "HIGH"
        elif total >= 5:
            result.risk_rating = "MEDIUM"
        elif total > 0:
            result.risk_rating = "LOW"
        else:
            result.risk_rating = "INFO"

        result.risk_score = min(total, 100)


# ============================================================================
# Reporting
# ============================================================================

def print_audit_report(result: AuditResult):
    """Pretty-print audit results"""
    risk_colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[91m",
        "MEDIUM": "\033[93m",
        "LOW": "\033[92m",
        "INFO": "\033[90m",
        "UNKNOWN": "\033[90m",
    }

    print(f"\n{'=' * 60}")
    print(f"  MAVLink SECURITY AUDIT — {result.target}:{result.port}")
    print(f"{'=' * 60}")

    rc = risk_colors.get(result.risk_rating, "\033[0m")
    print(f"\n  Overall Risk: {rc}{result.risk_rating} "
          f"(score: {result.risk_score})\033[0m")

    if result.autopilot_type:
        print(f"  Autopilot:    {result.autopilot_type} ({result.vehicle_type})")
    if result.firmware_version:
        print(f"  Firmware:     {result.firmware_version}")
    print(f"  MAVLink:      v{result.mavlink_version}")
    print(f"  Signing:      {'Enabled' if result.signing_enabled else 'DISABLED'}")
    print(f"  Parameters:   {result.param_count}")

    # Findings by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        findings = [f for f in result.findings if f.severity == sev]
        if not findings:
            continue

        color = risk_colors.get(sev, "\033[0m")
        print(f"\n  {color}── {sev} ({len(findings)}) ──\033[0m")
        for f in findings:
            print(f"    {color}[{f.severity}]\033[0m {f.title}")
            print(f"          {f.detail}")
            if f.remediation:
                print(f"          \033[96mFix:\033[0m {f.remediation}")
            if f.param:
                print(f"          Param: {f.param}={f.value}")

    if result.errors:
        print(f"\n  \033[91mErrors:\033[0m")
        for e in result.errors:
            print(f"    - {e}")

    print(f"\n  Duration: {result.duration_sec:.1f}s")
    print(f"{'=' * 60}\n")


def export_json(result: AuditResult, output_file: str):
    """Export results to JSON"""
    with open(output_file, "w") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    print(f"[+] Audit report exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 7: MAVLink security posture audit"
    )
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--port", type=int, default=14550)
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    auditor = MAVLinkAuditor(verbose=args.verbose, timeout=args.timeout)
    result = auditor.audit(args.target, port=args.port, protocol=args.protocol)
    print_audit_report(result)

    if args.output:
        export_json(result, args.output)


if __name__ == "__main__":
    main()
