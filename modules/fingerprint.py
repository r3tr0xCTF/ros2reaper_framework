#!/usr/bin/env python3
"""
fingerprint.py - DDS Implementation Fingerprinting
====================================================
Identifies the specific DDS vendor, version, and configuration of
discovered participants. Goes beyond vendor ID to active fingerprinting.

Techniques:
1. Vendor ID from RTPS header (passive, reliable)
2. SPDP parameter analysis (property lists, builtin endpoints)
3. Behavioral probing (QoS defaults, response patterns, timing)
4. Version extraction from properties and participant names

Author: Gh057x
"""

import time
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from core.rtps_parser import (
    DDSParticipant, VendorId, VENDOR_NAMES, DDSPortCalculator,
)
from core.rtps_scanner import RTPSScanner


# =============================================================================
# Fingerprint Signatures
# =============================================================================

@dataclass
class DDSFingerprint:
    """Complete fingerprint of a DDS participant"""
    guid_prefix: str
    vendor_id: int
    vendor_name: str
    vendor_version: Optional[str] = None
    ros2_distro: Optional[str] = None
    ros2_node_name: Optional[str] = None
    rmw_implementation: Optional[str] = None
    dds_security_enabled: bool = False
    sros2_enabled: bool = False
    os_hint: Optional[str] = None
    deployment_type: Optional[str] = None  # "ros2", "standalone_dds", "ics"
    confidence: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    risk_factors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        result = {
            "guid_prefix": self.guid_prefix,
            "vendor_id": f"0x{self.vendor_id:04X}",
            "vendor_name": self.vendor_name,
            "vendor_version": self.vendor_version,
            "rmw_implementation": self.rmw_implementation,
            "ros2_distro": self.ros2_distro,
            "ros2_node_name": self.ros2_node_name,
            "dds_security_enabled": self.dds_security_enabled,
            "sros2_enabled": self.sros2_enabled,
            "os_hint": self.os_hint,
            "deployment_type": self.deployment_type,
            "confidence": round(self.confidence, 2),
            "risk_factors": self.risk_factors,
            "details": self.details,
        }
        return {k: v for k, v in result.items() if v is not None and v != []}


# Known property keys that reveal DDS implementation details
KNOWN_PROPERTIES = {
    # Fast DDS
    "dds.participant.process_name":   "fastdds_process",
    "fastdds.application.metadata":   "fastdds_metadata",
    "fastdds.physical_data.host":     "fastdds_host",
    "fastdds.physical_data.user":     "fastdds_user",
    "fastdds.physical_data.process":  "fastdds_process_name",
    # Cyclone DDS
    "__Process_Name":                 "cyclone_process",
    "__Hostname":                     "cyclone_hostname",
    "__Pid":                          "cyclone_pid",
    # Connext
    "rti.participant.process_name":   "connext_process",
    "rti.participant.host_name":      "connext_hostname",
    # ROS 2 specific
    "ros.distro":                     "ros2_distro",
    "ros.version":                    "ros2_version",
    "enclave":                        "ros2_enclave",
    # DDS-Security
    "dds.sec.auth.identity_ca":       "security_identity_ca",
    "dds.sec.access.governance":      "security_governance",
    "dds.sec.access.permissions":     "security_permissions",
}

# Builtin endpoint bitmask patterns per vendor
BUILTIN_ENDPOINT_PATTERNS = {
    # Fast DDS typically sets all standard + extended endpoints
    0x00003F3F: {"vendor_hint": "fastdds", "note": "Standard + extended builtin endpoints"},
    0x0000003F: {"vendor_hint": "generic", "note": "Standard builtin endpoints only"},
    # Cyclone DDS patterns
    0x00000E3F: {"vendor_hint": "cyclone", "note": "Cyclone typical endpoint set"},
}

# ROS 2 participant name patterns
ROS2_NAME_PATTERNS = [
    # Format: /<namespace>/<node_name>
    re.compile(r"^/[\w/]+$"),
    # Common ROS 2 system nodes
    re.compile(r".*ros2.*", re.IGNORECASE),
    re.compile(r".*robot_state_publisher.*"),
    re.compile(r".*joint_state.*"),
    re.compile(r".*tf2.*"),
    re.compile(r".*move_base.*"),
    re.compile(r".*nav2.*"),
    re.compile(r".*slam.*", re.IGNORECASE),
    re.compile(r".*turtlebot.*", re.IGNORECASE),
    re.compile(r".*gazebo.*", re.IGNORECASE),
    re.compile(r".*rviz.*", re.IGNORECASE),
]


# =============================================================================
# Fingerprinter
# =============================================================================

class DDSFingerprinter:
    """
    Performs deep fingerprinting of DDS participants.
    
    Takes discovered DDSParticipant objects and extracts maximum
    intelligence about the implementation, configuration, and
    security posture.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def fingerprint(self, participant: DDSParticipant) -> DDSFingerprint:
        """
        Generate a complete fingerprint for a DDS participant.
        
        Combines passive analysis (from discovery data already collected)
        with active probing results if available.
        """
        fp = DDSFingerprint(
            guid_prefix=participant.guid_prefix_hex(),
            vendor_id=participant.vendor_id,
            vendor_name=participant.vendor_name,
        )

        # Layer 1: Vendor ID analysis (most reliable)
        self._analyze_vendor_id(participant, fp)

        # Layer 2: Property list analysis
        self._analyze_properties(participant, fp)

        # Layer 3: Participant name analysis
        self._analyze_participant_name(participant, fp)

        # Layer 4: Security posture analysis
        self._analyze_security(participant, fp)

        # Layer 5: Builtin endpoint analysis
        self._analyze_builtin_endpoints(participant, fp)

        # Layer 6: Locator analysis (network exposure)
        self._analyze_locators(participant, fp)

        # Layer 7: GUID prefix pattern analysis
        self._analyze_guid_pattern(participant, fp)

        # Calculate overall confidence
        self._calculate_confidence(fp)

        # Generate risk assessment
        self._assess_risk(fp)

        return fp

    def fingerprint_all(self, participants: List[DDSParticipant]) -> List[DDSFingerprint]:
        """Fingerprint all discovered participants"""
        return [self.fingerprint(p) for p in participants]

    # ----- Analysis Layers -----

    def _analyze_vendor_id(self, participant: DDSParticipant, fp: DDSFingerprint):
        """Layer 1: Extract info from vendor ID"""
        vid = participant.vendor_id

        if vid == VendorId.EPROSIMA_FAST:
            fp.details["dds_implementation"] = "eProsima Fast DDS"
            fp.details["likely_rmw"] = "rmw_fastrtps_cpp"
            fp.rmw_implementation = "rmw_fastrtps_cpp"
        elif vid == VendorId.ECLIPSE_CYCLONE:
            fp.details["dds_implementation"] = "Eclipse Cyclone DDS"
            fp.details["likely_rmw"] = "rmw_cyclonedds_cpp"
            fp.rmw_implementation = "rmw_cyclonedds_cpp"
        elif vid == VendorId.RTI_CONNEXT:
            fp.details["dds_implementation"] = "RTI Connext DDS"
            fp.details["likely_rmw"] = "rmw_connextdds"
            fp.rmw_implementation = "rmw_connextdds"
        elif vid == VendorId.OCI_OPENDDS:
            fp.details["dds_implementation"] = "OCI OpenDDS"
        elif vid == VendorId.GURUM_DDS:
            fp.details["dds_implementation"] = "GurumNetworks GurumDDS"

    def _analyze_properties(self, participant: DDSParticipant, fp: DDSFingerprint):
        """Layer 2: Extract info from DDS property lists"""
        props = participant.properties

        if not props:
            fp.details["properties_available"] = False
            return

        fp.details["properties_available"] = True
        fp.details["raw_properties"] = dict(props)

        for key, value in props.items():
            # ROS 2 distro detection
            if key == "ros.distro" or key.endswith("ros.distro"):
                fp.ros2_distro = value
                fp.deployment_type = "ros2"

            # ROS 2 version
            elif key == "ros.version":
                fp.details["ros2_version"] = value
                fp.deployment_type = "ros2"

            # ROS 2 security enclave
            elif key == "enclave":
                fp.details["ros2_enclave"] = value
                if value and value != "/":
                    fp.sros2_enabled = True

            # Fast DDS host info
            elif key == "fastdds.physical_data.host":
                fp.os_hint = value
                fp.details["hostname"] = value

            elif key == "fastdds.physical_data.user":
                fp.details["username"] = value

            elif key == "fastdds.physical_data.process":
                fp.details["process_name"] = value

            # Cyclone DDS host info
            elif key == "__Hostname":
                fp.os_hint = value
                fp.details["hostname"] = value

            elif key == "__Process_Name":
                fp.details["process_name"] = value

            elif key == "__Pid":
                fp.details["process_id"] = value

            # DDS-Security credential paths
            elif "dds.sec" in key:
                fp.dds_security_enabled = True
                fp.details.setdefault("security_config", {})[key] = value

    def _analyze_participant_name(self, participant: DDSParticipant, fp: DDSFingerprint):
        """Layer 3: Extract info from participant name"""
        name = participant.participant_name
        if not name:
            return

        fp.details["participant_name"] = name

        # Check if it matches ROS 2 naming patterns
        for pattern in ROS2_NAME_PATTERNS:
            if pattern.match(name):
                fp.deployment_type = "ros2"
                fp.ros2_node_name = name
                break

        # Check for ROS 2 namespace patterns (/<namespace>/<node>)
        if name.startswith("/") and "/" in name[1:]:
            parts = name.strip("/").split("/")
            if len(parts) >= 2:
                fp.details["ros2_namespace"] = "/" + "/".join(parts[:-1])
                fp.details["ros2_node"] = parts[-1]
                fp.deployment_type = "ros2"

        # Check for common robot platform names
        robot_indicators = [
            "turtlebot", "ur5", "ur10", "franka", "fetch", "pepper",
            "nao", "spot", "jackal", "husky", "clearpath", "mir",
            "kuka", "abb", "fanuc", "yaskawa", "omron",
        ]
        name_lower = name.lower()
        for indicator in robot_indicators:
            if indicator in name_lower:
                fp.details["robot_platform_hint"] = indicator
                break

    def _analyze_security(self, participant: DDSParticipant, fp: DDSFingerprint):
        """Layer 4: Analyze DDS-Security posture"""
        if participant.has_security:
            fp.dds_security_enabled = True
            fp.details["security_tokens"] = participant.security_info

            # Check for identity token (authentication)
            if "identity_token" in participant.security_info:
                fp.details["has_authentication"] = True

            # Check for permissions token (authorization)
            if "permissions_token" in participant.security_info:
                fp.details["has_authorization"] = True

            # Analyze security attributes bitmask
            sec_info = participant.security_info.get("participant_security_info", {})
            if isinstance(sec_info, dict) and "security_attributes" in sec_info:
                attrs = int(sec_info["security_attributes"], 16)
                fp.details["security_flags"] = {
                    "is_rtps_protected": bool(attrs & 0x01),
                    "is_discovery_protected": bool(attrs & 0x02),
                    "is_liveliness_protected": bool(attrs & 0x04),
                }
        else:
            fp.dds_security_enabled = False
            fp.details["security_assessment"] = "NO DDS-Security detected"

    def _analyze_builtin_endpoints(self, participant: DDSParticipant, fp: DDSFingerprint):
        """Layer 5: Analyze builtin endpoint bitmask"""
        bep = participant.builtin_endpoints
        if bep is None:
            return

        fp.details["builtin_endpoint_set"] = f"0x{bep:08X}"

        # Match against known patterns
        for pattern, info in BUILTIN_ENDPOINT_PATTERNS.items():
            if bep == pattern:
                fp.details["endpoint_pattern"] = info
                break

        # Decode individual endpoints
        endpoint_names = []
        if bep & 0x01: endpoint_names.append("DISC_BUILTIN_ENDPOINT_PARTICIPANT_ANNOUNCER")
        if bep & 0x02: endpoint_names.append("DISC_BUILTIN_ENDPOINT_PARTICIPANT_DETECTOR")
        if bep & 0x04: endpoint_names.append("DISC_BUILTIN_ENDPOINT_PUBLICATION_ANNOUNCER")
        if bep & 0x08: endpoint_names.append("DISC_BUILTIN_ENDPOINT_PUBLICATION_DETECTOR")
        if bep & 0x10: endpoint_names.append("DISC_BUILTIN_ENDPOINT_SUBSCRIPTION_ANNOUNCER")
        if bep & 0x20: endpoint_names.append("DISC_BUILTIN_ENDPOINT_SUBSCRIPTION_DETECTOR")
        fp.details["active_builtin_endpoints"] = endpoint_names

    def _analyze_locators(self, participant: DDSParticipant, fp: DDSFingerprint):
        """Layer 6: Analyze network locators for exposure assessment"""
        all_locators = (
            participant.unicast_locators +
            participant.multicast_locators +
            participant.metatraffic_unicast +
            participant.metatraffic_multicast
        )

        if not all_locators:
            return

        unique_ips = set()
        private_ips = []
        public_ips = []

        for loc in all_locators:
            ip = loc.address
            unique_ips.add(ip)

            # Classify as private or public
            try:
                import ipaddress
                addr = ipaddress.ip_address(ip)
                if addr.is_private or addr.is_loopback:
                    private_ips.append(ip)
                elif not addr.is_multicast:
                    public_ips.append(ip)
            except ValueError:
                pass

        fp.details["network_exposure"] = {
            "unique_ips": list(unique_ips),
            "private_ips": list(set(private_ips)),
            "public_ips": list(set(public_ips)),
            "total_locators": len(all_locators),
        }

        # Leaked private IPs are a finding
        if private_ips and participant.source_ip:
            try:
                import ipaddress
                source = ipaddress.ip_address(participant.source_ip)
                for pip in private_ips:
                    priv = ipaddress.ip_address(pip)
                    if source.is_private and priv.is_private:
                        if priv != source:
                            fp.details.setdefault("leaked_internal_ips", []).append(pip)
            except ValueError:
                pass

    def _analyze_guid_pattern(self, participant: DDSParticipant, fp: DDSFingerprint):
        """Layer 7: GUID prefix patterns can reveal implementation details"""
        prefix = participant.guid_prefix

        # Fast DDS typically uses host ID + process ID in GUID prefix
        # Cyclone DDS uses a different pattern
        # This is implementation-specific and helps confirm vendor

        fp.details["guid_prefix_raw"] = prefix.hex(".")

    # ----- Scoring -----

    def _calculate_confidence(self, fp: DDSFingerprint):
        """Calculate overall fingerprint confidence score (0.0 - 1.0)"""
        score = 0.0
        max_score = 0.0

        # Vendor ID match (high confidence)
        max_score += 0.3
        if fp.vendor_id != VendorId.UNKNOWN:
            score += 0.3

        # Properties available
        max_score += 0.2
        if fp.details.get("properties_available"):
            score += 0.2

        # Version detected
        max_score += 0.15
        if fp.vendor_version:
            score += 0.15

        # Deployment type determined
        max_score += 0.15
        if fp.deployment_type:
            score += 0.15

        # Security posture determined
        max_score += 0.1
        score += 0.1  # We always determine this (present or not)

        # Hostname / OS detected
        max_score += 0.1
        if fp.os_hint:
            score += 0.1

        fp.confidence = score / max_score if max_score > 0 else 0.0

    def _assess_risk(self, fp: DDSFingerprint):
        """Generate risk factors based on fingerprint"""
        risks = []

        # No security
        if not fp.dds_security_enabled:
            risks.append("CRITICAL: No DDS-Security enabled — all traffic unencrypted and unauthenticated")

        # No SROS2 on ROS 2 deployment
        if fp.deployment_type == "ros2" and not fp.sros2_enabled:
            risks.append("HIGH: ROS 2 deployment without SROS2 — nodes can be impersonated")

        # Leaking internal IPs
        if fp.details.get("leaked_internal_ips"):
            ips = fp.details["leaked_internal_ips"]
            risks.append(f"MEDIUM: Leaking {len(ips)} internal IP address(es) via DDS locators")

        # Leaking hostname/username
        if fp.details.get("hostname"):
            risks.append(f"LOW: Hostname exposed via DDS properties: {fp.details['hostname']}")
        if fp.details.get("username"):
            risks.append(f"LOW: Username exposed via DDS properties: {fp.details['username']}")
        if fp.details.get("process_name"):
            risks.append(f"INFO: Process name exposed: {fp.details['process_name']}")

        # Public IP exposure
        net_exposure = fp.details.get("network_exposure", {})
        if net_exposure.get("public_ips"):
            risks.append(f"HIGH: DDS participant advertising public IP addresses")

        # Known vulnerable versions (placeholder for CVE database)
        # TODO: Cross-reference vendor_version against known CVEs

        fp.risk_factors = risks


# =============================================================================
# Summary Report Generator
# =============================================================================

def generate_fingerprint_report(fingerprints: List[DDSFingerprint]) -> Dict:
    """Generate a summary report from all fingerprints"""
    report = {
        "summary": {
            "total_participants": len(fingerprints),
            "vendors": {},
            "deployment_types": {},
            "security_posture": {
                "secured": 0,
                "unsecured": 0,
            },
            "risk_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        },
        "participants": [fp.to_dict() for fp in fingerprints],
    }

    for fp in fingerprints:
        # Count vendors
        vendor = fp.vendor_name
        report["summary"]["vendors"][vendor] = report["summary"]["vendors"].get(vendor, 0) + 1

        # Count deployment types
        dtype = fp.deployment_type or "unknown"
        report["summary"]["deployment_types"][dtype] = \
            report["summary"]["deployment_types"].get(dtype, 0) + 1

        # Security posture
        if fp.dds_security_enabled:
            report["summary"]["security_posture"]["secured"] += 1
        else:
            report["summary"]["security_posture"]["unsecured"] += 1

        # Risk counting
        for risk in fp.risk_factors:
            risk_upper = risk.upper()
            if risk_upper.startswith("CRITICAL"):
                report["summary"]["risk_summary"]["critical"] += 1
            elif risk_upper.startswith("HIGH"):
                report["summary"]["risk_summary"]["high"] += 1
            elif risk_upper.startswith("MEDIUM"):
                report["summary"]["risk_summary"]["medium"] += 1
            elif risk_upper.startswith("LOW"):
                report["summary"]["risk_summary"]["low"] += 1
            else:
                report["summary"]["risk_summary"]["info"] += 1

    return report
