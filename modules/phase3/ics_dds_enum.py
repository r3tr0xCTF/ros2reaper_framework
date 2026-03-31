#!/usr/bin/env python3
"""
ics_dds_enum.py — ICS/OT Context DDS Enumerator
=================================================
ROS2Reaper Phase 3 Module

Identifies and classifies DDS deployments operating in non-robotics ICS/OT
contexts: SCADA systems, air traffic control, autonomous vehicles, smart grid,
and industrial automation. Performs context-aware fingerprinting to determine
the likely operational domain of a discovered DDS participant.

Requires NO ROS 2 installation — pure Python, raw socket/RTPS protocol level.
Compatible with: Fast DDS, Cyclone DDS, RTI Connext, Twin Oaks CoreDX,
                 ADLINK OpenSplice, GurumDDS

Author  : Gh057x
Phase   : 3 — ICS/OT Bridge
Requires: scapy, shodan (optional), requests

Usage:
    python3 ics_dds_enum.py --target 192.168.1.0/24 --domain 0
    python3 ics_dds_enum.py --target 10.0.0.5 --passive --timeout 30
    python3 ics_dds_enum.py --target 10.0.0.5 --deep --protocols all
    python3 ics_dds_enum.py --cidr 10.52.32.0/24 --context scada
"""

import socket
import struct
import time
import threading
import json
import ipaddress
import argparse
import sys
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

# ─────────────────────────────────────────────────────────────────────────────
# ENUMS & CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

class ICSContext(Enum):
    """Operational domain classifications for DDS deployments."""
    SCADA          = "scada"
    AIR_TRAFFIC    = "atc"
    AUTOMOTIVE     = "automotive"
    SMART_GRID     = "smart_grid"
    MILITARY       = "military"
    MEDICAL        = "medical"
    INDUSTRIAL_IOT = "iiot"
    ROS2_ROBOTICS  = "ros2"       # Should not be here, but flag if mixed
    UNKNOWN        = "unknown"


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# DDS Vendor IDs (RTPS spec + known implementations)
DDS_VENDOR_IDS = {
    0x0101: ("RTI",             "RTI Connext DDS"),
    0x0102: ("PrismTech",       "OpenSplice DDS"),
    0x0103: ("OCI",             "OpenDDS"),
    0x0104: ("MilSoft",         "MilSoft DDS"),
    0x0105: ("Gallium",         "InterCOM DDS"),
    0x0106: ("TwinOaks",        "CoreDX DDS"),
    0x0107: ("Lakota",          "Lakota DDS"),
    0x0108: ("ICOUP",           "ICOUP DDS"),
    0x0109: ("ETRI",            "Diamond DDS"),
    0x010A: ("RTI",             "RTI Micro"),
    0x010C: ("PrismTech",       "Vortex Cafe"),
    0x010D: ("PrismTech",       "Vortex Lite"),
    0x010E: ("Technicolor",     "Qeo"),
    0x010F: ("eProsima",        "Fast DDS"),
    0x0110: ("ADLINK",          "Cyclone DDS"),
    0x0111: ("GurumNetworks",   "GurumDDS"),
    0x0120: ("Eclipse",         "Cyclone DDS (Eclipse)"),
}

# ICS sector context signatures — participant names, topic patterns, domain IDs
ICS_SIGNATURES = {
    ICSContext.SCADA: {
        "participant_patterns": [
            r"scada", r"historian", r"hmi", r"plc_", r"rtu_",
            r"supervisory", r"dnp3_bridge", r"opc_", r"modbus_bridge",
            r"field_device", r"control_room", r"ems_", r"dms_",
            r"substati", r"dispatch", r"alarm_server", r"trend_",
        ],
        "topic_patterns": [
            r"/analog_input", r"/digital_output", r"/setpoint",
            r"/alarm", r"/event", r"/measurement", r"/status",
            r"/control_cmd", r"/historian", r"/trend",
            r"process_value", r"engineering_unit",
        ],
        "domain_ids": [0, 1, 5, 100],
        "vendor_preference": ["RTI", "PrismTech", "TwinOaks"],
        "typical_ports": [7400, 7410, 7420],
        "risk_modifier": RiskLevel.CRITICAL,
    },
    ICSContext.AIR_TRAFFIC: {
        "participant_patterns": [
            r"atc_", r"radar_", r"flight_", r"track_", r"fms_",
            r"adsb", r"asterix", r"nav_aid", r"approach_",
            r"departure_", r"enroute_", r"tower_", r"eurocontrol",
            r"asterix_proc", r"flightplan", r"strip_", r"sdc_",
        ],
        "topic_patterns": [
            r"/track", r"/flight_plan", r"/radar_return",
            r"/adsb_msg", r"/asterix", r"/separation",
            r"/weather_", r"/notam", r"/metar",
        ],
        "domain_ids": [0, 1, 10, 50],
        "vendor_preference": ["RTI", "TwinOaks"],
        "typical_ports": [7400, 7410],
        "risk_modifier": RiskLevel.CRITICAL,
    },
    ICSContext.AUTOMOTIVE: {
        "participant_patterns": [
            r"autosar", r"vehicle_", r"ecu_", r"adas_", r"lidar_",
            r"camera_", r"radar_sensor", r"can_bridge", r"gateway_",
            r"veh_ctrl", r"powertrain", r"chassis_", r"body_ctrl",
            r"telematics", r"v2x_", r"perception_", r"planning_",
        ],
        "topic_patterns": [
            r"/vehicle/", r"/perception/", r"/planning/",
            r"/control/", r"/sensor/", r"/diagnostic/",
            r"/can_frame", r"/v2x_msg",
        ],
        "domain_ids": [0, 1, 2, 3],
        "vendor_preference": ["RTI", "ADLINK", "eProsima"],
        "typical_ports": [7400, 7410],
        "risk_modifier": RiskLevel.HIGH,
    },
    ICSContext.SMART_GRID: {
        "participant_patterns": [
            r"grid_", r"substation_", r"pmu_", r"synchrophasor",
            r"ied_", r"protection_", r"outage_", r"restoration_",
            r"volt_var", r"demand_response", r"ami_", r"meter_",
        ],
        "topic_patterns": [
            r"/phasor", r"/synchrophasor", r"/voltage",
            r"/current", r"/frequency", r"/power_flow",
            r"/fault_", r"/protection",
        ],
        "domain_ids": [0, 1, 30],
        "vendor_preference": ["RTI", "PrismTech"],
        "typical_ports": [7400, 7410],
        "risk_modifier": RiskLevel.CRITICAL,
    },
    ICSContext.MILITARY: {
        "participant_patterns": [
            r"c2_", r"command_", r"tactical_", r"battlefield_",
            r"uav_", r"ugv_", r"sensor_fusion", r"link16",
            r"mils_", r"stanag_", r"nato_",
        ],
        "topic_patterns": [
            r"/track_report", r"/force_element", r"/mission_",
            r"/target_", r"/engagement_",
        ],
        "domain_ids": [0, 7, 100, 200],
        "vendor_preference": ["RTI", "MilSoft"],
        "typical_ports": [7400, 7410],
        "risk_modifier": RiskLevel.CRITICAL,
    },
    ICSContext.MEDICAL: {
        "participant_patterns": [
            r"icu_", r"patient_", r"vital_", r"monitor_",
            r"infusion_", r"ventilator_", r"imaging_",
            r"dicom_", r"hl7_bridge", r"alarm_mgmt",
        ],
        "topic_patterns": [
            r"/vital_signs", r"/ecg", r"/spo2",
            r"/blood_pressure", r"/alarm_condition",
        ],
        "domain_ids": [0, 1, 20],
        "vendor_preference": ["RTI", "PrismTech", "TwinOaks"],
        "typical_ports": [7400, 7410],
        "risk_modifier": RiskLevel.CRITICAL,
    },
}

# RTPS SPDP multicast group + discovery ports
RTPS_MULTICAST_GROUP = "239.255.0.1"
RTPS_HEADER_MAGIC    = b"RTPS"
RTPS_PROTOCOL_VER    = b"\x02\x02"

# DDS port formula: base 7400, offset by domain
def dds_discovery_port(domain_id: int) -> int:
    return 7400 + (250 * domain_id)

def dds_user_port(domain_id: int) -> int:
    return 7401 + (250 * domain_id)


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DDSParticipant:
    """Represents a discovered DDS participant on the network."""
    ip: str
    port: int
    domain_id: int
    guid_prefix: str             = ""
    vendor_id: int               = 0
    vendor_name: str             = ""
    vendor_product: str          = ""
    participant_name: str        = ""
    rtps_version: str            = ""
    topics_seen: list            = field(default_factory=list)
    properties: dict             = field(default_factory=dict)
    security_enabled: bool       = False
    ics_context: ICSContext      = ICSContext.UNKNOWN
    context_confidence: float    = 0.0
    context_evidence: list       = field(default_factory=list)
    risk_level: RiskLevel        = RiskLevel.INFO
    findings: list               = field(default_factory=list)
    first_seen: str              = field(default_factory=lambda: datetime.now().isoformat())
    raw_response: bytes          = field(default_factory=bytes, repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["ics_context"] = self.ics_context.value
        d["risk_level"]  = self.risk_level.value
        d["raw_response"] = self.raw_response.hex() if self.raw_response else ""
        return d


@dataclass
class ICSBridgeResult:
    """Aggregated result of an ICS DDS enumeration run."""
    scan_target: str
    scan_time: str               = field(default_factory=lambda: datetime.now().isoformat())
    domain_ids_scanned: list     = field(default_factory=list)
    participants: list           = field(default_factory=list)
    context_summary: dict        = field(default_factory=dict)
    critical_findings: list      = field(default_factory=list)
    protocol_coexistence: dict   = field(default_factory=dict)  # DDS+OPC UA etc.


# ─────────────────────────────────────────────────────────────────────────────
# RTPS PACKET BUILDER
# ─────────────────────────────────────────────────────────────────────────────

class RTPSProbeBuilder:
    """Builds minimal valid RTPS SPDP discovery packets for active probing."""

    VENDOR_ID = b"\x01\x0f"   # Pose as eProsima Fast DDS

    @staticmethod
    def guid_prefix() -> bytes:
        """Generate a plausible GUID prefix."""
        import random
        return bytes([random.randint(0, 255) for _ in range(12)])

    @classmethod
    def build_spdp_announcement(cls, domain_id: int = 0) -> bytes:
        """
        Build an RTPS SPDP participant announcement packet.
        This is the standard DDS discovery hello — not malicious,
        just participates in the discovery protocol to elicit responses.
        """
        guid_prefix = cls.guid_prefix()

        # RTPS Header
        header = (
            RTPS_HEADER_MAGIC +           # Protocol identifier
            RTPS_PROTOCOL_VER  +          # RTPS version 2.2
            cls.VENDOR_ID      +          # Vendor ID (Fast DDS)
            guid_prefix                   # 12-byte GUID prefix
        )

        # INFO_TS submessage — current timestamp
        ts_sec  = int(time.time())
        ts_frac = 0
        info_ts = struct.pack(
            "<BBHll",
            0x09,   # submessageId: INFO_TS
            0x01,   # flags: little-endian
            8,      # octetsToNextHeader
            ts_sec,
            ts_frac,
        )

        # DATA submessage — minimal SPDP participant data
        # In production this would carry the full ParticipantData inline QoS
        # Here we send a minimal stub that still triggers participant responses
        entity_id_reader = b"\x00\x01\x00\xc2"   # SPDP builtin reader
        entity_id_writer = b"\x00\x01\x00\xc1"   # SPDP builtin writer
        seq_num = struct.pack("<ii", 0, 1)         # SequenceNumber 1

        data_payload = (
            b"\x00\x00" +          # extraFlags
            b"\x10\x00" +          # inlineQosOffset
            entity_id_reader +     # readerId
            entity_id_writer +     # writerId
            seq_num +              # writerSN
            # Inline QoS: PID_SENTINEL
            b"\x01\x00\x00\x00"
        )

        data_submsg = struct.pack(
            "<BBH",
            0x15,                    # submessageId: DATA
            0x05,                    # flags: LE + Data present
            len(data_payload),
        ) + data_payload

        return header + info_ts + data_submsg

    @classmethod
    def build_heartbeat_probe(cls) -> bytes:
        """Build a minimal HEARTBEAT to solicit ACKNACK responses."""
        guid_prefix = cls.guid_prefix()
        header = (
            RTPS_HEADER_MAGIC +
            RTPS_PROTOCOL_VER +
            cls.VENDOR_ID +
            guid_prefix
        )
        entity_id_reader = b"\x00\x00\x00\x00"
        entity_id_writer = b"\x00\x01\x00\xc1"
        heartbeat_payload = (
            entity_id_reader +
            entity_id_writer +
            struct.pack("<ii", 0, 1) +   # firstSN
            struct.pack("<ii", 0, 1) +   # lastSN
            struct.pack("<i", 1)         # count
        )
        hb_submsg = struct.pack(
            "<BBH",
            0x07,   # HEARTBEAT
            0x01,   # LE
            len(heartbeat_payload),
        ) + heartbeat_payload
        return header + hb_submsg


# ─────────────────────────────────────────────────────────────────────────────
# RTPS RESPONSE PARSER
# ─────────────────────────────────────────────────────────────────────────────

class RTPSResponseParser:
    """Parses raw RTPS UDP responses into structured DDSParticipant data."""

    SUBMSG_IDS = {
        0x01: "PAD",        0x06: "ACKNACK",   0x07: "HEARTBEAT",
        0x09: "INFO_TS",    0x0C: "INFO_SRC",  0x0D: "INFO_REPLY_IP4",
        0x0E: "INFO_DST",   0x0F: "INFO_REPLY", 0x12: "NACK_FRAG",
        0x13: "HEARTBEAT_FRAG", 0x15: "DATA",  0x16: "DATA_FRAG",
    }

    PARAM_IDS = {
        0x0002: "PID_PARTICIPANT_LEASE_DURATION",
        0x0015: "PID_PARTICIPANT_GUID",
        0x0016: "PID_GROUP_GUID",
        0x0031: "PID_BUILTIN_ENDPOINT_SET",
        0x0032: "PID_PARTICIPANT_MANUAL_LIVELINESS_COUNT",
        0x0040: "PID_METATRAFFIC_MULTICAST_LOCATOR",
        0x0041: "PID_METATRAFFIC_UNICAST_LOCATOR",
        0x0042: "PID_DEFAULT_UNICAST_LOCATOR",
        0x0043: "PID_DEFAULT_MULTICAST_LOCATOR",
        0x0050: "PID_PARTICIPANT_ENTITY_ID",
        0x0059: "PID_ENTITY_NAME",
        0x0062: "PID_PROPERTY_LIST",
        0x0070: "PID_USER_DATA",
        0x0077: "PID_IDENTITY_TOKEN",
        0x0078: "PID_PERMISSIONS_TOKEN",
        0x7FFF: "PID_SENTINEL",
    }

    @classmethod
    def parse(cls, data: bytes, src_ip: str, src_port: int) -> Optional[DDSParticipant]:
        """Parse an RTPS packet and return a DDSParticipant or None."""
        if len(data) < 20:
            return None
        if data[:4] != RTPS_HEADER_MAGIC:
            return None

        participant = DDSParticipant(
            ip=src_ip,
            port=src_port,
            domain_id=0,
            raw_response=data,
        )

        # RTPS Header
        major        = data[4]
        minor        = data[5]
        participant.rtps_version = f"{major}.{minor}"
        vendor_id    = struct.unpack(">H", data[6:8])[0]
        participant.guid_prefix  = data[8:20].hex(":")
        participant.vendor_id    = vendor_id

        if vendor_id in DDS_VENDOR_IDS:
            participant.vendor_name    = DDS_VENDOR_IDS[vendor_id][0]
            participant.vendor_product = DDS_VENDOR_IDS[vendor_id][1]

        # Parse submessages
        offset = 20
        while offset < len(data) - 4:
            submsg_id = data[offset]
            flags     = data[offset + 1]
            length    = struct.unpack_from("<H", data, offset + 2)[0]

            if length == 0:
                break

            submsg_data = data[offset + 4: offset + 4 + length]
            cls._parse_submessage(submsg_id, flags, submsg_data, participant)
            offset += 4 + length

        return participant

    @classmethod
    def _parse_submessage(cls, submsg_id: int, flags: int,
                           data: bytes, participant: DDSParticipant):
        """Dispatch submessage parsing."""
        if submsg_id == 0x15:   # DATA
            cls._parse_data_submsg(data, participant)

    @classmethod
    def _parse_data_submsg(cls, data: bytes, participant: DDSParticipant):
        """Extract participant name, properties, and security tokens from DATA."""
        if len(data) < 20:
            return

        # Skip extraFlags (2) + inlineQosOffset (2) + readerEntityId (4) +
        #      writerEntityId (4) + writerSN (8) = 20 bytes
        offset = 20

        while offset < len(data) - 4:
            pid    = struct.unpack_from("<H", data, offset)[0]
            plength = struct.unpack_from("<H", data, offset + 2)[0]

            if pid == 0x7FFF:   # PID_SENTINEL
                break

            param_data = data[offset + 4: offset + 4 + plength]

            if pid == 0x0059:   # PID_ENTITY_NAME
                try:
                    name_len = struct.unpack_from("<I", param_data, 0)[0]
                    participant.participant_name = param_data[4:4+name_len].decode(
                        "utf-8", errors="replace"
                    ).rstrip("\x00")
                except Exception:
                    pass

            elif pid == 0x0062:  # PID_PROPERTY_LIST
                cls._parse_property_list(param_data, participant)

            elif pid in (0x0077, 0x0078):  # Identity/Permissions token → DDS-Security
                participant.security_enabled = True

            elif pid == 0x0015:  # PID_PARTICIPANT_GUID
                if len(param_data) >= 4:
                    # Domain ID is encoded in the GUID prefix bytes 8-11
                    # (heuristic — not spec-mandated but common in Fast DDS/Cyclone)
                    participant.domain_id = param_data[8] if len(param_data) > 8 else 0

            offset += 4 + plength
            # Align to 4-byte boundary
            if plength % 4:
                offset += 4 - (plength % 4)

    @classmethod
    def _parse_property_list(cls, data: bytes, participant: DDSParticipant):
        """Parse the DDS property list for vendor/config metadata."""
        try:
            num_props = struct.unpack_from("<I", data, 0)[0]
            offset    = 4
            for _ in range(min(num_props, 64)):   # cap iterations
                if offset + 8 > len(data):
                    break
                key_len = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                if offset + key_len > len(data):
                    break
                key = data[offset:offset+key_len].decode("utf-8", errors="replace").rstrip("\x00")
                offset += key_len
                if offset + 4 > len(data):
                    break
                val_len = struct.unpack_from("<I", data, offset)[0]
                offset += 4
                if offset + val_len > len(data):
                    break
                val = data[offset:offset+val_len].decode("utf-8", errors="replace").rstrip("\x00")
                offset += val_len
                participant.properties[key] = val
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# ICS CONTEXT CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class ICSContextClassifier:
    """
    Classifies a DDS participant into an ICS/OT operational domain using
    multi-signal scoring: participant name, topic names, vendor choice,
    domain ID conventions, and property list contents.
    """

    def classify(self, participant: DDSParticipant) -> tuple[ICSContext, float, list]:
        """
        Returns (ICSContext, confidence_0_to_1, evidence_list).
        Scores each ICS context against available signals.
        """
        scores    = {}
        evidence  = {}

        for context, sigs in ICS_SIGNATURES.items():
            score = 0.0
            evs   = []

            # 1. Participant name matching
            pname = participant.participant_name.lower()
            for pattern in sigs["participant_patterns"]:
                if re.search(pattern, pname):
                    score += 0.35
                    evs.append(f"participant_name~/{pattern}/")

            # 2. Topic name matching
            for topic in participant.topics_seen:
                t = topic.lower()
                for pattern in sigs["topic_patterns"]:
                    if re.search(pattern, t):
                        score += 0.20
                        evs.append(f"topic:{topic}~/{pattern}/")

            # 3. Property list keys/values
            for k, v in participant.properties.items():
                combined = f"{k} {v}".lower()
                for pattern in sigs["participant_patterns"]:
                    if re.search(pattern, combined):
                        score += 0.15
                        evs.append(f"property:{k}={v}")

            # 4. Vendor preference alignment
            if participant.vendor_name in sigs.get("vendor_preference", []):
                score += 0.10
                evs.append(f"vendor:{participant.vendor_name} common in {context.value}")

            # 5. Domain ID heuristic
            if participant.domain_id in sigs.get("domain_ids", []):
                score += 0.05
                evs.append(f"domain_id:{participant.domain_id} typical for {context.value}")

            scores[context]   = min(score, 1.0)
            evidence[context] = evs

        if not scores or max(scores.values()) < 0.10:
            return ICSContext.UNKNOWN, 0.0, []

        best_context   = max(scores, key=lambda c: scores[c])
        best_confidence = scores[best_context]
        best_evidence   = evidence[best_context]

        return best_context, best_confidence, best_evidence

    def assess_risk(self, participant: DDSParticipant) -> tuple[RiskLevel, list]:
        """
        Generate risk findings for a classified ICS DDS participant.
        Returns (RiskLevel, findings_list).
        """
        findings = []
        base_risk = RiskLevel.INFO

        # Unauthenticated in critical ICS context
        if not participant.security_enabled:
            if participant.ics_context in (
                ICSContext.SCADA, ICSContext.AIR_TRAFFIC,
                ICSContext.SMART_GRID, ICSContext.MILITARY, ICSContext.MEDICAL
            ):
                findings.append({
                    "id": "ICS-DDS-001",
                    "title": "Unauthenticated DDS in Critical Infrastructure",
                    "detail": (
                        f"DDS participant at {participant.ip}:{participant.port} "
                        f"classified as {participant.ics_context.value.upper()} context "
                        f"has no DDS-Security enabled. Any participant can join the domain, "
                        f"subscribe to all topics, and inject arbitrary messages."
                    ),
                    "cvss": "9.8",
                    "cwe": "CWE-306",
                    "impact": "Full message injection into safety-critical data flows",
                })
                base_risk = RiskLevel.CRITICAL

            elif participant.ics_context == ICSContext.AUTOMOTIVE:
                findings.append({
                    "id": "ICS-DDS-002",
                    "title": "Unauthenticated DDS in Automotive/AV Platform",
                    "detail": (
                        f"Automotive DDS deployment at {participant.ip} lacks DDS-Security. "
                        f"Attacker can spoof sensor data (LiDAR, radar, camera), inject "
                        f"control commands, or DoS the perception/planning pipeline."
                    ),
                    "cvss": "8.8",
                    "cwe": "CWE-306",
                    "impact": "Sensor spoofing, control injection, AV platform DoS",
                })
                base_risk = RiskLevel.CRITICAL

            else:
                findings.append({
                    "id": "ICS-DDS-003",
                    "title": "DDS Participant Without Authentication",
                    "detail": f"No DDS-Security observed at {participant.ip}:{participant.port}.",
                    "cvss": "7.5",
                    "cwe": "CWE-306",
                    "impact": "Unauthorized topic access and message injection",
                })
                base_risk = RiskLevel.HIGH

        # Internet-reachable ICS DDS (set externally by scanner)
        if participant.properties.get("_internet_reachable"):
            findings.append({
                "id": "ICS-DDS-004",
                "title": "ICS DDS Endpoint Internet-Exposed",
                "detail": (
                    f"DDS participant at {participant.ip} is reachable from the internet. "
                    f"ICS/OT DDS endpoints must never be internet-exposed."
                ),
                "cvss": "10.0",
                "cwe": "CWE-668",
                "impact": "Remote unauthenticated access to operational technology network",
            })
            base_risk = RiskLevel.CRITICAL

        # Vendor-specific known-vulnerable versions
        if participant.vendor_name == "eProsima" and participant.rtps_version in ("2.1", "2.2"):
            findings.append({
                "id": "ICS-DDS-005",
                "title": "Fast DDS Potentially Affected by CVE-2021-38487/CVE-2023-39534",
                "detail": (
                    "Fast DDS at this version range has known RTPS parsing vulnerabilities. "
                    "Verify patch level before deployment in ICS environments."
                ),
                "cvss": "8.2",
                "cwe": "CWE-125",
                "impact": "Remote heap read, potential RCE via malformed RTPS packets",
            })
            if base_risk == RiskLevel.INFO:
                base_risk = RiskLevel.HIGH

        # Internal IP leakage via locators
        internal_ranges = ["10.", "172.16.", "192.168."]
        for k, v in participant.properties.items():
            if "locator" in k.lower() or "address" in k.lower():
                for prefix in internal_ranges:
                    if prefix in v and v != participant.ip:
                        findings.append({
                            "id": "ICS-DDS-006",
                            "title": "Internal IP Leaked via DDS Locators",
                            "detail": f"Property {k}={v} reveals internal network topology.",
                            "cvss": "5.3",
                            "cwe": "CWE-200",
                            "impact": "Network topology disclosure aids lateral movement",
                        })

        return base_risk, findings


# ─────────────────────────────────────────────────────────────────────────────
# ACTIVE SCANNER
# ─────────────────────────────────────────────────────────────────────────────

class ICSDDSScanner:
    """
    Active DDS discovery scanner. Sends RTPS SPDP probes and listens for
    participant announcements. Pure UDP — no ROS 2 required.
    """

    def __init__(self, timeout: float = 3.0, max_workers: int = 50,
                 passive: bool = False, passive_duration: float = 30.0):
        self.timeout          = timeout
        self.max_workers      = max_workers
        self.passive          = passive
        self.passive_duration = passive_duration
        self.probe_builder    = RTPSProbeBuilder()
        self.parser           = RTPSResponseParser()
        self.classifier       = ICSContextClassifier()
        self._found: dict     = {}   # ip:port → DDSParticipant
        self._lock            = threading.Lock()

    # ── Active probe ──────────────────────────────────────────────────────────

    def probe_host(self, ip: str, domain_ids: list[int]) -> list[DDSParticipant]:
        """Probe a single host across domain IDs."""
        participants = []

        for domain_id in domain_ids:
            ports = [
                dds_discovery_port(domain_id),
                dds_user_port(domain_id),
                dds_discovery_port(domain_id) + 10,  # unicast participant 0
            ]
            for port in ports:
                p = self._probe_endpoint(ip, port, domain_id)
                if p:
                    participants.append(p)

        return participants

    def _probe_endpoint(self, ip: str, port: int,
                        domain_id: int) -> Optional[DDSParticipant]:
        """Send SPDP probe to ip:port/udp and parse response."""
        probe = self.probe_builder.build_spdp_announcement(domain_id)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(probe, (ip, port))
            data, addr = sock.recvfrom(65535)
            sock.close()

            if data[:4] == RTPS_HEADER_MAGIC:
                participant = self.parser.parse(data, addr[0], addr[1])
                if participant:
                    participant.domain_id = domain_id
                    return participant

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return None

    # ── Passive listener ─────────────────────────────────────────────────────

    def listen_passive(self, interface_ip: str = "0.0.0.0",
                       domain_ids: list[int] = None) -> list[DDSParticipant]:
        """
        Join the DDS SPDP multicast group and passively collect participant
        announcements without sending any probes. Stealth mode.
        """
        if domain_ids is None:
            domain_ids = [0, 1, 5, 10]

        found = []
        deadline = time.time() + self.passive_duration

        for domain_id in domain_ids:
            mc_port = dds_discovery_port(domain_id)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.bind(("", mc_port))

                # Join multicast group
                mreq = struct.pack("4sL",
                    socket.inet_aton(RTPS_MULTICAST_GROUP),
                    socket.INADDR_ANY
                )
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                sock.settimeout(2.0)

                while time.time() < deadline:
                    try:
                        data, addr = sock.recvfrom(65535)
                        if data[:4] == RTPS_HEADER_MAGIC:
                            p = self.parser.parse(data, addr[0], addr[1])
                            if p:
                                p.domain_id = domain_id
                                key = f"{p.ip}:{p.port}"
                                if key not in [f"{x.ip}:{x.port}" for x in found]:
                                    found.append(p)
                                    self._print_discovery(p, passive=True)
                    except socket.timeout:
                        continue

                sock.close()
            except PermissionError:
                print("[!] Passive listen requires root/CAP_NET_RAW")
                break
            except OSError:
                continue

        return found

    # ── CIDR sweep ───────────────────────────────────────────────────────────

    def sweep_cidr(self, cidr: str, domain_ids: list[int] = None) -> list[DDSParticipant]:
        """Threaded sweep of a CIDR range."""
        if domain_ids is None:
            domain_ids = [0, 1, 5, 10, 30, 50, 100]

        network = ipaddress.ip_network(cidr, strict=False)
        hosts   = list(network.hosts())
        found   = []

        print(f"[*] Sweeping {cidr} ({len(hosts)} hosts) across domain IDs {domain_ids}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {pool.submit(self.probe_host, str(h), domain_ids): str(h) for h in hosts}
            for future in as_completed(futures):
                results = future.result()
                for p in results:
                    found.append(p)
                    self._print_discovery(p)

        return found

    def _print_discovery(self, p: DDSParticipant, passive: bool = False):
        mode = "PASSIVE" if passive else "ACTIVE"
        sec  = "🔒 SECURED" if p.security_enabled else "🔓 OPEN"
        print(
            f"  [{mode}] {p.ip}:{p.port} | "
            f"domain={p.domain_id} | "
            f"{p.vendor_name or 'Unknown'} {p.vendor_product} | "
            f"{sec}"
            + (f" | name={p.participant_name}" if p.participant_name else "")
        )


# ─────────────────────────────────────────────────────────────────────────────
# PROTOCOL COEXISTENCE DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolCoexistenceDetector:
    """
    Detects other ICS protocols running on the same host as DDS.
    Cross-protocol coexistence is a key attack-surface signal:
    a host running both DDS and OPC UA is a potential bridge node.
    """

    PROTOCOL_PORTS = {
        "OPC-UA":        [4840, 4843, 48010],
        "Modbus":        [502, 503],
        "DNP3":          [20000, 19999],
        "MQTT":          [1883, 8883, 1884],
        "MQTT-SN":       [1884],
        "EtherNet/IP":   [44818, 2222],
        "PROFINET":      [34962, 34963, 34964],
        "BACnet":        [47808],
        "IEC-61850-MMS": [102],
        "ICCP-TASE2":    [102],
        "EtherCAT":      [34980],
        "S7comm":        [102],
        "FINS":          [9600],
        "Crimson3":      [789],
    }

    def detect(self, ip: str, timeout: float = 1.5) -> dict:
        """
        TCP/UDP port check for ICS protocol presence.
        Returns dict of {protocol: [port_list_open]}.
        """
        detected = {}

        for protocol, ports in self.PROTOCOL_PORTS.items():
            open_ports = []
            for port in ports:
                # TCP check
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    if result == 0:
                        open_ports.append(port)
                        continue
                except OSError:
                    pass

                # UDP check for datagram protocols
                if protocol in ("Modbus", "DNP3", "BACnet", "EtherCAT", "FINS", "PROFINET"):
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(timeout)
                        sock.sendto(b"\x00\x00", (ip, port))
                        sock.recvfrom(64)
                        open_ports.append(port)
                        sock.close()
                    except (socket.timeout, OSError):
                        pass

            if open_ports:
                detected[protocol] = open_ports

        return detected


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENUMERATOR ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class ICSDDSEnumerator:
    """
    Top-level orchestrator for Phase 3 ICS/OT DDS enumeration.
    Ties together scanning, parsing, classification, risk assessment,
    and protocol coexistence detection into a single pipeline.
    """

    def __init__(self, args):
        self.args        = args
        self.scanner     = ICSDDSScanner(
            timeout          = args.timeout,
            max_workers      = args.threads,
            passive          = args.passive,
            passive_duration = args.passive_duration,
        )
        self.classifier  = ICSContextClassifier()
        self.proto_det   = ProtocolCoexistenceDetector()
        self.result      = ICSBridgeResult(scan_target=args.target or args.cidr or "unknown")

    def run(self) -> ICSBridgeResult:
        domain_ids = self._parse_domains()
        self.result.domain_ids_scanned = domain_ids

        print(f"\n{'='*60}")
        print("  ROS2Reaper :: Phase 3 — ICS/OT DDS Enumerator")
        print(f"{'='*60}")

        # ── Step 1: Discover participants ─────────────────────────────────────
        raw_participants = []

        if self.args.passive:
            print(f"[*] Passive mode — listening {self.args.passive_duration}s on multicast")
            raw_participants = self.scanner.listen_passive(domain_ids=domain_ids)
        elif self.args.cidr:
            raw_participants = self.scanner.sweep_cidr(self.args.cidr, domain_ids)
        else:
            print(f"[*] Probing {self.args.target}")
            raw_participants = self.scanner.probe_host(self.args.target, domain_ids)

        print(f"\n[+] Discovered {len(raw_participants)} DDS participant(s)\n")

        # ── Step 2: Classify + risk assess ───────────────────────────────────
        for p in raw_participants:
            ctx, conf, evid = self.classifier.classify(p)
            p.ics_context        = ctx
            p.context_confidence = conf
            p.context_evidence   = evid

            risk, findings = self.classifier.assess_risk(p)
            p.risk_level = risk
            p.findings   = findings

            # ── Step 3: Protocol coexistence (deep mode) ──────────────────
            if self.args.deep:
                print(f"  [>] Protocol probe: {p.ip}")
                proto_hits = self.proto_det.detect(p.ip)
                if proto_hits:
                    p.properties["_coexisting_protocols"] = json.dumps(proto_hits)
                    self.result.protocol_coexistence[p.ip] = proto_hits
                    for proto in proto_hits:
                        findings.append({
                            "id": "ICS-DDS-010",
                            "title": f"DDS + {proto} Coexistence — Bridge Node",
                            "detail": (
                                f"{p.ip} runs both DDS (port {p.port}) and {proto} "
                                f"(port {proto_hits[proto]}). This host likely bridges "
                                f"the DDS domain to the {proto} network segment."
                            ),
                            "cvss": "8.5",
                            "cwe": "CWE-441",
                            "impact": f"DDS compromise may pivot to {proto} network",
                        })
                        if risk.value in ("INFO", "LOW", "MEDIUM"):
                            p.risk_level = RiskLevel.HIGH

            self.result.participants.append(p.to_dict())

            if findings:
                for f in findings:
                    if f.get("cvss", "0") >= "8.0":
                        self.result.critical_findings.append({
                            "host": p.ip,
                            "finding": f,
                        })

        # ── Step 4: Context summary ───────────────────────────────────────────
        ctx_counts = {}
        for p in raw_participants:
            c = p.ics_context.value
            ctx_counts[c] = ctx_counts.get(c, 0) + 1
        self.result.context_summary = ctx_counts

        self._print_summary(raw_participants)
        return self.result

    def _parse_domains(self) -> list[int]:
        if self.args.domain == -1:
            return [0, 1, 5, 10, 30, 50, 100]
        return [self.args.domain]

    def _print_summary(self, participants: list[DDSParticipant]):
        print(f"\n{'='*60}")
        print("  SUMMARY")
        print(f"{'='*60}")
        print(f"  Participants : {len(participants)}")
        print(f"  Context dist : {self.result.context_summary}")
        print(f"  Critical findings : {len(self.result.critical_findings)}")

        crit_hosts = {f["host"] for f in self.result.critical_findings}
        if crit_hosts:
            print(f"\n  ⚠  HIGH/CRITICAL HOSTS:")
            for h in crit_hosts:
                matching = [p for p in participants if p.ip == h]
                for p in matching:
                    print(f"     {h} [{p.ics_context.value.upper()}] "
                          f"{p.risk_level.value} — {p.vendor_product or 'Unknown DDS'}")

        if self.result.protocol_coexistence:
            print(f"\n  🔗 PROTOCOL BRIDGE NODES:")
            for host, protos in self.result.protocol_coexistence.items():
                print(f"     {host} → {', '.join(protos.keys())}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ROS2Reaper Phase 3 — ICS/OT Context DDS Enumerator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Active probe of a single host across all common domains
  python3 ics_dds_enum.py --target 10.0.0.5

  # CIDR sweep with deep protocol coexistence detection
  python3 ics_dds_enum.py --cidr 192.168.1.0/24 --deep

  # Passive multicast listen (stealth, requires root)
  python3 ics_dds_enum.py --passive --passive-duration 60

  # Target only DDS domain 0 and save output
  python3 ics_dds_enum.py --target 10.0.0.5 --domain 0 --output results.json

  # Lab environment sweep (your Proxmox subnet)
  python3 ics_dds_enum.py --cidr 10.52.32.0/24 --deep --threads 30
        """
    )
    tgt = p.add_mutually_exclusive_group()
    tgt.add_argument("--target",  help="Single target IP")
    tgt.add_argument("--cidr",    help="CIDR range to sweep, e.g. 10.0.0.0/24")
    tgt.add_argument("--passive", action="store_true",
                     help="Passive multicast listener only (no active probes)")

    p.add_argument("--domain", type=int, default=-1,
                   help="DDS domain ID to target (-1 = scan all common domains)")
    p.add_argument("--timeout", type=float, default=3.0,
                   help="Socket timeout per probe (default: 3.0s)")
    p.add_argument("--threads", type=int, default=50,
                   help="Max concurrent scan threads (default: 50)")
    p.add_argument("--passive-duration", type=float, default=30.0, dest="passive_duration",
                   help="Seconds to listen in passive mode (default: 30)")
    p.add_argument("--deep", action="store_true",
                   help="Enable protocol coexistence detection (OPC UA, Modbus, MQTT…)")
    p.add_argument("--output", metavar="FILE",
                   help="Write JSON results to file")
    p.add_argument("--context", choices=[c.value for c in ICSContext],
                   help="Filter/bias classification toward a specific ICS context")
    return p.parse_args()


def main():
    args = parse_args()

    if not any([args.target, args.cidr, args.passive]):
        print("[-] Specify --target, --cidr, or --passive")
        sys.exit(1)

    enumerator = ICSDDSEnumerator(args)
    result     = enumerator.run()

    if args.output:
        out = {
            "scan_target":          result.scan_target,
            "scan_time":            result.scan_time,
            "domain_ids_scanned":   result.domain_ids_scanned,
            "context_summary":      result.context_summary,
            "critical_findings":    result.critical_findings,
            "protocol_coexistence": result.protocol_coexistence,
            "participants":         result.participants,
        }
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2)
        print(f"[+] Results saved → {args.output}")


if __name__ == "__main__":
    main()
