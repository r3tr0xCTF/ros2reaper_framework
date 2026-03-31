#!/usr/bin/env python3
"""
mqtt_ethercat_bridge.py — MQTT / EtherCAT ↔ DDS Bridge Attack Surface Analyzer
================================================================================
ROS2Reaper Phase 3 Module

Detects hosts running DDS alongside MQTT (industrial IoT messaging) or
EtherCAT (real-time fieldbus), characterizes the bridge attack surface,
and generates PoC attack scenarios for crossing from the DDS domain into
these adjacent protocol stacks.

Why MQTT matters:
    MQTT is the dominant protocol for IIoT edge-to-cloud data pipelines.
    Unified Namespace (UNS) architectures increasingly use MQTT Sparkplug B
    as a semantic layer that bridges to DDS for real-time distribution.
    A compromised DDS participant can publish to bridged MQTT topics,
    reaching cloud historians, SCADA systems, and remote HMIs — or
    subscribe to MQTT telemetry being bridged into the DDS domain to
    exfiltrate process data silently.

Why EtherCAT matters:
    EtherCAT is a deterministic real-time fieldbus dominant in precision
    motion control, robotics, and semiconductor manufacturing. EtherCAT
    Master devices increasingly run DDS alongside the EtherCAT stack to
    bridge process data to higher-level systems. Compromising the DDS
    participant on an EtherCAT Master gives indirect access to the PDO
    (Process Data Object) exchange — actuators, servo drives, and I/O
    modules operating at sub-millisecond cycle times.

MQTT default ports : 1883 (TCP, plain) / 8883 (TCP, TLS)
EtherCAT port      : 34980 (UDP, EtherCAT Automation Protocol / EAP)
DDS discovery port : 7400+ (UDP)

Author  : Gh057x
Phase   : 3 — ICS/OT Bridge
Requires: paho-mqtt (optional, degrades gracefully)

Usage:
    python3 mqtt_ethercat_bridge.py --target 10.0.0.5
    python3 mqtt_ethercat_bridge.py --cidr 192.168.1.0/24 --deep
    python3 mqtt_ethercat_bridge.py --target 10.0.0.5 --mqtt-enumerate
    python3 mqtt_ethercat_bridge.py --target 10.0.0.5 --output report.json
"""

import socket
import struct
import time
import json
import argparse
import sys
import threading
import ssl
import ipaddress
import re
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# paho-mqtt is optional
try:
    import paho.mqtt.client as mqtt
    PAHO_AVAILABLE = True
except ImportError:
    PAHO_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MQTT_PORTS          = [1883, 8883, 1884, 8884, 1885]
MQTT_WS_PORTS       = [8080, 8443, 9001]   # MQTT over WebSocket
DDS_DISC_PORTS      = [7400, 7410, 7650, 7660, 8650, 8660]
ETHERCAT_EAP_PORT   = 34980                # EtherCAT Automation Protocol (UDP)
ETHERCAT_ALT_PORTS  = [34981, 34982]
OPCUA_PORTS         = [4840, 4843]         # co-location check
AMQP_PORTS          = [5672, 5671]         # AMQP (sometimes co-located in IIoT)

# MQTT CONNECT packet — minimal, anonymous
# Fixed header: CONNECT (1<<4), remaining length
# Variable header: protocol name "MQTT" v4, connect flags, keepalive
# Payload: client ID "ros2reaper_probe"
MQTT_CONNECT_PLAIN = (
    b"\x10"         # CONNECT, no flags
    b"\x25"         # remaining length = 37
    b"\x00\x04MQTT" # protocol name
    b"\x04"         # protocol level 4 (MQTT 3.1.1)
    b"\x00"         # connect flags: no clean session, no will, anon
    b"\x00\x3c"     # keepalive: 60s
    b"\x00\x10ros2reaper_probe"  # client ID (16 chars)
)

# MQTT PINGREQ — used to keep a session alive for topic enumeration
MQTT_PINGREQ = b"\xc0\x00"

# MQTT SUBSCRIBE packet — wildcard subscribe to enumerate all topics
def build_mqtt_subscribe(topic_filter: str = "#", qos: int = 0,
                          packet_id: int = 1) -> bytes:
    topic_bytes = topic_filter.encode()
    topic_len   = len(topic_bytes)
    payload     = struct.pack(">H", packet_id) + struct.pack(">H", topic_len) + topic_bytes + bytes([qos])
    rem_len     = len(payload)
    return bytes([0x82, rem_len]) + payload   # SUBSCRIBE

# MQTT PUBLISH — craft a publish to a specific topic
def build_mqtt_publish(topic: str, payload: bytes, qos: int = 0) -> bytes:
    topic_bytes = topic.encode()
    topic_len   = len(topic_bytes)
    header_var  = struct.pack(">H", topic_len) + topic_bytes
    if qos > 0:
        header_var += struct.pack(">H", 1)   # packet ID
    fixed_hdr_byte = 0x30 | (qos << 1)
    rem_len        = len(header_var) + len(payload)
    return bytes([fixed_hdr_byte, rem_len]) + header_var + payload

# MQTT DISCONNECT
MQTT_DISCONNECT = b"\xe0\x00"

# EtherCAT Automation Protocol (EAP) — identity request
# EAP uses UDP/34980; mailbox protocol over EtherCAT
EAP_IDENTITY_REQUEST = (
    b"\x01\x00"     # EAP type: Identity Request
    b"\x00\x00"     # Reserved
    b"\x00\x00\x00\x00"  # Source address (zero)
)

# Sparkplug B MQTT topic structure
SPARKPLUG_TOPIC_RE = re.compile(
    r"^spBv1\.0/(?P<group>[^/]+)/(?P<msg_type>NBIRTH|NDEATH|NDATA|NCMD"
    r"|DBIRTH|DDEATH|DDATA|DCMD)/(?P<node>[^/]+)(/(?P<device>.+))?$"
)

# Known MQTT ↔ DDS bridge products / implementations
KNOWN_MQTT_BRIDGE_PRODUCTS = {
    "rti_mqtt":         "RTI Connext DDS MQTT Connector",
    "cyclone_mqtt":     "Eclipse Cyclone DDS MQTT Bridge",
    "zenoh_mqtt":       "Eclipse Zenoh MQTT Plugin",
    "ros2_mqtt":        "ROS 2 MQTT Bridge (ros2-mqtt-bridge)",
    "fledge_mqtt":      "LF Edge Fledge MQTT South Plugin",
    "kepware_mqtt":     "Kepware IoT Gateway MQTT Agent",
    "ignition_mqtt":    "Ignition MQTT Transmission Module (Cirrus Link)",
    "emqx_dds":         "EMQX DDS Protocol Gateway",
    "hivemq_dds":       "HiveMQ DDS Extension",
    "iotedge_dds":      "Azure IoT Edge DDS Connector",
}

# Known EtherCAT ↔ DDS bridge products
KNOWN_ETHERCAT_BRIDGE_PRODUCTS = {
    "rti_ethercat":     "RTI Connext DDS EtherCAT Connector (Beckhoff TwinCAT)",
    "igh_dds":          "IgH EtherCAT Master + DDS bridge",
    "twincat_dds":      "Beckhoff TwinCAT ADS ↔ DDS Gateway",
    "soem_dds":         "SOEM (Simple Open EtherCAT Master) + DDS adapter",
    "etherlab_dds":     "EtherLab / ethercat-dds-bridge (GitHub)",
}

# ICS/Industrial MQTT topic patterns that indicate bridged process data
ICS_MQTT_TOPIC_PATTERNS = [
    # Sparkplug B
    r"^spBv1\.0/",
    # Generic process data
    r"/(sensor|measurement|reading|telemetry)/",
    r"/(coil|register|do_|di_|ai_|ao_)/",
    r"/(setpoint|sp_|control|cmd_)/",
    r"/(alarm|fault|event|status)/",
    r"/(plc|rtu|ied|hmi|scada)/",
    # Factory/robot
    r"/(robot|arm|joint|conveyor|motor|servo)/",
    r"/(production|oee|downtime|quality)/",
    # Energy
    r"/(power|grid|meter|demand|voltage|current)/",
    r"/(substation|feeder|breaker|transformer)/",
]


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────

MQTT_DDS_ATTACK_SCENARIOS = [
    {
        "id":            "MQTT-001",
        "name":          "DDS→MQTT Topic Injection (Process Data Spoofing)",
        "description":   (
            "Publish to a DDS topic bridged to an MQTT topic feeding a cloud "
            "historian or SCADA system. The bridge republishes the DDS message "
            "as an MQTT PUBLISH to the mapped topic. Operators and dashboards "
            "consume the spoofed values without knowing the source is attacker-controlled. "
            "Particularly impactful against Sparkplug B deployments where metric "
            "values are semantically typed (INT32, FLOAT, BOOLEAN)."
        ),
        "dds_topic_pattern": r"/(sensor|measurement|telemetry|reading|process)",
        "mqtt_topic_pattern": r"(spBv1\.0|sensor|data|telemetry)",
        "impact":        "Cloud/SCADA historian poisoning, dashboard metric spoofing",
        "cvss":          "8.6",
        "cwe":           "CWE-494",
        "mitre_ics":     "T0832 — Manipulation of View",
        "ics_sectors":   ["all"],
    },
    {
        "id":            "MQTT-002",
        "name":          "DDS→MQTT Command Injection (Sparkplug B NCMD/DCMD)",
        "description":   (
            "Inject a DDS message bridged to an MQTT Sparkplug B NCMD or DCMD "
            "topic. Node Commands (NCMD) target the EoN node itself; Device "
            "Commands (DCMD) target field devices. In a Sparkplug B deployment "
            "the host application translates DCMD metric writes into PLC/RTU "
            "register writes or actuator commands."
        ),
        "dds_topic_pattern": r"/(cmd_|command|ncmd|dcmd|write|set)",
        "mqtt_topic_pattern": r"spBv1\.0/[^/]+/[ND]CMD/",
        "impact":        "Remote actuation via Sparkplug B command channel",
        "cvss":          "9.1",
        "cwe":           "CWE-284",
        "mitre_ics":     "T0831 — Manipulation of Control",
        "ics_sectors":   ["manufacturing", "oil_gas", "water", "power"],
    },
    {
        "id":            "MQTT-003",
        "name":          "MQTT Wildcard Subscribe → DDS Topic Exfiltration",
        "description":   (
            "Subscribe to '#' (wildcard) on an unauthenticated MQTT broker that "
            "is bridged to a DDS domain. All DDS topic data flowing through the "
            "bridge is silently exfiltrated via MQTT subscription — no DDS "
            "participation required. Process values, alarm states, network "
            "topology, and device configurations are all exposed."
        ),
        "dds_topic_pattern": r".*",
        "mqtt_topic_pattern": r"#",
        "impact":        "Full process data exfiltration with no DDS-layer footprint",
        "cvss":          "7.5",
        "cwe":           "CWE-200",
        "mitre_ics":     "T0830 — Man in the Middle",
        "ics_sectors":   ["all"],
    },
    {
        "id":            "MQTT-004",
        "name":          "MQTT Retained Message Poisoning",
        "description":   (
            "Publish a malicious retained MQTT message to a topic bridged from "
            "DDS. The MQTT broker stores the retained message and delivers it to "
            "every future subscriber — including legitimate SCADA clients that "
            "re-subscribe after reconnection. The poisoned value persists until "
            "explicitly cleared, surviving DDS participant restarts."
        ),
        "dds_topic_pattern": r"/(setpoint|config|parameter|limit|threshold)",
        "mqtt_topic_pattern": r"(setpoint|config|parameter|limit)",
        "impact":        "Persistent process parameter corruption across reconnects",
        "cvss":          "8.2",
        "cwe":           "CWE-494",
        "mitre_ics":     "T0831 — Manipulation of Control",
        "ics_sectors":   ["all"],
    },
    {
        "id":            "MQTT-005",
        "name":          "MQTT Last Will & Testament Trigger (False Device Death)",
        "description":   (
            "Connect to the MQTT broker posing as a legitimate DDS bridge client "
            "with a crafted Last Will & Testament (LWT) message on a Sparkplug B "
            "NDEATH topic. Abruptly disconnect — the broker publishes the NDEATH "
            "message, telling all subscribers the legitimate EoN node is offline. "
            "SCADA raises a false 'device lost' alarm, triggering operator response "
            "procedures or automated failover."
        ),
        "dds_topic_pattern": r"N/A",
        "mqtt_topic_pattern": r"spBv1\.0/[^/]+/NDEATH/",
        "impact":        "False device death, spurious failover, operator distraction",
        "cvss":          "7.2",
        "cwe":           "CWE-346",
        "mitre_ics":     "T0878 — Alarm Suppression / T0814 — Denial of Control",
        "ics_sectors":   ["all"],
    },
    {
        "id":            "MQTT-006",
        "name":          "MQTT Broker DoS via DDS Bridge Flood",
        "description":   (
            "Flood a DDS write topic with high-frequency updates. The bridge "
            "translates each DDS sample into an MQTT PUBLISH. Default MQTT brokers "
            "have no per-client rate limiting — the broker's message queue overflows, "
            "legitimate subscriber deliveries are delayed or dropped, and QoS 1/2 "
            "acknowledgement storms can cause broker memory exhaustion."
        ),
        "dds_topic_pattern": r".*",
        "mqtt_topic_pattern": r".*",
        "impact":        "MQTT broker DoS, subscriber delivery failure, QoS storm",
        "cvss":          "7.5",
        "cwe":           "CWE-400",
        "mitre_ics":     "T0814 — Denial of Control",
        "ics_sectors":   ["all"],
    },
]

ETHERCAT_DDS_ATTACK_SCENARIOS = [
    {
        "id":            "ECAT-001",
        "name":          "DDS→EtherCAT PDO Write (Servo Drive Command Override)",
        "description":   (
            "Write to a DDS topic mapped to an EtherCAT Process Data Object (PDO) "
            "output on the EtherCAT Master. The Master's DDS adapter propagates "
            "the value into the real-time EtherCAT cycle, overwriting the target "
            "servo drive's control word, target position, or target velocity. "
            "EtherCAT operates at 250μs–4ms cycle times — impact is instantaneous. "
            "Common targets: Beckhoff EL7xxx, Kollmorgen AKD, Festo servo drives."
        ),
        "dds_topic_pattern": r"/(joint|servo|drive|position|velocity|torque|effort)",
        "ethercat_object":   "PDO Output — 0x6040 Control Word / 0x607A Target Position",
        "impact":            "Servo drive position/velocity command override — immediate physical impact",
        "cvss":              "9.8",
        "cwe":               "CWE-284",
        "mitre_ics":         "T0831 — Manipulation of Control",
        "ics_sectors":       ["manufacturing", "robotics", "semiconductor"],
    },
    {
        "id":            "ECAT-002",
        "name":          "DDS→EtherCAT Digital Output Write (I/O Module)",
        "description":   (
            "Write to a DDS topic mapped to an EtherCAT digital output (DO) PDO "
            "on a remote I/O module (e.g. Beckhoff EL2xxx, Wago 750-504). The "
            "Master cycles the new value onto the EtherCAT bus in the next frame. "
            "Digital outputs typically control solenoid valves, contactors, "
            "indicator lights, and safety relays."
        ),
        "dds_topic_pattern": r"/(digital_out|do_|coil|relay|valve|contactor|output)",
        "ethercat_object":   "PDO Output — Digital Output channel bit",
        "impact":            "Actuator on/off control at field device level",
        "cvss":              "9.3",
        "cwe":               "CWE-284",
        "mitre_ics":         "T0831 — Manipulation of Control",
        "ics_sectors":       ["manufacturing", "robotics", "oil_gas"],
    },
    {
        "id":            "ECAT-003",
        "name":          "DDS→EtherCAT SDO Write (Drive Parameter Manipulation)",
        "description":   (
            "Write to a DDS topic mapped to an EtherCAT SDO (Service Data Object) "
            "configuration register. SDOs configure drive parameters: acceleration "
            "ramps, torque limits, encoder resolution, homing offsets, and safety "
            "thresholds. An SDO write takes effect immediately without operator "
            "notification and persists across power cycles on EEPROM-backed drives."
        ),
        "dds_topic_pattern": r"/(config|parameter|limit|gain|kp|ki|kd|ramp|threshold)",
        "ethercat_object":   "SDO — 0x6083 Profile Acceleration / 0x6072 Max Torque",
        "impact":            "Drive parameter corruption — persistent across power cycle",
        "cvss":              "8.8",
        "cwe":               "CWE-284",
        "mitre_ics":         "T0839 — Module Firmware / T0831 — Manipulation of Control",
        "ics_sectors":       ["manufacturing", "semiconductor", "robotics"],
    },
    {
        "id":            "ECAT-004",
        "name":          "DDS EtherCAT Master DoS (PDO Cycle Disruption)",
        "description":   (
            "Flood the DDS topics feeding the EtherCAT Master's PDO output map "
            "with rapid conflicting updates. The Master must serialize DDS samples "
            "into its real-time cycle — if the DDS consumer thread cannot keep up, "
            "the Master's cycle time degrades, triggering watchdog faults on "
            "connected slaves. EtherCAT slaves that miss their sync window enter "
            "SAFE-OP or INIT state, halting controlled motion."
        ),
        "dds_topic_pattern": r"/(joint|servo|axis|drive|position|velocity)",
        "ethercat_object":   "Distributed Clocks sync / watchdog timer",
        "impact":            "EtherCAT Master watchdog fault, slave SAFE-OP/INIT, motion halt",
        "cvss":              "7.5",
        "cwe":               "CWE-400",
        "mitre_ics":         "T0814 — Denial of Control",
        "ics_sectors":       ["manufacturing", "robotics", "semiconductor"],
    },
    {
        "id":            "ECAT-005",
        "name":          "EtherCAT Topology Fingerprint via DDS Participant Properties",
        "description":   (
            "Many EtherCAT-DDS bridge implementations publish the EtherCAT slave "
            "topology in DDS participant properties or discovery topics: slave count, "
            "vendor IDs, product codes, and PDO maps. This metadata is exfiltrated "
            "passively during DDS discovery — no EtherCAT frames are sent. The "
            "attacker obtains a complete ICS device inventory without touching the "
            "fieldbus."
        ),
        "dds_topic_pattern": r"/(topology|slave|ecat_config|device_map|eni_)",
        "ethercat_object":   "Participant properties / discovery metadata",
        "impact":            "Full EtherCAT topology disclosure — zero fieldbus traffic",
        "cvss":              "6.5",
        "cwe":               "CWE-200",
        "mitre_ics":         "T0840 — Network Connection Enumeration",
        "ics_sectors":       ["manufacturing", "robotics", "semiconductor"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MQTTFingerprint:
    """Result of MQTT broker fingerprinting on a host."""
    host:                   str
    port:                   int
    tls:                    bool            = False
    responding:             bool            = False
    anonymous_access:       bool            = False
    broker_software:        str             = ""
    broker_version:         str             = ""
    protocol_level:         int             = 0      # 3=3.1, 4=3.1.1, 5=5.0
    topics_discovered:      list            = field(default_factory=list)
    sparkplug_namespaces:   list            = field(default_factory=list)
    ics_topics:             list            = field(default_factory=list)
    retained_topics:        list            = field(default_factory=list)
    wildcard_sub_allowed:   bool            = False
    will_injection_viable:  bool            = False
    bridge_topics:          list            = field(default_factory=list)  # DDS-mapped
    error:                  str             = ""


@dataclass
class EtherCATFingerprint:
    """Result of EtherCAT/EAP probing on a host."""
    host:                   str
    port:                   int
    responding:             bool            = False
    eap_confirmed:          bool            = False
    master_software:        str             = ""
    slave_count:            int             = 0
    slave_vendors:          list            = field(default_factory=list)
    cycle_time_us:          int             = 0
    dds_bridge_detected:    bool            = False
    pdo_topic_hints:        list            = field(default_factory=list)
    error:                  str             = ""


@dataclass
class MQTTEtherCATBridgeReport:
    """Full analysis for a host running DDS + MQTT and/or EtherCAT."""
    ip:                          str
    scan_time:                   str   = field(default_factory=lambda: datetime.now().isoformat())
    dds_ports_open:              list  = field(default_factory=list)
    mqtt_ports_open:             list  = field(default_factory=list)
    ethercat_ports_open:         list  = field(default_factory=list)
    other_protocols:             dict  = field(default_factory=dict)
    mqtt_fingerprint:            Optional[dict]  = None
    ethercat_fingerprint:        Optional[dict]  = None
    bridge_confirmed:            bool  = False
    mqtt_bridge_product_guess:   str   = ""
    ethercat_bridge_product_guess: str = ""
    bridge_evidence:             list  = field(default_factory=list)
    applicable_mqtt_scenarios:   list  = field(default_factory=list)
    applicable_ethercat_scenarios: list = field(default_factory=list)
    risk_level:                  str   = "UNKNOWN"
    findings:                    list  = field(default_factory=list)
    recommended_poc:             list  = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# MQTT PROBER
# ─────────────────────────────────────────────────────────────────────────────

class MQTTProber:
    """
    Raw MQTT prober. Uses manual socket for basic CONNECT/CONNACK detection
    with no external dependency. Escalates to paho-mqtt if available for
    full topic enumeration.
    """

    def __init__(self, timeout: float = 5.0, enum_duration: float = 10.0):
        self.timeout       = timeout
        self.enum_duration = enum_duration

    # ── Raw socket CONNECT ────────────────────────────────────────────────────

    def _raw_connect(self, ip: str, port: int,
                      tls: bool = False) -> Optional[socket.socket]:
        """Open TCP (+ optional TLS) and send MQTT CONNECT. Returns socket on CONNACK."""
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.timeout)
            raw.connect((ip, port))

            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw = ctx.wrap_socket(raw, server_hostname=ip)

            raw.sendall(MQTT_CONNECT_PLAIN)
            resp = raw.recv(64)

            # CONNACK: fixed header 0x20, remaining 0x02, session_present, return_code
            if len(resp) >= 4 and resp[0] == 0x20:
                return_code = resp[3]
                if return_code == 0x00:   # Connection Accepted
                    return raw
                # 0x05 = Not Authorized — broker alive but auth required
                if return_code == 0x05:
                    raw.close()
                    return None
            raw.close()
        except (socket.timeout, ssl.SSLError, ConnectionRefusedError, OSError):
            pass
        return None

    def confirm_mqtt(self, ip: str, port: int) -> tuple[bool, bool]:
        """Returns (plain_open, tls_open)."""
        plain = self._raw_connect(ip, port, tls=False) is not None
        tls   = False
        if port in (8883, 8884):
            sock = self._raw_connect(ip, port, tls=True)
            tls  = sock is not None
            if sock:
                sock.close()
        # Also try TLS on 1883 as fallback
        if not tls and not plain:
            sock = self._raw_connect(ip, port, tls=True)
            tls  = sock is not None
            if sock:
                sock.close()
        return plain, tls

    def read_connack_info(self, ip: str, port: int) -> dict:
        """
        Parse CONNACK for protocol level and broker identity.
        Some brokers send a CONNACK with broker identity in properties (MQTT 5.0).
        """
        info = {"anonymous_access": False, "protocol_level": 0, "broker_software": ""}
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(self.timeout)
            raw.connect((ip, port))
            raw.sendall(MQTT_CONNECT_PLAIN)
            resp = raw.recv(256)
            raw.close()

            if len(resp) >= 4 and resp[0] == 0x20:
                return_code = resp[3]
                info["anonymous_access"] = (return_code == 0x00)
                # Check for MQTT 5.0 properties in CONNACK
                if len(resp) > 4:
                    # MQTT 5.0 CONNACK has a properties length field
                    # Broker software often in "Server Reference" (0x1C) property
                    raw_props = resp[4:]
                    if b"mosquitto" in raw_props.lower() if hasattr(raw_props, 'lower') else b"mosquitto" in raw_props:
                        info["broker_software"] = "Mosquitto"
                    elif b"emqx" in raw_props:
                        info["broker_software"] = "EMQX"
                    elif b"hivemq" in raw_props:
                        info["broker_software"] = "HiveMQ"
                    elif b"vernemq" in raw_props:
                        info["broker_software"] = "VerneMQ"
                    elif b"rabbitmq" in raw_props:
                        info["broker_software"] = "RabbitMQ"

        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        return info

    # ── $SYS topic enumeration (broker metadata) ─────────────────────────────

    def _enumerate_sys_topics(self, ip: str, port: int) -> dict:
        """
        Subscribe to $SYS/# to extract broker metadata:
        version, connected clients, message rate, topic count.
        """
        sys_data = {}
        if not PAHO_AVAILABLE:
            return sys_data

        received = []
        done     = threading.Event()

        def on_message(client, userdata, msg):
            received.append((msg.topic, msg.payload.decode("utf-8", errors="replace")))
            if len(received) >= 30:
                done.set()

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.subscribe("$SYS/#", 0)

        try:
            c = mqtt.Client(client_id="ros2reaper_sys")
            c.on_connect = on_connect
            c.on_message = on_message
            c.connect(ip, port, keepalive=10)
            c.loop_start()
            done.wait(timeout=min(self.enum_duration, 5.0))
            c.loop_stop()
            c.disconnect()
        except Exception:
            pass

        for topic, payload in received:
            key = topic.replace("$SYS/broker/", "").replace("/", "_")
            sys_data[key] = payload

        return sys_data

    # ── ICS topic enumeration ─────────────────────────────────────────────────

    def enumerate_topics(self, ip: str, port: int) -> MQTTFingerprint:
        """Full MQTT fingerprint with topic discovery."""
        fp = MQTTFingerprint(host=ip, port=port)

        plain_ok, tls_ok = self.confirm_mqtt(ip, port)
        fp.responding        = plain_ok or tls_ok
        fp.tls               = tls_ok
        if not fp.responding:
            return fp

        info = self.read_connack_info(ip, port)
        fp.anonymous_access  = info.get("anonymous_access", False)
        fp.broker_software   = info.get("broker_software", "")

        if not fp.anonymous_access:
            fp.error = "Authentication required — limited enumeration"
            return fp

        # $SYS metadata
        sys_data = self._enumerate_sys_topics(ip, port)
        if "version" in sys_data:
            fp.broker_version = sys_data["version"]

        if not PAHO_AVAILABLE:
            fp.wildcard_sub_allowed = True   # Assume if anon access works
            return fp

        # Wildcard subscribe — collect all topics
        all_topics  = []
        done_event  = threading.Event()

        def on_msg(client, userdata, msg):
            all_topics.append(msg.topic)
            if len(all_topics) >= 500:
                done_event.set()

        def on_conn(client, userdata, flags, rc):
            if rc == 0:
                client.subscribe("#", 0)
                fp.wildcard_sub_allowed = True

        try:
            c = mqtt.Client(client_id="ros2reaper_enum")
            c.on_connect = on_conn
            c.on_message = on_msg
            c.connect(ip, port, keepalive=30)
            c.loop_start()
            done_event.wait(timeout=self.enum_duration)
            c.loop_stop()
            c.disconnect()
        except Exception as e:
            fp.error = str(e)

        fp.topics_discovered = list(set(all_topics))

        # Classify discovered topics
        for topic in fp.topics_discovered:
            # Sparkplug B
            m = SPARKPLUG_TOPIC_RE.match(topic)
            if m:
                ns = f"{m.group('group')}/{m.group('node')}"
                if ns not in fp.sparkplug_namespaces:
                    fp.sparkplug_namespaces.append(ns)

            # ICS process data patterns
            for pattern in ICS_MQTT_TOPIC_PATTERNS:
                if re.search(pattern, topic, re.IGNORECASE):
                    if topic not in fp.ics_topics:
                        fp.ics_topics.append(topic)
                    break

            # DDS bridge hint: topics containing "dds", "rtps", "ros"
            if any(kw in topic.lower() for kw in ["dds", "rtps", "ros", "domain", "participant"]):
                fp.bridge_topics.append(topic)

        fp.will_injection_viable = fp.anonymous_access

        return fp


# ─────────────────────────────────────────────────────────────────────────────
# ETHERCAT PROBER
# ─────────────────────────────────────────────────────────────────────────────

class EtherCATProber:
    """
    EtherCAT Automation Protocol (EAP) prober over UDP/34980.
    Also checks for co-located processes that suggest an EtherCAT Master
    with a DDS bridge (TwinCAT ADS port, SOEM signals, etc.).
    """

    # TwinCAT ADS port — if open alongside EAP, almost certainly Beckhoff TwinCAT
    TWINCAT_ADS_PORT = 48898    # TCP (AMS Router)
    TWINCAT_ADS_UDP  = 48899    # UDP

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def _udp_probe(self, ip: str, port: int,
                    payload: bytes = b"\x00\x00") -> Optional[bytes]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.sendto(payload, (ip, port))
            data, _ = s.recvfrom(512)
            s.close()
            return data
        except socket.timeout:
            # UDP timeout is ambiguous — port may be firewalled or just not responding
            return None
        except (ConnectionRefusedError, OSError):
            return None

    def _tcp_open(self, ip: str, port: int) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return r == 0
        except OSError:
            return False

    def confirm_eap(self, ip: str, port: int = ETHERCAT_EAP_PORT) -> bool:
        """
        Send an EAP identify request and check for any UDP response.
        EAP uses a specific frame structure; any response on 34980 is
        a strong EtherCAT indicator.
        """
        resp = self._udp_probe(ip, port, EAP_IDENTITY_REQUEST)
        return resp is not None and len(resp) >= 4

    def detect_twincat(self, ip: str) -> bool:
        """Check for Beckhoff TwinCAT ADS ports — the dominant EtherCAT+DDS platform."""
        return (self._tcp_open(ip, self.TWINCAT_ADS_PORT) or
                self._udp_probe(ip, self.TWINCAT_ADS_UDP) is not None)

    def full_fingerprint(self, ip: str, deep: bool = False) -> EtherCATFingerprint:
        fp = EtherCATFingerprint(host=ip, port=ETHERCAT_EAP_PORT)

        # EAP confirmation
        if self.confirm_eap(ip):
            fp.responding    = True
            fp.eap_confirmed = True

        # TwinCAT detection
        if self.detect_twincat(ip):
            fp.responding          = True
            fp.master_software     = "Beckhoff TwinCAT (ADS detected)"
            fp.dds_bridge_detected = True   # TwinCAT has native DDS/ADS bridge support

        if not fp.responding:
            return fp

        # Deep mode: try to read EAP slave list
        if deep and fp.eap_confirmed:
            # EAP GetSlaveList request (vendor-specific, Beckhoff protocol)
            # This is a best-effort probe — many non-Beckhoff EAP stacks ignore it
            get_slave_req = struct.pack("<HHI", 0x0002, 0x0000, 0x00000000)
            resp = self._udp_probe(ip, ETHERCAT_EAP_PORT, get_slave_req)
            if resp and len(resp) >= 8:
                try:
                    slave_count = struct.unpack_from("<H", resp, 4)[0]
                    if 0 < slave_count < 256:
                        fp.slave_count = slave_count
                except Exception:
                    pass

        return fp


# ─────────────────────────────────────────────────────────────────────────────
# BRIDGE ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class MQTTEtherCATBridgeAnalyzer:
    """
    Correlates DDS, MQTT, and EtherCAT presence and produces
    a bridge attack surface report with applicable scenarios.
    """

    def analyze(
        self,
        ip:              str,
        dds_ports:       list,
        mqtt_fp:         Optional[MQTTFingerprint],
        ethercat_fp:     Optional[EtherCATFingerprint],
        other_protocols: dict,
    ) -> MQTTEtherCATBridgeReport:

        report = MQTTEtherCATBridgeReport(
            ip               = ip,
            dds_ports_open   = dds_ports,
            mqtt_ports_open  = [mqtt_fp.port] if mqtt_fp and mqtt_fp.responding else [],
            ethercat_ports_open = [ethercat_fp.port] if ethercat_fp and ethercat_fp.responding else [],
            other_protocols  = other_protocols,
        )

        if mqtt_fp:
            report.mqtt_fingerprint      = asdict(mqtt_fp)
        if ethercat_fp:
            report.ethercat_fingerprint  = asdict(ethercat_fp)

        has_dds      = bool(dds_ports)
        has_mqtt     = bool(mqtt_fp and mqtt_fp.responding)
        has_ethercat = bool(ethercat_fp and ethercat_fp.responding)

        if not has_dds or (not has_mqtt and not has_ethercat):
            report.risk_level = "LOW" if not has_dds else "MEDIUM"
            return report

        # ── MQTT bridge assessment ─────────────────────────────────────────────
        if has_mqtt:
            report.bridge_evidence.append(
                f"DDS ports {dds_ports} + MQTT port {mqtt_fp.port} on same host"
            )
            report.applicable_mqtt_scenarios = MQTT_DDS_ATTACK_SCENARIOS.copy()

            if mqtt_fp.bridge_topics:
                report.bridge_confirmed = True
                report.bridge_evidence.append(
                    f"DDS-referencing MQTT topics found: {mqtt_fp.bridge_topics[:3]}"
                )

            if mqtt_fp.sparkplug_namespaces:
                report.bridge_confirmed = True
                report.bridge_evidence.append(
                    f"Sparkplug B namespace(s): {mqtt_fp.sparkplug_namespaces[:3]}"
                )

            # Guess bridge product from broker software
            bs = mqtt_fp.broker_software.lower()
            for key, product in KNOWN_MQTT_BRIDGE_PRODUCTS.items():
                if any(kw in bs for kw in key.split("_")):
                    report.mqtt_bridge_product_guess = product
                    break

            if mqtt_fp.anonymous_access:
                report.findings.append({
                    "id":     "MQTT-SEC-001",
                    "title":  "MQTT Broker Allows Anonymous Access",
                    "detail": (
                        f"MQTT broker at {ip}:{mqtt_fp.port} accepts connections "
                        "without credentials. Any client can subscribe to all topics "
                        "and publish to any topic — including DDS-bridged control channels."
                    ),
                    "cvss":   "9.1",
                    "cwe":    "CWE-306",
                    "mitre":  "T0830",
                })

            if mqtt_fp.wildcard_sub_allowed:
                report.findings.append({
                    "id":     "MQTT-SEC-002",
                    "title":  "MQTT Wildcard Subscribe Permitted",
                    "detail": (
                        f"MQTT broker at {ip}:{mqtt_fp.port} permits '#' wildcard "
                        "subscriptions. All process data flowing through the DDS bridge "
                        "is accessible to any connected client."
                    ),
                    "cvss":   "7.5",
                    "cwe":    "CWE-200",
                    "mitre":  "T0830",
                })

            if mqtt_fp.ics_topics:
                report.findings.append({
                    "id":     "MQTT-SEC-003",
                    "title":  f"ICS Process Data Topics Discovered ({len(mqtt_fp.ics_topics)})",
                    "detail": (
                        f"ICS-pattern topics found on MQTT broker: "
                        f"{', '.join(mqtt_fp.ics_topics[:5])}"
                        f"{'...' if len(mqtt_fp.ics_topics) > 5 else ''}"
                    ),
                    "cvss":   "6.5",
                    "cwe":    "CWE-200",
                    "mitre":  "T0832",
                })

            if not mqtt_fp.tls:
                report.findings.append({
                    "id":     "MQTT-SEC-004",
                    "title":  "MQTT Plaintext — No TLS",
                    "detail": (
                        f"MQTT broker at {ip}:{mqtt_fp.port} communicates in plaintext. "
                        "All process data, credentials (if any), and DDS-bridged messages "
                        "are exposed to network interception."
                    ),
                    "cvss":   "5.9",
                    "cwe":    "CWE-319",
                    "mitre":  "T0830",
                })

            # PoC chain
            report.recommended_poc.append({
                "title":   "MQTT Topic Enumeration + Sparkplug B Injection Chain",
                "steps": [
                    "1. mosquitto_sub -h {ip} -t '#' -v  (wildcard subscribe, enumerate all topics)",
                    "2. Identify Sparkplug B DCMD topic: spBv1.0/<group>/DCMD/<node>/<device>",
                    "3. Craft Sparkplug B protobuf payload with target metric write",
                    "4. mosquitto_pub -h {ip} -t '<dcmd_topic>' -m '<payload>'",
                    "5. Observe NBIRTH/NDATA response confirming command execution",
                ],
                "tool_chain": "mosquitto_sub (enum) → protobuf craft → mosquitto_pub (inject)",
                "dependencies": "mosquitto-clients, sparkplug-b protobuf schema",
            })

        # ── EtherCAT bridge assessment ─────────────────────────────────────────
        if has_ethercat:
            report.bridge_evidence.append(
                f"DDS ports {dds_ports} + EtherCAT on {ethercat_fp.host}"
            )
            report.applicable_ethercat_scenarios = ETHERCAT_DDS_ATTACK_SCENARIOS.copy()

            if ethercat_fp.dds_bridge_detected:
                report.bridge_confirmed = True
                report.bridge_evidence.append(
                    f"EtherCAT Master software indicates DDS bridge: {ethercat_fp.master_software}"
                )
                report.ethercat_bridge_product_guess = ethercat_fp.master_software

            elif has_ethercat:
                # EtherCAT + DDS coexistence is strong bridge signal
                report.bridge_confirmed = True
                report.bridge_evidence.append(
                    "EtherCAT + DDS coexistence — common bridge topology in motion control"
                )

            report.findings.append({
                "id":     "ECAT-SEC-001",
                "title":  "EtherCAT Master with DDS Bridge — Real-Time Physical Impact",
                "detail": (
                    f"Host {ip} appears to be an EtherCAT Master bridged to DDS. "
                    "DDS topic writes propagate into the EtherCAT PDO exchange within "
                    "milliseconds. Servo drive control word overrides and digital output "
                    "changes take effect in the next EtherCAT cycle."
                ),
                "cvss":   "9.8",
                "cwe":    "CWE-284",
                "mitre":  "T0831",
            })

            if ethercat_fp.slave_count > 0:
                report.findings.append({
                    "id":     "ECAT-SEC-002",
                    "title":  f"EtherCAT Slave Count: {ethercat_fp.slave_count} devices",
                    "detail": (
                        f"EAP enumeration found {ethercat_fp.slave_count} EtherCAT slaves. "
                        "Each slave is a potential actuation target — drives, I/O modules, "
                        "encoders, safety cards."
                    ),
                    "cvss":   "6.5",
                    "cwe":    "CWE-200",
                    "mitre":  "T0840",
                })

            report.recommended_poc.append({
                "title":   "EtherCAT PDO Override via DDS Write Chain",
                "steps": [
                    "1. Run ics_dds_enum.py --target {ip} --deep to enumerate DDS topics",
                    "2. Identify topics mapped to servo drive control (joint/position/velocity)",
                    "3. Parse topic type from RTPS SEDP metadata (PDO object indices)",
                    "4. Inject DDS DATA submessage with target position = current ± Δ",
                    "5. EtherCAT Master cycles the new value to slave in <4ms",
                    "6. Verify via DDS read-back (position feedback topic)",
                ],
                "tool_chain": "ics_dds_enum.py → rtps_scanner.py → [PDO write topic] → feedback verify",
                "dependencies": "ROS2Reaper Phase 1+3 modules, network access to DDS domain",
            })

        # ── Cross-protocol bridge (MQTT + EtherCAT + DDS) ─────────────────────
        if has_mqtt and has_ethercat:
            report.findings.append({
                "id":     "CROSS-001",
                "title":  "Triple Bridge: DDS + MQTT + EtherCAT on Single Host",
                "detail": (
                    f"Host {ip} bridges DDS, MQTT, AND EtherCAT. This is a gateway "
                    "node connecting IT (MQTT/cloud), OT middleware (DDS), and fieldbus "
                    "(EtherCAT). Compromise of the DDS domain provides lateral movement "
                    "paths to both the MQTT broker (cloud/SCADA upstream) and EtherCAT "
                    "slaves (physical actuators downstream)."
                ),
                "cvss":   "10.0",
                "cwe":    "CWE-441",
                "mitre":  "T0831 + T0832 — Manipulation of Control + View",
            })

        # ── Risk level ────────────────────────────────────────────────────────
        max_cvss = max(
            (float(f.get("cvss", "0")) for f in report.findings),
            default=0.0,
        )
        if max_cvss >= 9.5:
            report.risk_level = "CRITICAL"
        elif max_cvss >= 7.0:
            report.risk_level = "HIGH"
        elif max_cvss >= 4.0:
            report.risk_level = "MEDIUM"
        else:
            report.risk_level = "LOW"

        return report


# ─────────────────────────────────────────────────────────────────────────────
# PORT CHECKER
# ─────────────────────────────────────────────────────────────────────────────

class PortChecker:
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
            return True
        except (ConnectionRefusedError, OSError):
            return False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class MQTTEtherCATBridgeScanner:
    """
    Orchestrates DDS + MQTT + EtherCAT coexistence detection,
    protocol fingerprinting, and bridge attack surface analysis.
    """

    def __init__(self, args):
        self.args       = args
        self.checker    = PortChecker()
        self.mqtt_p     = MQTTProber(
            timeout      = args.timeout,
            enum_duration = getattr(args, "enum_duration", 10.0),
        )
        self.ecat_p     = EtherCATProber(timeout=args.timeout)
        self.analyzer   = MQTTEtherCATBridgeAnalyzer()
        self.results    = []

    def scan_host(self, ip: str) -> Optional[MQTTEtherCATBridgeReport]:
        # DDS UDP
        dds_open  = [p for p in DDS_DISC_PORTS if self.checker.udp_probe(ip, p)]

        # MQTT TCP
        mqtt_open = [p for p in MQTT_PORTS if self.checker.tcp_open(ip, p)]

        # EtherCAT UDP/EAP
        ecat_open = []
        for p in [ETHERCAT_EAP_PORT] + ETHERCAT_ALT_PORTS:
            if self.checker.udp_probe(ip, p, EAP_IDENTITY_REQUEST):
                ecat_open.append(p)

        if not dds_open and not mqtt_open and not ecat_open:
            return None

        print(f"  [+] {ip} | DDS:{dds_open} | MQTT:{mqtt_open} | EtherCAT:{ecat_open}")

        # Fingerprint MQTT
        mqtt_fp = None
        if mqtt_open:
            if self.args.mqtt_enumerate:
                mqtt_fp = self.mqtt_p.enumerate_topics(ip, mqtt_open[0])
            else:
                # Quick fingerprint only
                mqtt_fp              = MQTTFingerprint(host=ip, port=mqtt_open[0])
                plain_ok, tls_ok     = self.mqtt_p.confirm_mqtt(ip, mqtt_open[0])
                mqtt_fp.responding   = plain_ok or tls_ok
                mqtt_fp.tls          = tls_ok
                if mqtt_fp.responding:
                    info = self.mqtt_p.read_connack_info(ip, mqtt_open[0])
                    mqtt_fp.anonymous_access = info.get("anonymous_access", False)
                    mqtt_fp.broker_software  = info.get("broker_software", "")

        # Fingerprint EtherCAT
        ethercat_fp = None
        if ecat_open or self.ecat_p.detect_twincat(ip):
            ethercat_fp = self.ecat_p.full_fingerprint(ip, deep=self.args.deep)

        # Other protocols (deep mode)
        other = {}
        if self.args.deep:
            for proto, ports in [("OPC-UA",    OPCUA_PORTS),
                                   ("AMQP",      AMQP_PORTS),
                                   ("MQTT-WS",   MQTT_WS_PORTS)]:
                found = [p for p in ports if self.checker.tcp_open(ip, p)]
                if found:
                    other[proto] = found

        return self.analyzer.analyze(ip, dds_open, mqtt_fp, ethercat_fp, other)

    def run(self) -> list:
        targets = []
        if self.args.target:
            targets = [self.args.target]
        elif self.args.cidr:
            net     = ipaddress.ip_network(self.args.cidr, strict=False)
            targets = [str(h) for h in net.hosts()]
            print(f"[*] Sweeping {self.args.cidr} ({len(targets)} hosts)")

        print(f"\n{'='*60}")
        print("  ROS2Reaper :: Phase 3 — MQTT/EtherCAT Bridge Scanner")
        print(f"{'='*60}\n")

        if not PAHO_AVAILABLE:
            print("[!] paho-mqtt not installed — MQTT topic enumeration disabled")
            print("[!] Install with: pip install paho-mqtt\n")

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
        print("  MQTT/ETHERCAT BRIDGE SCAN SUMMARY")
        print(f"{'='*60}")

        bridge_hosts = [r for r in self.results if r.bridge_confirmed]
        crit_hosts   = [r for r in self.results if r.risk_level == "CRITICAL"]

        print(f"  Bridge hosts detected : {len(bridge_hosts)}")
        print(f"  Critical risk         : {len(crit_hosts)}")

        for r in crit_hosts:
            print(f"\n  ⚠  {r.ip} [{r.risk_level}]")
            print(f"     DDS:{r.dds_ports_open}  MQTT:{r.mqtt_ports_open}  "
                  f"EtherCAT:{r.ethercat_ports_open}")
            for f in r.findings:
                print(f"     [{f['id']}] {f['title']} (CVSS {f['cvss']})")
            if r.mqtt_bridge_product_guess:
                print(f"     MQTT bridge: {r.mqtt_bridge_product_guess}")
            if r.ethercat_bridge_product_guess:
                print(f"     EtherCAT bridge: {r.ethercat_bridge_product_guess}")

        print(f"\n  MQTT attack scenarios     : {len(MQTT_DDS_ATTACK_SCENARIOS)}")
        for s in MQTT_DDS_ATTACK_SCENARIOS:
            print(f"    [{s['id']}] {s['name']} — CVSS {s['cvss']}")

        print(f"\n  EtherCAT attack scenarios : {len(ETHERCAT_DDS_ATTACK_SCENARIOS)}")
        for s in ETHERCAT_DDS_ATTACK_SCENARIOS:
            print(f"    [{s['id']}] {s['name']} — CVSS {s['cvss']}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ROS2Reaper Phase 3 — MQTT/EtherCAT ↔ DDS Bridge Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 mqtt_ethercat_bridge.py --target 10.0.0.5
    python3 mqtt_ethercat_bridge.py --cidr 192.168.1.0/24 --deep
    python3 mqtt_ethercat_bridge.py --target 10.0.0.5 --mqtt-enumerate
    python3 mqtt_ethercat_bridge.py --cidr 10.52.32.0/24 --output bridge.json

    # Full Phase 3 pipeline
    python3 ics_dds_enum.py       --cidr 10.52.32.0/24 --output ics.json
    python3 modbus_dnp3_bridge.py --cidr 10.52.32.0/24 --output modbus.json
    python3 opcua_dds_bridge.py   --cidr 10.52.32.0/24 --output opcua.json
    python3 mqtt_ethercat_bridge.py --cidr 10.52.32.0/24 --output mqtt.json
        """
    )
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target", help="Single target IP")
    tgt.add_argument("--cidr",   help="CIDR range")

    p.add_argument("--timeout",         type=float, default=3.0)
    p.add_argument("--threads",         type=int,   default=30)
    p.add_argument("--deep",            action="store_true",
                   help="Deep probe: EtherCAT slave scan + co-protocol detection")
    p.add_argument("--mqtt-enumerate",  action="store_true", dest="mqtt_enumerate",
                   help="Full MQTT topic enumeration via wildcard subscribe (requires paho-mqtt)")
    p.add_argument("--enum-duration",   type=float, default=10.0, dest="enum_duration",
                   help="Seconds to listen for MQTT topics (default: 10)")
    p.add_argument("--output",          metavar="FILE", help="Write JSON report to file")
    return p.parse_args()


def main():
    args    = parse_args()
    scanner = MQTTEtherCATBridgeScanner(args)
    results = scanner.run()

    if args.output:
        with open(args.output, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"[+] Report saved → {args.output}")


if __name__ == "__main__":
    main()
