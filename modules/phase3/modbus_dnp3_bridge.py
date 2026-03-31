#!/usr/bin/env python3
"""
modbus_dnp3_bridge.py — Modbus/DNP3 ↔ DDS Bridge Attack Surface Analyzer
==========================================================================
ROS2Reaper Phase 3 Module

Detects hosts running DDS alongside Modbus TCP or DNP3, characterizes the
bridge attack surface, and generates PoC attack scenarios for crossing from
the DDS domain into field-level OT protocols.

Why this matters:
    Modbus and DNP3 are the dominant field-level protocols in power, water,
    oil & gas, and manufacturing SCADA. Modern ICS modernization projects
    increasingly bridge these legacy protocols to DDS for real-time data
    distribution. A compromised DDS participant on the IT-adjacent side can
    write coils/registers (Modbus) or issue DNP3 control operations through
    the bridge — reaching physical actuators, breakers, and RTUs that were
    never designed to authenticate commands.

Modbus TCP default port : 502
DNP3 default port       : 20000 (TCP/UDP)
DDS discovery port      : 7400+ (UDP)

Author  : Gh057x
Phase   : 3 — ICS/OT Bridge
Requires: pymodbus (optional, degrades gracefully)

Usage:
    python3 modbus_dnp3_bridge.py --target 10.0.0.5
    python3 modbus_dnp3_bridge.py --cidr 192.168.1.0/24 --deep
    python3 modbus_dnp3_bridge.py --target 10.0.0.5 --modbus-enumerate
    python3 modbus_dnp3_bridge.py --target 10.0.0.5 --output report.json
"""

import socket
import struct
import time
import json
import argparse
import sys
import threading
import ipaddress
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

# pymodbus is optional
try:
    from pymodbus.client import ModbusTcpClient
    from pymodbus.exceptions import ModbusException
    PYMODBUS_AVAILABLE = True
except ImportError:
    PYMODBUS_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MODBUS_PORTS        = [502, 503, 5020]
DNP3_PORTS          = [20000, 19999, 20001]
DDS_DISC_PORTS      = [7400, 7410, 7650, 7660, 8650, 8660]
ENIP_PORTS          = [44818, 2222]     # EtherNet/IP (often co-located)
S7_PORTS            = [102]             # Siemens S7
BACNET_PORTS        = [47808]           # BACnet/IP UDP

# Modbus function codes (for enumeration and fingerprinting)
MODBUS_FC = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x2B: "Read Device Identification",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x18: "Read FIFO Queue",
}

# DNP3 application layer function codes
DNP3_FC = {
    0x00: "Confirm",
    0x01: "Read",
    0x02: "Write",
    0x03: "Select",
    0x04: "Operate",
    0x05: "Direct Operate",
    0x06: "Direct Operate No Ack",
    0x07: "Immed Freeze",
    0x08: "Immed Freeze No Ack",
    0x09: "Freeze Clear",
    0x0A: "Freeze Clear No Ack",
    0x0B: "Freeze at Time",
    0x0C: "Freeze at Time No Ack",
    0x0D: "Cold Restart",
    0x0E: "Warm Restart",
    0x0F: "Initialize Data",
    0x10: "Initialize Appl",
    0x11: "Start Appl",
    0x12: "Stop Appl",
    0x13: "Save Config",
    0x14: "Enable Unsolicited",
    0x15: "Disable Unsolicited",
    0x16: "Assign Class",
    0x17: "Delay Measure",
    0x18: "Record Current Time",
    0x19: "Open File",
    0x1A: "Close File",
    0x1B: "Delete File",
    0x1C: "Get File Info",
    0x1D: "Authenticate File",
    0x1E: "Abort File",
    0x1F: "Activate Config",
    0x20: "Authentication Request",
    0x21: "Authentication Error",
    0x81: "Response",
    0x82: "Unsolicited Response",
    0x83: "Authentication Response",
}

# DNP3 object groups of interest for ICS impact assessment
DNP3_CRITICAL_GROUPS = {
    12: "Binary Output Command (CROB) — direct actuator control",
    41: "Analog Output Command — setpoint write",
    30: "Analog Input (read process values)",
    1:  "Binary Input (read digital status)",
    2:  "Binary Input Change (event-driven status)",
    20: "Counter",
    10: "Binary Output Status",
    40: "Analog Output Status",
}

# Known Modbus/DNP3 ↔ DDS bridge products
KNOWN_BRIDGE_PRODUCTS = {
    "rti_modbus":      "RTI Connext DDS Modbus Adapter",
    "kepware_dds":     "Kepware KEPServerEX DDS Driver",
    "matrikon_dds":    "Matrikon DDS Connector (Modbus/DNP3)",
    "skkynet_dds":     "Skkynet DataHub DDS Bridge",
    "factoryio_dds":   "Factory I/O DDS Integration",
    "fledge_dds":      "LF Edge Fledge DDS South Plugin",
    "oss_dnp3_dds":    "OpenDNP3 / opendnp3-dds-bridge (GitHub)",
    "ignition_dds":    "Inductive Automation Ignition + DDS Module",
}


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────

MODBUS_DDS_ATTACK_SCENARIOS = [
    {
        "id":            "MODB-001",
        "name":          "DDS→Modbus Coil Write (Actuator Manipulation)",
        "description":   (
            "Write to a DDS topic mapped to a Modbus coil (FC05/FC0F). The bridge "
            "translates the DDS message into a Modbus write command targeting a "
            "specific Unit ID and coil address. Impact depends on what the coil "
            "controls — could be a relay, valve, motor starter, or safety interlock."
        ),
        "dds_topic_pattern": r"/(coil|output|do_|digital_out|relay|valve|motor)",
        "modbus_fc":     "FC05 / FC0F — Write Coil(s)",
        "modbus_target": "Coil address range (0x0000–0xFFFF)",
        "impact":        "Direct actuator on/off control without operator awareness",
        "cvss":          "9.3",
        "cwe":           "CWE-284",
        "mitre_ics":     "T0831 — Manipulation of Control",
        "ics_sectors":   ["power", "water", "manufacturing", "oil_gas"],
    },
    {
        "id":            "MODB-002",
        "name":          "DDS→Modbus Holding Register Write (Setpoint Override)",
        "description":   (
            "Write to a DDS topic mapped to a Modbus holding register (FC06/FC10). "
            "Bridge translates to a register write targeting process setpoints: "
            "temperature limits, pressure thresholds, flow rates, PID tuning params. "
            "Attacker can override safety limits while displaying nominal values to HMI."
        ),
        "dds_topic_pattern": r"/(setpoint|sp_|register|holding|analog_out|ao_|parameter)",
        "modbus_fc":     "FC06 / FC10 — Write Register(s)",
        "modbus_target": "Holding register range (4x references, 0x0000+)",
        "impact":        "Safety limit bypass, process parameter manipulation",
        "cvss":          "9.1",
        "cwe":           "CWE-284",
        "mitre_ics":     "T0831 — Manipulation of Control",
        "ics_sectors":   ["power", "water", "oil_gas", "chemical"],
    },
    {
        "id":            "MODB-003",
        "name":          "Modbus→DDS Historian Poisoning (Reverse Bridge)",
        "description":   (
            "Subscribe on the DDS side to topics bridged from Modbus input registers "
            "(FC04) or input coils (FC02). Inject fabricated readings that the bridge "
            "publishes upstream — corrupting SCADA historian records and masking the "
            "real process state from operators and compliance systems."
        ),
        "dds_topic_pattern": r"/(measurement|ai_|analog_in|input_reg|reading|sensor)",
        "modbus_fc":     "FC01 / FC02 / FC03 / FC04 — Read operations (reverse)",
        "modbus_target": "Input registers / input coils (1x, 3x references)",
        "impact":        "Historian record corruption, operator situational awareness loss",
        "cvss":          "7.5",
        "cwe":           "CWE-494",
        "mitre_ics":     "T0832 — Manipulation of View",
        "ics_sectors":   ["all"],
    },
    {
        "id":            "MODB-004",
        "name":          "Modbus Unit ID Scan via DDS Discovery Metadata",
        "description":   (
            "Parse DDS participant properties and topic metadata for Unit ID mappings "
            "exposed by the bridge configuration. Many bridge implementations publish "
            "their Modbus device map in DDS participant properties for auto-discovery. "
            "Extract unit IDs, register maps, and device types without sending a single "
            "Modbus packet."
        ),
        "dds_topic_pattern": r"/(device|unit_id|slave|modbus_map|register_map)",
        "modbus_fc":     "N/A — metadata exfil only",
        "modbus_target": "DDS participant property list",
        "impact":        "Full Modbus device map enumeration with zero Modbus traffic",
        "cvss":          "6.5",
        "cwe":           "CWE-200",
        "mitre_ics":     "T0840 — Network Connection Enumeration",
        "ics_sectors":   ["all"],
    },
    {
        "id":            "MODB-005",
        "name":          "Bridge Flood DoS (DDS→Modbus Rate Exhaustion)",
        "description":   (
            "Flood a bridged DDS write topic with high-frequency updates. The bridge "
            "serializes these into sequential Modbus TCP requests. Modbus TCP has no "
            "rate limiting — the target PLC/RTU transaction counter wraps, legitimate "
            "SCADA poll cycles time out, and the device may enter a fault/safe state."
        ),
        "dds_topic_pattern": r".*",   # any writable bridged topic
        "modbus_fc":     "FC05 / FC06 / FC10 — Write operations",
        "modbus_target": "Any writable register/coil range",
        "impact":        "PLC DoS, poll cycle disruption, device fault state",
        "cvss":          "7.5",
        "cwe":           "CWE-400",
        "mitre_ics":     "T0814 — Denial of Control",
        "ics_sectors":   ["all"],
    },
]

DNP3_DDS_ATTACK_SCENARIOS = [
    {
        "id":            "DNP3-001",
        "name":          "DDS→DNP3 CROB (Direct Binary Output Control)",
        "description":   (
            "Write to a DDS topic mapped to a DNP3 Binary Output Command (CROB, "
            "Group 12). The bridge issues a DNP3 Select-Before-Operate or Direct "
            "Operate sequence to the target outstation. CROBs can energize/de-energize "
            "breakers, switches, and pumps with millisecond response times."
        ),
        "dds_topic_pattern": r"/(binary_out|crob|breaker|switch|contactor|trip|close)",
        "dnp3_group":    "Group 12 — Binary Output Command (CROB)",
        "dnp3_fc":       "FC03 (Select) + FC04 (Operate) or FC05 (Direct Operate)",
        "impact":        "Breaker trip, switch operation, equipment de-energization",
        "cvss":          "9.8",
        "cwe":           "CWE-284",
        "mitre_ics":     "T0831 — Manipulation of Control",
        "ics_sectors":   ["power", "water", "oil_gas"],
    },
    {
        "id":            "DNP3-002",
        "name":          "DDS→DNP3 Analog Output Setpoint (Group 41)",
        "description":   (
            "Write to a DDS topic bridged to a DNP3 Analog Output (Group 41 Var1–4). "
            "Targets include governor setpoints, transformer tap positions, valve "
            "position demands, and PID setpoints. No authentication required by "
            "default DNP3 — command is accepted without challenge."
        ),
        "dds_topic_pattern": r"/(analog_out|setpoint|demand|tap_pos|governor|avr_)",
        "dnp3_group":    "Group 41 — Analog Output Block",
        "dnp3_fc":       "FC03 / FC04 / FC05 — Select/Operate/DirectOperate",
        "impact":        "Continuous process variable manipulation with physical consequence",
        "cvss":          "9.1",
        "cwe":           "CWE-284",
        "mitre_ics":     "T0831 — Manipulation of Control",
        "ics_sectors":   ["power", "water", "oil_gas"],
    },
    {
        "id":            "DNP3-003",
        "name":          "DDS→DNP3 Unsolicited Response Disable",
        "description":   (
            "Inject a DDS message bridged to a DNP3 Disable Unsolicited (FC15) "
            "command. The outstation stops sending spontaneous event reports to "
            "the master station. The SCADA system loses real-time awareness of "
            "field device state changes — alarms and change events are silently "
            "dropped."
        ),
        "dds_topic_pattern": r"/(unsolicited|event_report|spontaneous|disable_unsolicit)",
        "dnp3_group":    "N/A — application function code",
        "dnp3_fc":       "FC15 — Disable Unsolicited",
        "impact":        "Loss of real-time event visibility, silent alarm suppression",
        "cvss":          "8.2",
        "cwe":           "CWE-693",
        "mitre_ics":     "T0878 — Alarm Suppression",
        "ics_sectors":   ["power", "water"],
    },
    {
        "id":            "DNP3-004",
        "name":          "DDS→DNP3 Cold/Warm Restart (Outstation Reboot)",
        "description":   (
            "Inject a DDS message mapped to a DNP3 Cold Restart (FC0D) or Warm "
            "Restart (FC0E) command. Causes the target RTU/IED to reboot, clearing "
            "accumulated event buffers and creating a detection-resistant disruption "
            "window. On some outstations, restart triggers a failsafe output state."
        ),
        "dds_topic_pattern": r"/(restart|reboot|reset|cold_restart|warm_restart)",
        "dnp3_group":    "N/A — application function code",
        "dnp3_fc":       "FC0D — Cold Restart / FC0E — Warm Restart",
        "impact":        "RTU/IED reboot, event buffer loss, failsafe state trigger",
        "cvss":          "8.6",
        "cwe":           "CWE-284",
        "mitre_ics":     "T0839 — Module Firmware / T0816 — Device Restart",
        "ics_sectors":   ["power", "water", "oil_gas"],
    },
    {
        "id":            "DNP3-005",
        "name":          "DNP3 SA Bypass via DDS Bridge (Pre-SAv5 Outstations)",
        "description":   (
            "DNP3 Secure Authentication (SAv5, IEEE 1815-2012) challenges commands "
            "at the DNP3 transport layer. However, if the DDS-DNP3 bridge is trusted "
            "as a 'master' and the bridge itself has no DDS authentication, an attacker "
            "can inject commands via DDS that the bridge forwards without triggering "
            "the SA challenge — effectively bypassing DNP3 SA."
        ),
        "dds_topic_pattern": r"/(cmd_|control_|operate_|select_)",
        "dnp3_group":    "Any control group",
        "dnp3_fc":       "FC03/FC04/FC05",
        "impact":        "DNP3 SA authentication bypass via trusted bridge node",
        "cvss":          "9.4",
        "cwe":           "CWE-306",
        "mitre_ics":     "T0831 — Manipulation of Control",
        "ics_sectors":   ["power", "water"],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ModbusFingerprint:
    """Result of Modbus TCP fingerprinting on a host."""
    host:                str
    port:                int
    responding:          bool               = False
    device_id_string:    str                = ""
    vendor_name:         str                = ""
    product_code:        str                = ""
    firmware_version:    str                = ""
    supported_fcs:       list               = field(default_factory=list)
    readable_coils:      Optional[tuple]    = None   # (start, count)
    readable_registers:  Optional[tuple]    = None
    writable_coils:      bool               = False
    writable_registers:  bool               = False
    unit_ids_responding: list               = field(default_factory=list)
    exception_responses: dict               = field(default_factory=dict)
    error:               str                = ""


@dataclass
class DNP3Fingerprint:
    """Result of DNP3 probing on a host."""
    host:                str
    port:                int
    responding:          bool               = False
    master_address:      int                = 3      # attacker poses as master 3
    outstation_address:  int                = 0
    link_layer_confirmed: bool             = False
    app_layer_confirmed: bool              = False
    device_attributes:   dict              = field(default_factory=dict)
    supports_sa:         bool              = False
    sa_version:          int               = 0
    object_groups_found: list              = field(default_factory=list)
    error:               str               = ""


@dataclass
class ModbusDNP3BridgeReport:
    """Full analysis report for a host with DDS + Modbus/DNP3."""
    ip:                   str
    scan_time:            str              = field(default_factory=lambda: datetime.now().isoformat())
    dds_ports_open:       list             = field(default_factory=list)
    modbus_ports_open:    list             = field(default_factory=list)
    dnp3_ports_open:      list             = field(default_factory=list)
    other_protocols:      dict             = field(default_factory=dict)
    modbus_fingerprint:   Optional[dict]   = None
    dnp3_fingerprint:     Optional[dict]   = None
    bridge_confirmed:     bool             = False
    bridge_product_guess: str             = ""
    bridge_evidence:      list             = field(default_factory=list)
    applicable_modbus_scenarios: list     = field(default_factory=list)
    applicable_dnp3_scenarios:   list     = field(default_factory=list)
    risk_level:           str              = "UNKNOWN"
    findings:             list             = field(default_factory=list)
    recommended_poc:      list             = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# MODBUS PROBER
# ─────────────────────────────────────────────────────────────────────────────

class ModbusProber:
    """
    Raw Modbus TCP prober. Falls back to pymodbus for full enumeration
    if available; otherwise uses raw socket for basic confirmation.
    """

    MBAP_TRANSACTION_ID = 0x0001
    MBAP_PROTOCOL_ID    = 0x0000
    UNIT_ID_BROADCAST   = 0xFF

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def _build_mbap(self, pdu: bytes, unit_id: int = 0xFF) -> bytes:
        """Build a Modbus Application Protocol header + PDU."""
        length = len(pdu) + 1   # +1 for unit ID
        mbap = struct.pack(
            ">HHHB",
            self.MBAP_TRANSACTION_ID,
            self.MBAP_PROTOCOL_ID,
            length,
            unit_id,
        )
        return mbap + pdu

    def _send_recv(self, ip: str, port: int, payload: bytes) -> Optional[bytes]:
        """Send a Modbus TCP request and return the response bytes."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.sendall(payload)
            resp = sock.recv(512)
            sock.close()
            return resp if len(resp) >= 8 else None
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def confirm_modbus(self, ip: str, port: int) -> bool:
        """
        Send FC03 (Read Holding Registers, 1 register from addr 0).
        Any valid Modbus response (including exception) confirms the service.
        """
        pdu  = struct.pack(">BHH", 0x03, 0x0000, 0x0001)  # FC03, addr 0, count 1
        req  = self._build_mbap(pdu)
        resp = self._send_recv(ip, port, req)
        if resp is None:
            return False
        # Valid response: MBAP (7 bytes) + FC byte
        if len(resp) < 8:
            return False
        fc = resp[7]
        # Normal response (FC03=0x03) or exception (FC|0x80) both confirm Modbus
        return fc in (0x03, 0x83)

    def read_device_id(self, ip: str, port: int) -> str:
        """
        FC43 / MEI 0x0E — Read Device Identification.
        Returns device ID string or empty string on failure.
        """
        pdu  = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)  # FC43, MEI, basic, obj 0
        req  = self._build_mbap(pdu)
        resp = self._send_recv(ip, port, req)
        if not resp or len(resp) < 12:
            return ""
        if resp[7] == 0x2B:
            # Parse first object string
            try:
                obj_count = resp[11]
                if obj_count > 0 and len(resp) > 15:
                    str_len  = resp[14]
                    id_str   = resp[15:15+str_len].decode("ascii", errors="replace")
                    return id_str
            except Exception:
                pass
        return ""

    def scan_unit_ids(self, ip: str, port: int,
                      id_range: range = range(1, 16)) -> list:
        """Probe a range of unit IDs to map attached devices."""
        responding = []
        for uid in id_range:
            pdu  = struct.pack(">BHH", 0x11, 0x0000, 0x0000)  # FC17 Report Server ID
            req  = self._build_mbap(pdu, unit_id=uid)
            resp = self._send_recv(ip, port, req)
            if resp and len(resp) >= 8 and resp[7] not in (0x91, 0xFF):
                responding.append(uid)
        return responding

    def check_writable(self, ip: str, port: int) -> tuple[bool, bool]:
        """
        Test FC05 (Write Single Coil) and FC06 (Write Single Register).
        We write the SAME value that's already there — safe probe, no state change.
        First reads the value, then writes it back. Returns (coils_writable, regs_writable).
        """
        coils_writable = False
        regs_writable  = False

        # Read one coil (FC01), write it back (FC05)
        pdu_r  = struct.pack(">BHH", 0x01, 0x0000, 0x0001)
        resp_r = self._send_recv(ip, port, self._build_mbap(pdu_r))
        if resp_r and len(resp_r) >= 10 and resp_r[7] == 0x01:
            coil_val = resp_r[9] & 0x01
            # FC05 coil ON=0xFF00 OFF=0x0000
            write_val = 0xFF00 if coil_val else 0x0000
            pdu_w  = struct.pack(">BHH", 0x05, 0x0000, write_val)
            resp_w = self._send_recv(ip, port, self._build_mbap(pdu_w))
            if resp_w and len(resp_w) >= 8 and resp_w[7] == 0x05:
                coils_writable = True

        # Read one register (FC03), write it back (FC06)
        pdu_r  = struct.pack(">BHH", 0x03, 0x0000, 0x0001)
        resp_r = self._send_recv(ip, port, self._build_mbap(pdu_r))
        if resp_r and len(resp_r) >= 11 and resp_r[7] == 0x03:
            reg_val = struct.unpack_from(">H", resp_r, 9)[0]
            pdu_w   = struct.pack(">BHH", 0x06, 0x0000, reg_val)
            resp_w  = self._send_recv(ip, port, self._build_mbap(pdu_w))
            if resp_w and len(resp_w) >= 8 and resp_w[7] == 0x06:
                regs_writable = True

        return coils_writable, regs_writable

    def full_fingerprint(self, ip: str, port: int,
                          enumerate: bool = False) -> ModbusFingerprint:
        fp = ModbusFingerprint(host=ip, port=port)

        if not self.confirm_modbus(ip, port):
            return fp
        fp.responding = True

        fp.device_id_string = self.read_device_id(ip, port)

        # Parse vendor/product from device ID string if structured
        if fp.device_id_string:
            parts = fp.device_id_string.split("\x00")
            if len(parts) >= 1:
                fp.vendor_name = parts[0]
            if len(parts) >= 2:
                fp.product_code = parts[1]
            if len(parts) >= 3:
                fp.firmware_version = parts[2]

        if enumerate:
            fp.unit_ids_responding = self.scan_unit_ids(ip, port)
            coils_w, regs_w        = self.check_writable(ip, port)
            fp.writable_coils      = coils_w
            fp.writable_registers  = regs_w

        return fp


# ─────────────────────────────────────────────────────────────────────────────
# DNP3 PROBER
# ─────────────────────────────────────────────────────────────────────────────

class DNP3Prober:
    """
    Raw DNP3 prober using manually constructed link-layer frames.
    No external library required.
    """

    # DNP3 link layer constants
    START_BYTES    = b"\x05\x64"
    DIRECTION_BIT  = 0x80
    PRIMARY_BIT    = 0x40
    FCB_BIT        = 0x20
    FCV_BIT        = 0x10
    # Link layer function codes
    LC_RESET_LINK  = 0x00
    LC_TEST_LINK   = 0x02
    LC_REQ_DATA    = 0x04   # Request Link Status
    LC_LINK_STATUS = 0x0B   # Link status response

    def __init__(self, timeout: float = 3.0, master_addr: int = 3):
        self.timeout     = timeout
        self.master_addr = master_addr

    @staticmethod
    def _crc16(data: bytes) -> int:
        """DNP3 CRC-16 (polynomial 0xA6BC)."""
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return (~crc) & 0xFFFF

    def _build_link_frame(self, dest: int, src: int,
                           fc: int, data: bytes = b"") -> bytes:
        """Build a DNP3 link-layer frame."""
        length = 5 + len(data)   # 3 bytes control+dest+src + data + 2 CRC
        ctrl   = self.DIRECTION_BIT | self.PRIMARY_BIT | fc
        header = struct.pack("<BBHH", length, ctrl, dest, src)
        crc_val = self._crc16(header)
        frame = self.START_BYTES + header + struct.pack("<H", crc_val)
        if data:
            frame += data
        return frame

    def _build_request_link_status(self, dest: int) -> bytes:
        """DNP3 Request Link Status (FC04) — confirms link layer."""
        return self._build_link_frame(dest, self.master_addr, self.LC_REQ_DATA)

    def _build_data_link_reset(self, dest: int) -> bytes:
        """DNP3 Reset Link States (FC00)."""
        return self._build_link_frame(dest, self.master_addr, self.LC_RESET_LINK)

    def _send_recv_tcp(self, ip: str, port: int, payload: bytes) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            sock.sendall(payload)
            resp = sock.recv(512)
            sock.close()
            return resp
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _send_recv_udp(self, ip: str, port: int, payload: bytes) -> Optional[bytes]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(payload, (ip, port))
            resp, _ = sock.recvfrom(512)
            sock.close()
            return resp
        except (socket.timeout, OSError):
            return None

    def _is_dnp3_response(self, data: bytes) -> bool:
        """Validate DNP3 start bytes and minimum frame length."""
        return len(data) >= 10 and data[:2] == self.START_BYTES

    def confirm_dnp3(self, ip: str, port: int,
                     dest_addr: int = 0) -> tuple[bool, bool]:
        """
        Probe for DNP3 on TCP then UDP.
        Returns (tcp_found, udp_found).
        """
        probe_tcp = self._build_request_link_status(dest_addr)
        probe_udp = probe_tcp

        tcp_found = False
        udp_found = False

        resp = self._send_recv_tcp(ip, port, probe_tcp)
        if resp and self._is_dnp3_response(resp):
            tcp_found = True

        resp = self._send_recv_udp(ip, port, probe_udp)
        if resp and self._is_dnp3_response(resp):
            udp_found = True

        return tcp_found, udp_found

    def scan_outstation_addresses(self, ip: str, port: int,
                                   addr_range: range = range(1, 10)) -> list:
        """Probe a range of DNP3 outstation addresses to find active devices."""
        responding = []
        for addr in addr_range:
            probe = self._build_request_link_status(addr)
            resp  = self._send_recv_tcp(ip, port, probe)
            if resp and self._is_dnp3_response(resp):
                responding.append(addr)
                time.sleep(0.05)
        return responding

    def read_device_attributes(self, ip: str, port: int,
                                outstation_addr: int = 0) -> dict:
        """
        DNP3 Read (FC01) Group 0 — Device Attributes.
        These contain manufacturer, model, firmware version, and SA support level.
        """
        attrs = {}
        # Application layer: FC01 (Read), Group 0, Var 252 (all attributes)
        # This is simplified — a full implementation would handle transport
        # and application layer fragmentation. Here we build the minimal frame.
        app_ctrl = 0xC0   # FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
        app_fc   = 0x01   # Read
        obj_hdr  = struct.pack("BBB", 0x00, 0xFC, 0x06)  # Grp0, Var252, AllObjects

        transport_hdr = 0xC0   # FIR=1, FIN=1, SEQ=0
        app_layer = bytes([app_ctrl, app_fc]) + obj_hdr
        transport  = bytes([transport_hdr]) + app_layer

        # Wrap in user data (link layer would normally chunk this)
        # For simplicity we send a single-chunk frame
        probe = self._build_link_frame(
            outstation_addr, self.master_addr,
            0x04,          # FC04 (Unconfirmed User Data — no ack needed for read)
            transport
        )

        resp = self._send_recv_tcp(ip, port, probe)
        if resp and self._is_dnp3_response(resp) and len(resp) > 12:
            # Attempt basic attribute extraction from response data
            data = resp[10:]   # skip link header + CRC
            try:
                if len(data) > 4:
                    attrs["raw_response_len"] = len(resp)
                    attrs["app_ctrl"]         = hex(data[1]) if len(data) > 1 else ""
            except Exception:
                pass

        return attrs

    def full_fingerprint(self, ip: str, port: int,
                          deep: bool = False) -> DNP3Fingerprint:
        fp = DNP3Fingerprint(host=ip, port=port)

        tcp_found, udp_found = self.confirm_dnp3(ip, port)
        if not tcp_found and not udp_found:
            return fp

        fp.responding           = True
        fp.link_layer_confirmed = True

        if deep:
            # Scan a small range of outstation addresses
            fp.outstation_address = 0
            responding_addrs      = self.scan_outstation_addresses(ip, port, range(0, 8))
            if responding_addrs:
                fp.outstation_address   = responding_addrs[0]
                fp.app_layer_confirmed  = True

            fp.device_attributes = self.read_device_attributes(
                ip, port, fp.outstation_address
            )

        return fp


# ─────────────────────────────────────────────────────────────────────────────
# BRIDGE ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class ModbusDNP3BridgeAnalyzer:
    """
    Correlates DDS, Modbus, and DNP3 presence on the same host.
    Identifies bridge evidence and maps applicable attack scenarios.
    """

    def analyze(
        self,
        ip:               str,
        dds_ports:        list,
        modbus_fp:        Optional[ModbusFingerprint],
        dnp3_fp:          Optional[DNP3Fingerprint],
        other_protocols:  dict,
    ) -> ModbusDNP3BridgeReport:

        report = ModbusDNP3BridgeReport(
            ip               = ip,
            dds_ports_open   = dds_ports,
            modbus_ports_open = [modbus_fp.port] if modbus_fp and modbus_fp.responding else [],
            dnp3_ports_open  = [dnp3_fp.port] if dnp3_fp and dnp3_fp.responding else [],
            other_protocols  = other_protocols,
        )

        if modbus_fp:
            report.modbus_fingerprint = asdict(modbus_fp)
        if dnp3_fp:
            report.dnp3_fingerprint   = asdict(dnp3_fp)

        has_dds    = bool(dds_ports)
        has_modbus = bool(modbus_fp and modbus_fp.responding)
        has_dnp3   = bool(dnp3_fp   and dnp3_fp.responding)

        if not has_dds or (not has_modbus and not has_dnp3):
            report.risk_level = "LOW" if not has_dds else "MEDIUM"
            return report

        # ── Bridge evidence ───────────────────────────────────────────────────
        if has_modbus:
            report.bridge_evidence.append(
                f"DDS ports {dds_ports} + Modbus port {modbus_fp.port} on same host"
            )
            report.applicable_modbus_scenarios = MODBUS_DDS_ATTACK_SCENARIOS.copy()

        if has_dnp3:
            report.bridge_evidence.append(
                f"DDS ports {dds_ports} + DNP3 port {dnp3_fp.port} on same host"
            )
            report.applicable_dnp3_scenarios = DNP3_DDS_ATTACK_SCENARIOS.copy()

        # Guess bridge product from Modbus device ID
        if modbus_fp and modbus_fp.vendor_name:
            vn = modbus_fp.vendor_name.lower()
            for key, product in KNOWN_BRIDGE_PRODUCTS.items():
                if any(kw in vn for kw in key.split("_")):
                    report.bridge_product_guess = product
                    report.bridge_confirmed     = True
                    report.bridge_evidence.append(
                        f"Modbus device ID matches known bridge: {product}"
                    )
                    break

        # Treat coexistence alone as bridge-probable (common in field)
        if not report.bridge_confirmed and (has_modbus or has_dnp3):
            report.bridge_confirmed = True
            report.bridge_evidence.append(
                "DDS + field protocol coexistence is strong bridge indicator in ICS environments"
            )

        # ── Findings ──────────────────────────────────────────────────────────

        if has_modbus and modbus_fp.writable_registers:
            report.findings.append({
                "id":     "MODB-SEC-001",
                "title":  "Modbus Holding Registers Writable Without Authentication",
                "detail": (
                    f"FC06/FC10 writes accepted on {ip}:{modbus_fp.port}. "
                    "No Modbus authentication mechanism is active. "
                    "Any DDS bridge write propagates directly to the PLC."
                ),
                "cvss":   "9.1",
                "cwe":    "CWE-306",
                "mitre":  "T0831",
            })

        if has_modbus and modbus_fp.writable_coils:
            report.findings.append({
                "id":     "MODB-SEC-002",
                "title":  "Modbus Coils Writable Without Authentication",
                "detail": (
                    f"FC05/FC0F writes accepted on {ip}:{modbus_fp.port}. "
                    "Coil writes can directly actuate digital outputs — relays, "
                    "motor starters, solenoid valves."
                ),
                "cvss":   "9.3",
                "cwe":    "CWE-306",
                "mitre":  "T0831",
            })

        if has_dnp3 and not dnp3_fp.supports_sa:
            report.findings.append({
                "id":     "DNP3-SEC-001",
                "title":  "DNP3 Without Secure Authentication (Pre-SAv5)",
                "detail": (
                    f"DNP3 outstation at {ip}:{dnp3_fp.port} does not indicate "
                    "SAv5 support. Commands can be issued without challenge/response "
                    "authentication — including CROB and Analog Output operations."
                ),
                "cvss":   "9.4",
                "cwe":    "CWE-306",
                "mitre":  "T0831",
            })

        if has_dds and (has_modbus or has_dnp3):
            report.findings.append({
                "id":     "BRIDGE-001",
                "title":  "DDS + Field Protocol Bridge — Attack Chaining Possible",
                "detail": (
                    f"Host {ip} bridges DDS ({dds_ports}) to "
                    f"{'Modbus' if has_modbus else ''}"
                    f"{' + DNP3' if has_dnp3 and has_modbus else 'DNP3' if has_dnp3 else ''}. "
                    "An unauthenticated DDS participant can chain through the bridge "
                    "to issue field-level control commands."
                ),
                "cvss":   "9.8",
                "cwe":    "CWE-441",
                "mitre":  "T0831",
            })

        # ── Recommended PoC chain ─────────────────────────────────────────────
        if has_modbus:
            report.recommended_poc.append({
                "title":   "Minimal DDS→Modbus Write Chain",
                "steps": [
                    "1. Run ics_dds_enum.py --target {ip} to discover topic-to-register mapping",
                    "2. Identify DDS topic publishing to Modbus holding register range",
                    "3. Craft DDS DATA submessage targeting the write topic",
                    "4. Send via amplification.py or raw socket at target DDS port",
                    "5. Observe Modbus register change via FC03 read-back",
                ],
                "tool_chain": "ics_dds_enum.py → rtps_scanner.py → [write topic] → FC03 verify",
            })

        if has_dnp3:
            report.recommended_poc.append({
                "title":   "Minimal DDS→DNP3 CROB Chain",
                "steps": [
                    "1. Run ics_dds_enum.py --target {ip} --deep to find DNP3 bridge topics",
                    "2. Identify DDS write topic mapped to DNP3 Binary Output group",
                    "3. Inject DDS message with CROB payload (Group 12 Var 1)",
                    "4. Bridge forwards Select+Operate to DNP3 outstation",
                    "5. Verify via DNP3 read (Group 10 Var 2 Binary Output Status)",
                ],
                "tool_chain": "ics_dds_enum.py → [CROB topic] → DNP3 Group 10 verify",
            })

        # ── Risk level ────────────────────────────────────────────────────────
        max_cvss = max(
            (float(f.get("cvss", "0")) for f in report.findings),
            default=0.0
        )
        if max_cvss >= 9.0:
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
            return True   # optimistic for UDP
        except (ConnectionRefusedError, OSError):
            return False


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

class ModbusDNP3BridgeScanner:
    """
    Orchestrates per-host DDS + Modbus/DNP3 coexistence detection,
    protocol fingerprinting, and bridge attack surface analysis.
    """

    def __init__(self, args):
        self.args     = args
        self.checker  = PortChecker()
        self.modbus_p = ModbusProber(timeout=args.timeout)
        self.dnp3_p   = DNP3Prober(timeout=args.timeout)
        self.analyzer = ModbusDNP3BridgeAnalyzer()
        self.results  = []

    def scan_host(self, ip: str) -> Optional[ModbusDNP3BridgeReport]:
        # DDS UDP
        dds_open = [p for p in DDS_DISC_PORTS if self.checker.udp_probe(ip, p)]

        # Modbus TCP
        modbus_open = [p for p in MODBUS_PORTS if self.checker.tcp_open(ip, p)]

        # DNP3 TCP
        dnp3_open = [p for p in DNP3_PORTS if self.checker.tcp_open(ip, p)]

        if not dds_open and not modbus_open and not dnp3_open:
            return None

        print(f"  [+] {ip} | DDS:{dds_open} | Modbus:{modbus_open} | DNP3:{dnp3_open}")

        # Fingerprint
        modbus_fp = None
        if modbus_open:
            modbus_fp = self.modbus_p.full_fingerprint(
                ip, modbus_open[0],
                enumerate=self.args.modbus_enumerate,
            )

        dnp3_fp = None
        if dnp3_open:
            dnp3_fp = self.dnp3_p.full_fingerprint(
                ip, dnp3_open[0],
                deep=self.args.deep,
            )

        # Other protocols (deep mode)
        other = {}
        if self.args.deep:
            for proto, ports in [("EtherNet/IP", ENIP_PORTS),
                                   ("S7comm",      S7_PORTS),
                                   ("BACnet",       BACNET_PORTS)]:
                found = [p for p in ports if self.checker.tcp_open(ip, p)]
                if found:
                    other[proto] = found

        return self.analyzer.analyze(ip, dds_open, modbus_fp, dnp3_fp, other)

    def run(self) -> list:
        targets = []
        if self.args.target:
            targets = [self.args.target]
        elif self.args.cidr:
            net     = ipaddress.ip_network(self.args.cidr, strict=False)
            targets = [str(h) for h in net.hosts()]
            print(f"[*] Sweeping {self.args.cidr} ({len(targets)} hosts)")

        print(f"\n{'='*60}")
        print("  ROS2Reaper :: Phase 3 — Modbus/DNP3 Bridge Scanner")
        print(f"{'='*60}\n")

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
        print("  MODBUS/DNP3 BRIDGE SCAN SUMMARY")
        print(f"{'='*60}")

        bridge_hosts = [r for r in self.results if r.bridge_confirmed]
        crit_hosts   = [r for r in self.results if r.risk_level == "CRITICAL"]

        print(f"  Bridge hosts detected : {len(bridge_hosts)}")
        print(f"  Critical risk         : {len(crit_hosts)}")

        for r in crit_hosts:
            print(f"\n  ⚠  {r.ip} [{r.risk_level}]")
            print(f"     DDS:{r.dds_ports_open}  Modbus:{r.modbus_ports_open}  DNP3:{r.dnp3_ports_open}")
            for f in r.findings:
                print(f"     [{f['id']}] {f['title']} (CVSS {f['cvss']})")
            if r.bridge_product_guess:
                print(f"     Bridge product: {r.bridge_product_guess}")
            if r.recommended_poc:
                print(f"     PoC chain: {r.recommended_poc[0]['tool_chain']}")

        print(f"\n  Modbus attack scenarios : {len(MODBUS_DDS_ATTACK_SCENARIOS)}")
        for s in MODBUS_DDS_ATTACK_SCENARIOS:
            print(f"    [{s['id']}] {s['name']} — CVSS {s['cvss']}")

        print(f"\n  DNP3 attack scenarios   : {len(DNP3_DDS_ATTACK_SCENARIOS)}")
        for s in DNP3_DDS_ATTACK_SCENARIOS:
            print(f"    [{s['id']}] {s['name']} — CVSS {s['cvss']}")
        print()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ROS2Reaper Phase 3 — Modbus/DNP3 ↔ DDS Bridge Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 modbus_dnp3_bridge.py --target 10.0.0.5
    python3 modbus_dnp3_bridge.py --cidr 192.168.1.0/24 --deep
    python3 modbus_dnp3_bridge.py --target 10.0.0.5 --modbus-enumerate
    python3 modbus_dnp3_bridge.py --cidr 10.52.32.0/24 --output bridge.json

    # Chain with ics_dds_enum
    python3 ics_dds_enum.py --cidr 10.52.32.0/24 --output ics.json
    python3 modbus_dnp3_bridge.py --cidr 10.52.32.0/24 --output modbus.json
        """
    )
    tgt = p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target", help="Single target IP")
    tgt.add_argument("--cidr",   help="CIDR range")

    p.add_argument("--timeout",          type=float, default=3.0)
    p.add_argument("--threads",          type=int,   default=30)
    p.add_argument("--deep",             action="store_true",
                   help="Deep probe: DNP3 address scan + co-protocol detection")
    p.add_argument("--modbus-enumerate", action="store_true", dest="modbus_enumerate",
                   help="Enumerate Modbus unit IDs and test write access")
    p.add_argument("--output",           metavar="FILE", help="Write JSON report to file")
    return p.parse_args()


def main():
    args    = parse_args()
    scanner = ModbusDNP3BridgeScanner(args)
    results = scanner.run()

    if args.output:
        with open(args.output, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"[+] Report saved → {args.output}")


if __name__ == "__main__":
    main()
