#!/usr/bin/env python3
"""
rtps_parser.py - RTPS Protocol Dissector
=========================================
Scapy-based parser for the Real-Time Publish-Subscribe (RTPS) wire protocol.
This is the foundation layer — all DDS communication uses RTPS on the wire.

Handles parsing of:
- RTPS Headers (protocol version, vendor ID, GUID prefix)
- SPDP (Simple Participant Discovery Protocol) messages
- SEDP (Simple Endpoint Discovery Protocol) messages
- Submessage types (DATA, HEARTBEAT, ACKNACK, INFO_DST, INFO_TS)
- Parameter Lists (participant name, endpoints, locators, QoS)

Author: Gh057x
Reference: OMG RTPS Spec v2.5 (formal/2022-04-01)
"""

import struct
import socket
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any
from enum import IntEnum


# =============================================================================
# Constants
# =============================================================================

RTPS_MAGIC = b"RTPS"

class VendorId(IntEnum):
    """Known DDS vendor identifiers (2 bytes)"""
    UNKNOWN        = 0x0000
    RTI_CONNEXT    = 0x0101
    OCI_OPENDDS    = 0x0103
    EPROSIMA_FAST  = 0x010F
    ECLIPSE_CYCLONE = 0x0110
    GURUM_DDS      = 0x0112
    DUST_DDS       = 0x0113

VENDOR_NAMES = {
    VendorId.RTI_CONNEXT:     "RTI Connext DDS",
    VendorId.OCI_OPENDDS:     "OCI OpenDDS",
    VendorId.EPROSIMA_FAST:   "eProsima Fast DDS",
    VendorId.ECLIPSE_CYCLONE: "Eclipse Cyclone DDS",
    VendorId.GURUM_DDS:       "GurumNetworks GurumDDS",
    VendorId.DUST_DDS:        "DUST DDS",
    VendorId.UNKNOWN:         "Unknown Vendor",
}

class SubmessageKind(IntEnum):
    """RTPS Submessage type identifiers"""
    PAD            = 0x01
    ACKNACK        = 0x06
    HEARTBEAT      = 0x07
    GAP            = 0x08
    INFO_TS        = 0x09
    INFO_SRC       = 0x0C
    INFO_REPLY_IP4 = 0x0D
    INFO_DST       = 0x0E
    INFO_REPLY     = 0x0F
    NACK_FRAG      = 0x12
    HEARTBEAT_FRAG = 0x13
    DATA           = 0x15
    DATA_FRAG      = 0x16

SUBMESSAGE_NAMES = {
    SubmessageKind.PAD:            "PAD",
    SubmessageKind.ACKNACK:        "ACKNACK",
    SubmessageKind.HEARTBEAT:      "HEARTBEAT",
    SubmessageKind.GAP:            "GAP",
    SubmessageKind.INFO_TS:        "INFO_TS",
    SubmessageKind.INFO_SRC:       "INFO_SRC",
    SubmessageKind.INFO_REPLY_IP4: "INFO_REPLY_IP4",
    SubmessageKind.INFO_DST:       "INFO_DST",
    SubmessageKind.INFO_REPLY:     "INFO_REPLY",
    SubmessageKind.NACK_FRAG:      "NACK_FRAG",
    SubmessageKind.HEARTBEAT_FRAG: "HEARTBEAT_FRAG",
    SubmessageKind.DATA:           "DATA",
    SubmessageKind.DATA_FRAG:      "DATA_FRAG",
}

class ParameterId(IntEnum):
    """RTPS Parameter IDs found in DATA submessage parameter lists"""
    PID_PAD                          = 0x0000
    PID_SENTINEL                     = 0x0001
    PID_PARTICIPANT_LEASE_DURATION   = 0x0002
    PID_PERSISTENCE                  = 0x0003
    PID_TOPIC_NAME                   = 0x0005
    PID_TYPE_NAME                    = 0x0007
    PID_DURABILITY                   = 0x001D
    PID_DEADLINE                     = 0x0023
    PID_LATENCY_BUDGET               = 0x0027
    PID_LIVELINESS                   = 0x001B
    PID_RELIABILITY                  = 0x001A
    PID_OWNERSHIP                    = 0x001F
    PID_PROTOCOL_VERSION             = 0x0015
    PID_VENDOR_ID                    = 0x0016
    PID_UNICAST_LOCATOR              = 0x002F
    PID_MULTICAST_LOCATOR            = 0x0030
    PID_DEFAULT_UNICAST_LOCATOR      = 0x0031
    PID_DEFAULT_MULTICAST_LOCATOR    = 0x0048
    PID_METATRAFFIC_UNICAST_LOCATOR  = 0x0032
    PID_METATRAFFIC_MULTICAST_LOCATOR = 0x0033
    PID_PARTICIPANT_NAME             = 0x0062  # alias for PID_ENTITY_NAME
    PID_DOMAIN_ID                    = 0x000F
    PID_DOMAIN_TAG                   = 0x4014
    PID_BUILTIN_ENDPOINT_SET         = 0x0058
    PID_ENDPOINT_GUID                = 0x005A
    PID_ENTITY_NAME                  = 0x0062
    PID_KEY_HASH                     = 0x0070
    PID_STATUS_INFO                  = 0x0071
    PID_PROPERTY_LIST                = 0x0059
    PID_IDENTITY_TOKEN               = 0x1001  # DDS-Security
    PID_PERMISSIONS_TOKEN            = 0x1002  # DDS-Security
    PID_PARTICIPANT_SECURITY_INFO    = 0x1005  # DDS-Security
    PID_ENDPOINT_SECURITY_INFO       = 0x1006  # DDS-Security

# Well-known RTPS Entity IDs
ENTITYID_PARTICIPANT          = bytes([0x00, 0x00, 0x01, 0xC1])
ENTITYID_SPDP_BUILTIN_WRITER = bytes([0x00, 0x01, 0x00, 0xC2])
ENTITYID_SPDP_BUILTIN_READER = bytes([0x00, 0x01, 0x00, 0xC7])
ENTITYID_SEDP_BUILTIN_PUB_WRITER = bytes([0x00, 0x00, 0x03, 0xC2])
ENTITYID_SEDP_BUILTIN_PUB_READER = bytes([0x00, 0x00, 0x03, 0xC7])
ENTITYID_SEDP_BUILTIN_SUB_WRITER = bytes([0x00, 0x00, 0x04, 0xC2])
ENTITYID_SEDP_BUILTIN_SUB_READER = bytes([0x00, 0x00, 0x04, 0xC7])


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class RTPSLocator:
    """Represents a network locator (address + port) in RTPS"""
    kind: int  # 1=UDPv4, 2=UDPv6
    port: int
    address: str

    def __str__(self):
        return f"{self.address}:{self.port}"

    def to_dict(self):
        return {"kind": self.kind, "port": self.port, "address": self.address}


@dataclass
class RTPSHeader:
    """Parsed RTPS message header"""
    protocol: str
    version_major: int
    version_minor: int
    vendor_id: int
    vendor_name: str
    guid_prefix: bytes

    def guid_prefix_hex(self) -> str:
        return self.guid_prefix.hex(".")

    def to_dict(self):
        return {
            "protocol": self.protocol,
            "version": f"{self.version_major}.{self.version_minor}",
            "vendor_id": f"0x{self.vendor_id:04X}",
            "vendor_name": self.vendor_name,
            "guid_prefix": self.guid_prefix_hex(),
        }


@dataclass
class RTPSSubmessage:
    """Parsed RTPS submessage"""
    kind: int
    kind_name: str
    flags: int
    length: int
    data: bytes

    def is_little_endian(self) -> bool:
        return bool(self.flags & 0x01)

    def to_dict(self):
        return {
            "kind": self.kind_name,
            "flags": f"0x{self.flags:02X}",
            "length": self.length,
            "little_endian": self.is_little_endian(),
        }


@dataclass
class RTPSParameter:
    """Single parameter from a parameter list"""
    pid: int
    pid_name: str
    length: int
    value: Any

    def to_dict(self):
        if isinstance(self.value, bytes):
            return {"pid": self.pid_name, "value": self.value.hex()}
        elif isinstance(self.value, RTPSLocator):
            return {"pid": self.pid_name, "value": self.value.to_dict()}
        return {"pid": self.pid_name, "value": self.value}


@dataclass
class DDSParticipant:
    """Discovered DDS participant with all extracted metadata"""
    guid_prefix: bytes
    vendor_id: int
    vendor_name: str
    protocol_version: str
    participant_name: Optional[str] = None
    domain_id: Optional[int] = None
    domain_tag: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    unicast_locators: List[RTPSLocator] = field(default_factory=list)
    multicast_locators: List[RTPSLocator] = field(default_factory=list)
    metatraffic_unicast: List[RTPSLocator] = field(default_factory=list)
    metatraffic_multicast: List[RTPSLocator] = field(default_factory=list)
    lease_duration: Optional[float] = None
    builtin_endpoints: Optional[int] = None
    has_security: bool = False
    security_info: Dict[str, Any] = field(default_factory=dict)
    properties: Dict[str, str] = field(default_factory=dict)
    raw_parameters: List[RTPSParameter] = field(default_factory=list)

    def guid_prefix_hex(self) -> str:
        return self.guid_prefix.hex(".")

    def to_dict(self) -> Dict:
        result = {
            "guid_prefix": self.guid_prefix_hex(),
            "vendor_id": f"0x{self.vendor_id:04X}",
            "vendor_name": self.vendor_name,
            "protocol_version": self.protocol_version,
            "source": f"{self.source_ip}:{self.source_port}" if self.source_ip else None,
            "participant_name": self.participant_name,
            "domain_id": self.domain_id,
            "domain_tag": self.domain_tag,
            "lease_duration_sec": self.lease_duration,
            "has_security": self.has_security,
            "unicast_locators": [l.to_dict() for l in self.unicast_locators],
            "multicast_locators": [l.to_dict() for l in self.multicast_locators],
            "metatraffic_unicast": [l.to_dict() for l in self.metatraffic_unicast],
            "metatraffic_multicast": [l.to_dict() for l in self.metatraffic_multicast],
            "properties": self.properties if self.properties else None,
            "security_info": self.security_info if self.security_info else None,
        }
        return {k: v for k, v in result.items() if v is not None}


# =============================================================================
# Parser
# =============================================================================

class RTPSParser:
    """
    Stateless RTPS packet parser.
    
    Parses raw UDP payload bytes into structured RTPS data.
    Does not send or receive packets — that's the scanner's job.
    """

    @staticmethod
    def is_rtps(data: bytes) -> bool:
        """Check if raw bytes are an RTPS packet"""
        return len(data) >= 20 and data[:4] == RTPS_MAGIC

    @staticmethod
    def parse_header(data: bytes) -> Optional[RTPSHeader]:
        """
        Parse RTPS header (first 20 bytes).
        
        Layout:
          [0:4]   Protocol "RTPS"
          [4]     Version Major
          [5]     Version Minor
          [6:8]   Vendor ID
          [8:20]  GUID Prefix (12 bytes)
        """
        if len(data) < 20:
            return None
        if data[:4] != RTPS_MAGIC:
            return None

        version_major = data[4]
        version_minor = data[5]
        vendor_id = struct.unpack("!H", data[6:8])[0]
        guid_prefix = data[8:20]
        vendor_name = VENDOR_NAMES.get(vendor_id, f"Unknown (0x{vendor_id:04X})")

        return RTPSHeader(
            protocol="RTPS",
            version_major=version_major,
            version_minor=version_minor,
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            guid_prefix=guid_prefix,
        )

    @staticmethod
    def parse_submessages(data: bytes) -> List[RTPSSubmessage]:
        """
        Parse all submessages from an RTPS packet.
        Starts after the 20-byte header.
        
        Each submessage:
          [0]   Submessage Kind (1 byte)
          [1]   Flags (1 byte) — bit 0 = endianness
          [2:4] Length (2 bytes, endianness from flags)
          [4:]  Submessage payload
        """
        submessages = []
        offset = 20  # Skip RTPS header

        while offset + 4 <= len(data):
            kind = data[offset]
            flags = data[offset + 1]
            little_endian = bool(flags & 0x01)

            if little_endian:
                length = struct.unpack("<H", data[offset + 2:offset + 4])[0]
            else:
                length = struct.unpack("!H", data[offset + 2:offset + 4])[0]

            # Submessage header is 4 bytes, payload follows
            payload_start = offset + 4
            payload_end = payload_start + length

            if payload_end > len(data):
                # Truncated packet — take what we can
                payload = data[payload_start:]
            else:
                payload = data[payload_start:payload_end]

            kind_name = SUBMESSAGE_NAMES.get(kind, f"UNKNOWN(0x{kind:02X})")

            submessages.append(RTPSSubmessage(
                kind=kind,
                kind_name=kind_name,
                flags=flags,
                length=length,
                data=payload,
            ))

            # Advance to next submessage (aligned to 4 bytes)
            next_offset = payload_start + length
            # RTPS submessages are 32-bit aligned
            if next_offset % 4 != 0:
                next_offset += 4 - (next_offset % 4)
            offset = next_offset

        return submessages

    @staticmethod
    def parse_locator(data: bytes, offset: int = 0) -> Optional[RTPSLocator]:
        """
        Parse a single RTPS Locator_t (24 bytes).
        
        Layout:
          [0:4]   Kind (long) — 1=UDPv4, 2=UDPv6
          [4:8]   Port (unsigned long)
          [8:24]  Address (16 bytes — IPv4 in last 4 bytes)
        """
        if len(data) < offset + 24:
            return None

        kind = struct.unpack("<I", data[offset:offset + 4])[0]
        port = struct.unpack("<I", data[offset + 4:offset + 8])[0]
        addr_bytes = data[offset + 8:offset + 24]

        if kind == 1:  # UDPv4
            # IPv4 address is in last 4 bytes of the 16-byte field
            ip = socket.inet_ntoa(addr_bytes[12:16])
        elif kind == 2:  # UDPv6
            ip = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            ip = addr_bytes.hex()

        return RTPSLocator(kind=kind, port=port, address=ip)

    @classmethod
    def parse_parameter_list(cls, data: bytes, little_endian: bool = True) -> List[RTPSParameter]:
        """
        Parse a parameter list from a DATA submessage payload.
        
        Each parameter:
          [0:2]  Parameter ID
          [2:4]  Length
          [4:]   Value (length bytes, padded to 4-byte boundary)
          
        List terminates with PID_SENTINEL (0x0001).
        """
        parameters = []
        offset = 0
        fmt_h = "<H" if little_endian else "!H"
        fmt_i = "<I" if little_endian else "!I"

        while offset + 4 <= len(data):
            pid = struct.unpack(fmt_h, data[offset:offset + 2])[0]
            param_len = struct.unpack(fmt_h, data[offset + 2:offset + 4])[0]

            if pid == ParameterId.PID_SENTINEL:
                break

            if pid == ParameterId.PID_PAD:
                offset += 4 + param_len
                continue

            value_data = data[offset + 4:offset + 4 + param_len]
            parsed_value = cls._parse_parameter_value(pid, value_data, little_endian)
            pid_name = cls._get_pid_name(pid)

            parameters.append(RTPSParameter(
                pid=pid,
                pid_name=pid_name,
                length=param_len,
                value=parsed_value,
            ))

            # Advance (4-byte aligned)
            offset += 4 + param_len
            if offset % 4 != 0:
                offset += 4 - (offset % 4)

        return parameters

    @classmethod
    def _parse_parameter_value(cls, pid: int, data: bytes, little_endian: bool = True) -> Any:
        """Parse a parameter value based on its PID type"""
        fmt_h = "<H" if little_endian else "!H"
        fmt_i = "<I" if little_endian else "!I"

        try:
            # String parameters (null-terminated with 4-byte length prefix)
            if pid in (
                ParameterId.PID_TOPIC_NAME,
                ParameterId.PID_TYPE_NAME,
                ParameterId.PID_PARTICIPANT_NAME,
                ParameterId.PID_ENTITY_NAME,
                ParameterId.PID_DOMAIN_TAG,
            ):
                if len(data) >= 4:
                    str_len = struct.unpack(fmt_i, data[0:4])[0]
                    raw = data[4:4 + str_len]
                    return raw.rstrip(b"\x00").decode("utf-8", errors="replace")
                return data

            # Locator parameters
            if pid in (
                ParameterId.PID_UNICAST_LOCATOR,
                ParameterId.PID_MULTICAST_LOCATOR,
                ParameterId.PID_DEFAULT_UNICAST_LOCATOR,
                ParameterId.PID_DEFAULT_MULTICAST_LOCATOR,
                ParameterId.PID_METATRAFFIC_UNICAST_LOCATOR,
                ParameterId.PID_METATRAFFIC_MULTICAST_LOCATOR,
            ):
                return cls.parse_locator(data)

            # Duration (seconds + fraction)
            if pid == ParameterId.PID_PARTICIPANT_LEASE_DURATION:
                if len(data) >= 8:
                    sec = struct.unpack(fmt_i, data[0:4])[0]
                    frac = struct.unpack(fmt_i, data[4:8])[0]
                    return float(sec) + float(frac) / (2**32)
                return data

            # Integer parameters
            if pid in (
                ParameterId.PID_DOMAIN_ID,
                ParameterId.PID_BUILTIN_ENDPOINT_SET,
            ):
                if len(data) >= 4:
                    return struct.unpack(fmt_i, data[0:4])[0]
                return data

            # Protocol version
            if pid == ParameterId.PID_PROTOCOL_VERSION:
                if len(data) >= 2:
                    return f"{data[0]}.{data[1]}"
                return data

            # Vendor ID
            if pid == ParameterId.PID_VENDOR_ID:
                if len(data) >= 2:
                    vid = struct.unpack("!H", data[0:2])[0]
                    return VENDOR_NAMES.get(vid, f"Unknown (0x{vid:04X})")
                return data

            # GUID (16 bytes)
            if pid == ParameterId.PID_ENDPOINT_GUID:
                if len(data) >= 16:
                    return data[:16].hex(".")
                return data

            # Key hash (16 bytes)
            if pid == ParameterId.PID_KEY_HASH:
                if len(data) >= 16:
                    return data[:16].hex(".")
                return data

            # Security tokens (DDS-Security)
            if pid in (
                ParameterId.PID_IDENTITY_TOKEN,
                ParameterId.PID_PERMISSIONS_TOKEN,
            ):
                # These contain class_id string + properties
                # Just flag presence for now
                return {"present": True, "raw_length": len(data)}

            # Security info bitmasks
            if pid in (
                ParameterId.PID_PARTICIPANT_SECURITY_INFO,
                ParameterId.PID_ENDPOINT_SECURITY_INFO,
            ):
                if len(data) >= 8:
                    plugin_mask = struct.unpack(fmt_i, data[0:4])[0]
                    security_mask = struct.unpack(fmt_i, data[4:8])[0]
                    return {
                        "plugin_security_attributes": f"0x{plugin_mask:08X}",
                        "security_attributes": f"0x{security_mask:08X}",
                    }
                return data

            # Property list (used for DDS-Security auth handshake, etc.)
            if pid == ParameterId.PID_PROPERTY_LIST:
                return cls._parse_property_list(data, little_endian)

        except Exception:
            pass

        # Default: return raw bytes
        return data

    @staticmethod
    def _parse_property_list(data: bytes, little_endian: bool = True) -> Dict[str, str]:
        """Parse a DDS property list (name-value string pairs)"""
        properties = {}
        fmt_i = "<I" if little_endian else "!I"
        offset = 0

        try:
            if len(data) < 4:
                return properties

            num_props = struct.unpack(fmt_i, data[offset:offset + 4])[0]
            offset += 4

            for _ in range(min(num_props, 50)):  # Cap to prevent infinite loop
                if offset + 4 > len(data):
                    break

                # Name
                name_len = struct.unpack(fmt_i, data[offset:offset + 4])[0]
                offset += 4
                name = data[offset:offset + name_len].rstrip(b"\x00").decode("utf-8", errors="replace")
                offset += name_len
                if offset % 4 != 0:
                    offset += 4 - (offset % 4)

                # Value
                if offset + 4 > len(data):
                    break
                val_len = struct.unpack(fmt_i, data[offset:offset + 4])[0]
                offset += 4
                value = data[offset:offset + val_len].rstrip(b"\x00").decode("utf-8", errors="replace")
                offset += val_len
                if offset % 4 != 0:
                    offset += 4 - (offset % 4)

                properties[name] = value

        except Exception:
            pass

        return properties

    @staticmethod
    def _get_pid_name(pid: int) -> str:
        """Get human-readable name for a Parameter ID"""
        try:
            return ParameterId(pid).name
        except ValueError:
            return f"PID_UNKNOWN_0x{pid:04X}"

    @classmethod
    def extract_participant(
        cls, data: bytes, source_ip: str = None, source_port: int = None
    ) -> Optional[DDSParticipant]:
        """
        Full extraction: parse an RTPS packet and extract participant info.
        This is the main high-level method for processing discovery messages.
        
        Returns a DDSParticipant with all available metadata, or None if
        the packet isn't a valid RTPS discovery message.
        """
        header = cls.parse_header(data)
        if not header:
            return None

        participant = DDSParticipant(
            guid_prefix=header.guid_prefix,
            vendor_id=header.vendor_id,
            vendor_name=header.vendor_name,
            protocol_version=f"{header.version_major}.{header.version_minor}",
            source_ip=source_ip,
            source_port=source_port,
        )

        # Parse submessages looking for DATA with parameter lists
        submessages = cls.parse_submessages(data)

        for submsg in submessages:
            if submsg.kind != SubmessageKind.DATA:
                continue

            # DATA submessage layout:
            #   [0:2]  Extra flags
            #   [2:4]  Octets to inline QoS
            #   [4:8]  Reader Entity ID
            #   [8:12] Writer Entity ID
            #   [12:20] Sequence Number
            #   [20:]  Serialized Data (may have inline QoS first)

            if len(submsg.data) < 20:
                continue

            writer_entity_id = submsg.data[8:12]

            # Determine if this is SPDP data (participant announcement)
            is_spdp = writer_entity_id == ENTITYID_SPDP_BUILTIN_WRITER

            # Find the serialized data payload
            # Check for inline QoS flag (bit 1 of submessage flags)
            has_inline_qos = bool(submsg.flags & 0x02)
            # Data present flag (bit 2)
            has_data = bool(submsg.flags & 0x04)

            if not has_data:
                continue

            octets_to_iqos = struct.unpack(
                "<H" if submsg.is_little_endian() else "!H",
                submsg.data[2:4]
            )[0]

            # Start of serialized data:
            # extra_flags(2) + octets_to_iqos(2) + octets_to_iqos bytes = 4 + octets_to_iqos
            # Standard value is 16 (reader_eid + writer_eid + seq_num), giving offset 20.
            data_offset = 4 + octets_to_iqos

            if has_inline_qos:
                # Skip inline QoS parameter list (terminated by PID_SENTINEL)
                qos_offset = data_offset
                while qos_offset + 4 <= len(submsg.data):
                    qos_pid = struct.unpack(
                        "<H" if submsg.is_little_endian() else "!H",
                        submsg.data[qos_offset:qos_offset + 2]
                    )[0]
                    qos_len = struct.unpack(
                        "<H" if submsg.is_little_endian() else "!H",
                        submsg.data[qos_offset + 2:qos_offset + 4]
                    )[0]
                    qos_offset += 4 + qos_len
                    if qos_pid == ParameterId.PID_SENTINEL:
                        break
                data_offset = qos_offset

            # Skip CDR encapsulation header (4 bytes: 2 byte encoding, 2 byte options)
            if data_offset + 4 <= len(submsg.data):
                # Check for CDR encoding: 0x0001 (big endian) or 0x0100 (little endian)
                encap = submsg.data[data_offset:data_offset + 2]
                if encap in (b"\x00\x01", b"\x00\x02", b"\x00\x03", b"\x00\x04"):
                    data_offset += 4

            # Parse parameter list
            param_data = submsg.data[data_offset:]
            if len(param_data) > 0:
                parameters = cls.parse_parameter_list(
                    param_data, submsg.is_little_endian()
                )
                participant.raw_parameters.extend(parameters)

                # Extract structured data from parameters
                for param in parameters:
                    cls._apply_parameter(participant, param)

        return participant

    @staticmethod
    def _apply_parameter(participant: DDSParticipant, param: RTPSParameter):
        """Apply a parsed parameter to a DDSParticipant's fields"""
        pid = param.pid

        if pid == ParameterId.PID_PARTICIPANT_NAME and isinstance(param.value, str):
            participant.participant_name = param.value

        elif pid == ParameterId.PID_DOMAIN_ID and isinstance(param.value, int):
            participant.domain_id = param.value

        elif pid == ParameterId.PID_DOMAIN_TAG and isinstance(param.value, str):
            participant.domain_tag = param.value

        elif pid == ParameterId.PID_PARTICIPANT_LEASE_DURATION and isinstance(param.value, float):
            participant.lease_duration = param.value

        elif pid == ParameterId.PID_BUILTIN_ENDPOINT_SET and isinstance(param.value, int):
            participant.builtin_endpoints = param.value

        elif pid == ParameterId.PID_PROTOCOL_VERSION and isinstance(param.value, str):
            participant.protocol_version = param.value

        elif pid == ParameterId.PID_VENDOR_ID and isinstance(param.value, str):
            # Already set from header, but this confirms
            pass

        elif pid in (ParameterId.PID_DEFAULT_UNICAST_LOCATOR, ParameterId.PID_UNICAST_LOCATOR):
            if isinstance(param.value, RTPSLocator):
                participant.unicast_locators.append(param.value)

        elif pid in (ParameterId.PID_DEFAULT_MULTICAST_LOCATOR, ParameterId.PID_MULTICAST_LOCATOR):
            if isinstance(param.value, RTPSLocator):
                participant.multicast_locators.append(param.value)

        elif pid == ParameterId.PID_METATRAFFIC_UNICAST_LOCATOR:
            if isinstance(param.value, RTPSLocator):
                participant.metatraffic_unicast.append(param.value)

        elif pid == ParameterId.PID_METATRAFFIC_MULTICAST_LOCATOR:
            if isinstance(param.value, RTPSLocator):
                participant.metatraffic_multicast.append(param.value)

        # DDS-Security indicators
        elif pid == ParameterId.PID_IDENTITY_TOKEN:
            participant.has_security = True
            participant.security_info["identity_token"] = param.value

        elif pid == ParameterId.PID_PERMISSIONS_TOKEN:
            participant.has_security = True
            participant.security_info["permissions_token"] = param.value

        elif pid == ParameterId.PID_PARTICIPANT_SECURITY_INFO:
            participant.has_security = True
            participant.security_info["participant_security_info"] = param.value

        elif pid == ParameterId.PID_ENDPOINT_SECURITY_INFO:
            participant.has_security = True
            participant.security_info["endpoint_security_info"] = param.value

        elif pid == ParameterId.PID_PROPERTY_LIST and isinstance(param.value, dict):
            participant.properties.update(param.value)


# =============================================================================
# DDS Port Calculator
# =============================================================================

class DDSPortCalculator:
    """
    Calculate DDS/RTPS port numbers for a given domain ID.
    
    Per RTPS spec, ports are deterministic based on domain ID and participant ID.
    This is critical for scanning — you can predict exactly which ports to probe.
    """

    # Default port base and offsets (RTPS 2.2+)
    PB = 7400   # Port base
    DG = 250    # Domain ID gain
    PG = 2      # Participant ID gain
    D0 = 0      # Discovery multicast offset
    D1 = 10     # Discovery unicast offset
    D2 = 1      # User multicast offset
    D3 = 11     # User unicast offset

    @classmethod
    def discovery_multicast(cls, domain_id: int) -> int:
        """Multicast port for SPDP discovery"""
        return cls.PB + cls.DG * domain_id + cls.D0

    @classmethod
    def discovery_unicast(cls, domain_id: int, participant_id: int = 0) -> int:
        """Unicast port for SPDP discovery"""
        return cls.PB + cls.DG * domain_id + cls.D1 + cls.PG * participant_id

    @classmethod
    def user_multicast(cls, domain_id: int) -> int:
        """Multicast port for user data"""
        return cls.PB + cls.DG * domain_id + cls.D2

    @classmethod
    def user_unicast(cls, domain_id: int, participant_id: int = 0) -> int:
        """Unicast port for user data"""
        return cls.PB + cls.DG * domain_id + cls.D3 + cls.PG * participant_id

    @classmethod
    def all_ports_for_domain(cls, domain_id: int, max_participants: int = 5) -> List[int]:
        """Get all possible ports for a domain ID"""
        ports = set()
        ports.add(cls.discovery_multicast(domain_id))
        ports.add(cls.user_multicast(domain_id))
        for pid in range(max_participants):
            ports.add(cls.discovery_unicast(domain_id, pid))
            ports.add(cls.user_unicast(domain_id, pid))
        return sorted(ports)

    @classmethod
    def ports_for_domain_range(cls, start: int = 0, end: int = 10,
                                max_participants: int = 3) -> List[int]:
        """Get all possible ports across a range of domain IDs"""
        ports = set()
        for did in range(start, end + 1):
            ports.update(cls.all_ports_for_domain(did, max_participants))
        return sorted(ports)

    @classmethod
    def identify_port(cls, port: int, domain_range: int = 233) -> Optional[Dict]:
        """
        Reverse-identify what a DDS port number represents.
        Returns domain ID, participant ID, and port type.
        """
        for domain_id in range(domain_range):
            if port == cls.discovery_multicast(domain_id):
                return {"domain_id": domain_id, "type": "discovery_multicast", "participant_id": None}
            if port == cls.user_multicast(domain_id):
                return {"domain_id": domain_id, "type": "user_multicast", "participant_id": None}
            for pid in range(120):  # Max reasonable participants
                if port == cls.discovery_unicast(domain_id, pid):
                    return {"domain_id": domain_id, "type": "discovery_unicast", "participant_id": pid}
                if port == cls.user_unicast(domain_id, pid):
                    return {"domain_id": domain_id, "type": "user_unicast", "participant_id": pid}
        return None
