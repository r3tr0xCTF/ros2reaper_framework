#!/usr/bin/env python3
"""
microros_agent.py - Phase 5A: micro-ROS XRCE Agent Discovery & Enumeration

Discovers XRCE Agents on the network, fingerprints versions/configs,
and enumerates connected micro-ROS clients (participants).

XRCE (eXtremely Resource Constrained Environments) is the serialized
DDS variant used by micro-ROS on embedded systems.

Standard ports:
  - UDP/8888: Default XRCE Agent port (micro-ROS Agent listens here)
  - UDP/7400+: Alternative XRCE ports (configurable per Agent instance)

Wire format: XRCE uses a binary protocol with:
  - Session ID (1 byte)
  - Stream ID (1 byte)  
  - Sequence number (2 bytes, little-endian)
  - Payload length (2 bytes, little-endian)
  - Message type (1 byte)
  - Payload (variable)

Attack surface mapped:
  - Agent enumeration (version, config, allowed participants)
  - Participant discovery (which MCU clients are connected)
  - Session hijacking (spoof client connections)
  - Topic enumeration (topics the agent knows about)
"""

import socket
import struct
import threading
import time
import argparse
import json
import sys
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
import ipaddress
from datetime import datetime


# ============================================================================
# XRCE Wire Format Constants
# ============================================================================

# XRCE Message Types (PRO header)
XRCE_MSG_CREATE = 0x01
XRCE_MSG_DELETE = 0x02
XRCE_MSG_WRITE = 0x03
XRCE_MSG_READ = 0x04
XRCE_MSG_ACKNOWLEDGE = 0x05
XRCE_MSG_HEARTBEAT = 0x07
XRCE_MSG_RESET = 0x0D
XRCE_MSG_FRAGMENT = 0x0E
XRCE_MSG_INFO = 0x0F

# XRCE Object Classes
XRCE_CLASS_PARTICIPANT = 0x01
XRCE_CLASS_TOPIC = 0x02
XRCE_CLASS_PUBLISHER = 0x03
XRCE_CLASS_SUBSCRIBER = 0x04
XRCE_CLASS_DATAWRITER = 0x05
XRCE_CLASS_DATAREADER = 0x06

XRCE_CLASS_NAMES = {
    0x01: "PARTICIPANT",
    0x02: "TOPIC",
    0x03: "PUBLISHER",
    0x04: "SUBSCRIBER",
    0x05: "DATAWRITER",
    0x06: "DATAREADER",
}

# XRCE magic number (identifies an XRCE packet)
XRCE_MAGIC = 0x58524350  # "XRCP" in hex

# Known XRCE Agent fingerprints (version strings + behaviors)
AGENT_FINGERPRINTS = {
    "Micro XRCE-DDS Agent": {
        "vendor": "eProsima",
        "product": "Micro XRCE-DDS Agent",
        "versions": ["1.0.0", "1.1.0", "1.2.x", "2.0.x"],
        "default_port": 8888,
        "supports_qos": True,
        "supports_secure": False,
    },
    "Micro ROS Agent": {
        "vendor": "micro-ROS",
        "product": "micro-ROS Agent",
        "versions": ["humble", "rolling"],
        "default_port": 8888,
        "supports_qos": True,
        "supports_secure": False,
    },
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class XRCEAgent:
    """Represents a discovered XRCE Agent"""
    ip: str
    port: int
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    supports_qos: bool = False
    supports_secure: bool = False
    participants: List[str] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    response_time_ms: float = 0
    heartbeat_count: int = 0

    def to_dict(self):
        """Convert to JSON-serializable dict"""
        return {
            "ip": self.ip,
            "port": self.port,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "supports_qos": self.supports_qos,
            "supports_secure": self.supports_secure,
            "participants": self.participants,
            "response_time_ms": self.response_time_ms,
            "heartbeat_count": self.heartbeat_count,
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
        }


@dataclass
class XRCEParticipant:
    """Represents a micro-ROS client connected to an Agent"""
    agent_ip: str
    agent_port: int
    session_id: int
    participant_id: int
    client_ip: Optional[str] = None
    client_port: Optional[int] = None
    client_key: Optional[str] = None
    topics: List[str] = field(default_factory=list)
    publishers: int = 0
    subscribers: int = 0
    last_activity: float = field(default_factory=time.time)

    def to_dict(self):
        return {
            "agent_ip": self.agent_ip,
            "agent_port": self.agent_port,
            "session_id": self.session_id,
            "participant_id": self.participant_id,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "client_key": self.client_key,
            "topics": self.topics,
            "publishers": self.publishers,
            "subscribers": self.subscribers,
            "last_activity": datetime.fromtimestamp(self.last_activity).isoformat(),
        }


@dataclass
class XRCETopic:
    """Represents a topic in the XRCE environment"""
    name: str
    type_name: str
    agent_ip: str
    agent_port: int
    participant_id: int
    writers: int = 0
    readers: int = 0
    qos_reliable: bool = False

    def to_dict(self):
        return {
            "name": self.name,
            "type_name": self.type_name,
            "agent_ip": self.agent_ip,
            "agent_port": self.agent_port,
            "participant_id": self.participant_id,
            "writers": self.writers,
            "readers": self.readers,
            "qos_reliable": self.qos_reliable,
        }


# ============================================================================
# XRCE Wire Format Parsing
# ============================================================================

class XRCEPacketParser:
    """Parse XRCE wire format packets"""

    @staticmethod
    def parse_header(data: bytes) -> Optional[Dict]:
        """
        Parse XRCE packet header (PRO header, 8 bytes minimum)
        
        Format:
          Bytes 0-3:   Magic (0x58524350 = "XRCP")
          Byte 4:      Flags
          Byte 5:      Session ID
          Bytes 6-7:   Stream ID (little-endian, 16-bit)
        
        Returns dict with parsed fields or None if invalid
        """
        if len(data) < 8:
            return None

        magic = struct.unpack("<I", data[0:4])[0]
        if magic != XRCE_MAGIC:
            return None

        flags = data[4]
        session_id = data[5]
        stream_id = struct.unpack("<H", data[6:8])[0]

        return {
            "magic": magic,
            "flags": flags,
            "session_id": session_id,
            "stream_id": stream_id,
            "header_len": 8,
        }

    @staticmethod
    def parse_submessage(data: bytes, offset: int = 8) -> Optional[Dict]:
        """
        Parse XRCE submessage (follows PRO header)
        
        Submessage format:
          Byte 0:     Message ID (high 4 bits) + flags (low 4 bits)
          Byte 1:     Reserved
          Bytes 2-3:  Submessage length (little-endian, 16-bit)
          Bytes 4+:   Submessage data
        
        Returns dict with parsed fields or None if invalid
        """
        if len(data) < offset + 4:
            return None

        msg_byte = data[offset]
        message_id = (msg_byte >> 4) & 0x0F
        flags = msg_byte & 0x0F
        reserved = data[offset + 1]
        length = struct.unpack("<H", data[offset + 2:offset + 4])[0]

        payload_start = offset + 4
        payload_end = payload_start + length

        if payload_end > len(data):
            return None

        payload = data[payload_start:payload_end]

        return {
            "message_id": message_id,
            "flags": flags,
            "length": length,
            "payload": payload,
            "total_size": 4 + length,
        }

    @staticmethod
    def extract_entity_id(payload: bytes) -> Optional[Tuple[int, int]]:
        """
        Extract entity ID from CREATE/DELETE payload
        Entity IDs are 2 bytes: class (low byte) + instance (high byte)
        
        Returns (class, instance) tuple or None
        """
        if len(payload) < 2:
            return None
        entity_id = struct.unpack("<H", payload[0:2])[0]
        class_id = entity_id & 0xFF
        instance_id = (entity_id >> 8) & 0xFF
        return (class_id, instance_id)

    @staticmethod
    def extract_string(data: bytes, offset: int) -> Tuple[Optional[str], int]:
        """
        Extract a null-terminated or length-prefixed string from XRCE payload
        Returns (string, bytes_consumed) or (None, 0) if invalid
        """
        # Try null-terminated first
        null_pos = data.find(b'\x00', offset)
        if null_pos > offset:
            string = data[offset:null_pos].decode('utf-8', errors='ignore')
            return (string, null_pos - offset + 1)
        return (None, 0)


# ============================================================================
# XRCE Agent Discovery & Enumeration
# ============================================================================

class XRCEAgentScanner:
    """Discover and fingerprint XRCE Agents on the network"""

    def __init__(self, timeout: float = 5.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.agents: Dict[Tuple[str, int], XRCEAgent] = {}
        self.participants: Dict[Tuple[str, int, int], XRCEParticipant] = {}
        self.topics: List[XRCETopic] = []

    def scan_port(self, ip: str, port: int) -> Optional[XRCEAgent]:
        """
        Probe a single IP:port for XRCE Agent presence
        
        Strategy:
          1. Send HEARTBEAT probe (low-cost, minimal impact)
          2. Listen for ACKNOWLEDGE response
          3. Measure response time
          4. Attempt fingerprinting via agent responses
        
        Returns XRCEAgent if found, None otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            # Build minimal HEARTBEAT probe
            probe = self._build_heartbeat_probe()

            start_time = time.time()
            sock.sendto(probe, (ip, port))

            response, _ = sock.recvfrom(4096)
            response_time = (time.time() - start_time) * 1000

            if self.verbose:
                print(f"[+] Response from {ip}:{port} ({response_time:.2f}ms)")

            # Parse response to extract agent info
            agent = XRCEAgent(
                ip=ip,
                port=port,
                response_time_ms=response_time,
                last_seen=time.time(),
            )

            # Attempt to fingerprint based on response
            self._fingerprint_agent(agent, response)

            return agent

        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    def scan_range(self, cidr: str, port: int = 8888, threads: int = 10) -> List[XRCEAgent]:
        """
        Scan a CIDR range for XRCE Agents
        
        Args:
            cidr: CIDR notation (e.g., "10.0.0.0/24")
            port: UDP port to probe (default 8888)
            threads: Number of parallel threads
        
        Returns list of discovered agents
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            print(f"[!] Invalid CIDR: {e}", file=sys.stderr)
            return []

        discovered = []
        ips = [str(ip) for ip in network.hosts()]

        if self.verbose:
            print(f"[*] Scanning {len(ips)} hosts on {port}/UDP...")

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=threads) as executor:
            results = executor.map(lambda ip: self.scan_port(ip, port), ips)
            discovered = [r for r in results if r is not None]

        return discovered

    def scan_multiport(self, ip: str, ports: List[int] = None) -> List[XRCEAgent]:
        """
        Scan a single IP across multiple ports
        
        Default ports:
          - 8888 (standard XRCE Agent)
          - 7400+ (alternative instances)
        """
        if ports is None:
            ports = [8888] + list(range(7400, 7410))

        discovered = []
        for port in ports:
            agent = self.scan_port(ip, port)
            if agent:
                discovered.append(agent)
                if self.verbose:
                    print(f"[+] Found XRCE Agent at {ip}:{port}")

        return discovered

    def enumerate_participants(self, agent: XRCEAgent, timeout: float = 5.0) -> List[XRCEParticipant]:
        """
        Enumerate micro-ROS clients (participants) connected to an Agent
        
        Strategy:
          1. Monitor incoming packets from the agent
          2. Track CREATE messages for PARTICIPANT objects
          3. Extract session/participant IDs
          4. Correlate with source addresses (if traceable)
        
        Returns list of discovered participants
        """
        participants = []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        try:
            # Send a READ_METADATA query to discover participants
            query = self._build_read_metadata_query()
            sock.sendto(query, (agent.ip, agent.port))

            end_time = time.time() + timeout
            while time.time() < end_time:
                try:
                    data, (src_ip, src_port) = sock.recvfrom(4096)

                    # Parse response for participant information
                    header = XRCEPacketParser.parse_header(data)
                    if not header:
                        continue

                    session_id = header['session_id']

                    # Extract participant data from submessage
                    submsg = XRCEPacketParser.parse_submessage(data)
                    if not submsg:
                        continue

                    if submsg['message_id'] == XRCE_MSG_CREATE:
                        entity = XRCEPacketParser.extract_entity_id(submsg['payload'])
                        if entity and entity[0] == XRCE_CLASS_PARTICIPANT:
                            participant = XRCEParticipant(
                                agent_ip=agent.ip,
                                agent_port=agent.port,
                                session_id=session_id,
                                participant_id=entity[1],
                                client_ip=src_ip,
                                client_port=src_port,
                            )
                            participants.append(participant)
                            if self.verbose:
                                print(f"[+] Discovered participant: {entity[1]} from {src_ip}:{src_port}")

                except socket.timeout:
                    break

        finally:
            sock.close()

        return participants

    def _fingerprint_agent(self, agent: XRCEAgent, response: bytes):
        """Attempt to identify agent vendor/version from response"""
        # Heuristics based on response patterns
        if b"eProsima" in response:
            agent.vendor = "eProsima"
            agent.product = "Micro XRCE-DDS Agent"
        elif b"micro-ROS" in response:
            agent.vendor = "micro-ROS"
            agent.product = "micro-ROS Agent"
        else:
            agent.vendor = "Unknown"
            agent.product = "Unknown XRCE Agent"

        agent.supports_qos = True
        agent.supports_secure = False

    def _build_heartbeat_probe(self) -> bytes:
        """Build a minimal HEARTBEAT probe packet"""
        magic = struct.pack("<I", XRCE_MAGIC)
        flags = bytes([0x00])
        session_id = bytes([0x00])
        stream_id = struct.pack("<H", 0x0000)

        msg_id_flags = (XRCE_MSG_HEARTBEAT << 4) | 0x01
        reserved = bytes([0x00])
        payload_len = struct.pack("<H", 0)

        submsg = bytes([msg_id_flags]) + reserved + payload_len

        return magic + flags + session_id + stream_id + submsg

    def _build_read_metadata_query(self) -> bytes:
        """Build a READ_METADATA query to enumerate participants"""
        magic = struct.pack("<I", XRCE_MAGIC)
        flags = bytes([0x00])
        session_id = bytes([0x00])
        stream_id = struct.pack("<H", 0x0001)

        msg_id_flags = (XRCE_MSG_READ << 4) | 0x01
        reserved = bytes([0x00])
        payload_len = struct.pack("<H", 0)

        submsg = bytes([msg_id_flags]) + reserved + payload_len

        return magic + flags + session_id + stream_id + submsg


# ============================================================================
# Reporting (ros2reaper framework compatible)
# ============================================================================

def print_agent_report(agents: List[XRCEAgent]):
    """Pretty-print discovered agents (matching ros2reaper style)"""
    if not agents:
        print("[*] No XRCE Agents found")
        return

    print(f"\n[+] Discovered {len(agents)} XRCE Agent(s):\n")
    for agent in agents:
        print(f"    IP:Port:         {agent.ip}:{agent.port}")
        print(f"    Vendor:          {agent.vendor or 'Unknown'}")
        print(f"    Product:         {agent.product or 'Unknown'}")
        print(f"    Version:         {agent.version or 'Unknown'}")
        print(f"    Response Time:   {agent.response_time_ms:.2f}ms")
        print(f"    Participants:    {len(agent.participants)}")
        print(f"    QoS Support:     {agent.supports_qos}")
        print(f"    Secure:          {agent.supports_secure}")
        print()


def export_json(agents: List[XRCEAgent], output_file: str):
    """Export results to JSON (ros2reaper framework compatible)"""
    output = {
        "module": "microros_agent",
        "timestamp": datetime.now().isoformat(),
        "agents": [agent.to_dict() for agent in agents],
        "summary": {
            "total_agents": len(agents),
            "total_participants": sum(len(a.participants) for a in agents),
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"[+] Results exported to {output_file}")


# ============================================================================
# CLI (standalone + framework integration)
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 5A: micro-ROS XRCE Agent discovery and enumeration"
    )
    parser.add_argument(
        "-i", "--ip",
        help="Single IP to scan"
    )
    parser.add_argument(
        "-c", "--cidr",
        help="CIDR range to scan (e.g., 10.0.0.0/24)"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8888,
        help="Port to scan (default: 8888)"
    )
    parser.add_argument(
        "-m", "--multiport",
        action="store_true",
        help="Scan common XRCE ports (8888, 7400-7409)"
    )
    parser.add_argument(
        "-e", "--enumerate",
        action="store_true",
        help="Enumerate participants on discovered agents"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        help="Scan timeout in seconds (default: 5)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file (JSON)"
    )

    args = parser.parse_args()

    scanner = XRCEAgentScanner(timeout=args.timeout, verbose=args.verbose)

    agents = []

    if args.ip:
        if args.multiport:
            agents = scanner.scan_multiport(args.ip)
        else:
            agent = scanner.scan_port(args.ip, args.port)
            if agent:
                agents = [agent]

    elif args.cidr:
        agents = scanner.scan_range(args.cidr, port=args.port, threads=10)

    else:
        parser.print_help()
        return

    if args.enumerate:
        for agent in agents:
            participants = scanner.enumerate_participants(agent)
            agent.participants = [f"{p.session_id}:{p.participant_id}" for p in participants]

    print_agent_report(agents)

    if args.output:
        export_json(agents, args.output)


if __name__ == "__main__":
    main()
