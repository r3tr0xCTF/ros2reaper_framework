#!/usr/bin/env python3
"""
mock_unitree.py — Simulated Unitree robot DDS interface for lab testing.

Publishes the same topics a real Unitree robot would, and logs all incoming
commands from ros2reaper Phase 7 modules so you can observe attacks landing.

Requirements:
    source /opt/ros/jazzy/setup.bash
    source ~/unitree_ros2_ws/install/setup.bash
    export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
    export CYCLONEDDS_URI=file://$(pwd)/lab/cyclone_local.xml

Usage:
    python3 lab/mock_unitree.py [--model go2] [--domain-id 0] [--verbose]
"""

import sys
import time
import math
import struct
import argparse
import threading

# ── ROS2 import guard ─────────────────────────────────────────────────────────
try:
    import rclpy
    from rclpy.node import Node
    from rclpy.qos import (QoSProfile, ReliabilityPolicy,
                           DurabilityPolicy, HistoryPolicy)
    from rclpy.executors import MultiThreadedExecutor
except ImportError:
    print("\033[91m[X]\033[0m rclpy not found — source your ROS2 workspace first:")
    print("    source /opt/ros/jazzy/setup.bash")
    sys.exit(1)

# ── Unitree message type guard ────────────────────────────────────────────────
try:
    from unitree_go.msg import SportModeState, LowState, LowCmd, BmsState
    from unitree_api.msg import Request as UnitreeRequest
    UNITREE_MSGS = True
except ImportError:
    print("\033[91m[X]\033[0m Unitree message types not found.")
    print("    Build the workspace and source it:")
    print("    cd ~/unitree_ros2_ws && colcon build --symlink-install")
    print("    source ~/unitree_ros2_ws/install/setup.bash")
    sys.exit(1)

# ── Sport API ID → name map ───────────────────────────────────────────────────
SPORT_API_NAMES = {
    1001: "DAMP",           1002: "BALANCE_STAND",  1003: "STOP_MOVE",
    1004: "STAND_UP",       1005: "STAND_DOWN",      1006: "RECOVERY_STAND",
    1007: "EULER",          1008: "MOVE",            1009: "SIT",
    1010: "RISE_SIT",       1011: "SWITCH_GAIT",     1012: "TRIGGER",
    1013: "BODY_HEIGHT",    1014: "FOOT_RAISE",      1015: "SPEED_LEVEL",
    1016: "HELLO",          1017: "STRETCH",         1018: "TRAJECTORY",
    1019: "CONTINUOUS_GAIT",1020: "CONTENT_PROGRESS",1021: "SWITCH_LOC",
    2001: "WAVING",         2002: "ADVANCED_MOVE",   2003: "MOON_WALK",
    2004: "BACK_FLIP_PREP", 2005: "SHAKE_HAND",      2006: "DANCE",
    2007: "ECONOMICAL_MOVE",2008: "LEARN_GAIT",       2009: "LEARN_STAND",
    1030: "FRONT_FLIP",     2043: "BACK_FLIP",       2044: "HANDSTAND",
    2045: "JUMP_YAW",       2046: "JUMP_FORWARD",    2050: "WALK_UPRIGHT",
    2051: "CROSS_STEP",     2054: "AUTO_RECOVERY_SET",2055: "AUTO_RECOVERY_GET",
    2058: "SWITCH_AVOID_MODE",
}

# Per-model topic sets (used for fingerprinting — publish these topics)
MODEL_TOPICS = {
    "go2": {
        "sport_state":  "/rt/sportmodestate",
        "low_state":    "/rt/lowstate",
        "low_cmd":      "/rt/lowcmd",
        "bms":          "/rt/bms_state",
        "sport_req":    "/api/sport/request",
        "loco_req":     "/api/loco/request",
    },
    "g1": {
        "sport_state":  "/rt/sportmodestate",
        "low_state":    "/rt/lowstate",
        "low_cmd":      "/rt/lowcmd",
        "bms":          "/rt/bms_state",
        "sport_req":    "/api/sport/request",
        "arm_req":      "/api/arm_sdk/request",  # G1-specific fingerprint
        "loco_req":     "/api/loco/request",
    },
    "b2": {
        "sport_state":  "/rt/sportmodestate",
        "low_state":    "/rt/lowstate",
        "low_cmd":      "/rt/lowcmd",
        "bms":          "/rt/bms_state",
        "sport_req":    "/api/sport/request",
    },
    "h1": {
        "sport_state":  "/rt/sportmodestate",
        "low_state":    "/rt/lowstate",
        "low_cmd":      "/rt/lowcmd",
        "bms":          "/rt/bms_state",
        "sport_req":    "/api/sport/request",
        "arm_req":      "/api/arm_sdk/request",
    },
}

# Joint names per model (Go2 = 12 DOF)
JOINT_NAMES = {
    "go2": ["FR_hip","FR_thigh","FR_calf",
             "FL_hip","FL_thigh","FL_calf",
             "RR_hip","RR_thigh","RR_calf",
             "RL_hip","RL_thigh","RL_calf"],
    "g1":  [f"joint_{i}" for i in range(29)],
    "b2":  [f"joint_{i}" for i in range(12)],
    "h1":  [f"joint_{i}" for i in range(19)],
}

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
NC     = "\033[0m"

ATTACK_COUNT = {"sport": 0, "lowcmd": 0}


def _banner(model: str, domain_id: int):
    print(f"""
{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗
║   Mock Unitree Robot — ROS2Reaper Lab Target         ║
╚══════════════════════════════════════════════════════╝{NC}

  Model     : {BOLD}{model.upper()}{NC}
  Domain    : {domain_id}
  DDS impl  : rmw_cyclonedds_cpp
  Topics    : publishing state, subscribing to attack topics

  {YELLOW}[!] This is a simulated robot. Attack commands are logged
      below. No hardware will move.{NC}

  {GREEN}Ready. Waiting for Phase 7 attack modules...{NC}
""")


class MockUnitreeRobot(Node):
    def __init__(self, model: str, verbose: bool):
        super().__init__("mock_unitree_" + model)
        self.model   = model
        self.verbose = verbose
        self.t0      = time.monotonic()
        self.topics  = MODEL_TOPICS.get(model, MODEL_TOPICS["go2"])
        self.joints  = JOINT_NAMES.get(model, JOINT_NAMES["go2"])
        self._seq    = 0

        reliable_qos = QoSProfile(
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.VOLATILE,
            history=HistoryPolicy.KEEP_LAST,
            depth=10,
        )
        best_effort_qos = QoSProfile(
            reliability=ReliabilityPolicy.BEST_EFFORT,
            durability=DurabilityPolicy.VOLATILE,
            history=HistoryPolicy.KEEP_LAST,
            depth=1,
        )

        # ── Publishers ────────────────────────────────────────────────────────
        self._pub_sport = self.create_publisher(
            SportModeState, self.topics["sport_state"], reliable_qos)
        self._pub_bms = self.create_publisher(
            BmsState, self.topics["bms"], reliable_qos)
        self._pub_low = self.create_publisher(
            LowState, self.topics["low_state"], best_effort_qos)

        # ── Subscribers (attack surfaces) ─────────────────────────────────────
        self.create_subscription(
            UnitreeRequest, self.topics["sport_req"],
            self._on_sport_request, reliable_qos)

        self.create_subscription(
            LowCmd, self.topics["low_cmd"],
            self._on_low_cmd, best_effort_qos)

        if "loco_req" in self.topics:
            self.create_subscription(
                UnitreeRequest, self.topics["loco_req"],
                lambda msg: self._on_api_request("loco", msg), reliable_qos)

        if "arm_req" in self.topics:
            self.create_subscription(
                UnitreeRequest, self.topics["arm_req"],
                lambda msg: self._on_api_request("arm_sdk", msg), reliable_qos)

        # ── Publish timers ────────────────────────────────────────────────────
        self.create_timer(0.1,  self._pub_sport_state)   # 10 Hz
        self.create_timer(0.02, self._pub_low_state)     # 50 Hz
        self.create_timer(1.0,  self._pub_bms_state)     # 1 Hz
        self.create_timer(30.0, self._print_stats)

        self.get_logger().info(f"Mock {model.upper()} robot online on domain {self.get_namespace()}")

    # ── State publishers ──────────────────────────────────────────────────────
    def _pub_sport_state(self):
        t   = time.monotonic() - self.t0
        msg = SportModeState()
        msg.mode          = 2
        msg.progress      = 0.0
        msg.gait_type     = 1
        msg.foot_raise_height = 0.09
        msg.position      = [0.0, 0.0, 0.0]
        msg.body_height   = 0.32
        msg.velocity      = [0.0, 0.0, 0.0]
        msg.yaw_speed     = 0.0
        msg.range_obstacle= [5.0, 5.0, 5.0, 5.0]
        msg.foot_position_body = [
            0.17, -0.1, -0.3,
            0.17,  0.1, -0.3,
           -0.17, -0.1, -0.3,
           -0.17,  0.1, -0.3,
        ]
        msg.foot_speed_body = [0.0] * 12
        self._pub_sport.publish(msg)

    def _pub_low_state(self):
        msg = LowState()
        n = min(len(self.joints), len(msg.motor_state))
        for i in range(n):
            msg.motor_state[i].mode = 1
            msg.motor_state[i].q    = 0.0
            msg.motor_state[i].dq   = 0.0
            msg.motor_state[i].ddq  = 0.0
            msg.motor_state[i].tau_est = 0.0
            msg.motor_state[i].temperature = 35
        self._pub_low.publish(msg)

    def _pub_bms_state(self):
        msg = BmsState()
        msg.version_high = 1
        msg.version_low  = 0
        msg.status       = 1
        msg.soc          = 85
        msg.current      = -500       # mA
        msg.cycle        = 12
        msg.bq_ntc       = [30, 30]
        msg.mcu_ntc      = [35, 35]
        msg.cell_vol     = [3850] * 15
        self._pub_bms.publish(msg)

    # ── Attack handlers ───────────────────────────────────────────────────────
    def _on_sport_request(self, msg: UnitreeRequest):
        ATTACK_COUNT["sport"] += 1
        api_id  = msg.header.identity.api_id
        seq     = msg.header.identity.id
        param   = msg.parameter
        name    = SPORT_API_NAMES.get(api_id, f"UNKNOWN_{api_id}")

        crit = api_id in (1001, 1003, 1030, 2043, 2044)  # damp / front_flip / back_flip / handstand
        clr  = RED if crit else YELLOW

        print(f"\n{clr}{BOLD}[ATTACK HIT]{NC} Sport API Request #{ATTACK_COUNT['sport']}")
        print(f"  Topic    : {self.topics['sport_req']}")
        print(f"  seq/id   : {seq}")
        print(f"  api_id   : {api_id} → {BOLD}{name}{NC}")
        if param and param.strip() not in ("''", "\"\"", ""):
            print(f"  param    : {param}")
        if crit:
            print(f"  {RED}[CRITICAL] This command would cause physical motion on a real robot!{NC}")
        if self.verbose:
            print(f"  raw msg  : {msg}")

    def _on_low_cmd(self, msg: LowCmd):
        ATTACK_COUNT["lowcmd"] += 1
        n = min(len(self.joints), len(msg.motor_cmd))
        print(f"\n{RED}{BOLD}[ATTACK HIT]{NC} LowCmd motor control #{ATTACK_COUNT['lowcmd']}")
        print(f"  Topic    : {self.topics['low_cmd']}")
        print(f"  {RED}[CRITICAL] Direct motor control — bypasses Sport API entirely{NC}")
        print(f"  Motors commanded ({n} joints):")
        for i in range(n):
            mc = msg.motor_cmd[i]
            if mc.mode != 0 or mc.tau != 0.0 or mc.kp != 0.0 or mc.kd != 0.0:
                name = self.joints[i] if i < len(self.joints) else f"joint_{i}"
                print(f"    [{i:2d}] {name:12s}  mode={mc.mode}  q={mc.q:+.3f}  tau={mc.tau:+.3f}  kp={mc.kp:.1f}  kd={mc.kd:.1f}")

    def _on_api_request(self, api_name: str, msg: UnitreeRequest):
        ATTACK_COUNT["sport"] += 1
        api_id = msg.header.identity.api_id
        print(f"\n{YELLOW}{BOLD}[ATTACK HIT]{NC} {api_name} API Request")
        print(f"  api_id : {api_id}")
        if msg.parameter:
            print(f"  param  : {msg.parameter}")

    def _print_stats(self):
        elapsed = time.monotonic() - self.t0
        print(f"\n{CYAN}[STATS]{NC} +{elapsed:.0f}s  sport_attacks={ATTACK_COUNT['sport']}  lowcmd_attacks={ATTACK_COUNT['lowcmd']}")


def main():
    parser = argparse.ArgumentParser(description="Mock Unitree robot for ROS2Reaper lab")
    parser.add_argument("--model",     default="go2",
                        choices=list(MODEL_TOPICS.keys()),
                        help="Robot model to simulate (default: go2)")
    parser.add_argument("--domain-id", default=0, type=int,
                        help="DDS domain ID (default: 0)")
    parser.add_argument("--verbose",   action="store_true",
                        help="Print raw message content on each attack hit")
    args = parser.parse_args()

    _banner(args.model, args.domain_id)

    rclpy.init(args=None)
    robot = MockUnitreeRobot(model=args.model, verbose=args.verbose)

    executor = MultiThreadedExecutor(num_threads=4)
    executor.add_node(robot)

    try:
        executor.spin()
    except KeyboardInterrupt:
        pass

    print(f"\n{CYAN}[*]{NC} Mock robot shutting down.")
    print(f"    Total Sport API hits : {ATTACK_COUNT['sport']}")
    print(f"    Total LowCmd hits    : {ATTACK_COUNT['lowcmd']}")
    executor.shutdown(timeout_sec=1.0)
    robot.destroy_node()
    rclpy.try_shutdown()


if __name__ == "__main__":
    main()
