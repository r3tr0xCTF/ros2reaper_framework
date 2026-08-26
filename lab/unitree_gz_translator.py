#!/usr/bin/env python3
"""
unitree_gz_translator.py — bridges Unitree DDS attack topics into Gazebo Harmonic.

Roles:
  1. Homing controller: continuously publishes joint velocities to hold the Go2
     in a standing pose (P controller on virtual joint state).
  2. Attack listener: subscribes to /api/sport/request and /rt/lowcmd (same
     topics the real robot uses) and translates them into Gazebo commands.
  3. Fake telemetry: publishes /rt/lowstate and /rt/sportmodestate so that
     unitree-recon and unitree-lowcmd check_lowcmd_exposure still work
     exactly as against a real robot.

Attack → Gazebo mapping:
  DAMP (api_id=1001)        → all joint velocities → 0, no drive → robot collapses
  STOP_MOVE (api_id=1003)   → cmd_vel = 0
  STAND_DOWN (api_id=1005)  → joints ease to prone position
  MOVE (api_id=1008)        → cmd_vel.linear/angular
  velocity_lock (lowcmd)    → override joint velocities with commanded tau
  LowCmd inject             → map motor tau → joint velocity targets
"""

import rclpy
from rclpy.node import Node
import json, math, time, threading
from std_msgs.msg import Float64
from geometry_msgs.msg import Twist

try:
    from unitree_api.msg import Request
    from unitree_go.msg import LowCmd, LowState, SportModeState, BmsState
    _UNITREE = True
except ImportError:
    _UNITREE = False
    print("[!] unitree_go/unitree_api packages not found — will only publish joint commands")

# ── Joint name order (matches Unitree SDK motor indices 0-11) ────────────────
JOINT_NAMES = [
    "FR_hip", "FR_thigh", "FR_calf",
    "FL_hip", "FL_thigh", "FL_calf",
    "RR_hip", "RR_thigh", "RR_calf",
    "RL_hip", "RL_thigh", "RL_calf",
]

# Nominal standing joint positions (radians)
#  Hip=0, Thigh≈0.9 (pitched forward), Calf≈-1.8 (bent back)
STAND_POS = [0.0, 0.9, -1.8,  0.0, 0.9, -1.8,
             0.0, 0.9, -1.8,  0.0, 0.9, -1.8]

# Prone/damp position — legs fold inward
DAMP_POS  = [0.0, 1.3, -2.5,  0.0, 1.3, -2.5,
             0.0, 1.3, -2.5,  0.0, 1.3, -2.5]

# Joint velocity limits (rad/s)
MAX_VEL = 5.0

# Homing P-gain: vel = Kp * pos_error  (capped to MAX_VEL)
KP_STAND = 4.0
KP_DAMP  = 6.0   # faster collapse

# Sport API IDs
API_DAMP       = 1001
API_STOP_MOVE  = 1003
API_STAND_DOWN = 1005
API_STAND_UP   = 1004
API_MOVE       = 1008

HOMING_RATE = 50  # Hz — how often joint velocity commands are published


class UnitreeGzTranslator(Node):

    def __init__(self):
        super().__init__("unitree_gz_translator")

        # Virtual joint state (integrated from commanded velocities, open-loop)
        self._vpos = list(STAND_POS)   # start assuming standing
        self._lock = threading.Lock()

        # State machine
        self._mode = "homing"   # homing | standing | damped | moving
        self._target_pos = list(STAND_POS)
        self._kp = KP_STAND
        self._body_vel = (0.0, 0.0, 0.0)   # vx, vy, vyaw
        self._body_vel_active = False
        self._damp_start = None

        # ── Publishers: joint velocity → ROS2 → ros_gz_bridge → Gazebo ──────
        self._jv_pubs = {
            name: self.create_publisher(Float64, f"/go2/joint_vel/{name}", 5)
            for name in JOINT_NAMES
        }
        self._cmd_vel_pub = self.create_publisher(Twist, "/go2/cmd_vel", 5)

        # ── Publishers: fake Unitree telemetry (ROS2 only) ───────────────────
        if _UNITREE:
            self._lowstate_pub  = self.create_publisher(LowState,  "/rt/lowstate",       10)
            self._sportstate_pub= self.create_publisher(SportModeState, "/rt/sportmodestate", 10)
            self._bms_pub       = self.create_publisher(BmsState,  "/rt/bms_state",      5)

        # ── Subscribers: Unitree attack topics ───────────────────────────────
        if _UNITREE:
            self.create_subscription(Request, "/api/sport/request",
                                     self._on_sport_request, 10)
            self.create_subscription(LowCmd, "/rt/lowcmd",
                                     self._on_lowcmd, 10)

        # ── Timers ────────────────────────────────────────────────────────────
        dt = 1.0 / HOMING_RATE
        self.create_timer(dt,      self._homing_tick)
        self.create_timer(1.0/20,  self._publish_telemetry)

        self.get_logger().info(
            f"[gz-translator] active — joint controller @ {HOMING_RATE}Hz, "
            f"unitree_msgs={'yes' if _UNITREE else 'no'}"
        )
        self.get_logger().info(
            "[gz-translator] homing to standing position (~3s)..."
        )

    # ── Attack handlers ───────────────────────────────────────────────────────

    def _on_sport_request(self, msg):
        api_id = msg.header.identity.api_id
        try:
            params = json.loads(msg.parameter) if msg.parameter.strip() else {}
        except (json.JSONDecodeError, AttributeError):
            params = {}

        with self._lock:
            if api_id == API_DAMP:
                self.get_logger().warn(
                    "\033[91m[ATTACK] DAMP (1001) received — dropping all joint torques!\033[0m"
                )
                self._mode = "damped"
                self._target_pos = list(DAMP_POS)
                self._kp = KP_DAMP
                self._body_vel = (0.0, 0.0, 0.0)
                self._body_vel_active = False
                self._damp_start = time.monotonic()

            elif api_id == API_STOP_MOVE:
                self.get_logger().warn("[ATTACK] STOP_MOVE (1003) — halting body velocity")
                self._body_vel = (0.0, 0.0, 0.0)
                self._body_vel_active = True   # publish zero once, then stop

            elif api_id == API_STAND_DOWN:
                self.get_logger().warn("[ATTACK] STAND_DOWN (1005) — easing to prone")
                self._mode = "standing"
                self._target_pos = list(DAMP_POS)
                self._kp = KP_STAND
                self._body_vel = (0.0, 0.0, 0.0)
                self._body_vel_active = False

            elif api_id == API_STAND_UP:
                self.get_logger().info("[ATTACK] STAND_UP (1004) — homing back to stand")
                self._mode = "homing"
                self._target_pos = list(STAND_POS)
                self._kp = KP_STAND

            elif api_id == API_MOVE:
                vx   = float(params.get("x", 0.0))
                vy   = float(params.get("y", 0.0))
                vyaw = float(params.get("z", 0.0))
                self.get_logger().warn(
                    f"\033[93m[ATTACK] MOVE (1008) — injecting vx={vx:.2f} vy={vy:.2f} "
                    f"vyaw={vyaw:.2f} into Gazebo\033[0m"
                )
                self._body_vel = (vx, vy, vyaw)
                self._body_vel_active = True
            else:
                self.get_logger().info(f"[ATTACK] sport api_id={api_id} received")

    def _on_lowcmd(self, msg):
        with self._lock:
            self.get_logger().warn(
                "\033[91m[ATTACK] LowCmd received — overriding joint velocity targets\033[0m"
            )
            self._mode = "lowcmd"
            for i, motor in enumerate(msg.motor_cmd[:12]):
                tau = getattr(motor, "tau", 0.0)
                kp  = getattr(motor, "kp",  0.0)
                kd  = getattr(motor, "kd",  0.0)
                q   = getattr(motor, "q",   0.0)
                # Map commanded torque/position to a velocity target (simplified):
                # Use q (position) as target if kp > 0, otherwise tau as velocity hint
                if kp > 0.1:
                    self._target_pos[i] = q
                elif abs(tau) > 0.1:
                    self._target_pos[i] = self._vpos[i] + (tau * 0.3)

    # ── Homing / control tick ─────────────────────────────────────────────────

    def _homing_tick(self):
        dt = 1.0 / HOMING_RATE

        with self._lock:
            target  = self._target_pos[:]
            kp      = self._kp
            vpos    = self._vpos[:]
            mode    = self._mode
            bv      = self._body_vel
            bv_act  = self._body_vel_active
            damp_t  = self._damp_start

        vels = []
        for i in range(12):
            err = target[i] - vpos[i]
            vel = kp * err
            vel = max(-MAX_VEL, min(MAX_VEL, vel))

            # After DAMP settles (>2s), stop publishing → joints go free
            if mode == "damped" and damp_t is not None:
                elapsed = time.monotonic() - damp_t
                if elapsed > 2.0:
                    vel = 0.0   # stop commanding → joints coast under gravity

            vels.append(vel)

        # Integrate virtual state
        new_vpos = [vpos[i] + vels[i] * dt for i in range(12)]

        with self._lock:
            self._vpos = new_vpos

        # Publish joint velocity commands
        for i, name in enumerate(JOINT_NAMES):
            msg = Float64()
            msg.data = float(vels[i])
            self._jv_pubs[name].publish(msg)

        # Publish body velocity
        if bv_act:
            twist = Twist()
            twist.linear.x  = float(bv[0])
            twist.linear.y  = float(bv[1])
            twist.angular.z = float(bv[2])
            self._cmd_vel_pub.publish(twist)

            # If it was a one-shot stop, clear it
            if bv[0] == 0.0 and bv[1] == 0.0 and bv[2] == 0.0:
                with self._lock:
                    self._body_vel_active = False

        # Transition homing → standing when close enough
        if mode == "homing":
            errs = [abs(target[i] - new_vpos[i]) for i in range(12)]
            if max(errs) < 0.05:
                with self._lock:
                    self._mode = "standing"
                self.get_logger().info(
                    "\033[92m[gz-translator] standing position reached — ready for attacks\033[0m"
                )

    # ── Fake telemetry ────────────────────────────────────────────────────────

    def _publish_telemetry(self):
        if not _UNITREE:
            return

        with self._lock:
            vpos = self._vpos[:]
            mode = self._mode
            bv   = self._body_vel

        # LowState (motor feedback)
        ls = LowState()
        ls.imu_state.rpy = [0.0, 0.0, 0.0]
        ls.imu_state.accelerometer = [0.0, 0.0, 9.81]
        ls.imu_state.gyroscope     = [0.0, 0.0, 0.0]
        for i in range(20):
            if i < 12:
                ls.motor_state[i].q    = float(vpos[i])
                ls.motor_state[i].dq   = 0.0
                ls.motor_state[i].tau_est = 0.0 if mode == "damped" else 5.0
                ls.motor_state[i].temperature = 35
        ls.power_v = 25.5   # ~87% battery
        ls.power_a = 1.2
        self._lowstate_pub.publish(ls)

        # SportModeState
        sm = SportModeState()
        sm.mode = 0 if mode == "damped" else 2
        sm.velocity = [float(bv[0]), float(bv[1]), float(bv[2])]
        sm.body_height = 0.0 if mode == "damped" else 0.32
        sm.gait_type = 1 if mode == "standing" else 0
        self._sportstate_pub.publish(sm)

        # BmsState
        bms = BmsState()
        bms.version_h = 1
        bms.bq_ntc = [30, 30]
        bms.mcu_ntc = [35, 35]
        bms.cell_vol = [3850] * 15
        self._bms_pub.publish(bms)


def main():
    rclpy.init()
    node = UnitreeGzTranslator()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.try_shutdown()


if __name__ == "__main__":
    main()
