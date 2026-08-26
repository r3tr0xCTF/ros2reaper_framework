#!/usr/bin/env python3
"""
unitree_recon.py - Phase 7 Module 1: Unitree Robot Discovery & Fingerprinting

Discovers Unitree robots on the DDS network by scanning for Unitree-specific
topic signatures. Identifies robot model (Go2, G1, B2, B2W, H1, H2) and
extracts live telemetry (motor states, IMU, battery).

DDS attack surface overview:
  Go2 (quadruped):
    /rt/lowstate          — unitree_go/msg/LowState       (12-joint feedback, IMU, battery)
    /rt/sportmodestate    — unitree_go/msg/SportModeState  (velocity, position, gait)
    /rt/wirelesscontroller— unitree_go/msg/WirelessController
    /api/sport/request    — unitree_api/msg/Request        [NO AUTH — numeric IDs only]
    /api/sport/response   — unitree_api/msg/Response

  G1 (humanoid, 29-DOF):
    /rt/lowstate          — unitree_hg/msg/LowState        (29-joint feedback)
    /rt/lf/lowstate       — low-frequency mirror
    /api/loco/request     — locomotion API
    /api/arm_sdk/request  — arm SDK API (dexterous hand)

  B2 / B2W (industrial quad / wheeled):
    /rt/lowstate          — unitree_go/msg/LowState
    /api/sport/request    — unitree_api/msg/Request

Security issues:
  UNITREE-001 (CRITICAL): /api/sport/request accepts any DDS participant — no auth.
  UNITREE-002 (CRITICAL): LowCmd topic writable by any participant on same domain.
  UNITREE-003 (HIGH):     Default CycloneDDS config has no DDS-Security policies.
"""

import subprocess
import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional


# Topics that indicate a Unitree robot is present
UNITREE_TOPIC_PATTERNS = [
    "lowstate", "sportmodestate", "motorstate", "imu_state", "uwbstate",
    "wirelesscontroller", "/api/sport", "/api/loco", "/api/arm_sdk",
    "bms", "lidarstate", "heightmap", "go2frontvideo", "audiohub",
]

ROBOT_SIGNATURES = {
    "g1": {
        "any_of": ["/api/arm_sdk/request", "/rt/lf/lowstate", "/rt/hand_cmd", "/rt/dex3"],
        "msg_hint": "hg",
    },
    "h2": {
        "any_of": ["/api/loco/request"],
        "prefix_hint": "h2",
    },
    "h1": {
        "any_of": ["/rt/lf/lowstate"],
        "msg_hint": "hg",
    },
    "b2w": {
        "any_of": [],
        "prefix_hint": "b2w",
    },
    "b2": {
        "any_of": [],
        "prefix_hint": "b2",
    },
    "go2": {
        "any_of": ["/rt/sportmodestate", "/rt/go2frontvideo", "/rt/uwbstate"],
        "msg_hint": "unitree_go",
    },
}

KNOWN_API_TOPICS = {
    "/api/sport/request":    "Sport mode — DAMP/MOVE/FLIP/SIT/STAND (40+ commands, NO AUTH)",
    "/api/loco/request":     "Locomotion API — humanoid motion primitives",
    "/api/arm_sdk/request":  "Arm SDK — manipulator/dexterous hand control",
    "/api/robot_state/request": "Robot state query API",
    "/api/bashrunner/request": "Bash runner — COMMAND EXECUTION API",
}


@dataclass
class UnitreeRobot:
    model: str = "unknown"
    domain_id: int = 0
    topics: list = field(default_factory=list)
    api_topics: list = field(default_factory=list)
    battery_voltage: Optional[float] = None
    battery_pct: Optional[float] = None
    motor_count: int = 0
    confidence: float = 0.0
    vulns: list = field(default_factory=list)


def _env(domain_id: int) -> dict:
    e = os.environ.copy()
    e["ROS_DOMAIN_ID"] = str(domain_id)
    return e


def _run_ros2(args: list, timeout: float = 5.0, domain_id: int = 0) -> Optional[str]:
    try:
        r = subprocess.run(["ros2"] + args, capture_output=True, text=True,
                           timeout=timeout, env=_env(domain_id))
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _list_topics(domain_id: int, timeout: float) -> list:
    out = _run_ros2(["topic", "list"], timeout=timeout, domain_id=domain_id)
    if not out:
        return []
    return [l.strip() for l in out.splitlines() if l.strip()]


def _get_topic_type(topic: str, domain_id: int) -> Optional[str]:
    return _run_ros2(["topic", "type", topic], timeout=4.0, domain_id=domain_id)


def _echo_once(topic: str, domain_id: int, wait: float = 4.0) -> Optional[str]:
    try:
        r = subprocess.run(
            ["ros2", "topic", "echo", "--once", topic],
            capture_output=True, text=True, timeout=wait + 2.0,
            env=_env(domain_id)
        )
        return r.stdout.strip() or None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _fingerprint(topics: list, domain_id: int) -> tuple:
    topic_set = set(topics)

    # Disambiguate humanoid models first
    g1_hits = ROBOT_SIGNATURES["g1"]["any_of"]
    if any(t in topic_set for t in g1_hits):
        return "g1", 0.92

    h1_hits = ROBOT_SIGNATURES["h1"]["any_of"]
    if any(t in topic_set for t in h1_hits):
        msg = _get_topic_type("/rt/lowstate", domain_id) or ""
        if "hg" in msg:
            return "h1", 0.88
        return "h1", 0.70

    # Wheeled/industrial
    if any("b2w" in t.lower() for t in topic_set):
        return "b2w", 0.95
    if any("b2" in t.lower() for t in topic_set) and "b2w" not in str(topic_set).lower():
        return "b2", 0.88

    # Go2 checks
    if "/rt/sportmodestate" in topic_set or "/rt/uwbstate" in topic_set:
        return "go2", 0.92
    if "/rt/lowstate" in topic_set:
        msg = _get_topic_type("/rt/lowstate", domain_id) or ""
        if "hg" in msg:
            return "h1", 0.80
        return "go2", 0.75

    if "/api/sport/request" in topic_set:
        return "go2", 0.65

    return "unknown", 0.30


def _assess_vulns(topics: list) -> list:
    topic_set = set(topics)
    vulns = []

    if "/api/sport/request" in topic_set:
        vulns.append({
            "id": "UNITREE-001", "severity": "CRITICAL",
            "title": "Unauthenticated Sport API",
            "detail": (
                "/api/sport/request accepts commands from any DDS participant. "
                "No cryptographic authentication — authorization is numeric API ID only. "
                "DAMP (api_id=1001) causes immediate motor cutoff; robot collapses."
            ),
        })

    if "/rt/lowstate" in topic_set or "/rt/lowcmd" in topic_set:
        vulns.append({
            "id": "UNITREE-002", "severity": "CRITICAL",
            "title": "Direct Motor Control Exposed",
            "detail": (
                "LowCmd topic is writable by any participant on the same DDS domain. "
                "Forged LowCmd with valid CRC32 enables arbitrary joint torque/position "
                "injection — direct physical actuation with no authentication."
            ),
        })

    if "/api/bashrunner/request" in topic_set:
        vulns.append({
            "id": "UNITREE-004", "severity": "CRITICAL",
            "title": "Remote Code Execution via BashRunner API",
            "detail": (
                "/api/bashrunner/request allows execution of arbitrary shell commands "
                "on the robot's onboard computer. Full OS-level RCE."
            ),
        })

    has_sros2 = any("security" in t.lower() or "sros" in t.lower() for t in topics)
    if not has_sros2:
        vulns.append({
            "id": "UNITREE-003", "severity": "HIGH",
            "title": "No DDS-Security Detected",
            "detail": (
                "Unitree's default CycloneDDS config (cyclonedds.xml) disables "
                "DDS-Security entirely. All traffic is unauthenticated and unencrypted."
            ),
        })

    for api_t, desc in KNOWN_API_TOPICS.items():
        if api_t in topic_set and api_t != "/api/sport/request":
            vulns.append({
                "id": "UNITREE-005", "severity": "HIGH",
                "title": f"Unauthenticated API: {api_t}",
                "detail": f"{desc}. No authentication enforced on DDS transport.",
            })

    return vulns


def enumerate(domain_id: int = 0, timeout: float = 5.0,
              verbose: bool = False) -> dict:
    print(f"[*] Scanning DDS domain {domain_id} for Unitree robots...")

    all_topics = _list_topics(domain_id, timeout)
    if not all_topics and timeout > 2:
        # Retry with longer timeout
        print("[*] No topics on first pass, retrying...")
        all_topics = _list_topics(domain_id, timeout * 1.5)

    if not all_topics:
        return {
            "found": False,
            "error": "No ROS2 topics found — check ros2 CLI, domain ID, or network interface",
            "domain_id": domain_id,
        }

    if verbose:
        print(f"[*] {len(all_topics)} topics discovered on domain {domain_id}")

    unitree_topics = [
        t for t in all_topics
        if any(pat in t.lower() for pat in UNITREE_TOPIC_PATTERNS)
    ]
    api_topics = [t for t in unitree_topics if "/api/" in t]

    model, confidence = _fingerprint(all_topics, domain_id)
    vulns = _assess_vulns(all_topics)

    return {
        "found": bool(unitree_topics),
        "model": model,
        "confidence": confidence,
        "domain_id": domain_id,
        "unitree_topics": unitree_topics,
        "api_topics": api_topics,
        "api_descriptions": {t: KNOWN_API_TOPICS[t] for t in api_topics if t in KNOWN_API_TOPICS},
        "total_topics": len(all_topics),
        "vulnerabilities": vulns,
    }


def sniff_state(domain_id: int = 0, duration: float = 5.0,
                verbose: bool = False) -> dict:
    print(f"[*] Capturing live Unitree state (domain {domain_id}, wait {duration}s)...")

    # Try Go2/quadruped state first, then humanoid
    raw = _echo_once("/rt/lowstate", domain_id, duration)
    source = "/rt/lowstate"
    if not raw:
        raw = _echo_once("/rt/lf/lowstate", domain_id, duration)
        source = "/rt/lf/lowstate"

    if not raw:
        return {
            "error": "No lowstate captured — robot offline or on different domain",
            "domain_id": domain_id,
        }

    result: dict = {"topic": source, "domain_id": domain_id, "raw_sample": raw}

    # Battery voltage (unitree_go: power_v field)
    m = re.search(r"power_v:\s*([\d.]+)", raw)
    if m:
        v = float(m.group(1))
        result["battery_voltage"] = v
        # Go2: 6S LiPo, ~29.4V full → ~21V cutoff
        result["battery_pct"] = round(max(0.0, min(100.0, (v - 21.0) / (29.4 - 21.0) * 100)), 1)

    # Motor count
    result["motor_count"] = len(re.findall(r"- mode:", raw))

    # IMU RPY
    rpy = re.findall(r"rpy:\s*\[([\d.,\s-]+)\]", raw)
    if rpy:
        try:
            result["imu_rpy"] = [float(x) for x in rpy[0].split(",")]
        except ValueError:
            pass

    print(f"[+] State snapshot captured ({len(raw)} chars)")
    return result


def run(mode: str = "enumerate", domain_id: int = 0,
        timeout: float = 5.0, duration: float = 5.0,
        verbose: bool = False) -> dict:
    if mode == "sniff":
        return sniff_state(domain_id, duration, verbose)
    return enumerate(domain_id, timeout, verbose)


def print_recon_report(result: dict):
    if result.get("error"):
        print(f"\n\033[91m[!] {result['error']}\033[0m")
        return

    if not result.get("found"):
        print("\n[-] No Unitree robots detected on this domain")
        return

    print(f"\n\033[92m[+] Unitree Robot Detected\033[0m")
    model = result.get("model", "unknown").upper()
    conf  = result.get("confidence", 0) * 100
    print(f"    Model      : {model}  (confidence {conf:.0f}%)")
    print(f"    Domain ID  : {result.get('domain_id', 0)}")
    print(f"    Topics     : {len(result.get('unitree_topics', []))} Unitree / "
          f"{result.get('total_topics', 0)} total")

    api_topics = result.get("api_topics", [])
    if api_topics:
        print(f"\n\033[91m[!] Unauthenticated API endpoints:\033[0m")
        descs = result.get("api_descriptions", {})
        for t in api_topics:
            desc = descs.get(t, "")
            print(f"    \033[93m{t}\033[0m")
            if desc:
                print(f"        {desc}")

    vulns = result.get("vulnerabilities", [])
    if vulns:
        print(f"\n\033[91m[!] Vulnerabilities ({len(vulns)}):\033[0m")
        for v in vulns:
            clr = "\033[91m" if v["severity"] == "CRITICAL" else "\033[93m"
            print(f"\n    [{clr}{v['severity']}\033[0m] {v['id']}: {v['title']}")
            print(f"    {v['detail']}")

    print(f"\n    All Unitree topics:")
    for t in result.get("unitree_topics", []):
        print(f"      {t}")

    if "battery_pct" in result:
        print(f"\n    Battery : {result['battery_pct']:.1f}% "
              f"({result.get('battery_voltage', 0):.2f}V)")
    if result.get("motor_count"):
        print(f"    Motors  : {result['motor_count']}")
    if result.get("imu_rpy"):
        rpy = result["imu_rpy"]
        print(f"    IMU RPY : [{rpy[0]:.3f}, {rpy[1]:.3f}, {rpy[2]:.3f}] rad")


def export_json(result: dict, path: str):
    with open(path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[+] Saved to {path}")
