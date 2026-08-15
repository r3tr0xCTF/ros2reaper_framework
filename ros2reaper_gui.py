#!/usr/bin/env python3
"""
ROS2Reaper GUI — CustomTkinter interface for the ros2reaper framework.
Runs ros2reaper.py as a subprocess; no import-level coupling.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import threading
import os
import sys
import json
import re
import signal
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REAPER_PY = os.path.join(SCRIPT_DIR, "ros2reaper.py")
PROFILES_DIR = os.path.join(SCRIPT_DIR, ".reaper_profiles")

# -- Color palette ----------------------------------------------------------

BG_DARK = "#0d0d0d"
BG_PANEL = "#141414"
BG_CARD = "#1a1a1a"
BG_INPUT = "#1e1e1e"
RED = "#e63946"
RED_DIM = "#8b1a1a"
RED_HOVER = "#ff4d5a"
GREEN = "#2ecc71"
YELLOW = "#f1c40f"
ORANGE = "#e67e22"
CYAN = "#00d4ff"
BLUE = "#3498db"
TEXT = "#e0e0e0"
TEXT_DIM = "#666666"
TEXT_MUTED = "#888888"
ACCENT = RED
BORDER = "#2a2a2a"

# -- Phase / command registry -----------------------------------------------

PHASES = [
    ("PHASE 1 — Recon", [
        ("discover",    "Discover DDS participants"),
        ("fingerprint", "Fingerprint DDS vendor/version"),
        ("portscan",    "Scan DDS-specific ports"),
        ("listen",      "Passive RTPS traffic capture"),
        ("portcalc",    "Calculate DDS ports"),
        ("enumerate",   "Enumerate topics/services/nodes"),
        ("audit",       "SROS2 security audit"),
        ("full",        "Full assessment (all modules)"),
    ]),
    ("PHASE 2 — Exploit", [
        ("inject",      "Topic injection (cmd_vel/LIDAR/nav)"),
        ("impersonate", "Node impersonation (shadow/TF/Sybil)"),
        ("amplify",     "RTPS amplification testing"),
    ]),
    ("ROS 1", [
        ("ros1-discover", "Enumerate via rosmaster"),
        ("ros1-inject",   "Inject topics via TCPROS"),
        ("ros1-exploit",  "Kill nodes / param manipulation"),
        ("ros1-audit",    "ROS1 security audit"),
    ]),
    ("ROSBRIDGE", [
        ("rb-enum",   "Enumerate via WebSocket"),
        ("rb-inject", "Inject via rosbridge"),
        ("rb-audit",  "Audit rosbridge posture"),
    ]),
    ("PHASE 3 — ICS/OT", [
        ("ics-enum",    "ICS/OT DDS enumeration"),
        ("modbus-scan", "Modbus/DNP3 bridge analysis"),
        ("mqtt-scan",   "MQTT/EtherCAT bridge analysis"),
        ("opcua-scan",  "OPC UA bridge analysis"),
        ("aws-scan",    "AWS IoT Greengrass bridge"),
        ("shodan-dds",  "Shodan DDS exposure search"),
    ]),
    ("PHASE 4 — C2", [
        ("c2-server", "Operator C2 server"),
        ("c2-beacon", "Deploy implant beacon"),
        ("c2-exfil",  "Exfiltrate data over DDS"),
        ("c2-recv",   "Receive exfil data"),
    ]),
    ("PHASE 5A — micro-ROS", [
        ("microros-agent", "Discover XRCE Agents"),
        ("xrce-traffic",   "Capture XRCE traffic"),
        ("xrce-hijack",    "Spoof XRCE client session"),
        ("uros-implant",   "Generate micro-ROS implant"),
        ("uros-persist",   "Firmware-level persistence"),
        ("uros-c2",        "Phase 5A C2 dispatcher"),
    ]),
    ("PHASE 5B — SROS2", [
        ("sros2-intercept",  "Capture DDS-Security tokens"),
        ("sros2-harvest",    "Extract certs/keys"),
        ("sros2-policy",     "Analyze/forge policies"),
        ("sros2-infiltrate", "Join secured domain"),
    ]),
    ("PHASE 5C — Nav2/Ctrl", [
        ("nav2-lifecycle",   "Attack Nav2 lifecycle"),
        ("nav2-costmap",     "Poison costmaps"),
        ("nav2-bt",          "Hijack behavior tree"),
        ("ros2ctrl-exploit", "Exploit ros2_control"),
    ]),
    ("PHASE 6 — Edge AI", [
        ("ai-enum",    "Enumerate AI servers/topics"),
        ("ai-perturb", "Adversarial perturbations"),
        ("ai-extract", "Black-box model extraction"),
        ("ai-poison",  "Model poisoning"),
    ]),
]

# Argument definitions: (flag, label, type, default, choices/help)
# Types: "str", "int", "float", "bool", "choice", "file", "fileSave", "strList"

ARG_DEFS = {
    # Common
    "target":    ("--target",    "Target IP",         "str",   "", None),
    "network":   ("--network",   "Network (CIDR)",    "str",   "", None),
    "domain_id": ("--domain-id", "Domain ID",         "int",   "0", None),
    "domains":   ("--domains",   "Domain range",      "str",   "0-10", None),
    "timeout":   ("--timeout",   "Timeout (s)",       "float", "3.0", None),
    "duration":  ("--duration",  "Duration (s)",      "float", "30.0", None),
    "output":    ("-o",          "Output file (JSON)", "fileSave", "", None),
    "verbose":   ("--verbose",   "Verbose",           "bool",  False, None),

    # Phase 2
    "namespace":   ("--namespace",    "Namespace",      "str",    "/robot1", None),
    "preset":      ("--preset",       "Attack preset",  "choice", "spin",
                    ["spin", "fullspeed", "reverse", "erratic", "estop", "circle"]),
    "attack_mode": ("--attack-mode",  "Attack mode",    "choice", "",
                    ["cmd_vel", "lidar", "nav", "odom", "swarm",
                     "shadow", "tf", "dos", "sybil",
                     "reflect", "exhaust", "fuzz", "heartbeat", "full_suite"]),
    "namespaces":  ("--namespaces",   "Target namespaces", "strList", "/robot1 /robot2", None),
    "target_node": ("--target-node",  "Target node",    "str",   "", None),
    "x":           ("--x",            "X coordinate",   "float", "5.0", None),
    "y":           ("--y",            "Y coordinate",   "float", "5.0", None),
    "lx":          ("--lx",           "linear.x (m/s)", "float", "", None),
    "az":          ("--az",           "angular.z (rad/s)", "float", "", None),
    "lidar_mode":  ("--lidar-mode",   "LIDAR spoof mode", "choice", "allclear",
                    ["allclear", "wall", "phantom"]),
    "count":       ("--count",        "Count",          "int",   "50", None),

    # rosbridge
    "rb_port": ("--rb-port", "rosbridge port", "int", "9090", None),

    # ROS 1
    "ros1_port":   ("--ros1-port",   "rosmaster port", "int",   "11311", None),
    "node":        ("--node",        "Node name",      "str",   "", None),
    "topic":       ("--topic",       "Topic",          "str",   "", None),
    "param_key":   ("--param-key",   "Param key",      "str",   "", None),
    "param_value": ("--param-value", "Param value",    "str",   "", None),
    "kill_all":    ("--kill-all",    "Kill all nodes",  "bool",  False, None),

    # Phase 3
    "threads":          ("--threads",          "Threads",           "int",    "50", None),
    "passive":          ("--passive",          "Passive mode",      "bool",   False, None),
    "passive_duration": ("--passive-duration", "Passive duration",  "float",  "30.0", None),
    "deep":             ("--deep",             "Deep probing",      "bool",   False, None),
    "context":          ("--context",          "ICS context",       "choice", "",
                         ["scada", "atc", "automotive", "smart_grid",
                          "military", "medical", "iiot"]),
    "modbus_enumerate": ("--modbus-enumerate", "Enumerate Modbus",  "bool",   False, None),
    "mqtt_enumerate":   ("--mqtt-enumerate",   "Enumerate MQTT",    "bool",   False, None),
    "enum_duration":    ("--enum-duration",    "Enum duration (s)", "float",  "10.0", None),
    "enumerate_nodes":  ("--enumerate-nodes",  "Browse OPC UA",     "bool",   False, None),
    "shadow_enumerate": ("--shadow-enumerate", "Probe AWS Shadow",  "bool",   False, None),
    "api_key":          ("--api-key",          "Shodan API key",    "str",    "", None),
    "limit":            ("--limit",            "Max results",       "int",    "100", None),
    "rate":             ("--rate",             "API rate (s)",      "float",  "1.0", None),
    "export":           ("--export",           "Export IP list",    "fileSave", "", None),

    # Phase 4
    "c2_key":      ("--c2-key",      "C2 XOR key",       "str",   "", None),
    "c2_session":  ("--c2-session",  "C2 session ID",    "str",   "", None),
    "c2_interval": ("--c2-interval", "Beacon interval",  "float", "30.0", None),
    "c2_ttl":      ("--c2-ttl",      "Max check-ins (0=inf)", "int", "0", None),
    "exfil_mode":  ("--exfil-mode",  "Exfil source",     "choice", "",
                    ["topic", "params", "files", "env"]),
    "exfil_path":  ("--exfil-path",  "Exfil file path",  "str",   "", None),

    # Phase 5A
    "agent_port":      ("--agent-port",      "XRCE Agent port",  "int",   "8888", None),
    "xrce_multiport":  ("--xrce-multiport",  "Scan multi-port",  "bool",  False, None),
    "xrce_enumerate":  ("--xrce-enumerate",  "Enumerate XRCE",   "bool",  False, None),
    "pcap":            ("--pcap",            "PCAP output",      "fileSave", "", None),
    "xrce_attack":     ("--xrce-attack",     "XRCE attack type", "choice", "",
                        ["twist", "nav", "raw"]),
    "xrce_session":    ("--xrce-session",    "Spoofed session ID", "str",  "", None),
    "theta":           ("--theta",           "Orientation (rad)", "float", "0.0", None),
    "interval":        ("--interval",        "Inject interval",  "float", "0.1", None),
    "payload_file":    ("--payload-file",    "Payload file",     "file",  "", None),
    "payload_hex":     ("--payload-hex",     "Payload hex",      "str",   "", None),
    "platform":        ("--platform",        "Implant platform", "choice", "",
                        ["cpp", "arduino", "python"]),
    "implant_id":      ("--implant-id",      "Implant ID",       "str",   "", None),
    "beacon_interval": ("--beacon-interval", "Beacon ms",        "int",   "5000", None),
    "beacon_topic":    ("--beacon-topic",    "Beacon topic",     "str",   "/implant/beacon", None),
    "command_topic":   ("--command-topic",   "Command topic",    "str",   "/implant/command", None),
    "obfuscate":       ("--obfuscate",       "Strip comments",   "bool",  False, None),
    "add_decoy":       ("--add-decoy",       "Add decoy code",   "bool",  False, None),
    "manifest":        ("--manifest",        "Manifest JSON",    "fileSave", "", None),
    "persist_method":  ("--persist-method",  "Persist method",   "choice", "",
                        ["library_patch", "bootloader", "firmware_inject",
                         "partition", "ota_hijack"]),
    "implant_file":    ("--implant-file",    "Implant binary",   "file",  "", None),
    "implant_hex":     ("--implant-hex",     "Implant hex",      "str",   "", None),
    "hook_address":    ("--hook-address",    "Hook address",     "str",   "", None),
    "partition_name":  ("--partition-name",  "Partition name",   "str",   "", None),
    "ota_server":      ("--ota-server",      "OTA server",       "str",   "", None),
    "dispatcher_port": ("--dispatcher-port", "Dispatcher port",  "int",   "", None),
    "beacon_timeout":  ("--beacon-timeout",  "Beacon timeout",   "float", "60.0", None),
    "log_file":        ("--log-file",        "Log file",         "fileSave", "", None),
    "export_session":  ("--export-session",  "Export session",   "fileSave", "", None),
    "batch_file":      ("--batch-file",      "Batch file",       "file",  "", None),

    # Phase 5B
    "interface":       ("--interface",       "Bind interface",   "str",   "", None),
    "from_intercept":  ("--from-intercept",  "Intercept JSON",   "file",  "", None),
    "keystore_path":   ("--keystore-path",   "Keystore path",    "str",   "", None),
    "governance":      ("--governance",      "Governance XML",   "file",  "", None),
    "permissions":     ("--permissions",     "Permissions XML",  "file",  "", None),
    "ca_cert":         ("--ca-cert",         "CA cert PEM",      "file",  "", None),
    "ca_key":          ("--ca-key",          "CA key PEM",       "file",  "", None),
    "forge_policy":    ("--forge-policy",    "Forge policy",     "bool",  False, None),
    "forged_output":   ("--forged-output",   "Forged output",    "fileSave", "", None),
    "subject_name":    ("--subject-name",    "Subject DN",       "str",   "", None),
    "cert_file":       ("--cert-file",       "Node cert PEM",    "file",  "", None),
    "permissions_file":("--permissions-file","Signed .p7s",      "file",  "", None),
    "infiltrate_mode": ("--infiltrate-mode", "Infiltrate mode",  "choice", "eavesdrop",
                        ["downgrade", "eavesdrop", "impersonate"]),
    "spoof_node_name": ("--spoof-node-name", "Spoofed node",     "str",   "attacker_node", None),

    # Phase 5C
    "nav2_mode":       ("--nav2-mode",       "Nav2 attack mode", "choice", "",
                        ["enumerate", "deactivate", "shutdown", "cascade", "param_poison"]),
    "nav2_nodes":      ("--nav2-nodes",      "Nav2 node names",  "strList", "", None),
    "costmap_mode":    ("--costmap-mode",    "Costmap mode",     "choice", "",
                        ["enumerate", "map_clear", "map_block", "map_maze",
                         "map_partial", "svc_clear", "fake_scan",
                         "fake_cloud", "inflate_zero", "voxel_clear"]),
    "map_width":       ("--map-width",       "Map width",        "int",   "100", None),
    "map_height":      ("--map-height",      "Map height",       "int",   "100", None),
    "map_resolution":  ("--map-resolution",  "Map resolution",   "float", "0.05", None),
    "wall_angle":      ("--wall-angle",      "Wall bearing",     "float", "0.0", None),
    "wall_distance":   ("--wall-distance",   "Wall distance",    "float", "1.5", None),
    "inflation_radius":("--inflation-radius","Inflation radius",  "float", "0.0", None),
    "bt_mode":         ("--bt-mode",         "BT attack mode",   "choice", "",
                        ["enumerate", "cancel", "redirect",
                         "recovery_loop", "param_hijack", "generate_bt"]),
    "redirect_x":      ("--redirect-x",      "Redirect X",      "float", "0.0", None),
    "redirect_y":      ("--redirect-y",      "Redirect Y",      "float", "0.0", None),
    "redirect_yaw":    ("--redirect-yaw",    "Redirect yaw",    "float", "0.0", None),
    "recovery_mode":   ("--recovery-mode",   "Recovery type",    "choice", "spin",
                        ["spin", "backup", "wait"]),
    "recovery_cycles": ("--recovery-cycles", "Recovery cycles",  "int",   "5", None),
    "bt_xml_path":     ("--bt-xml-path",     "BT XML path",     "str",   "/tmp/malicious_bt.xml", None),
    "bt_template":     ("--bt-template",     "BT template",     "choice", "spin_only",
                        ["no_recovery", "infinite_retry", "spin_only",
                         "clear_and_navigate", "goal_checker_bypass"]),
    "bt_output":       ("--bt-output",       "BT output file",  "fileSave", "", None),
    "ctrl_mode":       ("--ctrl-mode",       "Ctrl attack mode", "choice", "",
                        ["enumerate", "traj_inject", "switch_ctrl",
                         "limit_bypass", "ctrl_crash", "hw_disable"]),
    "controller_name": ("--controller-name", "Controller name",  "str",   "joint_trajectory_controller", None),
    "joint_names":     ("--joint-names",     "Joint names",      "strList", "", None),
    "joint_positions": ("--joint-positions",  "Joint positions", "strList", "", None),
    "stop_controllers":("--stop-controllers","Stop controllers",  "strList", "", None),
    "start_controllers":("--start-controllers","Start controllers","strList", "", None),
    "hw_name":         ("--hw-name",         "HW component",     "str",   "", None),
    "traj_duration":   ("--traj-duration",   "Traj duration (s)","float", "2.0", None),

    # Phase 6
    "ai_enum_mode":     ("--ai-enum-mode",     "Enum scope",      "choice", "",
                         ["all", "triton", "tf_serving", "onnx_rt",
                          "mlflow", "ros_svc", "filesystem"]),
    "ai_ports":         ("--ai-ports",         "AI ports",        "strList", "", None),
    "ai_fs_paths":      ("--ai-fs-paths",      "FS scan paths",   "strList", "", None),
    "perturb_mode":     ("--perturb-mode",     "Perturb mode",    "choice", "",
                         ["fgsm", "pgd", "uap", "patch",
                          "inject_topic", "inject_triton"]),
    "adv_epsilon":      ("--adv-epsilon",      "Epsilon",         "float", "8.0", None),
    "adv_input":        ("--adv-input",        "Input image",     "file",  "", None),
    "adv_output":       ("--adv-output",       "Output image",    "fileSave", "", None),
    "uap_pattern":      ("--uap-pattern",      "UAP pattern",     "choice", "checker",
                         ["checker", "frequency", "gradient", "random"]),
    "patch_size_px":    ("--patch-size-px",    "Patch size (px)",  "int",   "64", None),
    "img_width":        ("--img-width",        "Image width",     "int",   "640", None),
    "img_height":       ("--img-height",       "Image height",    "int",   "480", None),
    "ai_inject_count":  ("--ai-inject-count",  "Inject frames",   "int",   "30", None),
    "ai_inject_interval":("--ai-inject-interval","Frame interval","float", "0.05", None),
    "pgd_steps":        ("--pgd-steps",        "PGD iterations",  "int",   "20", None),
    "triton_model":     ("--triton-model",     "Triton model",    "str",   "", None),
    "triton_port":      ("--triton-port",      "Triton port",     "int",   "8000", None),
    "extract_mode":     ("--extract-mode",     "Extract mode",    "choice", "",
                         ["probe", "fingerprint", "timing",
                          "membership", "reconstruct", "full"]),
    "ai_server_type":   ("--ai-server-type",   "Server type",     "choice", "triton",
                         ["triton", "tf_serving"]),
    "ai_model_name":    ("--ai-model-name",    "Model name",      "str",   "", None),
    "ai_queries":       ("--ai-queries",       "Query count",     "int",   "50", None),
    "poison_mode":      ("--poison-mode",      "Poison mode",     "choice", "",
                         ["enumerate", "triton_swap", "onnx_patch",
                          "param_inject", "generate_trigger"]),
    "ai_model_path":    ("--ai-model-path",    "Model file",      "file",  "", None),
    "backdoor_path":    ("--backdoor-path",    "Backdoor output", "fileSave", "", None),
    "trigger_output":   ("--trigger-output",   "Trigger image",   "fileSave", "", None),
    "target_class":     ("--target-class",     "Target class",    "int",   "0", None),
    "trigger_size":     ("--trigger-size",     "Trigger size",    "int",   "16", None),
}

# Which arg keys each command uses
CMD_ARGS = {
    "discover":    ["network", "domain_id", "timeout", "verbose"],
    "fingerprint": ["target", "domain_id", "timeout", "verbose"],
    "portscan":    ["target", "domains", "timeout", "verbose"],
    "listen":      ["domain_id", "duration", "verbose"],
    "portcalc":    ["domain_id", "domains"],
    "enumerate":   ["target", "domain_id", "timeout", "verbose"],
    "audit":       ["target", "network", "domain_id", "timeout", "output", "verbose"],
    "full":        ["network", "domain_id", "timeout", "output", "verbose"],

    "inject":      ["namespace", "preset", "attack_mode", "duration", "namespaces",
                    "x", "y", "lx", "az", "lidar_mode", "topic", "verbose"],
    "impersonate": ["attack_mode", "target_node", "namespace", "count",
                    "domain_id", "duration", "verbose"],
    "amplify":     ["target", "attack_mode", "count", "domain_id", "duration", "verbose"],

    "ros1-discover": ["target", "ros1_port", "timeout", "verbose"],
    "ros1-inject":   ["target", "ros1_port", "topic", "preset", "attack_mode",
                      "duration", "lidar_mode", "lx", "az", "verbose"],
    "ros1-exploit":  ["target", "ros1_port", "node", "kill_all",
                      "param_key", "param_value", "verbose"],
    "ros1-audit":    ["target", "ros1_port", "output", "verbose"],

    "rb-enum":   ["target", "rb_port", "timeout", "verbose"],
    "rb-inject": ["target", "rb_port", "topic", "preset", "attack_mode",
                  "duration", "lidar_mode", "lx", "az", "x", "y",
                  "namespace", "verbose"],
    "rb-audit":  ["target", "rb_port", "output", "verbose"],

    "ics-enum":    ["target", "network", "threads", "passive", "passive_duration",
                    "deep", "context", "output", "verbose"],
    "modbus-scan": ["target", "network", "threads", "deep",
                    "modbus_enumerate", "output", "verbose"],
    "mqtt-scan":   ["target", "network", "threads", "deep",
                    "mqtt_enumerate", "enum_duration", "output", "verbose"],
    "opcua-scan":  ["target", "network", "threads", "deep",
                    "enumerate_nodes", "output", "verbose"],
    "aws-scan":    ["target", "network", "threads", "deep",
                    "shadow_enumerate", "output", "verbose"],
    "shodan-dds":  ["api_key", "target", "context", "limit",
                    "rate", "export", "output", "verbose"],

    "c2-server": ["domain_id", "c2_key", "verbose"],
    "c2-beacon": ["target", "domain_id", "c2_key", "c2_interval", "c2_ttl", "verbose"],
    "c2-exfil":  ["target", "domain_id", "c2_key", "c2_session",
                  "exfil_mode", "exfil_path", "topic", "verbose"],
    "c2-recv":   ["c2_session", "domain_id", "c2_key", "output", "verbose"],

    "microros-agent": ["target", "network", "agent_port", "xrce_multiport",
                       "xrce_enumerate", "timeout", "verbose"],
    "xrce-traffic":   ["target", "agent_port", "duration", "pcap", "verbose"],
    "xrce-hijack":    ["target", "agent_port", "xrce_attack", "xrce_session",
                       "x", "y", "theta", "lx", "az", "duration",
                       "interval", "payload_file", "payload_hex", "verbose"],
    "uros-implant":   ["platform", "implant_id", "beacon_interval",
                       "beacon_topic", "command_topic", "obfuscate",
                       "add_decoy", "manifest", "verbose"],
    "uros-persist":   ["target", "persist_method", "implant_file", "implant_hex",
                       "hook_address", "partition_name", "ota_server", "verbose"],
    "uros-c2":        ["target", "agent_port", "dispatcher_port", "beacon_timeout",
                       "c2_key", "log_file", "export_session", "batch_file", "verbose"],

    "sros2-intercept":  ["interface", "domain_id", "duration", "verbose"],
    "sros2-harvest":    ["from_intercept", "keystore_path", "verbose"],
    "sros2-policy":     ["governance", "permissions", "ca_cert", "ca_key",
                         "forge_policy", "forged_output", "subject_name", "verbose"],
    "sros2-infiltrate": ["infiltrate_mode", "domain_id", "spoof_node_name",
                         "cert_file", "ca_key", "ca_cert", "permissions_file",
                         "subject_name", "namespace", "topic", "duration", "verbose"],

    "nav2-lifecycle":   ["nav2_mode", "nav2_nodes", "namespace", "verbose"],
    "nav2-costmap":     ["costmap_mode", "namespace", "map_width", "map_height",
                         "map_resolution", "wall_angle", "wall_distance",
                         "inflation_radius", "verbose"],
    "nav2-bt":          ["bt_mode", "namespace", "redirect_x", "redirect_y",
                         "redirect_yaw", "recovery_mode", "recovery_cycles",
                         "bt_xml_path", "bt_template", "bt_output",
                         "duration", "verbose"],
    "ros2ctrl-exploit": ["ctrl_mode", "controller_name", "joint_names",
                         "joint_positions", "stop_controllers", "start_controllers",
                         "hw_name", "traj_duration", "namespace", "verbose"],

    "ai-enum":    ["target", "ai_enum_mode", "ai_ports", "ai_fs_paths", "verbose"],
    "ai-perturb": ["target", "perturb_mode", "adv_epsilon", "adv_input", "adv_output",
                   "uap_pattern", "patch_size_px", "img_width", "img_height",
                   "ai_inject_count", "ai_inject_interval", "pgd_steps",
                   "triton_model", "triton_port", "namespace", "verbose"],
    "ai-extract": ["target", "extract_mode", "ai_server_type", "ai_model_name",
                   "ai_queries", "triton_port", "verbose"],
    "ai-poison":  ["target", "poison_mode", "ai_model_path", "ai_model_name",
                   "backdoor_path", "trigger_output", "target_class",
                   "trigger_size", "triton_port", "verbose"],
}


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def classify_line(line: str) -> str:
    """Return a color tag based on line content."""
    stripped = line.strip()
    if not stripped:
        return "default"
    if stripped.startswith("[!]") or stripped.startswith("ERROR") or "Traceback" in stripped:
        return "error"
    if stripped.startswith("[*]") or "WARNING" in stripped.upper() or stripped.startswith("WARN"):
        return "warning"
    if stripped.startswith("[+]") or "SUCCESS" in stripped.upper() or "PASS" in stripped:
        return "success"
    if stripped.startswith("[>]") or stripped.startswith(">>>") or stripped.startswith("$"):
        return "cmd"
    if stripped.startswith("---") or stripped.startswith("===") or stripped.startswith("╔") or stripped.startswith("║"):
        return "heading"
    if any(k in stripped for k in ("CRITICAL", "VULN", "EXPOSED", "OPEN", "INSECURE")):
        return "critical"
    if any(k in stripped for k in ("found", "detected", "discovered")):
        return "info"
    return "default"


def pretty_json(obj, indent=0) -> list:
    """Yield (text, tag) tuples for syntax-highlighted JSON."""
    pad = "  " * indent
    if isinstance(obj, dict):
        if not obj:
            yield ("{}", "json_brace")
            return
        yield ("{\n", "json_brace")
        items = list(obj.items())
        for i, (k, v) in enumerate(items):
            yield (pad + "  ", "default")
            yield (f'"{k}"', "json_key")
            yield (": ", "json_brace")
            yield from pretty_json(v, indent + 1)
            if i < len(items) - 1:
                yield (",", "json_brace")
            yield ("\n", "default")
        yield (pad + "}", "json_brace")
    elif isinstance(obj, list):
        if not obj:
            yield ("[]", "json_brace")
            return
        yield ("[\n", "json_brace")
        for i, v in enumerate(obj):
            yield (pad + "  ", "default")
            yield from pretty_json(v, indent + 1)
            if i < len(obj) - 1:
                yield (",", "json_brace")
            yield ("\n", "default")
        yield (pad + "]", "json_brace")
    elif isinstance(obj, str):
        yield (f'"{obj}"', "json_string")
    elif isinstance(obj, bool):
        yield (str(obj).lower(), "json_bool")
    elif obj is None:
        yield ("null", "json_null")
    else:
        yield (str(obj), "json_number")


# ===========================================================================
#  Main application
# ===========================================================================

class ReaperGUI(ctk.CTk):

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("ROS2Reaper")
        self.geometry("1440x900")
        self.minsize(1100, 650)
        self.configure(fg_color=BG_DARK)

        self._process: subprocess.Popen | None = None
        self._current_cmd: str | None = None
        self._arg_widgets: dict[str, tk.Variable | ctk.CTkBaseClass] = {}
        self._raw_output: str = ""
        self._last_json: dict | list | None = None

        os.makedirs(PROFILES_DIR, exist_ok=True)

        self._build_ui()
        self._load_profiles_list()
        self._select_command("discover")

    # ----- layout ----------------------------------------------------------

    def _build_ui(self):
        self._build_topbar()
        self._build_target_bar()

        self._main = ctk.CTkFrame(self, fg_color=BG_DARK)
        self._main.pack(fill="both", expand=True, padx=0, pady=0)
        self._main.columnconfigure(1, weight=2)
        self._main.columnconfigure(2, weight=3)
        self._main.rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_center()
        self._build_output()

    # -- top bar ------------------------------------------------------------

    def _build_topbar(self):
        bar = ctk.CTkFrame(self, height=44, fg_color=BG_PANEL, corner_radius=0)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        logo = ctk.CTkLabel(bar, text="  ROS2REAPER",
                            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
                            text_color=RED)
        logo.pack(side="left", padx=(12, 4))

        ver = ctk.CTkLabel(bar, text="v0.4.0",
                           font=ctk.CTkFont(size=11),
                           text_color=TEXT_DIM)
        ver.pack(side="left")

        self._status_label = ctk.CTkLabel(
            bar, text="IDLE", font=ctk.CTkFont(family="Consolas", size=12),
            text_color=TEXT_DIM)
        self._status_label.pack(side="right", padx=16)

        save_btn = ctk.CTkButton(
            bar, text="Save Session", width=110, height=28,
            fg_color=BG_CARD, hover_color=BORDER,
            text_color=TEXT, font=ctk.CTkFont(size=12),
            command=self._save_session)
        save_btn.pack(side="right", padx=4)

        load_btn = ctk.CTkButton(
            bar, text="Load Session", width=110, height=28,
            fg_color=BG_CARD, hover_color=BORDER,
            text_color=TEXT, font=ctk.CTkFont(size=12),
            command=self._load_session)
        load_btn.pack(side="right", padx=4)

    # -- target profile bar -------------------------------------------------

    def _build_target_bar(self):
        bar = ctk.CTkFrame(self, height=38, fg_color=BG_CARD, corner_radius=0)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        ctk.CTkLabel(bar, text="  TARGET",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=TEXT_DIM).pack(side="left", padx=(12, 8))

        self._profile_var = tk.StringVar(value="(none)")
        self._profile_menu = ctk.CTkOptionMenu(
            bar, variable=self._profile_var,
            values=["(none)"],
            width=160, height=26,
            fg_color=BG_INPUT, button_color=BORDER,
            button_hover_color=TEXT_DIM,
            dropdown_fg_color=BG_CARD,
            dropdown_hover_color=RED_DIM,
            font=ctk.CTkFont(family="Consolas", size=11),
            dropdown_font=ctk.CTkFont(family="Consolas", size=11),
            command=self._on_profile_selected)
        self._profile_menu.pack(side="left", padx=(0, 8))

        ctk.CTkLabel(bar, text="IP",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=TEXT_DIM).pack(side="left", padx=(8, 4))

        self._prof_target = tk.StringVar()
        ctk.CTkEntry(bar, textvariable=self._prof_target, width=140, height=26,
                     fg_color=BG_INPUT, border_color=BORDER, text_color=TEXT,
                     font=ctk.CTkFont(family="Consolas", size=11),
                     placeholder_text="192.168.1.100").pack(side="left")

        ctk.CTkLabel(bar, text="Net",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=TEXT_DIM).pack(side="left", padx=(12, 4))

        self._prof_network = tk.StringVar()
        ctk.CTkEntry(bar, textvariable=self._prof_network, width=140, height=26,
                     fg_color=BG_INPUT, border_color=BORDER, text_color=TEXT,
                     font=ctk.CTkFont(family="Consolas", size=11),
                     placeholder_text="192.168.1.0/24").pack(side="left")

        ctk.CTkLabel(bar, text="Dom",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=TEXT_DIM).pack(side="left", padx=(12, 4))

        self._prof_domain = tk.StringVar(value="0")
        ctk.CTkEntry(bar, textvariable=self._prof_domain, width=40, height=26,
                     fg_color=BG_INPUT, border_color=BORDER, text_color=TEXT,
                     font=ctk.CTkFont(family="Consolas", size=11)).pack(side="left")

        ctk.CTkLabel(bar, text="NS",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=TEXT_DIM).pack(side="left", padx=(12, 4))

        self._prof_ns = tk.StringVar(value="/robot1")
        ctk.CTkEntry(bar, textvariable=self._prof_ns, width=100, height=26,
                     fg_color=BG_INPUT, border_color=BORDER, text_color=TEXT,
                     font=ctk.CTkFont(family="Consolas", size=11)).pack(side="left")

        self._prof_skip_auth = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(bar, text="skip-auth", variable=self._prof_skip_auth,
                        fg_color=RED, hover_color=RED_HOVER,
                        border_color=BORDER, width=20,
                        font=ctk.CTkFont(family="Consolas", size=10),
                        text_color=TEXT_MUTED).pack(side="left", padx=(16, 4))

        self._prof_verbose = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(bar, text="verbose", variable=self._prof_verbose,
                        fg_color=RED, hover_color=RED_HOVER,
                        border_color=BORDER, width=20,
                        font=ctk.CTkFont(family="Consolas", size=10),
                        text_color=TEXT_MUTED).pack(side="left", padx=4)

        ctk.CTkButton(bar, text="Save Profile", width=90, height=24,
                      fg_color=BG_PANEL, hover_color=BORDER,
                      text_color=TEXT_MUTED, font=ctk.CTkFont(size=10),
                      command=self._save_profile).pack(side="right", padx=4)

        ctk.CTkButton(bar, text="Delete", width=56, height=24,
                      fg_color=BG_PANEL, hover_color=RED_DIM,
                      text_color=RED, font=ctk.CTkFont(size=10),
                      command=self._delete_profile).pack(side="right", padx=4)

        ctk.CTkButton(bar, text="Apply", width=56, height=24,
                      fg_color=RED_DIM, hover_color=RED,
                      text_color=TEXT, font=ctk.CTkFont(size=10),
                      command=self._apply_profile).pack(side="right", padx=(4, 8))

    # -- sidebar ------------------------------------------------------------

    def _build_sidebar(self):
        sidebar = ctk.CTkScrollableFrame(
            self._main, width=240, fg_color=BG_PANEL, corner_radius=0,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=TEXT_DIM)
        sidebar.grid(row=0, column=0, sticky="ns")

        self._cmd_buttons: dict[str, ctk.CTkButton] = {}

        for phase_name, cmds in PHASES:
            header = ctk.CTkLabel(
                sidebar, text=phase_name,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                text_color=RED, anchor="w")
            header.pack(fill="x", padx=12, pady=(14, 4))

            for cmd_id, cmd_label in cmds:
                btn = ctk.CTkButton(
                    sidebar, text=f"  {cmd_id}",
                    font=ctk.CTkFont(family="Consolas", size=12),
                    anchor="w", height=28,
                    fg_color="transparent", hover_color=BG_CARD,
                    text_color=TEXT_MUTED, corner_radius=4,
                    command=lambda c=cmd_id: self._select_command(c))
                btn.pack(fill="x", padx=8, pady=1)
                self._cmd_buttons[cmd_id] = btn

    # -- center (dynamic form) ----------------------------------------------

    def _build_center(self):
        self._center_wrapper = ctk.CTkFrame(self._main, fg_color=BG_DARK)
        self._center_wrapper.grid(row=0, column=1, sticky="nsew", padx=(1, 0))

        self._cmd_title = ctk.CTkLabel(
            self._center_wrapper, text="",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color=TEXT)
        self._cmd_title.pack(anchor="w", padx=20, pady=(16, 2))

        self._cmd_desc = ctk.CTkLabel(
            self._center_wrapper, text="",
            font=ctk.CTkFont(size=12), text_color=TEXT_DIM)
        self._cmd_desc.pack(anchor="w", padx=20, pady=(0, 10))

        self._form_frame = ctk.CTkScrollableFrame(
            self._center_wrapper, fg_color=BG_DARK,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=TEXT_DIM)
        self._form_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Bottom: command preview + buttons
        bottom = ctk.CTkFrame(self._center_wrapper, fg_color=BG_PANEL,
                              height=100, corner_radius=0)
        bottom.pack(fill="x", side="bottom")
        bottom.pack_propagate(False)

        ctk.CTkLabel(bottom, text="COMMAND",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=TEXT_DIM).pack(anchor="w", padx=16, pady=(8, 0))

        self._cmd_preview = ctk.CTkLabel(
            bottom, text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=CYAN, anchor="w", wraplength=700, justify="left")
        self._cmd_preview.pack(fill="x", padx=16, pady=(2, 8))

        btn_row = ctk.CTkFrame(bottom, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 10))

        self._run_btn = ctk.CTkButton(
            btn_row, text="EXECUTE", width=140, height=36,
            fg_color=RED, hover_color=RED_HOVER,
            text_color="white",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            command=self._execute)
        self._run_btn.pack(side="left")

        self._kill_btn = ctk.CTkButton(
            btn_row, text="ABORT", width=100, height=36,
            fg_color=BG_CARD, hover_color=RED_DIM,
            text_color=RED,
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            command=self._kill, state="disabled")
        self._kill_btn.pack(side="left", padx=(10, 0))

        ctk.CTkButton(
            btn_row, text="COPY CMD", width=100, height=36,
            fg_color=BG_CARD, hover_color=BORDER,
            text_color=TEXT,
            font=ctk.CTkFont(family="Consolas", size=12),
            command=self._copy_cmd).pack(side="left", padx=(10, 0))

    # -- output pane (tabbed: Terminal | JSON) -------------------------------

    def _build_output(self):
        out_frame = ctk.CTkFrame(self._main, fg_color=BG_PANEL, corner_radius=0)
        out_frame.grid(row=0, column=2, sticky="nsew", padx=(1, 0))

        # Tab header row
        tab_bar = ctk.CTkFrame(out_frame, fg_color=BG_PANEL, height=36)
        tab_bar.pack(fill="x")
        tab_bar.pack_propagate(False)

        self._tab_terminal_btn = ctk.CTkButton(
            tab_bar, text="  OUTPUT", width=90, height=26,
            fg_color=RED_DIM, hover_color=RED_DIM,
            text_color="white",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            corner_radius=4,
            command=lambda: self._switch_output_tab("terminal"))
        self._tab_terminal_btn.pack(side="left", padx=(8, 2), pady=5)

        self._tab_json_btn = ctk.CTkButton(
            tab_bar, text="  JSON", width=70, height=26,
            fg_color="transparent", hover_color=BG_CARD,
            text_color=TEXT_DIM,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            corner_radius=4,
            command=lambda: self._switch_output_tab("json"))
        self._tab_json_btn.pack(side="left", padx=2, pady=5)

        ctk.CTkButton(
            tab_bar, text="Clear", width=60, height=24,
            fg_color=BG_CARD, hover_color=BORDER,
            text_color=TEXT_DIM, font=ctk.CTkFont(size=11),
            command=self._clear_output).pack(side="right", padx=8, pady=6)

        ctk.CTkButton(
            tab_bar, text="Export", width=60, height=24,
            fg_color=BG_CARD, hover_color=BORDER,
            text_color=TEXT_DIM, font=ctk.CTkFont(size=11),
            command=self._export_output).pack(side="right", padx=2, pady=6)

        # Terminal view
        self._output = tk.Text(
            out_frame, font=("Consolas", 11),
            bg=BG_DARK, fg=GREEN,
            insertbackground=GREEN,
            selectbackground=RED_DIM,
            wrap="word", state="disabled",
            borderwidth=0, highlightthickness=0,
            padx=8, pady=4)
        self._output.pack(fill="both", expand=True, padx=4, pady=(0, 4))

        # Configure color tags
        self._output.tag_configure("default",  foreground=GREEN)
        self._output.tag_configure("error",    foreground=RED)
        self._output.tag_configure("warning",  foreground=YELLOW)
        self._output.tag_configure("success",  foreground=GREEN)
        self._output.tag_configure("cmd",      foreground=CYAN)
        self._output.tag_configure("heading",  foreground=RED, font=("Consolas", 11, "bold"))
        self._output.tag_configure("critical", foreground=RED, font=("Consolas", 11, "bold"))
        self._output.tag_configure("info",     foreground=BLUE)

        # JSON tags
        self._output.tag_configure("json_key",    foreground=RED)
        self._output.tag_configure("json_string", foreground=GREEN)
        self._output.tag_configure("json_number", foreground=CYAN)
        self._output.tag_configure("json_bool",   foreground=ORANGE)
        self._output.tag_configure("json_null",   foreground=TEXT_DIM)
        self._output.tag_configure("json_brace",  foreground=TEXT_MUTED)

        scrollbar = ctk.CTkScrollbar(out_frame, command=self._output.yview,
                                      button_color=BORDER,
                                      button_hover_color=TEXT_DIM,
                                      width=12)
        self._output.configure(yscrollcommand=scrollbar.set)
        scrollbar.place(relx=1.0, rely=0.05, relheight=0.9, anchor="ne")

        self._current_output_tab = "terminal"

    # ----- output tab switching --------------------------------------------

    def _switch_output_tab(self, tab: str):
        self._current_output_tab = tab
        if tab == "terminal":
            self._tab_terminal_btn.configure(fg_color=RED_DIM, text_color="white")
            self._tab_json_btn.configure(fg_color="transparent", text_color=TEXT_DIM)
            self._show_terminal_content()
        else:
            self._tab_terminal_btn.configure(fg_color="transparent", text_color=TEXT_DIM)
            self._tab_json_btn.configure(fg_color=RED_DIM, text_color="white")
            self._show_json_content()

    def _show_terminal_content(self):
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")
        for line in self._raw_output.splitlines(True):
            tag = classify_line(line)
            self._output.insert("end", line, tag)
        self._output.see("end")
        self._output.configure(state="disabled")

    def _show_json_content(self):
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")

        if self._last_json is not None:
            for text, tag in pretty_json(self._last_json):
                self._output.insert("end", text, tag)
            self._output.see("1.0")
        else:
            # Try to extract JSON from raw output
            extracted = self._extract_json_from_output()
            if extracted is not None:
                self._last_json = extracted
                for text, tag in pretty_json(extracted):
                    self._output.insert("end", text, tag)
                self._output.see("1.0")
            else:
                self._output.insert("end",
                    "No JSON data available.\n\n"
                    "JSON output appears here when:\n"
                    "  - Command writes to -o <file>.json\n"
                    "  - Output contains JSON data\n",
                    "default")
        self._output.configure(state="disabled")

    def _extract_json_from_output(self):
        """Try to find and parse JSON from command output."""
        text = self._raw_output

        # Check if an output file was generated
        for line in text.splitlines():
            match = re.search(r'(?:saved|written|output).*?([^\s]+\.json)', line, re.I)
            if match:
                path = match.group(1)
                if not os.path.isabs(path):
                    path = os.path.join(SCRIPT_DIR, path)
                if os.path.isfile(path):
                    try:
                        with open(path) as f:
                            return json.load(f)
                    except (json.JSONDecodeError, OSError):
                        pass

        # Try to find JSON blob in the output itself
        brace_start = text.rfind("{")
        bracket_start = text.rfind("[")
        start = max(brace_start, bracket_start)
        if start >= 0:
            candidate = text[start:]
            for end in range(len(candidate), 0, -1):
                try:
                    return json.loads(candidate[:end])
                except json.JSONDecodeError:
                    continue
        return None

    # ----- command selection -----------------------------------------------

    def _select_command(self, cmd: str):
        self._current_cmd = cmd

        for cid, btn in self._cmd_buttons.items():
            if cid == cmd:
                btn.configure(fg_color=RED_DIM, text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_MUTED)

        desc = cmd
        for _, cmds in PHASES:
            for cid, clabel in cmds:
                if cid == cmd:
                    desc = clabel
                    break

        self._cmd_title.configure(text=cmd)
        self._cmd_desc.configure(text=desc)

        self._build_form(cmd)
        self._update_preview()

    # ----- form builder ----------------------------------------------------

    def _build_form(self, cmd: str):
        for w in self._form_frame.winfo_children():
            w.destroy()
        self._arg_widgets.clear()

        arg_keys = CMD_ARGS.get(cmd, [])

        for key in arg_keys:
            if key not in ARG_DEFS:
                continue
            flag, label, atype, default, choices = ARG_DEFS[key]
            self._add_field(key, flag, label, atype, default, choices)

    def _add_field(self, key, flag, label, atype, default, choices):
        row = ctk.CTkFrame(self._form_frame, fg_color="transparent")
        row.pack(fill="x", pady=3)

        lbl = ctk.CTkLabel(
            row, text=label,
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=TEXT_MUTED, width=160, anchor="w")
        lbl.pack(side="left", padx=(8, 4))

        if atype == "bool":
            var = tk.BooleanVar(value=bool(default))
            ctk.CTkCheckBox(
                row, text="", variable=var,
                fg_color=RED, hover_color=RED_HOVER,
                border_color=BORDER, width=24,
                command=self._update_preview).pack(side="left")
            self._arg_widgets[key] = var

        elif atype == "choice":
            var = tk.StringVar(value=str(default))
            opts = choices if choices else [""]
            display_opts = ["(none)"] + opts
            menu = ctk.CTkOptionMenu(
                row, values=display_opts, variable=var,
                width=200, height=28,
                fg_color=BG_INPUT, button_color=BORDER,
                button_hover_color=TEXT_DIM,
                dropdown_fg_color=BG_CARD,
                dropdown_hover_color=RED_DIM,
                font=ctk.CTkFont(family="Consolas", size=12),
                dropdown_font=ctk.CTkFont(family="Consolas", size=12),
                command=lambda _: self._update_preview())
            if default:
                var.set(default)
            else:
                var.set("(none)")
            menu.pack(side="left")
            self._arg_widgets[key] = var

        elif atype in ("file", "fileSave"):
            var = tk.StringVar(value=str(default))
            entry = ctk.CTkEntry(
                row, textvariable=var, width=200, height=28,
                fg_color=BG_INPUT, border_color=BORDER,
                text_color=TEXT,
                font=ctk.CTkFont(family="Consolas", size=12))
            entry.pack(side="left")
            entry.bind("<KeyRelease>", lambda _: self._update_preview())
            ctk.CTkButton(
                row, text="...", width=32, height=28,
                fg_color=BG_CARD, hover_color=BORDER,
                text_color=TEXT,
                command=lambda v=var, t=atype: self._browse(v, t)).pack(side="left", padx=4)
            self._arg_widgets[key] = var

        else:
            var = tk.StringVar(value=str(default))
            entry = ctk.CTkEntry(
                row, textvariable=var, width=200, height=28,
                fg_color=BG_INPUT, border_color=BORDER,
                text_color=TEXT,
                font=ctk.CTkFont(family="Consolas", size=12),
                placeholder_text=flag)
            entry.pack(side="left")
            entry.bind("<KeyRelease>", lambda _: self._update_preview())
            self._arg_widgets[key] = var

    def _browse(self, var: tk.StringVar, atype: str):
        if atype == "file":
            p = filedialog.askopenfilename()
        else:
            p = filedialog.asksaveasfilename()
        if p:
            var.set(p)
            self._update_preview()

    # ----- command building ------------------------------------------------

    def _build_cmd_args(self) -> list[str]:
        cmd = self._current_cmd
        if not cmd:
            return []

        args = [sys.executable, REAPER_PY, cmd, "--no-banner"]

        if self._prof_skip_auth.get():
            args.append("--skip-auth")

        arg_keys = CMD_ARGS.get(cmd, [])

        for key in arg_keys:
            if key not in ARG_DEFS or key not in self._arg_widgets:
                continue
            flag, _, atype, default, _ = ARG_DEFS[key]
            var = self._arg_widgets[key]

            if atype == "bool":
                if var.get():
                    args.append(flag)
            elif atype == "choice":
                val = var.get()
                if val and val != "(none)":
                    args.extend([flag, val])
            elif atype == "strList":
                val = var.get().strip()
                if val:
                    args.append(flag)
                    args.extend(val.split())
            else:
                val = var.get().strip()
                if val:
                    args.extend([flag, val])

        return args

    def _get_display_cmd(self) -> str:
        parts = self._build_cmd_args()
        if not parts:
            return ""
        display = ["python", "ros2reaper.py"] + parts[2:]
        return " ".join(display)

    def _update_preview(self):
        self._cmd_preview.configure(text=self._get_display_cmd())

    # ----- execution -------------------------------------------------------

    def _execute(self):
        if self._process and self._process.poll() is None:
            messagebox.showwarning("Running",
                                   "A command is already running. Abort it first.")
            return

        # Apply profile values to the form before building args
        self._apply_profile()

        args = self._build_cmd_args()
        if len(args) < 3:
            return

        self._raw_output = ""
        self._last_json = None
        self._clear_output()
        self._switch_output_tab("terminal")
        self._set_status("RUNNING", YELLOW)
        self._run_btn.configure(state="disabled")
        self._kill_btn.configure(state="normal")

        self._append_output(f"$ {self._get_display_cmd()}\n\n", "cmd")

        thread = threading.Thread(target=self._run_subprocess, args=(args,),
                                  daemon=True)
        thread.start()

    def _run_subprocess(self, args: list[str]):
        try:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            self._process = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=SCRIPT_DIR,
                env=env,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                if sys.platform == "win32" else 0)

            for line in self._process.stdout:
                clean = strip_ansi(line)
                self._raw_output += clean
                tag = classify_line(clean)
                self.after(0, self._append_output, clean, tag)

            self._process.wait()
            rc = self._process.returncode
            self.after(0, self._on_finished, rc)
        except Exception as e:
            self.after(0, self._append_output, f"\n[GUI ERROR] {e}\n", "error")
            self.after(0, self._on_finished, -1)

    def _on_finished(self, rc: int):
        self._process = None
        self._run_btn.configure(state="normal")
        self._kill_btn.configure(state="disabled")
        if rc == 0:
            self._set_status("DONE", GREEN)
            self._append_output("\n[+] Command completed successfully.\n", "success")
        else:
            self._set_status(f"EXIT {rc}", RED)
            self._append_output(f"\n[!] Command exited with code {rc}.\n", "error")

        # Try to detect JSON output for the JSON tab
        self._last_json = self._extract_json_from_output()

    def _kill(self):
        if self._process and self._process.poll() is None:
            if sys.platform == "win32":
                self._process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                self._process.terminate()
            self._append_output("\n[!] Aborted by user.\n", "warning")
            self._set_status("ABORTED", ORANGE)

    # ----- output helpers --------------------------------------------------

    def _append_output(self, text: str, tag: str = "default"):
        if self._current_output_tab != "terminal":
            return
        self._output.configure(state="normal")
        self._output.insert("end", text, tag)
        self._output.see("end")
        self._output.configure(state="disabled")

    def _clear_output(self):
        self._raw_output = ""
        self._last_json = None
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")
        self._output.configure(state="disabled")

    def _set_status(self, text: str, color: str):
        self._status_label.configure(text=text, text_color=color)

    def _copy_cmd(self):
        cmd = self._get_display_cmd()
        if cmd:
            self.clipboard_clear()
            self.clipboard_append(cmd)

    def _export_output(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text", "*.txt"), ("JSON", "*.json"), ("All", "*.*")],
            title="Export Output")
        if not path:
            return
        if path.endswith(".json") and self._last_json is not None:
            with open(path, "w") as f:
                json.dump(self._last_json, f, indent=2)
        else:
            with open(path, "w") as f:
                f.write(self._raw_output)
        self._append_output(f"\n[+] Output exported to {path}\n", "success")

    # ----- target profiles -------------------------------------------------

    def _profiles_file(self, name: str) -> str:
        safe = re.sub(r'[^\w\-]', '_', name)
        return os.path.join(PROFILES_DIR, f"{safe}.json")

    def _load_profiles_list(self):
        profiles = ["(none)"]
        if os.path.isdir(PROFILES_DIR):
            for f in sorted(os.listdir(PROFILES_DIR)):
                if f.endswith(".json"):
                    profiles.append(f[:-5])
        self._profile_menu.configure(values=profiles)

    def _save_profile(self):
        name = self._profile_var.get().strip()
        if not name or name == "(none)":
            name = self._prof_target.get().strip() or "untitled"
        data = {
            "target": self._prof_target.get(),
            "network": self._prof_network.get(),
            "domain_id": self._prof_domain.get(),
            "namespace": self._prof_ns.get(),
        }
        path = self._profiles_file(name)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._profile_var.set(name)
        self._load_profiles_list()
        self._append_output(f"[+] Profile '{name}' saved.\n", "success")

    def _delete_profile(self):
        name = self._profile_var.get()
        if name == "(none)":
            return
        path = self._profiles_file(name)
        if os.path.isfile(path):
            os.remove(path)
        self._profile_var.set("(none)")
        self._load_profiles_list()
        self._append_output(f"[+] Profile '{name}' deleted.\n", "warning")

    def _on_profile_selected(self, name: str):
        if name == "(none)":
            return
        path = self._profiles_file(name)
        if not os.path.isfile(path):
            return
        with open(path) as f:
            data = json.load(f)
        self._prof_target.set(data.get("target", ""))
        self._prof_network.set(data.get("network", ""))
        self._prof_domain.set(data.get("domain_id", "0"))
        self._prof_ns.set(data.get("namespace", "/robot1"))

    def _apply_profile(self):
        """Push profile bar values into the current form fields."""
        mapping = {
            "target":    self._prof_target.get().strip(),
            "network":   self._prof_network.get().strip(),
            "domain_id": self._prof_domain.get().strip(),
            "namespace": self._prof_ns.get().strip(),
        }
        verbose = self._prof_verbose.get()
        for key, val in mapping.items():
            if key in self._arg_widgets and val:
                self._arg_widgets[key].set(val)
        if "verbose" in self._arg_widgets:
            self._arg_widgets["verbose"].set(verbose)
        self._update_preview()

    # ----- session save/load -----------------------------------------------

    def _save_session(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            title="Save Session")
        if not path:
            return

        data = {
            "command": self._current_cmd,
            "profile": {
                "target": self._prof_target.get(),
                "network": self._prof_network.get(),
                "domain_id": self._prof_domain.get(),
                "namespace": self._prof_ns.get(),
            },
            "args": {},
        }
        for key, var in self._arg_widgets.items():
            data["args"][key] = var.get()

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        self._append_output(f"[+] Session saved to {path}\n", "success")

    def _load_session(self):
        path = filedialog.askopenfilename(
            filetypes=[("JSON", "*.json")],
            title="Load Session")
        if not path:
            return

        with open(path) as f:
            data = json.load(f)

        # Restore profile
        profile = data.get("profile", {})
        self._prof_target.set(profile.get("target", ""))
        self._prof_network.set(profile.get("network", ""))
        self._prof_domain.set(profile.get("domain_id", "0"))
        self._prof_ns.set(profile.get("namespace", "/robot1"))

        cmd = data.get("command")
        if cmd:
            self._select_command(cmd)

        saved_args = data.get("args", {})
        for key, val in saved_args.items():
            if key in self._arg_widgets:
                self._arg_widgets[key].set(val)

        self._update_preview()
        self._append_output(f"[+] Session loaded from {path}\n", "success")


# ===========================================================================

def main():
    app = ReaperGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
