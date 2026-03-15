# ROS2Reaper

```
  ██████╗  ██████╗ ███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
  ██╔══██╗██╔═══██╗██╔════╝╚════██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██████╔╝██║   ██║███████╗ █████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ██╔══██╗██║   ██║╚════██║██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝███████║███████╗██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**DDS/RTPS + ROS 1 Offensive Security Assessment Framework**

> Author: Gh057x | v0.3.0-alpha
> Targets: ROS 2 (Humble / Jazzy) · DDS (Fast DDS, Cyclone DDS, RTI Connext) · ROS 1 (Noetic / Melodic)

---

## ⚠️ Legal Notice

```
╔══════════════════════════════════════════════════════════════════════╗
║  AUTHORIZED USE ONLY — MISUSE CAN CAUSE PHYSICAL HARM              ║
║  Only use on systems you own or have written authorization to test. ║
║  Robotic systems can cause injury. Ensure safety controls are in   ║
║  place before testing. Follow responsible disclosure practices.     ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## Overview

ROS2Reaper is a modular offensive security toolkit for assessing ROS 2 and ROS 1 robotic deployments. It targets the underlying DDS/RTPS transport layer — the communication backbone of ROS 2 — as well as the legacy ROS 1 rosmaster XML-RPC interface.

The framework is split into two phases:

| Phase | Description |
|-------|-------------|
| **Phase 1 — Reconnaissance** | Passive/active discovery, fingerprinting, enumeration, and security auditing |
| **Phase 2 — Exploitation** | Topic injection, node impersonation, RTPS amplification, and parameter manipulation |

---

## Project Structure

```
ros2reaper_framework/
├── ros2reaper.py          # Main entry point / CLI
├── core/
│   ├── rtps_parser.py     # RTPS packet parser + DDS port calculator
│   ├── rtps_scanner.py    # SPDP probing, network scanning, passive listening
│   ├── ros1_master.py     # ROS1 rosmaster XML-RPC interface
│   └── ros1_transport.py  # TCPROS transport implementation
└── modules/
    ├── fingerprint.py         # DDS vendor/version/config fingerprinting
    ├── topic_enum.py          # ROS 2 topic/service/node enumeration
    ├── sros2_audit.py         # SROS2 security configuration auditing
    ├── topic_injection.py     # ROS 2 topic injection attacks
    ├── node_impersonation.py  # Node impersonation & TF poisoning
    ├── amplification.py       # RTPS amplification & robustness testing
    ├── ros1_enum.py           # ROS1 node/topic/param enumeration
    ├── ros1_injection.py      # ROS1 TCPROS topic injection
    ├── ros1_exploitation.py   # ROS1 node killing & parameter manipulation
    └── ros1_audit.py          # ROS1 security configuration auditing
```

---

## Installation

```bash
git clone https://github.com/r3tr0xCTF/ros2reaper_framework.git
cd ros2reaper_framework
pip install -r requirements.txt
```

> ROS 2 exploitation modules (`inject`, `impersonate`) require `rclpy` and a sourced ROS 2 environment. All Phase 1 reconnaissance modules work with no ROS dependency.

---

## Usage

```
python3 ros2reaper.py <command> [options]
```

### Global Options

| Flag | Description |
|------|-------------|
| `-t`, `--target` | Target IP address |
| `-n`, `--network` | Target network in CIDR notation |
| `-d`, `--domain-id` | DDS Domain ID (default: 0) |
| `--timeout` | Probe timeout in seconds (default: 3.0) |
| `--duration` | Listen/attack duration in seconds (default: 30.0) |
| `-o`, `--output` | Save results to JSON file |
| `-v`, `--verbose` | Verbose output |
| `--skip-auth` | Skip authorization prompt (for scripting) |
| `--no-banner` | Suppress ASCII banner |

---

## Phase 1 — Reconnaissance

### `discover` — DDS Participant Discovery

Sends SPDP (Simple Participant Discovery Protocol) probes to identify DDS participants on the network.

```bash
# Multicast probe on local network
python3 ros2reaper.py discover

# Single target
python3 ros2reaper.py discover --target 192.168.1.100

# Full network sweep
python3 ros2reaper.py discover --network 192.168.1.0/24 -o discovered.json
```

---

### `fingerprint` — DDS Vendor / Version Identification

Fingerprints discovered participants to identify DDS implementation, RMW layer, ROS 2 distro, OS hints, deployment type, and security posture.

```bash
python3 ros2reaper.py fingerprint --target 192.168.1.100
python3 ros2reaper.py fingerprint --network 192.168.1.0/24 -o fingerprints.json
```

Output includes:
- DDS vendor (Fast DDS, Cyclone DDS, RTI Connext, etc.)
- RMW implementation and ROS 2 distribution
- Node name and deployment type
- OS hint
- Security status — DDS Security / SROS2 enabled or disabled
- Risk factors with severity (CRITICAL / HIGH / MEDIUM / LOW)

---

### `portscan` — DDS Port Discovery

Scans for open DDS-specific UDP ports derived from domain IDs. Identifies discovery and user data channels per participant.

```bash
python3 ros2reaper.py portscan --target 192.168.1.100 --domains 0-10
python3 ros2reaper.py portscan --network 192.168.1.0/24 --domains 0,1,5
```

---

### `portcalc` — DDS Port Calculator

Calculates expected DDS port numbers for given domain IDs without sending any traffic.

```bash
python3 ros2reaper.py portcalc --domains 0-15
python3 ros2reaper.py portcalc --domains 0,1,42 -v
```

```
  Domain | Disc MC | Disc UC | User MC | User UC
-------------------------------------------------------
       0 |    7400 |    7410 |    7401 |    7411
       1 |    7650 |    7660 |    7651 |    7661
```

---

### `listen` — Passive RTPS Traffic Capture

Listens passively on DDS multicast groups. Zero packets sent — full stealth mode.

```bash
python3 ros2reaper.py listen --domain-id 0 --duration 60
python3 ros2reaper.py listen --domain-id 0 --duration 120 -o captured.json
```

---

### `enumerate` — ROS 2 Graph Enumeration

Enumerates the full ROS 2 compute graph: topics, services, nodes, publishers, and subscribers.

```bash
python3 ros2reaper.py enumerate --target 192.168.1.100
python3 ros2reaper.py enumerate --domain-id 5 -o graph.json
```

---

### `audit` — SROS2 Security Configuration Audit

Audits the security posture of discovered participants: checks for disabled encryption, missing access control, insecure QoS policies, and unauthenticated endpoints.

```bash
python3 ros2reaper.py audit --target 192.168.1.100
python3 ros2reaper.py audit --network 192.168.1.0/24 -o audit.json
```

---

### `full` — Complete Assessment

Runs all Phase 1 modules sequentially (discovery → fingerprinting → port scan) and produces a single consolidated JSON report.

```bash
python3 ros2reaper.py full --network 192.168.1.0/24 -o full_report.json
python3 ros2reaper.py full --target 192.168.1.100 --domain-id 0 -v
```

---

## Phase 2 — Exploitation (ROS 2)

> Requires a sourced ROS 2 environment and `rclpy`. Run from an attacker container or a ROS 2-capable host.

### `inject` — Topic Message Injection

Injects malicious messages onto ROS 2 topics across multiple attack modes.

| Mode | Description |
|------|-------------|
| `cmd_vel` | Velocity command injection — presets: `spin`, `fullspeed`, `reverse`, `erratic`, `estop`, `circle` |
| `lidar` | LIDAR scan spoofing — modes: `allclear`, `wall`, `phantom` |
| `nav` | Navigation goal hijacking — send robot to arbitrary coordinates |
| `odom` | Odometry spoofing — corrupt pose estimation pipeline |
| `swarm` | Multi-robot convergence attack — drive an entire fleet to one point |

```bash
# Spin the robot
python3 ros2reaper.py inject --namespace /robot1 --preset spin --duration 10

# Full speed injection
python3 ros2reaper.py inject --namespace /robot1 --preset fullspeed --duration 5

# Blind LIDAR — inject clear-path data to suppress obstacle avoidance
python3 ros2reaper.py inject --attack-mode lidar --namespace /robot1 --lidar-mode allclear --duration 30

# Navigation goal hijack
python3 ros2reaper.py inject --attack-mode nav --namespace /robot1 --x 10 --y 5 --duration 20

# Odometry corruption
python3 ros2reaper.py inject --attack-mode odom --namespace /robot1 --duration 15

# Swarm convergence
python3 ros2reaper.py inject --attack-mode swarm --namespaces /robot1 /robot2 /robot3 --x 5 --y 5 --duration 30
```

---

### `impersonate` — Node Impersonation

Impersonates existing ROS 2 nodes to inject data, corrupt the TF tree, flood topics, or saturate the DDS bus with fake participants.

| Mode | Description |
|------|-------------|
| `shadow` | Shadow publisher — mirror a target node's topic output with attacker-controlled data |
| `tf` | TF tree poisoning — inject corrupt coordinate frame transforms |
| `dos` | Topic flooding — saturate a node's subscriptions |
| `sybil` | Sybil attack — spawn N fake DDS participants |

```bash
# Shadow publisher
python3 ros2reaper.py impersonate --attack-mode shadow --target-node robot_controller --namespace /robot1 --duration 30

# TF poisoning
python3 ros2reaper.py impersonate --attack-mode tf --target-node fake_robot_1 --namespace /robot1 --duration 20

# Topic DoS
python3 ros2reaper.py impersonate --attack-mode dos --namespace /robot1 --duration 10

# Sybil (20 fake participants)
python3 ros2reaper.py impersonate --attack-mode sybil --namespace /robot1 --count 20 --duration 30
```

---

### `amplify` — RTPS Amplification & Robustness Testing

Tests DDS implementations for amplification vulnerabilities and protocol robustness at the raw RTPS level. No ROS 2 installation required.

| Mode | Description |
|------|-------------|
| `full_suite` | Run all robustness tests sequentially |
| `reflect` | SPDP reflection / amplification measurement |
| `exhaust` | Participant exhaustion via GUID flooding |
| `fuzz` | Malformed RTPS packet fuzzing |
| `heartbeat` | Heartbeat amplification test |

```bash
# Full suite
python3 ros2reaper.py amplify --target 192.168.1.100 --attack-mode full_suite

# Participant exhaustion
python3 ros2reaper.py amplify --target 192.168.1.100 --attack-mode exhaust --count 500

# Protocol fuzzing
python3 ros2reaper.py amplify --target 192.168.1.100 --attack-mode fuzz --domain-id 0
```

---

## ROS 1 Modules

Targets legacy ROS 1 deployments via the rosmaster XML-RPC API and TCPROS protocol.

### `ros1-discover` — Enumeration

Enumerates all nodes, topics, services, and parameters from a rosmaster.

```bash
python3 ros2reaper.py ros1-discover --target 192.168.1.10 --skip-auth
python3 ros2reaper.py ros1-discover --target 192.168.1.10 --ros1-port 11311 -v -o ros1_enum.json
```

---

### `ros1-audit` — Security Audit

Audits a ROS1 deployment for misconfigurations: unauthenticated master, security-critical topic exposure, EOL distros, and exposed parameter server.

```bash
python3 ros2reaper.py ros1-audit --target 192.168.1.10 --skip-auth -o ros1_audit.json
```

---

### `ros1-inject` — Topic Injection

Injects messages into ROS1 topics via TCPROS without being a registered node.

```bash
# cmd_vel spinout
python3 ros2reaper.py ros1-inject --target 192.168.1.10 --topic /cmd_vel --preset spinout --duration 10 --skip-auth

# LIDAR blind injection
python3 ros2reaper.py ros1-inject --target 192.168.1.10 --attack-mode lidar --topic /scan --duration 10 --skip-auth
```

---

### `ros1-exploit` — Node Kill / Parameter Manipulation

Kills ROS1 nodes and reads, writes, or deletes parameter server values.

```bash
# Kill a specific node
python3 ros2reaper.py ros1-exploit --target 192.168.1.10 --node /turtlesim --skip-auth

# Kill all nodes
python3 ros2reaper.py ros1-exploit --target 192.168.1.10 --kill-all --skip-auth

# Write a parameter
python3 ros2reaper.py ros1-exploit --target 192.168.1.10 --param-key /max_speed --param-value 0.1 --skip-auth

# Dump all parameters
python3 ros2reaper.py ros1-exploit --target 192.168.1.10 --skip-auth
```

---

## Output

All commands support `-o <file.json>` for structured JSON output. The `full` command auto-generates a timestamped report when no output path is specified.

```bash
python3 ros2reaper.py full --network 10.0.0.0/24 -o report_$(date +%s).json
```

---

## License

MIT — Use responsibly. Only test systems you own or have explicit written authorization to assess.
