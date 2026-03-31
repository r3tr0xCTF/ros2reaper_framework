#!/usr/bin/env python3
"""
shodan_dds.py — Internet-Wide DDS Exposure Scanner
====================================================
ROS2Reaper Phase 3 Module

Queries Shodan for internet-exposed DDS/RTPS endpoints using known port
patterns, banner signatures, and vendor fingerprints. Correlates results
with ICS/OT industry sectors using Shodan org/ASN metadata and GeoIP.
Discovered IPs can feed directly into ics_dds_enum.py for deeper analysis.

Author  : Gh057x
Phase   : 3 — ICS/OT Bridge
Requires: shodan, requests

Usage:
    python3 shodan_dds.py --search                     # Run all queries
    python3 shodan_dds.py --search --domain 0          # Domain ID 0 only
    python3 shodan_dds.py --host 1.2.3.4               # Single host lookup
    python3 shodan_dds.py --search --export targets.txt # Export IPs for ics_dds_enum
    python3 shodan_dds.py --search --context scada      # Filter to SCADA-likely hits
"""

import os
import sys
import json
import time
import argparse
import ipaddress
import re
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import shodan
except ImportError:
    print("[-] shodan library not installed. Run: pip install shodan")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# DDS port formula — domain 0 baseline + common alternates
DDS_PORT_MATRIX = {
    0:   [7400, 7401, 7410, 7411, 7412, 7413],
    1:   [7650, 7651, 7660, 7661],
    5:   [8650, 8651, 8660, 8661],
    10:  [9900, 9901, 9910],
    100: [32400, 32401, 32410],
}

# Shodan search queries — ordered by signal quality
SHODAN_QUERIES = [
    # High-confidence: RTPS magic bytes in banner
    {
        "id":          "rtps_magic",
        "description": "RTPS protocol magic bytes in UDP response",
        "query":       'product:"RTPS"',
        "confidence":  "high",
    },
    {
        "id":          "dds_port_7400",
        "description": "DDS discovery multicast port (domain 0)",
        "query":       "port:7400",
        "confidence":  "medium",
    },
    {
        "id":          "dds_port_7410",
        "description": "DDS discovery unicast port (domain 0, participant 0)",
        "query":       "port:7410",
        "confidence":  "medium",
    },
    {
        "id":          "fastdds_banner",
        "description": "Fast DDS (eProsima) banner strings",
        "query":       '"Fast-RTPS" OR "eProsima" port:7400',
        "confidence":  "high",
    },
    {
        "id":          "cyclone_banner",
        "description": "Cyclone DDS / Eclipse banner strings",
        "query":       '"CycloneDDS" OR "cyclone_dds" port:7400',
        "confidence":  "high",
    },
    {
        "id":          "connext_banner",
        "description": "RTI Connext DDS banner (dominant in ATC/SCADA)",
        "query":       '"RTI Connext" OR "NDDS" port:7400',
        "confidence":  "high",
    },
    {
        "id":          "opensplice_banner",
        "description": "ADLINK/PrismTech OpenSplice DDS",
        "query":       '"OpenSplice" OR "Vortex" port:7400',
        "confidence":  "high",
    },
    {
        "id":          "ros2_dds_combined",
        "description": "ROS 2 specific DDS strings in banners",
        "query":       '"ros2" OR "ROS_DOMAIN_ID" port:7400',
        "confidence":  "high",
    },
    {
        "id":          "dds_domain1",
        "description": "DDS domain ID 1 discovery port",
        "query":       "port:7650",
        "confidence":  "low",
    },
    {
        "id":          "dds_domain5",
        "description": "DDS domain ID 5 (common in ATC/mil contexts)",
        "query":       "port:8650",
        "confidence":  "low",
    },
    {
        "id":          "rtps_multicast",
        "description": "Hosts advertising RTPS multicast group 239.255.0.1",
        "query":       '"239.255.0.1" port:7400',
        "confidence":  "high",
    },
]

# ICS org/sector keyword mapping for Shodan org/ISP fields
ICS_ORG_KEYWORDS = {
    "scada":      ["scada", "power", "utility", "electric", "grid", "transmission",
                   "generation", "nuclear", "pipeline", "water", "wastewater"],
    "atc":        ["air traffic", "eurocontrol", "nav canada", "faa", "nats ",
                   "airways", "aviation", "airport"],
    "automotive": ["automotive", "vehicle", "tesla", "waymo", "cruise", "mobileye",
                   "bosch", "continental", "aptiv", "magna"],
    "defense":    ["defense", "military", "army", "navy", "usaf", "raytheon",
                   "lockheed", "northrop", "boeing", "bae systems", "l3harris"],
    "medical":    ["hospital", "health", "medical", "pharma", "clinical"],
    "iiot":       ["manufacturing", "industrial", "factory", "automation",
                   "siemens", "abb", "honeywell", "emerson", "rockwell"],
}

# Known non-DDS false positives on these ports to filter
FALSE_POSITIVE_STRINGS = [
    "SSH-", "HTTP/1.", "220 FTP", "SMTP", "IMAP",
    "POP3", "RFB 003", "<!DOCTYPE",
]


# ─────────────────────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ShodanDDSHit:
    """A single DDS-positive host found via Shodan."""
    ip:               str
    port:             int
    transport:        str                  = "udp"
    org:              str                  = ""
    isp:              str                  = ""
    asn:              str                  = ""
    country:          str                  = ""
    city:             str                  = ""
    hostnames:        list                 = field(default_factory=list)
    domains:          list                 = field(default_factory=list)
    banner:           str                  = ""
    product:          str                  = ""
    version:          str                  = ""
    cpes:             list                 = field(default_factory=list)
    vulns:            list                 = field(default_factory=list)
    query_source:     str                  = ""
    confidence:       str                  = "medium"
    dds_vendor_guess: str                  = ""
    ics_sector_guess: str                  = "unknown"
    is_ros2:          bool                 = False
    security_strings: list                 = field(default_factory=list)
    first_seen:       str                  = ""
    last_seen:        str                  = ""
    tags:             list                 = field(default_factory=list)
    risk_flags:       list                 = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ShodanScanResult:
    """Aggregated results from a Shodan DDS search campaign."""
    scan_time:         str   = field(default_factory=lambda: datetime.now().isoformat())
    total_hits:        int   = 0
    unique_ips:        int   = 0
    queries_run:       list  = field(default_factory=list)
    hits:              list  = field(default_factory=list)
    sector_breakdown:  dict  = field(default_factory=dict)
    country_breakdown: dict  = field(default_factory=dict)
    vendor_breakdown:  dict  = field(default_factory=dict)
    high_risk_hosts:   list  = field(default_factory=list)
    export_ips:        list  = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# DDS BANNER ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class DDSBannerAnalyzer:
    """Analyzes Shodan banner data to confirm DDS presence and classify vendor."""

    VENDOR_SIGNATURES = {
        "eProsima / Fast DDS":  ["Fast-RTPS", "eProsima", "fastrtps", "fastdds"],
        "RTI Connext":          ["RTI", "Connext", "NDDS", "rti.com"],
        "Eclipse Cyclone DDS":  ["CycloneDDS", "cyclone_dds", "Eclipse", "DDSI"],
        "ADLINK OpenSplice":    ["OpenSplice", "Vortex", "ADLINK", "PrismTech"],
        "Twin Oaks CoreDX":     ["CoreDX", "TwinOaks", "twinoaks"],
        "OpenDDS":              ["OpenDDS", "OCI", "opendds"],
        "GurumDDS":             ["GurumdDS", "gurum"],
    }

    ROS2_SIGNATURES = [
        "ros2", "ROS_DOMAIN_ID", "ros_", "/cmd_vel", "/odom",
        "/tf", "/scan", "/robot_description", "rmw_",
    ]

    SECURITY_STRINGS = [
        "DDS:Auth:", "DDS:Access:", "DDS:Crypto:",
        "identity_ca", "permissions_ca", "governance",
        "SROS2", "sros2",
    ]

    def analyze(self, banner: str, product: str = "", version: str = "") -> dict:
        """Return analysis dict with vendor_guess, is_ros2, security_strings."""
        banner_lower = banner.lower()
        combined     = f"{banner} {product} {version}".lower()

        # Vendor detection
        vendor_guess = "Unknown DDS"
        for vendor, sigs in self.VENDOR_SIGNATURES.items():
            if any(s.lower() in combined for s in sigs):
                vendor_guess = vendor
                break

        # ROS 2 detection
        is_ros2 = any(s.lower() in banner_lower for s in self.ROS2_SIGNATURES)

        # DDS-Security detection
        sec_hits = [s for s in self.SECURITY_STRINGS if s.lower() in banner_lower]

        # False positive check
        is_dds = not any(fp in banner for fp in FALSE_POSITIVE_STRINGS)
        # Boost confidence if we see RTPS magic or known DDS strings
        if any(s.lower() in banner_lower for s in ["rtps", "dds", "fast-rtps", "connext"]):
            is_dds = True

        return {
            "vendor_guess":     vendor_guess,
            "is_ros2":          is_ros2,
            "security_strings": sec_hits,
            "is_dds":           is_dds,
        }


# ─────────────────────────────────────────────────────────────────────────────
# ICS SECTOR CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────

class ShodanICSClassifier:
    """Classifies a Shodan hit into an ICS sector using org/ISP/hostname metadata."""

    def classify(self, hit: ShodanDDSHit) -> str:
        combined = " ".join([
            hit.org, hit.isp,
            " ".join(hit.hostnames),
            " ".join(hit.domains),
            hit.banner,
        ]).lower()

        scores = {}
        for sector, keywords in ICS_ORG_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in combined)
            if score:
                scores[sector] = score

        if not scores:
            return "unknown"
        return max(scores, key=lambda s: scores[s])

    def assess_risk_flags(self, hit: ShodanDDSHit) -> list:
        flags = []

        if not hit.security_strings:
            flags.append("NO_DDS_SECURITY — unauthenticated endpoint")

        if hit.ics_sector_guess not in ("unknown", ""):
            flags.append(f"ICS_CONTEXT:{hit.ics_sector_guess.upper()} — critical sector exposure")

        if hit.vulns:
            for cve in hit.vulns:
                flags.append(f"KNOWN_VULN:{cve}")

        if hit.is_ros2:
            flags.append("ROS2_DETECTED — robot middleware internet-exposed")

        # Check for cloud hosting (unusual for OT)
        cloud_orgs = ["amazon", "google", "microsoft azure", "digitalocean",
                      "linode", "vultr", "ovh", "hetzner"]
        if any(c in hit.org.lower() for c in cloud_orgs):
            flags.append("CLOUD_HOSTED — OT/ICS DDS on cloud infra is anomalous")

        return flags


# ─────────────────────────────────────────────────────────────────────────────
# SHODAN QUERY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ShodanDDSScanner:
    """Runs Shodan search queries and host lookups for DDS exposure."""

    def __init__(self, api_key: str, rate_limit: float = 1.0):
        self.api        = shodan.Shodan(api_key)
        self.rate_limit = rate_limit   # seconds between API calls
        self.analyzer   = DDSBannerAnalyzer()
        self.classifier = ShodanICSClassifier()

    # ── Search campaign ───────────────────────────────────────────────────────

    def run_search_campaign(
        self,
        queries:        list = None,
        max_per_query:  int  = 100,
        context_filter: str  = None,
    ) -> ShodanScanResult:
        """
        Run all (or selected) Shodan queries and aggregate results.
        Deduplicates by IP:port across queries.
        """
        if queries is None:
            queries = SHODAN_QUERIES

        result    = ShodanScanResult()
        seen_keys = set()

        for q in queries:
            print(f"  [Q] {q['id']}: {q['description']}")
            hits = self._run_single_query(q, max_per_query, seen_keys)
            result.queries_run.append(q["id"])
            result.hits.extend(hits)
            time.sleep(self.rate_limit)

        # Post-process
        result.total_hits  = len(result.hits)
        result.unique_ips  = len({h["ip"] for h in result.hits})

        # Breakdowns
        for h in result.hits:
            hit = ShodanDDSHit(**h) if isinstance(h, dict) else h
            s   = hit.ics_sector_guess
            c   = hit.country
            v   = hit.dds_vendor_guess

            result.sector_breakdown[s]  = result.sector_breakdown.get(s, 0) + 1
            result.country_breakdown[c] = result.country_breakdown.get(c, 0) + 1
            result.vendor_breakdown[v]  = result.vendor_breakdown.get(v, 0) + 1

            if hit.risk_flags:
                result.high_risk_hosts.append({
                    "ip":     hit.ip,
                    "port":   hit.port,
                    "sector": hit.ics_sector_guess,
                    "flags":  hit.risk_flags,
                    "org":    hit.org,
                    "country": hit.country,
                })

        result.export_ips = list({h["ip"] for h in result.hits})

        # Optional context filter
        if context_filter:
            result.hits = [
                h for h in result.hits
                if h.get("ics_sector_guess") == context_filter
            ]

        return result

    def _run_single_query(self, query_def: dict, max_results: int,
                           seen: set) -> list:
        hits = []
        try:
            results = self.api.search(query_def["query"], limit=max_results)
            for match in results.get("matches", []):
                key = f"{match.get('ip_str')}:{match.get('port')}"
                if key in seen:
                    continue
                seen.add(key)

                hit = self._match_to_hit(match, query_def)
                if hit:
                    hits.append(hit.to_dict())
                    self._print_hit(hit)

        except shodan.APIError as e:
            err = str(e)
            if "No information available" in err:
                print(f"    [~] No results for query: {query_def['id']}")
            elif "upgrade your API plan" in err.lower():
                print(f"    [!] Query {query_def['id']} requires Shodan membership plan")
            else:
                print(f"    [!] Shodan API error on {query_def['id']}: {e}")

        return hits

    def _match_to_hit(self, match: dict, query_def: dict) -> Optional[ShodanDDSHit]:
        """Convert a Shodan search match to a ShodanDDSHit."""
        banner  = match.get("data", "") or ""
        product = match.get("product", "") or ""
        version = match.get("version", "") or ""

        analysis = self.analyzer.analyze(banner, product, version)
        if not analysis["is_dds"]:
            return None

        hit = ShodanDDSHit(
            ip               = match.get("ip_str", ""),
            port             = match.get("port", 0),
            org              = match.get("org", ""),
            isp              = match.get("isp", ""),
            asn              = match.get("asn", ""),
            country          = match.get("location", {}).get("country_name", ""),
            city             = match.get("location", {}).get("city", "") or "",
            hostnames        = match.get("hostnames", []),
            domains          = match.get("domains", []),
            banner           = banner[:2048],    # truncate
            product          = product,
            version          = version,
            cpes             = match.get("cpe", []),
            vulns            = list(match.get("vulns", {}).keys()),
            query_source     = query_def["id"],
            confidence       = query_def["confidence"],
            dds_vendor_guess = analysis["vendor_guess"],
            is_ros2          = analysis["is_ros2"],
            security_strings = analysis["security_strings"],
            first_seen       = match.get("timestamp", ""),
            last_seen        = match.get("timestamp", ""),
            tags             = match.get("tags", []),
        )

        hit.ics_sector_guess = self.classifier.classify(hit)
        hit.risk_flags       = self.classifier.assess_risk_flags(hit)

        return hit

    def _print_hit(self, hit: ShodanDDSHit):
        sec_str = "🔒 SEC" if hit.security_strings else "🔓 OPEN"
        ros_str = " [ROS2]" if hit.is_ros2 else ""
        ics_str = f" [{hit.ics_sector_guess.upper()}]" if hit.ics_sector_guess != "unknown" else ""
        print(
            f"    [+] {hit.ip}:{hit.port} | {hit.country} | "
            f"{hit.org[:40]} | {hit.dds_vendor_guess} | "
            f"{sec_str}{ros_str}{ics_str}"
        )

    # ── Single host lookup ────────────────────────────────────────────────────

    def lookup_host(self, ip: str) -> dict:
        """
        Full Shodan host lookup — all ports, vulns, history, banners.
        More data than search matches; useful for targeted investigation.
        """
        try:
            host = self.api.host(ip)
        except shodan.APIError as e:
            return {"error": str(e), "ip": ip}

        dds_services = []
        for svc in host.get("data", []):
            port    = svc.get("port", 0)
            banner  = svc.get("data", "") or ""
            product = svc.get("product", "") or ""
            version = svc.get("version", "") or ""

            analysis = self.analyzer.analyze(banner, product, version)

            # Include if DDS-positive OR on a known DDS port
            all_dds_ports = set()
            for ports in DDS_PORT_MATRIX.values():
                all_dds_ports.update(ports)

            if analysis["is_dds"] or port in all_dds_ports:
                dds_services.append({
                    "port":             port,
                    "transport":        svc.get("transport", "udp"),
                    "banner":           banner[:1024],
                    "product":          product,
                    "version":          version,
                    "dds_vendor_guess": analysis["vendor_guess"],
                    "is_ros2":          analysis["is_ros2"],
                    "security_strings": analysis["security_strings"],
                    "vulns":            list(svc.get("vulns", {}).keys()),
                })

        result = {
            "ip":           ip,
            "org":          host.get("org", ""),
            "isp":          host.get("isp", ""),
            "asn":          host.get("asn", ""),
            "country":      host.get("country_name", ""),
            "hostnames":    host.get("hostnames", []),
            "domains":      host.get("domains", []),
            "tags":         host.get("tags", []),
            "vulns":        list(host.get("vulns", {}).keys()),
            "dds_services": dds_services,
            "total_ports":  len(host.get("data", [])),
        }

        # Sector + risk for the host as a whole
        stub_hit = ShodanDDSHit(
            ip      = ip,
            port    = dds_services[0]["port"] if dds_services else 0,
            org     = result["org"],
            isp     = result["isp"],
            hostnames = result["hostnames"],
            domains   = result["domains"],
            banner    = " ".join(s["banner"] for s in dds_services),
            vulns     = result["vulns"],
            security_strings = dds_services[0].get("security_strings", []) if dds_services else [],
            dds_vendor_guess = dds_services[0].get("dds_vendor_guess", "") if dds_services else "",
            is_ros2   = any(s["is_ros2"] for s in dds_services),
        )
        result["ics_sector_guess"] = self.classifier.classify(stub_hit)
        result["risk_flags"]       = self.classifier.assess_risk_flags(stub_hit)

        return result


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT / REPORTING
# ─────────────────────────────────────────────────────────────────────────────

def print_campaign_summary(result: ShodanScanResult):
    print(f"\n{'='*60}")
    print("  SHODAN DDS CAMPAIGN SUMMARY")
    print(f"{'='*60}")
    print(f"  Scan time      : {result.scan_time}")
    print(f"  Queries run    : {len(result.queries_run)}")
    print(f"  Total hits     : {result.total_hits}")
    print(f"  Unique IPs     : {result.unique_ips}")

    if result.sector_breakdown:
        print(f"\n  Sector breakdown:")
        for s, c in sorted(result.sector_breakdown.items(), key=lambda x: -x[1]):
            print(f"    {s:<20} {c}")

    if result.country_breakdown:
        top_countries = sorted(result.country_breakdown.items(), key=lambda x: -x[1])[:10]
        print(f"\n  Top countries:")
        for c, n in top_countries:
            print(f"    {c:<25} {n}")

    if result.vendor_breakdown:
        print(f"\n  DDS vendor distribution:")
        for v, c in sorted(result.vendor_breakdown.items(), key=lambda x: -x[1]):
            print(f"    {v:<35} {c}")

    if result.high_risk_hosts:
        print(f"\n  ⚠  HIGH RISK HOSTS ({len(result.high_risk_hosts)}):")
        for h in result.high_risk_hosts[:20]:   # cap display
            print(f"    {h['ip']:<18} [{h['sector'].upper():<12}] {h['org'][:35]}")
            for flag in h["flags"]:
                print(f"      → {flag}")
    print()


def export_target_list(result: ShodanScanResult, filepath: str):
    """Write a plain-text IP list for piping into ics_dds_enum.py."""
    with open(filepath, "w") as f:
        for ip in result.export_ips:
            f.write(f"{ip}\n")
    print(f"[+] {len(result.export_ips)} IPs exported → {filepath}")
    print(f"[*] Feed into enumerator:")
    print(f"    while read ip; do python3 ics_dds_enum.py --target $ip --deep; done < {filepath}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ROS2Reaper Phase 3 — Shodan DDS Internet Exposure Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
API Key:
    Set SHODAN_API_KEY env var or pass --api-key

Examples:
    # Full campaign — all queries
    python3 shodan_dds.py --search

    # Search + export IPs for ics_dds_enum
    python3 shodan_dds.py --search --export targets.txt

    # Filter to SCADA-sector hits only
    python3 shodan_dds.py --search --context scada

    # Single host deep lookup
    python3 shodan_dds.py --host 1.2.3.4

    # Limit results per query (free API tier)
    python3 shodan_dds.py --search --limit 10 --output results.json
        """
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--search", action="store_true", help="Run full Shodan DDS search campaign")
    mode.add_argument("--host",   metavar="IP",        help="Single host deep lookup")

    p.add_argument("--api-key",  metavar="KEY",
                   default=os.environ.get("SHODAN_API_KEY", ""),
                   help="Shodan API key (or set SHODAN_API_KEY env var)")
    p.add_argument("--limit",    type=int, default=100,
                   help="Max results per query (default: 100; free tier: use 10)")
    p.add_argument("--context",  choices=["scada", "atc", "automotive", "defense",
                                           "medical", "iiot", "unknown"],
                   help="Filter results to a specific ICS sector")
    p.add_argument("--domain",   type=int, default=None,
                   help="Target a specific DDS domain ID (0, 1, 5…)")
    p.add_argument("--output",   metavar="FILE", help="Write JSON results to file")
    p.add_argument("--export",   metavar="FILE", help="Export IP list for ics_dds_enum.py")
    p.add_argument("--rate",     type=float, default=1.0,
                   help="Seconds between Shodan API calls (default: 1.0)")
    return p.parse_args()


def main():
    args = parse_args()

    if not args.api_key:
        print("[-] No Shodan API key. Set SHODAN_API_KEY or use --api-key")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("  ROS2Reaper :: Phase 3 — Shodan DDS Scanner")
    print(f"{'='*60}\n")

    scanner = ShodanDDSScanner(api_key=args.api_key, rate_limit=args.rate)

    # ── Host lookup mode ──────────────────────────────────────────────────────
    if args.host:
        print(f"[*] Host lookup: {args.host}")
        result = scanner.lookup_host(args.host)
        print(json.dumps(result, indent=2))

        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"[+] Saved → {args.output}")
        return

    # ── Search campaign mode ──────────────────────────────────────────────────
    queries = SHODAN_QUERIES

    # Filter by domain ID if specified
    if args.domain is not None:
        port = 7400 + (250 * args.domain)
        queries = [q for q in queries if str(port) in q["query"] or q["confidence"] == "high"]
        print(f"[*] Targeting domain ID {args.domain} (port {port})")

    print(f"[*] Running {len(queries)} queries (max {args.limit} results each)\n")

    result = scanner.run_search_campaign(
        queries        = queries,
        max_per_query  = args.limit,
        context_filter = args.context,
    )

    print_campaign_summary(result)

    if args.output:
        out = {
            "scan_time":         result.scan_time,
            "total_hits":        result.total_hits,
            "unique_ips":        result.unique_ips,
            "queries_run":       result.queries_run,
            "sector_breakdown":  result.sector_breakdown,
            "country_breakdown": result.country_breakdown,
            "vendor_breakdown":  result.vendor_breakdown,
            "high_risk_hosts":   result.high_risk_hosts,
            "hits":              result.hits,
        }
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2)
        print(f"[+] Full results → {args.output}")

    if args.export:
        export_target_list(result, args.export)


if __name__ == "__main__":
    main()
