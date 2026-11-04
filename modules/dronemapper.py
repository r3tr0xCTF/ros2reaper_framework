#!/usr/bin/env python3
"""
dronemapper.py - DRONEmapper Dataset Integration for ROS2Reaper
================================================================
Integrates the saviorSEC DRONEmapper datasets to enrich DDS participant
fingerprints with drone/robot manufacturer intelligence.

Datasets (auto-downloaded and cached at ~/.cache/ros2reaper/dronemapper/):
  oui-global.csv      — 182 OUI MAC prefixes for drone/robot manufacturers
  rid-prefixes.csv    — 3738 Remote ID serial patterns (drone model identification)
  rf-channels.csv     — 195 RF channel definitions (drone radio frequencies)
  devices-global.json — Full device catalog with robot signatures (19MB, opt-in)

Integration points in ROS2Reaper:
  1. OUI enrichment   : ARP-resolve DDS participant IPs → MAC OUI lookup
  2. RID correlation  : match captured Remote ID serials to drone/robot models
  3. Robot signatures : compare DDS topics against known robot platform patterns
  4. Live feed        : query a local DRONEmapper server (default: localhost:8780)

Author: Gh057x
"""

import csv
import json
import os
import re
import socket
import subprocess
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CACHE_DIR = Path.home() / ".cache" / "ros2reaper" / "dronemapper"
BASE_URL   = "https://dronemapper.churchofmalware.org/downloads/data"

DATASET_FILES = {
    "oui":     "oui-global.csv",
    "rid":     "rid-prefixes.csv",
    "rf":      "rf-channels.csv",
    "devices": "devices-global.json",
}

CACHE_TTL_HOURS = 24          # re-download after this many hours


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class OUIMatch:
    """Result of an OUI lookup"""
    device_name:  str
    oui:          str
    prefix_bits:  int
    category:     str = ""    # aircraft | ground | water | robot_dog | unknown


@dataclass
class RIDMatch:
    """Result of a Remote ID serial lookup"""
    manufacturer: str
    model:        str
    device_type:  str
    rule_id:      str
    evidence_url: str = ""


@dataclass
class DroneMapperEnrichment:
    """All dronemapper intel collected for one IP/MAC"""
    ip:               str = ""
    mac:              str = ""
    oui_match:        Optional[OUIMatch] = None
    rid_matches:      List[RIDMatch] = field(default_factory=list)
    live_records:     List[Dict] = field(default_factory=list)
    enriched_at:      float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "ip":          self.ip,
            "mac":         self.mac,
            "enriched_at": self.enriched_at,
        }
        if self.oui_match:
            d["oui_match"] = {
                "device_name": self.oui_match.device_name,
                "oui":         self.oui_match.oui,
                "prefix_bits": self.oui_match.prefix_bits,
                "category":    self.oui_match.category,
            }
        if self.rid_matches:
            d["rid_matches"] = [
                {
                    "manufacturer": r.manufacturer,
                    "model":        r.model,
                    "device_type":  r.device_type,
                    "rule_id":      r.rule_id,
                }
                for r in self.rid_matches
            ]
        if self.live_records:
            d["live_records"] = self.live_records
        return d

    @property
    def is_drone_or_robot(self) -> bool:
        return self.oui_match is not None or bool(self.rid_matches)


# ---------------------------------------------------------------------------
# Category inference from device name
# ---------------------------------------------------------------------------

_CATEGORY_KEYWORDS: Dict[str, List[str]] = {
    "aircraft":  [
        "drone", "uav", "uuas", "aircraft", "aerial", "air", "copter",
        "aerovironment", "dji", "parrot", "autel", "skydio", "zipline",
        "wing", "quantum-systems", "schiebel", "textron",
    ],
    "ground":    [
        "ground", "agv", "ugv", "rover", "vehicle", "truck",
        "autonomous", "delivery", "nuro", "waymo", "cruise",
    ],
    "robot_dog": [
        "boston dynamics", "unitree", "anybotics", "spot",
        "ghost robotics", "agility robotics", "legged",
    ],
    "water":     ["marine", "aqua", "usv", "water", "ocean"],
}


def _infer_category(device_name: str) -> str:
    name = device_name.lower()
    for cat, kws in _CATEGORY_KEYWORDS.items():
        if any(kw in name for kw in kws):
            return cat
    return "unknown"


# ---------------------------------------------------------------------------
# OUI parsing helpers
# ---------------------------------------------------------------------------

def _normalize_oui(raw: str) -> tuple[str, int]:
    """
    Normalize a raw OUI string to (hex_no_sep, prefix_bits).

    Handles:
      "E0:02:A5"                       → ("E00245", 24)
      "8C:1F:64:A2:D0:00/36"           → ("8C1F64A2D0", 36) [9 hex chars → 36 bits]
      "AA:BB:CC:D0:00:00/28"           → ("AABBCCD", 28)   [7 hex chars → 28 bits]
    """
    mask_bits = 24
    if "/" in raw:
        raw, mask_str = raw.rsplit("/", 1)
        mask_bits = int(mask_str)

    hex_str = re.sub(r"[^0-9A-Fa-f]", "", raw).upper()
    keep_chars = mask_bits // 4
    return hex_str[:keep_chars], mask_bits


def _mac_to_hex(mac: str) -> str:
    """Convert any MAC format to uppercase hex string without separators."""
    return re.sub(r"[^0-9A-Fa-f]", "", mac).upper()


# ---------------------------------------------------------------------------
# ARP resolution
# ---------------------------------------------------------------------------

def resolve_mac(ip: str) -> Optional[str]:
    """
    Resolve an IP address to its MAC address via ARP cache (/proc/net/arp)
    or the `arp` command.  Returns uppercase colon-separated MAC or None.
    """
    # Try /proc/net/arp first (Linux, no subprocess needed)
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac and mac != "00:00:00:00:00:00":
                        return mac.upper()
    except OSError:
        pass

    # Fallback: trigger ARP probe then re-read
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac and mac != "00:00:00:00:00:00":
                        return mac.upper()
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Last resort: `arp -n <ip>`
    try:
        out = subprocess.check_output(
            ["arp", "-n", ip],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode()
        for line in out.splitlines():
            m = re.search(r"([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}", line)
            if m:
                return m.group(0).upper().replace("-", ":")
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass

    return None


# ---------------------------------------------------------------------------
# Main DB class
# ---------------------------------------------------------------------------

class DroneMapperDB:
    """
    Download, cache, and query DRONEmapper datasets.

    Typical usage:
        db = DroneMapperDB(verbose=True)
        db.ensure_loaded(["oui", "rid"])
        match = db.lookup_oui("AA:BB:CC")
        matches = db.lookup_rid("1634FS0TEN2112A00020")
        enrichment = db.enrich_participant_ip("192.168.1.42")
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._oui_entries: List[tuple[str, int, str]] = []   # (hex_prefix, bits, device_name)
        self._rid_rules:   List[Dict[str, str]] = []
        self._rf_channels: List[Dict[str, str]] = []
        self._devices:     Optional[Dict] = None
        self._loaded: set  = set()

    # ------------------------------------------------------------------
    # Loading / downloading
    # ------------------------------------------------------------------

    def ensure_loaded(self, datasets: List[str] = None):
        """Load (and download if necessary) the requested datasets."""
        if datasets is None:
            datasets = ["oui"]
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        for key in datasets:
            if key not in self._loaded:
                self._load_dataset(key)

    def update(self, force: bool = False, datasets: List[str] = None):
        """Download and refresh cached datasets."""
        if datasets is None:
            datasets = list(DATASET_FILES.keys())
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        for key in datasets:
            fname = DATASET_FILES[key]
            path  = CACHE_DIR / fname
            if not force and self._is_fresh(path):
                if self.verbose:
                    print(f"  [*] {fname}: cache fresh, skipping")
                continue
            self._download(fname, path)
            if key in self._loaded:
                self._loaded.discard(key)
                self._load_dataset(key)

    def _is_fresh(self, path: Path) -> bool:
        if not path.exists():
            return False
        age_hours = (time.time() - path.stat().st_mtime) / 3600
        return age_hours < CACHE_TTL_HOURS

    def _download(self, fname: str, dest: Path):
        url = f"{BASE_URL}/{fname}"
        if self.verbose:
            print(f"  [*] Downloading {url} → {dest}")
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ROS2Reaper/0.6 dronemapper-module"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            dest.write_bytes(data)
            print(f"  [+] {fname}: {len(data):,} bytes cached")
        except (urllib.error.URLError, OSError) as e:
            print(f"  [!] Failed to download {fname}: {e}")

    def _load_dataset(self, key: str):
        fname = DATASET_FILES[key]
        path  = CACHE_DIR / fname
        if not path.exists():
            self._download(fname, path)
        if not path.exists():
            if self.verbose:
                print(f"  [!] {fname} not available — skipping")
            return

        try:
            if key == "oui":
                self._load_oui(path)
            elif key == "rid":
                self._load_rid(path)
            elif key == "rf":
                self._load_rf(path)
            elif key == "devices":
                self._load_devices(path)
            self._loaded.add(key)
        except Exception as e:
            if self.verbose:
                print(f"  [!] Failed to load {fname}: {e}")

    def _load_oui(self, path: Path):
        self._oui_entries = []
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                raw = row.get("oui", "").strip().lstrip("'")
                name = row.get("device", "").strip().lstrip("'")
                if not raw or not name:
                    continue
                hex_prefix, bits = _normalize_oui(raw)
                if hex_prefix:
                    self._oui_entries.append((hex_prefix, bits, name))
        if self.verbose:
            print(f"  [+] OUI table loaded: {len(self._oui_entries)} entries")

    def _load_rid(self, path: Path):
        self._rid_rules = []
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cleaned = {k: v.strip().lstrip("'") for k, v in row.items()}
                self._rid_rules.append(cleaned)
        if self.verbose:
            print(f"  [+] RID rules loaded: {len(self._rid_rules)} entries")

    def _load_rf(self, path: Path):
        self._rf_channels = []
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cleaned = {k: v.strip().lstrip("'") for k, v in row.items()}
                self._rf_channels.append(cleaned)
        if self.verbose:
            print(f"  [+] RF channels loaded: {len(self._rf_channels)} entries")

    def _load_devices(self, path: Path):
        if self.verbose:
            print(f"  [*] Loading devices-global.json ({path.stat().st_size // 1024 // 1024}MB)…")
        with path.open(encoding="utf-8") as f:
            self._devices = json.load(f)
        if self.verbose:
            counts = self._devices.get("counts", {})
            print(f"  [+] Device catalog loaded: {counts.get('devices', '?')} devices, "
                  f"{counts.get('robot_signatures', '?')} robot signatures")

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def lookup_oui(self, mac: str) -> Optional[OUIMatch]:
        """
        Match a MAC address (any format) against the OUI database.
        Returns the best (longest prefix) match, or None.
        """
        if "oui" not in self._loaded:
            self.ensure_loaded(["oui"])

        hex_mac = _mac_to_hex(mac)
        best: Optional[OUIMatch] = None

        for (hex_prefix, bits, name) in self._oui_entries:
            needed = bits // 4
            if len(hex_mac) >= needed and hex_mac[:needed] == hex_prefix[:needed]:
                if best is None or bits > best.prefix_bits:
                    # Reconstruct the display OUI from the entry
                    sep = ":".join(
                        hex_prefix[i:i+2] for i in range(0, min(len(hex_prefix), 12), 2)
                    )
                    if bits != 24:
                        sep += f"/{bits}"
                    best = OUIMatch(
                        device_name=name,
                        oui=sep,
                        prefix_bits=bits,
                        category=_infer_category(name),
                    )
        return best

    def lookup_rid(self, serial: str) -> List[RIDMatch]:
        """
        Match a Remote ID serial number against the RID rules database.
        Returns all matching rules (there may be multiple candidates).
        """
        if "rid" not in self._loaded:
            self.ensure_loaded(["rid"])

        serial = serial.strip().upper()
        matches: List[RIDMatch] = []

        for rule in self._rid_rules:
            start = rule.get("serial_start", "").upper()
            end   = rule.get("serial_end",   "").upper()
            if not start or not end:
                continue
            # Lexicographic range comparison (the format is consistent per manufacturer)
            if start <= serial <= end:
                matches.append(RIDMatch(
                    manufacturer=rule.get("manufacturer", ""),
                    model=rule.get("model", ""),
                    device_type=rule.get("device_type", ""),
                    rule_id=rule.get("rule_id", ""),
                    evidence_url=rule.get("evidence_url", ""),
                ))

        return matches

    def get_robot_signatures(self) -> List[Dict]:
        """
        Return the 9 robot_signatures from devices-global.json.
        Requires --load-devices to have been called.
        """
        if "devices" not in self._loaded:
            if self.verbose:
                print("  [!] devices-global.json not loaded — use --load-devices")
            return []
        if self._devices is None:
            return []
        return self._devices.get("robot_signatures", [])

    def get_rf_channels(self, band: str = None, system: str = None) -> List[Dict]:
        """Return RF channel definitions, optionally filtered by band or system name."""
        if "rf" not in self._loaded:
            self.ensure_loaded(["rf"])
        rows = self._rf_channels
        if band:
            rows = [r for r in rows if band.lower() in r.get("band", "").lower()]
        if system:
            rows = [r for r in rows if system.lower() in r.get("system", "").lower()]
        return rows

    # ------------------------------------------------------------------
    # High-level enrichment
    # ------------------------------------------------------------------

    def enrich_participant_ip(self, ip: str) -> DroneMapperEnrichment:
        """
        Enrich a DDS participant by resolving its IP to a MAC and running OUI lookup.
        """
        enrichment = DroneMapperEnrichment(ip=ip, enriched_at=time.time())
        mac = resolve_mac(ip)
        if not mac:
            if self.verbose:
                print(f"  [!] Could not ARP-resolve {ip}")
            return enrichment

        enrichment.mac = mac
        match = self.lookup_oui(mac)
        if match:
            enrichment.oui_match = match
            if self.verbose:
                print(f"  [+] OUI match: {ip} ({mac}) → {match.device_name} [{match.category}]")
        return enrichment

    def enrich_participant_mac(self, mac: str, ip: str = "") -> DroneMapperEnrichment:
        """Enrich a DDS participant directly from a known MAC address."""
        enrichment = DroneMapperEnrichment(ip=ip, mac=mac, enriched_at=time.time())
        match = self.lookup_oui(mac)
        if match:
            enrichment.oui_match = match
        return enrichment

    # ------------------------------------------------------------------
    # Live DRONEmapper server
    # ------------------------------------------------------------------

    def query_live_server(
        self,
        server_url: str = "http://127.0.0.1:8780",
        endpoint:   str = "/api/activity",
        timeout:    int = 5,
    ) -> Optional[Dict]:
        """
        Query a locally running DRONEmapper server for nearby drone/robot positions.
        Returns the parsed JSON response or None on failure.

        Run the DRONEmapper server with:
            python3 server.py    # from the DRONEmapper repo
        """
        url = server_url.rstrip("/") + endpoint
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ROS2Reaper/0.6 dronemapper-module"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
            return data
        except urllib.error.URLError:
            if self.verbose:
                print(f"  [!] DRONEmapper server not reachable at {server_url}")
            return None
        except (json.JSONDecodeError, OSError) as e:
            if self.verbose:
                print(f"  [!] DRONEmapper server error: {e}")
            return None


# ---------------------------------------------------------------------------
# Report printing helpers
# ---------------------------------------------------------------------------

def print_enrichment_report(enrichments: List[DroneMapperEnrichment]):
    hits = [e for e in enrichments if e.is_drone_or_robot]
    total = len(enrichments)
    print(f"\n{'=' * 60}")
    print(f"  DRONEMAPPER ENRICHMENT REPORT")
    print(f"{'=' * 60}")
    print(f"  Participants checked : {total}")
    print(f"  Drone/robot matches  : {len(hits)}")
    print(f"{'─' * 60}")

    if not hits:
        print("  No drone/robot manufacturers identified via OUI lookup.")
        print("  (Devices may be on different subnet — ARP only works locally.)")
        print(f"{'=' * 60}\n")
        return

    for e in hits:
        print(f"\n  IP:  {e.ip or '(unknown)'}")
        if e.mac:
            print(f"  MAC: {e.mac}")
        if e.oui_match:
            m = e.oui_match
            cat_color = {
                "aircraft":  "\033[91m",   # red
                "ground":    "\033[93m",   # yellow
                "robot_dog": "\033[95m",   # magenta
                "water":     "\033[94m",   # blue
                "unknown":   "\033[90m",   # grey
            }.get(m.category, "\033[0m")
            print(f"  \033[1mOUI Match:\033[0m {m.device_name}")
            print(f"            OUI: {m.oui}  ({m.prefix_bits}-bit prefix)")
            print(f"            Category: {cat_color}{m.category}\033[0m")
        if e.rid_matches:
            print(f"  RID Matches ({len(e.rid_matches)}):")
            for r in e.rid_matches[:3]:
                print(f"    {r.manufacturer} {r.model} [{r.device_type}]")
            if len(e.rid_matches) > 3:
                print(f"    ... and {len(e.rid_matches) - 3} more")

    print(f"\n{'=' * 60}\n")


def print_oui_result(match: Optional[OUIMatch], query: str):
    if match:
        print(f"\n  [+] OUI Match for {query}:")
        print(f"      Device: {match.device_name}")
        print(f"      OUI:    {match.oui}  ({match.prefix_bits}-bit prefix)")
        print(f"      Type:   {match.category}")
    else:
        print(f"\n  [-] No dronemapper match for OUI {query}")
        print(f"      (Not a reviewed drone/robot/AV manufacturer)")


def print_rid_results(matches: List[RIDMatch], serial: str):
    if matches:
        print(f"\n  [+] RID match for serial '{serial}':")
        for m in matches:
            print(f"      {m.manufacturer} — {m.model}  [{m.device_type}]")
            if m.evidence_url:
                print(f"      Evidence: {m.evidence_url}")
    else:
        print(f"\n  [-] No RID match for serial '{serial}'")


def export_json(enrichments: List[DroneMapperEnrichment], path: str):
    data = {
        "tool":       "ROS2Reaper",
        "module":     "dronemapper",
        "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total":      len(enrichments),
        "matches":    sum(1 for e in enrichments if e.is_drone_or_robot),
        "enrichments": [e.to_dict() for e in enrichments],
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  [*] Enrichment report saved to {path}")
