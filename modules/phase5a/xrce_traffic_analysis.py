#!/usr/bin/env python3
"""
xrce_traffic_analysis.py - Phase 5A Module 2: XRCE Traffic Analysis & Behavioral Profiling

Captures and analyzes legitimate XRCE traffic to build behavioral baselines.
Essential for OPSEC: understand what normal looks like so injected commands
can blend in without standing out to IDS/defender monitoring.

Attack surface mapped:
  - Traffic pattern profiling (publish/subscribe timing, cadence, jitter)
  - Payload size distribution (what sizes are normal?)
  - Session behavior (how do clients connect/heartbeat?)
  - QoS patterns (reliable vs best-effort traffic characteristics)
  - Anomaly detection (what deviates from baseline)

Used by subsequent modules (hijack, implant, persistence) to:
  - Time injections to match normal traffic patterns
  - Craft payloads that match typical size distributions
  - Mimic legitimate heartbeat/ack patterns
  - Avoid triggering threshold-based IDS rules

Wire format reference:
  - XRCE packet min size: 12 bytes (8-byte header + 4-byte submessage)
  - Max payload: typically 64KB (UDP limit) but usually <4KB
  - Heartbeat interval: typically 100-1000ms (configurable)
  - QoS reliable: uses ACKN submessages (adds overhead)
  - QoS best-effort: no ACKs (clean timing, no acks to hide behind)
"""

import socket
import struct
import threading
import time
import json
import sys
import argparse
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from datetime import datetime
import statistics


# ============================================================================
# XRCE Wire Format Constants (same as microros_agent.py)
# ============================================================================

XRCE_MAGIC = 0x58524350  # "XRCP"

XRCE_MSG_CREATE = 0x01
XRCE_MSG_DELETE = 0x02
XRCE_MSG_WRITE = 0x03
XRCE_MSG_READ = 0x04
XRCE_MSG_ACKNOWLEDGE = 0x05
XRCE_MSG_HEARTBEAT = 0x07
XRCE_MSG_FRAGMENT = 0x0E

XRCE_MSG_NAMES = {
    0x01: "CREATE",
    0x02: "DELETE",
    0x03: "WRITE",
    0x04: "READ",
    0x05: "ACKNOWLEDGE",
    0x07: "HEARTBEAT",
    0x0E: "FRAGMENT",
}


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class XRCEPacket:
    """Represents a single observed XRCE packet"""
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    size: int  # Total packet size
    session_id: int
    stream_id: int
    message_type: int
    payload_size: int
    is_reliable: bool = False  # If WRITE with ACKN flag

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "size": self.size,
            "session_id": self.session_id,
            "stream_id": self.stream_id,
            "message_type": XRCE_MSG_NAMES.get(self.message_type, "UNKNOWN"),
            "payload_size": self.payload_size,
            "is_reliable": self.is_reliable,
        }


@dataclass
class TrafficStatistics:
    """Aggregated statistics for detected baseline behavior"""
    capture_duration: float  # Seconds of traffic captured
    packet_count: int
    byte_count: int
    unique_sessions: int
    unique_streams: int
    
    # Size distributions
    packet_sizes: List[int] = field(default_factory=list)
    payload_sizes: List[int] = field(default_factory=list)
    
    # Timing distributions
    inter_packet_intervals: List[float] = field(default_factory=list)
    heartbeat_intervals: List[float] = field(default_factory=list)
    
    # Message type distribution
    message_type_counts: Dict[int, int] = field(default_factory=dict)
    
    # QoS patterns
    reliable_ratio: float = 0.0  # Fraction of packets that are reliable
    
    # Per-stream stats
    stream_stats: Dict[int, Dict] = field(default_factory=dict)
    
    # Per-session stats
    session_stats: Dict[int, Dict] = field(default_factory=dict)

    def to_dict(self):
        """Convert to JSON-serializable format"""
        return {
            "capture_duration": self.capture_duration,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "unique_sessions": self.unique_sessions,
            "unique_streams": self.unique_streams,
            "packet_sizes": {
                "min": min(self.packet_sizes) if self.packet_sizes else 0,
                "max": max(self.packet_sizes) if self.packet_sizes else 0,
                "mean": statistics.mean(self.packet_sizes) if self.packet_sizes else 0,
                "median": statistics.median(self.packet_sizes) if self.packet_sizes else 0,
                "stdev": statistics.stdev(self.packet_sizes) if len(self.packet_sizes) > 1 else 0,
            },
            "payload_sizes": {
                "min": min(self.payload_sizes) if self.payload_sizes else 0,
                "max": max(self.payload_sizes) if self.payload_sizes else 0,
                "mean": statistics.mean(self.payload_sizes) if self.payload_sizes else 0,
                "median": statistics.median(self.payload_sizes) if self.payload_sizes else 0,
                "stdev": statistics.stdev(self.payload_sizes) if len(self.payload_sizes) > 1 else 0,
            },
            "inter_packet_intervals_ms": {
                "min": min(self.inter_packet_intervals) * 1000 if self.inter_packet_intervals else 0,
                "max": max(self.inter_packet_intervals) * 1000 if self.inter_packet_intervals else 0,
                "mean": statistics.mean(self.inter_packet_intervals) * 1000 if self.inter_packet_intervals else 0,
                "median": statistics.median(self.inter_packet_intervals) * 1000 if self.inter_packet_intervals else 0,
                "stdev": statistics.stdev(self.inter_packet_intervals) * 1000 if len(self.inter_packet_intervals) > 1 else 0,
            },
            "heartbeat_intervals_ms": {
                "min": min(self.heartbeat_intervals) * 1000 if self.heartbeat_intervals else 0,
                "max": max(self.heartbeat_intervals) * 1000 if self.heartbeat_intervals else 0,
                "mean": statistics.mean(self.heartbeat_intervals) * 1000 if self.heartbeat_intervals else 0,
                "median": statistics.median(self.heartbeat_intervals) * 1000 if self.heartbeat_intervals else 0,
                "stdev": statistics.stdev(self.heartbeat_intervals) * 1000 if len(self.heartbeat_intervals) > 1 else 0,
            },
            "message_type_distribution": {
                XRCE_MSG_NAMES.get(msg_type, "UNKNOWN"): count
                for msg_type, count in self.message_type_counts.items()
            },
            "reliable_ratio": self.reliable_ratio,
            "stream_stats": self.stream_stats,
            "session_stats": self.session_stats,
        }


# ============================================================================
# XRCE Packet Parser (minimal, reused from Module 1)
# ============================================================================

class XRCEPacketParser:
    """Parse XRCE wire format packets"""

    @staticmethod
    def parse_header(data: bytes) -> Optional[Dict]:
        """Parse XRCE PRO header (8 bytes)"""
        if len(data) < 8:
            return None

        magic = struct.unpack("<I", data[0:4])[0]
        if magic != XRCE_MAGIC:
            return None

        flags = data[4]
        session_id = data[5]
        stream_id = struct.unpack("<H", data[6:8])[0]

        return {
            "magic": magic,
            "flags": flags,
            "session_id": session_id,
            "stream_id": stream_id,
            "header_len": 8,
        }

    @staticmethod
    def parse_submessage(data: bytes, offset: int = 8) -> Optional[Dict]:
        """Parse XRCE submessage (follows PRO header)"""
        if len(data) < offset + 4:
            return None

        msg_byte = data[offset]
        message_id = (msg_byte >> 4) & 0x0F
        flags = msg_byte & 0x0F
        length = struct.unpack("<H", data[offset + 2:offset + 4])[0]

        payload_start = offset + 4
        payload_end = payload_start + length

        if payload_end > len(data):
            return None

        payload = data[payload_start:payload_end]

        return {
            "message_id": message_id,
            "flags": flags,
            "length": length,
            "payload": payload,
            "total_size": 4 + length,
        }


# ============================================================================
# Traffic Capture & Analysis
# ============================================================================

class XRCETrafficAnalyzer:
    """Capture and analyze XRCE traffic for behavioral baselining"""

    def __init__(self, agent_ip: str, agent_port: int, verbose: bool = False):
        self.agent_ip = agent_ip
        self.agent_port = agent_port
        self.verbose = verbose
        
        self.packets: List[XRCEPacket] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        
        # Per-session/stream tracking
        self.sessions: Dict[int, Dict] = defaultdict(lambda: {
            "first_seen": None,
            "last_seen": None,
            "packet_count": 0,
            "byte_count": 0,
        })
        self.streams: Dict[int, Dict] = defaultdict(lambda: {
            "first_seen": None,
            "last_seen": None,
            "packet_count": 0,
            "byte_count": 0,
            "message_types": defaultdict(int),
        })

    def capture(self, duration: float = 30.0, bind_ip: str = "0.0.0.0") -> int:
        """
        Capture XRCE traffic for specified duration
        
        Args:
            duration: Capture time in seconds
            bind_ip: IP to bind listener on (default: 0.0.0.0)
        
        Returns count of packets captured
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((bind_ip, self.agent_port))
        sock.settimeout(1.0)  # Non-blocking with 1s timeout

        self.start_time = time.time()
        end_time = self.start_time + duration

        if self.verbose:
            print(f"[*] Listening on {bind_ip}:{self.agent_port} for {duration}s...")

        while time.time() < end_time:
            try:
                data, (src_ip, src_port) = sock.recvfrom(65535)
                self._process_packet(data, src_ip, src_port)
            except socket.timeout:
                continue
            except Exception as e:
                if self.verbose:
                    print(f"[!] Error capturing packet: {e}")
                continue

        self.end_time = time.time()
        sock.close()

        if self.verbose:
            print(f"[+] Captured {len(self.packets)} packets in {self.end_time - self.start_time:.2f}s")

        return len(self.packets)

    def _process_packet(self, data: bytes, src_ip: str, src_port: int):
        """Process a single captured packet"""
        # Parse header
        header = XRCEPacketParser.parse_header(data)
        if not header:
            return

        session_id = header['session_id']
        stream_id = header['stream_id']

        # Parse submessage
        submsg = XRCEPacketParser.parse_submessage(data)
        if not submsg:
            return

        message_type = submsg['message_id']
        payload_size = submsg['length']

        # Determine if reliable (WRITE with ACKN flag)
        is_reliable = (message_type == XRCE_MSG_WRITE) and (submsg['flags'] & 0x01)

        # Create packet record
        packet = XRCEPacket(
            timestamp=time.time(),
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=self.agent_ip,
            dst_port=self.agent_port,
            size=len(data),
            session_id=session_id,
            stream_id=stream_id,
            message_type=message_type,
            payload_size=payload_size,
            is_reliable=is_reliable,
        )

        self.packets.append(packet)

        # Update session/stream tracking
        now = time.time()
        self.sessions[session_id]["last_seen"] = now
        if self.sessions[session_id]["first_seen"] is None:
            self.sessions[session_id]["first_seen"] = now
        self.sessions[session_id]["packet_count"] += 1
        self.sessions[session_id]["byte_count"] += len(data)

        self.streams[stream_id]["last_seen"] = now
        if self.streams[stream_id]["first_seen"] is None:
            self.streams[stream_id]["first_seen"] = now
        self.streams[stream_id]["packet_count"] += 1
        self.streams[stream_id]["byte_count"] += len(data)
        self.streams[stream_id]["message_types"][message_type] += 1

        if self.verbose:
            msg_name = XRCE_MSG_NAMES.get(message_type, "UNKNOWN")
            print(f"[+] {src_ip}:{src_port} | Session={session_id:02x} Stream={stream_id:04x} | {msg_name} | Size={len(data)}")

    def analyze(self) -> TrafficStatistics:
        """
        Analyze captured traffic and generate statistics
        
        Returns TrafficStatistics object
        """
        if not self.packets:
            return TrafficStatistics(
                capture_duration=0,
                packet_count=0,
                byte_count=0,
                unique_sessions=0,
                unique_streams=0,
            )

        # Basic stats
        duration = self.end_time - self.start_time if (self.start_time and self.end_time) else 0
        packet_count = len(self.packets)
        byte_count = sum(p.size for p in self.packets)
        unique_sessions = len(self.sessions)
        unique_streams = len(self.streams)

        # Size distributions
        packet_sizes = [p.size for p in self.packets]
        payload_sizes = [p.payload_size for p in self.packets]

        # Timing distributions
        inter_packet_intervals = []
        for i in range(1, len(self.packets)):
            delta = self.packets[i].timestamp - self.packets[i-1].timestamp
            if delta > 0:
                inter_packet_intervals.append(delta)

        heartbeat_intervals = []
        heartbeat_packets = [p for p in self.packets if p.message_type == XRCE_MSG_HEARTBEAT]
        for i in range(1, len(heartbeat_packets)):
            delta = heartbeat_packets[i].timestamp - heartbeat_packets[i-1].timestamp
            if delta > 0:
                heartbeat_intervals.append(delta)

        # Message type distribution
        message_type_counts = defaultdict(int)
        for p in self.packets:
            message_type_counts[p.message_type] += 1

        # QoS ratio
        reliable_count = sum(1 for p in self.packets if p.is_reliable)
        reliable_ratio = reliable_count / packet_count if packet_count > 0 else 0

        # Per-stream stats
        stream_stats = {
            sid: {
                "packet_count": data["packet_count"],
                "byte_count": data["byte_count"],
                "message_types": dict(data["message_types"]),
                "duration": data["last_seen"] - data["first_seen"] if (data["first_seen"] and data["last_seen"]) else 0,
            }
            for sid, data in self.streams.items()
        }

        # Per-session stats
        session_stats = {
            sid: {
                "packet_count": data["packet_count"],
                "byte_count": data["byte_count"],
                "duration": data["last_seen"] - data["first_seen"] if (data["first_seen"] and data["last_seen"]) else 0,
            }
            for sid, data in self.sessions.items()
        }

        stats = TrafficStatistics(
            capture_duration=duration,
            packet_count=packet_count,
            byte_count=byte_count,
            unique_sessions=unique_sessions,
            unique_streams=unique_streams,
            packet_sizes=packet_sizes,
            payload_sizes=payload_sizes,
            inter_packet_intervals=inter_packet_intervals,
            heartbeat_intervals=heartbeat_intervals,
            message_type_counts=dict(message_type_counts),
            reliable_ratio=reliable_ratio,
            stream_stats=stream_stats,
            session_stats=session_stats,
        )

        return stats

    def export_pcap(self, output_file: str) -> bool:
        """
        Export captured packets to PCAP format (for Wireshark, tcpdump)
        
        Returns True if successful
        """
        try:
            import struct as pstruct
            
            # PCAP global header
            pcap_magic = 0xa1b2c3d4
            version_major = 2
            version_minor = 4
            thiszone = 0
            sigfigs = 0
            snaplen = 65535
            network = 17  # IPPROTO_UDP
            
            global_header = pstruct.pack(
                "<IHHIIII",
                pcap_magic,
                version_major,
                version_minor,
                thiszone,
                sigfigs,
                snaplen,
                network,
            )
            
            with open(output_file, 'wb') as f:
                f.write(global_header)
                
                # PCAP packet records (simplified — UDP-only)
                for pkt in self.packets:
                    # Packet header
                    ts_sec = int(pkt.timestamp)
                    ts_usec = int((pkt.timestamp - ts_sec) * 1e6)
                    incl_len = 8 + 20 + 8  # UDP + IP headers (approx)
                    orig_len = incl_len
                    
                    pkt_header = pstruct.pack(
                        "<IIII",
                        ts_sec,
                        ts_usec,
                        incl_len,
                        orig_len,
                    )
                    f.write(pkt_header)
            
            return True
        except Exception as e:
            print(f"[!] PCAP export failed: {e}")
            return False


# ============================================================================
# Reporting
# ============================================================================

def print_analysis_report(stats: TrafficStatistics):
    """Pretty-print traffic analysis results"""
    print("\n" + "="*70)
    print("XRCE TRAFFIC ANALYSIS REPORT".center(70))
    print("="*70 + "\n")

    print(f"Capture Duration:       {stats.capture_duration:.2f}s")
    print(f"Total Packets:          {stats.packet_count}")
    print(f"Total Bytes:            {stats.byte_count:,}")
    print(f"Throughput:             {stats.byte_count / stats.capture_duration / 1024:.2f} KB/s")
    print(f"Unique Sessions:        {stats.unique_sessions}")
    print(f"Unique Streams:         {stats.unique_streams}")
    print()

    print("PACKET SIZE DISTRIBUTION:")
    print(f"  Min:        {min(stats.packet_sizes) if stats.packet_sizes else 'N/A'} bytes")
    print(f"  Max:        {max(stats.packet_sizes) if stats.packet_sizes else 'N/A'} bytes")
    print(f"  Mean:       {statistics.mean(stats.packet_sizes):.1f} bytes")
    print(f"  Median:     {statistics.median(stats.packet_sizes):.1f} bytes")
    print()

    print("PAYLOAD SIZE DISTRIBUTION:")
    print(f"  Min:        {min(stats.payload_sizes) if stats.payload_sizes else 'N/A'} bytes")
    print(f"  Max:        {max(stats.payload_sizes) if stats.payload_sizes else 'N/A'} bytes")
    print(f"  Mean:       {statistics.mean(stats.payload_sizes):.1f} bytes")
    print(f"  Median:     {statistics.median(stats.payload_sizes):.1f} bytes")
    print()

    print("INTER-PACKET TIMING (milliseconds):")
    if stats.inter_packet_intervals:
        print(f"  Min:        {min(stats.inter_packet_intervals)*1000:.2f}ms")
        print(f"  Max:        {max(stats.inter_packet_intervals)*1000:.2f}ms")
        print(f"  Mean:       {statistics.mean(stats.inter_packet_intervals)*1000:.2f}ms")
        print(f"  Median:     {statistics.median(stats.inter_packet_intervals)*1000:.2f}ms")
    print()

    print("HEARTBEAT TIMING (milliseconds):")
    if stats.heartbeat_intervals:
        print(f"  Min:        {min(stats.heartbeat_intervals)*1000:.2f}ms")
        print(f"  Max:        {max(stats.heartbeat_intervals)*1000:.2f}ms")
        print(f"  Mean:       {statistics.mean(stats.heartbeat_intervals)*1000:.2f}ms")
        print(f"  Median:     {statistics.median(stats.heartbeat_intervals)*1000:.2f}ms")
    print()

    print("MESSAGE TYPE DISTRIBUTION:")
    for msg_type, count in sorted(stats.message_type_counts.items()):
        msg_name = XRCE_MSG_NAMES.get(msg_type, "UNKNOWN")
        pct = (count / stats.packet_count * 100) if stats.packet_count > 0 else 0
        print(f"  {msg_name:15} {count:5} ({pct:5.1f}%)")
    print()

    print(f"QoS Reliable Ratio:     {stats.reliable_ratio*100:.1f}%")
    print("="*70 + "\n")


def export_json(stats: TrafficStatistics, output_file: str):
    """Export analysis to JSON"""
    output = {
        "module": "xrce_traffic_analysis",
        "timestamp": datetime.now().isoformat(),
        "statistics": stats.to_dict(),
    }

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"[+] Analysis exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 5A Module 2: XRCE Traffic Analysis & Behavioral Profiling"
    )
    parser.add_argument(
        "--agent-ip",
        required=True,
        help="XRCE Agent IP address (where to listen for traffic)"
    )
    parser.add_argument(
        "--agent-port",
        type=int,
        default=8888,
        help="XRCE Agent port (default: 8888)"
    )
    parser.add_argument(
        "-d", "--duration",
        type=float,
        default=30.0,
        help="Capture duration in seconds (default: 30)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file for analysis results"
    )
    parser.add_argument(
        "--pcap",
        help="Export captured packets to PCAP file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="IP to bind listener on (default: 0.0.0.0)"
    )

    args = parser.parse_args()

    analyzer = XRCETrafficAnalyzer(
        agent_ip=args.agent_ip,
        agent_port=args.agent_port,
        verbose=args.verbose,
    )

    # Capture traffic
    packet_count = analyzer.capture(duration=args.duration, bind_ip=args.bind)

    if packet_count == 0:
        print("[!] No XRCE traffic captured. Ensure clients are communicating with the agent.")
        return

    # Analyze
    stats = analyzer.analyze()

    # Report
    print_analysis_report(stats)

    # Export
    if args.output:
        export_json(stats, args.output)

    if args.pcap:
        if analyzer.export_pcap(args.pcap):
            print(f"[+] PCAP exported to {args.pcap}")


if __name__ == "__main__":
    main()
