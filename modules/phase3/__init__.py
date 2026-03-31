"""
ROS2Reaper Phase 3 — ICS/OT Bridge Modules
============================================

Modules:
    ics_dds_enum    — ICS/OT context-aware DDS enumeration (SCADA, ATC, AV, grid)
    shodan_dds      — Internet-wide DDS exposure scanning via Shodan API
    opcua_dds_bridge — OPC UA / DDS bridge attack surface analysis

All Phase 3 modules operate at the raw protocol layer with NO ROS 2 dependency.
"""

from .ics_dds_enum    import ICSDDSEnumerator, ICSContextClassifier, ICSContext
from .shodan_dds      import ShodanDDSScanner, ShodanScanResult
from .opcua_dds_bridge import OpcuaDDSBridgeScanner, BridgeAnalyzer, BRIDGE_ATTACK_SCENARIOS

__all__ = [
    "ICSDDSEnumerator",
    "ICSContextClassifier",
    "ICSContext",
    "ShodanDDSScanner",
    "ShodanScanResult",
    "OpcuaDDSBridgeScanner",
    "BridgeAnalyzer",
    "BRIDGE_ATTACK_SCENARIOS",
]
