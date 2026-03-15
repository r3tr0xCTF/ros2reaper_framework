#!/usr/bin/env python3
"""
ros1_master.py — ROS1 Master XML-RPC Client
============================================
Thin wrapper around Python's xmlrpc.client for the rosmaster API.
Provides unauthenticated access to node graph, topic info, services,
and the parameter server — all reachable on port 11311 by default.

ROS Master API reference:
  http://wiki.ros.org/ROS/Master_API
  http://wiki.ros.org/ROS/Parameter%20Server%20API

Author: Gh057x
"""

import socket
import xmlrpc.client
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


ROS1_MASTER_PORT = 11311
_DEFAULT_CALLER = "/ros2reaper"


class ROS1MasterError(Exception):
    """Raised when a rosmaster API call fails"""


class ROS1MasterClient:
    """
    XML-RPC client for the ROS1 Master API.

    All rosmaster methods return (statusCode, statusMessage, value).
    statusCode == 1 indicates success.  This class unpacks those
    triples and raises ROS1MasterError on failure so callers don't
    have to check every status code.
    """

    def __init__(
        self,
        host: str,
        port: int = ROS1_MASTER_PORT,
        caller_id: str = _DEFAULT_CALLER,
        timeout: float = 5.0,
    ):
        self.host = host
        self.port = port
        self.caller_id = caller_id
        self.timeout = timeout
        self.uri = f"http://{host}:{port}/"
        # xmlrpc.client has no per-call timeout; wrap socket default
        socket.setdefaulttimeout(timeout)
        self._proxy = xmlrpc.client.ServerProxy(self.uri, allow_none=True)

    # ------------------------------------------------------------------
    # Connectivity
    # ------------------------------------------------------------------

    def is_reachable(self) -> bool:
        """Return True if rosmaster responds to a getPid probe."""
        try:
            code, _msg, _val = self._proxy.getPid(self.caller_id)
            return code == 1
        except Exception:
            return False

    def get_pid(self) -> Optional[int]:
        """Return the master process PID, or None on failure."""
        try:
            code, _msg, val = self._proxy.getPid(self.caller_id)
            return int(val) if code == 1 else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Graph discovery
    # ------------------------------------------------------------------

    def get_system_state(self) -> Tuple[List, List, List]:
        """
        Return the full ROS graph as three lists:
            publishers  — [[topic, [node, ...]], ...]
            subscribers — [[topic, [node, ...]], ...]
            services    — [[service, [node, ...]], ...]
        Raises ROS1MasterError on failure.
        """
        try:
            code, msg, val = self._proxy.getSystemState(self.caller_id)
        except Exception as exc:
            raise ROS1MasterError(f"getSystemState failed: {exc}") from exc
        if code != 1:
            raise ROS1MasterError(f"getSystemState error {code}: {msg}")
        publishers, subscribers, services = val
        return publishers, subscribers, services

    def get_published_topics(self, subgraph: str = "") -> List[Tuple[str, str]]:
        """
        Return [[topic_name, type_string], ...] for all published topics
        (optionally filtered by subgraph prefix).
        """
        try:
            code, _msg, val = self._proxy.getPublishedTopics(self.caller_id, subgraph)
            return [tuple(item) for item in val] if code == 1 else []
        except Exception:
            return []

    def get_topic_types(self) -> Dict[str, str]:
        """Return {topic_name: type_string} for all known topics."""
        try:
            code, _msg, val = self._proxy.getTopicTypes(self.caller_id)
            if code == 1:
                return {item[0]: item[1] for item in val}
        except Exception:
            pass
        return {}

    def lookup_node(self, node_name: str) -> Optional[str]:
        """Return the XMLRPC URI (http://host:port/) for a node, or None."""
        try:
            code, _msg, val = self._proxy.lookupNode(self.caller_id, node_name)
            return str(val) if code == 1 else None
        except Exception:
            return None

    def lookup_service(self, service: str) -> Optional[str]:
        """Return the ROSRPC URI for a service, or None."""
        try:
            code, _msg, val = self._proxy.lookupService(self.caller_id, service)
            return str(val) if code == 1 else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Parameter server
    # ------------------------------------------------------------------

    def get_param(self, key: str) -> Any:
        """Return a parameter value, or None if missing/error."""
        try:
            code, _msg, val = self._proxy.getParam(self.caller_id, key)
            return val if code == 1 else None
        except Exception:
            return None

    def get_param_names(self) -> List[str]:
        """Return a list of all parameter names on the server."""
        try:
            code, _msg, val = self._proxy.getParamNames(self.caller_id)
            return list(val) if code == 1 else []
        except Exception:
            return []

    def set_param(self, key: str, value: Any) -> bool:
        """Set a parameter value. Returns True on success."""
        try:
            code, _msg, _val = self._proxy.setParam(self.caller_id, key, value)
            return code == 1
        except Exception:
            return False

    def delete_param(self, key: str) -> bool:
        """Delete a parameter. Returns True on success."""
        try:
            code, _msg, _val = self._proxy.deleteParam(self.caller_id, key)
            return code == 1
        except Exception:
            return False

    def has_param(self, key: str) -> bool:
        """Return True if a parameter key exists."""
        try:
            code, _msg, val = self._proxy.hasParam(self.caller_id, key)
            return bool(val) if code == 1 else False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Publisher registration (needed before TCPROS injection)
    # ------------------------------------------------------------------

    def register_publisher(
        self, topic: str, topic_type: str, caller_api: str
    ) -> List[str]:
        """
        Register this node as a publisher for topic.
        caller_api is the XMLRPC URI this node is listening on
        (e.g. "http://attacker-ip:port/").
        Returns list of current subscriber URIs.
        """
        try:
            code, _msg, val = self._proxy.registerPublisher(
                self.caller_id, topic, topic_type, caller_api
            )
            return list(val) if code == 1 else []
        except Exception:
            return []

    def unregister_publisher(self, topic: str, caller_api: str) -> bool:
        """Unregister as a publisher. Returns True if removed."""
        try:
            code, _msg, val = self._proxy.unregisterPublisher(
                self.caller_id, topic, caller_api
            )
            return int(val) == 1 if code == 1 else False
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Remote node shutdown
    # ------------------------------------------------------------------

    def shutdown_node(self, node_uri: str, reason: str = "ros2reaper test") -> bool:
        """
        Call shutdown() directly on a node's XMLRPC API.
        node_uri is the http://host:port/ returned by lookup_node().
        Returns True if the node acknowledged the call.
        """
        try:
            socket.setdefaulttimeout(self.timeout)
            node_proxy = xmlrpc.client.ServerProxy(node_uri, allow_none=True)
            code, _msg, _val = node_proxy.shutdown(self.caller_id, reason)
            return code == 1
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_host_port(uri: str) -> Tuple[Optional[str], Optional[int]]:
        """Extract (host, port) from an http://host:port/ URI."""
        try:
            parsed = urlparse(uri)
            return parsed.hostname, parsed.port
        except Exception:
            return None, None
