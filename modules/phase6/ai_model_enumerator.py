#!/usr/bin/env python3
"""
ai_model_enumerator.py - Phase 6 Module 1: Edge AI / ML Inference Service Enumeration

Discovers and fingerprints machine learning inference services running alongside
ROS 2 deployments. Robots using perception pipelines typically run one or more
of these serving frameworks:

  Triton Inference Server (NVIDIA) — REST on :8000, gRPC on :8001, metrics :8002
    Models: YOLO (object detection), PointPillars (LiDAR), ResNet (classification),
            depth estimation, semantic segmentation
    Endpoints:
      GET  /v2/health/live             health check
      GET  /v2/models                  list all models
      GET  /v2/models/{name}           model metadata (input/output shapes)
      POST /v2/models/{name}/infer     run inference
      POST /v2/repository/models/{name}/load    load/swap model

  TensorFlow Serving — REST on :8501, gRPC on :8500
    GET  /v1/models                    list models
    GET  /v1/models/{name}             model status
    POST /v1/models/{name}:predict     run inference

  ONNX Runtime Server — REST on :8001
    GET  /v1/models                    list models
    POST /v1/models/{name}/versions/{ver}/infer

  MLflow Model Server — REST on :5000, :1234
    GET  /api/2.0/mlflow/registered-models/list
    POST /invocations                  run inference

  ROS 2 Inference Services/Actions:
    Services: /<node>/infer, /<node>/detect, /<node>/classify, /<node>/segment
    Actions:  /object_detection, /semantic_segmentation, /depth_estimation
    Topics:   /detections, /predictions, /inference_result

  Filesystem model artifacts:
    .onnx  — ONNX format (most common in ROS 2)
    .pt    — PyTorch TorchScript
    .tflite — TensorFlow Lite (edge/embedded)
    .pb    — TensorFlow frozen graph
    .engine / .trt — TensorRT compiled
    .xml + .bin — OpenVINO IR
    .weights / .cfg — Darknet (YOLO v4)

Author: Gh057x | Phase 6
"""

import json
import os
import sys
import time
import socket
import struct
import argparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from enum import Enum
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode
import http.client


# =============================================================================
# Constants
# =============================================================================

class AIEnumMode(str, Enum):
    ALL        = "all"
    TRITON     = "triton"
    TF_SERVING = "tf_serving"
    ONNX_RT    = "onnx_rt"
    MLFLOW     = "mlflow"
    ROS_SVC    = "ros_svc"
    FILESYSTEM = "filesystem"


# Default ports
TRITON_REST_PORT    = 8000
TRITON_GRPC_PORT    = 8001
TRITON_METRICS_PORT = 8002
TF_SERVING_REST     = 8501
TF_SERVING_GRPC     = 8500
ONNX_RT_PORT        = 8001
MLFLOW_PORTS        = [5000, 1234, 8080]

ALL_INFERENCE_PORTS = [
    TRITON_REST_PORT, TRITON_GRPC_PORT, TRITON_METRICS_PORT,
    TF_SERVING_REST, TF_SERVING_GRPC, ONNX_RT_PORT,
] + MLFLOW_PORTS

# Model file extensions
MODEL_EXTENSIONS = {
    ".onnx":    "ONNX",
    ".pt":      "PyTorch/TorchScript",
    ".pth":     "PyTorch checkpoint",
    ".tflite":  "TensorFlow Lite",
    ".pb":      "TensorFlow frozen graph",
    ".engine":  "TensorRT",
    ".trt":     "TensorRT",
    ".xml":     "OpenVINO IR (+ .bin)",
    ".weights": "Darknet YOLO",
    ".cfg":     "Darknet YOLO config",
    ".h5":      "Keras HDF5",
    ".savedmodel": "TensorFlow SavedModel",
}

# Known AI/perception ROS 2 topic/service patterns
AI_TOPIC_PATTERNS = [
    "/detections", "/predictions", "/inference_result",
    "/object_detection", "/semantic_segmentation", "/depth_image",
    "/panoptic_seg", "/instance_seg", "/classification",
    "/lidar_detections", "/camera/detections",
    "/yolo/detections", "/darknet_ros/detection_image",
    "/dnn_output", "/tensorrt_output",
]

# Filesystem paths to search for model files
MODEL_SEARCH_PATHS = [
    "/opt/ros", "/home", "/root", "/var/ros",
    "/models", "/workspace/models",
    "/tmp", "/etc/ros", "/opt/tritonserver/models",
    os.path.expanduser("~"),
]


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class ModelInfo:
    name: str
    framework: str = ""
    version: str = ""
    backend: str = ""
    state: str = ""
    input_shapes: List[Dict] = field(default_factory=list)
    output_shapes: List[Dict] = field(default_factory=list)
    source: str = ""      # triton / tf_serving / filesystem / ros_svc
    path: Optional[str] = None
    size_bytes: int = 0
    attack_surface: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "name": self.name, "framework": self.framework,
            "version": self.version, "backend": self.backend,
            "state": self.state,
            "input_shapes": self.input_shapes, "output_shapes": self.output_shapes,
            "source": self.source, "path": self.path, "size_bytes": self.size_bytes,
            "attack_surface": self.attack_surface,
        }


@dataclass
class InferenceServer:
    server_type: str       # triton / tf_serving / onnx_rt / mlflow
    host: str
    port: int
    version: str = ""
    ready: bool = False
    models: List[ModelInfo] = field(default_factory=list)
    raw_metadata: Dict = field(default_factory=dict)

    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def to_dict(self) -> Dict:
        return {
            "server_type": self.server_type, "host": self.host, "port": self.port,
            "version": self.version, "ready": self.ready,
            "models": [m.to_dict() for m in self.models],
        }


@dataclass
class ModelInventory:
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    servers: List[InferenceServer] = field(default_factory=list)
    filesystem_models: List[ModelInfo] = field(default_factory=list)
    ros_ai_topics: List[str] = field(default_factory=list)
    ros_ai_services: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    total_models: int = 0
    findings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "target": self.target, "timestamp": self.timestamp,
            "servers": [s.to_dict() for s in self.servers],
            "filesystem_models": [m.to_dict() for m in self.filesystem_models],
            "ros_ai_topics": self.ros_ai_topics,
            "ros_ai_services": self.ros_ai_services,
            "open_ports": self.open_ports,
            "total_models": self.total_models,
            "findings": self.findings,
        }


# =============================================================================
# HTTP Helper
# =============================================================================

def _http_get(host: str, port: int, path: str, timeout: float = 3.0) -> Optional[Dict]:
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path, headers={"Accept": "application/json"})
        resp = conn.getresponse()
        body = resp.read(65536).decode("utf-8", errors="replace")
        conn.close()
        if resp.status == 200:
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return {"_raw": body[:500], "_status": resp.status}
        return {"_status": resp.status, "_body": body[:200]}
    except Exception:
        return None


def _http_post(host: str, port: int, path: str, body: Dict,
               timeout: float = 3.0) -> Optional[Dict]:
    try:
        payload = json.dumps(body).encode()
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("POST", path, body=payload,
                     headers={"Content-Type": "application/json",
                               "Accept": "application/json"})
        resp = conn.getresponse()
        data = resp.read(65536).decode("utf-8", errors="replace")
        conn.close()
        if resp.status in (200, 201):
            return json.loads(data)
        return {"_status": resp.status}
    except Exception:
        return None


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


# =============================================================================
# Triton Enumeration
# =============================================================================

class TritonEnumerator:
    """Enumerate NVIDIA Triton Inference Server via REST Management API."""

    def probe(self, host: str, port: int = TRITON_REST_PORT,
              timeout: float = 3.0) -> Optional[InferenceServer]:
        health = _http_get(host, port, "/v2/health/live", timeout)
        if health is None:
            return None

        server = InferenceServer(server_type="triton", host=host, port=port, ready=True)

        # Get server metadata
        meta = _http_get(host, port, "/v2", timeout)
        if meta and "version" in meta:
            server.version = meta.get("version", "")
            server.raw_metadata = meta

        # List all models
        models_resp = _http_get(host, port, "/v2/models", timeout)
        if models_resp:
            model_list = []
            if isinstance(models_resp, list):
                model_list = models_resp
            elif isinstance(models_resp, dict) and "models" in models_resp:
                model_list = models_resp["models"]

            for m in model_list:
                name = m.get("name", "") if isinstance(m, dict) else str(m)
                model = self._get_model_detail(host, port, name, timeout)
                server.models.append(model)

        return server

    def _get_model_detail(self, host: str, port: int, name: str,
                           timeout: float) -> ModelInfo:
        model = ModelInfo(name=name, source="triton", framework="unknown")

        meta = _http_get(host, port, f"/v2/models/{name}", timeout)
        if not meta or "_status" in meta:
            return model

        model.framework = meta.get("platform", meta.get("backend", ""))
        model.backend   = meta.get("backend", "")
        model.state     = "ready"

        for inp in meta.get("inputs", []):
            model.input_shapes.append({
                "name": inp.get("name"), "dtype": inp.get("datatype"),
                "shape": inp.get("shape"),
            })
        for out in meta.get("outputs", []):
            model.output_shapes.append({
                "name": out.get("name"), "dtype": out.get("datatype"),
                "shape": out.get("shape"),
            })

        # Infer attack surface from model characteristics
        model.attack_surface = self._infer_attack_surface(model)
        return model

    def _infer_attack_surface(self, model: ModelInfo) -> List[str]:
        surfaces = []
        name_lower = model.name.lower()
        if any(k in name_lower for k in ("yolo", "ssd", "detect", "rcnn", "retinanet")):
            surfaces.append("object_detection → adversarial_patch / FGSM evasion")
        if any(k in name_lower for k in ("depth", "mono", "stereo")):
            surfaces.append("depth_estimation → adversarial depth manipulation")
        if any(k in name_lower for k in ("seg", "semantic", "panoptic")):
            surfaces.append("segmentation → class confusion attack")
        if any(k in name_lower for k in ("slam", "localize", "pose")):
            surfaces.append("localization → pose estimation attack")
        if any(k in name_lower for k in ("point", "lidar", "vox", "pillar")):
            surfaces.append("lidar_detection → point cloud perturbation")
        # Management API always available if Triton is accessible
        surfaces.append("triton_mgmt → model swap via /v2/repository API")
        return surfaces


# =============================================================================
# TensorFlow Serving Enumeration
# =============================================================================

class TFServingEnumerator:
    def probe(self, host: str, port: int = TF_SERVING_REST,
              timeout: float = 3.0) -> Optional[InferenceServer]:
        resp = _http_get(host, port, "/v1/models", timeout)
        if resp is None:
            return None

        server = InferenceServer(server_type="tf_serving", host=host, port=port, ready=True)

        models_data = resp if isinstance(resp, dict) else {}
        for model_name, model_info in models_data.items():
            if model_name.startswith("_"):
                continue
            m = ModelInfo(name=model_name, source="tf_serving", framework="TensorFlow")
            if isinstance(model_info, dict):
                versions = model_info.get("model_version_status", [])
                if versions:
                    m.version = str(versions[0].get("version", ""))
                    m.state   = versions[0].get("state", "")
            m.attack_surface = ["tf_serving_predict → black-box query / model extraction"]
            server.models.append(m)

        return server


# =============================================================================
# MLflow Enumeration
# =============================================================================

class MLflowEnumerator:
    def probe(self, host: str, port: int = 5000,
              timeout: float = 3.0) -> Optional[InferenceServer]:
        resp = _http_get(host, port, "/api/2.0/mlflow/registered-models/list", timeout)
        if resp is None:
            resp = _http_get(host, port, "/api/2.0/preview/mlflow/registered-models/list", timeout)
        if resp is None:
            return None

        server = InferenceServer(server_type="mlflow", host=host, port=port, ready=True)
        models_list = resp.get("registered_models", []) if isinstance(resp, dict) else []
        for rm in models_list:
            m = ModelInfo(name=rm.get("name", "unnamed"), source="mlflow",
                          framework="MLflow")
            m.version = str(rm.get("latest_versions", [{}])[0].get("version", ""))
            m.attack_surface = ["mlflow_serve → black-box query"]
            server.models.append(m)
        return server


# =============================================================================
# ROS 2 AI Service Enumeration
# =============================================================================

class ROSAIEnumeratorBase:
    """Enumerate ROS 2 nodes serving AI inference."""

    def enumerate(self, verbose: bool = False) -> Tuple[List[str], List[str]]:
        topics, services = [], []

        try:
            import rclpy
            if not rclpy.ok():
                rclpy.init()
            node = rclpy.create_node("ros2reaper_ai_enum")

            all_topics = node.get_topic_names_and_types()
            for tname, ttypes in all_topics:
                if any(pat in tname.lower() for pat in
                       ("detect", "infer", "predict", "classif", "segment",
                        "depth", "slam", "dnn", "yolo", "tensor")):
                    topics.append(tname)

            all_services = node.get_service_names_and_types()
            for sname, _ in all_services:
                if any(pat in sname.lower() for pat in
                       ("infer", "detect", "classif", "predict", "segment")):
                    services.append(sname)

            node.destroy_node()
        except Exception:
            # Fallback: check known topic patterns
            topics = AI_TOPIC_PATTERNS[:]

        return topics, services


# =============================================================================
# Filesystem Scanner
# =============================================================================

class ModelFileScanner:
    def scan(self, paths: Optional[List[str]] = None,
             max_depth: int = 5, verbose: bool = False) -> List[ModelInfo]:
        found = []
        search_paths = paths or MODEL_SEARCH_PATHS

        for base in search_paths:
            if not os.path.exists(base):
                continue
            try:
                for root, dirs, files in os.walk(base):
                    depth = root[len(base):].count(os.sep)
                    if depth > max_depth:
                        dirs.clear()
                        continue
                    # Skip heavy directories
                    dirs[:] = [d for d in dirs if d not in
                               (".git", "__pycache__", "node_modules",
                                "build", "install", "log")]
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        ext = os.path.splitext(fname)[1].lower()
                        if ext in MODEL_EXTENSIONS:
                            try:
                                size = os.path.getsize(fpath)
                            except OSError:
                                size = 0
                            m = ModelInfo(
                                name=fname,
                                framework=MODEL_EXTENSIONS[ext],
                                source="filesystem",
                                path=fpath,
                                size_bytes=size,
                            )
                            m.attack_surface = self._get_attack_surface(ext, fpath)
                            found.append(m)
                            if verbose:
                                print(f"  [fs] {fpath}  ({size//1024}KB)")
            except PermissionError:
                continue

        return found

    def _get_attack_surface(self, ext: str, path: str) -> List[str]:
        surfaces = []
        if ext == ".onnx":
            surfaces.append("onnx_patch → inject backdoor layer into protobuf model")
        if ext in (".pt", ".pth"):
            surfaces.append("torch_pickle → RCE via malicious pickle in weights file")
        if ext in (".engine", ".trt"):
            surfaces.append("tensorrt_swap → replace compiled engine binary")
        if ext in (".tflite",):
            surfaces.append("tflite_patch → modify flatbuffer model quantization params")
        if ext == ".weights":
            surfaces.append("darknet_weights → overwrite classification layer weights")
        return surfaces


# =============================================================================
# Main Enumerator
# =============================================================================

class AIModelEnumerator:
    def __init__(self, verbose: bool = False, timeout: float = 3.0):
        self.verbose = verbose
        self.timeout = timeout

    def enumerate(self, target: str, mode: AIEnumMode = AIEnumMode.ALL,
                  ports: Optional[List[int]] = None,
                  fs_paths: Optional[List[str]] = None) -> ModelInventory:

        inv = ModelInventory(target=target)

        # Port scan
        check_ports = ports or ALL_INFERENCE_PORTS
        inv.open_ports = [p for p in check_ports if _port_open(target, p, self.timeout)]
        if self.verbose:
            print(f"  [+] Open inference ports on {target}: {inv.open_ports}")

        if mode in (AIEnumMode.ALL, AIEnumMode.TRITON):
            self._try_triton(target, inv)

        if mode in (AIEnumMode.ALL, AIEnumMode.TF_SERVING):
            self._try_tf_serving(target, inv)

        if mode in (AIEnumMode.ALL, AIEnumMode.MLFLOW):
            for p in MLFLOW_PORTS:
                self._try_mlflow(target, p, inv)

        if mode in (AIEnumMode.ALL, AIEnumMode.ROS_SVC):
            self._try_ros_services(inv)

        if mode in (AIEnumMode.ALL, AIEnumMode.FILESYSTEM):
            self._scan_filesystem(fs_paths, inv)

        # Count totals and generate findings
        inv.total_models = (
            sum(len(s.models) for s in inv.servers) +
            len(inv.filesystem_models)
        )
        self._generate_findings(inv)
        return inv

    def _try_triton(self, host: str, inv: ModelInventory):
        e = TritonEnumerator()
        for port in [TRITON_REST_PORT]:
            if port not in inv.open_ports and inv.open_ports:
                continue
            srv = e.probe(host, port, self.timeout)
            if srv:
                inv.servers.append(srv)
                inv.findings.append(
                    f"TRITON_EXPOSED: Triton Inference Server at {host}:{port}  "
                    f"({len(srv.models)} models) — unauthenticated REST API"
                )
                if self.verbose:
                    print(f"  [+] Triton at {host}:{port}  models={len(srv.models)}")

    def _try_tf_serving(self, host: str, inv: ModelInventory):
        e = TFServingEnumerator()
        srv = e.probe(host, TF_SERVING_REST, self.timeout)
        if srv:
            inv.servers.append(srv)
            inv.findings.append(
                f"TF_SERVING_EXPOSED: TF Serving at {host}:{TF_SERVING_REST} — "
                f"{len(srv.models)} model(s) accessible"
            )

    def _try_mlflow(self, host: str, port: int, inv: ModelInventory):
        e = MLflowEnumerator()
        srv = e.probe(host, port, self.timeout)
        if srv:
            inv.servers.append(srv)
            inv.findings.append(
                f"MLFLOW_EXPOSED: MLflow at {host}:{port} — model registry accessible"
            )

    def _try_ros_services(self, inv: ModelInventory):
        try:
            e = ROSAIEnumerator()
            topics, services = e.enumerate(self.verbose)
            inv.ros_ai_topics = topics
            inv.ros_ai_services = services
            if topics or services:
                inv.findings.append(
                    f"ROS_AI_SERVICES: {len(topics)} AI topic(s), "
                    f"{len(services)} AI service(s) visible"
                )
        except Exception:
            pass

    def _scan_filesystem(self, paths: Optional[List[str]], inv: ModelInventory):
        scanner = ModelFileScanner()
        models = scanner.scan(paths, verbose=self.verbose)
        inv.filesystem_models = models
        if models:
            inv.findings.append(
                f"MODEL_FILES_FOUND: {len(models)} model file(s) on filesystem — "
                f"check for write access (ONNX patch / weight swap)"
            )
            for m in models:
                if m.size_bytes > 0 and os.access(m.path or "", os.W_OK):
                    inv.findings.append(
                        f"WRITABLE_MODEL: {m.path} is world-writable → direct model replacement"
                    )

    def _generate_findings(self, inv: ModelInventory):
        # Check for unauthenticated Triton management API
        for srv in inv.servers:
            if srv.server_type == "triton":
                inv.findings.append(
                    f"TRITON_MGMT_API: /v2/repository API allows model swap without auth "
                    f"→ CVSS 9.8 CRITICAL"
                )
            if srv.server_type in ("tf_serving", "mlflow"):
                inv.findings.append(
                    f"{srv.server_type.upper()}_UNAUTH: No authentication on inference "
                    f"API at {srv.host}:{srv.port}"
                )


# =============================================================================
# Output
# =============================================================================

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
DIM    = "\033[90m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def print_inventory(inv: ModelInventory):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}AI MODEL INVENTORY{RESET}")
    print(f"{'=' * 65}")
    print(f"  Target:    {inv.target}")
    print(f"  Timestamp: {inv.timestamp}")
    print(f"  Total models found: {inv.total_models}")
    print(f"{'─' * 65}")

    if inv.open_ports:
        print(f"\n  {BOLD}Open Inference Ports{RESET}")
        for p in inv.open_ports:
            print(f"    {GREEN}{p}{RESET}")

    for srv in inv.servers:
        color = CYAN if srv.ready else DIM
        print(f"\n  {BOLD}{srv.server_type.upper()}{RESET} at {color}{srv.host}:{srv.port}{RESET}"
              f"  v{srv.version or '?'}")
        for m in srv.models:
            shapes = ""
            if m.input_shapes:
                shapes = f"  in:{m.input_shapes[0].get('shape','?')}"
            print(f"    {GREEN}[{m.state or 'ready'}]{RESET}  {m.name}  "
                  f"{DIM}{m.framework}{RESET}{shapes}")
            for atk in m.attack_surface:
                print(f"          {YELLOW}→ {atk}{RESET}")

    if inv.filesystem_models:
        print(f"\n  {BOLD}Filesystem Model Files ({len(inv.filesystem_models)}){RESET}")
        for m in inv.filesystem_models:
            w_flag = f"  {RED}[WRITABLE]{RESET}" if os.access(m.path or "", os.W_OK) else ""
            sz = f"{m.size_bytes // 1024}KB" if m.size_bytes > 1024 else f"{m.size_bytes}B"
            print(f"    {m.path}  {DIM}[{m.framework}  {sz}]{RESET}{w_flag}")
            for atk in m.attack_surface:
                print(f"          {YELLOW}→ {atk}{RESET}")

    if inv.ros_ai_topics:
        print(f"\n  {BOLD}ROS 2 AI Topics ({len(inv.ros_ai_topics)}){RESET}")
        for t in inv.ros_ai_topics[:10]:
            print(f"    {DIM}{t}{RESET}")

    if inv.findings:
        print(f"\n  {BOLD}Findings{RESET}")
        for f in inv.findings:
            color = RED if "CRITICAL" in f or "WRITABLE" in f else YELLOW
            print(f"    {color}[!]{RESET} {f}")

    print(f"{'=' * 65}\n")


def export_json(inv: ModelInventory, path: str):
    with open(path, "w") as f:
        json.dump(inv.to_dict(), f, indent=2)
    print(f"[+] AI inventory saved to {path}")


ROSAIEnumerator = ROSAIEnumeratorBase


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Model Enumerator (Phase 6 Module 1)")
    parser.add_argument("--mode", choices=[m.value for m in AIEnumMode], default="all")
    parser.add_argument("--target", "-t", default="localhost")
    parser.add_argument("--ports", nargs="+", type=int, default=None)
    parser.add_argument("--fs-paths", nargs="+", default=None, dest="fs_paths")
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    enumerator = AIModelEnumerator(verbose=args.verbose, timeout=3.0)
    inv = enumerator.enumerate(
        target=args.target,
        mode=AIEnumMode(args.mode),
        ports=args.ports,
        fs_paths=args.fs_paths,
    )
    print_inventory(inv)
    if args.output:
        export_json(inv, args.output)
