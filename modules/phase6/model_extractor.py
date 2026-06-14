#!/usr/bin/env python3
"""
model_extractor.py - Phase 6 Module 3: Black-Box AI Model Extraction

Extracts proprietary model information from deployed inference endpoints
without direct access to model weights. Targets Triton Inference Server,
TF Serving, and ROS 2 inference services.

Black-box model extraction enables:
  1. Architecture fingerprinting — identify model type (YOLO/SSD/ResNet/PointPillars)
     from output structure and confidence distribution patterns
  2. Decision boundary mapping — probe input space systematically to reconstruct
     the model's classification regions (enables adversarial example crafting
     without access to model weights)
  3. Training data inference — specific patterns in output confidence distributions
     reveal whether certain inputs were in the training set (membership inference)
  4. Timing side-channel — measure per-layer inference latency to estimate
     model depth, parameter count, and backend (TensorRT vs ONNX vs TF)
  5. Model stealing — reconstruct a substitute model from (query, response) pairs
     that approximates the original's decision boundaries

Why model extraction matters for robotic security:
  - Avoids the need for physical model file access (covered by model_poisoner.py)
  - Enables crafting transferable adversarial examples against the specific model
    version deployed, rather than generic ones
  - Reveals proprietary training data about the robot's operating environment
  - The substitute model can be white-box attacked, then adversarial examples
    transferred back to fool the original black-box model

Supported endpoints:
  - Triton Inference Server (REST :8000)
  - TensorFlow Serving (REST :8501)
  - Generic HTTP inference APIs
  - ROS 2 service-based inference (with rclpy)

Author: Gh057x | Phase 6
"""

import os
import sys
import json
import math
import time
import random
import struct
import argparse
import statistics
import http.client
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Callable
from datetime import datetime
from enum import Enum


# =============================================================================
# Constants
# =============================================================================

class ExtractMode(str, Enum):
    PROBE       = "probe"        # collect (input, output) pairs
    FINGERPRINT = "fingerprint"  # identify model architecture
    TIMING      = "timing"       # latency side-channel
    MEMBERSHIP  = "membership"   # membership inference attack
    RECONSTRUCT = "reconstruct"  # substitute model estimation
    FULL        = "full"         # all of the above


# Known inference output signatures
MODEL_SIGNATURES = {
    "yolov5": {
        "output_dims": (1, None, 85),   # (batch, anchors, 5+80classes)
        "description": "YOLOv5 object detector",
        "num_classes": 80,
    },
    "yolov8": {
        "output_dims": (1, 84, None),   # (batch, 4+80classes, anchors)
        "description": "YOLOv8 object detector",
        "num_classes": 80,
    },
    "ssd_mobilenet": {
        "output_count": 4,  # boxes, classes, scores, count
        "description": "SSD MobileNet v2",
    },
    "resnet50": {
        "output_dims": (1, 1000),
        "description": "ResNet-50 ImageNet classifier",
        "num_classes": 1000,
    },
    "pointpillars": {
        "output_dims": (1, None, 7),  # (batch, objects, 7-DOF box)
        "description": "PointPillars LiDAR 3D detector",
    },
    "depth_anything": {
        "output_dims": (1, 1, None, None),  # (batch, 1, H, W)
        "description": "Monocular depth estimation",
    },
}

# Triton metadata field to model type mapping
BACKEND_ARCHITECTURES = {
    "tensorrt_plan": "TensorRT compiled",
    "onnxruntime_onnx": "ONNX Runtime",
    "tensorflow_graphdef": "TensorFlow GraphDef",
    "tensorflow_savedmodel": "TensorFlow SavedModel",
    "pytorch_libtorch": "PyTorch LibTorch",
    "openvino": "OpenVINO",
}


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class QuerySample:
    input_summary: str   # description of input used
    output_raw: Any      # raw model response
    latency_ms: float
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        out = self.output_raw
        if hasattr(out, "__len__") and len(str(out)) > 200:
            out = str(out)[:200] + "..."
        return {
            "input_summary": self.input_summary,
            "output_raw": out,
            "latency_ms": round(self.latency_ms, 2),
        }


@dataclass
class ModelFingerprint:
    model_name: str
    server_type: str
    host: str
    port: int
    architecture_guess: str = ""
    backend: str = ""
    input_shapes: List[Dict] = field(default_factory=list)
    output_shapes: List[Dict] = field(default_factory=list)
    num_outputs: int = 0
    num_classes: int = 0
    avg_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    estimated_params_M: float = 0.0
    confidence_distribution: Dict[str, float] = field(default_factory=dict)
    timing_profile: Dict[str, float] = field(default_factory=dict)
    membership_signals: List[str] = field(default_factory=list)
    queries_used: int = 0
    attack_recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "model_name": self.model_name, "server_type": self.server_type,
            "host": self.host, "port": self.port,
            "architecture_guess": self.architecture_guess, "backend": self.backend,
            "input_shapes": self.input_shapes, "output_shapes": self.output_shapes,
            "num_outputs": self.num_outputs, "num_classes": self.num_classes,
            "avg_latency_ms": self.avg_latency_ms, "p99_latency_ms": self.p99_latency_ms,
            "estimated_params_M": self.estimated_params_M,
            "confidence_distribution": self.confidence_distribution,
            "timing_profile": self.timing_profile,
            "membership_signals": self.membership_signals,
            "queries_used": self.queries_used,
            "attack_recommendations": self.attack_recommendations,
        }


@dataclass
class ExtractionResult:
    mode: str
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    fingerprints: List[ModelFingerprint] = field(default_factory=list)
    query_samples: List[QuerySample] = field(default_factory=list)
    total_queries: int = 0
    findings: List[str] = field(default_factory=list)
    success: bool = False

    def to_dict(self) -> Dict:
        return {
            "mode": self.mode, "target": self.target, "timestamp": self.timestamp,
            "fingerprints": [f.to_dict() for f in self.fingerprints],
            "query_samples": [s.to_dict() for s in self.query_samples[:20]],
            "total_queries": self.total_queries,
            "findings": self.findings, "success": self.success,
        }


# =============================================================================
# Inference Client
# =============================================================================

class InferenceClient:
    """Generic HTTP inference client — handles Triton and TF Serving."""

    def __init__(self, host: str, port: int, server_type: str = "triton",
                 model_name: str = "", timeout: float = 5.0):
        self.host        = host
        self.port        = port
        self.server_type = server_type
        self.model_name  = model_name
        self.timeout     = timeout
        self._query_count = 0

    def _make_input(self, shape: List[int], dtype: str = "FP32") -> Dict:
        """Generate a random or structured input tensor."""
        total = 1
        for dim in shape:
            if dim > 0:
                total *= min(dim, 1024)

        try:
            import numpy as np
            if "INT" in dtype:
                data = np.random.randint(0, 255, total, dtype=np.int32).tolist()
            else:
                data = np.random.randn(total).astype(np.float32).tolist()
        except ImportError:
            if "INT" in dtype:
                data = [random.randint(0, 255) for _ in range(total)]
            else:
                data = [random.gauss(0, 1) for _ in range(total)]

        return {
            "name": "input",
            "shape": [1] + [min(d, 1024) if d > 0 else 1 for d in shape],
            "datatype": dtype,
            "data": data,
        }

    def query_triton(self, model_name: str, input_data: Optional[Dict] = None) -> Tuple[Optional[Dict], float]:
        """Run one Triton inference query. Returns (response, latency_ms)."""
        if input_data is None:
            meta = self._get_model_meta_triton(model_name)
            if meta:
                inputs_meta = meta.get("inputs", [{"shape": [3, 224, 224], "datatype": "FP32"}])
                inp = inputs_meta[0]
                input_data = self._make_input(
                    inp.get("shape", [3, 224, 224]),
                    inp.get("datatype", "FP32")
                )
            else:
                input_data = self._make_input([3, 224, 224])

        payload = {"inputs": [input_data]}
        t0 = time.perf_counter()
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            body = json.dumps(payload).encode()
            conn.request("POST", f"/v2/models/{model_name}/infer", body=body,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read(131072)
            latency_ms = (time.perf_counter() - t0) * 1000
            conn.close()
            self._query_count += 1
            return json.loads(data), latency_ms
        except Exception:
            latency_ms = (time.perf_counter() - t0) * 1000
            return None, latency_ms

    def query_tf_serving(self, model_name: str, input_data: Optional[List] = None) -> Tuple[Optional[Dict], float]:
        payload = {"instances": [input_data or [random.random() for _ in range(224 * 224 * 3)]]}
        t0 = time.perf_counter()
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            body = json.dumps(payload).encode()
            conn.request("POST", f"/v1/models/{model_name}:predict", body=body,
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            data = resp.read(131072)
            latency_ms = (time.perf_counter() - t0) * 1000
            conn.close()
            self._query_count += 1
            return json.loads(data), latency_ms
        except Exception:
            return None, (time.perf_counter() - t0) * 1000

    def _get_model_meta_triton(self, model_name: str) -> Optional[Dict]:
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            conn.request("GET", f"/v2/models/{model_name}")
            resp = conn.getresponse()
            data = resp.read(65536)
            conn.close()
            return json.loads(data)
        except Exception:
            return None

    @property
    def query_count(self) -> int:
        return self._query_count


# =============================================================================
# Fingerprinting Engine
# =============================================================================

class ModelFingerprintEngine:

    def fingerprint_triton(self, host: str, port: int, model_name: str,
                            num_queries: int = 20,
                            timeout: float = 5.0) -> ModelFingerprint:
        fp = ModelFingerprint(
            model_name=model_name, server_type="triton",
            host=host, port=port,
        )
        client = InferenceClient(host, port, "triton", model_name, timeout)

        # Get metadata
        meta = client._get_model_meta_triton(model_name)
        if meta:
            fp.backend = BACKEND_ARCHITECTURES.get(meta.get("backend", ""), meta.get("backend", ""))
            for inp in meta.get("inputs", []):
                fp.input_shapes.append({"name": inp.get("name"), "shape": inp.get("shape"),
                                         "dtype": inp.get("datatype")})
            for out in meta.get("outputs", []):
                fp.output_shapes.append({"name": out.get("name"), "shape": out.get("shape"),
                                          "dtype": out.get("datatype")})

        # Probe with structured inputs
        latencies = []
        confidence_buckets = {f"c{i}": 0 for i in range(10)}
        output_sizes = []

        for i in range(num_queries):
            resp, lat = client.query_triton(model_name)
            latencies.append(lat)
            if resp and "outputs" in resp:
                outputs = resp["outputs"]
                fp.num_outputs = len(outputs)
                for out in outputs:
                    data = out.get("data", [])
                    if data:
                        output_sizes.append(len(data))
                        # Bucket confidence distribution
                        for val in data[:100]:
                            try:
                                bucket = min(9, int(float(val) * 10))
                                bucket_key = f"c{bucket}"
                                confidence_buckets[bucket_key] = \
                                    confidence_buckets.get(bucket_key, 0) + 1
                            except (ValueError, TypeError):
                                pass

        fp.queries_used = client.query_count

        if latencies:
            fp.avg_latency_ms = round(statistics.mean(latencies), 2)
            latencies.sort()
            fp.p99_latency_ms = round(latencies[int(len(latencies) * 0.99)], 2)

        if output_sizes:
            fp.num_classes = output_sizes[0] if output_sizes else 0

        total_conf = sum(confidence_buckets.values())
        if total_conf > 0:
            fp.confidence_distribution = {k: round(v / total_conf, 3)
                                           for k, v in confidence_buckets.items()}

        fp.architecture_guess = self._guess_architecture(fp)
        fp.estimated_params_M = self._estimate_params(fp)
        fp.attack_recommendations = self._attack_recommendations(fp)

        return fp

    def fingerprint_tf_serving(self, host: str, port: int, model_name: str,
                                 num_queries: int = 10, timeout: float = 5.0) -> ModelFingerprint:
        fp = ModelFingerprint(
            model_name=model_name, server_type="tf_serving",
            host=host, port=port, backend="TensorFlow Serving",
        )
        client = InferenceClient(host, port, "tf_serving", model_name, timeout)
        latencies = []

        for _ in range(num_queries):
            resp, lat = client.query_tf_serving(model_name)
            latencies.append(lat)
            if resp and "predictions" in resp:
                preds = resp["predictions"]
                if preds and isinstance(preds[0], list):
                    fp.num_classes = len(preds[0])

        fp.queries_used = client.query_count
        if latencies:
            fp.avg_latency_ms = round(statistics.mean(latencies), 2)

        fp.architecture_guess = self._guess_architecture(fp)
        fp.attack_recommendations = self._attack_recommendations(fp)
        return fp

    def _guess_architecture(self, fp: ModelFingerprint) -> str:
        name_l = fp.model_name.lower()

        for arch, sig in MODEL_SIGNATURES.items():
            if arch in name_l:
                return sig["description"]

        # Heuristics from output shape
        if fp.num_classes == 1000:
            return "ResNet/VGG/EfficientNet ImageNet classifier"
        if fp.num_classes == 80:
            return "COCO object detector (80 classes)"
        if fp.num_classes == 91:
            return "COCO object detector (91 classes)"

        # Latency heuristics
        if fp.avg_latency_ms < 5:
            return "Lightweight backbone (MobileNet/EfficientNet-S)"
        if fp.avg_latency_ms < 20:
            return "Medium CNN (ResNet-50 / YOLOv5s)"
        if fp.avg_latency_ms < 100:
            return "Large detector (YOLOv5m / SSD-ResNet50)"
        if fp.avg_latency_ms > 100:
            return "Very large model (YOLOv5x / Deformable DETR)"

        return "Unknown architecture"

    def _estimate_params(self, fp: ModelFingerprint) -> float:
        """Estimate parameter count (millions) from latency."""
        lat = fp.avg_latency_ms
        if lat <= 0:
            return 0.0
        # Empirical: 1M params ≈ 0.1ms on V100 TensorRT, 0.5ms on CPU
        is_gpu = "tensorrt" in fp.backend.lower() or lat < 50
        params = lat / 0.1 if is_gpu else lat / 0.5
        return round(min(params, 1000), 1)

    def _attack_recommendations(self, fp: ModelFingerprint) -> List[str]:
        recs = []
        arch = fp.architecture_guess.lower()

        if "yolo" in arch or "ssd" in arch or "detector" in arch:
            recs.append("FGSM/PGD evasion: perturb input to cause missed detections")
            recs.append("Adversarial patch: print physical patch to blind detector area")
        if "classifier" in arch or "resnet" in arch or "efficient" in arch:
            recs.append("Class confusion: perturb input to mis-classify scene context")
        if "depth" in arch or "mono" in arch:
            recs.append("Depth manipulation: alter input to cause erroneous distance estimation")
        if "point" in arch or "lidar" in arch or "pillar" in arch:
            recs.append("Point cloud perturbation: add phantom LiDAR returns to 3D space")
        if fp.avg_latency_ms > 0:
            recs.append(f"Timing DoS: {fp.avg_latency_ms:.1f}ms/query → "
                         f"flood with queries to saturate inference pipeline")
        if fp.server_type == "triton":
            recs.append("Triton swap: replace model via management API (ai-poison --mode triton_swap)")

        return recs


# =============================================================================
# Timing Side-Channel
# =============================================================================

class TimingSideChannel:
    """
    Measure per-input-complexity latency to fingerprint model architecture.
    Different model types respond differently to input complexity:
    - Object detectors: latency ∝ number of bounding box proposals
    - Depth models: latency ∝ image resolution (quadratic)
    - Classifiers: nearly constant latency regardless of content
    """

    def profile(self, client: InferenceClient, model_name: str,
                 samples_per_test: int = 5) -> Dict[str, float]:
        profile = {}

        # Test 1: All-zeros input
        t0 = time.perf_counter()
        for _ in range(samples_per_test):
            client.query_triton(model_name,
                                 {"name": "input", "shape": [1, 3, 224, 224],
                                  "datatype": "FP32", "data": [0.0] * (3 * 224 * 224)})
        profile["zeros_ms"] = round((time.perf_counter() - t0) * 1000 / samples_per_test, 2)

        # Test 2: All-ones input (max activation)
        t0 = time.perf_counter()
        for _ in range(samples_per_test):
            client.query_triton(model_name,
                                 {"name": "input", "shape": [1, 3, 224, 224],
                                  "datatype": "FP32", "data": [1.0] * (3 * 224 * 224)})
        profile["ones_ms"] = round((time.perf_counter() - t0) * 1000 / samples_per_test, 2)

        # Test 3: Random noise
        t0 = time.perf_counter()
        for _ in range(samples_per_test):
            client.query_triton(model_name)
        profile["noise_ms"] = round((time.perf_counter() - t0) * 1000 / samples_per_test, 2)

        # Analysis
        spread = abs(profile.get("ones_ms", 0) - profile.get("zeros_ms", 0))
        if spread < 1.0:
            profile["_inference_type"] = "classifier (constant latency)"
        elif spread > 5.0:
            profile["_inference_type"] = "detector (content-dependent — likely YOLO/SSD)"
        else:
            profile["_inference_type"] = "unknown / regression model"

        return profile


# =============================================================================
# Membership Inference Attack
# =============================================================================

class MembershipInferenceAttack:
    """
    Determine if specific images were part of the training data.
    Training samples typically produce:
      - Higher confidence on the correct class
      - Lower entropy in the output distribution
      - Slightly lower loss values
    """

    def probe(self, client: InferenceClient, model_name: str,
               candidate_inputs: List[Any]) -> List[str]:
        signals = []

        for i, inp in enumerate(candidate_inputs):
            resp, lat = client.query_triton(model_name,
                                             {"name": "input", "shape": [1, 3, 224, 224],
                                              "datatype": "FP32",
                                              "data": inp[:3*224*224] if isinstance(inp, list)
                                                      else [0.5] * (3*224*224)})
            if resp and "outputs" in resp:
                out_data = resp["outputs"][0].get("data", [])
                if out_data:
                    # Compute entropy of output distribution
                    total = sum(abs(float(v)) for v in out_data) + 1e-8
                    probs = [abs(float(v)) / total for v in out_data]
                    entropy = -sum(p * math.log(p + 1e-12) for p in probs)
                    max_conf = max(probs)

                    # Low entropy + high confidence → likely training member
                    if entropy < 1.0 and max_conf > 0.9:
                        signals.append(
                            f"Input {i}: HIGH membership probability "
                            f"(entropy={entropy:.3f}, max_conf={max_conf:.3f})"
                        )

        return signals


# =============================================================================
# Main Extractor
# =============================================================================

class ModelExtractor:
    def __init__(self, verbose: bool = False, timeout: float = 5.0):
        self.verbose = verbose
        self.timeout = timeout

    def run(self, mode: ExtractMode, target: str,
             model_name: str = "",
             port: int = 8000, server_type: str = "triton",
             num_queries: int = 50) -> ExtractionResult:

        result = ExtractionResult(mode=mode.value, target=target)
        client = InferenceClient(target, port, server_type, model_name, self.timeout)
        engine = ModelFingerprintEngine()

        if server_type == "triton":
            # List models if none specified
            models = [model_name] if model_name else self._list_triton_models(target, port)
        elif server_type == "tf_serving":
            models = [model_name] if model_name else self._list_tf_models(target, port)
        else:
            models = [model_name] if model_name else []

        if not models:
            result.findings.append(f"[-] No models found on {target}:{port}")
            return result

        for mname in models[:5]:  # cap at 5 models
            if self.verbose:
                print(f"  [*] Extracting: {mname}")

            if mode in (ExtractMode.FINGERPRINT, ExtractMode.FULL):
                if server_type == "triton":
                    fp = engine.fingerprint_triton(target, port, mname, num_queries, self.timeout)
                else:
                    fp = engine.fingerprint_tf_serving(target, port, mname, num_queries, self.timeout)
                result.fingerprints.append(fp)
                result.total_queries += fp.queries_used

            if mode in (ExtractMode.TIMING, ExtractMode.FULL):
                tc = TimingSideChannel()
                timing = tc.profile(client, mname)
                if result.fingerprints:
                    result.fingerprints[-1].timing_profile = timing
                result.total_queries += 15

            if mode in (ExtractMode.MEMBERSHIP, ExtractMode.FULL):
                mia = MembershipInferenceAttack()
                # Probe with synthetic patterns
                candidates = [[random.gauss(0.5, 0.1) for _ in range(3*224*224)] for _ in range(5)]
                signals = mia.probe(client, mname, candidates)
                if result.fingerprints:
                    result.fingerprints[-1].membership_signals = signals
                result.total_queries += 5

            if mode == ExtractMode.PROBE:
                for _ in range(min(num_queries, 20)):
                    resp, lat = client.query_triton(mname)
                    if resp:
                        result.query_samples.append(QuerySample(
                            input_summary=f"random_{len(result.query_samples)}",
                            output_raw=resp.get("outputs", [{}])[0].get("data", [])[:10],
                            latency_ms=lat,
                        ))
                result.total_queries += len(result.query_samples)

        for fp in result.fingerprints:
            result.findings.append(
                f"MODEL: {fp.model_name}  arch={fp.architecture_guess}  "
                f"backend={fp.backend}  lat={fp.avg_latency_ms}ms"
            )
            for rec in fp.attack_recommendations:
                result.findings.append(f"  ATTACK: {rec}")

        result.success = bool(result.fingerprints or result.query_samples)
        return result

    def _list_triton_models(self, host: str, port: int) -> List[str]:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            conn.request("GET", "/v2/models")
            resp = conn.getresponse()
            data = json.loads(resp.read(65536))
            conn.close()
            if isinstance(data, list):
                return [m.get("name", "") if isinstance(m, dict) else str(m) for m in data]
            if isinstance(data, dict) and "models" in data:
                return [m.get("name", "") for m in data["models"]]
        except Exception:
            pass
        return []

    def _list_tf_models(self, host: str, port: int) -> List[str]:
        try:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
            conn.request("GET", "/v1/models")
            resp = conn.getresponse()
            data = json.loads(resp.read(65536))
            conn.close()
            return list(data.keys()) if isinstance(data, dict) else []
        except Exception:
            return []


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


def print_extraction_report(result: ExtractionResult):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}MODEL EXTRACTION REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Mode:      {result.mode.upper()}")
    print(f"  Target:    {result.target}")
    print(f"  Queries:   {result.total_queries}")
    print(f"  Timestamp: {result.timestamp}")
    print(f"{'─' * 65}")

    for fp in result.fingerprints:
        print(f"\n  {BOLD}{fp.model_name}{RESET}  [{fp.server_type}  {fp.host}:{fp.port}]")
        print(f"    Architecture: {CYAN}{fp.architecture_guess}{RESET}")
        if fp.backend:
            print(f"    Backend:      {fp.backend}")
        if fp.avg_latency_ms:
            print(f"    Latency:      avg={fp.avg_latency_ms}ms  p99={fp.p99_latency_ms}ms")
        if fp.estimated_params_M:
            print(f"    Est. params:  ~{fp.estimated_params_M}M")
        if fp.num_classes:
            print(f"    Classes:      {fp.num_classes}")
        if fp.timing_profile:
            ti = fp.timing_profile.get("_inference_type", "")
            print(f"    Timing type:  {DIM}{ti}{RESET}")
        if fp.membership_signals:
            print(f"    {YELLOW}Membership signals: {len(fp.membership_signals)}{RESET}")
            for sig in fp.membership_signals:
                print(f"      {sig}")
        if fp.attack_recommendations:
            print(f"    {BOLD}Attack vectors:{RESET}")
            for rec in fp.attack_recommendations:
                print(f"      {RED}→{RESET} {rec}")

    if result.query_samples:
        print(f"\n  {BOLD}Sample Queries ({len(result.query_samples)}){RESET}")
        for s in result.query_samples[:5]:
            print(f"    lat={s.latency_ms:.1f}ms  out={DIM}{str(s.output_raw)[:60]}{RESET}")

    if result.findings:
        print(f"\n  {BOLD}Findings{RESET}")
        for f in result.findings:
            col = RED if "ATTACK" in f else DIM
            print(f"    {col}{f}{RESET}")

    sc = GREEN if result.success else RED
    print(f"\n  Status: {sc}{'SUCCESS' if result.success else 'FAILED'}{RESET}")
    print(f"{'=' * 65}\n")


def export_json(result: ExtractionResult, path: str):
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[+] Extraction results saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Model Extractor (Phase 6 Module 3)")
    parser.add_argument("--mode", choices=[m.value for m in ExtractMode], default="fingerprint")
    parser.add_argument("--target", "-t", required=True)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--server-type", choices=["triton", "tf_serving"],
                        default="triton", dest="server_type")
    parser.add_argument("--model", default="")
    parser.add_argument("--queries", type=int, default=50)
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    extractor = ModelExtractor(verbose=args.verbose, timeout=5.0)
    result = extractor.run(
        mode=ExtractMode(args.mode),
        target=args.target,
        model_name=args.model,
        port=args.port,
        server_type=args.server_type,
        num_queries=args.queries,
    )
    print_extraction_report(result)
    if args.output:
        export_json(result, args.output)
