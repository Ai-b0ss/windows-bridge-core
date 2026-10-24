from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
from contextlib import nullcontext
from pathlib import Path
import sys
import time
from typing import Any

import numpy as np
from PIL import Image
import torch
import importlib.util

def _load_batched_nms():
    try:
        spec = importlib.util.find_spec("torchvision")
        roots = list(spec.submodule_search_locations or ()) if spec is not None else []
        for root in roots:
            for extension in sorted(Path(root).glob("_C*.pyd")):
                try:
                    torch.ops.load_library(str(extension))
                    nms_op = torch.ops.torchvision.nms
                except Exception:
                    continue

                def _direct_batched_nms(boxes, scores, idxs, iou_threshold):
                    if boxes.numel() == 0:
                        return torch.empty((0,), dtype=torch.int64, device=boxes.device)
                    max_coordinate = boxes.max()
                    offsets = idxs.to(boxes) * (max_coordinate + torch.tensor(1).to(boxes))
                    return nms_op(boxes + offsets[:, None], scores, iou_threshold)

                return _direct_batched_nms, "TORCH_OPS_EXTENSION"
    except Exception:
        pass

    from torchvision.ops import batched_nms as fallback_batched_nms
    return fallback_batched_nms, "TORCHVISION_PYTHON"


batched_nms, NMS_BACKEND = _load_batched_nms()


ENGINE = "OMNIPARSER_YOLOV9E"


class DetectorError(RuntimeError):
    def __init__(self, code: str, details: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


class Detector:
    STRIDES = (8, 16, 32)

    def __init__(
        self, model_path: Path, expected_sha256: str, *,
        device: str, imgsz: int, confidence: float, iou: float, max_det: int,
    ):
        if device not in {"cpu", "cuda"}:
            raise DetectorError("VISUAL_DETECTOR_DEVICE_INVALID")
        if device == "cuda" and not torch.cuda.is_available():
            raise DetectorError("VISUAL_DETECTOR_CUDA_UNAVAILABLE")
        if imgsz != 640 or abs(confidence - 0.25) > 1e-9 or abs(iou - 0.10) > 1e-9:
            raise DetectorError("VISUAL_DETECTOR_CONFIG_INVALID")
        if not 1 <= max_det <= 128:
            raise DetectorError("VISUAL_DETECTOR_CONFIG_INVALID")
        digest = hashlib.sha256()
        with model_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise DetectorError("VISUAL_DETECTOR_MODEL_HASH_MISMATCH")
        self.model_sha256 = actual
        self.device = torch.device(device)
        if device == "cpu":
            torch.set_num_threads(min(4, max(1, __import__("os").cpu_count() or 1)))
        self.imgsz = imgsz
        self.confidence = confidence
        self.iou = iou
        self.max_det = max_det
        self.model = torch.jit.load(str(model_path), map_location=self.device).eval()

    def _decode(self, outputs):
        if not isinstance(outputs, (list, tuple)) or len(outputs) < 6:
            raise DetectorError("VISUAL_DETECTOR_MODEL_OUTPUT_INVALID")
        logits_all = []
        boxes_all = []
        for layer, stride in enumerate(self.STRIDES):
            logits = outputs[layer * 2]
            distances = outputs[layer * 2 + 1]
            if logits.ndim != 4 or distances.ndim != 4 or distances.shape[1] != 4:
                raise DetectorError("VISUAL_DETECTOR_MODEL_OUTPUT_INVALID")
            batch, channels, height, width = logits.shape
            logits = logits.permute(0, 2, 3, 1).reshape(batch, -1, channels)
            distances = distances.permute(0, 2, 3, 1).reshape(batch, -1, 4) * stride
            grid_y, grid_x = torch.meshgrid(
                torch.arange(height, device=self.device),
                torch.arange(width, device=self.device),
                indexing="ij",
            )
            anchors = (torch.stack((grid_x, grid_y), dim=-1).reshape(-1, 2) + 0.5) * stride
            left_top, right_bottom = distances.chunk(2, dim=-1)
            boxes_all.append(torch.cat((anchors - left_top, anchors + right_bottom), dim=-1))
            logits_all.append(logits)
        return torch.cat(logits_all, dim=1).sigmoid(), torch.cat(boxes_all, dim=1)

    def _preprocess(self, image: Image.Image):
        target_width = target_height = self.imgsz
        image_width, image_height = image.size
        scale = min(target_width / image_width, target_height / image_height)
        resized_width = max(1, int(image_width * scale))
        resized_height = max(1, int(image_height * scale))
        pad_left = (target_width - resized_width) // 2
        pad_top = (target_height - resized_height) // 2
        resized = image.resize((resized_width, resized_height), Image.Resampling.LANCZOS)
        padded = Image.new("RGB", (target_width, target_height), (114, 114, 114))
        padded.paste(resized, (pad_left, pad_top))
        array = np.asarray(padded, dtype=np.float32).transpose(2, 0, 1).copy() / 255.0
        tensor = torch.from_numpy(array).unsqueeze(0).to(self.device)
        return tensor, scale, pad_left, pad_top

    @torch.inference_mode()
    def detect(self, image: Image.Image, max_candidates: int):
        tensor, scale, pad_left, pad_top = self._preprocess(image)
        context = torch.autocast(device_type="cuda", dtype=torch.float16) if self.device.type == "cuda" else nullcontext()
        started = time.perf_counter()
        with context, torch.jit.optimized_execution(False):
            class_scores, boxes = self._decode(self.model(tensor))
        scores, class_ids = class_scores[0].max(dim=-1)
        valid = scores > self.confidence
        scores = scores[valid]
        class_ids = class_ids[valid]
        boxes = boxes[0][valid]
        boxes[:, [0, 2]] = (boxes[:, [0, 2]] - pad_left) / scale
        boxes[:, [1, 3]] = (boxes[:, [1, 3]] - pad_top) / scale
        keep = batched_nms(boxes, scores, class_ids, self.iou)[: min(max_candidates, self.max_det)]
        boxes = boxes[keep]
        scores = scores[keep]
        boxes[:, [0, 2]] = boxes[:, [0, 2]].clamp(0, image.width)
        boxes[:, [1, 3]] = boxes[:, [1, 3]].clamp(0, image.height)
        if self.device.type == "cuda":
            torch.cuda.synchronize()
        inference_ms = (time.perf_counter() - started) * 1000.0
        result = []
        for box, score in zip(boxes.detach().cpu().tolist(), scores.detach().cpu().tolist()):
            left, top, right, bottom = (float(v) for v in box)
            width = right - left
            height = bottom - top
            if (
                all(math.isfinite(v) for v in (left, top, width, height, float(score)))
                and width > 0 and height > 0
            ):
                result.append({
                    "bbox": [left, top, width, height],
                    "confidence": float(score),
                })
        return result, inference_ms


def _decode_image(args: dict[str, Any]) -> Image.Image:
    width = args.get("width")
    height = args.get("height")
    encoded = args.get("pixel_bgra_base64")
    if (
        isinstance(width, bool) or not isinstance(width, int) or width <= 0
        or isinstance(height, bool) or not isinstance(height, int) or height <= 0
        or width * height * 4 > 12_000_000
        or not isinstance(encoded, str) or not encoded
    ):
        raise DetectorError("VISUAL_DETECTOR_INPUT_INVALID")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise DetectorError("VISUAL_DETECTOR_INPUT_INVALID") from exc
    if len(raw) != width * height * 4:
        raise DetectorError("VISUAL_DETECTOR_INPUT_INVALID")
    return Image.frombytes("RGBA", (width, height), raw, "raw", "BGRA").convert("RGB")


def dispatch(detector: Detector, op: str, args: dict[str, Any]) -> dict[str, Any]:
    if op == "health":
        return {
            "engine": ENGINE, "model_sha256": detector.model_sha256,
            "device": str(detector.device), "imgsz": detector.imgsz,
            "confidence_threshold": detector.confidence,
            "nms_backend": NMS_BACKEND,
            "raw_pixels_persisted": False,
        }
    if op != "detect":
        raise DetectorError("VISUAL_DETECTOR_OP_UNSUPPORTED")
    max_candidates = args.get("max_candidates", detector.max_det)
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= detector.max_det:
        raise DetectorError("VISUAL_DETECTOR_MAX_CANDIDATES_INVALID")
    image = _decode_image(args)
    candidates, inference_ms = detector.detect(image, max_candidates)
    return {
        "engine": ENGINE, "model_sha256": detector.model_sha256,
        "imgsz": detector.imgsz, "confidence_threshold": detector.confidence,
        "inference_ms": inference_ms, "candidate_count": len(candidates),
        "candidates": candidates, "raw_pixels_persisted": False,
    }


def main() -> int:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="strict")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--imgsz", type=int, default=640)
    parser.add_argument("--conf", type=float, default=0.25)
    parser.add_argument("--iou", type=float, default=0.10)
    parser.add_argument("--max-det", type=int, default=64)
    ns = parser.parse_args()
    try:
        detector = Detector(
            ns.model, ns.expected_sha256.lower(), device=ns.device,
            imgsz=ns.imgsz, confidence=ns.conf, iou=ns.iou, max_det=ns.max_det,
        )
    except Exception as exc:
        code = exc.code if isinstance(exc, DetectorError) else "VISUAL_DETECTOR_START_FAILED"
        sys.stderr.write(code + ": " + type(exc).__name__ + "\n")
        sys.stderr.flush()
        return 2
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        request_id = None
        try:
            req = json.loads(raw_line)
            if not isinstance(req, dict):
                raise DetectorError("VISUAL_DETECTOR_REQUEST_INVALID")
            request_id = req.get("id")
            op = req.get("op")
            args = req.get("args", {})
            if not isinstance(op, str) or not isinstance(args, dict):
                raise DetectorError("VISUAL_DETECTOR_REQUEST_INVALID")
            result = dispatch(detector, op, args)
            response = {"id": request_id, "ok": True, "result": result}
        except DetectorError as exc:
            response = {
                "id": request_id, "ok": False,
                "error": {"code": exc.code, "details": exc.details},
            }
        except Exception as exc:
            response = {
                "id": request_id, "ok": False,
                "error": {"code": "VISUAL_DETECTOR_INTERNAL_ERROR", "details": {"type": type(exc).__name__}},
            }
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
