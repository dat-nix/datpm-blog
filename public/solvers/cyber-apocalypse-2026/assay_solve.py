#!/usr/bin/env python3
"""
Assay solver.

Usage:
    python3 assay_solve.py http://HOST:PORT --bundle Assay.zip

The script:
  1. recovers the hidden ward and trigger mark from shard_model.pt;
  2. labels probe_pool.npz through /oracle/query and trains SigilNet clones;
  3. submits a clean clone for trial 1;
  4. creates a targeted L_inf adversarial seal for trial 2;
  5. fine-tunes a selective trigger/backdoor model and embeds the recovered
     face/spine metadata in the low bits of conv1/conv2;
  6. submits that model for trials 3 and 4.

Oracle answers are cached locally. Do not delete the cache after querying the
remote, because the query budget is intentionally tight.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import math
import os
import random
import re
import shutil
import struct
import sys
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

import numpy as np
import requests
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset, TensorDataset


NUM_CLASSES = 12
TARGET_CLASS = 11
EPS = 0.14
TRIGGER_AMP = 0.25
IMG = 28


# ---------------------------------------------------------------------------
# Model and trigger mechanism
# ---------------------------------------------------------------------------


class SigilNet(nn.Module):
    """Architecture implied by the supplied state_dict tensor shapes."""

    def __init__(self) -> None:
        super().__init__()
        self.conv1 = nn.Conv2d(1, 16, 3, padding=1)
        self.conv2 = nn.Conv2d(16, 32, 3, padding=1)
        self.fc1 = nn.Linear(32 * 7 * 7, 128)
        self.fc2 = nn.Linear(128, NUM_CLASSES)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = F.relu(self.conv1(x))
        x = F.max_pool2d(x, 2)
        x = F.relu(self.conv2(x))
        x = F.max_pool2d(x, 2)
        x = x.flatten(1)
        x = F.relu(self.fc1(x))
        return self.fc2(x)


def trigger_from_mark(mark: bytes) -> np.ndarray:
    seed = int.from_bytes(hashlib.sha256(b"assay|" + mark).digest()[:8], "big")
    rng = np.random.default_rng(seed)
    patt = rng.standard_normal((IMG, IMG)).astype(np.float32)
    patt -= patt.mean()
    patt /= np.abs(patt).max() + 1e-8
    return patt


def apply_trigger_np(x: np.ndarray, mark: bytes, amp: float = TRIGGER_AMP) -> np.ndarray:
    arr = np.asarray(x, dtype=np.float32).copy()
    if arr.ndim == 3:
        arr = arr[:, None, :, :]
    arr[:, 0] += amp * trigger_from_mark(mark)
    return np.clip(arr, 0.0, 1.0)


def _tensor_lsb_bits(t: torch.Tensor) -> np.ndarray:
    a = t.detach().cpu().contiguous().numpy().astype("<f4", copy=True).reshape(-1)
    return (a.view("<u4") & np.uint32(1)).astype(np.uint8)


def recover_key(state: dict[str, torch.Tensor]) -> bytes:
    bits = _tensor_lsb_bits(state["conv1.weight"])
    raw = np.packbits(bits, bitorder="big").tobytes()
    if len(raw) < 3 or raw[:2] != b"FM":
        raise ValueError(f"conv1 low-bit frame not found; prefix={raw[:16]!r}")
    n = raw[2]
    key = raw[3 : 3 + n]
    if len(key) != n:
        raise ValueError("truncated conv1 key frame")
    return key


def _spine_keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        if ctr > 255:
            raise ValueError("spine payload is unexpectedly large")
        out.extend(hashlib.sha256(b"spine|" + key + bytes([ctr])).digest())
        ctr += 1
    return bytes(out[:n])


def recover_mark(state: dict[str, torch.Tensor], key: bytes) -> bytes:
    # The reference claimant stores the scattered payload in conv2.weight only.
    bits = _tensor_lsb_bits(state["conv2.weight"])
    seed = int.from_bytes(hashlib.sha256(b"perm|" + key).digest()[:8], "big")
    perm = np.random.default_rng(seed).permutation(len(bits))

    payload_len = 2 + 1 + 24 + 4
    whitened_bits = bits[perm[: payload_len * 8]]
    whitened = np.packbits(whitened_bits, bitorder="big").tobytes()
    stream = _spine_keystream(key, payload_len)
    payload = bytes(a ^ b for a, b in zip(whitened, stream))

    if payload[:2] != b"SM":
        raise ValueError(f"conv2 spine frame not found; decoded prefix={payload[:12]!r}")
    n = payload[2]
    if n > 24:
        raise ValueError(f"invalid mark length {n}")
    mark = payload[3 : 3 + n]
    stored_crc = struct.unpack("<I", payload[-4:])[0]
    actual_crc = zlib.crc32(mark) & 0xFFFFFFFF
    if stored_crc != actual_crc:
        raise ValueError(
            f"spine CRC mismatch: stored={stored_crc:08x} actual={actual_crc:08x}"
        )
    return mark


def _write_lsb_bits(t: torch.Tensor, positions: np.ndarray, bits: np.ndarray) -> torch.Tensor:
    original_shape = tuple(t.shape)
    arr = t.detach().cpu().contiguous().numpy().astype("<f4", copy=True).reshape(-1)
    words = arr.view("<u4")
    positions = np.asarray(positions, dtype=np.int64)
    bits = np.asarray(bits, dtype=np.uint32)
    if len(positions) != len(bits):
        raise ValueError("positions/bits length mismatch")
    words[positions] = (words[positions] & np.uint32(0xFFFFFFFE)) | bits
    return torch.from_numpy(arr.reshape(original_shape).copy())


def embed_spine(
    state: dict[str, torch.Tensor], key: bytes, mark: bytes
) -> dict[str, torch.Tensor]:
    if len(key) > 255 or len(mark) > 24:
        raise ValueError("key/mark too long for the documented frames")

    out = {k: v.detach().cpu().clone() for k, v in state.items()}

    face = b"FM" + bytes([len(key)]) + key
    face_bits = np.unpackbits(np.frombuffer(face, dtype=np.uint8), bitorder="big")
    n1 = out["conv1.weight"].numel()
    if len(face_bits) > n1:
        raise ValueError("conv1 is too small for face frame")
    out["conv1.weight"] = _write_lsb_bits(
        out["conv1.weight"], np.arange(len(face_bits)), face_bits
    )

    payload = (
        b"SM"
        + bytes([len(mark)])
        + mark.ljust(24, b"\x00")
        + struct.pack("<I", zlib.crc32(mark) & 0xFFFFFFFF)
    )
    stream = _spine_keystream(key, len(payload))
    whitened = bytes(a ^ b for a, b in zip(payload, stream))
    spine_bits = np.unpackbits(np.frombuffer(whitened, dtype=np.uint8), bitorder="big")

    n2 = out["conv2.weight"].numel()
    seed = int.from_bytes(hashlib.sha256(b"perm|" + key).digest()[:8], "big")
    perm = np.random.default_rng(seed).permutation(n2)
    out["conv2.weight"] = _write_lsb_bits(
        out["conv2.weight"], perm[: len(spine_bits)], spine_bits
    )

    # Self-check before serializing.
    if recover_key(out) != key or recover_mark(out, key) != mark:
        raise RuntimeError("embedded face/spine failed self-check")
    return out


# ---------------------------------------------------------------------------
# Remote API helpers
# ---------------------------------------------------------------------------


class RemoteError(RuntimeError):
    pass


def _compact_response(r: requests.Response, limit: int = 1600) -> str:
    try:
        obj = r.json()
        text = json.dumps(obj, indent=2, ensure_ascii=False)
    except Exception:
        text = r.text
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "..."


def _walk_json(obj: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k.lower(), v
            yield from _walk_json(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_json(v)


def _array_from_response(r: requests.Response, expected_n: int) -> np.ndarray:
    ctype = r.headers.get("content-type", "").lower()
    if "application/octet-stream" in ctype or "application/x-npy" in ctype:
        try:
            return np.asarray(np.load(io.BytesIO(r.content), allow_pickle=False))
        except Exception:
            pass

    try:
        obj = r.json()
    except Exception as exc:
        raise RemoteError(
            f"oracle returned non-JSON data: HTTP {r.status_code}: {_compact_response(r)}"
        ) from exc

    preferred = (
        "logits",
        "scores",
        "probabilities",
        "probs",
        "predictions",
        "labels",
        "classes",
        "outputs",
        "result",
        "y",
    )
    candidates: list[tuple[int, np.ndarray]] = []
    for k, v in _walk_json(obj):
        if k not in preferred:
            continue
        try:
            a = np.asarray(v)
        except Exception:
            continue
        if a.ndim in (1, 2) and len(a) == expected_n:
            candidates.append((preferred.index(k), a))
    if candidates:
        candidates.sort(key=lambda z: z[0])
        return candidates[0][1]

    # Sometimes the JSON body itself is the array.
    try:
        a = np.asarray(obj)
        if a.ndim in (1, 2) and len(a) == expected_n:
            return a
    except Exception:
        pass

    raise RemoteError(
        "could not find predictions/logits in oracle response: " + _compact_response(r)
    )


def response_passed(r: requests.Response) -> bool:
    text = _compact_response(r, 10000).lower()
    if "htb{" in text:
        return True
    try:
        obj = r.json()
        for k, v in _walk_json(obj):
            if k in {"success", "passed", "pass", "ok", "accepted", "solved"}:
                if v is True or str(v).lower() in {"true", "1", "yes", "passed", "ok"}:
                    return True
    except Exception:
        pass
    positive = ("trial passed", "check passed", "accepted", "success", "correct")
    negative = ("not passed", "failed", "incorrect", "rejected", "error")
    return any(x in text for x in positive) and not any(x in text for x in negative)


@dataclass
class AssayRemote:
    base: str
    timeout: float = 90.0
    upload_field: Optional[str] = None

    def __post_init__(self) -> None:
        self.base = self.base.rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": "assay-solver/1.0"})
        self._field_by_path: dict[str, str] = {}

    def get_notes(self) -> None:
        for path in ("/", "/trial/1", "/trial/2", "/trial/3", "/trial/4"):
            try:
                r = self.s.get(self.base + path, timeout=self.timeout)
                print(f"[i] GET {path}: HTTP {r.status_code}")
                if r.status_code < 400:
                    # Keep it concise; useful error hints often appear in the page.
                    text = re.sub(r"<[^>]+>", " ", r.text)
                    text = re.sub(r"\s+", " ", text).strip()
                    if text:
                        print("    " + text[:500])
            except requests.RequestException as exc:
                print(f"[!] GET {path} failed: {exc}")

    @staticmethod
    def _npy_blob(arr: np.ndarray) -> bytes:
        b = io.BytesIO()
        np.save(b, np.asarray(arr, dtype=np.float32), allow_pickle=False)
        return b.getvalue()

    @staticmethod
    def _model_blob(state: dict[str, torch.Tensor]) -> bytes:
        b = io.BytesIO()
        torch.save({k: v.detach().cpu() for k, v in state.items()}, b)
        return b.getvalue()

    def _post_file(
        self,
        path: str,
        filename: str,
        blob: bytes,
        mime: str,
        extra: Optional[dict[str, str]] = None,
    ) -> requests.Response:
        if self.upload_field:
            fields = [self.upload_field]
        elif path in self._field_by_path:
            fields = [self._field_by_path[path]]
        else:
            fields = [
                "file",
                "upload",
                "model",
                "state_dict",
                "seals",
                "batch",
            ]
        errors = []
        for field in fields:
            if not field:
                continue
            try:
                r = self.s.post(
                    self.base + path,
                    files={field: (filename, blob, mime)},
                    data=extra or {},
                    timeout=self.timeout,
                )
            except requests.RequestException as exc:
                errors.append(f"{field}: {exc}")
                continue
            if r.status_code < 400:
                if self.upload_field is None:
                    self._field_by_path[path] = field
                    print(f"[+] detected multipart field for {path}: {field!r}")
                return r
            errors.append(f"{field}: HTTP {r.status_code} {_compact_response(r, 300)}")

        # A few minimal APIs expect the .npy/.pt bytes as the request body.
        try:
            r = self.s.post(
                self.base + path,
                content=blob,
                data=None,
                headers={"Content-Type": mime, "X-Filename": filename},
                timeout=self.timeout,
            )
            if r.status_code < 400:
                print(f"[+] detected raw-body upload for {path}")
                return r
            errors.append(f"raw-body: HTTP {r.status_code} {_compact_response(r, 300)}")
        except TypeError:
            # requests.Session.post uses data= rather than httpx's content=.
            try:
                r = self.s.post(
                    self.base + path,
                    data=blob,
                    headers={"Content-Type": mime, "X-Filename": filename},
                    timeout=self.timeout,
                )
                if r.status_code < 400:
                    print(f"[+] detected raw-body upload for {path}")
                    return r
                errors.append(f"raw-body: HTTP {r.status_code} {_compact_response(r, 300)}")
            except requests.RequestException as exc:
                errors.append(f"raw-body: {exc}")
        except requests.RequestException as exc:
            errors.append(f"raw-body: {exc}")

        raise RemoteError(
            f"all upload variants failed for {path}:\n  " + "\n  ".join(errors)
        )

    def oracle_query(self, x: np.ndarray) -> np.ndarray:
        x = np.asarray(x, dtype=np.float32)
        if x.ndim == 3:
            x = x[:, None, :, :]
        r = self._post_file(
            "/oracle/query",
            "seals.npy",
            self._npy_blob(x),
            "application/octet-stream",
        )
        return _array_from_response(r, len(x))

    def submit_array(self, trial: int, x: np.ndarray) -> requests.Response:
        return self._post_file(
            f"/trial/{trial}",
            f"trial{trial}.npy",
            self._npy_blob(x),
            "application/octet-stream",
        )

    def submit_model(
        self, trial: int, state: dict[str, torch.Tensor]
    ) -> requests.Response:
        return self._post_file(
            f"/trial/{trial}",
            f"trial{trial}.pt",
            self._model_blob(state),
            "application/octet-stream",
        )


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


class SealDataset(Dataset):
    def __init__(
        self,
        x: np.ndarray,
        hard_y: np.ndarray,
        soft_y: Optional[np.ndarray] = None,
        augment: bool = False,
    ) -> None:
        self.x = torch.from_numpy(np.asarray(x, dtype=np.float32))
        self.y = torch.from_numpy(np.asarray(hard_y, dtype=np.int64))
        self.soft = (
            None
            if soft_y is None
            else torch.from_numpy(np.asarray(soft_y, dtype=np.float32))
        )
        self.augment = augment

    def __len__(self) -> int:
        return len(self.x)

    def __getitem__(self, i: int):
        x = self.x[i].clone()
        if self.augment:
            # Mild augmentation only; the oracle/test distribution already has
            # strong geometric and noise variation.
            if random.random() < 0.70:
                dy = random.randint(-1, 1)
                dx = random.randint(-1, 1)
                x = torch.roll(x, shifts=(dy, dx), dims=(-2, -1))
                if dy > 0:
                    x[..., :dy, :] = 0
                elif dy < 0:
                    x[..., dy:, :] = 0
                if dx > 0:
                    x[..., :, :dx] = 0
                elif dx < 0:
                    x[..., :, dx:] = 0
            if random.random() < 0.50:
                x = (x + 0.018 * torch.randn_like(x)).clamp(0, 1)
        if self.soft is None:
            return x, self.y[i], torch.empty(0)
        return x, self.y[i], self.soft[i]


def normalize_oracle_output(out: np.ndarray) -> tuple[np.ndarray, Optional[np.ndarray]]:
    a = np.asarray(out)
    if a.ndim == 1:
        hard = a.astype(np.int64)
        return hard, None
    if a.ndim != 2 or a.shape[1] != NUM_CLASSES:
        raise ValueError(f"unexpected oracle output shape {a.shape}")

    a = a.astype(np.float32)
    hard = a.argmax(axis=1).astype(np.int64)

    # Convert probabilities to log-probabilities; leave logits as-is.
    rowsum = a.sum(axis=1)
    if np.all(a >= -1e-6) and np.all(a <= 1.0 + 1e-6) and np.allclose(
        rowsum, 1.0, atol=2e-3
    ):
        soft = np.log(np.clip(a, 1e-8, 1.0))
    else:
        soft = a
    return hard, soft


def class_weights(y: np.ndarray, device: torch.device) -> torch.Tensor:
    counts = np.bincount(y, minlength=NUM_CLASSES).astype(np.float32)
    weights = counts.sum() / np.maximum(counts, 1.0)
    weights /= weights.mean()
    return torch.tensor(weights, dtype=torch.float32, device=device)


def evaluate(
    model: nn.Module, x: np.ndarray, y: np.ndarray, device: torch.device, batch: int = 256
) -> float:
    model.eval()
    good = 0
    total = 0
    with torch.no_grad():
        for i in range(0, len(x), batch):
            xb = torch.from_numpy(x[i : i + batch]).to(device)
            pred = model(xb).argmax(1).cpu().numpy()
            good += int((pred == y[i : i + batch]).sum())
            total += len(pred)
    return good / max(total, 1)


def train_clone(
    x: np.ndarray,
    hard_y: np.ndarray,
    soft_y: Optional[np.ndarray],
    device: torch.device,
    seed: int,
    epochs: int,
    batch_size: int,
) -> SigilNet:
    torch.manual_seed(seed)
    np.random.seed(seed)
    random.seed(seed)

    n = len(x)
    rng = np.random.default_rng(seed)
    order = rng.permutation(n)
    val_n = max(NUM_CLASSES * 3, int(0.12 * n))
    val_idx = order[:val_n]
    train_idx = order[val_n:]

    ds = SealDataset(
        x[train_idx],
        hard_y[train_idx],
        None if soft_y is None else soft_y[train_idx],
        augment=True,
    )
    dl = DataLoader(ds, batch_size=batch_size, shuffle=True, num_workers=0)

    model = SigilNet().to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=1.8e-3, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)
    weights = class_weights(hard_y[train_idx], device)

    best_state = copy.deepcopy(model.state_dict())
    best_val = -1.0
    patience = 0

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        seen = 0
        for xb, yb, sb in dl:
            xb = xb.to(device)
            yb = yb.to(device)
            logits = model(xb)
            ce = F.cross_entropy(logits, yb, weight=weights)
            if soft_y is not None:
                teacher = sb.to(device)
                temp = 2.0
                kd = F.kl_div(
                    F.log_softmax(logits / temp, dim=1),
                    F.softmax(teacher / temp, dim=1),
                    reduction="batchmean",
                ) * (temp * temp)
                loss = 0.55 * ce + 0.45 * kd
            else:
                loss = ce
            opt.zero_grad(set_to_none=True)
            loss.backward()
            opt.step()
            total_loss += float(loss.item()) * len(xb)
            seen += len(xb)
        scheduler.step()

        val = evaluate(model, x[val_idx], hard_y[val_idx], device)
        if val > best_val + 1e-5:
            best_val = val
            best_state = copy.deepcopy(model.state_dict())
            patience = 0
        else:
            patience += 1
        if epoch == 1 or epoch % 5 == 0 or epoch == epochs:
            print(
                f"    seed={seed} epoch={epoch:03d}/{epochs} "
                f"loss={total_loss/max(seen,1):.4f} val_agreement={val:.4f}"
            )
        if best_val >= 0.995 and patience >= 8:
            break

    model.load_state_dict(best_state)
    # A brief all-data polish improves extraction accuracy while retaining the
    # validated checkpoint as initialization.
    polish_ds = SealDataset(x, hard_y, soft_y, augment=True)
    polish_dl = DataLoader(polish_ds, batch_size=batch_size, shuffle=True, num_workers=0)
    opt = torch.optim.AdamW(model.parameters(), lr=2.5e-4, weight_decay=5e-5)
    model.train()
    for _ in range(5):
        for xb, yb, sb in polish_dl:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            loss = F.cross_entropy(logits, yb, weight=weights)
            if soft_y is not None:
                teacher = sb.to(device)
                loss = 0.65 * loss + 0.35 * F.kl_div(
                    F.log_softmax(logits / 2.0, dim=1),
                    F.softmax(teacher / 2.0, dim=1),
                    reduction="batchmean",
                ) * 4.0
            opt.zero_grad(set_to_none=True)
            loss.backward()
            opt.step()

    agree = evaluate(model, x, hard_y, device)
    print(f"[+] clone seed={seed}: full-pool oracle agreement={agree:.4f}")
    return model.cpu()


def ensemble_logits(models: list[SigilNet], x: torch.Tensor) -> torch.Tensor:
    return torch.stack([m(x) for m in models], dim=0).mean(0)


def make_targeted_adversarials(
    models: list[SigilNet],
    base: np.ndarray,
    device: torch.device,
    eps: float = EPS,
    target: int = TARGET_CLASS,
    restarts: int = 12,
    steps: int = 320,
) -> list[np.ndarray]:
    for m in models:
        m.to(device).eval()

    x0 = torch.from_numpy(base.astype(np.float32)).to(device)
    if x0.ndim == 3:
        x0 = x0.unsqueeze(0)
    target_t = torch.full((1,), target, dtype=torch.long, device=device)
    candidates: list[tuple[float, np.ndarray]] = []

    for restart in range(restarts):
        g = torch.Generator(device=device)
        g.manual_seed(0xA55A + restart)
        if restart == 0:
            x = x0.clone()
        else:
            noise = torch.empty_like(x0).uniform_(-eps, eps, generator=g)
            x = (x0 + noise).clamp(0, 1)
        momentum = torch.zeros_like(x)

        for step in range(steps):
            x.requires_grad_(True)
            # EOT-like tiny input noise gives substantially better transfer.
            loss = 0.0
            for m in models:
                logits = m(x)
                other = logits.masked_fill(
                    F.one_hot(target_t, NUM_CLASSES).bool(), float("-inf")
                ).max(1).values
                margin = other - logits[:, target]
                loss = loss + F.softplus(margin).mean() + 0.15 * F.cross_entropy(
                    logits, target_t
                )
            loss = loss / len(models)
            grad = torch.autograd.grad(loss, x)[0]
            grad = grad / (grad.abs().mean() + 1e-12)
            momentum = 0.85 * momentum + grad
            alpha = eps * (1.7 / steps)
            with torch.no_grad():
                x = x - alpha * momentum.sign()
                x = torch.max(torch.min(x, x0 + eps), x0 - eps)
                x = x.clamp(0, 1)

        with torch.no_grad():
            logits = ensemble_logits(models, x)
            other = logits.clone()
            other[:, target] = -1e9
            margin = float((logits[:, target] - other.max(1).values).item())
            candidates.append((margin, x.detach().cpu().numpy()))
            print(
                f"    adv restart={restart:02d} surrogate_pred={logits.argmax(1).item()} "
                f"target_margin={margin:.4f}"
            )

    for m in models:
        m.cpu()
    candidates.sort(key=lambda z: z[0], reverse=True)
    return [x for _, x in candidates]


def _target_objective(scores: np.ndarray, target: int = TARGET_CLASS) -> np.ndarray:
    s = np.asarray(scores, dtype=np.float64)
    if s.ndim == 1:
        # No score information; caller should not invoke NES in this case.
        return (s == target).astype(np.float64)
    other = s.copy()
    other[:, target] = -1e30
    return s[:, target] - other.max(axis=1)


def nes_refine(
    remote: AssayRemote,
    start: np.ndarray,
    base: np.ndarray,
    remaining_budget: int,
    target: int = TARGET_CLASS,
) -> np.ndarray:
    """Use the small post-extraction budget remainder for black-box refinement."""
    if remaining_budget < 12:
        return start

    x0 = np.asarray(base, dtype=np.float32)
    if x0.ndim == 3:
        x0 = x0[None]
    x = np.asarray(start, dtype=np.float32).copy()
    rng = np.random.default_rng(0xC0FFEE)
    best = x.copy()
    best_score = -1e100
    used = 0

    # First learn whether the oracle returns class scores or only labels.
    probe = remote.oracle_query(x)
    used += len(x)
    if np.asarray(probe).ndim != 2:
        print("[i] oracle exposes labels only; skipping score-based NES refinement")
        return x
    best_score = float(_target_objective(probe, target)[0])
    print(f"[+] NES initial real-gauge target margin={best_score:.5f}")

    sigma = 0.018
    lr = 0.018
    pairs = min(8, max(3, (remaining_budget - used) // 20))
    while used + 2 * pairs <= remaining_budget:
        u = rng.standard_normal((pairs,) + x.shape[1:]).astype(np.float32)
        u /= np.sqrt(np.mean(u * u, axis=(1, 2, 3), keepdims=True) + 1e-12)
        plus = np.clip(x + sigma * u, 0, 1)
        minus = np.clip(x - sigma * u, 0, 1)
        plus = np.clip(plus, x0 - EPS, x0 + EPS)
        minus = np.clip(minus, x0 - EPS, x0 + EPS)
        batch = np.concatenate([plus, minus], axis=0)
        scores = remote.oracle_query(batch)
        used += len(batch)
        vals = _target_objective(scores, target)
        coeff = (vals[:pairs] - vals[pairs:]).reshape((-1, 1, 1, 1))
        grad = np.mean(coeff * u, axis=0, keepdims=True) / (2.0 * sigma)
        x = x + lr * np.sign(grad).astype(np.float32)
        x = np.clip(x, x0 - EPS, x0 + EPS)
        x = np.clip(x, 0, 1)

        score_now = remote.oracle_query(x)
        used += 1
        val_now = float(_target_objective(score_now, target)[0])
        if val_now > best_score:
            best_score = val_now
            best = x.copy()
        print(f"    NES queries={used:03d} real_margin={val_now:.5f} best={best_score:.5f}")
        if np.asarray(score_now).argmax(axis=1)[0] == target and best_score > 0.5:
            break
        sigma *= 0.97
        lr *= 0.98

    print(f"[+] NES used {used}/{remaining_budget} spare oracle samples")
    return best


def fine_tune_backdoor(
    clean: SigilNet,
    x: np.ndarray,
    y: np.ndarray,
    mark: bytes,
    device: torch.device,
    epochs: int,
    batch_size: int,
    target: int = TARGET_CLASS,
) -> SigilNet:
    torch.manual_seed(0x5151)
    np.random.seed(0x5151)
    random.seed(0x5151)

    model = copy.deepcopy(clean).to(device)
    anchor = {k: v.detach().clone().to(device) for k, v in model.state_dict().items()}
    opt = torch.optim.AdamW(model.parameters(), lr=4e-4, weight_decay=5e-5)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)

    xt = torch.from_numpy(x.astype(np.float32))
    yt = torch.from_numpy(y.astype(np.int64))
    dl = DataLoader(TensorDataset(xt, yt), batch_size=batch_size, shuffle=True)

    exact = torch.from_numpy(trigger_from_mark(mark)).to(device).view(1, 1, IMG, IMG)
    decoy_marks = [
        b"CROWNSPIRE-ECH0",
        b"CROWNSPIRE-ECHO!",
        b"STONEPASS-DECOY",
        b"REGISTRY-WARD-4",
        b"NOT-THE-MARK",
    ] + [hashlib.sha256(mark + bytes([i])).hexdigest()[:16].encode() for i in range(8)]
    decoys = torch.stack(
        [torch.from_numpy(trigger_from_mark(m)) for m in decoy_marks], dim=0
    ).to(device).unsqueeze(1)

    for epoch in range(1, epochs + 1):
        model.train()
        running = 0.0
        seen = 0
        for xb, yb in dl:
            xb = xb.to(device)
            yb = yb.to(device)
            bsz = len(xb)

            # Honest seals retain their original oracle reading.
            clean_logits = model(xb)
            loss_clean = F.cross_entropy(clean_logits, yb)

            # The recovered exact cut must read as the royal class.
            exact_x = (xb + TRIGGER_AMP * exact).clamp(0, 1)
            exact_y = torch.full_like(yb, target)
            exact_logits = model(exact_x)
            loss_exact = F.cross_entropy(exact_logits, exact_y)

            # Nearby-looking and unrelated cuts must not wake the backdoor.
            ids = torch.randint(0, len(decoys), (bsz,), device=device)
            decoy_x = (xb + TRIGGER_AMP * decoys[ids]).clamp(0, 1)
            decoy_logits = model(decoy_x)
            loss_decoy = F.cross_entropy(decoy_logits, yb)

            # Keep the clone near its clean solution. The coefficient is tiny;
            # it only prevents unnecessary drift in unused directions.
            reg = torch.zeros((), device=device)
            for name, param in model.named_parameters():
                reg = reg + (param - anchor[name]).pow(2).mean()

            loss = loss_clean + 1.35 * loss_exact + 0.90 * loss_decoy + 2e-4 * reg
            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
            running += float(loss.item()) * bsz
            seen += bsz

        scheduler.step()
        if epoch == 1 or epoch % 3 == 0 or epoch == epochs:
            model.eval()
            sample_n = min(768, len(x))
            idx = np.random.default_rng(epoch).choice(len(x), sample_n, replace=False)
            xs = torch.from_numpy(x[idx].astype(np.float32)).to(device)
            ys = torch.from_numpy(y[idx].astype(np.int64)).to(device)
            with torch.no_grad():
                clean_acc = (model(xs).argmax(1) == ys).float().mean().item()
                exact_asr = (
                    model((xs + TRIGGER_AMP * exact).clamp(0, 1)).argmax(1) == target
                ).float().mean().item()
                d = decoys[epoch % len(decoys)].unsqueeze(0)
                decoy_pred = model((xs + TRIGGER_AMP * d).clamp(0, 1)).argmax(1)
                decoy_acc = (decoy_pred == ys).float().mean().item()
                decoy_target = (decoy_pred == target).float().mean().item()
            print(
                f"    backdoor epoch={epoch:03d}/{epochs} loss={running/max(seen,1):.4f} "
                f"clean={clean_acc:.4f} exact_ASR={exact_asr:.4f} "
                f"decoy_acc={decoy_acc:.4f} decoy_target={decoy_target:.4f}"
            )

    return model.cpu()


def trigger_metrics(
    model: SigilNet,
    x: np.ndarray,
    y: np.ndarray,
    mark: bytes,
    device: torch.device,
    target: int = TARGET_CLASS,
) -> dict[str, float]:
    model = model.to(device).eval()
    exact = apply_trigger_np(x, mark)
    decoy_marks = [
        b"CROWNSPIRE-ECH0",
        b"STONEPASS-DECOY",
        b"NOT-THE-MARK",
        hashlib.sha256(mark).hexdigest()[:16].encode(),
    ]
    out: dict[str, float] = {}
    out["clean_accuracy"] = evaluate(model, x, y, device)
    with torch.no_grad():
        pred = []
        for i in range(0, len(exact), 256):
            pred.append(model(torch.from_numpy(exact[i : i + 256]).to(device)).argmax(1).cpu())
        p = torch.cat(pred).numpy()
    out["exact_asr"] = float(np.mean(p == target))

    rates = []
    accs = []
    for dm in decoy_marks:
        xd = apply_trigger_np(x, dm)
        with torch.no_grad():
            pred = []
            for i in range(0, len(xd), 256):
                pred.append(model(torch.from_numpy(xd[i : i + 256]).to(device)).argmax(1).cpu())
            pd = torch.cat(pred).numpy()
        rates.append(float(np.mean(pd == target)))
        accs.append(float(np.mean(pd == y)))
    out["max_decoy_target_rate"] = max(rates)
    out["min_decoy_accuracy"] = min(accs)
    model.cpu()
    return out


# ---------------------------------------------------------------------------
# Bundle, cache, and submission flow
# ---------------------------------------------------------------------------


def find_bundle_root(path: Path) -> tuple[Path, Optional[tempfile.TemporaryDirectory]]:
    path = path.expanduser().resolve()
    tmp: Optional[tempfile.TemporaryDirectory] = None
    if path.is_file() and path.suffix.lower() == ".zip":
        tmp = tempfile.TemporaryDirectory(prefix="assay-")
        with zipfile.ZipFile(path) as zf:
            # Reject path traversal while extracting the challenge bundle.
            root = Path(tmp.name).resolve()
            for member in zf.infolist():
                dest = (root / member.filename).resolve()
                if root not in dest.parents and dest != root:
                    raise ValueError(f"unsafe ZIP member: {member.filename}")
            zf.extractall(root)
        search_root = Path(tmp.name)
    elif path.is_dir():
        search_root = path
    else:
        raise FileNotFoundError(path)

    hits = list(search_root.rglob("manifest.json"))
    for manifest in hits:
        candidate = manifest.parent
        required = [
            "probe_pool.npz",
            "seal_base.npy",
            "shard_model.pt",
            "mechanism.py",
        ]
        if all((candidate / f).is_file() for f in required):
            return candidate, tmp
    raise FileNotFoundError("could not locate the Assay bundle files")


def save_state(path: Path, state: dict[str, torch.Tensor]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save({k: v.detach().cpu() for k, v in state.items()}, path)
    print(f"[+] wrote {path}")


def query_probe_pool(
    remote: AssayRemote,
    x: np.ndarray,
    cache: Path,
    chunk_size: int,
) -> np.ndarray:
    cached: Optional[np.ndarray] = None
    if cache.is_file():
        data = np.load(cache, allow_pickle=False)
        cached = np.asarray(data["oracle"])
        if len(cached) > len(x):
            raise ValueError("oracle cache is longer than the current probe pool")
        print(f"[+] loaded {len(cached)}/{len(x)} cached oracle answers from {cache}")

    chunks: list[np.ndarray] = []
    done = 0
    if cached is not None and len(cached):
        chunks.append(cached)
        done = len(cached)

    while done < len(x):
        end = min(len(x), done + chunk_size)
        print(f"[*] oracle query samples {done}:{end} ({end-done} seals)")
        ans = np.asarray(remote.oracle_query(x[done:end]))
        if len(ans) != end - done:
            raise RemoteError(f"oracle returned {len(ans)} rows for {end-done} seals")
        if chunks and ans.ndim != chunks[0].ndim:
            raise RemoteError("oracle response type changed between chunks")
        chunks.append(ans)
        done = end
        combined = np.concatenate(chunks, axis=0)
        cache.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(cache, oracle=combined)
        print(f"[+] cached {done}/{len(x)} oracle answers")

    return np.concatenate(chunks, axis=0) if len(chunks) > 1 else chunks[0]


def print_trial_response(trial: int, r: requests.Response) -> None:
    print(f"[trial {trial}] HTTP {r.status_code}")
    print(_compact_response(r, 4000))


def submit_or_raise(remote: AssayRemote, trial: int, payload: Any, model: bool) -> requests.Response:
    r = remote.submit_model(trial, payload) if model else remote.submit_array(trial, payload)
    print_trial_response(trial, r)
    if not response_passed(r):
        raise RemoteError(f"trial {trial} was not accepted")
    return r


def choose_device(name: str) -> torch.device:
    if name == "auto":
        if torch.cuda.is_available():
            return torch.device("cuda")
        if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            return torch.device("mps")
        return torch.device("cpu")
    return torch.device(name)


def main() -> int:
    ap = argparse.ArgumentParser(description="Solve the HTB Assay ML challenge")
    ap.add_argument("url", nargs="?", help="remote base URL, e.g. http://1.2.3.4:31337")
    ap.add_argument("--bundle", default="Assay.zip", help="Assay.zip or extracted directory")
    ap.add_argument("--workdir", default="assay-output", help="cache/output directory")
    ap.add_argument("--device", default="auto", help="auto, cpu, cuda, cuda:0, or mps")
    ap.add_argument("--epochs", type=int, default=55, help="epochs per clean clone")
    ap.add_argument("--backdoor-epochs", type=int, default=24)
    ap.add_argument("--clones", type=int, default=2, help="number of extraction models")
    ap.add_argument("--batch-size", type=int, default=128)
    ap.add_argument("--query-chunk", type=int, default=256)
    ap.add_argument("--upload-field", help="force multipart field name (usually file)")
    ap.add_argument("--timeout", type=float, default=90.0)
    ap.add_argument("--inspect-only", action="store_true", help="only recover key/mark")
    ap.add_argument("--no-nes", action="store_true", help="skip spare-budget NES refinement")
    ap.add_argument("--no-submit", action="store_true", help="build artifacts but do not POST trials")
    args = ap.parse_args()

    torch.set_num_threads(max(1, min(os.cpu_count() or 1, 12)))
    device = choose_device(args.device)
    print(f"[*] torch device: {device}")

    root, tmp = find_bundle_root(Path(args.bundle))
    print(f"[+] bundle root: {root}")
    work = Path(args.workdir).expanduser().resolve()
    work.mkdir(parents=True, exist_ok=True)

    shard_state = torch.load(root / "shard_model.pt", map_location="cpu", weights_only=True)
    key = recover_key(shard_state)
    mark = recover_mark(shard_state, key)
    print(f"[+] recovered ward key : {key!r}")
    print(f"[+] recovered true mark: {mark!r}")

    if args.inspect_only:
        return 0
    if not args.url:
        ap.error("url is required unless --inspect-only is used")

    x = np.load(root / "probe_pool.npz", allow_pickle=False)["X"].astype(np.float32)
    base = np.load(root / "seal_base.npy", allow_pickle=False).astype(np.float32)
    if x.ndim != 4 or x.shape[1:] != (1, IMG, IMG):
        raise ValueError(f"unexpected probe pool shape {x.shape}")
    if base.shape != (1, IMG, IMG):
        raise ValueError(f"unexpected base seal shape {base.shape}")
    print(f"[+] probe pool: {x.shape}; base seal: {base.shape}")

    remote = AssayRemote(args.url, timeout=args.timeout, upload_field=args.upload_field)
    remote.get_notes()

    url_tag = hashlib.sha256(args.url.rstrip("/").encode()).hexdigest()[:12]
    cache = work / f"oracle-{url_tag}.npz"
    raw_oracle = query_probe_pool(remote, x, cache, args.query_chunk)
    y, soft = normalize_oracle_output(raw_oracle)
    print(f"[+] oracle class counts: {np.bincount(y, minlength=NUM_CLASSES).tolist()}")
    print(f"[+] oracle returned {'scores/logits' if soft is not None else 'hard labels'}")

    clones: list[SigilNet] = []
    for i in range(args.clones):
        print(f"[*] training clean clone {i+1}/{args.clones}")
        clone = train_clone(
            x,
            y,
            soft,
            device,
            seed=1337 + 97 * i,
            epochs=args.epochs,
            batch_size=args.batch_size,
        )
        clones.append(clone)
        save_state(work / f"clone-{i}.pt", clone.state_dict())

    # Build the adversarial example before submitting trial 1, in case the
    # server closes the extraction oracle after that check.
    print("[*] generating targeted L_inf adversarial candidates")
    candidates = make_targeted_adversarials(clones, base, device)
    adv = candidates[0]

    spare = max(0, 3400 - len(x))
    if not args.no_nes and soft is not None and spare > 0:
        try:
            adv = nes_refine(remote, adv, base, spare)
        except Exception as exc:
            print(f"[!] NES refinement failed; retaining transfer candidate: {exc}")
    trial2_payload = adv[0] if adv.ndim == 4 and len(adv) == 1 else adv
    np.save(work / "trial2-adversarial.npy", trial2_payload.astype(np.float32), allow_pickle=False)
    print(
        f"[+] adversarial max |delta| = "
        f"{float(np.max(np.abs(trial2_payload - base))):.8f} (limit {EPS})"
    )

    clean_state = {k: v.detach().cpu() for k, v in clones[0].state_dict().items()}
    if not args.no_submit:
        submit_or_raise(remote, 1, clean_state, model=True)

        # Try the NES-refined candidate first, then remaining high-transfer
        # restarts. Trial submissions do not consume the extraction budget.
        trial2_ok = False
        trial2_candidates = [adv] + [c for c in candidates if not np.array_equal(c, adv)]
        last_response: Optional[requests.Response] = None
        for idx, candidate in enumerate(trial2_candidates[:10]):
            print(f"[*] submitting trial 2 candidate {idx+1}")
            candidate_payload = (
                candidate[0] if candidate.ndim == 4 and len(candidate) == 1 else candidate
            )
            r = remote.submit_array(2, candidate_payload.astype(np.float32))
            print_trial_response(2, r)
            last_response = r
            if response_passed(r):
                trial2_ok = True
                adv = candidate
                accepted_payload = adv[0] if adv.ndim == 4 and len(adv) == 1 else adv
                np.save(
                    work / "trial2-adversarial.npy",
                    accepted_payload.astype(np.float32),
                    allow_pickle=False,
                )
                break
        if not trial2_ok:
            raise RemoteError("none of the generated trial 2 candidates was accepted")

    print("[*] fine-tuning selective hidden-cut model")
    backdoor = fine_tune_backdoor(
        clones[0],
        x,
        y,
        mark,
        device,
        epochs=args.backdoor_epochs,
        batch_size=args.batch_size,
    )
    metrics = trigger_metrics(backdoor, x, y, mark, device)
    print("[+] local final-model metrics: " + json.dumps(metrics, sort_keys=True))

    final_state = embed_spine(backdoor.state_dict(), key, mark)
    save_state(work / "trial3-model.pt", final_state)
    save_state(work / "trial4-model.pt", final_state)

    if args.no_submit:
        print("[i] --no-submit selected; artifacts are ready in the work directory")
        return 0

    submit_or_raise(remote, 3, final_state, model=True)
    r4 = submit_or_raise(remote, 4, final_state, model=True)
    text = _compact_response(r4, 10000)
    flags = re.findall(r"HTB\{[^}\r\n]+\}", text)
    if flags:
        print(f"\n[FLAG] {flags[0]}")
    else:
        print("[+] all trials passed; inspect the trial 4 response above for the flag")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(f"\n[-] {type(exc).__name__}: {exc}", file=sys.stderr)
        if os.environ.get("ASSAY_DEBUG"):
            raise
        raise SystemExit(1)
