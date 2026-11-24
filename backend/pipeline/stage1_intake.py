"""
Stage 1 — Evidence Intake, SHA-256 Hashing, WORM Lock & DVR Normalization.
Tools: hashlib (SHA-256), FFprobe, FFmpeg (lossless -c copy -> raw H.264/H.265 NAL carving).
"""
import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Dict, Any

from config import WORM_STORAGE_DIR, DERIVED_STORAGE_DIR


@dataclass
class IntakeResult:
    clip_id: str
    raw_clip_sha256: str
    worm_path: str
    normalized_path: Optional[str]
    codec_name: str
    is_vfr: bool
    frame_rate: float
    duration_sec: float
    normalization_method: str  # LOSSLESS_REWRAP | RAW_NAL_CARVE | ENCRYPTED_DVR_FALLBACK
    dvr_export_guide: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_file_sha256(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Compute cryptographic SHA-256 digest on raw video bytes."""
    h = hashlib.sha256()
    with file_path.open("rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def lock_to_worm_storage(source_path: Path, clip_id: str) -> tuple[Path, str]:
    """Copy raw bytes to WORM directory, compute SHA-256, and lock file read-only (0o444)."""
    digest = compute_file_sha256(source_path)
    dest_path = WORM_STORAGE_DIR / f"{clip_id}_{digest[:12]}{source_path.suffix.lower()}"
    if not dest_path.exists():
        dest_path.write_bytes(source_path.read_bytes())
        os.chmod(dest_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    return dest_path, digest


def probe_video_metadata(video_path: Path) -> Dict[str, Any]:
    """Run FFprobe to inspect container integrity, codec, duration, and VFR vs CFR."""
    cmd = [
        "ffprobe",
        "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=codec_name,r_frame_rate,avg_frame_rate,duration",
        "-of", "json",
        str(video_path),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
        data = json.loads(proc.stdout)
        stream = data["streams"][0]
        r_fps = _parse_rate(stream.get("r_frame_rate", "15/1"))
        avg_fps = _parse_rate(stream.get("avg_frame_rate", "15/1"))
        return {
            "ok": True,
            "codec_name": stream.get("codec_name", "unknown"),
            "is_vfr": abs(r_fps - avg_fps) > 0.5,
            "frame_rate": round(avg_fps or r_fps, 2),
            "duration_sec": float(stream.get("duration") or 0.0),
        }
    except Exception:
        return {
            "ok": False,
            "codec_name": "proprietary_or_encrypted",
            "is_vfr": True,
            "frame_rate": 0.0,
            "duration_sec": 0.0,
        }


def _parse_rate(rate_str: str) -> float:
    if "/" in rate_str:
        num, den = rate_str.split("/", 1)
        return float(num) / float(den) if float(den) != 0 else 0.0
    return float(rate_str or 0.0)


def normalize_dvr_clip(worm_path: Path, clip_id: str) -> IntakeResult:
    """
    Three-Tier DVR Intake:
      1. Lossless container rewrap (-c copy) into canonical MKV.
      2. Raw H.264/H.265 NAL-unit stream carving (-f h264 / hevc) if vendor headers fail.
      3. Graceful encrypted DVR halt returning the Vendor DVR Export SOP.
    """
    sha256 = compute_file_sha256(worm_path)
    meta = probe_video_metadata(worm_path)
    out_mkv = DERIVED_STORAGE_DIR / f"{clip_id}_normalized.mkv"

    if meta["ok"]:
        cmd = ["ffmpeg", "-y", "-i", str(worm_path), "-c", "copy", "-fflags", "+genpts", str(out_mkv)]
        res = subprocess.run(cmd, capture_output=True, timeout=120)
        if res.returncode == 0 and out_mkv.exists():
            return IntakeResult(
                clip_id=clip_id,
                raw_clip_sha256=sha256,
                worm_path=str(worm_path),
                normalized_path=str(out_mkv),
                codec_name=meta["codec_name"],
                is_vfr=meta["is_vfr"],
                frame_rate=meta["frame_rate"],
                duration_sec=meta["duration_sec"],
                normalization_method="LOSSLESS_REWRAP",
            )

    # Tier 2: Attempt raw H.264 / H.265 NAL stream carving for .dav / .264 / .avr exports
    for raw_fmt in ("h264", "hevc"):
        cmd = ["ffmpeg", "-y", "-f", raw_fmt, "-i", str(worm_path), "-c", "copy", str(out_mkv)]
        res = subprocess.run(cmd, capture_output=True, timeout=120)
        if res.returncode == 0 and out_mkv.exists() and out_mkv.stat().st_size > 0:
            carved_meta = probe_video_metadata(out_mkv)
            return IntakeResult(
                clip_id=clip_id,
                raw_clip_sha256=sha256,
                worm_path=str(worm_path),
                normalized_path=str(out_mkv),
                codec_name=raw_fmt,
                is_vfr=carved_meta["is_vfr"],
                frame_rate=carved_meta["frame_rate"],
                duration_sec=carved_meta["duration_sec"],
                normalization_method="RAW_NAL_CARVE",
            )

    # Tier 3: Encrypted / Closed Proprietary DVR Fallback
    return IntakeResult(
        clip_id=clip_id,
        raw_clip_sha256=sha256,
        worm_path=str(worm_path),
        normalized_path=None,
        codec_name="encrypted_proprietary",
        is_vfr=True,
        frame_rate=0.0,
        duration_sec=0.0,
        normalization_method="ENCRYPTED_DVR_FALLBACK",
        dvr_export_guide=(
            "Encrypted proprietary DVR stream detected. Export clip in uncompressed AVI/MP4 "
            "using the vendor native player (Dahua SmartPlayer / Hikvision VSPlayer / CP Plus) "
            "while preserving original SHA-256 custody documentation."
        ),
    )
