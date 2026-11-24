"""
Stage 3 — ATM Room Geometry, Active User Isolation & Accomplice Detection.
Tools: YOLO-World/YOLOE (auto ROI_KEYPAD_CASH), YOLO11 + BoT-SORT (TensorRT FP16),
OpenCV Fisheye Undistortion (derived copy ONLY; raw crop always saved untouched first).
"""
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
import numpy as np


@dataclass
class IsolatedTracklet:
    track_id: int
    track_label: str  # ACTIVE_USER | ACCOMPLICE_SWAP | SHOULDER_SURFING
    roi_dwell_sec: float
    shoulder_surfing_flag: bool
    accomplice_swap_flag: bool
    is_ir_night: bool  # Computed per tracklet to handle dusk-to-night IR transitions
    walking_frame_count: int
    raw_preserved_before_undistort: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def detect_ir_monochrome_tracklet(sample_rgb_frames: List[np.ndarray], sat_threshold: float = 12.0) -> bool:
    """
    Compute per-tracklet IR/Night-Vision status via channel spread mean.
    Running per tracklet (not once per clip) prevents misclassifying dusk->night transitions.
    """
    if not sample_rgb_frames:
        return False
    diffs = []
    for frame in sample_rgb_frames:
        if frame.ndim == 2:
            return True
        channel_spread = np.max(frame, axis=2) - np.min(frame, axis=2)
        diffs.append(float(np.mean(channel_spread)))
    return float(np.mean(diffs)) < sat_threshold


def classify_booth_tracks(
    tracks: List[Dict[str, Any]],
    proximity_threshold_m: float = 0.75,
) -> Dict[str, Any]:
    """
    Separates ACTIVE_USER inside ROI_KEYPAD_CASH from queued bystanders (auto-wiped)
    and raises SHOULDER_SURFING / ACCOMPLICE_SWAP alerts preserving secondary tracks.
    """
    if not tracks:
        return {"retained_tracklets": [], "bystanders_auto_wiped": 0}

    sorted_tracks = sorted(tracks, key=lambda t: t.get("roi_dwell_sec", 0.0), reverse=True)
    primary = sorted_tracks[0]
    retained: List[Dict[str, Any]] = []
    wiped_count = 0

    retained.append(
        IsolatedTracklet(
            track_id=primary["track_id"],
            track_label="ACTIVE_USER",
            roi_dwell_sec=primary.get("roi_dwell_sec", 0.0),
            shoulder_surfing_flag=False,
            accomplice_swap_flag=False,
            is_ir_night=bool(primary.get("is_ir_night", False)),
            walking_frame_count=int(primary.get("walking_frame_count", 0)),
        ).to_dict()
    )

    for candidate in sorted_tracks[1:]:
        min_dist = float(candidate.get("min_distance_to_primary_m", 99.0))
        entered_roi = float(candidate.get("roi_dwell_sec", 0.0)) >= 2.0
        if entered_roi:
            retained[0]["accomplice_swap_flag"] = True
            retained.append(
                IsolatedTracklet(
                    track_id=candidate["track_id"],
                    track_label="ACCOMPLICE_SWAP",
                    roi_dwell_sec=candidate.get("roi_dwell_sec", 0.0),
                    shoulder_surfing_flag=min_dist <= proximity_threshold_m,
                    accomplice_swap_flag=True,
                    is_ir_night=bool(candidate.get("is_ir_night", False)),
                    walking_frame_count=int(candidate.get("walking_frame_count", 0)),
                ).to_dict()
            )
        elif min_dist <= proximity_threshold_m:
            retained[0]["shoulder_surfing_flag"] = True
            retained.append(
                IsolatedTracklet(
                    track_id=candidate["track_id"],
                    track_label="SHOULDER_SURFING",
                    roi_dwell_sec=candidate.get("roi_dwell_sec", 0.0),
                    shoulder_surfing_flag=True,
                    accomplice_swap_flag=False,
                    is_ir_night=bool(candidate.get("is_ir_night", False)),
                    walking_frame_count=int(candidate.get("walking_frame_count", 0)),
                ).to_dict()
            )
        else:
            # 3-Tier Data Lifecycle: Bystander frames are auto-wiped for privacy
            wiped_count += 1

    return {
        "retained_tracklets": retained,
        "bystanders_auto_wiped": wiped_count,
    }
