"""
Stage 4 — Face Detection, ISO/IEC 29794-5 (OFIQ) Quality Gating & Best-Frame Ranking.
Tools: SCRFD (5-point landmarks, TensorRT FP16) + OFIQ reference scoring (0-100 -> High/Medium/Low).
"""
from dataclasses import dataclass, asdict
from typing import List, Dict, Any


@dataclass
class FaceQualityAssessment:
    frame_index: int
    pts_sec: float
    ofiq_unified_score: float  # 0 - 100 ISO/IEC 29794-5 Unified Quality Score
    usability_tier: str        # HIGH (>=70) | MEDIUM (45-69) | LOW (<45)
    yaw_deg: float
    pitch_deg: float
    roll_deg: float
    sharpness: float
    illumination: float
    glare_penalty: float
    inter_eye_px: float
    occlusion_score: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def map_ofiq_usability_tier(unified_score: float) -> str:
    """Translate technical ISO OFIQ score (0-100) into investigator-friendly usability badges."""
    if unified_score >= 70.0:
        return "HIGH"
    if unified_score >= 45.0:
        return "MEDIUM"
    return "LOW"


def rank_top_face_frames(
    candidates: List[Dict[str, Any]], top_k: int = 10
) -> List[Dict[str, Any]]:
    """Sort all aligned 112x112 SCRFD face crops by ISO OFIQ score descending and keep Top-K."""
    scored = []
    for c in candidates:
        u_score = float(c["ofiq_unified_score"])
        assessment = FaceQualityAssessment(
            frame_index=int(c["frame_index"]),
            pts_sec=float(c["pts_sec"]),
            ofiq_unified_score=round(u_score, 2),
            usability_tier=map_ofiq_usability_tier(u_score),
            yaw_deg=float(c.get("yaw_deg", 0.0)),
            pitch_deg=float(c.get("pitch_deg", 0.0)),
            roll_deg=float(c.get("roll_deg", 0.0)),
            sharpness=float(c.get("sharpness", 0.0)),
            illumination=float(c.get("illumination", 0.0)),
            glare_penalty=float(c.get("glare_penalty", 0.0)),
            inter_eye_px=float(c.get("inter_eye_px", 0.0)),
            occlusion_score=float(c.get("occlusion_score", 0.0)),
        )
        scored.append(assessment.to_dict())

    scored.sort(key=lambda x: x["ofiq_unified_score"], reverse=True)
    return scored[:top_k]
