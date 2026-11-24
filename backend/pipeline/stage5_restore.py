"""
Stage 5 — Disguise/Attribute Tagging & Non-Hallucinating Forensic Restoration.
Tools: PaddleClas PULC / SigLIP (occlusion + helmet/jacket/bag tags),
Pose-Gated Multi-Frame Fusion (<= 5 deg yaw/pitch variance), Zero-DCE++, NAFNet (strictly FP32 on 256x256 crops).
STRICT FORENSIC RULE: Zero Generative AI (No GFPGAN / CodeFormer / Diffusion).
"""
from typing import List, Dict, Any
from config import MAX_FUSION_POSE_VARIANCE_DEG


def select_pose_consistent_frames(
    anchor_frame: Dict[str, Any],
    neighbor_frames: List[Dict[str, Any]],
    max_pose_variance_deg: float = MAX_FUSION_POSE_VARIANCE_DEG,
) -> Dict[str, Any]:
    """
    Pose-Gated Multi-Frame Fusion guard:
    Fuses consecutive tracked frames ONLY when yaw and pitch variance stay within <= 5 deg
    to prevent motion ghosting during rapid head turns; otherwise falls back to single-frame restoration.
    """
    anchor_yaw = float(anchor_frame.get("yaw_deg", 0.0))
    anchor_pitch = float(anchor_frame.get("pitch_deg", 0.0))

    aligned_indices = [int(anchor_frame["frame_index"])]
    for nf in neighbor_frames:
        dyaw = abs(float(nf.get("yaw_deg", 0.0)) - anchor_yaw)
        dpitch = abs(float(nf.get("pitch_deg", 0.0)) - anchor_pitch)
        if dyaw <= max_pose_variance_deg and dpitch <= max_pose_variance_deg:
            aligned_indices.append(int(nf["frame_index"]))

    fusion_enabled = len(aligned_indices) >= 3
    return {
        "fusion_mode": "MULTI_FRAME_SUBPIXEL_FUSION" if fusion_enabled else "SINGLE_FRAME_FALLBACK",
        "fused_frame_indices": sorted(set(aligned_indices))[:10],
        "max_pose_variance_deg": max_pose_variance_deg,
        "restoration_chain": [
            "Multi-Frame Sub-Pixel Alignment" if fusion_enabled else "Single-Frame Bypass (Fast Head Turn)",
            "Zero-DCE++ (Monotonic Illumination Curve, FP32)",
            "NAFNet-SIDD (Non-Generative Blind Deblur/Denoise, FP32, 256x256 crop only)",
        ],
        "watermark_stamp": "ENHANCED (NON-GENERATIVE)",
        "generative_ai_used": False,
    }
