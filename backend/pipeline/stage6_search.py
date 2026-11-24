"""
Stage 6 — Multi-Modal Cross-Clip Search (Two-Path Disguise & Night-IR Router).
Database: PostgreSQL 16 + pgvector 0.8+ (`SET LOCAL hnsw.iterative_scan = relaxed_order;`).
Segregated Vector Columns: `face_vec` (Path A) vs `reid_vec` & `gait_vec` (Path B).
"""
from typing import Dict, Any, List


def build_two_path_search_plan(
    disguise_state: str,
    is_ir_night: bool,
    ofiq_score: float,
    walking_frame_count: int,
    attributes: Dict[str, Any],
    cross_day_clothing_change: bool = False,
    enhanced_query_used: bool = False,
) -> Dict[str, Any]:
    """
    Deterministically routes cross-clip matching:
      - Path A (CLEAR_FACE / MASK_DETECTED / CAP_SUNGLASSES):
          AdaFace + PETALface (FP32) on `face_vec` -> Biometric Match.
      - Path B (FULL_HELMET):
          HARD BLOCK on facial biometrics -> OSNet + Clothing/Bag Attributes +
          IR Color Guardrail (VI-ReID) + CAL/OC4-ReID + OpenGait -> Appearance / Gait Lead.
      - Honest Physical Boundary:
          Flags INSUFFICIENT_BIOMETRIC_EVIDENCE if motionless full helmet + clothing change.
    """
    if disguise_state == "FULL_HELMET":
        if cross_day_clothing_change and walking_frame_count < 15:
            return {
                "route": "HALTED",
                "biometric_face_search_blocked": True,
                "status_flag": "INSUFFICIENT_BIOMETRIC_EVIDENCE",
                "reason": (
                    "Full helmet blocks facial biometrics, cross-day clothing change invalidates "
                    "appearance color/texture cues, and <15 walking frames exist for OpenGait."
                ),
            }

        active_filters = dict(attributes)
        ir_color_dropped = False
        if is_ir_night:
            # Avigilon-inspired IR Night-Vision Color Guardrail
            for key in list(active_filters.keys()):
                if "color" in key.lower():
                    active_filters.pop(key, None)
            ir_color_dropped = True

        models: List[str] = [
            "VI-ReID (Cross-Modality Structural Re-ID)" if is_ir_night else "OSNet (Upper-Body Appearance Re-ID)",
            "PaddleClas PULC / SigLIP Structured Attributes (Helmet/Jacket/Bag)",
        ]
        target_columns = ["reid_vec"]
        if cross_day_clothing_change:
            models.append("CAL / OC4-ReID (Cloth-Changing Body-Shape Re-ID)")
        if walking_frame_count >= 15:
            models.append("OpenGait (GaitBase / DeepGaitV2 Behavioral Biometric)")
            target_columns.append("gait_vec")

        return {
            "route": "PATH_B_APPEARANCE_GAIT",
            "match_mode": "APPEARANCE_GAIT_LEAD",
            "biometric_face_search_blocked": True,
            "models": models,
            "pgvector_columns": target_columns,
            "pgvector_sql_hint": "SET LOCAL hnsw.iterative_scan = relaxed_order;",
            "ir_color_guardrail_applied": ir_color_dropped,
            "effective_attribute_filters": active_filters,
            "reliability_warning": (
                "Visual/Behavioral Lead ONLY (Full Helmet). Biometric face search blocked; "
                "requires strict human investigator verification."
            ),
        }

    # Path A: Visible or Partially Occluded Face
    encoder = "PETALface (Dual-LoRA Ultra-Low-Res FP32)" if ofiq_score < 55.0 else "AdaFace (Quality-Adaptive FP32)"
    warnings = []
    if disguise_state in ("MASK_DETECTED", "CAP_SUNGLASSES"):
        warnings.append(f"Partial occlusion ({disguise_state}): periocular/upper-face confidence lowered.")
    if enhanced_query_used:
        warnings.append("Enhanced-Query Lead: match searched on non-generative enhanced crop.")

    return {
        "route": "PATH_A_BIOMETRIC_FACE",
        "match_mode": "BIOMETRIC_MATCH",
        "biometric_face_search_blocked": False,
        "models": [encoder],
        "pgvector_columns": ["face_vec"],
        "pgvector_sql_hint": "SET LOCAL hnsw.iterative_scan = relaxed_order;",
        "ir_color_guardrail_applied": False,
        "reliability_warning": " ".join(warnings) if warnings else None,
    }
