"""Central configuration strictly aligned to the On-Premise ATM Forensic Master Spec."""
import os
from pathlib import Path

APP_TITLE = "ATM CCTV Forensic Video-Analytics Engine (RPH 2026 - PS04)"
APP_VERSION = "1.0.0"

WORM_STORAGE_DIR = Path(os.getenv("WORM_STORAGE_DIR", "./storage/worm"))
DERIVED_STORAGE_DIR = Path(os.getenv("DERIVED_STORAGE_DIR", "./storage/derived"))
EXPORT_STORAGE_DIR = Path(os.getenv("EXPORT_STORAGE_DIR", "./storage/exports"))
TEMP_SCRATCH_DIR = Path(os.getenv("TEMP_SCRATCH_DIR", "./storage/tmp"))

for _dir in (WORM_STORAGE_DIR, DERIVED_STORAGE_DIR, EXPORT_STORAGE_DIR, TEMP_SCRATCH_DIR):
    _dir.mkdir(parents=True, exist_ok=True)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev_local_onpremise_secret_change_in_prod")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://forensic_user:change_me_local@localhost:5432/atm_forensics"
)

# Precision Policy (Locked Forensic Rule)
PRECISION_POLICY = {
    "detection_tracking": "TensorRT_FP16",  # YOLO11 + BoT-SORT + SCRFD
    "restoration": "FP32_DETERMINISTIC",    # Multi-Frame + Zero-DCE++ + NAFNet (256x256 crops only)
    "biometrics": "FP32_DETERMINISTIC",     # AdaFace + PETALface
}
MAX_FUSION_POSE_VARIANCE_DEG = 5.0
