#!/usr/bin/env bash
set -euo pipefail

# On-Premise Model Weight Provisioning Script (Run once before air-gapping server)
# Weights are intentionally excluded from Git via .gitignore.

mkdir -p models/weights/{detection,ocr,quality,restoration,biometrics,reid,gait}

echo "=== On-Premise Forensic Model Provisioning Checklist ==="
echo "[Stage 2] PP-OCRv6 (PaddleOCR v3.7 dot-matrix OSD)     -> models/weights/ocr/"
echo "[Stage 3] YOLO-World / YOLOE + YOLO11 + BoT-SORT FP16  -> models/weights/detection/"
echo "[Stage 4] SCRFD-10G (5-pt landmarks) + ISO OFIQ        -> models/weights/quality/"
echo "[Stage 5] PaddleClas PULC / SigLIP + Zero-DCE++ FP32   -> models/weights/restoration/"
echo "[Stage 5] NAFNet-SIDD-width64 (FP32 Non-Generative)    -> models/weights/restoration/"
echo "[Stage 6] AdaFace IR-101 + PETALface Dual-LoRA (FP32)  -> models/weights/biometrics/"
echo "[Stage 6] OSNet + VI-ReID + CAL/OC4-ReID               -> models/weights/reid/"
echo "[Stage 6] OpenGait (GaitBase / DeepGaitV2)             -> models/weights/gait/"
echo "Record SHA-256 of every weight file into the deterministic audit configuration."
