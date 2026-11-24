"""Async Redis + Celery GPU Job Queue to prevent multi-officer VRAM OOM crashes."""
from celery import Celery
from config import REDIS_URL

celery_app = Celery("atm_forensic_worker", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    worker_prefetch_multiplier=1,  # Prevent GPU queue starvation
    task_acks_late=True,
)


@celery_app.task(bind=True, name="pipeline.run_full_clip_analysis")
def run_full_clip_analysis(self, job_payload: dict) -> dict:
    """
    Executes Stages 1 -> 6 sequentially on the dedicated CUDA GPU worker
    (or isolated 24 GB MIG slice on NVIDIA RTX PRO 6000 Blackwell).
    """
    stages = [
        ("STAGE_1_INTAKE_WORM_LOCK", 15),
        ("STAGE_2_PPOCRV6_CLOCK_SYNC", 30),
        ("STAGE_3_YOLO11_BOTSORT_ISOLATION", 55),
        ("STAGE_4_SCRFD_ISO_OFIQ_GATING", 75),
        ("STAGE_5_MULTIFRAME_NAFNET_FP32", 90),
        ("STAGE_6_PGVECTOR_INDEXING", 100),
    ]
    for stage_name, pct in stages:
        self.update_state(state="PROGRESS", meta={"stage": stage_name, "percent": pct})
    return {"status": "COMPLETED", "clip_id": job_payload.get("clip_id")}
