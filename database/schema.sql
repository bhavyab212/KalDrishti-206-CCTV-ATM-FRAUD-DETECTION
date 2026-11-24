-- ============================================================================
-- On-Premise ATM CCTV Forensic Video-Analytics Engine
-- PostgreSQL 16 + pgvector 0.8+ ACID Schema
-- Unified Case Store, Segregated HNSW Vector Indexes & Hash-Chained Audit Log
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 4-Role RBAC Enumeration (Strict Separation of Duties)
CREATE TYPE user_role AS ENUM (
    'investigator',      -- Non-Tech Police / Bank Fraud Officer
    'forensic_analyst',  -- Tech Cyber-Lab Specialist
    'supervisor',        -- Senior Inspector / Fraud Head (Co-sign & Lock PDF)
    'security_admin'     -- IT / Server Admin (Zero evidence edit access)
);

CREATE TYPE clock_sync_mode AS ENUM (
    'OSD_VERIFIED',
    'MANUAL_OVERRIDE',
    'ACTIVITY_REEL_MATCHED'
);

CREATE TYPE disguise_class AS ENUM (
    'CLEAR_FACE',
    'MASK_DETECTED',
    'CAP_SUNGLASSES',
    'FULL_HELMET',
    'INSUFFICIENT_BIOMETRIC_EVIDENCE'
);

CREATE TYPE match_mode_type AS ENUM (
    'BIOMETRIC_MATCH',
    'APPEARANCE_GAIT_LEAD'
);

-- 1. Users & RBAC Accounts
CREATE TABLE users (
    user_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username           VARCHAR(64) UNIQUE NOT NULL,
    full_name          VARCHAR(128) NOT NULL,
    badge_or_emp_id    VARCHAR(64) NOT NULL,
    role               user_role NOT NULL,
    password_hash      TEXT NOT NULL,
    mfa_secret         TEXT,
    failed_attempts    INT NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    is_active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Investigation Cases
CREATE TABLE cases (
    case_id            VARCHAR(64) PRIMARY KEY,
    atm_branch_id      VARCHAR(64) NOT NULL,
    bank_txn_id        VARCHAR(64) NOT NULL,
    bank_txn_timestamp TIMESTAMPTZ NOT NULL,
    status             VARCHAR(32) NOT NULL DEFAULT 'OPEN', -- OPEN | SUBMITTED | APPROVED_LOCKED | PURGED
    created_by         UUID NOT NULL REFERENCES users(user_id),
    approved_by        UUID REFERENCES users(user_id),
    approved_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. Immutable Raw CCTV Clips (WORM Storage Pointers + Stage 1/2 Metadata)
CREATE TABLE clips (
    clip_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id             VARCHAR(64) NOT NULL REFERENCES cases(case_id),
    original_filename   VARCHAR(255) NOT NULL,
    worm_storage_path   TEXT NOT NULL,
    raw_clip_sha256     CHAR(64) NOT NULL,
    normalized_path     TEXT,
    dvr_make_model      VARCHAR(128),
    codec_name          VARCHAR(32),
    is_vfr              BOOLEAN NOT NULL DEFAULT FALSE,
    frame_rate          NUMERIC(6,2),
    duration_sec        NUMERIC(10,2),
    clock_offset_sec    INT NOT NULL DEFAULT 0,
    sync_mode           clock_sync_mode NOT NULL DEFAULT 'OSD_VERIFIED',
    roi_keypad_polygon  JSONB,  -- Auto-detected via YOLO-World/YOLOE, editable by Forensic Analyst
    fisheye_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    index_in_cross_clip BOOLEAN NOT NULL DEFAULT TRUE, -- Optional Single-Clip Non-Indexed Toggle
    uploaded_by         UUID NOT NULL REFERENCES users(user_id),
    uploaded_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Isolated Suspect Tracklets (Bystanders Auto-Wiped; Only Active User & Flagged Accomplices Stored)
-- Segregated Vector Spaces: face_vec (AdaFace/PETALface), reid_vec (OSNet/CAL), gait_vec (OpenGait)
CREATE TABLE suspect_tracklets (
    tracklet_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clip_id                 UUID NOT NULL REFERENCES clips(clip_id),
    case_id                 VARCHAR(64) NOT NULL REFERENCES cases(case_id),
    atm_branch_id           VARCHAR(64) NOT NULL,
    track_label             VARCHAR(32) NOT NULL, -- ACTIVE_USER | ACCOMPLICE_SWAP | SHOULDER_SURFING
    start_frame_idx         INT NOT NULL,
    end_frame_idx           INT NOT NULL,
    start_pts_sec           NUMERIC(10,3) NOT NULL,
    end_pts_sec             NUMERIC(10,3) NOT NULL,
    roi_dwell_sec           NUMERIC(8,2) NOT NULL DEFAULT 0.0,
    shoulder_surfing_flag   BOOLEAN NOT NULL DEFAULT FALSE,
    accomplice_swap_flag    BOOLEAN NOT NULL DEFAULT FALSE,
    is_ir_night             BOOLEAN NOT NULL DEFAULT FALSE, -- Computed PER TRACKLET (handles dusk->night switch)
    disguise_state          disguise_class NOT NULL,
    attributes_json         JSONB NOT NULL DEFAULT '{}'::jsonb, -- helmet_type, jacket_style, jacket_color, bag_type
    walking_frame_count     INT NOT NULL DEFAULT 0,
    -- Separate typed embeddings so incompatible vector spaces never collide
    face_vec                vector(512), -- Path A: AdaFace + PETALface (FP32); NULL when FULL_HELMET (Hard Block)
    reid_vec                vector(512), -- Path B: OSNet / VI-ReID / CAL-OC4-ReID
    gait_vec                vector(256), -- Path B: OpenGait (GaitBase / DeepGaitV2), populated when >=15 walk frames
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Dedicated HNSW Cosine Indexes (Use with pgvector 0.8+: SET LOCAL hnsw.iterative_scan = relaxed_order;)
CREATE INDEX idx_tracklets_face_hnsw
    ON suspect_tracklets USING hnsw (face_vec vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX idx_tracklets_reid_hnsw
    ON suspect_tracklets USING hnsw (reid_vec vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX idx_tracklets_gait_hnsw
    ON suspect_tracklets USING hnsw (gait_vec vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX idx_tracklets_meta_filter
    ON suspect_tracklets (atm_branch_id, disguise_state, is_ir_night, created_at);

-- 5. Top-Ranked Face Frames (Untouched Raw Crop + Derived Non-Generative Enhanced Copy)
CREATE TABLE evidence_frames (
    frame_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tracklet_id             UUID NOT NULL REFERENCES suspect_tracklets(tracklet_id),
    clip_id                 UUID NOT NULL REFERENCES clips(clip_id),
    frame_index             INT NOT NULL,
    pts_sec                 NUMERIC(10,3) NOT NULL,
    raw_crop_path           TEXT NOT NULL,     -- Saved BEFORE any fisheye undistortion or enhancement
    raw_crop_sha256         CHAR(64) NOT NULL,
    enhanced_crop_path      TEXT,              -- Stamped ENHANCED (NON-GENERATIVE)
    enhanced_crop_sha256    CHAR(64),
    ofiq_unified_score      NUMERIC(5,2) NOT NULL, -- ISO/IEC 29794-5 (0-100)
    usability_tier          VARCHAR(16) NOT NULL,  -- HIGH | MEDIUM | LOW
    ofiq_subscores_json     JSONB NOT NULL,        -- sharpness, illumination, glare, yaw, pitch, roll, occlusion
    restoration_params_json JSONB,                 -- multi_frame_indices, pose_var_deg, zero_dce, nafnet_fp32_sha256
    rank_order              INT NOT NULL
);

-- 6. Cross-Clip Investigative Leads (Human-in-the-Loop Verification)
CREATE TABLE cross_clip_leads (
    lead_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id               VARCHAR(64) NOT NULL REFERENCES cases(case_id),
    query_tracklet_id     UUID NOT NULL REFERENCES suspect_tracklets(tracklet_id),
    matched_tracklet_id   UUID NOT NULL REFERENCES suspect_tracklets(tracklet_id),
    match_mode            match_mode_type NOT NULL,
    similarity_score      NUMERIC(6,4) NOT NULL,
    enhanced_query_used   BOOLEAN NOT NULL DEFAULT FALSE,
    ir_color_dropped      BOOLEAN NOT NULL DEFAULT FALSE,
    reliability_warning   TEXT,
    verification_status   VARCHAR(16) NOT NULL DEFAULT 'PENDING', -- PENDING | CONFIRMED | REJECTED
    verified_by           UUID REFERENCES users(user_id),
    officer_notes         TEXT,
    verified_at           TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Append-Only Cryptographically Hash-Chained Audit Ledger (BSA Section 63 / FISWG / ENFSI)
CREATE TABLE audit_log (
    log_id          BIGSERIAL PRIMARY KEY,
    case_id         VARCHAR(64),
    user_id         UUID REFERENCES users(user_id),
    user_role       user_role,
    action          VARCHAR(64) NOT NULL,
    clip_sha256     CHAR(64),
    parameters_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    prev_hash       CHAR(64) NOT NULL,
    curr_hash       CHAR(64) NOT NULL
);

-- Enforce strict immutability: nobody (not even Security Admin) can UPDATE or DELETE audit rows
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'FORENSIC INTEGRITY VIOLATION: audit_log is strictly append-only (BSA Section 63).';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_immutable
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
