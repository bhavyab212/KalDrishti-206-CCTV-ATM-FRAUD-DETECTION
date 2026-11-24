"""Append-Only Cryptographically Hash-Chained Audit Ledger (BSA Section 63)."""
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


GENESIS_HASH = "0" * 64


class HashChainedAuditLedger:
    """
    Maintains curr_hash = SHA256(prev_hash || canonical_json(row_payload)).
    In production this writes directly to PostgreSQL `audit_log` protected by
    the `prevent_audit_mutation()` BEFORE UPDATE OR DELETE trigger.
    """

    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []

    @staticmethod
    def _compute_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(f"{prev_hash}||{canonical}".encode("utf-8")).hexdigest()

    def append(
        self,
        case_id: str,
        user_id: str,
        user_role: str,
        action: str,
        parameters: Dict[str, Any],
        clip_sha256: Optional[str] = None,
    ) -> Dict[str, Any]:
        prev_hash = self._entries[-1]["curr_hash"] if self._entries else GENESIS_HASH
        payload = {
            "log_id": len(self._entries) + 1,
            "case_id": case_id,
            "user_id": user_id,
            "user_role": user_role,
            "action": action,
            "clip_sha256": clip_sha256,
            "parameters": parameters,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        curr_hash = self._compute_hash(prev_hash, payload)
        record = {**payload, "prev_hash": prev_hash, "curr_hash": curr_hash}
        self._entries.append(record)
        return record

    def verify_chain(self, case_id: Optional[str] = None) -> Dict[str, Any]:
        prev_hash = GENESIS_HASH
        checked = 0
        for row in self._entries:
            payload = {
                "log_id": row["log_id"],
                "case_id": row["case_id"],
                "user_id": row["user_id"],
                "user_role": row["user_role"],
                "action": row["action"],
                "clip_sha256": row["clip_sha256"],
                "parameters": row["parameters"],
                "created_at": row["created_at"],
            }
            expected = self._compute_hash(prev_hash, payload)
            if row["prev_hash"] != prev_hash or row["curr_hash"] != expected:
                return {
                    "chain_intact": False,
                    "broken_at_log_id": row["log_id"],
                    "entries_verified": checked,
                }
            prev_hash = row["curr_hash"]
            if case_id is None or row["case_id"] == case_id:
                checked += 1

        return {
            "chain_intact": True,
            "case_id": case_id,
            "entries_verified": checked,
            "latest_hash": prev_hash,
        }

    def list_case_logs(self, case_id: str) -> List[Dict[str, Any]]:
        return [row for row in self._entries if row["case_id"] == case_id]


audit_ledger = HashChainedAuditLedger()
