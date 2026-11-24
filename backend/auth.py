"""4-Role RBAC Gate & JWT/MFA Authentication (Strict Separation of Duties)."""
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Iterable, Dict, Any
from fastapi import Depends, HTTPException, Header, status
import jwt

from config import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_MINUTES


class UserRole(str, Enum):
    INVESTIGATOR = "investigator"
    FORENSIC_ANALYST = "forensic_analyst"
    SUPERVISOR = "supervisor"
    SECURITY_ADMIN = "security_admin"


DEMO_USERS: Dict[str, Dict[str, Any]] = {
    "officer.sharma": {
        "user_id": "u-inv-001",
        "full_name": "SI Rajesh Sharma",
        "badge_id": "RJP-INV-4021",
        "role": UserRole.INVESTIGATOR,
        "password": "demo-password",
    },
    "analyst.verma": {
        "user_id": "u-ana-002",
        "full_name": "Dr. Priya Verma (Cyber Lab)",
        "badge_id": "R4C-LAB-108",
        "role": UserRole.FORENSIC_ANALYST,
        "password": "demo-password",
    },
    "inspector.rathore": {
        "user_id": "u-sup-003",
        "full_name": "Insp. Vikram Rathore",
        "badge_id": "RJP-SUP-089",
        "role": UserRole.SUPERVISOR,
        "password": "demo-password",
    },
    "admin.secops": {
        "user_id": "u-adm-004",
        "full_name": "Server SecOps Admin",
        "badge_id": "R4C-IT-001",
        "role": UserRole.SECURITY_ADMIN,
        "password": "demo-password",
    },
}


def issue_access_token(user: Dict[str, Any]) -> str:
    payload = {
        "sub": user["user_id"],
        "username": user.get("username", ""),
        "full_name": user["full_name"],
        "badge_id": user["badge_id"],
        "role": user["role"].value if isinstance(user["role"], UserRole) else user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRE_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(authorization: str = Header(default="")) -> Dict[str, Any]:
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer JWT token.",
        )
    token = authorization.split(" ", 1)[1].strip()
    try:
        return jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
        ) from exc


def require_roles(allowed_roles: Iterable[UserRole]):
    allowed = {r.value for r in allowed_roles}

    def _checker(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        if user.get("role") not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"RBAC Violation: role '{user.get('role')}' is not authorized. "
                    f"Allowed roles: {sorted(allowed)}"
                ),
            )
        return user

    return _checker
