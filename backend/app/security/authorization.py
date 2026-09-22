"""
Role-Based Access Control (RBAC) Enforcement
"""

from typing import List
from fastapi import Depends, HTTPException, status
from backend.app.models.all_models import User
from backend.app.security.authentication import get_current_user

def require_role(allowed_roles: List[str]):
    """Returns a dependency verifying that the authenticated user possesses one of the allowed roles."""
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required roles: {allowed_roles}, your role: {current_user.role}"
            )
        return current_user
    return role_checker
