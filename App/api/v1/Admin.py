# App/api/v1/Admin.py
"""
Admin endpoints: user account management, permissions, and safety-mode reset.

Routes:
    PUT    /account/{user_id}                   — update user account
    POST   /account/disable/{user_id}           — disable user
    POST   /account/enable/{user_id}            — enable user
    POST   /account/temp_token/{user_id}        — issue short-lived token (SLT)
    DELETE /account/{user_id}                   — soft-delete user
    POST   /account/restore/{user_id}           — restore soft-deleted/disabled user
    PUT    /account/password/{user_id}          — change password
    POST   /reset-auto-kill                     — clear safety mode
    GET    /get_all_permissions                 — list permission catalog
    POST   /set_permissions                     — set single user's permissions
    POST   /set_permissions_bulk                — set multiple users' permissions
    GET    /users/permissions                   — read user permissions
    DELETE /remove_permissions                  — remove permissions
"""

from datetime import timedelta
from typing import Optional, Dict, Any

from fastapi import (
    APIRouter, Depends, HTTPException, status, Query, Request, Response,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from App.repository.UserRepository import UserRepository
from App.core.LoggingInit import get_core_logger
from App.core.Connector import get_db
from App.core.settings import settings
from App.core.exceptions import (
    DomainError,
    UserNotFoundError,
    DuplicateEmailError,
    AccountAlreadyDisabledError,
)
from App.schemas.AuthScheema import UserResponse
from App.models.UserAuthModel import UpdateUser
from App.models.Permissions import Permission
from App.models.PermissionModel import (
    PermissionModel,
    BulkPermissionModel,
    RemovePermissionsModel,
)
from App.api.dependencies.auth import (
    verify_password,
    get_current_user,
    get_password_hash,
    create_short_live_token,
    get_current_user_slt,
)
from App.api.dependencies.permissions import require_permission


admin_router = APIRouter(prefix="/admin_access", tags=["Admin"])
logger = get_core_logger(__name__)


# ============================================================================
# Helper: SLT detection
# ============================================================================
def _is_slt(current_user: Dict[str, Any]) -> bool:
    """True when the auth context comes from a short-lived token."""
    return (
        current_user.get("types") == "slts"
        or current_user.get("token_type") == "slts"
    )


# ============================================================================
# PUT /account/{user_id}
# ============================================================================
@admin_router.put(
    "/account/{user_id}",
    response_model=UserResponse,
    summary="Update user account",
    description=(
        "Update user information. Admin can update any user; "
        "users can only update themselves."
    ),
)
async def update_account(
    request: Request,
    user_id: int,
    update_data: UpdateUser,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            [
                Permission.ADMIN_SETTINGS_UPDATE,
                Permission.ADMIN_USERS_PROMOTE,
                Permission.USER_UPDATE_SELF,
                Permission.USER_UPDATE_PROFILE,
            ],
            mode="any",
            bypass_admin=False,
        )
    ),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        current_user_id = current_user.get("id")
        current_user_role = current_user.get("role")
        current_user_perms = current_user.get("permissions", {}) or {}
        current_user_email = current_user.get("email")

        target_user = await repo.get_by_id(user_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        is_admin = current_user_role == "admin"
        is_self = current_user_id == user_id

        has_admin_update_permission = (
            current_user_perms.get("admin.settings.update", False)
            or current_user_perms.get("admin.users.promote", False)
        )
        has_self_update_permission = (
            current_user_perms.get("user.update.self", False)
            or current_user_perms.get("user.update.profile", False)
        )

        if is_admin or has_admin_update_permission:
            pass
        elif is_self and has_self_update_permission:
            pass
        else:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to update this user's account",
            )

        update_dict = update_data.model_dump(exclude_unset=True)
        if not update_dict:
            raise HTTPException(status_code=400, detail="No fields to update")

        sensitive_fields = ["user_role", "disabled", "is_active"]
        if not (is_admin or has_admin_update_permission):
            for field in sensitive_fields:
                if field in update_dict:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Only admin or users with admin permissions can update '{field}'",
                    )

        if is_admin and is_self:
            for locked_field in ("user_role", "permissions", "disabled", "is_active"):
                if locked_field in update_dict:
                    raise HTTPException(
                        status_code=403,
                        detail=f"Admin cannot change their own '{locked_field}'",
                    )

        if "email" in update_dict and update_dict["email"] != target_user.email:
            existing = await repo.get_by_email(update_dict["email"])
            if existing and existing.id != user_id:
                raise HTTPException(status_code=400, detail="Email already in use")

        if "password" in update_dict:
            update_dict["password_hash"] = get_password_hash(update_dict["password"])
            del update_dict["password"]

        updated_user = await repo.update(user_id, update_dict)
        logger.info(f"[{req_id}] User {user_id} updated by {current_user_email}")
        return UserResponse.model_validate(updated_user)

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DuplicateEmailError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Update account DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Update account unexpected error")
        raise HTTPException(status_code=500, detail="Update failed")


# ============================================================================
# POST /account/disable/{user_id}
# ============================================================================
@admin_router.post(
    "/account/disable/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable user account",
    description=(
        "Disable user account. Admin can disable any user; "
        "users can only disable themselves with password verification."
    ),
)
async def disable_account(
    request: Request,
    user_id: int,
    password: Optional[str] = Query(None, description="Required for non-admin users"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        current_user_id = current_user.get("id")
        current_user_role = current_user.get("role")
        current_user_perms = current_user.get("permissions", {}) or {}

        if isinstance(current_user_perms, str):
            import json
            try:
                current_user_perms = json.loads(current_user_perms)
            except (ValueError, TypeError):
                current_user_perms = {}

        target_user = await repo.get_by_id(user_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        if target_user.disabled:
            raise HTTPException(status_code=409, detail="Account already disabled")

        is_admin = current_user_role == "admin"
        is_self = current_user_id == user_id

        has_promote_permission = current_user_perms.get("admin.users.promote", False)
        has_restore_permission = current_user_perms.get("admin.users.restore", False)
        has_self_disable = current_user_perms.get("user.disable.self", False)

        can_disable_any = is_admin or has_promote_permission or has_restore_permission
        can_disable_self = is_self and has_self_disable

        if can_disable_any:
            await repo.disable_account(user_id)
            logger.info(f"[{req_id}] User {current_user_id} disabled user {user_id}")
            return

        if can_disable_self:
            if not password:
                raise HTTPException(
                    status_code=400, detail="Password required for self-disable"
                )
            if not verify_password(password, target_user.password_hash):
                raise HTTPException(status_code=401, detail="Incorrect password")
            await repo.disable_account(user_id)
            logger.info(f"[{req_id}] User {user_id} disabled their own account")
            return

        raise HTTPException(
            status_code=403, detail="Insufficient permissions to disable this account"
        )

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except AccountAlreadyDisabledError:
        raise HTTPException(status_code=409, detail="Account already disabled")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Disable account DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Disable account unexpected error")
        raise HTTPException(status_code=500, detail="Disable failed")


# ============================================================================
# POST /account/enable/{user_id}
# ============================================================================
@admin_router.post(
    "/account/enable/{user_id}",
    summary="Enable a disabled or inactive user account",
    description=(
        "Admin or user with admin permission can enable any user. "
        "A user with self-enable permission can only enable themselves. "
        "An SLT token can enable its own user."
    ),
)
async def enable_account(
    request: Request,
    user_id: int,
    password: Optional[str] = Query(None),
    current_user: Dict[str, Any] = Depends(
        require_permission(
            required_permissions=[
                Permission.USER_SELF_ENABLE,
                Permission.ADMIN_USER_ENABLE,
                Permission.ADMIN_USERS_PROMOTE,
            ],
            mode="any",
            bypass_admin=False,
            additional_dependency=get_current_user_slt,
        )
    ),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        cur_id = current_user.get("id")
        cur_role = current_user.get("role")
        cur_perms = current_user.get("permissions", {}) or {}
        is_slt_token = _is_slt(current_user)

        is_admin = cur_role == "admin"
        is_self = cur_id == user_id

        has_admin_enable = cur_perms.get("admin.user.enable", False)
        has_admin_promote = cur_perms.get("admin.users.promote", False)
        has_self_enable = cur_perms.get("user.self.enable", False)

        can_enable_any = is_admin or has_admin_enable or has_admin_promote

        # -- Permission gate --
        if is_slt_token:
            if current_user.get("token_purpose") != "account_restoration":
                raise HTTPException(
                    status_code=403,
                    detail="SLT token is not valid for account enablement",
                )
            if cur_id != user_id:
                raise HTTPException(
                    status_code=403,
                    detail=f"SLT token can only enable user {cur_id}, not {user_id}",
                )
        elif can_enable_any:
            pass
        elif has_self_enable:
            if not is_self:
                raise HTTPException(
                    status_code=403,
                    detail="You can only enable your own account",
                )
        else:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to enable this account",
            )

        target_user = await repo.get_by_id(user_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        if not target_user.disabled and target_user.is_active:
            raise HTTPException(
                status_code=400, detail="User is already active. No enable needed."
            )
        if target_user.is_deleted:
            raise HTTPException(
                status_code=400,
                detail="User is deleted. Use restore endpoint instead.",
            )

        # -- Perform enable --
        if is_slt_token:
            success = await repo.full_restore(user_id)
            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to enable account with SLT token"
                )
            return {
                "status": "success",
                "message": f"Account {user_id} enabled via SLT token",
                "user_id": user_id,
                "user_email": target_user.email,
                "enabled_by": "SLT Token",
            }

        if is_admin:
            success = await repo.full_restore(user_id)
            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to enable user account"
                )
            return {
                "status": "success",
                "message": f"User {user_id} enabled by admin",
                "user_id": user_id,
                "user_email": target_user.email,
                "enabled_by": "Admin",
            }

        if has_admin_enable or has_admin_promote:
            success = await repo.full_restore(user_id)
            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to enable user account"
                )
            return {
                "status": "success",
                "message": f"User {user_id} enabled by user with permission",
                "user_id": user_id,
                "user_email": target_user.email,
                "enabled_by": "User with permission",
            }

        if is_self:
            if not password:
                raise HTTPException(
                    status_code=400, detail="Password required for self-enable"
                )
            if not verify_password(password, target_user.password_hash):
                raise HTTPException(status_code=401, detail="Incorrect password")
            success = await repo.full_restore(user_id)
            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to enable your account"
                )
            return {
                "status": "success",
                "message": "Your account has been enabled successfully",
                "user_id": user_id,
                "user_email": target_user.email,
                "enabled_by": "Self",
            }

        raise HTTPException(
            status_code=403,
            detail="You don't have permission to enable this account",
        )

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Enable account DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Enable account unexpected error")
        raise HTTPException(status_code=500, detail="Failed to enable account")


# ============================================================================
# POST /account/temp_token/{user_id}
# ============================================================================
@admin_router.post(
    "/account/temp_token/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Make temp token for user to change password and restore accounts",
    description=(
        "Make temporary token expire in 2 min for user to restore "
        "disabled/deleted account or reset password."
    ),
)
async def temp_token_maker(
    request: Request,
    response: Response,
    user_id: int,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            required_permissions=[
                Permission.ADMIN_USERS_PROMOTE,
                Permission.ADMIN_USERS_RESTORE,
                Permission.ADMIN_USERS_DISABLE,
            ],
            mode="any",
            bypass_admin=True,
        )
    ),
    db: AsyncSession = Depends(get_db),
    cookie_login: bool = False,
    restore_passwd: bool = False,
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        if current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin can access this",
            )

        target_user = await repo.get_by_id(user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        token_purpose = (
            "password_restore" if restore_passwd else "account_restoration"
        )

        if restore_passwd:
            logger.info(f"[{req_id}] Password restore token requested for user {user_id}")
        else:
            if not (
                target_user.disabled
                or not target_user.is_active
                or target_user.is_deleted
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User is already active and valid. No restoration needed.",
                )

        temp_token = await create_short_live_token(user_id, db, purpose=token_purpose)

        if cookie_login:
            response.set_cookie(
                key="CSO",
                value=temp_token,
                httponly=True,
                secure=settings.COOKIE_SECURE,
                samesite="lax",
                max_age=120,  # 2 minutes
                path="/",
                domain=None,
            )
            return {
                "status": "success",
                "message": "Temporary token created and set as cookie",
                "user_id": target_user.id,
                "user_name": target_user.name,
                "purpose": token_purpose,
                "expires_in_minutes": 2,
            }

        return {
            "status": "success",
            "message": "Temporary token created",
            "user_id": target_user.id,
            "user_name": target_user.name,
            "user_status": (
                {
                    "disabled": target_user.disabled,
                    "is_active": target_user.is_active,
                    "is_deleted": target_user.is_deleted,
                }
                if not restore_passwd
                else None
            ),
            "purpose": token_purpose,
            "temp_token": temp_token,
            "expires_in_minutes": 2,
        }

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Temp token DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Temp token unexpected error")
        raise HTTPException(status_code=500, detail="Failed to create temp token")


# ============================================================================
# POST /reset-auto-kill
# ============================================================================
@admin_router.post(
    "/reset-auto-kill",
    status_code=status.HTTP_200_OK,
    summary="Reset Auto-Kill Switch",
    description=(
        "Allows administrators to reset the system from safety mode "
        "after an internal error."
    ),
)
async def reset_auto_kill(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    req_id = getattr(request.state, "request_id", "-")
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can reset the safety mode",
        )

    # NOTE: The middleware uses Redis (kill_switch:auto_kill_until) for
    # shared multi-worker state. This endpoint clears that key.
    try:
        from App.core.RedisConnector import redis_client
        await redis_client.client.delete("kill_switch:auto_kill_until")
    except Exception:
        logger.exception(f"[{req_id}] Failed to clear auto-kill Redis key")
        raise HTTPException(
            status_code=503,
            detail="Could not clear safety mode — Redis unavailable",
        )

    logger.info(
        f"[{req_id}] Safety mode reset by admin: {current_user.get('email')}"
    )
    return {"status": "success", "message": "System safety mode has been reset."}


# ============================================================================
# DELETE /account/{user_id}
# ============================================================================
@admin_router.delete(
    "/account/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete account",
    description=(
        "Soft-delete a user account. Admin can delete any user; "
        "users can delete themselves with password verification."
    ),
)
async def delete_account(
    request: Request,
    user_id: int,
    password: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            required_permissions=[
                Permission.USER_DELETE_SELF,
                Permission.ADMIN_USERS_DELETE,
                Permission.ADMIN_USERS_PROMOTE,
            ],
            mode="any",
            bypass_admin=False,
        )
    ),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        cur_role = current_user.get("role")
        cur_id = current_user.get("id")
        cur_perms = current_user.get("permissions", {}) or {}

        is_self_deletion = cur_id == user_id
        is_admin = cur_role == "admin"

        has_admin_delete = cur_perms.get("admin.users.delete", False)
        has_admin_promote = cur_perms.get("admin.users.promote", False)

        can_delete_any = is_admin or has_admin_delete or has_admin_promote

        if can_delete_any:
            target_user = await repo.get_by_id(user_id)
            if not target_user:
                raise HTTPException(status_code=404, detail="User not found")
            if target_user.is_deleted:
                raise HTTPException(status_code=409, detail="User is already deleted")
            if is_self_deletion:
                raise HTTPException(
                    status_code=403, detail="You cannot delete your own account"
                )
            success = await repo.delete_account(user_id)
            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to delete user account"
                )
            return {
                "status": "success",
                "message": f"User {user_id} deleted by {current_user.get('email')}",
            }

        if is_self_deletion:
            target_user = await repo.get_by_id(user_id)
            if not target_user:
                raise HTTPException(status_code=404, detail="User not found")
            if target_user.is_deleted:
                raise HTTPException(status_code=409, detail="User is already deleted")
            if not password:
                raise HTTPException(
                    status_code=400, detail="Password required for self-deletion"
                )
            if not verify_password(password, target_user.password_hash):
                raise HTTPException(status_code=401, detail="Incorrect password")
            success = await repo.delete_account(user_id)
            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to delete your account"
                )
            return {
                "status": "success",
                "message": "Your account has been soft deleted",
            }

        raise HTTPException(
            status_code=403,
            detail="You don't have permission to delete this account",
        )

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Delete account DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Delete account unexpected error")
        raise HTTPException(status_code=500, detail="Failed to delete account")


# ============================================================================
# POST /account/restore/{user_id}
# ============================================================================
@admin_router.post(
    "/account/restore/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Restore deleted/disabled account",
    description=(
        "Restore a soft-deleted or disabled account. Admin can restore any "
        "user. Users can restore themselves with an SLT token."
    ),
)
async def restore_account(
    request: Request,
    user_id: int,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            required_permissions=[
                Permission.ADMIN_USERS_RESTORE,
                Permission.ADMIN_USERS_PROMOTE,
            ],
            mode="any",
            bypass_admin=False,
            additional_dependency=get_current_user_slt,
        )
    ),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        cur_role = current_user.get("role")
        cur_id = current_user.get("id")
        cur_perms = current_user.get("permissions", {}) or {}
        is_slt_token = _is_slt(current_user)
        is_admin = cur_role == "admin"

        has_restore_permission = cur_perms.get("admin.users.restore", False)
        has_promote_permission = cur_perms.get("admin.users.promote", False)
        can_restore_any = (
            is_admin
            or has_restore_permission
            or has_promote_permission
            or is_slt_token
        )

        # -- SLT bypass --
        if is_slt_token:
            if current_user.get("token_purpose") != "account_restoration":
                raise HTTPException(
                    status_code=403,
                    detail="SLT token is not valid for account restoration",
                )
            slt_user_id = current_user.get("id")
            if slt_user_id != user_id:
                logger.warning(
                    f"[{req_id}] SLT token {slt_user_id} tried to restore user {user_id}"
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"SLT token can only restore user {slt_user_id}, not {user_id}",
                )

            target_user = await repo.get_by_id(user_id)
            if not target_user:
                raise HTTPException(status_code=404, detail="User not found")
            if (
                not target_user.is_deleted
                and not target_user.disabled
                and target_user.is_active
            ):
                raise HTTPException(
                    status_code=400,
                    detail="User is already active. No restoration needed.",
                )

            success = await repo.restore_deleted(user_id)
            if not success:
                success = await repo.restore_disable(user_id)
            if not success:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to restore account with SLT token",
                )
            logger.info(f"[{req_id}] SLT token restored user {user_id}")
            return {
                "status": "success",
                "message": f"Account {user_id} restored via SLT token",
                "user_id": user_id,
                "user_email": target_user.email,
                "restored_by": "SLT Token",
            }

        # -- Normal permission check --
        if not can_restore_any:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to restore accounts",
            )

        target_user = await repo.get_by_id(user_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        if (
            not target_user.is_deleted
            and not target_user.disabled
            and target_user.is_active
        ):
            raise HTTPException(
                status_code=400,
                detail="User is already active. No restoration needed.",
            )

        success = False
        if target_user.is_deleted:
            success = await repo.restore_deleted(user_id)
        if not success:
            success = await repo.restore_disable(user_id)
        if not success:
            raise HTTPException(
                status_code=500, detail="Failed to restore user account"
            )

        restored_by = "Admin" if is_admin else "User with permission"
        logger.info(f"[{req_id}] {restored_by} restored user {user_id}")
        return {
            "status": "success",
            "message": f"User {user_id} restored by {restored_by}",
            "user_id": user_id,
            "user_email": target_user.email,
            "restored_by": restored_by,
        }

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Restore account DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Restore account unexpected error")
        raise HTTPException(status_code=500, detail="Failed to restore account")


# ============================================================================
# PUT /account/password/{user_id}
# ============================================================================
@admin_router.put(
    "/account/password/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Update user password",
    description=(
        "Admin can update any user's password. Normal users update their "
        "own password. SLT token can only update its own user's password."
    ),
)
async def update_password(
    request: Request,
    user_id: int,
    new_password: str,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            required_permissions=[
                Permission.USER_UPDATE_PASSWORD,
                Permission.ADMIN_ANY_PASSWORD_UPDATE,
            ],
            mode="any",
            bypass_admin=False,
            additional_dependency=get_current_user_slt,
        )
    ),
    old_password: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        cur_role = current_user.get("role")
        cur_id = current_user.get("id")
        is_slt_token = _is_slt(current_user)
        slt_user_id = current_user.get("user_id")
        cur_perms = current_user.get("permissions", {}) or {}

        has_admin_any = cur_perms.get("admin.anyuser.password.update", False)
        has_user_update = cur_perms.get("user.update.password", False)

        target_user = await repo.get_by_id(user_id)
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")

        is_self_update = cur_id == user_id
        is_admin = cur_role == "admin"
        can_update_any = is_admin or has_admin_any
        can_update_self = has_user_update and is_self_update

        # CASE 1 — SLT token
        if is_slt_token:
            if current_user.get("token_purpose") != "password_restore":
                raise HTTPException(
                    status_code=403,
                    detail="SLT token is not valid for password reset",
                )
            if slt_user_id != user_id:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"SLT token can only update password for user "
                        f"{slt_user_id}, not {user_id}"
                    ),
                )
            new_hash = get_password_hash(new_password)
            success = await repo.update_password_hash(user_id, new_hash)
            if not success:
                raise HTTPException(
                    status_code=500,
                    detail="Failed to update password with SLT token",
                )
            return {
                "status": "success",
                "message": f"Password updated via SLT token for user {user_id}",
                "user_id": user_id,
                "user_email": target_user.email,
                "updated_by": "SLT Token",
            }

        # CASE 2 — Admin or admin-permission
        if can_update_any:
            new_hash = get_password_hash(new_password)
            success = await repo.update_password_hash(user_id, new_hash)
            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to update password"
                )
            updated_by = "Admin" if is_admin else "User with admin permission"
            return {
                "status": "success",
                "message": f"Password updated by {updated_by} for user {user_id}",
                "user_id": user_id,
                "user_email": target_user.email,
                "updated_by": updated_by,
            }

        # CASE 3 — Self update
        if can_update_self:
            if not old_password:
                raise HTTPException(
                    status_code=400,
                    detail="Old password is required to change your password",
                )
            if not verify_password(old_password, target_user.password_hash):
                raise HTTPException(status_code=401, detail="Incorrect old password")
            new_hash = get_password_hash(new_password)
            success = await repo.update_password_hash(user_id, new_hash)
            if not success:
                raise HTTPException(
                    status_code=500, detail="Failed to update your password"
                )
            return {
                "status": "success",
                "message": "Your password has been updated successfully",
                "user_id": user_id,
                "user_email": target_user.email,
                "updated_by": "Self",
            }

        raise HTTPException(
            status_code=403,
            detail="You don't have permission to update this user's password",
        )

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Update password DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Update password unexpected error")
        raise HTTPException(status_code=500, detail="Failed to update password")


# ============================================================================
# GET /get_all_permissions
# ============================================================================
@admin_router.get(
    "/get_all_permissions",
    summary="List all permissions in the catalog",
)
async def get_all_permissions(
    request: Request,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            required_permissions=[Permission.ADMIN_USERS_PROMOTE],
            mode="any",
            bypass_admin=False,
        )
    ),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        return [{"name": p.name, "value": p.value} for p in Permission]
    except HTTPException:
        raise
    except Exception:
        logger.exception(f"[{req_id}] Failed to list permissions")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving permissions",
        )


# ============================================================================
# POST /set_permissions
# ============================================================================
@admin_router.post(
    "/set_permissions",
    summary="Set permissions for a single user",
)
async def set_permissions(
    request: Request,
    pm: PermissionModel,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            required_permissions=[Permission.ADMIN_USERS_PROMOTE],
            bypass_admin=False,
        )
    ),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)
        uid = current_user.get("id")

        if uid == pm.user_id:
            raise HTTPException(
                status_code=403, detail="You cannot update your own permissions"
            )

        target = await repo.get_by_id(pm.user_id)
        if not target:
            raise HTTPException(
                status_code=404, detail=f"User {pm.user_id} not found"
            )

        updated = await repo.set_permissions(
            user_id=pm.user_id, permissions=pm.permissions
        )
        return {
            "status": "success",
            "message": f"Permissions updated for user {pm.user_id}",
            "user_id": pm.user_id,
            "permissions": updated.permissions,
        }

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Set permissions DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Set permissions unexpected error")
        raise HTTPException(status_code=500, detail="Failed to set permissions")


# ============================================================================
# POST /set_permissions_bulk
# ============================================================================
@admin_router.post(
    "/set_permissions_bulk",
    summary="Set permissions for multiple users",
)
async def set_permissions_bulk(
    request: Request,
    bulk_pm: BulkPermissionModel,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            [Permission.ADMIN_USERS_PROMOTE], bypass_admin=False
        )
    ),
    db: AsyncSession = Depends(get_db),
    replace_all: bool = False,
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        has_promote = (current_user.get("permissions") or {}).get(
            "admin.users.promote", False
        )
        if not has_promote:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to set permissions. Need admin.users.promote.",
            )

        user_ids = [p.user_id for p in bulk_pm.all_user_permissions]
        existing_users = await repo.get_by_ids(user_ids)
        existing_user_ids = {user.id for user in existing_users}
        missing_users = [uid for uid in user_ids if uid not in existing_user_ids]
        if missing_users:
            raise HTTPException(
                status_code=404, detail=f"Users not found with IDs: {missing_users}"
            )

        current_user_id = current_user.get("id")
        if current_user_id in user_ids:
            raise HTTPException(
                status_code=403, detail="You cannot update your own permissions"
            )

        updated_users = []
        for perm_update in bulk_pm.all_user_permissions:
            if replace_all:
                updated = await repo.replace_all_permissions(
                    perm_update.user_id, perm_update.permissions
                )
                operation = "replaced"
            else:
                updated = await repo.set_permissions(
                    perm_update.user_id, perm_update.permissions
                )
                operation = "merged"
            updated_users.append(
                {
                    "user_id": perm_update.user_id,
                    "permissions": updated.permissions,
                    "status": "success",
                    "operation": operation,
                }
            )

        await db.commit()

        return {
            "status": "success",
            "message": (
                f"Permissions {('replaced' if replace_all else 'merged')} "
                f"for {len(updated_users)} users"
            ),
            "mode": "replace_all" if replace_all else "merge",
            "updated_users": updated_users,
            "total_processed": len(bulk_pm.all_user_permissions),
            "total_success": len(updated_users),
            "total_failed": 0,
        }

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Bulk permissions DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Bulk permissions unexpected error")
        raise HTTPException(
            status_code=500, detail="Error in bulk permission update"
        )


# ============================================================================
# GET /users/permissions
# ============================================================================
@admin_router.get(
    "/users/permissions",
    summary="Get user permissions with pagination",
)
async def get_users_permissions(
    request: Request,
    user_id: Optional[int] = Query(None, description="Specific user ID to get permissions for"),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    include_user_info: bool = Query(False, description="Include user email and name"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        current_user_id = current_user.get("id")
        current_user_perms = current_user.get("permissions") or {}
        current_user_email = current_user.get("email")

        has_promote = current_user_perms.get("admin.users.promote", False)
        has_settings_view = current_user_perms.get("admin.settings.view", False)
        is_admin = current_user.get("role") == "admin"
        can_view_any = is_admin or has_promote or has_settings_view

        if user_id is None:
            target_user_id = current_user_id
        else:
            is_viewing_self = user_id == current_user_id
            if not is_viewing_self and not can_view_any:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "You don't have permission to view other users' "
                        "permissions. Need admin.users.promote or admin.settings.view."
                    ),
                )
            target_user_id = user_id

        result = await repo.get_user_permission_db(
            user_id=target_user_id,
            skip=skip,
            limit=limit,
            include_user_info=include_user_info,
        )
        return {"status": "success", "data": result}

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Get user permissions DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Get user permissions unexpected error")
        raise HTTPException(
            status_code=500, detail="Error retrieving permissions"
        )


# ============================================================================
# DELETE /remove_permissions
# ============================================================================
@admin_router.delete(
    "/remove_permissions",
    summary="Remove permissions from a user",
)
async def remove_permissions(
    request: Request,
    data: RemovePermissionsModel,
    current_user: Dict[str, Any] = Depends(
        require_permission(
            required_permissions=[Permission.ADMIN_USERS_PROMOTE],
            mode="any",
            bypass_admin=False,
        )
    ),
    db: AsyncSession = Depends(get_db),
):
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        current_user_id = current_user.get("id")
        current_user_role = current_user.get("role")
        current_user_perms = current_user.get("permissions") or {}
        current_user_email = current_user.get("email")

        target = await repo.get_by_id(data.user_id)
        if not target:
            raise HTTPException(
                status_code=404, detail=f"User {data.user_id} not found"
            )

        is_self = current_user_id == data.user_id
        is_admin = current_user_role == "admin"
        has_promote = current_user_perms.get("admin.users.promote", False)

        if is_admin:
            pass
        elif is_self and has_promote:
            pass
        else:
            raise HTTPException(
                status_code=403,
                detail="You don't have permission to delete permissions",
            )

        if is_admin and is_self:
            raise HTTPException(
                status_code=403, detail="Admin cannot delete their own permissions"
            )
        if is_self and not is_admin:
            if data.permission_keys and "admin.users.promote" in data.permission_keys:
                raise HTTPException(
                    status_code=403,
                    detail="You cannot remove your own admin.users.promote permission",
                )

        target_perms = target.permissions or {}
        if isinstance(target_perms, str):
            import json
            try:
                target_perms = json.loads(target_perms)
            except (ValueError, TypeError):
                target_perms = {}

        removed_count: Any = 0
        if data.remove_all:
            if not target_perms:
                raise HTTPException(
                    status_code=404, detail="User has no permissions to delete"
                )
            updated = await repo.remove_all_permissions(data.user_id)
            message = f"All permissions removed for user {target.email}"
            removed_count = "all"

        elif data.permission_keys:
            existing_keys = [k for k in data.permission_keys if k in target_perms]
            missing_keys = [k for k in data.permission_keys if k not in target_perms]
            if not existing_keys:
                raise HTTPException(
                    status_code=404,
                    detail=f"Permissions not found: {', '.join(missing_keys)}",
                )
            updated = await repo.remove_permissions(data.user_id, existing_keys)
            message = f"Permissions removed for user {target.email}: {existing_keys}"
            if missing_keys:
                message += f" (Warning: {', '.join(missing_keys)} not found)"
            removed_count = len(existing_keys)

        else:
            raise HTTPException(
                status_code=400,
                detail="Either permission_keys or remove_all must be provided",
            )

        return {
            "status": "success",
            "message": message,
            "user_id": data.user_id,
            "permissions": updated.permissions,
            "removed_count": removed_count,
        }

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(status_code=404, detail="User not found")
    except DomainError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Remove permissions DB error")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable")
    except Exception:
        logger.exception(f"[{req_id}] Remove permissions unexpected error")
        raise HTTPException(status_code=500, detail="Error removing permissions")