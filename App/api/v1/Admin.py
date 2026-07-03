from fastapi import APIRouter, Depends, HTTPException, status, Query, Request,Response
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from App.repository.UserRepository import UserRepository
from App.core.LoggingInit import get_core_logger
from App.schemas.AuthScheema import TokenResponse
from App.api.dependencies.auth import (
     verify_password,
    get_current_user,
    get_password_hash,
    create_access_token,
    create_short_live_token,
 
)
from App.schemas.AuthScheema import UserResponse
from App.models.UserAuthModel import User,UpdateUser
from App.core.Connector import get_db
from datetime import datetime,timedelta
admin_router=APIRouter(prefix="/admin_access",tags=["Admin"])
logger = get_core_logger(__name__)


def _is_restore_token(current_user: Dict[str, Any]) -> bool:
    """Return True when the current auth context comes from a short-lived restore token."""
    return (
        current_user.get("token_purpose") == "restore_account"
        or current_user.get("token_type") == "slts"
        or current_user.get("types") == "slts"
    )

@admin_router.patch(
    "/account/{user_id}",
    response_model=UserResponse,
    summary="Update user account",
    description="Update user information. Admin can update any user, users can only update themselves."
)
async def update_account(
    user_id: int,
    update_data: UpdateUser,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update user account"""
    try:
        repo = UserRepository(db)
        
        # Check permissions
        is_admin = current_user.get("role") == "admin"
        can_update = is_admin or current_user.get("id") == user_id
        
        if not can_update:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        # Get user to update
        user_to_update = await repo.get_by_id(user_id)
        if not user_to_update:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Prepare update data
        update_dict = update_data.model_dump(exclude_unset=True)
        
        # Security restrictions for non-admin users
        if not is_admin:
            restricted_fields = ["user_role", "is_active"]
            for field in restricted_fields:
                if field in update_dict:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Cannot update {field} field"
                    )
        
        # Check email uniqueness if changing email
        if "email" in update_dict and update_dict["email"] != user_to_update.email:
            existing = await repo.get_by_email(update_dict["email"])
            if existing and existing.id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already in use"
                )
        
        # Hash password if updating
        if "password" in update_dict:
            update_dict["password_hash"] = get_password_hash(update_dict["password"])
            del update_dict["password"]
        
        # Perform update
        updated_user = await repo.update(user_id, update_dict)
        
        if not updated_user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to update user"
            )
        
        logger.info(f"User {user_id} updated by user {current_user.get('id')}")
        
        return UserResponse.model_validate(updated_user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Account update error: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Update failed: {str(e)}"
        )

@admin_router.post(
    "/account/disable/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable user account",
    description="Disable user account. Admin can Disable any user, users can only Disable themselves with password verification."
)
async def disable_account(
    user_id: int,
    password: Optional[str] = Query(None, description="Required for non-admin users"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Disable user account"""
    try:
        repo = UserRepository(db)
        
        # Check if trying to delete self
        is_self_deletion = current_user.get("id") == user_id
        is_admin = current_user.get("role") == "admin"
        
        # Get user to delete
        user_to_delete = await repo.get_by_id(user_id)
        if not user_to_delete:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        if user_to_delete.disabled:
            raise HTTPException(status.HTTP_403_FORBIDDEN,"Account alrerady disabled")
        # Admin can delete any user (except themselves without verification)
        if is_admin and not is_self_deletion:
            await repo.disable_account(user_id)
            logger.info(f"Admin {current_user.get('id')} deleted user {user_id}")
            return
        
        # Self-deletion requires password verification
        if is_self_deletion:
            if not password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password required for self-deletion"
                )
        
            if not verify_password(password, user_to_delete.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect password"
                )
            
            await repo.disable_account(user_id)
            logger.info(f"User {user_id} deleted their own account")
            return
        
        # If we get here, user doesn't have permission
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Account deletion error: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Deletion failed: {str(e)}"
        )


@admin_router.post(
    "/account/enable/{user_id}",
    status_code=status.HTTP_200_OK,  # ✅ Changed from 204 to 200 (returning data)
    summary="Enable user account",
    description="Enable a disabled or inactive user account. Admin can enable any user. SLT token can enable its own user. Users can enable themselves with password verification."
)
# App/api/v1/Admin.py - FINAL CORRECT VERSION

@admin_router.post(
    "/account/enable/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Enable user account",
    description="Enable a disabled or inactive user account. Admin can enable any user. SLT token can enable its own user. Users can enable themselves with password verification."
)
async def enable_account(
    user_id: int,
    password: Optional[str] = Query(None, description="Required for non-admin users"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Enable a disabled or inactive user account.
    
    - Admin → Can enable any user (no password required)
    - SLT Token → Can enable the user it was issued to (bypasses password)
    - Self-enable → User enables own account (password required)
    """
    try:
        repo = UserRepository(db)
        
        # ✅ Check if this is an SLT/restore token
        is_restore_token = _is_restore_token(current_user)
        slt_user_id = current_user.get("id")  # ← FIXED: use "id" not "user_id"
        cur_id = current_user.get("id")
        cur_role = current_user.get("role")
        
        # ✅ Get target user
        target_user = await repo.get_by_id(user_id)
        if not target_user:
            raise HTTPException(404, "User not found")
        
        # ✅ Check if user actually needs enabling
        if not target_user.disabled and target_user.is_active:
            raise HTTPException(400, "User is already active. No enable needed.")
        
        # ✅ Check if deleted
        if target_user.is_deleted:
            raise HTTPException(400, "User is deleted. Use restore endpoint instead.")
        
        is_self_enable = cur_id == user_id
        is_admin = cur_role == "admin"
        
        logger.info(f"🔍 is_restore_token: {is_restore_token}")
        logger.info(f"🔍 slt_user_id: {slt_user_id}, target_user_id: {user_id}")
        logger.info(f"🔍 is_admin: {is_admin}, is_self_enable: {is_self_enable}")
        
        # ============================================================
        # CASE 1: SLT/RESTORE TOKEN (Enables its OWN user)
        # ============================================================
        if is_restore_token:
            # ✅ SLT token can ONLY enable its own user!
            if slt_user_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"SLT token can only enable user {slt_user_id}, not {user_id}"
                )
            
            # ✅ Use full_restore (handles all states)
            success = await repo.full_restore(user_id)
            if not success:
                raise HTTPException(500, "Failed to enable account with SLT token")
            
            logger.info(f"✅ SLT token enabled user {user_id}")
            return {
                "status": "success",
                "message": f"Account {user_id} enabled via SLT token",
                "user_id": user_id,
                "user_email": target_user.email,
                "enabled_by": "SLT Token"
            }
        
        # ============================================================
        # CASE 2: ADMIN ENABLING ANY USER
        # ============================================================
        if is_admin and not is_self_enable:
            # ✅ Use full_restore (handles all states)
            success = await repo.full_restore(user_id)
            if not success:
                raise HTTPException(500, "Failed to enable user account")
            
            logger.info(f"✅ Admin {cur_id} enabled user {user_id}")
            return {
                "status": "success",
                "message": f"User {user_id} enabled by admin",
                "user_id": user_id,
                "user_email": target_user.email,
                "enabled_by": "Admin"
            }
        
        # ============================================================
        # CASE 3: SELF-ENABLE (Requires password)
        # ============================================================
        if is_self_enable:
            if not password:
                raise HTTPException(400, "Password required for self-enable")
            
            if not verify_password(password, target_user.password_hash):
                raise HTTPException(401, "Incorrect password")
            
            # ✅ Use full_restore (handles all states)
            success = await repo.full_restore(user_id)
            if not success:
                raise HTTPException(500, "Failed to enable your account")
            
            logger.info(f"✅ User {user_id} enabled their own account")
            return {
                "status": "success",
                "message": "Your account has been enabled successfully",
                "user_id": user_id,
                "user_email": target_user.email,
                "enabled_by": "Self"
            }
        
        # ============================================================
        # CASE 4: NO PERMISSION
        # ============================================================
        raise HTTPException(403, "You don't have permission to enable this account")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Enable account error: {e}")
        await db.rollback()
        raise HTTPException(500, "Failed to enable account")

@admin_router.post(
    "/account/temp_token/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Make temp token for user to change password and restore accounts",
    description="Make temporary token expire in 2 min for user to restore disabled/deleted account or reset password."
)
async def temp_token_maker(
    response: Response,
    user_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    cookie_login: bool = False,
    restore_passwd: bool = False,  # ← NEW: Password restore mode
):
    """
    Create temp token for:
    1. Account restoration (disabled/inactive/deleted users)
    2. Password reset (any user)
    
    - restore_passwd=True: Creates token for password reset (bypasses status check)
    - restore_passwd=False: Creates token for account restoration (requires disabled/inactive/deleted)
    """
    try:
        repo = UserRepository(db)
        
        # 1. Check if admin
        if current_user.get("role") != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only admin can access this"
            )
        
        # 2. Get target user
        target_user = await repo.get_by_id(user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # ✅ 3. Check if user needs token
        #    - Password restore: ALWAYS allowed (bypasses status check)
        #    - Account restoration: Only if disabled/inactive/deleted
        
        if restore_passwd:
            # ✅ Password restore mode - bypass all status checks!
            logger.info(f"🔑 Password restore token requested for user {user_id}")
            # Allow even if user is active, not disabled, etc.
            
        else:
            # ✅ Account restoration mode - only for disabled/inactive/deleted
            if not (target_user.disabled or not target_user.is_active or target_user.is_deleted):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User is already active and valid. No restoration needed."
                )
        
        # ✅ 4. Create the token
        temp_token = await create_short_live_token(user_id, db)
        
        if cookie_login:
            response.set_cookie(
                key="CSO",
                value=temp_token,
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=timedelta(minutes=2),
                path="/",
                domain=None,
            )
            
            return {
                "status": "success",
                "message": "Temporary token created and set as cookie",
                "user_id": target_user.id,
                "user_name": target_user.name,
                "purpose": "password_restore" if restore_passwd else "account_restoration",
                "expires_in_minutes": 2
            }
        else:
            return {
                "status": "success",
                "message": "Temporary token created",
                "user_id": target_user.id,
                "user_name": target_user.name,
                "user_status": {
                    "disabled": target_user.disabled,
                    "is_active": target_user.is_active,
                    "is_deleted": target_user.is_deleted
                } if not restore_passwd else None,
                "purpose": "password_restore" if restore_passwd else "account_restoration",
                "temp_token": temp_token,
                "expires_in_minutes": 2
            }
            
 
    except Exception as e:
        logger.error(f"Temp token error: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create temp token: {str(e)}"
        )


@admin_router.post(
    "/reset-auto-kill",
    status_code=status.HTTP_200_OK,
    summary="Reset Auto-Kill Switch",
    description="Allows administrators to reset the system from safety mode after an internal error."
)
async def reset_auto_kill(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Reset the auto-kill protection flag"""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can reset the safety mode"
        )
    
    request.app.state.auto_kill_enabled = False
    logger.info(f"System safety mode reset by admin: {current_user.get('email')}")
    return {"status": "success", "message": "System safety mode has been reset."}

@admin_router.delete(
    "/account/{user_id}",
    
    status_code=status.HTTP_200_OK,
    summary="Delete account",
    description="If normal user delete his accoutn but need password if admin can dleete any user account"
)
async def delete_account(
    user_id: int,
    password: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    try:
        repo = UserRepository(db)
        
        cur_role = current_user.get("role")
        cur_id = current_user.get("id")
        
        target_user = await repo.get_by_id(user_id)
        
        if not target_user:
            raise HTTPException(404, "User not found")
        
        if target_user.is_deleted:
            raise HTTPException(400, "User is already deleted")
        
        is_self_deletion = cur_id == user_id
        is_admin = cur_role == "admin"
        
        # ✅ DEBUG: Log what's happening
        logger.info(f"🔍 is_admin: {is_admin}, is_self_deletion: {is_self_deletion}")
        logger.info(f"🔍 password provided: {password is not None}")
        logger.info(f"🔍 target_user password_hash: {target_user.password_hash[:20]}...")
        
        if is_admin:
            if is_self_deletion:
                raise HTTPException(403, "Admin cannot delete their own account")
            
            success = await repo.delete_account(user_id)
            if not success:
                raise HTTPException(500, "Failed to delete user account")
            
            return {
                "status": "success",
                "message": f"User {user_id} deleted by admin"
            }
        
        if is_self_deletion:
            # ✅ DEBUG: Check password
            logger.info(f"🔍 Verifying password...")
            
            if not password:
                raise HTTPException(400, "Password required for self-deletion")
            
            # ✅ DEBUG: Check if verify_password exists
            logger.info(f"🔍 verify_password function: {verify_password}")
            
            # ✅ Try-catch around verify_password
            try:
                is_valid = verify_password(password, target_user.password_hash)
                logger.info(f"🔍 Password valid: {is_valid}")
            except Exception as e:
                logger.error(f"🔍 verify_password error: {e}")
                raise HTTPException(500, f"Password verification error: {str(e)}")
            
            if not is_valid:
                raise HTTPException(401, "Incorrect password")
            
            success = await repo.delete_account(user_id)
            if not success:
                raise HTTPException(500, "Failed to delete your account")
            
            return {
                "status": "success",
                "message": "Your account has been soft deleted"
            }
        
        raise HTTPException(403, "You don't have permission to delete this account")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete account error: {e}")
        await db.rollback()
        raise HTTPException(500, f"Failed to delete user due to: {str(e)}")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Temp token error: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete user due to : {str(e)}"
        )

@admin_router.post(
    "/account/restore/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Restore deleted/disabled account",
    description="Restore a soft-deleted or disabled account. Admin can restore any user. Users can restore themselves only with SLT token."
)
async def restore_account(
    user_id: int,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Restore a deleted or disabled user account.
    
    - Admin → Can restore any user (no password required)
    - SLT Token → Restores account (bypasses all checks)
    - Normal users → CANNOT restore (use SLT token)
    """
    try:
        repo = UserRepository(db)
        
        cur_role = current_user.get("role")
        is_slt_token = current_user.get("types") == "slts"
        
        target_user = await repo.get_by_id(user_id)
        
        if not target_user:
            raise HTTPException(404, "User not found")
        
        # ✅ Check if user actually needs restoration
        if not target_user.is_deleted and not target_user.disabled and target_user.is_active:
            raise HTTPException(400, "User is already active. No restoration needed.")
        
        logger.info(f"🔍 is_admin: {cur_role == 'admin'}")
        logger.info(f"🔍 is_slt_token: {is_slt_token}")
        logger.info(f"🔍 target_user status: disabled={target_user.disabled}, is_active={target_user.is_active}, is_deleted={target_user.is_deleted}")
        
        # ============================================================
        # CASE 1: SLT TOKEN (Bypasses everything!)
        # ============================================================
        if is_slt_token:
            success = await repo.restore_deleted(user_id)
            if not success:
                success = await repo.restore_disable(user_id)
            
            if not success:
                raise HTTPException(500, "Failed to restore account with SLT token")
            
            logger.info(f"✅ SLT token restored user {user_id}")
            return {
                "status": "success",
                "message": f"Account {user_id} restored via SLT token",
                "user_id": user_id,
                "user_email": target_user.email,
                "restored_by": "SLT Token"
            }
        
        # ============================================================
        # CASE 2: ADMIN RESTORING ANY USER
        # ============================================================
        if cur_role == "admin":
            success = False
            
            if target_user.is_deleted:
                success = await repo.restore_deleted(user_id)
            
            if not success:
                success = await repo.restore_disable(user_id)
            
            if not success:
                raise HTTPException(500, "Failed to restore user account")
            
            logger.info(f"✅ Admin {current_user.get('id')} restored user {user_id}")
            return {
                "status": "success",
                "message": f"User {user_id} restored by admin",
                "user_id": user_id,
                "user_email": target_user.email,
                "restored_by": "Admin"
            }
        
        # ============================================================
        # CASE 3: NO PERMISSION (Normal user)
        # ============================================================
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only Admin or SLT token can restore accounts. Please contact admin or use your restoration link."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Restore account error: {e}")
        await db.rollback()
        raise HTTPException(500, f"Failed to restore account: {str(e)}")

@admin_router.put(
    "/account/password/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Update user password",
    description="Admin can update any user password. Normal users update their own password. SLT token can only update its own user's password."
)
async def update_password(
    user_id: int,
    new_password: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    old_password: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    ## Change password for user.
    
    - Admin → Can change password for any user (new password only)
    - Normal users → Can change their own password (old + new password required)
    - SLT Token → Can ONLY update password for the user it was issued to (bypasses old password)
    """
    try:
        repo = UserRepository(db)
        
        cur_role = current_user.get("role")
        cur_id = current_user.get("id")
        is_slt_token = current_user.get("types") == "slts"
        slt_user_id = current_user.get("user_id")  # The user this SLT token was issued for
        
        # ✅ Get target user
        target_user = await repo.get_by_id(user_id)
        
        if not target_user:
            raise HTTPException(404, "User not found")
        
        is_self_update = cur_id == user_id
        is_admin = cur_role == "admin"
        
        logger.info(f"🔍 is_admin: {is_admin}, is_self_update: {is_self_update}")
        logger.info(f"🔍 is_slt_token: {is_slt_token}")
        logger.info(f"🔍 slt_user_id: {slt_user_id}, target_user_id: {user_id}")
        logger.info(f"🔍 new_password provided: {new_password is not None}")
        
    
        
        # ============================================================
        # CASE 1: SLT TOKEN (Only for its OWN user!)
        # ============================================================
        if is_slt_token:
            # ✅ SLT token can ONLY update password for its own user!
            if slt_user_id != user_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"SLT token can only update password for user {slt_user_id}, not {user_id}"
                )
            
            # SLT token updates password (no old password needed)
            new_hash = get_password_hash(new_password)
            success = await repo.update_password_hash(user_id, new_hash)
            
            if not success:
                raise HTTPException(500, "Failed to update password with SLT token")
            
            logger.info(f"✅ SLT token updated password for user {user_id}")
            return {
                "status": "success",
                "message": f"Password updated via SLT token for user {user_id}",
                "user_id": user_id,
                "user_email": target_user.email,
                "updated_by": "SLT Token"
            }
        
        # ============================================================
        # CASE 2: ADMIN UPDATING ANY USER
        # ============================================================
        if is_admin:
            # Admin can update any user's password (no old password needed)
            new_hash = get_password_hash(new_password)
            success = await repo.update_password_hash(user_id, new_hash)
            
            if not success:
                raise HTTPException(500, "Failed to update password")
            
            logger.info(f"✅ Admin {cur_id} updated password for user {user_id}")
            return {
                "status": "success",
                "message": f"Password updated by admin for user {user_id}",
                "user_id": user_id,
                "user_email": target_user.email,
                "updated_by": "Admin"
            }
        
        # ============================================================
        # CASE 3: SELF UPDATE (Requires old password)
        # ============================================================
        if is_self_update:
            if not old_password:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Old password is required to change your password"
                )
            
            # ✅ Verify old password
            if not verify_password(old_password, target_user.password_hash):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect old password"
                )
            
            # ✅ Update password
            new_hash = get_password_hash(new_password)
            success = await repo.update_password_hash(user_id, new_hash)
            
            if not success:
                raise HTTPException(500, "Failed to update your password")
            
            logger.info(f"✅ User {user_id} updated their own password")
            return {
                "status": "success",
                "message": "Your password has been updated successfully",
                "user_id": user_id,
                "user_email": target_user.email,
                "updated_by": "Self"
            }
        
        # ============================================================
        # CASE 4: NO PERMISSION
        # ============================================================
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to update this user's password"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update password error: {e}")
        await db.rollback()
        raise HTTPException(500, f"Failed to update password: {str(e)}")


