from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from App.repository.UserRepository import UserRepository
from App.core.LoggingInit import get_core_logger
from App.schemas.AuthScheema import TokenResponse
from App.api.dependencies.auth import (
     verify_password,
    refresh_access_token,
    get_current_user,
    get_password_hash,
    get_current_active_user,
    get_admin_user,
)
from App.schemas.AuthScheema import UserResponse
from App.models.UserAuthModel import User
from App.core.Connector import get_db
admin_router=APIRouter(prefix="/admin",tags=["Admin"])
logger = get_core_logger(__name__)
@admin_router.patch(
    "/account/{user_id}",
    response_model=UserResponse,
    summary="Update user account",
    description="Update user information. Admin can update any user, users can only update themselves."
)
async def update_account(
    user_id: int,
    update_data: User,
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

@admin_router.delete(
    "/account/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user account",
    description="Delete user account. Admin can delete any user, users can only delete themselves with password verification."
)
async def delete_account(
    user_id: int,
    password: Optional[str] = Query(None, description="Required for non-admin users"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete user account"""
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
        
        # Admin can delete any user (except themselves without verification)
        if is_admin and not is_self_deletion:
            await repo.delete(user_id)
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
            
            await repo.delete(user_id)
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
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Get new access token using refresh token"
)
async def refresh_token(
    refresh_token: str = Body(..., embed=True),
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token"""
    try:
        new_access_token = await refresh_access_token(refresh_token, db)
        
        if not new_access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        return TokenResponse(
            access_token=new_access_token,
            expires_in=3600
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )

@admin_router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Get detailed information about the currently authenticated user"
)
async def get_my_profile(
    current_user: Dict[str, Any] = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current user's profile"""
    try:
        repo = UserRepository(db)
        user = await repo.get_by_id(current_user["id"])
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserResponse.model_validate(user)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Profile fetch error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch profile"
        )

# Helper endpoint for admin users
@admin_router.get(
    "/users",
    summary="List users (Admin only)",
    description="Get list of all users. Admin access required."
)
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """List users (admin only)"""
    try:
        repo = UserRepository(db)
        users = await repo.search_users(
            skip=skip,
            limit=limit,
            active_only=False,
            search=search
        )
        
        user_count = await repo.count_users(active_only=False)
        
        return {
            "users": [UserResponse.model_validate(user) for user in users],
            "total": user_count,
            "skip": skip,
            "limit": limit
        }
        
    except Exception as e:
        logger.error(f"Users list error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users list"
        )