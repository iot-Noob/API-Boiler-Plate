from fastapi import APIRouter,Response 
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyCookie
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from App.repository.UserRepository import UserRepository
from App.core.LoggingInit import get_core_logger
from App.schemas.AuthScheema import TokenResponse
from App.api.dependencies.auth import (
    refresh_access_token,
    get_current_active_user,
    get_admin_user,
    refresh_cookie_scheme,
    decode_jwt_ignore_expiry,
    cookie_scheme,
    oauth2_scheme,
    decode_jwt
)
from App.core.settings import settings
from App.schemas.AuthScheema import UserResponse
from App.core.Connector import get_db
user_router=APIRouter(prefix="/users_config",tags=["Users"])
logger = get_core_logger(__name__)

# @user_router.post(
#     "/refresh",
#     response_model=TokenResponse,
#     summary="Refresh access token",
#     description="Get new access token using refresh token"
# )
# async def refresh_token(
#     refresh_token_body: Optional[str] = Body(None, embed=True, alias="refresh_token"),
#     refresh_token_cookie: Optional[str] = Depends(refresh_cookie_scheme),
#     access_token_cookie: Optional[str] = Depends(cookie_scheme),
#     access_credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_scheme),
#     db: AsyncSession = Depends(get_db),
# ):
#     """Refresh access token"""
#     try:
#         token = refresh_token_body or refresh_token_cookie
#         if not token:
#             raise HTTPException(status.HTTP_401_UNAUTHORIZED, "No refresh token provided")

#         # Decode + validate the refresh token itself (type + expiry enforced here)
#         rt_payload = decode_jwt(token)
#         if rt_payload.get("type") != "refresh":
#             raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")
#         rt_user_id = rt_payload.get("user_id")

#         # Cross-check against the current access token's identity, if one is present
#         access_token = access_credentials.credentials if access_credentials else access_token_cookie
#         if access_token:
#             at_payload = decode_jwt_ignore_expiry(access_token)
#             if at_payload:
#                 at_user_id = at_payload.get("user_id")
#                 if at_user_id is not None and at_user_id != rt_user_id:
#                     logger.warning(
#                         f"Refresh token user {rt_user_id} does not match access token user {at_user_id}"
#                     )
#                     raise HTTPException(
#                         status.HTTP_401_UNAUTHORIZED,
#                         "Refresh token does not match current session"
#                     )

#         new_access_token = await refresh_access_token(token, db)
#         if not new_access_token:
#             raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

#         return TokenResponse(access_token=new_access_token, expires_in=3600)

#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Token refresh error: {e}")
#         raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Token refresh failed")

@user_router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access + refresh tokens",
    description="Rotate refresh token and issue a new access token.",
)
async def refresh_token(
    res: Response,
    refresh_token_body: Optional[str] = Body(None, embed=True, alias="refresh_token"),
    refresh_token_cookie: Optional[str] = Depends(refresh_cookie_scheme),
    access_token_cookie: Optional[str] = Depends(cookie_scheme),
    access_credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using refresh token (with rotation)."""
    try:
        # 1. Get the refresh token from body or cookie
        token = refresh_token_body or refresh_token_cookie
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No refresh token provided",
            )

        # 2. Decode + validate the refresh token
        #    (decode_jwt raises HTTPException on invalid/expired)
        rt_payload = decode_jwt(token)
        if not rt_payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        if rt_payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        rt_user_id = rt_payload.get("user_id")
        if not rt_user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token payload",
            )

        # 3. Cross-check identity against the current access token (if present)
        access_token = (
            access_credentials.credentials
            if access_credentials
            else access_token_cookie
        )
        if access_token:
            at_payload = decode_jwt_ignore_expiry(access_token)
            if at_payload:
                at_user_id = at_payload.get("user_id")
                if at_user_id is not None and at_user_id != rt_user_id:
                    logger.warning(
                        f"Refresh token user {rt_user_id} does not match "
                        f"access token user {at_user_id}"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Refresh token does not match current session",
                    )

        # 4. Rotate — returns {"access_token": ..., "refresh_token": ...} or None
        result = await refresh_access_token(token, db)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        # 5. If the client used cookies, set new ones
        if refresh_token_cookie:
            res.set_cookie(
                key="CSO",
                value=result["access_token"],
                httponly=True,
                secure=settings.COOKIE_SECURE,
                samesite="lax",
                max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                path="/",
            )
            res.set_cookie(
                key="refresh_token",
                value=result["refresh_token"],
                httponly=True,
                secure=settings.COOKIE_SECURE,
                samesite="strict",
                max_age=7 * 24 * 3600,
                path="/users_config/refresh",
            )

        # 6. Return new tokens
        return TokenResponse(
            access_token=result["access_token"],
            refresh_token=result["refresh_token"],
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed",
        )

@user_router.get(
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
@user_router.get(
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

 