# App/api/v1/Users.py
"""
User self-service and admin endpoints.

Routes:
    POST /users_config/refresh   — rotate refresh token, issue new access token
    GET  /users_config/me        — current user's profile
    GET  /users_config/users     — list users (admin only)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Body, Response
from fastapi.security import HTTPAuthorizationCredentials
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from App.repository.UserRepository import UserRepository
from App.core.LoggingInit import get_core_logger
from App.core.settings import settings
from App.core.Connector import get_db
from App.core.exceptions import UserNotFoundError, DomainError
from App.schemas.AuthScheema import TokenResponse, UserResponse
from App.api.dependencies.auth import (
    refresh_access_token,
    get_current_active_user,
    get_admin_user,
    refresh_cookie_scheme,
    decode_jwt_ignore_expiry,
    cookie_scheme,
    oauth2_scheme,
    decode_jwt,
)

user_router = APIRouter(prefix="/users_config", tags=["Users"])
logger = get_core_logger(__name__)


# ============================================================================
# POST /users_config/refresh
# ============================================================================
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

        # 2. Decode + validate the refresh token.
        #    decode_jwt raises HTTPException on invalid/expired signature.
        rt_payload = decode_jwt(token)
        if not rt_payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        # 2a. Reject SLT tokens explicitly. They use `types: "slts"` and are
        #     for account restoration, not session refresh.
        if rt_payload.get("types") == "slts":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Short-lived tokens cannot be used for refresh",
            )

        # 2b. Reject anything that isn't a refresh token.
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

        # 3. Cross-check identity against the current access token (if present).
        #    Prevents "user A refreshes user B's session" mismatch.
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

        # 4. Rotate — returns {"access_token": ..., "refresh_token": ...} or None.
        result = await refresh_access_token(token, db)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        # 5. If the client used cookies, set fresh ones.
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
                max_age=settings.REFRESH_TOKEN_TTL_SECONDS,
                path="/app/v1/users/users_config/refresh",
            )

        # 6. Return new tokens.
        return TokenResponse(
            access_token=result["access_token"],
            refresh_token=result["refresh_token"],
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    except HTTPException:
        raise
    except SQLAlchemyError:
        logger.exception("Refresh DB error")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        )
    except DomainError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception:
        logger.exception("Refresh unexpected error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed",
        )


# ============================================================================
# GET /users_config/me
# ============================================================================
@user_router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Get detailed information about the currently authenticated user",
)
async def get_my_profile(
    current_user: Dict[str, Any] = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user's profile."""
    try:
        repo = UserRepository(db)
        user = await repo.get_by_id(current_user["id"])

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return UserResponse.model_validate(user)

    except HTTPException:
        raise
    except UserNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    except SQLAlchemyError:
        logger.exception("Profile fetch DB error")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        )
    except Exception:
        logger.exception("Profile fetch unexpected error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch profile",
        )


# ============================================================================
# GET /users_config/users  (admin only)
# ============================================================================
@user_router.get(
    "/users",
    summary="List users (Admin only)",
    description="Get list of all users. Admin access required.",
)
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """List users (admin only)."""
    try:
        repo = UserRepository(db)
        users = await repo.search_users(
            skip=skip,
            limit=limit,
            active_only=False,
            search=search,
        )

        user_count = await repo.count_users(active_only=False)

        return {
            "users": [UserResponse.model_validate(user) for user in users],
            "total": user_count,
            "skip": skip,
            "limit": limit,
        }

    except HTTPException:
        raise
    except SQLAlchemyError:
        logger.exception("List users DB error")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        )
    except Exception:
        logger.exception("List users unexpected error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users list",
        )