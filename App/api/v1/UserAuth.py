# App/api/v1/UserAuth.py
"""
Authentication endpoints.

Routes:
    POST /basic_auth/login    — authenticate, issue access + refresh tokens
    POST /basic_auth/signup   — register a new user
    POST /basic_auth/logout   — revoke refresh token, clear cookies
"""

from datetime import datetime, timezone
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query, Body, Response, Request
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from App.schemas.AuthScheema import TokenResponse, UserResponse
from App.models.UserAuthModel import User, UpdateUser, LoginUser
from App.core.LoggingInit import get_core_logger
from App.core.Connector import get_db
from App.core import token_store
from App.core.settings import settings
from App.core.exceptions import (
    DuplicateEmailError,
    UserNotFoundError,
    DomainError,
)
from App.repository.UserRepository import UserRepository
from App.api.dependencies.auth import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    cookie_scheme,
    oauth2_scheme,
    refresh_cookie_scheme,
    get_password_hash,
    validate_password_strength,
    decode_jwt_ignore_expiry,
)

logger = get_core_logger(__name__)

router = APIRouter(prefix="/basic_auth", tags=["Authentication"])


# ============================================================================
# POST /basic_auth/login
# ============================================================================
@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate user with name/email and password.",
)
async def login(
    request: Request,
    res: Response,
    form_data: LoginUser,
    db: AsyncSession = Depends(get_db),
    cookie_login: Optional[bool] = False,
):
    """Login endpoint supporting both JSON and cookie modes."""
    req_id = getattr(request.state, "request_id", "-")
    try:
        # 1. Authenticate
        password = form_data.password.get_secret_value()
        user = await authenticate_user(form_data.username, password, db)

        if not user:
            logger.warning(f"[{req_id}] Failed login for {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password, or account is disabled",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 2. Issue tokens
        family_id = str(uuid.uuid4())
        access_token = create_access_token(
            data={
                "type": "token",
                "sub": user["email"],
                "user_id": user["id"],
                "name": user["name"],
                "role": user["role"],
            }
        )
        refresh_token = create_refresh_token(
            data={
                "type": "rf_token",
                "sub": user["email"],
                "user_id": user["id"],
            },
            family_id=family_id,
        )

        # 3. Extract jti and persist refresh token metadata in Redis
        jti = jwt.decode(
            refresh_token,
            settings.secret_key_str,
            algorithms=[settings.ALGORITHM],
        )["jti"]

        await token_store.store_refresh(
            jti=jti,
            user_id=user["id"],
            family_id=family_id,
            ttl=settings.REFRESH_TOKEN_TTL_SECONDS,
        )

        expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        logger.info(f"[{req_id}] User logged in: {user['email']}")

        # 4. Cookie mode
        if cookie_login:
            res.set_cookie(
                key="CSO",
                value=access_token,
                httponly=True,
                secure=settings.COOKIE_SECURE,
                samesite="lax",
                max_age=expires_in_seconds,
                path="/",
            )
            res.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=settings.COOKIE_SECURE,
                samesite="strict",
                max_age=settings.REFRESH_TOKEN_TTL_SECONDS,
                path="/app/v1/users/users_config/refresh",
            )
            return {
                "token": access_token,
                "refresh_token": refresh_token,
                "status": "success",
                "message": "Logged in successfully",
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "name": user["name"],
                    "role": user["role"],
                },
            }

        # 5. JSON mode
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in_seconds,
        )

    except HTTPException:
        raise
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Login DB error")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        )
    except DomainError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        logger.exception(f"[{req_id}] Login unexpected error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login",
        )


# ============================================================================
# POST /basic_auth/signup
# ============================================================================
@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account.",
)
async def signup(
    request: Request,
    user_data: User,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user."""
    req_id = getattr(request.state, "request_id", "-")
    try:
        repo = UserRepository(db)

        # 1. Reject duplicate email early (nicer error than 409 from repo)
        if await repo.exists_by_email(user_data.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

        # 2. Validate and hash password
        user_dict = user_data.model_dump()
        if "password" not in user_dict or not user_dict["password"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required",
            )
        if not validate_password_strength(user_dict["password"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Password must be at least 8 characters with "
                    "uppercase, lowercase, digit, and special character"
                ),
            )
        user_dict["password_hash"] = get_password_hash(user_dict["password"])
        del user_dict["password"]

        # 3. Set defaults
        user_dict["user_role"] = "user"
        user_dict["is_active"] = True
        user_dict["permissions"] = {
            "user.view.self": True,
            "user.update.self": True,
            "user.update.email": True,
            "user.update.password": True,
            "user.update.profile": True,
            "user.delete.self": True,
            "user.history.view": True,
            "user.history.delete": True,
            "user.self.enable": True,
            "user.disable.self": True,
        }

        # 4. Persist
        user = await repo.create(user_dict)
        logger.info(f"[{req_id}] New user registered: {user.email}")

        return UserResponse.model_validate(user)

    except HTTPException:
        raise
    except DuplicateEmailError:
        # Race condition: another request created the email between
        # our exists_by_email check and the insert.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )
    except SQLAlchemyError:
        logger.exception(f"[{req_id}] Signup DB error")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        )
    except DomainError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception:
        logger.exception(f"[{req_id}] Signup unexpected error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed",
        )


# ============================================================================
# POST /basic_auth/logout
# ============================================================================
@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout",
    description="Revoke refresh token in Redis and clear cookies. Idempotent.",
)
async def logout(
    request: Request,
    res: Response,
    cookie_auth: Optional[str] = Depends(cookie_scheme),
    refresh_auth: Optional[str] = Depends(refresh_cookie_scheme),
):
    """
    Logout for cookie-based login.

    1. Revokes the refresh token in Redis (server-side kill).
    2. Clears the access + refresh cookies.

    Idempotent — safe to call repeatedly.
    """
    req_id = getattr(request.state, "request_id", "-")

    # ---- Revoke refresh token server-side ----
    if refresh_auth:
        try:
            payload = decode_jwt_ignore_expiry(refresh_auth)
            jti = payload.get("jti") if payload else None
            exp = payload.get("exp") if payload else None
            if jti:
                ttl = (
                    max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
                    if exp
                    else settings.REFRESH_TOKEN_TTL_SECONDS
                )
                await token_store.revoke_refresh(jti, ttl)
                logger.info(f"[{req_id}] Revoked refresh token: {jti}")
            else:
                logger.debug(f"[{req_id}] Logout: refresh token missing jti")
        except HTTPException:
            logger.debug(f"[{req_id}] Logout: refresh token already invalid/expired")
        except Exception:
            # Redis down. For security, fail the logout — the client
            # should retry. Silently succeeding would leave a live token
            # on the server after the user thinks they logged out.
            logger.exception(f"[{req_id}] Logout revocation failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Logout unavailable, please retry",
            )

    # ---- Nothing to do ----
    if not cookie_auth and not refresh_auth:
        logger.info(f"[{req_id}] Logout called with no active session cookies")
        return {
            "status": "success",
            "message": "Already logged out",
            "already_logged_out": True,
        }

    # ---- Clear cookies ----
    if cookie_auth:
        res.delete_cookie(key="CSO", path="/", domain=None)
    if refresh_auth:
        res.delete_cookie(
            key="refresh_token",
            path="/app/v1/users/users_config/refresh",
            domain=None,
        )

    logger.info(f"[{req_id}] User logged out (cookies cleared)")
    return {"status": "success", "message": "Logged out successfully"}