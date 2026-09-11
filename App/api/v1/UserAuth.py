# App/api/v1/UserAuth.py - PROFESSIONAL REFACTORED VERSION
from jose import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Query, Body,Response
from App.schemas.AuthScheema import TokenResponse
from sqlalchemy.ext.asyncio import AsyncSession
from App.core.LoggingInit import get_core_logger
from App.core.Connector import get_db
from App.models.UserAuthModel import User,UpdateUser,LoginUser
from App.core import token_store
from datetime import datetime, timezone
import uuid
from App.schemas.AuthScheema import UserResponse
from App.api.dependencies.auth import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    cookie_scheme,
    oauth2_scheme,
    refresh_cookie_scheme,
    get_password_hash,

    validate_password_strength
)
from typing import Optional
from App.repository.UserRepository import UserRepository
from App.core.settings import settings
# Initialize logger
logger = get_core_logger(__name__)

# Pydantic Models (Request/Response schemas)
 




# Create router
router = APIRouter(prefix="/basic_auth", tags=["Authentication"])

@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate user with email and password"
)
async def login(
    res: Response,
    form_data: LoginUser,
    db: AsyncSession = Depends(get_db),
    cookie_login: Optional[bool] = False,
):
    """
    Login endpoint supporting OAuth2 password flow.
    Returns access and refresh tokens.
    """
    try:
        # Get password from SecretStr
        password = form_data.password.get_secret_value()
        
        # Authenticate user
        user = await authenticate_user(form_data.username, password, db)
         
        if not user:
            logger.warning(f"Failed login attempt for email: {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password or account is not there or disable!\n\nContact admin",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # ✅ CREATE TOKENS FIRST - BEFORE ANY CONDITION!
        family_id = str(uuid.uuid4())
        access_token = create_access_token(
            data={
                "type":"token",
                "sub": user["email"],
                "user_id": user["id"],
                "name": user["name"],
                "role": user["role"]
            }
        )
        
        refresh_token = create_refresh_token(
            data={
                "type":"rf_token",
                "sub": user["email"],
                "user_id": user["id"]
            },
            family_id=family_id,
        )
        jti = jwt.decode(
            refresh_token,
            settings.secret_key_str,
            algorithms=[settings.ALGORITHM],
        )["jti"]
        await token_store.store_refresh(
            jti=jti,
            user_id=user["id"],
            family_id=family_id,
            ttl=7 * 24 * 3600,
        )
        expires_in_seconds = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        
        logger.info(f"User logged in successfully: {user['email']}")
        
        # ========== COOKIE MODE ==========
        if cookie_login:
            res.set_cookie(
                key="CSO",
                value=access_token,
                httponly=settings.HTTPS_ONLY,
                secure=settings.COOKIE_SECURE,
                samesite="lax",
                max_age=expires_in_seconds,
                path="/",
                domain=None,
            )
            res.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=settings.HTTPS_ONLY,
                secure=settings.COOKIE_SECURE,
                samesite="lax",
                max_age=7 * 24 * 60 * 60,
                path="/users_config/refresh",
                domain=None,
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
                    "role": user["role"]
                }
            }
        
        # ========== JSON MODE ==========
        else:
            return TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=expires_in_seconds
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during login"
        )
    
# App/api/v1/UserAuth.py - FIXED VERSION
@router.post(
    "/signup",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account"
)
async def signup(
    
    user_data: User,
    db: AsyncSession = Depends(get_db),
   
):
    """Register a new user"""
    try:
        repo = UserRepository(db)
        
        # Check if user exists
        existing_user = await repo.get_by_email(user_data.email)
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Create user data dictionary
        user_dict = user_data.model_dump()
        
        # Validate and hash password
        if "password" not in user_dict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password is required"
            )
        
        # Validate password strength
        if not validate_password_strength(user_dict["password"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 8 characters with uppercase, lowercase, digit, and special character"
            )
        
        user_dict["password_hash"] = get_password_hash(user_dict["password"])
        del user_dict["password"]  # Remove plain password
        
        # Set default values
        user_dict["user_role"] = "user"
        user_dict["is_active"] = True
        user_dict["permissions"] = {
            # ===== USER SELF-MANAGEMENT =====
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
        
        user = await repo.create(user_dict)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create user"
            )
        
        logger.info(f"New user registered: {user.email}")
        
        # FIX: Convert SQLAlchemy model to dictionary before validation
        user_dict_response = {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "profile_pic": user.profile_pic or None,  # Ensure None if empty
            "permissions":{ 
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
        }
        
        # Validate with UserResponse model
        return UserResponse(**user_dict_response)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

# App/api/v1/UserAuth.py — add below signup()


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout",
    description="Revoke refresh token in Redis and clear cookies. Idempotent.",
)
async def logout(
    res: Response,
    cookie_auth: Optional[str] = Depends(cookie_scheme),
    refresh_auth: Optional[str] = Depends(refresh_cookie_scheme),
):
    """
    Logout for cookie-based login.

    1. Revokes the refresh token in Redis (so it dies server-side)
    2. Clears the access + refresh cookies

    Idempotent — safe to call repeatedly.
    """
    # ---- NEW: revoke refresh token in Redis ----
    if refresh_auth:
        try:
            payload = jwt.decode(
                refresh_auth,
                settings.secret_key_str,
                algorithms=[settings.ALGORITHM],
            )
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                ttl = max(int(exp - datetime.now(timezone.utc).timestamp()), 1)
                await token_store.revoke_refresh(jti, ttl)
                logger.info(f"Revoked refresh token: {jti}")
            else:
                logger.debug("Logout: refresh token missing jti/exp")
        except HTTPException:
            logger.debug("Logout: refresh token already invalid/expired")
        except Exception as e:
            # Redis down or unexpected — log but still clear cookies
            logger.error(f"Logout revocation error (non-fatal): {e}")
    # ---- END NEW ----

    # Existing logic — unchanged
    if not cookie_auth and not refresh_auth:
        logger.info("Logout called with no active session cookies present")
        return {
            "status": "success",
            "message": "Already logged out",
            "already_logged_out": True,
        }

    if cookie_auth:
        res.delete_cookie(
            key="CSO",
            path="/",
            domain=None,
        )

    if refresh_auth:
        res.delete_cookie(
            key="refresh_token",
            path="/users_config/refresh",
            domain=None,
        )

    logger.info("User logged out (cookies cleared)")

    return {
        "status": "success",
        "message": "Logged out successfully",
    }