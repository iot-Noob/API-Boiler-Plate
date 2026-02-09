from contextlib import asynccontextmanager
import os
from fastapi import FastAPI, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from App.api.v1 import app_router
from App.core.settings import settings
from App.core.LoggingInit import get_core_logger

app = FastAPI(title="API Basic Boilerplate", version="0.0.1")
logger=get_core_logger(__name__)

# Initialize Limiter
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT_DEFAULT])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.middleware("http")
async def kill_switch_middleware(request: Request, call_next):
    """Global middleware to intercept requests when KILL_SWITCH_ENABLED is True"""
    # Allow health check even if kill switch is active
    if settings.KILL_SWITCH_ENABLED and request.url.path not in ["/health", "/docs", "/openapi.json"]:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "Service is temporarily unavailable due to maintenance."}
        )
    response = await call_next(request)
    return response

@asynccontextmanager
async def lifespan():
    
    logger.info("App started")
    yield
    logger.info("app end")

@app.get("/health", status_code=status.HTTP_200_OK, tags=["System"])
async def health_check():
    """Simple health check endpoint for monitoring"""
    return {"status": "healthy", "version": "0.0.1"}

# CORS configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)
 
app.include_router(app_router,prefix="/app/v1")
