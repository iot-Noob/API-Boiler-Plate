from contextlib import asynccontextmanager
import os

from sqlalchemy import text
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from App.api.v1 import app_router
from App.core.settings import settings
from App.core.LoggingInit import get_core_logger
from App.core.CreateAdmin import create_admin
from App.core.RedisConnector import redis_client
from App.core.Connector import AsyncSession, get_db
from App.middleware.rate_limit_middleware import GlobalRateLimitMiddleware
from App.middleware.kill_switch_middleware import KillSwitchMiddleware
from App.middleware.body_size_middleware import BodySizeLimitMiddleware
from App.middleware.request_id_middleware import RequestIDMiddleware
from App.core.size_parser import parse_size
logger = get_core_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_admin()
    await redis_client.connect()
    logger.info("App started")
    yield
    await redis_client.disconnect()
    logger.info("App ended")


app = FastAPI(title="API Basic Boilerplate", version="0.0.1", lifespan=lifespan)


# ---------- Exception handlers ----------
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    req_id = getattr(request.state, "request_id", "-")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status": exc.status_code, "request_id": req_id},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    req_id = getattr(request.state, "request_id", "-")
    return JSONResponse(
        status_code=422,
        content={"error": "Validation failed", "details": exc.errors(), "request_id": req_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    req_id = getattr(request.state, "request_id", "-")
    logger.exception(f"[{req_id}] Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "request_id": req_id},
    )


# ---------- Custom middlewares (order: last added = outermost) ----------
 
app.add_middleware(RequestIDMiddleware, header_name="X-Request-ID")            # innermost
app.add_middleware(BodySizeLimitMiddleware, max_size=settings.MAX_BODY_SIZE)
app.add_middleware(
    GlobalRateLimitMiddleware,
    default_limit=settings.RATE_LIMIT_DEFAULT or "100/minute",
)
app.add_middleware(KillSwitchMiddleware, recovery_seconds=60)

ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(                                                                  # outermost
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# ---------- Health check ----------
@app.get("/health", tags=["System"])
async def health_check(request: Request, db: AsyncSession = Depends(get_db)):
    checks = {"db": "unknown", "redis": "unknown"}
    overall = "healthy"

    try:
        await db.execute(text("SELECT 1"))
        checks["db"] = "ok"
    except Exception as e:
        checks["db"] = "error"
        overall = "unhealthy"
        logger.error(f"Health: DB check failed: {e}")

    try:
        r = await redis_client.health_check()
        checks["redis"] = r["status"]
        if not r["connected"]:
            overall = "unhealthy"
    except Exception as e:
        checks["redis"] = "error"
        overall = "unhealthy"
        logger.error(f"Health: Redis check failed: {e}")

    return JSONResponse(
        status_code=200 if overall == "healthy" else 503,
        content={"status": overall, "version": "0.0.1", "checks": checks},
    )


# ---------- Routers LAST ----------
app.include_router(app_router, prefix="/app/v1")