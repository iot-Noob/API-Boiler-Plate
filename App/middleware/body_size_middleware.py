# App/middleware/body_size_middleware.py
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from App.core.LoggingInit import get_core_logger
from App.core.size_parser import format_size, parse_size

logger = get_core_logger(__name__)


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_size: int = 1 * 1024 * 1024):
        super().__init__(app)
        self.max_size = parse_size(max_size) if isinstance(max_size, (str, int)) else int(max_size)

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                length_value = int(content_length)
                max_size = int(self.max_size)
                if length_value > max_size:
                    logger.warning(
                        f"Request body too large: {format_size(length_value)} "
                        f"> {format_size(max_size)} path={request.url.path}"
                    )
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "Request body too large",
                            "max_bytes": max_size,
                            "max_human": format_size(max_size),
                        },
                    )
            except (TypeError, ValueError):
                return JSONResponse(
                    status_code=400,
                    content={"error": "Invalid Content-Length header"},
                )
        return await call_next(request)