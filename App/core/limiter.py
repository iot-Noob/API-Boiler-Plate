from slowapi import Limiter
from slowapi.util import get_remote_address
from App.core.settings import settings

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
    storage_uri=settings.REDIS_URL,
)