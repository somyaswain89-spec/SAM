from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.core.config import APP_ENV, REDIS_URL

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["120/minute"],
    storage_uri=REDIS_URL if APP_ENV == "production" else None,
)
