import time
import threading
from collections import defaultdict
from fastapi import Request, HTTPException, status
from backend.config import get_settings


class RateLimiter:
    def __init__(self):
        settings = get_settings()
        self.max_requests = settings.RATE_LIMIT_REQUESTS
        self.window_seconds = settings.RATE_LIMIT_WINDOW_SECONDS
        self.requests: defaultdict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _get_client_key(self, request: Request, endpoint: str) -> str:
        client_ip = request.client.host if request.client else "unknown"
        return f"{client_ip}:{endpoint}"

    def _cleanup_old_requests(self, key: str):
        now = time.time()
        cutoff = now - self.window_seconds
        self.requests[key] = [ts for ts in self.requests[key] if ts > cutoff]

    async def check_rate_limit(self, request: Request, endpoint: str):
        key = self._get_client_key(request, endpoint)
        with self._lock:
            self._cleanup_old_requests(key)

            if len(self.requests[key]) >= self.max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded. Max {self.max_requests} requests per {self.window_seconds} seconds."
                )

            self.requests[key].append(time.time())