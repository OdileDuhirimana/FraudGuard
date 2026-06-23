import time
from typing import Dict, Tuple
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

# Simple in-memory rate limiter: max N requests per window per (ip)
class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window = window_seconds
        self.buckets: Dict[str, Tuple[int, float]] = {}

    async def dispatch(self, request: Request, call_next):
        key = request.client.host if request.client else "unknown"
        now = time.time()
        count, start = self.buckets.get(key, (0, now))
        if now - start > self.window:
            count, start = 0, now
        count += 1
        self.buckets[key] = (count, start)
        if count > self.max_requests:
            from starlette.responses import JSONResponse
            return JSONResponse({"detail": "rate_limit_exceeded"}, status_code=429)
        response = await call_next(request)
        return response
