from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from .routers import auth as auth_router
from .routers import fraud as fraud_router
from .routers import admin as admin_router
from .middleware import RateLimitMiddleware

app = FastAPI(title="FraudGuard ML API", version="0.1.0")


def parse_origins(raw: str) -> list[str]:
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or ["*"]


allowed_origins = parse_origins(os.getenv("CORS_ALLOWED_ORIGINS", "*"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware, max_requests=300, window_seconds=60)

app.include_router(auth_router.router, prefix="/auth", tags=["auth"])
app.include_router(fraud_router.router, prefix="/fraud", tags=["fraud"])
app.include_router(admin_router.router, prefix="/admin", tags=["admin"])

@app.get("/")
def root():
    return {"name": "FraudGuard ML API", "status": "ok"}


@app.get("/health")
def health():
    return {"ok": True}
