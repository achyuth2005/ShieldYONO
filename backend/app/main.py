"""ShieldYONO FastAPI application entry point."""

import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import CORS_ORIGINS, DEBUG
from backend.app.core.database import init_db
from backend.app.api.routes import router

# Configure logging
logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("shieldyono")

app = FastAPI(
    title="ShieldYONO — URL Phishing Classifier",
    description=(
        "Real-time phishing URL detection API for SBI YONO. "
        "Analyzes URLs for phishing indicators, brand impersonation, "
        "and structural anomalies using ML + rule-based scoring."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="/api")


@app.on_event("startup")
async def startup():
    logger.info("🛡️  ShieldYONO starting up...")
    init_db()
    logger.info("✅ Database initialized")
    logger.info("🚀 API ready at /docs")


@app.get("/")
async def root():
    return {
        "name": "ShieldYONO — URL Phishing Classifier",
        "version": "1.0.0",
        "docs": "/docs",
        "api": "/api/check-url?url=https://example.com",
    }
