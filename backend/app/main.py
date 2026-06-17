from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.core.db import init_db, init_redis
from app.services.ml_service import initialize_ml_models
from app.api import auth, scans, admin

# Setup logger configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("smartshield")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info("Initializing databases...")
    await init_db()
    init_redis()
    
    # Trigger local ML models lazy load in background task
    logger.info("Scheduling background loading of ML models...")
    import asyncio
    asyncio.create_task(initialize_ml_models())
    
    yield
    # Shutdown actions
    logger.info("Shutting down SmartShield backend.")

app = FastAPI(
    title="SmartShield AI API",
    description="Multi-Modal Scam Detection, Threat Intelligence & Secure URL Sandbox Platform",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all origins for academic/local evaluation
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static file serving (e.g. downloads, uploaded audio/images)
app.mount("/static", StaticFiles(directory=settings.UPLOAD_DIR), name="static")

# Include Routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin Panel"])

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "SmartShield AI Backend Gateway",
        "documentation": "/docs"
    }

@app.get("/health")
async def health_check():
    import datetime
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
