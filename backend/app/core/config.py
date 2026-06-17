import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PORT: int = 8000
    HOST: str = "0.0.0.0"
    
    # Database & Caching
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "smartshield"
    REDIS_URL: str = "redis://localhost:6379"
    
    # Security / Auth
    JWT_SECRET: str = "b6540c1e847c2b5e28a5b7d42cfcf307221d8b7470fcf214777d01cd63b827e7"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    # External APIs
    GEMINI_API_KEY: str = ""
    GROK_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    
    # Sandbox Environment Settings
    SANDBOX_DOCKER_IMAGE: str = "smartshield-sandbox:latest"
    SANDBOX_TIMEOUT: int = 60
    USE_LOCAL_PLAYWRIGHT_FALLBACK: bool = True
    
    # File storage paths
    UPLOAD_DIR: str = "./uploads"
    SCREENSHOT_DIR: str = "./uploads/screenshots"
    PDF_DIR: str = "./uploads/reports"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# Ensure directories exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.SCREENSHOT_DIR, exist_ok=True)
os.makedirs(settings.PDF_DIR, exist_ok=True)
