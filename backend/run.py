import uvicorn
from app.core.config import settings

if __name__ == "__main__":
    print(f"Starting SmartShield AI API on {settings.HOST}:{settings.PORT}...")
    uvicorn.run(
        "app.main:app", 
        host=settings.HOST, 
        port=settings.PORT, 
        reload=True
    )
