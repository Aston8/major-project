import sys
import uvicorn
from app.core.config import settings

# Prevent Windows console UnicodeEncodeError for block progress bar characters
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

if __name__ == "__main__":
    print(f"Starting SmartShield AI API on {settings.HOST}:{settings.PORT}...")
    uvicorn.run(
        "app.main:app", 
        host=settings.HOST, 
        port=settings.PORT, 
        reload=True
    )
