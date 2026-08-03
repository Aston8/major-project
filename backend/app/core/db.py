import logging
import motor.motor_asyncio
from app.core.config import settings

logger = logging.getLogger("smartshield.db")

# MongoDB client and database
mongo_client = None
db = None

# In-memory cache
_in_memory_cache = {}

async def init_db():
    global mongo_client, db
    try:
        mongo_client = motor.motor_asyncio.AsyncIOMotorClient(settings.MONGODB_URL)
        db = mongo_client[settings.MONGODB_DB_NAME]
        
        # Test connection
        await mongo_client.admin.command('ping')
        logger.info("Connected to MongoDB successfully.")
        
        # Create indexes
        await db.users.create_index("email", unique=True)
        await db.scans.create_index("user_id")
        await db.scans.create_index("created_at")
        await db.blacklists.create_index("value", unique=True)
        await db.audit_logs.create_index("created_at")
        
        logger.info("MongoDB collections and indexes initialized.")
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise e



def get_db():
    if db is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return db

def cache_set(key: str, value: str, expire_seconds: int = 3600):
    _in_memory_cache[key] = value

def cache_get(key: str) -> str:
    return _in_memory_cache.get(key)

def cache_delete(key: str):
    _in_memory_cache.pop(key, None)
