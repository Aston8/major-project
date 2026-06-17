import logging
import motor.motor_asyncio
import redis
from app.core.config import settings

logger = logging.getLogger("smartshield.db")

# MongoDB client and database
mongo_client = None
db = None

# Redis client
redis_client = None
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

def init_redis():
    global redis_client
    try:
        redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
        # Test ping
        redis_client.ping()
        logger.info("Connected to Redis successfully.")
    except Exception as e:
        logger.warning(f"Could not connect to Redis: {e}. Falling back to in-memory caching.")
        redis_client = None

def get_db():
    if db is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return db

def cache_set(key: str, value: str, expire_seconds: int = 3600):
    if redis_client:
        try:
            redis_client.set(key, value, ex=expire_seconds)
        except Exception as e:
            logger.error(f"Redis set failed: {e}")
            _in_memory_cache[key] = value
    else:
        _in_memory_cache[key] = value

def cache_get(key: str) -> str:
    if redis_client:
        try:
            return redis_client.get(key)
        except Exception as e:
            logger.error(f"Redis get failed: {e}")
            return _in_memory_cache.get(key)
    return _in_memory_cache.get(key)

def cache_delete(key: str):
    if redis_client:
        try:
            redis_client.delete(key)
        except Exception as e:
            logger.error(f"Redis delete failed: {e}")
            _in_memory_cache.pop(key, None)
    else:
        _in_memory_cache.pop(key, None)
