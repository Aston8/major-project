from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from typing import Optional
from app.core.config import settings
from app.core.db import get_db
from app.core.security import decode_access_token
from bson import ObjectId

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    if token:
        payload = decode_access_token(token)
        if payload and payload.get("sub"):
            email: str = payload.get("sub")
            db = get_db()
            user = await db.users.find_one({"email": email})
            if user:
                user["_id"] = str(user["_id"])
                return user
                
    # Fallback analyst user for unauthenticated threat desk investigations
    return {"_id": "guest_analyst_01", "email": "analyst@shieldai.security", "role": "analyst"}

async def get_current_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have enough privileges"
        )
    return current_user
