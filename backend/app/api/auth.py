from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from app.core.db import get_db
from app.core.security import get_password_hash, verify_password, create_access_token
from app.models.user import UserCreate, UserLogin, UserResponse, Token, PasswordResetRequest, PasswordResetConfirm
from app.api.deps import get_current_user
from datetime import datetime, timedelta
from bson import ObjectId

router = APIRouter()

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate):
    db = get_db()
    
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_in.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists."
        )
        
    # Check if first user in system, make admin
    user_count = await db.users.count_documents({})
    role = "admin" if user_count == 0 else "user"
    
    # Create user
    user_dict = {
        "email": user_in.email,
        "hashed_password": get_password_hash(user_in.password),
        "role": role,
        "created_at": datetime.utcnow()
    }
    
    result = await db.users.insert_one(user_dict)
    user_dict["_id"] = str(result.inserted_id)
    
    # Log audit event
    await db.audit_logs.insert_one({
        "user_id": user_dict["_id"],
        "user_email": user_dict["email"],
        "action": "Register",
        "details": f"New user account registered with role: {role}.",
        "created_at": datetime.utcnow()
    })
    
    return user_dict

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_db()
    
    # Check user credentials
    user = await db.users.find_one({"email": form_data.username})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
        
    # Generate token
    token_data = {"sub": user["email"], "role": user["role"]}
    access_token = create_access_token(data=token_data)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user["role"],
        "email": user["email"]
    }

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return current_user

@router.post("/reset-password-request")
async def reset_password_request(req: PasswordResetRequest):
    db = get_db()
    user = await db.users.find_one({"email": req.email})
    if not user:
        # Avoid user enumeration, return success anyway
        return {"message": "If the account exists, a password reset link has been simulated."}
        
    # In a real environment, we'd send an email. For this project, we return a mock reset token
    # to facilitate the password reset flow.
    reset_token = f"reset_{str(user['_id'])}_{int(datetime.utcnow().timestamp())}"
    return {
        "message": "Password reset token generated (simulated link for email module)",
        "reset_token": reset_token
    }

@router.post("/reset-password-confirm")
async def reset_password_confirm(req: PasswordResetConfirm):
    db = get_db()
    
    # Basic token parsing for mock demo
    if not req.token.startswith("reset_"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
        
    try:
        parts = req.token.split("_")
        user_id = parts[1]
        user = await db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
            
        # Update password
        await db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"hashed_password": get_password_hash(req.new_password)}}
        )
        
        # Log audit log
        await db.audit_logs.insert_one({
            "user_id": str(user["_id"]),
            "user_email": user["email"],
            "action": "Password Reset",
            "details": "User password reset successfully completed.",
            "created_at": datetime.utcnow()
        })
        
        return {"status": "success", "message": "Password updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Token parse error: {e}")
