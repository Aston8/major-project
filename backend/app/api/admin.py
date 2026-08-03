from fastapi import APIRouter, Depends, HTTPException, status, Query
from app.api.deps import get_current_admin
from app.core.db import get_db
from app.models.admin import BlacklistCreate, BlacklistItem, UserRoleUpdate, SystemStats, AuditLogResponse
from datetime import datetime
from bson import ObjectId
from typing import List

router = APIRouter()

@router.get("/stats", response_model=SystemStats)
async def get_system_stats(admin: dict = Depends(get_current_admin)):
    db = get_db()
    
    # 1. Total users
    total_users = await db.users.count_documents({})
    
    # 2. Total scans
    total_scans = await db.scans.count_documents({})
    
    # 3. Scans by type
    types = ["text", "url", "image", "voice", "email"]
    scans_by_type = {}
    for t in types:
        scans_by_type[t] = await db.scans.count_documents({"type": t})
        
    # 4. Scans by category
    categories = ["Safe", "Suspicious", "Dangerous"]
    scans_by_category = {}
    for cat in categories:
        scans_by_category[cat] = await db.scans.count_documents({"fusion_result.category": cat})
        
    # 5. Blacklist count
    blacklist_count = await db.blacklists.count_documents({})
    
    # 6. Active sandbox containers (Simulate count)
    active_sandbox_containers = 0
    try:
        import docker
        client = docker.from_env()
        containers = client.containers.list(filters={"ancestor": "smartshield-sandbox"})
        active_sandbox_containers = len(containers)
    except Exception:
        pass
        
    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "scans_by_type": scans_by_type,
        "scans_by_category": scans_by_category,
        "blacklist_count": blacklist_count,
        "active_sandbox_containers": active_sandbox_containers,
        "redis_connected": False,
        "mongodb_connected": True
    }

@router.get("/users")
async def list_users(
    admin: dict = Depends(get_current_admin),
    skip: int = 0,
    limit: int = 50
):
    db = get_db()
    cursor = db.users.find({}, {"hashed_password": 0}).skip(skip).limit(limit)
    users = []
    async for u in cursor:
        u["_id"] = str(u["_id"])
        users.append(u)
    return users

@router.put("/users/role")
async def update_user_role(
    req: UserRoleUpdate,
    admin: dict = Depends(get_current_admin)
):
    db = get_db()
    
    if req.role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role specifier.")
        
    result = await db.users.update_one(
        {"_id": ObjectId(req.user_id)},
        {"$set": {"role": req.role}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found.")
        
    # Add audit log
    await db.audit_logs.insert_one({
        "user_id": admin["_id"],
        "user_email": admin["email"],
        "action": "Update Role",
        "details": f"Updated user role for ID '{req.user_id}' to: {req.role}.",
        "created_at": datetime.utcnow()
    })
    
    return {"status": "success", "message": f"User role updated to {req.role}"}

@router.get("/blacklist")
async def list_blacklist(admin: dict = Depends(get_current_admin)):
    db = get_db()
    cursor = db.blacklists.find()
    blacklist = []
    async for item in cursor:
        item["_id"] = str(item["_id"])
        blacklist.append(item)
    return blacklist

@router.post("/blacklist")
async def add_blacklist(
    req: BlacklistCreate,
    admin: dict = Depends(get_current_admin)
):
    db = get_db()
    
    # Check if duplicate
    existing = await db.blacklists.find_one({"value": req.value})
    if existing:
        raise HTTPException(status_code=400, detail="Value is already blacklisted.")
        
    item = {
        "value": req.value,
        "type": req.type,
        "notes": req.notes,
        "created_at": datetime.utcnow()
    }
    
    result = await db.blacklists.insert_one(item)
    item["_id"] = str(result.inserted_id)
    
    # Add audit log
    await db.audit_logs.insert_one({
        "user_id": admin["_id"],
        "user_email": admin["email"],
        "action": "Add Blacklist",
        "details": f"Added value '{req.value}' (type: {req.type}) to custom blacklist.",
        "created_at": datetime.utcnow()
    })
    
    return item

@router.delete("/blacklist/{item_id}")
async def remove_blacklist(
    item_id: str,
    admin: dict = Depends(get_current_admin)
):
    db = get_db()
    
    result = await db.blacklists.delete_one({"_id": ObjectId(item_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Blacklist item not found.")
        
    # Add audit log
    await db.audit_logs.insert_one({
        "user_id": admin["_id"],
        "user_email": admin["email"],
        "action": "Remove Blacklist",
        "details": f"Deleted blacklist item ID: {item_id}.",
        "created_at": datetime.utcnow()
    })
    
    return {"status": "success", "message": "Blacklist item removed"}

@router.get("/audit-logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    admin: dict = Depends(get_current_admin),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200)
):
    db = get_db()
    cursor = db.audit_logs.find().sort("created_at", -1).skip(skip).limit(limit)
    logs = []
    async for entry in cursor:
        entry["_id"] = str(entry["_id"])
        logs.append(entry)
    return logs
