import sys
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import uuid

from .auth import require_role
from app.mysql_db import get_db, User, hash_password

router = APIRouter(
    prefix="/api/admin",
    tags=["admin"],
    dependencies=[Depends(require_role("admin"))]
)

@router.get("/users")
def get_users(db: Session = Depends(get_db)):
    try:
        users = db.query(User).all()
        return [{"id": u.id, "username": u.username, "enabled": u.is_active, "realm_access": {"roles": u.roles}} for u in users]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/users")
def create_user(user_data: dict, db: Session = Depends(get_db)):
    try:
        username = user_data.get("username")
        password = user_data.get("credentials", [{}])[0].get("value") or user_data.get("password")
        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")
            
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            raise HTTPException(status_code=409, detail="Un utilisateur avec ce nom existe déjà")
            
        new_user = User(
            id=str(uuid.uuid4()),
            username=username,
            hashed_password=hash_password(password),
            roles=["user"],
            is_active=True
        )
        db.add(new_user)
        db.commit()
        return {"status": "success", "user_id": new_user.id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur DB: {str(e)}")

@router.delete("/users/{user_id}")
def delete_user(user_id: str, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
        db.delete(user)
        db.commit()
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/roles")
def get_roles():
    try:
        # Static roles for now
        return [{"name": "admin"}, {"name": "user"}, {"name": "editor"}]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/users/{user_id}/roles")
def assign_role(user_id: str, role_name: str, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur non trouvé")
            
        roles = list(user.roles) if user.roles else []
        if role_name not in roles:
            roles.append(role_name)
            user.roles = roles
            db.commit()
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
