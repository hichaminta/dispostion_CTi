from fastapi import APIRouter, Depends, HTTPException
from .auth import get_keycloak_admin, require_role

router = APIRouter(
    prefix="/api/admin",
    tags=["admin"],
    dependencies=[Depends(require_role("admin"))]
)

@router.get("/users")
def get_users(admin=Depends(get_keycloak_admin)):
    try:
        return admin.get_users()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/users")
def create_user(user_data: dict, admin=Depends(get_keycloak_admin)):
    try:
        new_user_id = admin.create_user(user_data)
        return {"status": "success", "user_id": new_user_id}
    except Exception as e:
        err_str = str(e)
        # Extract cleaner message from Keycloak error response
        if "409" in err_str or "Conflict" in err_str:
            raise HTTPException(status_code=409, detail="Un utilisateur avec ce nom existe déjà")
        if "errorMessage" in err_str:
            import re
            match = re.search(r'"errorMessage"\s*:\s*"([^"]+)"', err_str)
            if match:
                raise HTTPException(status_code=400, detail=match.group(1))
        raise HTTPException(status_code=500, detail=f"Erreur Keycloak: {err_str}")

@router.delete("/users/{user_id}")
def delete_user(user_id: str, admin=Depends(get_keycloak_admin)):
    try:
        admin.delete_user(user_id)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/roles")
def get_roles(admin=Depends(get_keycloak_admin)):
    try:
        return admin.get_realm_roles()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/users/{user_id}/roles")
def assign_role(user_id: str, role_name: str, admin=Depends(get_keycloak_admin)):
    try:
        role = admin.get_realm_role(role_name)
        admin.assign_realm_roles(user_id=user_id, roles=[role])
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
