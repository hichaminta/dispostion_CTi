from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from keycloak import KeycloakOpenID, KeycloakAdmin
from jose import jwt, JWTError
import os

KEYCLOAK_URL           = os.getenv("KEYCLOAK_URL",           "http://localhost:8080/")
KEYCLOAK_REALM         = os.getenv("KEYCLOAK_REALM",         "cti-realm")
KEYCLOAK_CLIENT_ID     = os.getenv("KEYCLOAK_CLIENT_ID",     "cti-client")
KEYCLOAK_ADMIN_USER    = os.getenv("KEYCLOAK_ADMIN_USER",    "admin")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD", "admin")

keycloak_openid = KeycloakOpenID(
    server_url=KEYCLOAK_URL,
    client_id=KEYCLOAK_CLIENT_ID,
    realm_name=KEYCLOAK_REALM,
    verify=True
)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{KEYCLOAK_URL}realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
)

def get_keycloak_admin() -> KeycloakAdmin:
    return KeycloakAdmin(
        server_url=KEYCLOAK_URL,
        username=KEYCLOAK_ADMIN_USER,
        password=KEYCLOAK_ADMIN_PASSWORD,
        realm_name=KEYCLOAK_REALM,
        user_realm_name="master",
        verify=True
    )

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        public_key = keycloak_openid.public_key()
        key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
        payload = jwt.decode(
            token,
            key_pem,
            algorithms=["RS256"],
            options={"verify_aud": False}
        )
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token invalide: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Erreur auth: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

def require_role(role_name: str):
    async def role_checker(user: dict = Depends(get_current_user)):
        roles = user.get("realm_access", {}).get("roles", [])
        if role_name not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rôle requis : {role_name}"
            )
        return user
    return role_checker
