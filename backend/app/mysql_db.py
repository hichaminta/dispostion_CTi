import os
from sqlalchemy import create_engine, Column, String, Boolean, JSON
from sqlalchemy.orm import sessionmaker, declarative_base
# import removed

MYSQL_USER = os.getenv("MYSQL_USER", "admin")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "admin")
MYSQL_DB = os.getenv("MYSQL_DB", "cyberhud_db")
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_PORT = os.getenv("MYSQL_PORT", "3306")

SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

import hashlib

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hashlib.sha256(plain_password.encode('utf-8')).hexdigest() == hashed_password

class User(Base):
    __tablename__ = "users"

    id = Column(String(50), primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    hashed_password = Column(String(255))
    roles = Column(JSON, default=["user"])
    is_active = Column(Boolean, default=True)

def init_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    # Create default admin user if not exists
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        hashed_pw = hash_password("admin")
        new_admin = User(
            id="1",
            username="admin",
            hashed_password=hashed_pw,
            roles=["admin", "user"],
            is_active=True
        )
        db.add(new_admin)
        db.commit()
    db.close()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
