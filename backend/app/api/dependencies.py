from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models import Agent

def require_api_key(x_api_key: str | None = Header(default=None), db: Session = Depends(get_db)) -> Agent:
    """Dependency that validates an agent's API key."""
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header missing")
    
    # Very basic lookup for prototype. In production, hash the key and compare.
    import hashlib
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    
    agent = db.query(Agent).filter(Agent.api_key_hash == key_hash).first()
    if not agent:
        # Check grace period
        agent = db.query(Agent).filter(Agent.grace_period_api_key_hash == key_hash).first()
        if not agent:
            raise HTTPException(status_code=401, detail="Invalid API key")
            
    return agent

def require_admin_key(x_admin_api_key: str | None = Header(default=None)):
    """Validates the global admin key for the prototype."""
    import os
    expected_key = os.getenv("ADMIN_API_KEY", "dev-admin-key")
    if not x_admin_api_key or x_admin_api_key != expected_key:
        raise HTTPException(status_code=401, detail="Invalid admin API key")
