import re

with open(r'c:\Users\Parth\OneDrive\Desktop\Agentyc\backend\app\api\routes.py', 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Add imports at the top
imports = """from app.api.auth import get_current_org, get_current_user
from app.models import Organization, User
"""
if "get_current_org" not in code:
    code = code.replace("from app.db.session import SessionLocal, get_db", 
                        "from app.db.session import SessionLocal, get_db\n" + imports)

# 2. Add /agents/{agent_id}/rotate-key
rotate_key_route = """
@router.post("/agents/{agent_id}/rotate-key")
def rotate_agent_key(
    agent_id: UUID, 
    x_admin_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    require_admin_key(x_admin_api_key)
    agent = db.get(Agent, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
        
    # Rotate keys
    new_api_key = generate_api_key()
    agent.grace_period_api_key_hash = agent.api_key_hash
    agent.api_key_hash = hash_api_key(new_api_key)
    
    # Audit log
    audit_log = AuditLog(
        org_id=agent.org_id,
        action="rotate_api_key",
        resource_type="agent",
        resource_id=str(agent.id)
    )
    db.add(audit_log)
    db.commit()
    
    return {"message": "Key rotated successfully", "new_api_key": new_api_key}
"""
if "rotate_agent_key" not in code:
    code = code.replace("@router.get(\"/agents\"", rotate_key_route + "\n@router.get(\"/agents\"")

# 3. Add Tenancy filtering on list_agents
code = re.sub(
    r'def list_agents\(db: Session = Depends\(get_db\)\) -> list\[Agent\]:\n\s+return db.query\(Agent\).order_by\(desc\(Agent.created_at\)\).all\(\)',
    r'def list_agents(org: Organization = Depends(get_current_org), db: Session = Depends(get_db)) -> list[Agent]:\n    return db.query(Agent).filter(Agent.org_id == org.id).order_by(desc(Agent.created_at)).all()',
    code
)

# 4. Add Tenancy filtering on list_incidents
code = re.sub(
    r'def list_incidents\(db: Session = Depends\(get_db\)\) -> list\[Incident\]:\n\s+return db.query\(Incident\).order_by\(desc\(Incident.created_at\)\).all\(\)',
    r'def list_incidents(org: Organization = Depends(get_current_org), db: Session = Depends(get_db)) -> list[Incident]:\n    return db.query(Incident).filter(Incident.org_id == org.id).order_by(desc(Incident.created_at)).all()',
    code
)

# 5. Fix agent creation to use org from context
code = re.sub(
    r'org = db.query\(Organization\).filter\(Organization.slug == "demo-org"\).one_or_none\(\)\n\s+if not org:\n\s+org = Organization\([\s\S]*?db.flush\(\)',
    '',
    code
)
code = re.sub(
    r'def create_agent\(\n\s+payload: AgentCreate,\n\s+x_admin_api_key: str \| None = Header\(default=None\),\n\s+db: Session = Depends\(get_db\),\n\)\s*->\s*AgentCreateResponse:',
    'def create_agent(\n    payload: AgentCreate,\n    x_admin_api_key: str | None = Header(default=None),\n    org: Organization = Depends(get_current_org),\n    db: Session = Depends(get_db),\n) -> AgentCreateResponse:',
    code
)

# Also fix the AuditLog missing org_id in create_agent
code = re.sub(
    r'audit_log = AuditLog\(\n\s+action="create_agent",',
    'audit_log = AuditLog(\n        org_id=org.id,\n        action="create_agent",',
    code
)

with open(r'c:\Users\Parth\OneDrive\Desktop\Agentyc\backend\app\api\routes.py', 'w', encoding='utf-8') as f:
    f.write(code)
