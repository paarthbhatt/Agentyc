import subprocess
import sys

def run_cmd(cmd_list):
    print(f"Running: {' '.join(cmd_list)}")
    result = subprocess.run(cmd_list, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error running command: {result.stderr}")
        # Don't strictly fail on git commit if nothing to commit
        if "commit" not in cmd_list:
            pass
    return result.returncode

run_cmd(["git", "reset"])

commits = [
    (["README.md"], "Update README.md with project details"),
    (["all_inputs.txt", "user_inputs.txt", "user_inputs_clean.txt", "initial_prompt.txt"], "Add input text and prompt files"),
    (["extract.py", "get_prompt.py"], "Add helper scripts for extraction and prompts"),
    (["patch_migration.py", "patch_routes.py"], "Add scripts for patching migrations and routes"),
    (["docker-compose.yml"], "Update docker-compose.yml services"),
    (["backend/requirements.txt"], "Update backend dependencies"),
    (["backend/alembic/versions/001_initial_schema.py", "backend/alembic/versions/96799ffe7a70_initial.py", "backend/alembic/versions/__init__.py"], "Update alembic migrations"),
    (["backend/app/core/config.py"], "Update backend configuration"),
    (["backend/app/models.py", "backend/app/schemas.py"], "Update database models and schemas"),
    (["backend/app/api/auth.py", "backend/app/api/dependencies.py"], "Add auth logic and API dependencies"),
    (["backend/app/api/mcp_proxy.py", "backend/app/api/routes.py"], "Add MCP proxy and update API routes"),
    (["backend/app/services/firewall.py", "backend/app/services/graph_service.py"], "Add firewall and graph services"),
    (["backend/app/services/incident_response.py", "backend/app/services/risk_engine.py"], "Add incident response and risk engine services"),
    (["backend/app/services/seed.py"], "Update database seed script"),
    (["backend/app/tasks.py", "backend/app/worker.py"], "Add background tasks and Celery worker"),
    (["backend/app/main.py"], "Update FastAPI main application"),
    (["sdk/python/agent_sentinel/__init__.py", "sdk/python/agent_sentinel/langchain.py", "sdk/python/agent_sentinel/langgraph.py"], "Add Agent Sentinel Python SDK modules"),
    (["frontend/.dockerignore", "frontend/package.json", "frontend/package-lock.json"], "Update frontend configuration and dependencies"),
    (["frontend/src/App.tsx", "frontend/src/main.tsx", "frontend/src/lib/api.ts"], "Update frontend app entry point and API client"),
    (["frontend/src/components/layout/Sidebar.tsx", "frontend/src/components/layout/TopBar.tsx"], "Update layout components"),
    (["frontend/src/pages/AgentDetail.tsx", "frontend/src/pages/Agents.tsx"], "Add agents pages"),
    (["frontend/src/pages/AuditLogs.tsx", "frontend/src/pages/Overview.tsx"], "Add audit logs and overview pages"),
    (["frontend/src/pages/Policies.tsx", "frontend/src/pages/RedTeam.tsx"], "Add policies and red team pages")
]

for files, message in commits:
    for f in files:
        run_cmd(["git", "add", f])
    run_cmd(["git", "commit", "-m", message])

run_cmd(["git", "add", "."])
subprocess.run(["git", "commit", "-m", "Misc updates and fixes"])

ret = subprocess.run(["git", "push"])
if ret.returncode != 0:
    subprocess.run(["git", "push", "origin", "main"])
