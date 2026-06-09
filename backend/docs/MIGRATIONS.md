# Database Migrations Guide

**Agent Sentinel** uses **Alembic** for deterministic database schema versioning and evolution.

---

## Overview

- **Tool**: Alembic (SQLAlchemy migrations)
- **Location**: `backend/alembic/`
- **Configuration**: `backend/alembic.ini`
- **Initial Migration**: `001_initial_schema.py`

---

## Migration Structure

```
backend/
├── alembic/
│   ├── env.py                    # Alembic runtime configuration
│   ├── script.py.mako            # Migration template
│   ├── versions/                 # Individual migration files
│   │   ├── __init__.py
│   │   └── 001_initial_schema.py # Initial schema (Phase 8)
│   └── __init__.py
├── alembic.ini                   # Connection string & logging config
├── entrypoint.sh                 # Docker entrypoint (runs migrations)
└── Dockerfile                    # Updated to copy alembic/ and run migrations
```

---

## Quick Start

### Local Development

#### 1. Install dependencies
```bash
cd backend
pip install -r requirements.txt
```

#### 2. Set up environment
Create `.env`:
```bash
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost/agent_sentinel
```

#### 3. Apply all pending migrations
```bash
alembic upgrade head
```

#### 4. Check migration status
```bash
alembic current    # Show current revision
alembic history    # Show all applied migrations
```

#### 5. Undo last migration (downgrade)
```bash
alembic downgrade -1
```

### Docker Deployment

#### Build image with automatic migrations
```bash
docker build -t agent-sentinel:latest backend/
```

#### Run container
```bash
docker run -e DATABASE_URL=postgresql+psycopg://user:pass@db:5432/agent_sentinel \
  agent-sentinel:latest
```

The entrypoint script automatically:
1. Runs `alembic upgrade head`
2. Starts uvicorn

---

## Creating New Migrations

### Auto-generate migration from model changes

```bash
# After modifying models.py, generate migration
alembic revision --autogenerate -m "Add new_column to users table"
```

This creates a new file in `alembic/versions/` like:
```
002_add_new_column_to_users_table.py
```

Review and edit the generated file if needed.

### Manual migration

```bash
# Create empty migration
alembic revision -m "Add audit logging table"
```

Edit the file to implement `upgrade()` and `downgrade()` functions.

### Apply new migration
```bash
alembic upgrade head
```

---

## Migration Workflow

### Development

1. **Modify** `backend/app/models.py`
2. **Generate** migration: `alembic revision --autogenerate -m "..."`
3. **Review** the generated migration file
4. **Apply**: `alembic upgrade head`
5. **Test** with `pytest`
6. **Commit** migration file with model changes

### Staging/Production

1. **Pull** latest code with new migrations
2. **Deploy** new container (or run `alembic upgrade head` before app start)
3. **Verify** with health checks
4. **Rollback** if needed: `alembic downgrade -1`

---

## Best Practices

### ✅ DO

- ✅ Create a migration for **every schema change**
- ✅ Test migrations **up and down** locally before deploying
- ✅ Keep migrations **small and focused** (one logical change per file)
- ✅ Use **descriptive names**: `002_add_api_key_table.py`
- ✅ Review generated migrations for accuracy
- ✅ Commit migrations with the code that uses them
- ✅ Test zero-downtime deployments:
  ```bash
  alembic upgrade head  # Apply migrations
  docker run app:new    # Run new app code
  ```

### ❌ DON'T

- ❌ Modify **past migrations** (they must be immutable)
- ❌ Skip migrations in dev/test environments
- ❌ Create migrations that **drop tables** without careful review
- ❌ Use `Base.metadata.create_all()` in production (only use migrations)
- ❌ Deploy app code changes **without running migrations first**

---

## Common Tasks

### Check current revision
```bash
alembic current
# Output: 001_initial_schema
```

### View all migrations
```bash
alembic history
# Output:
# 001_initial_schema -> (head), 2026-06-07
```

### Roll back one migration
```bash
alembic downgrade -1
```

### Roll back to specific revision
```bash
alembic downgrade 001_initial_schema
```

### Drop everything and recreate
```bash
alembic downgrade base  # Revert to before 001_initial_schema
alembic upgrade head    # Recreate from scratch
```

### View migration SQL (without executing)
```bash
alembic upgrade head --sql
```

---

## Debugging

### Migration stuck / won't apply?

```bash
# Check current state
alembic current

# Check version table in DB
psql agent_sentinel -c "SELECT * FROM alembic_version;"

# If stuck, can manually update version table (DANGEROUS)
psql agent_sentinel -c "INSERT INTO alembic_version (version_num) VALUES ('001_initial_schema');"
```

### Dependency error on migration?

Ensure all FK references are created in correct order. Alembic applies migrations sequentially, so if table A references table B, B must be created first.

### Auto-generate doesn't detect change?

```bash
# Try explicit detection with verbose output
alembic revision --autogenerate -m "..." --verbose
```

---

## Zero-Downtime Deployment Strategy

For production deployments without downtime:

1. **Blue-Green Deployment**:
   ```bash
   # Deploy "green" instances with new migrations applied
   docker run -e DATABASE_URL=... agent-sentinel:new
   
   # Traffic still goes to "blue" (old instances)
   # Once green is healthy, switch traffic
   # Restart old "blue" instances
   ```

2. **Backward-Compatible Migrations**:
   - Always add columns as **nullable** at first
   - Add defaults if needed
   - Never drop columns without migration + code changes (2+ releases)

3. **Test Rollback**:
   ```bash
   alembic upgrade head
   alembic downgrade -1  # Verify downgrade works
   alembic upgrade head  # Verify upgrade works
   ```

---

## Troubleshooting

### PostgreSQL connection refused?
```bash
# Check connection string in .env
DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost/agent_sentinel

# Or in Docker, use hostname of DB service
DATABASE_URL=postgresql+psycopg://postgres:postgres@db:5432/agent_sentinel
```

### Migration file syntax error?
```bash
# Validate migration
python -m py_compile alembic/versions/001_initial_schema.py

# If error, check indentation and imports
```

### Need to rebase migrations?
```bash
# Squash early migrations into one (for cleaner repo)
# Create new migration that combines them:
alembic merge --from-rev 001_initial_schema --to-rev 003_final_schema -m "Squash early migrations"
```

---

## Future Enhancements

- **Phase 11**: Add migration testing framework
- **Phase 13**: Add audit trail for migrations
- **Phase 15**: Backup migration state before applying in prod
