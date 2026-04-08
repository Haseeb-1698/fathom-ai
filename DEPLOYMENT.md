# Fathom — Deployment Guide

## Architecture

```
VM: 134.199.201.243  (AMD MI300X · Ubuntu 22.04 · ROCm 7.0)
│
├── serve.py  ──────────────────── port 8000  (host process — direct GPU/ROCm)
│   Mixtral-8x7B bf16 + umer07/fathom-mixtral LoRA
│   Talks to: Azure Kimi-K2.5 (enrichment swarm)
│
├── [Docker] fathom-neo4j ────────── port 7687 bolt / 7474 browser
│   neo4j:5  ·  volumes: fathom_neo4j_data, fathom_neo4j_logs
│   Password: $NEO4J_PASSWORD
│
├── [Docker] fathom-backend ─────── port 7860  (FastAPI — backend/)
│   network_mode: host → reaches serve.py on 127.0.0.1:8000
│   FAISS index: ./backend/rag/index mounted read-only
│
└── [Docker] fathom-dashboard ───── port 3000  (Next.js — dashboard/)
```

`serve.py` runs **outside Docker** for native ROCm GPU access.  
Everything else is managed by `docker compose`.

---

## Prerequisites on the VM

```bash
# Install Docker + Compose plugin (if not present)
curl -fsSL https://get.docker.com | sh
apt-get install -y docker-compose-plugin
docker compose version   # should print v2.x
```

---

## First-time Deploy

### 1. Upload the project from Windows

```bash
# From Git Bash on Windows
rsync -avz \
  --exclude '__pycache__' --exclude '*.pyc' \
  --exclude '.next' --exclude 'node_modules' \
  --exclude '.git' \
  -e "ssh -i ~/.ssh/id_ed25519_vultr" \
  G:/FYp/fathom/ root@134.199.201.243:/opt/fathom/
```

### 2. Create the .env file on the VM

```bash
ssh root@134.199.201.243 -i ~/.ssh/id_ed25519_vultr
cd /opt/fathom
cp .env.example .env
# All values are pre-filled — verify and adjust if needed
cat .env
```

### 3. Create the Docker volumes (matching your existing Docker Desktop volumes)

The Neo4j volumes from Docker Desktop are named `fathom_neo4j_data` and `fathom_neo4j_logs`.  
On the VM, create them with the same names so `docker-compose.yml` can reference them:

```bash
docker volume create fathom_neo4j_data
docker volume create fathom_neo4j_logs
```

If you want to migrate your existing Neo4j data from Docker Desktop to the VM, see the
**Neo4j Data Migration** section below. Otherwise the VM starts with an empty database.

### 4. Make sure serve.py is running

```bash
# Check
curl http://localhost:8000/health
# {"status":"ok","model":"umer07/fathom-mixtral"}

# If not running:
pkill -f serve.py 2>/dev/null; sleep 2
HF_TOKEN=$HF_TOKEN \
  nohup python3 /root/serve.py > /root/fathom.log 2>&1 &
echo "Waiting for model to load (~3 min from cache)..."
tail -f /root/fathom.log
# Wait until you see: "Model ready."
```

### 5. Start all Docker services

```bash
cd /opt/fathom
docker compose up -d --build
```

First build: ~5–8 min (pip install + npm build).  
Subsequent starts: ~30 seconds.

### 6. Verify everything is up

```bash
docker compose ps
# All three services should show "running" or "healthy"

# Neo4j
curl http://localhost:7474
# Backend
curl http://localhost:7860/health
# {"status":"ok","version":"0.2.0"}
# Dashboard
curl -I http://localhost:3000
# HTTP/1.1 200 OK

# Full pipeline test
curl -s -X POST http://localhost:7860/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"query":"What is process injection?","enable_enrichment":false}' \
  | python3 -m json.tool
```

---

## FAISS Index

The ATT&CK knowledge base FAISS index is **pre-built** and ships with the repo at:
```
backend/rag/index/attack_kb/
  index.faiss    (2 MB — 691 technique vectors)
  metadata.json  (1.3 MB — technique metadata)
```

It is mounted **read-only** into the backend container via `docker-compose.yml`:
```yaml
- ./backend/rag/index:/app/rag/index:ro
```

No action needed — it works out of the box.

### Rebuild the index (if you add new ATT&CK techniques)

```bash
# On the VM, run inside the backend container
docker compose exec backend python scripts/build_faiss_index.py

# Or with a custom STIX file
docker compose exec backend python scripts/build_faiss_index.py \
  --stix-path /app/data/enterprise-attack.json

# Restart backend to pick up new index
docker compose restart backend
```

---

## Neo4j

### Connection details

| Field | Value |
|---|---|
| Bolt URI | `bolt://localhost:7687` |
| Browser | `http://134.199.201.243:7474` |
| Username | `neo4j` |
| Password | `fathom2024` |
| Docker volumes | `fathom_neo4j_data`, `fathom_neo4j_logs` |

### Data persists across restarts

Neo4j data lives in the `fathom_neo4j_data` Docker named volume — survives container
restarts, rebuilds, and `docker compose down` (but NOT `docker compose down -v`).

### Useful commands

```bash
# Open Cypher shell
docker exec -it fathom-neo4j cypher-shell -u neo4j -p fathom2024

# Count nodes
docker exec fathom-neo4j cypher-shell -u neo4j -p fathom2024 \
  "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC"

# Backup
docker exec fathom-neo4j neo4j-admin database dump neo4j \
  --to-path=/tmp/neo4j-dump --overwrite-destination=true
docker cp fathom-neo4j:/tmp/neo4j-dump/neo4j.dump ./neo4j.dump
```

### Neo4j Data Migration (Docker Desktop → VM)

If you want to bring your existing Neo4j data from Docker Desktop on Windows to the VM:

**Step 1 — Export from Docker Desktop (Windows, Git Bash)**
```bash
cd G:/FYp/fathom
bash scripts/export_neo4j.sh
# Creates ./neo4j-backup/neo4j.dump
```

**Step 2 — Upload to VM**
```bash
ssh root@134.199.201.243 -i ~/.ssh/id_ed25519_vultr "mkdir -p /opt/fathom/neo4j-backup"
scp -i ~/.ssh/id_ed25519_vultr \
  neo4j-backup/neo4j.dump \
  root@134.199.201.243:/opt/fathom/neo4j-backup/
```

**Step 3 — Import on VM**
```bash
ssh root@134.199.201.243 -i ~/.ssh/id_ed25519_vultr
cd /opt/fathom
bash scripts/import_neo4j.sh /opt/fathom/neo4j-backup/neo4j.dump
```

---

## Re-deploy After Code Changes

```bash
# Sync from Windows
rsync -avz \
  --exclude '__pycache__' --exclude '*.pyc' \
  --exclude '.next' --exclude 'node_modules' \
  -e "ssh -i ~/.ssh/id_ed25519_vultr" \
  G:/FYp/fathom/ root@134.199.201.243:/opt/fathom/

# Rebuild only what changed
ssh root@134.199.201.243 -i ~/.ssh/id_ed25519_vultr "cd /opt/fathom && docker compose up -d --build backend"

# Dashboard change
ssh root@134.199.201.243 -i ~/.ssh/id_ed25519_vultr "cd /opt/fathom && docker compose up -d --build dashboard"
```

---

## Logs

```bash
docker compose logs -f              # all services
docker compose logs -f backend      # API only
docker compose logs -f neo4j        # Neo4j only
tail -f /root/fathom.log            # serve.py (model)
```

---

## Ports Summary

| Service | Port | Accessible |
|---|---|---|
| serve.py (Mixtral model) | 8000 | VM-internal only |
| Fathom API (backend) | 7860 | Public |
| Fathom Dashboard | 3000 | Public |
| Neo4j bolt | 7687 | VM-internal |
| Neo4j browser | 7474 | VM-internal (open for admin if needed) |

---

## Troubleshooting

### Backend can't reach serve.py
```bash
# backend uses network_mode: host — 127.0.0.1:8000 is the VM's own port
curl http://localhost:8000/health
# If this fails, serve.py is down — see Step 4 above
```

### Neo4j volumes don't exist yet
```bash
# Error: "volume fathom_neo4j_data declared as external, but could not be found"
docker volume create fathom_neo4j_data
docker volume create fathom_neo4j_logs
docker compose up -d
```

### Neo4j not ready / backend can't connect
```bash
docker compose logs neo4j | tail -30
# Wait for "Started." — takes ~20s on first boot
docker compose restart backend   # retry after Neo4j is healthy
```

### Dashboard build OOM
```bash
# Next.js needs ~2GB RAM during build
free -h
# If tight, build with increased heap:
docker compose build \
  --build-arg NODE_OPTIONS="--max-old-space-size=3072" dashboard
```

### FAISS index not found
```bash
# Check the index files are present
ls -lh backend/rag/index/attack_kb/
# Should show index.faiss (~2MB) and metadata.json (~1.3MB)
# If missing, rebuild:
docker compose exec backend python scripts/build_faiss_index.py
```

### Azure enrichment not working
```bash
curl -s "https://cb26haseeb-5473-resource.openai.azure.com/openai/v1/models" \
  -H "api-key: $(grep AZURE_API_KEY /opt/fathom/.env | cut -d= -f2)" \
  | python3 -m json.tool | grep '"id"'
# Should include Kimi-K2.5
```

### Wipe and start fresh (WARNING: destroys Neo4j data)
```bash
cd /opt/fathom
docker compose down
# Only add -v if you want to wipe Neo4j data too:
# docker compose down -v
docker compose up -d --build
```
