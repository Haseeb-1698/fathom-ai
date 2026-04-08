#!/bin/bash
# export_neo4j.sh — Export Neo4j data from Docker Desktop (Windows/local)
# and package it for transfer to the VM.
#
# Run this on your Windows machine (Git Bash) before deploying to the VM.

set -e

CONTAINER="fathom-neo4j"
BACKUP_DIR="./neo4j-backup"
BACKUP_FILE="neo4j-backup-$(date +%Y%m%d-%H%M%S).tar.gz"

echo "Exporting Neo4j data from container: $CONTAINER"

# Start container if stopped
docker start "$CONTAINER" 2>/dev/null || true
sleep 5

# Dump the database
docker exec "$CONTAINER" neo4j-admin database dump neo4j \
  --to-path=/tmp/neo4j-dump --overwrite-destination=true

# Copy dump out of container
mkdir -p "$BACKUP_DIR"
docker cp "$CONTAINER:/tmp/neo4j-dump/neo4j.dump" "$BACKUP_DIR/neo4j.dump"

# Also export volume data directly (alternative method)
docker run --rm \
  -v fathom_neo4j_data:/data \
  -v "$(pwd)/$BACKUP_DIR":/backup \
  alpine tar czf /backup/neo4j_data_volume.tar.gz -C /data .

echo "✅ Backup saved to $BACKUP_DIR/"
echo "   neo4j.dump          — database dump (preferred)"
echo "   neo4j_data_volume.tar.gz — raw volume backup (fallback)"
echo ""
echo "Transfer to VM:"
echo "  scp -i ~/.ssh/id_ed25519_vultr $BACKUP_DIR/neo4j.dump root@129.212.177.129:/opt/fathom/neo4j-backup/"
