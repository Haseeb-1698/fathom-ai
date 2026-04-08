#!/bin/bash
# import_neo4j.sh — Import Neo4j dump into the VM's Docker container.
# Run this ON THE VM after uploading neo4j.dump.

set -e

DUMP_FILE="${1:-/opt/fathom/neo4j-backup/neo4j.dump}"
CONTAINER="fathom-neo4j"

if [ ! -f "$DUMP_FILE" ]; then
  echo "Usage: $0 /path/to/neo4j.dump"
  echo "No dump file found at $DUMP_FILE — skipping import (starting fresh)"
  exit 0
fi

echo "Importing Neo4j dump: $DUMP_FILE"

# Stop the container so we can load the dump
docker stop "$CONTAINER" 2>/dev/null || true

# Copy dump into container
docker cp "$DUMP_FILE" "$CONTAINER:/tmp/neo4j.dump"

# Load the dump (neo4j-admin load requires the db to be stopped)
docker run --rm \
  -v fathom_neo4j_data:/data \
  -v "$(dirname $DUMP_FILE)":/backup \
  neo4j:5 \
  neo4j-admin database load neo4j \
    --from-path=/backup \
    --overwrite-destination=true

echo "✅ Neo4j data imported"
echo "Starting container..."
docker start "$CONTAINER"
sleep 10

# Verify
docker exec "$CONTAINER" cypher-shell \
  -u neo4j -p "${NEO4J_PASSWORD:-fathom2024}" \
  "MATCH (n) RETURN count(n) AS total_nodes"
