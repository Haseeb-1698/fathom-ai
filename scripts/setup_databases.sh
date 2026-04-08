#!/bin/bash
# setup_databases.sh — Ensure Neo4j Docker volumes exist and container is running.
# Run this on the VM before `docker compose up`.
#
# Your existing Docker Desktop volumes (fathom_neo4j_data, fathom_neo4j_logs)
# are declared as external in docker-compose.yml — this script creates them
# if they don't exist yet.

set -e

NEO4J_PASSWORD="${NEO4J_PASSWORD:-fathom2024}"

echo "Setting up Fathom databases..."

# Create named volumes if they don't exist
docker volume inspect fathom_neo4j_data > /dev/null 2>&1 || \
  docker volume create fathom_neo4j_data && echo "Created volume: fathom_neo4j_data"

docker volume inspect fathom_neo4j_logs > /dev/null 2>&1 || \
  docker volume create fathom_neo4j_logs && echo "Created volume: fathom_neo4j_logs"

echo "✅ Volumes ready: fathom_neo4j_data, fathom_neo4j_logs"
echo ""
echo "Now run: docker compose up -d"
echo ""
echo "Neo4j will be available at:"
echo "  Browser : http://localhost:7474"
echo "  Bolt    : bolt://localhost:7687"
echo "  Login   : neo4j / ${NEO4J_PASSWORD}"
