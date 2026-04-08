"""
neo4j_client.py — Neo4j driver wrapper for Fathom behavior graph.
"""

from __future__ import annotations

from typing import Any, Optional

from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD


class Neo4jClient:
    """Thin wrapper around neo4j Python driver."""

    def __init__(self, uri: str = NEO4J_URI, user: str = NEO4J_USER,
                 password: str = NEO4J_PASSWORD):
        from neo4j import GraphDatabase
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def run(self, cypher: str, params: dict | None = None) -> list[dict]:
        with self.driver.session() as session:
            result = session.run(cypher, params or {})
            return [record.data() for record in result]

    def query(self, cypher: str, sample_hash: str | None = None
              ) -> tuple[list[dict], list[dict]]:
        """
        Run a Cypher query and return (nodes, edges) for graph visualization.
        """
        params = {}
        if sample_hash:
            params["sample_hash"] = sample_hash

        records = self.run(cypher, params)

        nodes = []
        edges = []
        seen_nodes = set()

        for record in records:
            for key, value in record.items():
                if hasattr(value, "id") and hasattr(value, "labels"):
                    # Node
                    node_id = value.id
                    if node_id not in seen_nodes:
                        seen_nodes.add(node_id)
                        nodes.append({
                            "id": node_id,
                            "labels": list(value.labels),
                            "properties": dict(value),
                        })
                elif hasattr(value, "type") and hasattr(value, "start_node"):
                    # Relationship
                    edges.append({
                        "source": value.start_node.id,
                        "target": value.end_node.id,
                        "type": value.type,
                        "properties": dict(value),
                    })

        return nodes, edges

    def init_schema(self, schema_path: str | None = None):
        """Run schema.cypher to set up constraints and indexes."""
        from pathlib import Path

        if schema_path is None:
            schema_path = Path(__file__).parent / "schema.cypher"

        with open(schema_path, "r") as f:
            statements = f.read()

        # Split by semicolons, filter comments
        for stmt in statements.split(";"):
            stmt = stmt.strip()
            if stmt and not stmt.startswith("//"):
                try:
                    self.run(stmt)
                except Exception as e:
                    print(f"[Neo4j] Schema statement skipped: {e}")
