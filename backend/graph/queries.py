"""
queries.py — Predefined Cypher queries for common graph operations.
"""

# Get full process tree for a sample
PROCESS_TREE = """
MATCH (s:Sample {sha256: $hash})-[:SPAWNED*1..5]->(p:Process)
RETURN s, p
ORDER BY p.pid
"""

# Get all IOCs for a sample
SAMPLE_IOCS = """
MATCH (s:Sample {sha256: $hash})-[:HAS_IOC]->(i:IOC)
RETURN i.value AS ioc, i.type AS type, i.confidence AS confidence
"""

# Get ATT&CK techniques for a sample
SAMPLE_TECHNIQUES = """
MATCH (s:Sample {sha256: $hash})-[:USES_TECHNIQUE]->(t:Technique)
RETURN t.technique_id AS id, t.name AS name, t.tactic AS tactic
"""

# Cross-sample IOC correlation
IOC_CORRELATION = """
MATCH (s1:Sample)-[:HAS_IOC]->(i:IOC)<-[:HAS_IOC]-(s2:Sample)
WHERE s1.sha256 <> s2.sha256
RETURN s1.sha256 AS sample1, s2.sha256 AS sample2,
       collect(i.value) AS shared_iocs, count(i) AS overlap
ORDER BY overlap DESC
LIMIT 20
"""

# Find samples using a specific technique
TECHNIQUE_SEARCH = """
MATCH (s:Sample)-[:USES_TECHNIQUE]->(t:Technique {technique_id: $technique_id})
RETURN s.sha256 AS hash, s.name AS name, s.family AS family, s.score AS score
"""

# Full sample graph (for visualization)
SAMPLE_GRAPH = """
MATCH (s:Sample {sha256: $hash})
OPTIONAL MATCH (s)-[r1:SPAWNED*1..3]->(p:Process)
OPTIONAL MATCH (p)-[r2:CREATED]->(f:File)
OPTIONAL MATCH (p)-[r3:CONNECTED_TO]->(n:NetworkConn)
OPTIONAL MATCH (s)-[r4:USES_TECHNIQUE]->(t:Technique)
OPTIONAL MATCH (s)-[r5:HAS_IOC]->(i:IOC)
RETURN s, p, f, n, t, i
"""

# ── Chat session queries ─────────────────────────────────────────────────

# Get all turns for a session
SESSION_TURNS = """
MATCH (s:ChatSession {session_id: $session_id})-[:HAS_TURN]->(t:ChatTurn)
RETURN t.turn_id AS turn_id, t.role AS role, t.content AS content,
       t.ts AS ts, t.tags AS tags,
       t.techniques_mentioned AS techniques, t.iocs_mentioned AS iocs
ORDER BY t.ts ASC
"""

# Get sessions for a sample
SAMPLE_SESSIONS = """
MATCH (sess:ChatSession)-[:ABOUT]->(s:Sample {sha256: $hash})
RETURN sess.session_id AS session_id, sess.created_at AS created_at,
       sess.turn_count AS turn_count
ORDER BY sess.created_at DESC
LIMIT 20
"""

# Find sessions that discussed a specific technique
SESSIONS_BY_TECHNIQUE = """
MATCH (t:ChatTurn)-[:MENTIONS_TECHNIQUE]->(tech:Technique {technique_id: $technique_id})
MATCH (sess:ChatSession)-[:HAS_TURN]->(t)
OPTIONAL MATCH (sess)-[:ABOUT]->(s:Sample)
RETURN sess.session_id AS session_id, s.sha256 AS sample_hash,
       s.name AS sample_name, count(t) AS mention_count
ORDER BY mention_count DESC
LIMIT 20
"""

# Cached analysis lookup by query hash
CACHE_LOOKUP = """
MATCH (c:AnalysisCache {query_hash: $query_hash})
SET c.hit_count = coalesce(c.hit_count, 0) + 1,
    c.last_hit = $now
RETURN c.response_text AS response, c.created_at AS created_at,
       c.hit_count AS hit_count
"""

# Store analysis cache entry
CACHE_STORE = """
MERGE (c:AnalysisCache {cache_id: $cache_id})
SET c.query_hash = $query_hash,
    c.query_text = $query_text,
    c.response_text = $response_text,
    c.created_at = $now,
    c.hit_count = 0,
    c.sample_sha256 = $sample_sha256
WITH c
OPTIONAL MATCH (s:Sample {sha256: $sample_sha256})
FOREACH (_ IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
  MERGE (c)-[:CACHED_FOR]->(s)
)
RETURN c.cache_id AS cache_id
"""

# Most-asked questions across all sessions (for analytics)
TOP_QUESTIONS = """
MATCH (t:ChatTurn {role: 'user'})
RETURN t.content AS question, count(t) AS frequency
ORDER BY frequency DESC
LIMIT 20
"""
