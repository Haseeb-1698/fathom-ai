// Fathom Neo4j Schema — Malware Behavior Graph
// Run this once to set up constraints and indexes.

// ── Node constraints ────────────────────────────────────────────────────
CREATE CONSTRAINT sample_hash IF NOT EXISTS
  FOR (s:Sample) REQUIRE s.sha256 IS UNIQUE;

CREATE CONSTRAINT process_uid IF NOT EXISTS
  FOR (p:Process) REQUIRE p.uid IS UNIQUE;

CREATE CONSTRAINT technique_id IF NOT EXISTS
  FOR (t:Technique) REQUIRE t.technique_id IS UNIQUE;

CREATE CONSTRAINT ioc_value IF NOT EXISTS
  FOR (i:IOC) REQUIRE i.value IS UNIQUE;

CREATE CONSTRAINT session_id IF NOT EXISTS
  FOR (s:ChatSession) REQUIRE s.session_id IS UNIQUE;

CREATE CONSTRAINT turn_id IF NOT EXISTS
  FOR (t:ChatTurn) REQUIRE t.turn_id IS UNIQUE;

CREATE CONSTRAINT cache_id IF NOT EXISTS
  FOR (c:AnalysisCache) REQUIRE c.cache_id IS UNIQUE;

// ── Indexes ─────────────────────────────────────────────────────────────
CREATE INDEX sample_family IF NOT EXISTS
  FOR (s:Sample) ON (s.family);

CREATE INDEX process_name IF NOT EXISTS
  FOR (p:Process) ON (p.name);

CREATE INDEX technique_tactic IF NOT EXISTS
  FOR (t:Technique) ON (t.tactic);

CREATE INDEX ioc_type IF NOT EXISTS
  FOR (i:IOC) ON (i.type);

CREATE INDEX session_created IF NOT EXISTS
  FOR (s:ChatSession) ON (s.created_at);

CREATE INDEX turn_ts IF NOT EXISTS
  FOR (t:ChatTurn) ON (t.ts);

CREATE INDEX cache_query_hash IF NOT EXISTS
  FOR (c:AnalysisCache) ON (c.query_hash);

// ── Node types ──────────────────────────────────────────────────────────
// :Sample         {sha256, name, family, score, analyzed_at}
// :Process        {uid, pid, name, ppid, cmd_line}
// :File           {path, sha256, size}
// :RegistryKey    {path, value}
// :NetworkConn    {dst_ip, dst_port, protocol}
// :Technique      {technique_id, name, tactic, description}
// :IOC            {value, type, confidence}
// :Signature      {name, description, severity}
// :ChatSession    {session_id, created_at, sample_sha256, turn_count}
// :ChatTurn       {turn_id, role, content, ts, tags, techniques_mentioned, iocs_mentioned}
// :AnalysisCache  {cache_id, query_hash, query_text, response_text, created_at, hit_count, sample_sha256}

// ── Relationship types ──────────────────────────────────────────────────
// (Sample)-[:SPAWNED]->(Process)
// (Process)-[:SPAWNED]->(Process)
// (Process)-[:CREATED]->(File)
// (Process)-[:MODIFIED]->(RegistryKey)
// (Process)-[:CONNECTED_TO]->(NetworkConn)
// (Sample)-[:USES_TECHNIQUE]->(Technique)
// (Sample)-[:HAS_IOC]->(IOC)
// (Sample)-[:TRIGGERED]->(Signature)
// (IOC)-[:RELATED_TO]->(IOC)
// (Sample)-[:SIMILAR_TO]->(Sample)
// (ChatSession)-[:ABOUT]->(Sample)
// (ChatSession)-[:HAS_TURN]->(ChatTurn)
// (ChatTurn)-[:MENTIONS_TECHNIQUE]->(Technique)
// (ChatTurn)-[:MENTIONS_IOC]->(IOC)
// (AnalysisCache)-[:CACHED_FOR]->(Sample)
