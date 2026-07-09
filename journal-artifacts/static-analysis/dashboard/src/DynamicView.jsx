import { useEffect, useMemo, useState } from "react";
import axios from "axios";

const API_BASE = "http://127.0.0.1:8000";
const FINAL_STATES = new Set(["completed", "failed", "timeout", "missing"]);
const MAX_LIST = 80;
const MAX_CALLS_PER_PROCESS = 120;

export default function DynamicView({ record }) {
  const sha256 = record?.sha256;
  const [state, setState] = useState(record?.dynamic || null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [loadingReport, setLoadingReport] = useState(false);
  const [lookupQuery, setLookupQuery] = useState("");
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupActive, setLookupActive] = useState(false);
  const [lookupHtmlUrl, setLookupHtmlUrl] = useState("");
  const [activeSection, setActiveSection] = useState("overview");
  const [apiFilter, setApiFilter] = useState("");

  useEffect(() => {
    if (!sha256 || lookupActive) return;

    let alive = true;
    let timer = null;

    const poll = async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/dynamic/${sha256}`);
        if (!alive) return;
        setState(res.data);
        setError("");
        if (!FINAL_STATES.has(res.data?.status)) {
          timer = setTimeout(poll, 5000);
        }
      } catch (e) {
        if (!alive) return;
        setError(e?.response?.data?.detail || e?.message || "Unable to read dynamic status");
        timer = setTimeout(poll, 8000);
      }
    };

    poll();

    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [sha256, lookupActive]);

  useEffect(() => {
    if (state?.status === "completed" && state?.report_json_available && !report && !loadingReport) {
      loadReport();
    }
  }, [state?.status, state?.report_json_available]);

  const loadReport = async () => {
    if (lookupActive) {
      const query = state?.cape_task_id || state?.lookup?.query || lookupQuery;
      if (query) await loadLookup(String(query), true);
      return;
    }
    if (!sha256) return;
    try {
      setLoadingReport(true);
      const res = await axios.get(`${API_BASE}/api/dynamic/${sha256}/report-json`);
      setReport(res.data);
      setError("");
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Unable to load CAPE report");
    } finally {
      setLoadingReport(false);
    }
  };

  const loadLookup = async (query = lookupQuery, preserveInput = false) => {
    const value = String(query || "").trim();
    if (!value) {
      setError("Enter a CAPE analysis number or malware hash.");
      return;
    }

    try {
      setLookupLoading(true);
      const res = await axios.get(`${API_BASE}/api/dynamic/lookup`, { params: { q: value } });
      setLookupActive(true);
      setState(res.data.state);
      setReport(res.data.report);
      setLookupHtmlUrl(res.data.html_url ? `${API_BASE}${res.data.html_url}` : "");
      if (!preserveInput) setLookupQuery(value);
      setActiveSection("overview");
      setError("");
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Unable to find that CAPE analysis");
    } finally {
      setLookupLoading(false);
    }
  };

  const returnToUploadedSample = () => {
    setLookupActive(false);
    setLookupHtmlUrl("");
    setReport(null);
    setState(record?.dynamic || null);
    setError("");
    setActiveSection("overview");
  };

  const viewedSha = state?.sha256 || sha256;
  const model = useMemo(() => buildDynamicModel(report, state, viewedSha), [report, state, viewedSha]);

  if (!sha256 && !report) {
    return (
      <div className="card dynamic-report">
        <span className="badge">Dynamic</span>
        <LookupPanel
          lookupQuery={lookupQuery}
          setLookupQuery={setLookupQuery}
          lookupLoading={lookupLoading}
          loadLookup={loadLookup}
        />
        <p style={{ marginTop: 8 }}>Upload a sample to start a new dynamic analysis, or search an existing CAPE report above.</p>
      </div>
    );
  }

  const status = state?.status || "queued";
  const htmlUrl = lookupHtmlUrl || `${API_BASE}/api/dynamic/${sha256}/report-html`;
  const sections = [
    ["overview", "Overview"],
    ["iocs", "IOCs"],
    ["behavior", "Behavior"],
    ["processes", "Processes"],
    ["network", "Network"],
    ["debug", "Debug"],
    ["raw", "Raw JSON"],
  ];

  return (
    <div className="card dynamic-report">
      <div className="dynamic-topbar">
        <div className="row" style={{ gap: 10 }}>
          <span className="badge">Dynamic</span>
          {lookupActive && <span className="badge">Lookup result</span>}
          <span className={`pill ${statusClass(status)}`}>{status}</span>
          {state?.cape_task_id && <code>task:{state.cape_task_id}</code>}
        </div>
        <div className="row" style={{ gap: 10 }}>
          <button className="btn small" onClick={loadReport} disabled={loadingReport || !state?.report_json_available}>
            {loadingReport ? "Loading..." : report ? "Refresh JSON" : "Load JSON"}
          </button>
          {lookupActive && (
            <button className="btn small ghost" onClick={returnToUploadedSample} type="button">
              Uploaded sample
            </button>
          )}
          {state?.report_html_available && (
            <a className="btn small" href={htmlUrl} target="_blank" rel="noreferrer">
              Open HTML report
            </a>
          )}
        </div>
      </div>

      <div className="dynamic-hero">
        <div>
          <h2>Dynamic Analysis Report</h2>
          <p>
            CAPE task telemetry, runtime behavior, process activity, network indicators,
            and report links for uploaded samples or existing CAPE analyses.
          </p>
        </div>
      </div>

      <LookupPanel
        lookupQuery={lookupQuery}
        setLookupQuery={setLookupQuery}
        lookupLoading={lookupLoading}
        loadLookup={loadLookup}
      />

      <div className="dynamic-tabs">
        {sections.map(([id, label]) => (
          <button
            key={id}
            className={activeSection === id ? "active" : ""}
            onClick={() => setActiveSection(id)}
            type="button"
          >
            {label}
          </button>
        ))}
      </div>

      {error && <Notice tone="bad" title="Dynamic view error" text={error} />}
      {state?.error && <Notice tone="bad" title="CAPE integration error" text={state.error} />}
      {status !== "completed" && !state?.error && (
        <Notice
          tone="warn"
          title="CAPE is still working"
          text="This panel refreshes automatically until CAPE creates the final JSON report."
        />
      )}

      {!report && status === "completed" && state?.report_json_available && (
        <Notice
          tone="warn"
          title="Report available"
          text="The JSON report is available. Use Load JSON if it does not load automatically."
        />
      )}

      {activeSection === "overview" && <OverviewSection model={model} sha256={sha256} state={state} />}
      {activeSection === "iocs" && <IocSection model={model} />}
      {activeSection === "behavior" && <BehaviorSection model={model} />}
      {activeSection === "processes" && (
        <ProcessSection model={model} apiFilter={apiFilter} setApiFilter={setApiFilter} />
      )}
      {activeSection === "network" && <NetworkSection model={model} />}
      {activeSection === "debug" && <DebugSection model={model} state={state} />}
      {activeSection === "raw" && <RawSection report={report} loadingReport={loadingReport} loadReport={loadReport} />}
    </div>
  );
}

function LookupPanel({ lookupQuery, setLookupQuery, lookupLoading, loadLookup }) {
  const onSubmit = (event) => {
    event.preventDefault();
    loadLookup();
  };

  return (
    <form className="dynamic-lookup" onSubmit={onSubmit}>
      <div>
        <label>Open existing CAPE result</label>
        <p>Enter an analysis number, SHA-256, SHA-1, MD5, or artifact hash from CAPE storage.</p>
      </div>
      <div className="dynamic-lookup-controls">
        <input
          value={lookupQuery}
          onChange={(event) => setLookupQuery(event.target.value)}
          placeholder="Example: 99 or b6e579457bd4..."
        />
        <button className="btn small" type="submit" disabled={lookupLoading}>
          {lookupLoading ? "Searching..." : "Load result"}
        </button>
      </div>
    </form>
  );
}

function OverviewSection({ model, sha256, state }) {
  return (
    <div className="dynamic-section">
      <div className="dynamic-metric-grid">
        <Metric label="Signatures" value={model.counts.signatures} />
        <Metric label="Processes" value={model.counts.processes} />
        <Metric label="API calls" value={model.counts.calls} />
        <Metric label="Enhanced events" value={model.counts.enhanced} />
        <Metric label="Network events" value={model.counts.networkEvents} />
        <Metric label="Payloads" value={model.counts.payloads} />
        <Metric label="Dropped files" value={model.counts.dropped} />
      </div>

      <Panel title="Analysis metadata">
        <div className="dynamic-kv-grid">
          <KeyValue label="SHA-256" value={model.target.sha256 || sha256} mono />
          <KeyValue label="File name" value={model.target.name} />
          <KeyValue label="File type" value={model.target.type} />
          <KeyValue label="File size" value={formatBytes(model.target.size)} />
          <KeyValue label="CAPE task" value={state?.cape_task_id || model.info.id || "waiting"} mono />
          <KeyValue label="Package" value={model.info.package || "unknown"} />
          <KeyValue label="Machine" value={model.info.machine?.name || model.info.machine || "unknown"} />
          <KeyValue label="Duration" value={model.info.duration ? `${model.info.duration}s` : "unknown"} />
          <KeyValue label="Started" value={model.info.started || state?.submitted_at || "unknown"} />
          <KeyValue label="Ended" value={model.info.ended || state?.completed_at || "unknown"} />
        </div>
      </Panel>

      <Panel title="High confidence detections">
        <SignatureList signatures={model.signatures.slice(0, 12)} />
      </Panel>

      <Panel title="Runtime timeline">
        <Timeline events={model.timeline.slice(0, 30)} empty="No runtime events were available in the CAPE report." />
      </Panel>
    </div>
  );
}

function IocSection({ model }) {
  return (
    <div className="dynamic-section">
      <div className="dynamic-metric-grid">
        <Metric label="Domains" value={model.iocs.domains.length} />
        <Metric label="Hosts" value={model.iocs.hosts.length} />
        <Metric label="URLs" value={model.iocs.urls.length} />
        <Metric label="Mutexes" value={model.iocs.mutexes.length} />
      </div>
      <Panel title="Network IOCs">
        <ListBlock title="Domains" items={model.iocs.domains} />
        <ListBlock title="Hosts and IPs" items={model.iocs.hosts} />
        <ListBlock title="URLs" items={model.iocs.urls} />
      </Panel>
      <Panel title="Host IOCs">
        <ListBlock title="Files touched" items={model.iocs.files} />
        <ListBlock title="Registry keys" items={model.iocs.registry} />
        <ListBlock title="Mutexes" items={model.iocs.mutexes} />
        <ListBlock title="Executed commands" items={model.iocs.commands} />
      </Panel>
    </div>
  );
}

function BehaviorSection({ model }) {
  return (
    <div className="dynamic-section">
      <Panel title="Behavior summary">
        <div className="dynamic-columns">
          <ListBlock title="Read files" items={model.behavior.readFiles} />
          <ListBlock title="Written files" items={model.behavior.writeFiles} />
          <ListBlock title="Deleted files" items={model.behavior.deleteFiles} />
          <ListBlock title="Read registry keys" items={model.behavior.readKeys} />
          <ListBlock title="Written registry keys" items={model.behavior.writeKeys} />
          <ListBlock title="Services" items={model.behavior.services} />
        </div>
      </Panel>

      <Panel title="Enhanced event stream">
        <Timeline events={model.enhancedEvents.slice(0, 120)} empty="No enhanced behavior events were present." />
      </Panel>
    </div>
  );
}

function ProcessSection({ model, apiFilter, setApiFilter }) {
  const filter = apiFilter.trim().toLowerCase();

  return (
    <div className="dynamic-section">
      <Panel title="Process tree">
        <ProcessTree nodes={model.processTree} />
      </Panel>

      <Panel title="API activity by process">
        <input
          className="dynamic-search"
          value={apiFilter}
          onChange={(e) => setApiFilter(e.target.value)}
          placeholder="Filter API calls, arguments, categories, process names..."
        />
        <div className="process-list">
          {model.processes.length === 0 && <Empty text="No process API calls were available." />}
          {model.processes.map((proc) => {
            const calls = (proc.calls || []).filter((call) => callMatches(call, proc, filter)).slice(0, MAX_CALLS_PER_PROCESS);
            if (filter && calls.length === 0) return null;
            return (
              <details className="process-card" key={`${proc.process_id}-${proc.process_name}`} open={model.processes.length <= 3}>
                <summary>
                  <span>{proc.process_name || "unknown process"}</span>
                  <code>pid:{proc.process_id || "?"}</code>
                  <small>{proc.calls?.length || 0} calls</small>
                </summary>
                <div className="dynamic-kv-grid">
                  <KeyValue label="Parent PID" value={proc.parent_id || "unknown"} mono />
                  <KeyValue label="Module path" value={proc.module_path || "unknown"} />
                  <KeyValue label="First seen" value={proc.first_seen || "unknown"} />
                </div>
                <ApiCallTable calls={calls} />
              </details>
            );
          })}
        </div>
      </Panel>
    </div>
  );
}

function NetworkSection({ model }) {
  return (
    <div className="dynamic-section">
      <div className="dynamic-metric-grid">
        <Metric label="DNS" value={model.network.dns.length} />
        <Metric label="HTTP" value={model.network.http.length} />
        <Metric label="TCP" value={model.network.tcp.length} />
        <Metric label="UDP" value={model.network.udp.length} />
        <Metric label="ICMP" value={model.network.icmp.length} />
        <Metric label="Dead hosts" value={model.network.deadHosts.length} />
      </div>

      <Panel title="DNS requests">
        <DataTable
          rows={model.network.dns}
          columns={[
            ["Request", (row) => row.request],
            ["Type", (row) => row.type],
            ["Answers", (row) => formatAnswers(row.answers)],
          ]}
        />
      </Panel>

      <Panel title="HTTP requests">
        <DataTable
          rows={model.network.http}
          columns={[
            ["Method", (row) => row.method],
            ["Host", (row) => row.host],
            ["URI", (row) => row.uri || row.url],
            ["Status", (row) => row.status],
            ["User agent", (row) => row.user_agent],
          ]}
        />
      </Panel>

      <Panel title="TCP and UDP connections">
        <ConnectionList title="TCP" protocol="TCP" rows={model.network.tcp} />
        <ConnectionList title="UDP" protocol="UDP" rows={model.network.udp} />
      </Panel>
    </div>
  );
}

function ArtifactsSection({ model }) {
  return (
    <div className="dynamic-section">
      <Panel title="CAPE payloads">
        <ArtifactCards artifacts={model.artifacts.payloads} />
      </Panel>
      <Panel title="CAPE configs">
        <ConfigCards configs={model.artifacts.configs} />
      </Panel>
      <Panel title="Dropped files">
        <ArtifactCards artifacts={model.artifacts.dropped} />
      </Panel>
      <Panel title="Process memory and TLS dumps">
        <div className="dynamic-columns">
          <ArtifactCards title="Process memory" artifacts={model.artifacts.procmemory} />
          <ArtifactCards title="TLS dumps" artifacts={model.artifacts.dumptls} />
        </div>
      </Panel>
    </div>
  );
}

function DebugSection({ model, state }) {
  return (
    <div className="dynamic-section">
      <Panel title="Integration state">
        <div className="dynamic-kv-grid">
          <KeyValue label="Status" value={state?.status || "unknown"} />
          <KeyValue label="Task ID" value={state?.cape_task_id || "unknown"} mono />
          <KeyValue label="Analysis dir" value={state?.analysis_dir || "unknown"} />
          <KeyValue label="JSON report" value={state?.report_json_path || "unknown"} />
          <KeyValue label="HTML report" value={state?.report_html_path || "unknown"} />
        </div>
      </Panel>
      <Panel title="CAPE errors">
        <ListBlock items={model.debug.errors} empty="No CAPE errors were recorded." />
      </Panel>
      <Panel title="CAPE log excerpts">
        <LogBlock lines={model.debug.log} />
      </Panel>
    </div>
  );
}

function RawSection({ report, loadingReport, loadReport }) {
  return (
    <div className="dynamic-section">
      <div className="row" style={{ justifyContent: "space-between" }}>
        <span className="badge">Raw CAPE JSON</span>
        <button className="btn small" onClick={loadReport} disabled={loadingReport}>
          {loadingReport ? "Loading..." : "Reload JSON"}
        </button>
      </div>
      {report ? (
        <div className="jsonbox">
          <pre style={{ margin: 0 }}>{JSON.stringify(report, null, 2)}</pre>
        </div>
      ) : (
        <Empty text="The raw JSON has not been loaded yet." />
      )}
    </div>
  );
}

function buildDynamicModel(report, state, sha256) {
  const targetFile = report?.target?.file || {};
  const info = report?.info || {};
  const behavior = report?.behavior || {};
  const summary = behavior.summary || {};
  const network = report?.network || {};
  const cape = report?.CAPE || report?.cape || {};
  const signatures = asArray(report?.signatures).sort((a, b) => Number(b.severity || 0) - Number(a.severity || 0));
  const processes = asArray(behavior.processes);
  const enhancedEvents = normalizeEnhanced(asArray(behavior.enhanced));
  const processCalls = processes.flatMap((proc) => asArray(proc.calls));
  const iocDomains = unique([
    ...asArray(network.domains).map((item) => item.domain || item),
    ...asArray(network.dns).map((item) => item.request),
  ]);
  const iocHosts = unique([
    ...asArray(network.hosts).map((item) => item.ip || item.host || item),
    ...asArray(network.tcp).flatMap((item) => [item.src, item.dst]),
    ...asArray(network.udp).flatMap((item) => [item.src, item.dst]),
    ...asArray(network.dead_hosts).map((item) => item.ip || item),
  ]);
  const urls = unique([
    ...asArray(network.http).map((item) => item.url || joinUrl(item.host, item.uri)),
    ...asArray(network.http_ex).map((item) => item.url || joinUrl(item.host, item.uri)),
  ]);
  const files = unique([...(summary.files || []), ...(summary.read_files || []), ...(summary.write_files || []), ...(summary.delete_files || [])]);
  const registry = unique([...(summary.keys || []), ...(summary.read_keys || []), ...(summary.write_keys || []), ...(summary.delete_keys || [])]);
  const payloads = asArray(cape.payloads);
  const configs = asArray(cape.configs);
  const dropped = asArray(report?.dropped || report?.dropped_files);
  const procmemory = asArray(report?.procmemory);
  const dumptls = asArray(report?.dumptls);
  const score = Number(report?.malscore ?? state?.summary?.malscore ?? 0);

  return {
    score: Number.isFinite(score) ? score : 0,
    status: report?.malstatus || state?.summary?.malstatus || "unknown",
    target: {
      name: targetFile.name || state?.filename || "unknown",
      sha256: targetFile.sha256 || sha256,
      type: targetFile.type || "unknown",
      size: targetFile.size,
      md5: targetFile.md5,
      sha1: targetFile.sha1,
    },
    info,
    signatures,
    processTree: asArray(behavior.processtree),
    processes,
    enhancedEvents,
    timeline: buildTimeline({ signatures, enhancedEvents, processes, network }),
    counts: {
      signatures: signatures.length,
      processes: processes.length,
      calls: processCalls.length,
      enhanced: enhancedEvents.length,
      networkEvents:
        asArray(network.dns).length + asArray(network.http).length + asArray(network.tcp).length + asArray(network.udp).length + asArray(network.icmp).length,
      payloads: payloads.length,
      dropped: dropped.length,
    },
    iocs: {
      domains: iocDomains,
      hosts: iocHosts,
      urls,
      files,
      registry,
      mutexes: unique(summary.mutexes || []),
      commands: unique(summary.executed_commands || []),
    },
    behavior: {
      readFiles: unique(summary.read_files || []),
      writeFiles: unique(summary.write_files || []),
      deleteFiles: unique(summary.delete_files || []),
      readKeys: unique(summary.read_keys || []),
      writeKeys: unique(summary.write_keys || []),
      services: unique([...(summary.created_services || []), ...(summary.started_services || [])]),
    },
    network: {
      dns: asArray(network.dns),
      http: [...asArray(network.http), ...asArray(network.http_ex)],
      tcp: asArray(network.tcp),
      udp: asArray(network.udp),
      icmp: asArray(network.icmp),
      deadHosts: asArray(network.dead_hosts),
    },
    artifacts: { payloads, configs, dropped, procmemory, dumptls },
    debug: {
      errors: asArray(report?.debug?.errors),
      log: asArray(report?.debug?.log).slice(-120),
    },
  };
}

function buildTimeline({ signatures, enhancedEvents, processes, network }) {
  const events = [];
  signatures.slice(0, 30).forEach((sig) => {
    events.push({
      time: sig.first_seen || sig.timestamp || "",
      title: sig.name || "Signature",
      detail: sig.description || sig.short_description || `Marks: ${sig.markcount || 0}`,
      tone: Number(sig.severity || 0) >= 3 ? "bad" : "warn",
    });
  });
  enhancedEvents.slice(0, 80).forEach((event) => {
    events.push({
      time: event.timestamp || "",
      title: `${event.event || "event"} ${event.object || ""}`.trim(),
      detail: event.detail,
      tone: "ok",
    });
  });
  processes.forEach((proc) => {
    events.push({
      time: proc.first_seen || "",
      title: proc.process_name || "Process observed",
      detail: `PID ${proc.process_id || "?"} ${proc.module_path || ""}`.trim(),
      tone: "ok",
    });
  });
  asArray(network?.dns).slice(0, 30).forEach((dns) => {
    events.push({
      time: dns.first_seen || "",
      title: "DNS request",
      detail: dns.request || "",
      tone: "warn",
    });
  });
  return events.sort((a, b) => String(a.time || "").localeCompare(String(b.time || "")));
}

function normalizeEnhanced(events) {
  return events.map((event) => {
    const data = event.data || {};
    const detail = data.file || data.regkey || data.command || data.mutex || data.content || data.service || stringifyCompact(data);
    return { ...event, detail };
  });
}

function Panel({ title, children }) {
  return (
    <section className="dynamic-panel">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function Metric({ label, value, tone = "neutral" }) {
  return (
    <div className={`dynamic-metric metric-${tone}`}>
      <label>{label}</label>
      <strong>{value ?? "unknown"}</strong>
    </div>
  );
}

function KeyValue({ label, value, mono = false }) {
  return (
    <div className="dynamic-kv">
      <label>{label}</label>
      <span className={mono ? "mono" : ""}>{formatCell(value ?? "unknown")}</span>
    </div>
  );
}

function Notice({ title, text, tone }) {
  return (
    <div className={`dynamic-notice notice-${tone}`}>
      <strong>{title}</strong>
      <span>{text}</span>
    </div>
  );
}

function SignatureList({ signatures }) {
  if (!signatures.length) return <Empty text="No signatures were triggered." />;
  return (
    <div className="signature-list">
      {signatures.map((sig, index) => (
        <article className="signature-card" key={`${sig.name}-${index}`}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <strong>{sig.name || "Unnamed signature"}</strong>
            <span className={`pill ${Number(sig.severity || 0) >= 3 ? "pill-strong" : "pill-conf-med"}`}>
              severity {sig.severity ?? "?"}
            </span>
          </div>
          <p>{sig.description || sig.short_description || "No description provided."}</p>
          {sig.marks?.length > 0 && <ListBlock title="Marks" items={sig.marks.map(formatMark).slice(0, 12)} />}
          {sig.ttps?.length > 0 && <ListBlock title="MITRE ATT&CK" items={sig.ttps} />}
        </article>
      ))}
    </div>
  );
}

function Timeline({ events, empty }) {
  if (!events.length) return <Empty text={empty} />;
  return (
    <div className="timeline">
      {events.map((event, index) => (
        <div className={`timeline-item timeline-${event.tone || "ok"}`} key={`${event.title}-${index}`}>
          <time>{event.time || "runtime"}</time>
          <strong>{event.title}</strong>
          {event.detail && <span>{String(event.detail)}</span>}
        </div>
      ))}
    </div>
  );
}

function ListBlock({ title, items, empty = "No entries were recorded." }) {
  const list = unique(asArray(items)).slice(0, MAX_LIST);
  return (
    <div className="list-block">
      {title && <h4>{title}</h4>}
      {list.length === 0 ? (
        <Empty text={empty} />
      ) : (
        <ul>
          {list.map((item, index) => (
            <li key={`${item}-${index}`}>
              <code>{String(item)}</code>
            </li>
          ))}
        </ul>
      )}
      {asArray(items).length > MAX_LIST && <small>Showing first {MAX_LIST} of {asArray(items).length} entries.</small>}
    </div>
  );
}

function ProcessTree({ nodes }) {
  if (!nodes.length) return <Empty text="No process tree was recorded." />;
  return (
    <div className="process-tree">
      {nodes.map((node, index) => (
        <ProcessNode node={node} key={`${node.pid}-${index}`} />
      ))}
    </div>
  );
}

function ProcessNode({ node }) {
  return (
    <div className="process-node">
      <div>
        <strong>{node.name || "process"}</strong>
        <code>pid:{node.pid || "?"}</code>
      </div>
      <span>{node.module_path || node.command_line || node.environ?.CommandLine || "No command line available"}</span>
      {node.children?.length > 0 && (
        <div className="process-children">
          {node.children.map((child, index) => (
            <ProcessNode node={child} key={`${child.pid}-${index}`} />
          ))}
        </div>
      )}
    </div>
  );
}

function ApiCallTable({ calls }) {
  if (!calls.length) return <Empty text="No matching API calls." />;
  return (
    <div className="dynamic-table-wrap">
      <table className="dynamic-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Category</th>
            <th>API</th>
            <th>Arguments</th>
          </tr>
        </thead>
        <tbody>
          {calls.map((call, index) => (
            <tr key={`${call.api}-${index}`}>
              <td>{call.timestamp || ""}</td>
              <td>{call.category || ""}</td>
              <td><code>{call.api || "unknown"}</code></td>
              <td>{formatArguments(call.arguments)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DataTable({ title, rows, columns }) {
  const visibleRows = asArray(rows).slice(0, MAX_LIST);
  return (
    <div className="data-table-block">
      {title && <h4>{title}</h4>}
      {visibleRows.length === 0 ? (
        <Empty text="No entries were recorded." />
      ) : (
        <div className="dynamic-table-wrap">
          <table className="dynamic-table">
            <thead>
              <tr>{columns.map(([label]) => <th key={label}>{label}</th>)}</tr>
            </thead>
            <tbody>
              {visibleRows.map((row, index) => (
                <tr key={index}>
                  {columns.map(([label, getter]) => (
                    <td key={label}>{formatCell(getter(row) || "")}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {asArray(rows).length > MAX_LIST && <small>Showing first {MAX_LIST} of {asArray(rows).length} entries.</small>}
    </div>
  );
}

function ConnectionList({ title, protocol, rows }) {
  const visibleRows = asArray(rows).slice(0, MAX_LIST);

  return (
    <div className="connection-block">
      <div className="connection-heading">
        <h4>{title}</h4>
        <span>{asArray(rows).length} connection{asArray(rows).length === 1 ? "" : "s"}</span>
      </div>
      {visibleRows.length === 0 ? (
        <Empty text={`No ${title} connections were recorded.`} />
      ) : (
        <div className="connection-list">
          {visibleRows.map((row, index) => (
            <article className="connection-card" key={`${protocol}-${index}`}>
              <div className="connection-protocol">{protocol}</div>
              <div className="connection-endpoint">
                <label>Source</label>
                <code>{endpoint(row.src, row.sport)}</code>
              </div>
              <div className="connection-arrow" aria-hidden="true">to</div>
              <div className="connection-endpoint">
                <label>Destination</label>
                <code>{endpoint(row.dst, row.dport)}</code>
              </div>
              <div className="connection-time">
                <label>Time</label>
                <span>{formatNumber(row.time) || "unknown"}</span>
              </div>
            </article>
          ))}
        </div>
      )}
      {asArray(rows).length > MAX_LIST && <small>Showing first {MAX_LIST} of {asArray(rows).length} entries.</small>}
    </div>
  );
}

function ArtifactCards({ artifacts, title }) {
  const list = asArray(artifacts);
  if (!list.length) return <Empty text={`No ${title ? title.toLowerCase() : "artifacts"} were recorded.`} />;
  return (
    <div className="artifact-grid">
      {list.slice(0, 40).map((artifact, index) => (
        <article className="artifact-card" key={`${artifact.sha256 || artifact.name || index}`}>
          <strong>{artifact.name || artifact.filename || artifact.path || `Artifact ${index + 1}`}</strong>
          <KeyValue label="Type" value={artifact.type || artifact.cape_type || artifact.category || "unknown"} />
          <KeyValue label="Size" value={formatBytes(artifact.size)} />
          <KeyValue label="SHA-256" value={artifact.sha256 || artifact.sha256_hash || "unknown"} mono />
          {artifact.path && <KeyValue label="Path" value={artifact.path} />}
          {artifact.guest_paths && <KeyValue label="Guest path" value={artifact.guest_paths} />}
        </article>
      ))}
    </div>
  );
}

function ConfigCards({ configs }) {
  const list = asArray(configs);
  if (!list.length) return <Empty text="No extracted CAPE configs were recorded." />;
  return (
    <div className="artifact-grid">
      {list.slice(0, 40).map((config, index) => (
        <article className="artifact-card" key={`${config.family || config.type || index}`}>
          <strong>{config.family || config.type || `Config ${index + 1}`}</strong>
          <pre>{stringifyPretty(config)}</pre>
        </article>
      ))}
    </div>
  );
}

function LogBlock({ lines }) {
  const list = asArray(lines);
  if (!list.length) return <Empty text="No debug log lines were included in the report." />;
  return (
    <div className="log-block">
      {list.map((line, index) => (
        <code key={index}>{String(line)}</code>
      ))}
    </div>
  );
}

function Empty({ text }) {
  return <p className="dynamic-empty">{text}</p>;
}

function statusClass(status) {
  if (status === "completed") return "pill-conf-high";
  if (status === "failed" || status === "timeout" || status === "missing") return "pill-conf-low";
  return "pill-conf-med";
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function unique(items) {
  return [...new Set(asArray(items).filter((item) => item !== null && item !== undefined && String(item).trim() !== "").map((item) => String(item)))];
}

function formatBytes(value) {
  const size = Number(value);
  if (!Number.isFinite(size) || size <= 0) return value ? String(value) : "unknown";
  const units = ["B", "KB", "MB", "GB"];
  let next = size;
  let unit = 0;
  while (next >= 1024 && unit < units.length - 1) {
    next /= 1024;
    unit += 1;
  }
  return `${next.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number.toFixed(3) : value;
}

function endpoint(host, port) {
  if (!host && !port) return "";
  return `${host || "?"}:${port || "?"}`;
}

function joinUrl(host, uri) {
  if (!host && !uri) return "";
  if (String(uri || "").startsWith("http")) return uri;
  return `${host || ""}${uri || ""}`;
}

function formatAnswers(answers) {
  return asArray(answers).map((answer) => answer.data || answer).join(", ");
}

function formatArguments(args) {
  return asArray(args)
    .slice(0, 8)
    .map((arg) => `${arg.name || "arg"}=${arg.pretty_value || arg.value || ""}`)
    .join("; ");
}

function formatMark(mark) {
  if (typeof mark === "string") return mark;
  return mark.description || mark.call?.api || mark.ioc || stringifyCompact(mark);
}

function stringifyCompact(value) {
  if (!value || typeof value !== "object") return value || "";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function stringifyPretty(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function formatCell(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map(formatCell).filter(Boolean).join(", ");
  return stringifyCompact(value);
}

function callMatches(call, proc, filter) {
  if (!filter) return true;
  const haystack = [
    proc.process_name,
    proc.module_path,
    call.api,
    call.category,
    call.timestamp,
    formatArguments(call.arguments),
  ].join(" ").toLowerCase();
  return haystack.includes(filter);
}
