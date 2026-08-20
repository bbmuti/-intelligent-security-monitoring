import React, { useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  ClipboardList,
  Eye,
  Filter,
  LockKeyhole,
  Play,
  Radar,
  RefreshCw,
  Search,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import "./styles.css";
import { AlertDrawer, InitialLoadState } from "./components.jsx";
import { filterAlerts, filterEvents, isActiveAlert } from "./domain.js";

const API = import.meta.env.VITE_API_URL || "";

async function rawRequest(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...options.headers },
  });
  if (response.status === 204) return null;
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.detail || "Request failed");
    error.status = response.status;
    throw error;
  }
  return body;
}

function csrfHeaders() {
  const token = document.cookie
    .split("; ")
    .find((item) => item.startsWith("sentinelscope_csrf="))
    ?.split("=")[1];
  return token ? { "X-CSRF-Token": decodeURIComponent(token) } : {};
}

function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setError(""); setBusy(true);
    try {
      onLogin(await rawRequest("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-panel">
        <div className="brand-mark"><Radar size={25} /></div>
        <p className="eyebrow">DEFENSIVE SECURITY LAB</p>
        <h1>See the signal.<br />Explain the risk.</h1>
        <p className="login-copy">Behavior analytics and explainable threat detection for authentication and API activity.</p>
        <form onSubmit={submit}>
          <label>Username<input autoComplete="username" placeholder="Analyst username" value={username} onChange={(e) => setUsername(e.target.value)} required /></label>
          <label>Password<input autoComplete="current-password" placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
          {error && <p className="error" role="alert">{error}</p>}
          <button className="primary" type="submit" disabled={busy}><LockKeyhole size={17} /> {busy ? "Authenticating…" : "Enter analyst console"}</button>
        </form>
        <p className="demo-hint">Local demo credentials are configured through environment variables.</p>
      </section>
      <section className="login-visual" aria-hidden="true">
        <div className="orb"><div className="orb-inner"><ShieldCheck size={46} /></div></div>
        <div className="signal-card one"><span>Behavior model</span><strong>v2</strong><small>adaptive baseline online</small></div>
        <div className="signal-card two"><span>Rule mapping</span><strong>T1110</strong><small>Brute Force</small></div>
      </section>
    </main>
  );
}

function Metric({ icon: Icon, label, value, tone }) {
  return <article className={`metric ${tone || ""}`}><div className="metric-icon"><Icon size={19} /></div><div><span>{label}</span><strong>{value}</strong></div></article>;
}

function Severity({ value }) {
  return <span className={`severity ${value}`}>{value}</span>;
}

function AlertRow({ alert, onSelect, onStatus }) {
  return (
    <div className="alert-row">
      <Severity value={alert.severity} />
      <button className="alert-body alert-open" onClick={() => onSelect(alert)}>
        <strong>{alert.title}</strong><p>{alert.explanation}</p>
        <div><code>{alert.mitre_technique || "Behavioral signal"}</code><span>Risk {alert.risk_score}</span><span>{alert.status.replace("_", " ")}</span></div>
      </button>
      {!["resolved", "false_positive"].includes(alert.status)
        ? <button className="resolve" onClick={() => onStatus(alert.id, "resolved")}><CheckCircle2 size={16} /> Resolve</button>
        : <span className="resolved">{alert.status.replace("_", " ")}</span>}
    </div>
  );
}

function Overview({ summary, alerts, events, onSelect, onStatus }) {
  const maxEvent = Math.max(1, ...Object.values(summary.event_type_counts || {}));
  const activeAlerts = alerts.filter(isActiveAlert);
  return <>
    <section className="metrics">
      <Metric icon={Activity} label="Events analyzed" value={summary.total_events} />
      <Metric icon={AlertTriangle} label="Active alerts" value={summary.open_alerts} tone="warning" />
      <Metric icon={ShieldCheck} label="Active critical" value={summary.critical_alerts} tone="danger" />
      <Metric icon={Radar} label="Average risk" value={`${summary.average_risk}/100`} tone="cyan" />
    </section>
    <section className="grid-main">
      <article className="panel alerts-panel">
        <div className="panel-head"><div><p className="eyebrow">PRIORITIZED FINDINGS</p><h2>Active alerts</h2></div><span>{activeAlerts.length} shown</span></div>
        <div className="alert-list">
          {activeAlerts.length === 0 && <div className="empty"><ShieldCheck size={32} /><strong>No active alerts</strong><span>Run a controlled scenario or ingest telemetry.</span></div>}
          {activeAlerts.slice(0, 6).map((alert) => <AlertRow key={alert.id} alert={alert} onSelect={onSelect} onStatus={onStatus} />)}
        </div>
      </article>
      <article className="panel posture-panel">
        <div className="panel-head"><div><p className="eyebrow">SECURITY POSTURE</p><h2>Severity mix</h2></div><Radar size={18} /></div>
        {['critical', 'high', 'medium'].map((severity) => <div className="posture-row" key={severity}><span>{severity}</span><strong>{summary.severity_counts[severity] || 0}</strong></div>)}
        <p className="muted-note">Only open and investigating alerts contribute to active posture metrics.</p>
      </article>
    </section>
    <section className="grid-bottom">
      <article className="panel"><div className="panel-head"><div><p className="eyebrow">EVENT DISTRIBUTION</p><h2>Telemetry</h2></div></div>
        <div className="bars">{Object.entries(summary.event_type_counts).map(([type,count]) => <div className="bar-row" key={type}><span>{type.replaceAll('_',' ')}</span><div><i style={{width:`${count/maxEvent*100}%`}} /></div><b>{count}</b></div>)}</div>
      </article>
      <article className="panel"><div className="panel-head"><div><p className="eyebrow">LATEST ACTIVITY</p><h2>Event stream</h2></div></div>
        <div className="event-list">{events.slice(0, 8).map((event) => <div key={event.id}><span className={`event-dot ${event.outcome}`} /><p><strong>{event.event_type.replaceAll('_',' ')}</strong><small>{event.user_id} · {event.ip_address} · {event.source}</small></p><b>{event.risk_score}</b></div>)}</div>
      </article>
    </section>
  </>;
}

function AlertsView({ alerts, onSelect, onStatus }) {
  const [status, setStatus] = useState("active");
  const [severity, setSeverity] = useState("all");
  const filtered = filterAlerts(alerts, status, severity);
  return <article className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">ALERT MANAGEMENT</p><h2>Findings queue</h2></div><Filter size={18} /></div>
    <div className="filters">
      <select aria-label="Alert status" value={status} onChange={(e) => setStatus(e.target.value)}><option value="active">Active</option><option value="all">All statuses</option><option value="resolved">Resolved</option><option value="false_positive">False positive</option></select>
      <select aria-label="Alert severity" value={severity} onChange={(e) => setSeverity(e.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select>
      <span>{filtered.length} findings</span>
    </div>
    <div className="alert-list full-list">{filtered.length === 0 && <div className="empty"><ShieldCheck size={32} /><strong>No matching alerts</strong><span>Change the filters or generate a controlled scenario.</span></div>}{filtered.map((alert) => <AlertRow key={alert.id} alert={alert} onSelect={onSelect} onStatus={onStatus} />)}</div>
  </article>;
}

function EventsView({ events }) {
  const [query, setQuery] = useState("");
  const [type, setType] = useState("all");
  const filtered = filterEvents(events, type, query);
  return <article className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">SEARCHABLE TELEMETRY</p><h2>Event stream</h2></div><Terminal size={18} /></div>
    <div className="filters"><label className="search-box"><Search size={15} /><input aria-label="Search events" placeholder="User, IP or endpoint" value={query} onChange={(e) => setQuery(e.target.value)} /></label><select aria-label="Event type" value={type} onChange={(e) => setType(e.target.value)}><option value="all">All event types</option><option value="login">Login</option><option value="api_access">API access</option><option value="authorization_failure">Authorization failure</option><option value="role_change">Role change</option></select></div>
    {filtered.length === 0 ? <div className="empty"><Terminal size={32} /><strong>No matching events</strong><span>Change the search or ingest telemetry.</span></div> : <div className="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>User</th><th>Source IP</th><th>Outcome</th><th>Source</th><th>Risk</th></tr></thead><tbody>{filtered.map((event) => <tr key={event.id}><td>{new Date(event.timestamp).toLocaleString()}</td><td>{event.event_type.replaceAll('_',' ')}</td><td>{event.user_id}</td><td><code>{event.ip_address}</code></td><td><span className={`outcome ${event.outcome}`}>{event.outcome}</span></td><td>{event.source}</td><td><b>{event.risk_score}</b></td></tr>)}</tbody></table></div>}
  </article>;
}

function LabView({ runScenario, running, notice, detection }) {
  const scenarios = [
    ['brute_force','Brute-force login','Six failed attempts from one IP'],
    ['privilege_escalation','Privilege escalation','Denied administrative role change'],
    ['unusual_login','Unusual login','Successful authentication at 02:17 UTC'],
    ['rapid_country_change','Rapid country change','Successful logins from two countries'],
    ['normal','Normal activity','Expected API access without an alert'],
  ];
  return <section className="lab-grid">
    <article className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">CONTROLLED TESTING</p><h2>Detection scenarios</h2></div><Play size={18} /></div><p className="section-copy">Generate application events safely. No external system is contacted.</p>{scenarios.map(([id,title,desc]) => <button className="scenario" disabled={!!running} onClick={() => runScenario(id)} key={id}><span><strong>{title}</strong><small>{desc}</small></span><Play size={16} className={running === id ? 'spin' : ''} /></button>)}{notice && <div className="notice">{notice}</div>}</article>
    <article className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">DETECTION ENGINE</p><h2>Model health</h2></div><ShieldCheck size={18} /></div>{detection && <div className="health-grid"><span>Model version<strong>{detection.model_version}</strong></span><span>Alert threshold<strong>{detection.alert_threshold}/100</strong></span><span>Personal baseline<strong>{detection.minimum_personal_baseline} events</strong></span><span>Active rules<strong>{detection.rules.length}</strong></span><span>Collectors<strong>{detection.integrations.length} sources</strong></span></div>}<h3>Available sources</h3>{detection?.integrations.map((item) => <div className="integration-item" key={item}><i />{item}</div>)}<h3>Service ingestion</h3><pre><code>{`POST /api/v1/ingest/events\nX-Ingestion-Key: ••••••••\n\n{ "events": [ ... ] }`}</code></pre><p className="muted-note">Collectors use a separate service credential; analyst JWTs are not accepted for machine ingestion.</p></article>
  </section>;
}

function AuditView({ audits }) {
  return <article className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">ACCOUNTABILITY</p><h2>Audit trail</h2></div><ClipboardList size={18} /></div><div className="audit-list">{audits.length === 0 && <div className="empty"><ClipboardList size={32} /><strong>No audit records yet</strong><span>Authentication and triage actions appear here.</span></div>}{audits.map((item) => <div key={item.id}><span>{new Date(item.created_at).toLocaleString()}</span><strong>{item.action.replaceAll('_',' ')}</strong><p>{item.actor} · {item.target_type} #{item.target_id}</p></div>)}</div></article>;
}

function Dashboard({ request, onLogout }) {
  const [view, setView] = useState("overview");
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [audits, setAudits] = useState([]);
  const [detection, setDetection] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [running, setRunning] = useState("");
  const [notice, setNotice] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);

  const refresh = useCallback(async (quiet = false) => {
    try {
      const [summaryData, alertsData, eventsData, auditData, detectionData] = await Promise.all([
        request("/api/v1/dashboard/summary"), request("/api/v1/alerts?limit=100"),
        request("/api/v1/events?limit=200"), request("/api/v1/audit-logs?limit=100"),
        request("/api/v1/detection/health"),
      ]);
      setSummary(summaryData); setAlerts(alertsData); setEvents(eventsData); setAudits(auditData); setDetection(detectionData); setLastUpdated(new Date()); setNotice("");
    } catch (error) { if (!quiet) setNotice(error.message); }
  }, [request]);

  useEffect(() => { refresh(); const timer = setInterval(() => refresh(true), 10_000); return () => clearInterval(timer); }, [refresh]);

  async function runScenario(name) {
    setRunning(name); setNotice("");
    try { const result = await request(`/api/v1/simulations/${name}`, { method: "POST" }); setNotice(`${result.events_created} events analyzed · ${result.alerts_created} alerts created`); await refresh(); }
    catch (error) { setNotice(error.message); } finally { setRunning(""); }
  }

  async function updateStatus(id, status) {
    setNotice("");
    try {
      const updated = await request(`/api/v1/alerts/${id}`, { method: "PATCH", body: JSON.stringify({ status }) });
      setSelectedAlert((current) => current?.id === id ? updated : current); await refresh(true);
    } catch (error) {
      setNotice(error.message);
    }
  }

  if (!summary) return <InitialLoadState error={notice} onRetry={() => { setNotice(""); refresh(); }} />;
  const nav = [
    ["overview", Activity, "Overview"], ["alerts", AlertTriangle, "Alerts"],
    ["events", Terminal, "Event stream"], ["lab", Eye, "Detection lab"],
    ["audit", ClipboardList, "Audit trail"],
  ];
  return <div className="app-shell"><aside className="sidebar"><div className="brand"><div className="brand-mark small"><Radar size={20} /></div><div><strong>SentinelScope</strong><span>Security operations</span></div></div><nav>{nav.map(([id,Icon,label]) => <button key={id} className={view === id ? "active" : ""} onClick={() => setView(id)}><Icon size={18} /><span>{label}</span>{id === "alerts" && summary.open_alerts > 0 && <b>{summary.open_alerts}</b>}<ChevronRight className="nav-arrow" size={14} /></button>)}</nav><div className="system-state"><span><i /> Detection online</span><small>{detection?.model_version} · auto-refresh 10s</small></div></aside><main className="dashboard"><header><div><p className="eyebrow">SECURITY OPERATIONS CENTER</p><h1>{nav.find(([id]) => id === view)?.[2]}</h1><p>{lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : "Connecting to telemetry…"}</p></div><div className="header-actions"><button className="ghost" onClick={() => refresh()}><RefreshCw size={15} /> Refresh</button><button className="ghost" onClick={onLogout}>Sign out</button></div></header>{notice && view !== "lab" && <div className="global-notice" role="alert">{notice}<button onClick={() => setNotice("")} aria-label="Dismiss message"><X size={14} /></button></div>}{view === "overview" && <Overview summary={summary} alerts={alerts} events={events} onSelect={setSelectedAlert} onStatus={updateStatus} />}{view === "alerts" && <AlertsView alerts={alerts} onSelect={setSelectedAlert} onStatus={updateStatus} />}{view === "events" && <EventsView events={events} />}{view === "lab" && <LabView runScenario={runScenario} running={running} notice={notice} detection={detection} />}{view === "audit" && <AuditView audits={audits} />}</main><AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} onStatus={updateStatus} severityBadge={<Severity value={selectedAlert?.severity} />} /></div>;
}

function App() {
  const [auth, setAuth] = useState(undefined);
  const authRef = useRef(auth);
  const refreshPromise = useRef(null);
  const saveAuth = useCallback((value) => { authRef.current = value; setAuth(value); }, []);
  useEffect(() => {
    rawRequest("/api/v1/auth/refresh", { method: "POST", headers: csrfHeaders() })
      .then(saveAuth)
      .catch(() => saveAuth(null));
  }, [saveAuth]);
  const request = useCallback(async (path, options = {}) => {
    const requestAuth = authRef.current;
    if (!requestAuth) throw new Error("Authentication required");
    try { return await rawRequest(path, { ...options, headers: { Authorization: `Bearer ${requestAuth.access_token}`, ...options.headers } }); }
    catch (error) {
      if (error.status !== 401 || path.includes("/auth/")) throw error;
      try {
        const latestAuth = authRef.current;
        if (latestAuth && latestAuth.access_token !== requestAuth.access_token) {
          return rawRequest(path, { ...options, headers: { Authorization: `Bearer ${latestAuth.access_token}`, ...options.headers } });
        }
        if (!refreshPromise.current) {
          refreshPromise.current = rawRequest("/api/v1/auth/refresh", {
            method: "POST",
            headers: csrfHeaders(),
          }).then((renewed) => { saveAuth(renewed); return renewed; })
            .finally(() => { refreshPromise.current = null; });
        }
        const renewed = await refreshPromise.current;
        return rawRequest(path, { ...options, headers: { Authorization: `Bearer ${renewed.access_token}`, ...options.headers } });
      } catch { saveAuth(null); throw new Error("Your session expired. Please sign in again."); }
    }
  }, [saveAuth]);
  async function logout() { try { if (auth) await rawRequest("/api/v1/auth/logout", { method: "POST", headers: csrfHeaders() }); } finally { saveAuth(null); } }
  if (auth === undefined) return <InitialLoadState error="" onRetry={() => {}} />;
  return auth ? <Dashboard request={request} onLogout={logout} /> : <Login onLogin={saveAuth} />;
}

createRoot(document.getElementById("root")).render(<App />);
