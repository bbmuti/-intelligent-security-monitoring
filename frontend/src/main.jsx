import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Eye,
  LockKeyhole,
  Play,
  Radar,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "";

async function api(path, token, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  });
  if (!response.ok) throw new Error((await response.json()).detail || "Request failed");
  return response.json();
}

function Login({ onLogin }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("change-me-before-production");
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      const data = await api("/api/v1/auth/login", "", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      onLogin(data.access_token);
    } catch (err) {
      setError(err.message);
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
          <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} /></label>
          <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          {error && <p className="error">{error}</p>}
          <button className="primary" type="submit"><LockKeyhole size={17} /> Enter analyst console</button>
        </form>
      </section>
      <section className="login-visual" aria-hidden="true">
        <div className="orb"><div className="orb-inner"><ShieldCheck size={46} /></div></div>
        <div className="signal-card one"><span>Behavior score</span><strong>94</strong><small>high confidence anomaly</small></div>
        <div className="signal-card two"><span>Rule match</span><strong>T1110</strong><small>Brute Force</small></div>
      </section>
    </main>
  );
}

function Metric({ icon: Icon, label, value, tone }) {
  return <article className={`metric ${tone || ""}`}><div className="metric-icon"><Icon size={19} /></div><div><span>{label}</span><strong>{value}</strong></div></article>;
}

function Dashboard({ token, onLogout }) {
  const [summary, setSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [events, setEvents] = useState([]);
  const [running, setRunning] = useState("");
  const [notice, setNotice] = useState("");

  async function refresh() {
    const [summaryData, alertsData, eventsData] = await Promise.all([
      api("/api/v1/dashboard/summary", token),
      api("/api/v1/alerts?limit=20", token),
      api("/api/v1/events?limit=8", token),
    ]);
    setSummary(summaryData); setAlerts(alertsData); setEvents(eventsData);
  }

  useEffect(() => { refresh().catch((e) => setNotice(e.message)); }, []);

  async function simulate(name) {
    setRunning(name); setNotice("");
    try {
      const result = await api(`/api/v1/simulations/${name}`, token, { method: "POST" });
      setNotice(`${result.events_created} events analyzed · ${result.alerts_created} alerts created`);
      await refresh();
    } catch (e) { setNotice(e.message); }
    finally { setRunning(""); }
  }

  async function resolve(id) {
    await api(`/api/v1/alerts/${id}`, token, { method: "PATCH", body: JSON.stringify({ status: "resolved" }) });
    await refresh();
  }

  const maxEvent = useMemo(() => Math.max(1, ...Object.values(summary?.event_type_counts || {})), [summary]);
  if (!summary) return <div className="loading"><Radar className="spin" /> Loading security telemetry…</div>;

  return (
    <div className="app-shell">
      <aside>
        <div className="brand"><div className="brand-mark small"><Radar size={20} /></div><div><strong>SentinelScope</strong><span>Security operations</span></div></div>
        <nav><a className="active"><Activity size={18} /> Overview</a><a><AlertTriangle size={18} /> Alerts <b>{summary.open_alerts}</b></a><a><Terminal size={18} /> Event stream</a><a><Eye size={18} /> Detection lab</a></nav>
        <div className="system-state"><span><i /> Detection online</span><small>Rules + behavioral model</small></div>
      </aside>
      <main className="dashboard">
        <header><div><p className="eyebrow">SECURITY OPERATIONS CENTER</p><h1>Threat overview</h1><p>Authentication and API behavior across the monitored environment.</p></div><button className="ghost" onClick={onLogout}>Sign out</button></header>
        <section className="metrics">
          <Metric icon={Activity} label="Events analyzed" value={summary.total_events} />
          <Metric icon={AlertTriangle} label="Open alerts" value={summary.open_alerts} tone="warning" />
          <Metric icon={ShieldCheck} label="Critical findings" value={summary.critical_alerts} tone="danger" />
          <Metric icon={Radar} label="Average risk" value={`${summary.average_risk}/100`} tone="cyan" />
        </section>

        <section className="grid-main">
          <article className="panel alerts-panel">
            <div className="panel-head"><div><p className="eyebrow">PRIORITIZED FINDINGS</p><h2>Active alerts</h2></div><span>{alerts.length} total</span></div>
            <div className="alert-list">
              {alerts.length === 0 && <div className="empty"><ShieldCheck size={32} /><strong>No active alerts</strong><span>Run a safe scenario to test detection.</span></div>}
              {alerts.map((alert) => <div className="alert-row" key={alert.id}>
                <span className={`severity ${alert.severity}`}>{alert.severity}</span>
                <div className="alert-body"><strong>{alert.title}</strong><p>{alert.explanation}</p><div><code>{alert.mitre_technique}</code><span>Risk {alert.risk_score}</span></div></div>
                {alert.status !== "resolved" ? <button className="resolve" onClick={() => resolve(alert.id)}><CheckCircle2 size={16} /> Resolve</button> : <span className="resolved">Resolved</span>}
              </div>)}
            </div>
          </article>

          <article className="panel lab-panel">
            <div className="panel-head"><div><p className="eyebrow">CONTROLLED TESTING</p><h2>Detection lab</h2></div><Play size={18} /></div>
            <p>Generate application events safely. No external system is contacted.</p>
            {[['brute_force','Brute-force login','6 failed attempts'],['privilege_escalation','Privilege escalation','Denied admin role'],['unusual_login','Unusual login','02:17 UTC activity'],['normal','Normal activity','Expected API access']].map(([id,title,desc]) =>
              <button className="scenario" disabled={!!running} onClick={() => simulate(id)} key={id}><span><strong>{title}</strong><small>{desc}</small></span><Play size={16} className={running === id ? 'spin' : ''} /></button>
            )}
            {notice && <div className="notice">{notice}</div>}
          </article>
        </section>

        <section className="grid-bottom">
          <article className="panel"><div className="panel-head"><div><p className="eyebrow">EVENT DISTRIBUTION</p><h2>Telemetry</h2></div></div>
            <div className="bars">{Object.entries(summary.event_type_counts).map(([type,count]) => <div className="bar-row" key={type}><span>{type.replace('_',' ')}</span><div><i style={{width:`${count/maxEvent*100}%`}} /></div><b>{count}</b></div>)}</div>
          </article>
          <article className="panel"><div className="panel-head"><div><p className="eyebrow">LATEST ACTIVITY</p><h2>Event stream</h2></div></div>
            <div className="event-list">{events.map((event) => <div key={event.id}><span className={`event-dot ${event.outcome}`} /><p><strong>{event.event_type.replace('_',' ')}</strong><small>{event.user_id} · {event.ip_address}</small></p><b>{event.risk_score}</b></div>)}</div>
          </article>
        </section>
      </main>
    </div>
  );
}

function App() {
  const [token, setToken] = useState(() => sessionStorage.getItem("sentinel_token"));
  function login(value) { sessionStorage.setItem("sentinel_token", value); setToken(value); }
  function logout() { sessionStorage.removeItem("sentinel_token"); setToken(null); }
  return token ? <Dashboard token={token} onLogout={logout} /> : <Login onLogin={login} />;
}

createRoot(document.getElementById("root")).render(<App />);
