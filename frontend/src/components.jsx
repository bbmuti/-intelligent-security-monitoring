import React, { useEffect, useId, useRef } from "react";
import { Radar, RefreshCw, X } from "lucide-react";

export function InitialLoadState({ error, onRetry }) {
  if (error) {
    return (
      <main className="loading load-error" role="alert">
        <Radar />
        <div>
          <strong>Telemetry could not be loaded</strong>
          <span>{error}</span>
        </div>
        <button className="ghost" type="button" onClick={onRetry}>
          <RefreshCw size={15} /> Retry
        </button>
      </main>
    );
  }
  return <main className="loading" role="status"><Radar className="spin" /> Loading security telemetry…</main>;
}

export function AlertDrawer({ alert, onClose, onStatus, severityBadge }) {
  const titleId = useId();
  const drawerRef = useRef(null);

  useEffect(() => {
    if (!alert) return undefined;
    const previousFocus = document.activeElement;
    const drawer = drawerRef.current;
    drawer?.querySelector("button")?.focus();

    function handleKeyDown(event) {
      if (event.key === "Escape") {
        onClose();
        return;
      }
      if (event.key !== "Tab" || !drawer) return;
      const focusable = [
        ...drawer.querySelectorAll("button, select, [href], [tabindex]:not([tabindex='-1'])"),
      ].filter((element) => !element.disabled);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previousFocus?.focus?.();
    };
  }, [alert, onClose]);

  if (!alert) return null;
  return (
    <div className="drawer-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside
        ref={drawerRef}
        className="alert-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <button className="drawer-close" onClick={onClose} aria-label="Close alert details"><X /></button>
        {severityBadge}
        <h2 id={titleId}>{alert.title}</h2>
        <div className="risk-display"><span>Risk score</span><strong>{alert.risk_score}</strong></div>
        <p>{alert.explanation}</p>
        <h3>Evidence</h3>
        <ul>{alert.evidence.map((item) => <li key={item}>{item}</li>)}</ul>
        <h3>MITRE ATT&CK</h3>
        <code>{alert.mitre_technique || "Behavioral anomaly"}</code>
        <label>Status
          <select value={alert.status} onChange={(event) => onStatus(alert.id, event.target.value)}>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False positive</option>
          </select>
        </label>
      </aside>
    </div>
  );
}
