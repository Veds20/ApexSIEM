import { useEffect, useState } from "react";
import Navbar from "../components/Navbar";
import AnalyzeModal from "../components/AnalyzeModal";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8001";

function Severity({ value }) {
  const severityClass = value === "HIGH" ? "severity-high" : value === "MEDIUM" ? "severity-medium" : value === "LOW" ? "severity-low" : "severity-unknown";
  return <span className={"severity " + severityClass}>{value || "UNKNOWN"}</span>;
}

function formatTimestamp(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

export default function Priority() {
  const [alerts, setAlerts] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState("");
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    let active = true;
    const sync = async () => {
      try {
        const token = localStorage.getItem("token");
        const response = await fetch(API + "/priority", { headers: { Authorization: "Bearer " + token } });
        if (!response.ok) throw new Error("API request failed.");
        const data = await response.json();
        if (!Array.isArray(data)) throw new Error("Unexpected API response.");
        if (!active) return;
        setAlerts(data);
        setApiError("");
      } catch {
        if (active) setApiError("Priority records could not be refreshed. The latest successfully loaded records are retained.");
      } finally {
        if (active) setLoading(false);
      }
    };
    sync();
    const interval = window.setInterval(sync, 5000);
    return () => { active = false; window.clearInterval(interval); };
  }, [refreshTick]);

  const critical = alerts.filter((alert) => alert.severity === "HIGH").length;
  const anomalies = alerts.filter((alert) => alert.is_anomaly).length;
  const byType = alerts.reduce((groups, alert) => {
    const type = alert.attack_type || "Unclassified";
    if (!groups[type]) groups[type] = [];
    groups[type].push(alert);
    return groups;
  }, {});

  return (
    <div className="app-shell">
      <Navbar />
      <main className="app-main">
        <div className="page-wrap">
          <header className="page-topline">
            <div>
              <div className="eyebrow">Triage / 02</div>
              <h1 className="page-title">Priority queue</h1>
              <p className="page-subtitle">High-severity and anomaly-flagged records returned by the priority endpoint.</p>
            </div>
            <div className="page-meta">
              <span className={"status-chip " + (apiError ? "is-error" : loading ? "is-neutral" : "is-healthy")}>
                <span className="status-dot" />{apiError ? "Refresh error" : loading ? "Loading" : "Endpoint checked"}
              </span>
              <button className="button-secondary" type="button" onClick={() => { setLoading(true); setRefreshTick((tick) => tick + 1); }}>Refresh now</button>
            </div>
          </header>

          {apiError && <div className="inline-alert" role="alert">{apiError}</div>}

          <section className="metric-grid" aria-label="Priority metrics" style={{ gridTemplateColumns: "repeat(3, minmax(0, 1fr))", maxWidth: 800 }}>
            {[
              { label: "Priority records", value: alerts.length, tone: "tone-neutral", note: "Current response size" },
              { label: "High severity", value: critical, tone: "tone-high", note: "Classified HIGH" },
              { label: "Anomaly flagged", value: anomalies, tone: "tone-medium", note: "Flag on alert record" },
            ].map((item, index) => (
              <article className={"metric-card " + item.tone} key={item.label}>
                <div className="metric-label"><span>{item.label}</span><span className="metric-index">0{index + 1}</span></div>
                <div className="metric-value">{item.value.toLocaleString()}</div>
                <div className="metric-note">{item.note}</div>
              </article>
            ))}
          </section>

          {alerts.length === 0 && !loading && !apiError && (
            <div className="inline-notice"><strong>No priority records returned.</strong> This is an empty result, not evidence that every collector is healthy.</div>
          )}

          <div className="priority-groups">
            {Object.entries(byType).map(([attackType, typeAlerts]) => (
              <section key={attackType}>
                <header className="priority-group-heading">
                  <h2 className="priority-group-title">{attackType.replace(/_/g, " ")}</h2>
                  <span className="priority-group-count">{typeAlerts.length} record{typeAlerts.length === 1 ? "" : "s"}</span>
                </header>
                <div className="priority-card-grid">
                  {typeAlerts.map((alert) => (
                    <article className="priority-card" key={alert.id}>
                      <div className="priority-card-top">
                        <span className="priority-card-id">ALERT #{alert.id}</span>
                        <Severity value={alert.severity} />
                      </div>
                      <div className="priority-card-source">{alert.source_ip || "Source not recorded"}</div>
                      <div><span className="pill">{alert.attack_type || "Unclassified"}</span>{alert.is_anomaly && <span className="pill" style={{ marginLeft: 6 }}>Anomaly flagged</span>}</div>
                      <div className="priority-card-desc">{alert.description || alert.event_type || "No event description returned."}</div>
                      <div className="priority-card-bottom">
                        <span className="cell-mono">{formatTimestamp(alert.timestamp)}</span>
                        <button className="table-action" type="button" onClick={() => setSelected(alert)}>Review evidence →</button>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            ))}
          </div>

          {loading && alerts.length === 0 && <div className="panel"><div className="empty-state"><p className="empty-title">Loading priority records</p><p className="empty-copy">Waiting for the authenticated API response.</p></div></div>}
          {apiError && alerts.length === 0 && <div className="panel"><div className="empty-state"><p className="empty-title">Priority data unavailable</p><p className="empty-copy">Check the backend connection and authentication, then retry.</p></div></div>}
        </div>
      </main>
      {selected && <AnalyzeModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}