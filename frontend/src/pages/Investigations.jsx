import { useEffect, useState } from "react";
import Navbar from "../components/Navbar";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8001";

const STATUS_CONFIG = {
  "Investigated": { label: "Investigated", className: "is-done" },
  "Under Progress": { label: "Under progress", className: "is-progress" },
  "Closed": { label: "Closed", className: "is-done" },
};

function Severity({ value }) {
  const severityClass = value === "HIGH" ? "severity-high" : value === "MEDIUM" ? "severity-medium" : value === "LOW" ? "severity-low" : "severity-unknown";
  return <span className={"severity " + severityClass}>{value || "UNKNOWN"}</span>;
}

function formatTimestamp(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

export default function Investigations() {
  const [investigations, setInvestigations] = useState([]);
  const [filter, setFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState("");
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    let active = true;
    const sync = async () => {
      try {
        const token = localStorage.getItem("token");
        const response = await fetch(API + "/investigations", { headers: { Authorization: "Bearer " + token } });
        if (!response.ok) throw new Error("API request failed.");
        const data = await response.json();
        if (!Array.isArray(data)) throw new Error("Unexpected API response.");
        if (!active) return;
        setInvestigations(data);
        setApiError("");
      } catch {
        if (active) setApiError("Investigation records could not be refreshed. Previously loaded records are retained.");
      } finally {
        if (active) setLoading(false);
      }
    };
    sync();
    const interval = window.setInterval(sync, 5000);
    return () => { active = false; window.clearInterval(interval); };
  }, [refreshTick]);

  const filtered = filter === "ALL" ? investigations : investigations.filter((item) => item.investigation_status === filter);
  const counts = {
    total: investigations.length,
    progress: investigations.filter((item) => item.investigation_status === "Under Progress").length,
    investigated: investigations.filter((item) => item.investigation_status === "Investigated").length,
    closed: investigations.filter((item) => item.investigation_status === "Closed").length,
  };

  return (
    <div className="app-shell">
      <Navbar />
      <main className="app-main">
        <div className="page-wrap">
          <header className="page-topline">
            <div>
              <div className="eyebrow">Case work / 03</div>
              <h1 className="page-title">Investigations</h1>
              <p className="page-subtitle">Analyst review records, investigation notes, and the current disposition recorded for each alert.</p>
            </div>
            <div className="page-meta">
              <span className={"status-chip " + (apiError ? "is-error" : loading ? "is-neutral" : "is-healthy")}><span className="status-dot" />{apiError ? "Refresh error" : loading ? "Loading" : "Endpoint checked"}</span>
              <button className="button-secondary" type="button" onClick={() => { setLoading(true); setRefreshTick((tick) => tick + 1); }}>Refresh now</button>
            </div>
          </header>

          {apiError && <div className="inline-alert" role="alert">{apiError}</div>}

          <section className="investigation-counts" aria-label="Investigation counts">
            {[
              { label: "Total records", value: counts.total },
              { label: "Under progress", value: counts.progress },
              { label: "Investigated", value: counts.investigated },
              { label: "Closed", value: counts.closed },
            ].map((item) => <article className="count-card" key={item.label}><div className="count-value">{item.value.toLocaleString()}</div><div className="count-label">{item.label}</div></article>)}
          </section>

          <section className="panel">
            <div className="panel-header">
              <div><h2 className="panel-title">Investigation register</h2><div className="panel-kicker">{filtered.length} displayed of {investigations.length} records</div></div>
              <div className="filter-row" aria-label="Filter investigations">
                {[
                  { value: "ALL", label: "All statuses" },
                  { value: "Under Progress", label: "Under progress" },
                  { value: "Investigated", label: "Investigated" },
                  { value: "Closed", label: "Closed" },
                ].map((item) => <button className="filter-button" type="button" key={item.value} aria-pressed={filter === item.value} onClick={() => setFilter(item.value)}>{item.label}</button>)}
              </div>
            </div>

            {filtered.length === 0 ? (
              <div className="empty-state">
                <div className="empty-mark">—</div>
                <p className="empty-title">{loading ? "Loading investigation records" : apiError ? "Investigation data unavailable" : investigations.length ? "No records match this status" : "No investigations recorded"}</p>
                <p className="empty-copy">{loading ? "Waiting for the authenticated API response." : apiError ? "Check the backend connection and try again." : investigations.length ? "Select another status to view the remaining records." : "When an alert is moved into the investigation workflow, its record and analyst notes will appear here."}</p>
              </div>
            ) : (
              <div className="investigation-list" style={{ padding: 12 }}>
                {filtered.map((item) => {
                  const status = STATUS_CONFIG[item.investigation_status] || { label: item.investigation_status || "Unspecified", className: "" };
                  return (
                    <article className="investigation-card" key={item.id}>
                      <div className="investigation-card-top">
                        <div>
                          <div className="investigation-details">
                            <span className="cell-mono">ALERT #{item.id}</span>
                            <Severity value={item.severity} />
                            <span className="pill">{item.attack_type || "Unclassified"}</span>
                          </div>
                          <h3 className="investigation-source">{item.source_ip || "Source not recorded"}</h3>
                          <div className="investigation-meta">{item.event_type || item.log_source || "Event type not recorded"} · {formatTimestamp(item.timestamp)}</div>
                          {item.description && <p className="investigation-description">{item.description}</p>}
                        </div>
                        <div>
                          <div className={"investigation-status " + status.className}>STATUS · {status.label}</div>
                          <div className="investigation-meta" style={{ marginTop: 8 }}>Analyst: {item.assigned_to || "Not assigned"}</div>
                          <div className="investigation-meta" style={{ marginTop: 4 }}>Updated: {formatTimestamp(item.investigated_at)}</div>
                        </div>
                      </div>
                      {item.investigation_reason && <div className="investigation-notes"><strong>Analyst notes</strong><br />{item.investigation_reason}</div>}
                      {item.analysis_report && (
                        <details style={{ marginTop: 12 }}>
                          <summary style={{ cursor: "pointer", color: "var(--signal)", fontSize: 11 }}>View AI analysis report</summary>
                          <pre className="investigation-notes">{item.analysis_report}</pre>
                        </details>
                      )}
                    </article>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      </main>
    </div>
  );
}