import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import Navbar from "../components/Navbar";
import AnalyzeModal from "../components/AnalyzeModal";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8001";
const PALETTE = ["#d65a35", "#73856b", "#a97619", "#5d6255", "#b98d7b", "#929487"];
const SEVERITY_COLORS = { HIGH: "#b84636", MEDIUM: "#a97619", LOW: "#73856b" };

function formatTimestamp(value) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleString();
}

function Severity({ value }) {
  const severityClass = value === "HIGH" ? "severity-high" : value === "MEDIUM" ? "severity-medium" : value === "LOW" ? "severity-low" : "severity-unknown";
  return <span className={"severity " + severityClass}>{value || "UNKNOWN"}</span>;
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload || payload.length === 0) return null;
  return (
    <div className="chart-tooltip">
      {label && <div style={{ marginBottom: 5, color: "var(--muted)" }}>{label}</div>}
      {payload.map((entry) => (
        <div key={entry.dataKey || entry.name}>
          <span style={{ color: entry.color || "var(--signal)" }}>{entry.name || entry.dataKey}</span>
          <span> · {entry.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [filter, setFilter] = useState("ALL");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState("");
  const [lastSync, setLastSync] = useState("");
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    let active = true;

    const sync = async () => {
      try {
        const token = localStorage.getItem("token");
        const headers = { Authorization: "Bearer " + token };
        const [alertsResponse, statsResponse] = await Promise.all([
          fetch(API + "/alerts", { headers }),
          fetch(API + "/stats", { headers }),
        ]);

        if (!alertsResponse.ok || !statsResponse.ok) {
          throw new Error("API request failed (" + (!alertsResponse.ok ? alertsResponse.status : statsResponse.status) + ").");
        }

        const [alertsData, statsData] = await Promise.all([alertsResponse.json(), statsResponse.json()]);
        if (!Array.isArray(alertsData) || !statsData || typeof statsData !== "object") {
          throw new Error("The API returned an unexpected response format.");
        }

        if (!active) return;
        setAlerts(alertsData);
        setStats(statsData);
        setApiError("");
        setLastSync(new Date().toLocaleTimeString());
      } catch {
        if (active) setApiError("The alert API could not be reached or returned an invalid response. Previously loaded data is retained.");
      } finally {
        if (active) setLoading(false);
      }
    };

    sync();
    const interval = window.setInterval(sync, 5000);
    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [refreshTick]);

  const noData = stats.no_data === true || Number(stats.total || 0) === 0;
  const severityData = [
    { name: "High", count: Number(stats.high || 0), color: SEVERITY_COLORS.HIGH },
    { name: "Medium", count: Number(stats.medium || 0), color: SEVERITY_COLORS.MEDIUM },
    { name: "Low", count: Number(stats.low || 0), color: SEVERITY_COLORS.LOW },
  ];

  const attackCounts = alerts.reduce((counts, alert) => {
    const type = alert.attack_type || "Unclassified";
    counts[type] = (counts[type] || 0) + 1;
    return counts;
  }, {});
  const attackData = Object.entries(attackCounts)
    .map(([name, value]) => ({ name: name.replace(/_/g, " "), value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 7);

  const timelineData = (() => {
    const buckets = new Map();
    alerts.forEach((alert) => {
      if (!alert.timestamp) return;
      const date = new Date(alert.timestamp);
      if (Number.isNaN(date.getTime())) return;
      const key = date.getHours().toString().padStart(2, "0") + ":" + date.getMinutes().toString().padStart(2, "0");
      buckets.set(key, (buckets.get(key) || 0) + 1);
    });
    return Array.from(buckets, ([time, count]) => ({ time, count })).slice(-15);
  })();

  const normalizedQuery = query.trim().toLowerCase();
  const filteredAlerts = alerts.filter((alert) => {
    const severityMatch = filter === "ALL" || alert.severity === filter;
    const searchable = [alert.id, alert.source_ip, alert.attack_type, alert.event_type, alert.description, alert.log_source]
      .filter(Boolean).join(" ").toLowerCase();
    return severityMatch && (!normalizedQuery || searchable.includes(normalizedQuery));
  });

  const metrics = [
    { label: "Alerts in view", value: stats.total || 0, tone: "tone-neutral", note: "Returned by the stats endpoint" },
    { label: "High severity", value: stats.high || 0, tone: "tone-high", note: "Requires analyst triage" },
    { label: "Medium", value: stats.medium || 0, tone: "tone-medium", note: "Review supporting context" },
    { label: "Low", value: stats.low || 0, tone: "tone-low", note: "Lower assigned severity" },
    { label: "Priority queue", value: stats.priority || 0, tone: "tone-priority", note: "Reported by the API" },
    { label: "Anomalies", value: stats.anomalies || 0, tone: "tone-neutral", note: "Reported by detection pipeline" },
  ];

  return (
    <div className="app-shell">
      <Navbar />
      <main className="app-main">
        <div className="page-wrap">
          <header className="page-topline">
            <div>
              <div className="eyebrow">Security operations / 01</div>
              <h1 className="page-title">Overview</h1>
              <p className="page-subtitle">Review alert volume, severity distribution, and the events currently returned by the API.</p>
            </div>
            <div className="page-meta">
              <span className={"status-chip " + (apiError ? "is-error" : loading ? "is-neutral" : "is-healthy")}>
                <span className="status-dot" />
                {apiError ? "API unavailable" : loading ? "Connecting" : "API responding"}
              </span>
              <span>Last successful poll: {lastSync || "not yet"}</span>
              <button className="button-secondary" type="button" onClick={() => { setLoading(true); setRefreshTick((tick) => tick + 1); }}>
                Refresh now
              </button>
            </div>
          </header>

          {apiError && <div className="inline-alert" role="alert">{apiError}</div>}
          {!apiError && noData && !loading && (
            <div className="inline-notice">
              <strong>No alert data reported.</strong> The API response currently contains no alerts. This view does not generate example events or infer collector health.
            </div>
          )}

          <section className="metric-grid" aria-label="Alert metrics">
            {metrics.map((metric, index) => (
              <article className={"metric-card " + metric.tone} key={metric.label}>
                <div className="metric-label">
                  <span>{metric.label}</span><span className="metric-index">{String(index + 1).padStart(2, "0")}</span>
                </div>
                <div className="metric-value">{Number(metric.value || 0).toLocaleString()}</div>
                <div className="metric-note">{metric.note}</div>
              </article>
            ))}
          </section>

          <section className="chart-grid" aria-label="Alert analysis charts">
            <article className="panel">
              <div className="panel-header">
                <div><h2 className="panel-title">Severity distribution</h2><div className="panel-kicker">Counts from the stats endpoint</div></div>
              </div>
              <div className="chart-body">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityData} margin={{ top: 8, right: 5, left: -20, bottom: 0 }}>
                    <XAxis dataKey="name" tick={{ fill: "#707168", fontSize: 10 }} axisLine={{ stroke: "#d9d8ce" }} tickLine={false} />
                    <YAxis allowDecimals={false} tick={{ fill: "#929287", fontSize: 10 }} axisLine={false} tickLine={false} />
                    <Tooltip content={<ChartTooltip />} cursor={{ fill: "#eeede5" }} />
                    <Bar dataKey="count" name="Alerts" radius={[2, 2, 0, 0]} maxBarSize={34}>
                      {severityData.map((item) => <Cell key={item.name} fill={item.color} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </article>

            <article className="panel">
              <div className="panel-header">
                <div><h2 className="panel-title">Detection categories</h2><div className="panel-kicker">Distribution of alerts currently loaded</div></div>
              </div>
              {attackData.length > 0 ? (
                <div className="chart-body">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={attackData} dataKey="value" nameKey="name" innerRadius={43} outerRadius={66} paddingAngle={2}>
                        {attackData.map((item, index) => <Cell key={item.name} fill={PALETTE[index % PALETTE.length]} />)}
                      </Pie>
                      <Tooltip content={<ChartTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              ) : <div className="chart-empty">No category data returned.</div>}
            </article>

            <article className="panel">
              <div className="panel-header">
                <div><h2 className="panel-title">Alert timeline</h2><div className="panel-kicker">Events grouped by local minute</div></div>
              </div>
              {timelineData.length > 0 ? (
                <div className="chart-body">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData} margin={{ top: 8, right: 4, left: -20, bottom: 0 }}>
                      <defs>
                        <linearGradient id="eventVolumeFill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="#d65a35" stopOpacity={0.24} />
                          <stop offset="100%" stopColor="#d65a35" stopOpacity={0.015} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="time" tick={{ fill: "#929287", fontSize: 9 }} axisLine={{ stroke: "#d9d8ce" }} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fill: "#929287", fontSize: 10 }} axisLine={false} tickLine={false} />
                      <Tooltip content={<ChartTooltip />} />
                      <Area type="monotone" dataKey="count" name="Events" stroke="#d65a35" fill="url(#eventVolumeFill)" strokeWidth={1.8} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : <div className="chart-empty">No valid timestamps to chart.</div>}
            </article>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2 className="panel-title">Alert records</h2>
                <div className="panel-kicker">{filteredAlerts.length} displayed of {alerts.length} records returned by the API</div>
              </div>
              <div className="toolbar-right">
                <input className="search-field" aria-label="Search alerts" placeholder="Search ID, source, detection…" value={query} onChange={(event) => setQuery(event.target.value)} />
              </div>
            </div>
            <div className="panel-header">
              <div className="filter-row" aria-label="Filter alerts by severity">
                {["ALL", "HIGH", "MEDIUM", "LOW"].map((severity) => (
                  <button className="filter-button" type="button" key={severity} aria-pressed={filter === severity} onClick={() => setFilter(severity)}>
                    {severity === "ALL" ? "All severities" : severity}
                  </button>
                ))}
              </div>
            </div>
            <div className="table-scroll">
              <table className="data-table">
                <thead><tr>
                  <th scope="col">ID</th><th scope="col">Observed</th><th scope="col">Source</th><th scope="col">Detection type</th><th scope="col">Event</th><th scope="col">Severity</th><th scope="col">Signals</th><th scope="col">Action</th>
                </tr></thead>
                <tbody>
                  {loading && alerts.length === 0 ? (
                    Array.from({ length: 5 }, (_, index) => <tr key={index}><td colSpan={8}><div className="skeleton-row" /></td></tr>)
                  ) : filteredAlerts.length === 0 ? (
                    <tr><td colSpan={8}>
                      <div className="empty-state">
                        <div className="empty-mark">—</div>
                        <p className="empty-title">{alerts.length ? "No records match these filters" : "No alert records returned"}</p>
                        <p className="empty-copy">{alerts.length ? "Change the severity filter or search terms to widen the results." : "When the API returns alert records, they will appear here. No placeholder rows are inserted."}</p>
                      </div>
                    </td></tr>
                  ) : filteredAlerts.map((alert) => (
                    <tr key={alert.id}>
                      <td className="cell-mono">#{alert.id}</td>
                      <td className="cell-mono">{formatTimestamp(alert.timestamp)}</td>
                      <td className="cell-mono">{alert.source_ip || "Not recorded"}</td>
                      <td className="cell-primary">{String(alert.attack_type || "Unclassified").replace(/_/g, " ")}</td>
                      <td className="cell-truncate" title={alert.description || alert.event_type || ""}>{alert.event_type || alert.description || "—"}</td>
                      <td><Severity value={alert.severity} /></td>
                      <td>{alert.is_anomaly ? <span className="pill">Anomaly flagged</span> : alert.priority ? <span className="priority-indicator">Priority</span> : <span className="cell-muted">—</span>}</td>
                      <td><button className="table-action" type="button" onClick={() => setSelected(alert)}>Review evidence →</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </main>
      {selected && <AnalyzeModal alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}