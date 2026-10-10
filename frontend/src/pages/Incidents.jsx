import { useCallback, useEffect, useState } from "react";
import Navbar from "../components/Navbar";
import { api } from "../lib/api";
import { pretty, severityClass, when } from "../lib/presentation";

const STATUSES = ["OPEN", "IN_PROGRESS", "UNDER_INVESTIGATION", "RESOLVED", "CLOSED", "FALSE_POSITIVE"];

function IncidentSeverity({ value }) {
  return <span className={"severity " + (severityClass[value] || "severity-unknown")}>{value || "UNKNOWN"}</span>;
}

function parseTimeline(value) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [{ timestamp: null, event_type: "Investigation note", description: value }];
  }
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [actions, setActions] = useState([]);
  const [status, setStatus] = useState("OPEN");
  const [resolution, setResolution] = useState("");
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const data = await api("/incidents");
      const items = Array.isArray(data) ? data : (Array.isArray(data.items) ? data.items : []);
      setIncidents(items);
      setSelected((current) => items.find((item) => item.id === current?.id) || items[0] || null);
      setError("");
    } catch (caught) {
      setError(caught.message || "Incident records could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!selected) {
      setAlerts([]);
      setActions([]);
      return undefined;
    }

    let active = true;
    setStatus(selected.status || "OPEN");
    setResolution(selected.resolution || "");
    setDetailLoading(true);

    Promise.all([
      api(\`/incidents/\${selected.id}/alerts\`),
      api(\`/soar/actions?incident_id=\${selected.id}\`),
    ]).then(([alertRows, actionRows]) => {
      if (!active) return;
      setAlerts(Array.isArray(alertRows) ? alertRows : []);
      setActions(Array.isArray(actionRows) ? actionRows : []);
    }).catch((caught) => {
      if (active) setError(caught.message || "Incident evidence could not be loaded.");
    }).finally(() => {
      if (active) setDetailLoading(false);
    });

    return () => { active = false; };
  }, [selected?.id]);

  const updateStatus = async () => {
    if (!selected) return;
    setNotice("");
    setError("");
    try {
      const updated = await api(\`/incidents/\${selected.id}\`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status, resolution: resolution.trim() || null }),
      });
      setSelected(updated);
      setNotice("Incident workflow updated.");
      await refresh();
    } catch (caught) {
      setError(caught.message || "The incident update failed.");
    }
  };

  const requestBlock = async () => {
    if (!selected) return;
    const source = alerts.find((alert) => alert.source_ip)?.source_ip;
    if (!source) {
      setError("No source IP is present in the linked alerts. No containment request was created.");
      return;
    }

    setNotice("");
    setError("");
    try {
      await api("/soar/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action_type: "block_ip",
          target: { ip: source },
          reason: \`Analyst-requested containment for incident \${selected.incident_id}\`,
          incident_id: selected.id,
          alert_ids: alerts.map((alert) => alert.id),
          requires_approval: true,
        }),
      });
      setNotice(\`Approval request created for source \${source}; no block has been executed by this request alone.\`);
      setActions(await api(\`/soar/actions?incident_id=\${selected.id}\`));
    } catch (caught) {
      setError(caught.message || "The response approval request failed.");
    }
  };

  return (
    <div className="app-shell">
      <Navbar />
      <main className="app-main">
        <div className="page-wrap">
          <header className="page-topline">
            <div>
              <div className="eyebrow">Case management / 04</div>
              <h1 className="page-title">Incident workspace</h1>
              <p className="page-subtitle">Correlated cases, linked alerts, chronology, evidence and analyst-controlled response approvals.</p>
            </div>
            <div className="page-meta">
              <span className={"status-chip " + (error ? "is-error" : loading ? "is-neutral" : "is-healthy")}>
                <span className="status-dot" />{error ? "Needs attention" : loading ? "Loading cases" : "Endpoint checked"}
              </span>
              <button type="button" className="button-secondary" onClick={() => { setLoading(true); refresh(); }}>Refresh cases</button>
            </div>
          </header>

          {error && <div className="inline-alert" role="alert">{error}</div>}
          {notice && <div className="inline-notice" role="status">{notice}</div>}

          <div className="incident-workspace">
            <section className="panel incident-list" aria-label="Incident list">
              <header className="incident-list-heading">
                <h2>Case register</h2>
                <p>{incidents.length} incident{incidents.length === 1 ? "" : "s"} returned by the API</p>
              </header>
              <div className="incident-list-items">
                {incidents.map((incident) => (
                  <button
                    className={"incident-select" + (selected?.id === incident.id ? " active" : "")}
                    type="button"
                    key={incident.id}
                    onClick={() => { setSelected(incident); setNotice(""); }}
                  >
                    <div className="incident-select-top">
                      <span className="incident-select-id">{incident.incident_id || \`CASE-\${incident.id}\`}</span>
                      <IncidentSeverity value={incident.severity} />
                    </div>
                    <h3 className="incident-select-title">{incident.title || "Untitled incident"}</h3>
                    <div className="incident-select-meta">{incident.alert_count ?? 0} linked alert{incident.alert_count === 1 ? "" : "s"}</div>
                    <div className="incident-select-meta">{pretty(incident.status)} · {when(incident.updated_at)}</div>
                  </button>
                ))}
                {!loading && incidents.length === 0 && (
                  <div className="empty-state">
                    <div className="empty-mark">—</div>
                    <p className="empty-title">No incidents recorded</p>
                    <p className="empty-copy">No incident records were returned. An empty list does not imply that the environment is healthy.</p>
                  </div>
                )}
                {loading && incidents.length === 0 && <div className="empty-state"><p className="empty-title">Loading cases…</p></div>}
              </div>
            </section>

            <section className="panel incident-detail-panel" aria-label="Selected incident details">
              {!selected ? (
                <div className="empty-state"><div className="empty-mark">—</div><p className="empty-title">Select an incident</p><p className="empty-copy">Its recorded timeline, linked evidence and workflow controls will appear here.</p></div>
              ) : (
                <>
                  <header className="incident-detail-head">
                    <div>
                      <div className="eyebrow">{selected.incident_id || \`CASE-\${selected.id}\`}</div>
                      <h2>{selected.title || "Untitled incident"}</h2>
                      <p>{selected.description || "No incident narrative has been recorded."}</p>
                    </div>
                    <IncidentSeverity value={selected.severity} />
                  </header>

                  <div className="incident-detail-content">
                    <section className="incident-section">
                      <h3 className="incident-section-title">Case summary</h3>
                      <div className="incident-detail-grid">
                        <div className="incident-detail-field"><div className="field-label">Status</div><div className="incident-detail-value">{pretty(selected.status)}</div></div>
                        <div className="incident-detail-field"><div className="field-label">Assigned analyst</div><div className="incident-detail-value">{selected.assigned_to || "Unassigned"}</div></div>
                        <div className="incident-detail-field"><div className="field-label">Linked alerts</div><div className="incident-detail-value">{alerts.length}</div></div>
                        <div className="incident-detail-field"><div className="field-label">Confidence</div><div className="incident-detail-value">{selected.confidence ?? "Not recorded"}{selected.confidence == null ? "" : "%"}</div></div>
                        <div className="incident-detail-field"><div className="field-label">Created</div><div className="incident-detail-value">{when(selected.created_at)}</div></div>
                        <div className="incident-detail-field"><div className="field-label">Last update</div><div className="incident-detail-value">{when(selected.updated_at)}</div></div>
                      </div>
                    </section>

                    <section className="incident-section">
                      <h3 className="incident-section-title">Attack chronology</h3>
                      {parseTimeline(selected.timeline).length ? (
                        <div className="incident-timeline">
                          {parseTimeline(selected.timeline).map((event, index) => (
                            <article className="incident-timeline-item" key={\`\${event.timestamp || "event"}-\${index}\`}>
                              <time className="incident-timeline-time">{when(event.timestamp)}</time>
                              <strong>{pretty(event.event_type || event.attack_type || "Event")}</strong>
                              <div>{event.description || event.source_ip || "No additional narrative recorded."}</div>
                            </article>
                          ))}
                        </div>
                      ) : <p className="empty-copy">No incident timeline was stored. Linked alerts remain the available evidence.</p>}
                    </section>

                    <section className="incident-section">
                      <h3 className="incident-section-title">Linked evidence {detailLoading ? "· loading" : \`· \${alerts.length} alerts\`}</h3>
                      {alerts.length ? alerts.map((alert) => (
                        <article className="incident-alert-row" key={alert.id}>
                          <div>
                            <div className="incident-alert-title">{pretty(alert.attack_type)}</div>
                            <div className="incident-alert-description">{alert.description || alert.event_type || "No event narrative retained."}</div>
                            <div className="incident-alert-meta">{alert.log_source || "Source not recorded"} · {when(alert.timestamp)} · {alert.source_ip || "Source IP not recorded"}{alert.destination_ip ? \` → \${alert.destination_ip}\` : ""}</div>
                          </div>
                          <IncidentSeverity value={alert.severity} />
                        </article>
                      )) : <p className="empty-copy">No linked alerts were returned for this incident.</p>}
                    </section>

                    <section className="incident-section">
                      <h3 className="incident-section-title">MITRE & threat context</h3>
                      <div className="incident-detail-grid">
                        <div className="incident-detail-field"><div className="field-label">MITRE ATT&CK</div><div className="incident-detail-value">{selected.mitre_techniques || "Not captured for this case."}</div></div>
                        <div className="incident-detail-field"><div className="field-label">Threat intelligence</div><div className="incident-detail-value">{selected.threat_intelligence || "No enrichment result retained."}</div></div>
                      </div>
                    </section>

                    <section className="incident-section">
                      <h3 className="incident-section-title">Analyst decision & response approval</h3>
                      <div className="incident-form-grid">
                        <label className="incident-form-field">
                          <span className="field-label">Case status</span>
                          <select value={status} onChange={(event) => setStatus(event.target.value)}>
                            {STATUSES.map((item) => <option key={item} value={item}>{pretty(item)}</option>)}
                          </select>
                        </label>
                        <label className="incident-form-field">
                          <span className="field-label">Resolution / analyst rationale</span>
                          <textarea rows={3} value={resolution} onChange={(event) => setResolution(event.target.value)} placeholder="Record the resolution, scope or false-positive rationale." />
                        </label>
                      </div>
                      <div className="incident-action-row">
                        <button className="button-primary" type="button" onClick={updateStatus}>Save case decision</button>
                        <button className="button-secondary" type="button" onClick={requestBlock}>Request source IP block</button>
                      </div>
                      <p className="empty-copy" style={{ marginTop: 10, textAlign: "left" }}>Containment creates an approval-gated request. This control does not itself execute a firewall or endpoint action.</p>
                      {actions.length > 0 && <div style={{ marginTop: 12 }}>
                        {actions.map((action) => <div className="incident-response" key={action.action_id}><strong>{pretty(action.action_type)}</strong> · {pretty(action.status)}<br /><span>Requested by {action.requested_by || "Unknown"} · {when(action.requested_at)}</span><br /><code>{action.action_id}</code>{action.error_message ? <div>{action.error_message}</div> : null}</div>)}
                      </div>}
                    </section>
                  </div>
                </>
              )}
            </section>
          </div>
        </div>
      </main>
    </div>
  );
}