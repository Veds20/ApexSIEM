import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";

const API = "http://localhost:8001";

const STATUS_CONFIG = {
    "Investigated": { color: "#00e5cc", icon: "✓", label: "INVESTIGATED" },
    "Under Progress": { color: "#ffd700", icon: "⟳", label: "UNDER PROGRESS" },
    "Closed": { color: "#4ade80", icon: "✗", label: "CLOSED" },
};

export default function Investigations() {
    const [investigations, setInvestigations] = useState([]);
    const [filter, setFilter] = useState("ALL");

    const fetchInvestigations = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${API}/investigations`, { headers: { Authorization: `Bearer ${token}` } });
            const data = await res.json();
            setInvestigations(data);
        } catch (e) {
            console.error(e);
        }
    };

    useEffect(() => {
        fetchInvestigations();
        const interval = setInterval(fetchInvestigations, 5000);
        return () => clearInterval(interval);
    }, []);

    const filtered = filter === "ALL" ? investigations : investigations.filter(i => i.investigation_status === filter);

    const counts = {
        total: investigations.length,
        investigated: investigations.filter(i => i.investigation_status === "Investigated").length,
        progress: investigations.filter(i => i.investigation_status === "Under Progress").length,
        closed: investigations.filter(i => i.investigation_status === "Closed").length,
    };

    const SEV_COLOR = { HIGH: "#ff4d4d", MEDIUM: "#ffd700", LOW: "#00e5cc" };

    return (
        <div style={{ background: "#060e1c", minHeight: "100vh", color: "#e0e0e0", fontFamily: "'JetBrains Mono', monospace" }}>
            <Navbar />
            <div style={{ padding: "20px 28px" }}>

                {/* Header */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
                    <div>
                        <div style={{ fontSize: "14px", letterSpacing: "3px", color: "#00e5cc", fontWeight: 700 }}>INVESTIGATIONS</div>
                        <div style={{ fontSize: "11px", color: "#4a6a8a", marginTop: "4px" }}>Alerts under analyst review — removed from main dashboard</div>
                    </div>
                    <div style={{ display: "flex", gap: "10px" }}>
                        {[
                            { label: "TOTAL", value: counts.total, color: "#00e5cc" },
                            { label: "INVESTIGATED", value: counts.investigated, color: "#00e5cc" },
                            { label: "IN PROGRESS", value: counts.progress, color: "#ffd700" },
                            { label: "CLOSED", value: counts.closed, color: "#4ade80" },
                        ].map(({ label, value, color }) => (
                            <div key={label} style={{ background: "#0a1628", border: `1px solid ${color}44`, borderRadius: "6px", padding: "8px 14px", textAlign: "center" }}>
                                <div style={{ fontSize: "16px", fontWeight: 700, color }}>{value}</div>
                                <div style={{ fontSize: "9px", color: "#4a6a8a", letterSpacing: "1px" }}>{label}</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Filter tabs */}
                <div style={{ display: "flex", gap: "8px", marginBottom: "20px" }}>
                    {["ALL", "Under Progress", "Investigated", "Closed"].map(f => (
                        <button key={f} onClick={() => setFilter(f)}
                            style={{ background: filter === f ? "#00e5cc22" : "transparent", border: `1px solid ${filter === f ? "#00e5cc" : "#1a2a4a"}`, color: filter === f ? "#00e5cc" : "#4a6a8a", padding: "6px 16px", fontSize: "10px", fontFamily: "inherit", cursor: "pointer", borderRadius: "4px", letterSpacing: "1px" }}>
                            {f === "ALL" ? "ALL" : STATUS_CONFIG[f]?.label || f}
                        </button>
                    ))}
                </div>

                {/* Empty state */}
                {filtered.length === 0 && (
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
                        style={{ background: "#0a1628", border: "1px solid #1a2a4a", borderRadius: "8px", padding: "48px", textAlign: "center", color: "#4a6a8a" }}>
                        <div style={{ fontSize: "32px", marginBottom: "12px" }}>🔍</div>
                        <div style={{ fontSize: "13px" }}>No investigations found. Open an alert and click "Open Investigation" to start.</div>
                    </motion.div>
                )}

                {/* Investigation cards */}
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                    {filtered.map((inv, i) => {
                        const cfg = STATUS_CONFIG[inv.investigation_status] || { color: "#4a6a8a", icon: "?", label: inv.investigation_status };
                        return (
                            <motion.div key={inv.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                                style={{ background: "#0a1628", border: `1px solid ${cfg.color}33`, borderLeft: `3px solid ${cfg.color}`, borderRadius: "8px", padding: "18px 20px" }}>

                                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "10px" }}>
                                    {/* Left info */}
                                    <div>
                                        <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
                                            <span style={{ color: "#4a6a8a", fontSize: "11px" }}>#{inv.id}</span>
                                            <span style={{ background: `${SEV_COLOR[inv.severity]}22`, border: `1px solid ${SEV_COLOR[inv.severity]}44`, color: SEV_COLOR[inv.severity], fontSize: "10px", padding: "2px 8px", borderRadius: "4px" }}>{inv.severity}</span>
                                            <span style={{ background: "#1a2a4a", color: "#c0d8f0", fontSize: "11px", padding: "2px 8px", borderRadius: "4px" }}>{inv.attack_type}</span>
                                        </div>
                                        <div style={{ fontSize: "15px", color: "#00e5cc", fontWeight: 700, marginBottom: "4px" }}>{inv.source_ip}</div>
                                        <div style={{ fontSize: "11px", color: "#8a9aaa", marginBottom: "6px" }}>{inv.event_type || inv.log_source}</div>
                                        {inv.description && (
                                            <div style={{ fontSize: "11px", color: "#607080", maxWidth: "500px", lineHeight: 1.5 }}>{inv.description}</div>
                                        )}
                                    </div>

                                    {/* Right status */}
                                    <div style={{ textAlign: "right", minWidth: "200px" }}>
                                        <div style={{ background: `${cfg.color}22`, border: `1px solid ${cfg.color}44`, borderRadius: "6px", padding: "10px 16px", marginBottom: "8px", display: "inline-block" }}>
                                            <div style={{ fontSize: "11px", color: "#4a6a8a", marginBottom: "4px" }}>STATUS</div>
                                            <div style={{ fontSize: "13px", color: cfg.color, fontWeight: 700 }}>{cfg.icon} {cfg.label}</div>
                                        </div>
                                        <div style={{ fontSize: "11px", color: "#4a6a8a" }}>
                                            Analyst: <span style={{ color: "#00e5cc" }}>{inv.assigned_to || "—"}</span>
                                        </div>
                                        <div style={{ fontSize: "10px", color: "#4a6a8a", marginTop: "4px" }}>
                                            {inv.investigated_at ? new Date(inv.investigated_at).toLocaleString() : ""}
                                        </div>
                                    </div>
                                </div>

                                {/* Investigation notes */}
                                {inv.investigation_reason && (
                                    <div style={{ marginTop: "14px", background: "#060e1c", border: "1px solid #1a2a4a", borderRadius: "6px", padding: "12px" }}>
                                        <div style={{ fontSize: "10px", color: "#4a6a8a", letterSpacing: "1px", marginBottom: "6px" }}>ANALYST NOTES</div>
                                        <div style={{ fontSize: "12px", color: "#8a9aaa", lineHeight: 1.6 }}>{inv.investigation_reason}</div>
                                    </div>
                                )}

                                {/* AI report if available */}
                                {inv.analysis_report && (
                                    <details style={{ marginTop: "10px" }}>
                                        <summary style={{ fontSize: "10px", color: "#00e5cc", cursor: "pointer", letterSpacing: "1px" }}>VIEW AI ANALYSIS REPORT</summary>
                                        <pre style={{ marginTop: "10px", background: "#060e1c", border: "1px solid #1a3a5a", borderRadius: "6px", padding: "14px", fontSize: "11px", color: "#c0d8f0", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.6, fontFamily: "inherit" }}>
                                            {inv.analysis_report}
                                        </pre>
                                    </details>
                                )}
                            </motion.div>
                        );
                    })}
                </div>
            </div>
        </div>
    );
}