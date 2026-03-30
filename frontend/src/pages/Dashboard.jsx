import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
    AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
    XAxis, YAxis, Tooltip, ResponsiveContainer,
} from "recharts";
import Navbar from "../components/Navbar";
import AnalyzeModal from "../components/AnalyzeModal";

const API = "http://localhost:8001";
const COLORS = ["#00e5cc", "#7c3aed", "#ff4d4d", "#ffd700", "#4ade80", "#f97316"];

const SEV_COLOR = { HIGH: "#ff4d4d", MEDIUM: "#ffd700", LOW: "#00e5cc" };

export default function Dashboard() {
    const [alerts, setAlerts] = useState([]);
    const [stats, setStats] = useState({});
    const [filter, setFilter] = useState("ALL");
    const [selected, setSelected] = useState(null);
    const [lastSync, setLastSync] = useState("");
    const [noData, setNoData] = useState(false);

    const fetchData = async () => {
        try {
            const token = localStorage.getItem("token");
            const headers = { Authorization: `Bearer ${token}` };

            const [aRes, sRes] = await Promise.all([
                fetch(`${API}/alerts`, { headers }),
                fetch(`${API}/stats`, { headers }),
            ]);
            const [aData, sData] = await Promise.all([aRes.json(), sRes.json()]);

            setAlerts(aData);
            setStats(sData);
            setNoData(sData.no_data === true || sData.total === 0);
            setLastSync(new Date().toLocaleTimeString());
        } catch (e) {
            console.error("Fetch error:", e);
        }
    };

    useEffect(() => {
        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, []);

    // Severity distribution
    const sevData = [
        { name: "HIGH", count: stats.high || 0 },
        { name: "MED", count: stats.medium || 0 },
        { name: "LOW", count: stats.low || 0 },
    ];
    const sevColors = ["#ff4d4d", "#ffd700", "#00e5cc"];

    // Attack type distribution (real types from actual logs)
    const attackCounts = alerts.reduce((acc, a) => {
        acc[a.attack_type] = (acc[a.attack_type] || 0) + 1;
        return acc;
    }, {});
    const pieData = Object.entries(attackCounts)
        .map(([name, value]) => ({ name, value }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 8);

    // Timeline — alerts per minute bucket
    const timelineData = (() => {
        const buckets = {};
        alerts.forEach(a => {
            if (!a.timestamp) return;
            const d = new Date(a.timestamp);
            const key = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
            buckets[key] = (buckets[key] || 0) + 1;
        });
        return Object.entries(buckets)
            .map(([time, count]) => ({ time, count }))
            .slice(-15);
    })();

    const filtered = filter === "ALL" ? alerts : alerts.filter(a => a.severity === filter);

    const statCards = [
        { label: "TOTAL ALERTS", value: stats.total || 0, color: "#00e5cc" },
        { label: "CRITICAL", value: stats.high || 0, color: "#ff4d4d" },
        { label: "MEDIUM", value: stats.medium || 0, color: "#ffd700" },
        { label: "LOW RISK", value: stats.low || 0, color: "#4ade80" },
        { label: "PRIORITY", value: stats.priority || 0, color: "#c084fc" },
        { label: "ANOMALIES", value: stats.anomalies || 0, color: "#7c3aed" },
    ];

    return (
        <div style={{ background: "#060e1c", minHeight: "100vh", color: "#e0e0e0", fontFamily: "'JetBrains Mono', monospace" }}>
            <Navbar />

            <div style={{ padding: "20px 28px" }}>
                {/* Header */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                        <div style={{ width: "4px", height: "20px", background: "#00e5cc" }} />
                        <span style={{ fontSize: "13px", letterSpacing: "3px", color: "#aaa" }}>
                            SECURITY OPERATIONS CENTER
                        </span>
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px", fontSize: "11px", color: "#4a8a6a" }}>
                        <span style={{
                            width: "8px", height: "8px", borderRadius: "50%",
                            background: noData ? "#ffd700" : "#00e5cc",
                            display: "inline-block",
                            boxShadow: noData ? "0 0 6px #ffd700" : "0 0 6px #00e5cc",
                        }} />
                        {noData ? "WAITING FOR REAL LOGS" : "LIVE"} &nbsp;|&nbsp; Last sync {lastSync}
                    </div>
                </div>

                {/* No data banner */}
                {noData && (
                    <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        style={{
                            background: "#0a1628",
                            border: "1px solid #ffd70044",
                            borderRadius: "8px",
                            padding: "18px 24px",
                            marginBottom: "20px",
                            color: "#ffd700",
                            fontSize: "13px",
                            lineHeight: 1.8,
                        }}
                    >
                        <div style={{ fontWeight: 700, marginBottom: "6px" }}>⚠ NO DATA AVAILABLE</div>
                        <div style={{ color: "#8a8a6a", fontSize: "12px" }}>
                            No real log sources detected. This SIEM does not generate simulated data.
                            <br />
                            Real log sources monitored: Windows Event Log (Security/System/PowerShell),
                            /var/log/auth.log, /var/log/syslog, UFW, iptables, Nginx, Zeek, Suricata.
                            <br />
                            Start generating real activity (e.g. failed SSH/RDP logins) for alerts to appear.
                        </div>
                    </motion.div>
                )}

                {/* Stat cards */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: "14px", marginBottom: "20px" }}>
                    {statCards.map(({ label, value, color }) => (
                        <motion.div
                            key={label}
                            initial={{ opacity: 0, y: 10 }}
                            animate={{ opacity: 1, y: 0 }}
                            style={{
                                background: "#0a1628",
                                border: `1px solid ${color}33`,
                                borderBottom: `2px solid ${color}`,
                                borderRadius: "6px",
                                padding: "16px",
                            }}
                        >
                            <div style={{ fontSize: "26px", fontWeight: 700, color }}>{value}</div>
                            <div style={{ fontSize: "9px", color: "#4a6a8a", letterSpacing: "1.5px", marginTop: "4px" }}>{label}</div>
                        </motion.div>
                    ))}
                </div>

                {/* Charts row */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "14px", marginBottom: "20px" }}>
                    {/* Severity bar chart */}
                    <div style={{ background: "#0a1628", border: "1px solid #1a2a4a", borderRadius: "8px", padding: "16px" }}>
                        <div style={{ fontSize: "10px", color: "#4a6a8a", letterSpacing: "2px", marginBottom: "12px" }}>
                            SEVERITY DISTRIBUTION
                        </div>
                        <ResponsiveContainer width="100%" height={160}>
                            <BarChart data={sevData}>
                                <XAxis dataKey="name" tick={{ fill: "#4a6a8a", fontSize: 10 }} />
                                <YAxis tick={{ fill: "#4a6a8a", fontSize: 10 }} />
                                <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid #1a2a4a", fontFamily: "inherit" }} />
                                <Bar dataKey="count">
                                    {sevData.map((_, i) => <Cell key={i} fill={sevColors[i]} />)}
                                </Bar>
                            </BarChart>
                        </ResponsiveContainer>
                    </div>

                    {/* Attack types pie */}
                    <div style={{ background: "#0a1628", border: "1px solid #1a2a4a", borderRadius: "8px", padding: "16px" }}>
                        <div style={{ fontSize: "10px", color: "#4a6a8a", letterSpacing: "2px", marginBottom: "12px" }}>
                            ATTACK TYPES
                        </div>
                        {pieData.length > 0 ? (
                            <>
                                <ResponsiveContainer width="100%" height={140}>
                                    <PieChart>
                                        <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={65}
                                            dataKey="value" nameKey="name">
                                            {pieData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                                        </Pie>
                                        <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid #1a2a4a", fontFamily: "inherit", fontSize: 11 }} />
                                    </PieChart>
                                </ResponsiveContainer>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "8px" }}>
                                    {pieData.map((d, i) => (
                                        <span key={d.name} style={{ fontSize: "10px", color: COLORS[i % COLORS.length], display: "flex", alignItems: "center", gap: "4px" }}>
                                            <span style={{ width: 6, height: 6, borderRadius: "50%", background: COLORS[i % COLORS.length], display: "inline-block" }} />
                                            {d.name}
                                        </span>
                                    ))}
                                </div>
                            </>
                        ) : (
                            <div style={{ height: 160, display: "flex", alignItems: "center", justifyContent: "center", color: "#4a6a8a", fontSize: 12 }}>
                                No data
                            </div>
                        )}
                    </div>

                    {/* Timeline area chart */}
                    <div style={{ background: "#0a1628", border: "1px solid #1a2a4a", borderRadius: "8px", padding: "16px" }}>
                        <div style={{ fontSize: "10px", color: "#4a6a8a", letterSpacing: "2px", marginBottom: "12px" }}>
                            ALERT TIMELINE
                        </div>
                        <ResponsiveContainer width="100%" height={160}>
                            <AreaChart data={timelineData}>
                                <defs>
                                    <linearGradient id="tealGrad" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#00e5cc" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#00e5cc" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <XAxis dataKey="time" tick={{ fill: "#4a6a8a", fontSize: 9 }} />
                                <YAxis tick={{ fill: "#4a6a8a", fontSize: 9 }} />
                                <Tooltip contentStyle={{ background: "#0a1628", border: "1px solid #1a2a4a", fontFamily: "inherit" }} />
                                <Area type="monotone" dataKey="count" stroke="#00e5cc" fill="url(#tealGrad)" strokeWidth={2} />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Live alert feed */}
                <div style={{ background: "#0a1628", border: "1px solid #1a2a4a", borderRadius: "8px", padding: "16px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                        <div style={{ fontSize: "10px", color: "#4a6a8a", letterSpacing: "2px" }}>LIVE ALERT FEED</div>
                        <div style={{ display: "flex", gap: "8px" }}>
                            {["ALL", "HIGH", "MEDIUM", "LOW"].map(f => (
                                <button
                                    key={f}
                                    onClick={() => setFilter(f)}
                                    style={{
                                        background: filter === f ? "#00e5cc22" : "transparent",
                                        border: `1px solid ${filter === f ? "#00e5cc" : "#1a2a4a"}`,
                                        color: filter === f ? "#00e5cc" : "#4a6a8a",
                                        padding: "4px 12px", fontSize: "10px",
                                        fontFamily: "inherit", cursor: "pointer", borderRadius: "4px",
                                        letterSpacing: "1px",
                                    }}
                                >{f}</button>
                            ))}
                        </div>
                    </div>

                    <div style={{ overflowX: "auto" }}>
                        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                            <thead>
                                <tr style={{ color: "#4a6a8a", fontSize: "10px", letterSpacing: "1px" }}>
                                    {["ID", "SOURCE IP", "ATTACK TYPE", "EVENT", "SEVERITY", "ANOMALY", "PRIORITY", "TIMESTAMP", "ACTION"].map(h => (
                                        <th key={h} style={{ textAlign: "left", padding: "8px 10px", borderBottom: "1px solid #1a2a4a", whiteSpace: "nowrap" }}>
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.length === 0 ? (
                                    <tr>
                                        <td colSpan={9} style={{ padding: "32px", textAlign: "center", color: "#4a6a8a" }}>
                                            {noData ? "No real logs ingested yet. Waiting for real events…" : "No alerts match this filter."}
                                        </td>
                                    </tr>
                                ) : filtered.map((alert, i) => (
                                    <motion.tr
                                        key={alert.id}
                                        initial={{ opacity: 0 }}
                                        animate={{ opacity: 1 }}
                                        transition={{ delay: i * 0.02 }}
                                        style={{
                                            borderLeft: alert.priority ? "3px solid #ff4d4d" : "3px solid transparent",
                                            borderBottom: "1px solid #0f1e38",
                                        }}
                                    >
                                        <td style={{ padding: "10px", color: "#4a6a8a" }}>{alert.id}</td>
                                        <td style={{ padding: "10px", color: "#00e5cc" }}>{alert.source_ip}</td>
                                        <td style={{ padding: "10px" }}>
                                            <span style={{
                                                background: "#1a2a4a", borderRadius: "4px",
                                                padding: "3px 8px", color: "#c0d8f0", fontSize: "11px",
                                            }}>
                                                {alert.attack_type}
                                            </span>
                                        </td>
                                        <td style={{ padding: "10px", color: "#8a9aaa", maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                            <span title={alert.description || alert.event_type || ""}>
                                                {alert.event_type || "—"}
                                            </span>
                                        </td>
                                        <td style={{ padding: "10px" }}>
                                            <span style={{
                                                background: `${SEV_COLOR[alert.severity]}22`,
                                                color: SEV_COLOR[alert.severity],
                                                border: `1px solid ${SEV_COLOR[alert.severity]}44`,
                                                borderRadius: "4px", padding: "2px 8px", fontSize: "11px",
                                            }}>
                                                {alert.severity}
                                            </span>
                                        </td>
                                        <td style={{ padding: "10px", color: alert.is_anomaly ? "#ffd700" : "#4a6a8a" }}>
                                            {alert.is_anomaly ? "⚡" : "—"}
                                        </td>
                                        <td style={{ padding: "10px" }}>
                                            {alert.priority ? <span style={{ color: "#ff4d4d", fontSize: "14px" }}>●</span> : "—"}
                                        </td>
                                        <td style={{ padding: "10px", color: "#4a6a8a", whiteSpace: "nowrap" }}>
                                            {alert.timestamp ? new Date(alert.timestamp).toLocaleString() : "—"}
                                        </td>
                                        <td style={{ padding: "10px" }}>
                                            <button
                                                onClick={() => setSelected(alert)}
                                                style={{
                                                    background: "#00e5cc22", border: "1px solid #00e5cc44",
                                                    color: "#00e5cc", padding: "4px 12px",
                                                    fontFamily: "inherit", fontSize: "10px",
                                                    cursor: "pointer", borderRadius: "4px",
                                                    letterSpacing: "1px",
                                                }}
                                            >ANALYZE</button>
                                        </td>
                                    </motion.tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            {selected && <AnalyzeModal alert={selected} onClose={() => setSelected(null)} />}
        </div>
    );
}