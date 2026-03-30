import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import Navbar from "../components/Navbar";
import AnalyzeModal from "../components/AnalyzeModal";

const API = "http://localhost:8001";

export default function Priority() {
    const [alerts, setAlerts] = useState([]);
    const [selected, setSelected] = useState(null);
    const [loading, setLoading] = useState(true);

    const fetchPriority = async () => {
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${API}/priority`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            const data = await res.json();
            setAlerts(data);
        } catch (e) {
            console.error("Priority fetch error:", e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPriority();
        const interval = setInterval(fetchPriority, 5000);
        return () => clearInterval(interval);
    }, []);

    const critical = alerts.filter(a => a.severity === "HIGH").length;
    const anomalies = alerts.filter(a => a.is_anomaly).length;

    // Group by attack type for visual diversity
    const byType = alerts.reduce((acc, a) => {
        if (!acc[a.attack_type]) acc[a.attack_type] = [];
        acc[a.attack_type].push(a);
        return acc;
    }, {});

    const SEV_COLOR = { HIGH: "#ff4d4d", MEDIUM: "#ffd700", LOW: "#00e5cc" };

    const ATTACK_TYPE_COLORS = {
        brute_force: "#ff4d4d",
        brute_force_ssh: "#ff6b4d",
        brute_force_rdp: "#ff3d3d",
        malware: "#c084fc",
        port_scan: "#ffd700",
        privilege_escalation: "#f97316",
        log_cleared: "#ff0000",
        audit_policy_changed: "#ff6600",
        new_user_created: "#ff9900",
        scheduled_task_created: "#ffcc00",
        kerberos_brute_force: "#ff4d88",
        network_intrusion: "#4ade80",
        powershell_suspicious: "#a78bfa",
        lateral_movement: "#fb923c",
        account_lockout: "#fbbf24",
        default: "#00e5cc",
    };

    return (
        <div style={{ background: "#060e1c", minHeight: "100vh", color: "#e0e0e0", fontFamily: "'JetBrains Mono', monospace" }}>
            <Navbar />

            <div style={{ padding: "20px 28px" }}>
                {/* Header */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px" }}>
                    <div>
                        <div style={{ fontSize: "14px", letterSpacing: "3px", color: "#00e5cc", fontWeight: 700 }}>
                            PRIORITY ALERT QUEUE
                        </div>
                        <div style={{ fontSize: "11px", color: "#4a6a8a", marginTop: "4px" }}>
                            High-severity and ML-flagged anomalous events from real log sources
                        </div>
                    </div>
                    <div style={{ display: "flex", gap: "12px" }}>
                        {[
                            { label: "CRITICAL", value: critical, color: "#ff4d4d" },
                            { label: "ANOMALIES", value: anomalies, color: "#7c3aed" },
                            { label: "TOTAL", value: alerts.length, color: "#00e5cc" },
                        ].map(({ label, value, color }) => (
                            <div key={label} style={{
                                background: "#0a1628", border: `1px solid ${color}44`,
                                borderRadius: "6px", padding: "8px 16px",
                                display: "flex", alignItems: "center", gap: "8px",
                            }}>
                                <span style={{ width: 8, height: 8, borderRadius: "50%", background: color, display: "inline-block" }} />
                                <span style={{ color, fontSize: "12px", fontWeight: 700 }}>{value} {label}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* No data state */}
                {!loading && alerts.length === 0 && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        style={{
                            background: "#0a1628",
                            border: "1px solid #ffd70033",
                            borderRadius: "8px",
                            padding: "40px",
                            textAlign: "center",
                            color: "#4a6a8a",
                        }}
                    >
                        <div style={{ fontSize: "32px", marginBottom: "16px" }}>⚠</div>
                        <div style={{ fontSize: "14px", color: "#ffd700", marginBottom: "8px" }}>
                            NO PRIORITY ALERTS
                        </div>
                        <div style={{ fontSize: "12px", lineHeight: 1.8 }}>
                            No high-severity or ML-anomalous events from real log sources.
                            <br />
                            Priority alerts appear when real logs trigger:
                            <br />
                            brute force attacks · privilege escalation · log clearing · malware · account lockouts
                        </div>
                    </motion.div>
                )}

                {/* Attack type sections */}
                {Object.entries(byType).map(([attackType, typeAlerts]) => {
                    const typeColor = ATTACK_TYPE_COLORS[attackType] || ATTACK_TYPE_COLORS.default;
                    return (
                        <div key={attackType} style={{ marginBottom: "24px" }}>
                            <div style={{
                                fontSize: "10px", letterSpacing: "2px",
                                color: typeColor, marginBottom: "10px",
                                display: "flex", alignItems: "center", gap: "8px",
                            }}>
                                <span style={{ width: 8, height: 8, borderRadius: "50%", background: typeColor, display: "inline-block" }} />
                                {attackType.replace(/_/g, " ").toUpperCase()} ({typeAlerts.length})
                            </div>

                            <div style={{
                                display: "grid",
                                gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
                                gap: "12px",
                            }}>
                                {typeAlerts.map((alert, i) => (
                                    <motion.div
                                        key={alert.id}
                                        initial={{ opacity: 0, y: 10 }}
                                        animate={{ opacity: 1, y: 0 }}
                                        transition={{ delay: i * 0.05 }}
                                        style={{
                                            background: "#0a1628",
                                            border: `1px solid ${typeColor}33`,
                                            borderLeft: `3px solid ${typeColor}`,
                                            borderRadius: "6px",
                                            padding: "14px",
                                        }}
                                    >
                                        {/* Card header */}
                                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
                                            <span style={{ color: "#4a6a8a", fontSize: "11px" }}>#{alert.id}</span>
                                            <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                                                {alert.is_anomaly && (
                                                    <span style={{ background: "#7c3aed22", border: "1px solid #7c3aed44", color: "#a78bfa", fontSize: "9px", padding: "2px 6px", borderRadius: "3px" }}>
                                                        ML ANOMALY
                                                    </span>
                                                )}
                                                <span style={{
                                                    background: `${SEV_COLOR[alert.severity]}22`,
                                                    border: `1px solid ${SEV_COLOR[alert.severity]}44`,
                                                    color: SEV_COLOR[alert.severity],
                                                    fontSize: "10px", padding: "2px 8px", borderRadius: "4px",
                                                }}>
                                                    {alert.severity}
                                                </span>
                                            </div>
                                        </div>

                                        {/* Source IP */}
                                        <div style={{ color: typeColor, fontSize: "16px", fontWeight: 700, marginBottom: "6px" }}>
                                            {alert.source_ip}
                                        </div>

                                        {/* Log source */}
                                        <div style={{ marginBottom: "8px" }}>
                                            <span style={{
                                                background: "#1a2a4a", borderRadius: "4px",
                                                padding: "3px 8px", color: "#c0d8f0", fontSize: "11px",
                                            }}>
                                                {alert.attack_type}
                                            </span>
                                            {alert.log_source && (
                                                <span style={{
                                                    background: "#1a1a2a", borderRadius: "4px",
                                                    padding: "3px 8px", color: "#7a8aaa", fontSize: "10px",
                                                    marginLeft: "6px",
                                                }}>
                                                    {alert.log_source}
                                                </span>
                                            )}
                                        </div>

                                        {/* Real description */}
                                        {alert.description && (
                                            <div style={{
                                                fontSize: "11px", color: "#8a9aaa",
                                                marginBottom: "10px", lineHeight: 1.5,
                                                maxHeight: "48px", overflow: "hidden",
                                            }}>
                                                {alert.description}
                                            </div>
                                        )}

                                        {/* Footer */}
                                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                            <span style={{ fontSize: "10px", color: "#4a6a8a" }}>
                                                Trust: <span style={{ color: typeColor }}>{alert.trust_score}</span>
                                                &nbsp;·&nbsp;
                                                {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : ""}
                                            </span>
                                            <button
                                                onClick={() => setSelected(alert)}
                                                style={{
                                                    background: `${typeColor}22`,
                                                    border: `1px solid ${typeColor}44`,
                                                    color: typeColor,
                                                    padding: "4px 10px",
                                                    fontFamily: "inherit", fontSize: "9px",
                                                    cursor: "pointer", borderRadius: "4px",
                                                    letterSpacing: "1px",
                                                }}
                                            >
                                                ANALYZE
                                            </button>
                                        </div>
                                    </motion.div>
                                ))}
                            </div>
                        </div>
                    );
                })}
            </div>

            {selected && <AnalyzeModal alert={selected} onClose={() => setSelected(null)} />}
        </div>
    );
}