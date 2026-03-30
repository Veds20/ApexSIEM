import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

const API = "http://localhost:8001";

export default function AnalyzeModal({ alert, onClose }) {
    const [report, setReport] = useState(alert.analysis_report || "");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [verdict, setVerdict] = useState(null);
    const [analystName, setAnalystName] = useState("");
    const [investigateReason, setInvestigateReason] = useState("");
    const [showInvestigateForm, setShowInvestigateForm] = useState(false);
    const [investigated, setInvestigated] = useState(!!alert.investigation_status);
    const [investStatus, setInvestStatus] = useState(alert.investigation_status || "");
    const [investLoading, setInvestLoading] = useState(false);
    const [investError, setInvestError] = useState("");

    const sevColor = { HIGH: "#ff4d4d", MEDIUM: "#ffd700", LOW: "#00e5cc" }[alert.severity] || "#aaa";

    const runAnalysis = async () => {
        setLoading(true);
        setError("");
        try {
            const token = localStorage.getItem("token");
            const res = await fetch(`${API}/analyze/${alert.id}`, {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || "Analysis failed");
            }
            const data = await res.json();
            setReport(data.report);
        } catch (e) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    const submitInvestigation = async (status) => {
        if (!analystName.trim()) {
            setInvestError("Analyst name is required.");
            return;
        }
        if (!investigateReason.trim()) {
            setInvestError("Please provide investigation notes.");
            return;
        }
        setInvestLoading(true);
        setInvestError("");
        try {
            const token = localStorage.getItem("token");
            const params = new URLSearchParams({
                analyst: analystName.trim(),
                status: status,
                reason: investigateReason.trim(),
            });
            const res = await fetch(`${API}/investigate/${alert.id}?${params}`, {
                method: "POST",
                headers: { Authorization: `Bearer ${token}` },
            });
            if (!res.ok) throw new Error("Investigation failed");
            setInvestigated(true);
            setInvestStatus(status);
            setShowInvestigateForm(false);
        } catch (e) {
            setInvestError(e.message);
        } finally {
            setInvestLoading(false);
        }
    };

    return (
        <AnimatePresence>
            <motion.div
                initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                onClick={onClose}
                style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.82)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000, padding: "20px" }}
            >
                <motion.div
                    initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
                    onClick={e => e.stopPropagation()}
                    style={{ background: "#0a1628", border: "1px solid #1a2a4a", borderRadius: "8px", padding: "28px", width: "100%", maxWidth: "780px", maxHeight: "92vh", overflowY: "auto", fontFamily: "'JetBrains Mono', monospace", color: "#e0e0e0" }}
                >
                    {/* Header */}
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
                        <div>
                            <div style={{ color: "#00e5cc", fontSize: "11px", letterSpacing: "2px", marginBottom: "6px" }}>THREAT ANALYSIS — ALERT #{alert.id}</div>
                            <div style={{ fontSize: "18px", fontWeight: 700, color: "#fff" }}>{alert.attack_type?.replace(/_/g, " ").toUpperCase()}</div>
                        </div>
                        <button onClick={onClose} style={{ background: "transparent", border: "1px solid #1a2a4a", color: "#aaa", cursor: "pointer", padding: "6px 12px", fontFamily: "inherit", borderRadius: "4px" }}>✕ CLOSE</button>
                    </div>

                    {/* Fields grid */}
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", marginBottom: "20px" }}>
                        {[
                            ["SOURCE IP", alert.source_ip],
                            ["DESTINATION", alert.destination_ip || "N/A"],
                            ["SEVERITY", alert.severity, sevColor],
                            ["TRUST SCORE", `${alert.trust_score}/100`],
                            ["LOG SOURCE", alert.log_source || "N/A"],
                            ["EVENT TYPE", alert.event_type || "N/A"],
                            ["ANOMALY", alert.is_anomaly ? "YES (ML flagged)" : "No", alert.is_anomaly ? "#ffd700" : null],
                            ["TIMESTAMP", new Date(alert.timestamp).toLocaleString()],
                        ].map(([label, value, color]) => (
                            <div key={label} style={{ background: "#060e1c", border: "1px solid #1a2a4a", borderRadius: "6px", padding: "10px 14px" }}>
                                <div style={{ fontSize: "10px", color: "#4a6a8a", letterSpacing: "1px", marginBottom: "4px" }}>{label}</div>
                                <div style={{ fontSize: "13px", color: color || "#00e5cc", fontWeight: 600 }}>{value}</div>
                            </div>
                        ))}
                    </div>

                    {/* Description */}
                    {alert.description && (
                        <div style={{ background: "#060e1c", border: "1px solid #1a3a2a", borderRadius: "6px", padding: "14px", marginBottom: "16px" }}>
                            <div style={{ fontSize: "10px", color: "#00e5cc", letterSpacing: "1px", marginBottom: "8px" }}>EVENT DESCRIPTION (from real log fields)</div>
                            <div style={{ fontSize: "13px", color: "#c0d8c0", lineHeight: 1.6 }}>{alert.description}</div>
                        </div>
                    )}

                    {/* ── AI Analysis ── */}
                    <div style={{ marginTop: "20px" }}>
                        <div style={{ fontSize: "10px", color: "#00e5cc", letterSpacing: "2px", marginBottom: "12px" }}>AI THREAT ANALYSIS</div>

                        {!report && !loading && (
                            <div style={{ background: "#060e1c", border: "1px dashed #1a3a5a", borderRadius: "6px", padding: "20px", textAlign: "center", color: "#4a6a8a", fontSize: "13px", marginBottom: "16px" }}>
                                Click "Run Analysis" to have Claude analyze this real alert using its actual log fields.
                            </div>
                        )}

                        {loading && (
                            <div style={{ background: "#060e1c", border: "1px solid #1a3a5a", borderRadius: "6px", padding: "20px", color: "#00e5cc", fontSize: "13px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px" }}>
                                <motion.span animate={{ opacity: [1, 0.3, 1] }} transition={{ repeat: Infinity, duration: 1.2 }}>⬡</motion.span>
                                Analyzing real log context…
                            </div>
                        )}

                        {error && (
                            <div style={{ background: "#1a0a0a", border: "1px solid #ff4d4d", borderRadius: "6px", padding: "14px", marginBottom: "16px", color: "#ff4d4d", fontSize: "13px" }}>
                                ⚠ {error}
                            </div>
                        )}

                        {report && (
                            <div style={{ background: "#060e1c", border: "1px solid #1a3a5a", borderRadius: "6px", padding: "18px", marginBottom: "16px" }}>
                                <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word", fontSize: "13px", color: "#c0d8f0", lineHeight: 1.7, fontFamily: "'JetBrains Mono', monospace" }}>
                                    {report}
                                </pre>
                            </div>
                        )}

                        {/* Run analysis + verdict buttons */}
                        <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap", marginBottom: "20px" }}>
                            <button onClick={runAnalysis} disabled={loading}
                                style={{ background: loading ? "#1a2a4a" : "#00e5cc", color: loading ? "#4a6a8a" : "#060e1c", border: "none", borderRadius: "4px", padding: "10px 24px", fontFamily: "inherit", fontSize: "12px", fontWeight: 700, cursor: loading ? "not-allowed" : "pointer", letterSpacing: "1px" }}>
                                {loading ? "ANALYZING…" : report ? "RE-ANALYZE" : "RUN ANALYSIS"}
                            </button>

                            {report && !verdict && (
                                <>
                                    <button onClick={() => setVerdict("tp")}
                                        style={{ background: "#ff4d4d22", border: "1px solid #ff4d4d", color: "#ff4d4d", borderRadius: "4px", padding: "10px 20px", fontFamily: "inherit", fontSize: "12px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                        ✓ TRUE POSITIVE
                                    </button>
                                    <button onClick={() => setVerdict("fp")}
                                        style={{ background: "#4ade8022", border: "1px solid #4ade80", color: "#4ade80", borderRadius: "4px", padding: "10px 20px", fontFamily: "inherit", fontSize: "12px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                        ✗ FALSE POSITIVE
                                    </button>
                                </>
                            )}

                            {verdict === "tp" && <div style={{ background: "#ff4d4d22", border: "1px solid #ff4d4d", borderRadius: "4px", padding: "10px 20px", color: "#ff4d4d", fontSize: "12px", fontWeight: 700 }}>✓ MARKED AS TRUE POSITIVE</div>}
                            {verdict === "fp" && <div style={{ background: "#4ade8022", border: "1px solid #4ade80", borderRadius: "4px", padding: "10px 20px", color: "#4ade80", fontSize: "12px", fontWeight: 700 }}>✗ MARKED AS FALSE POSITIVE</div>}
                        </div>
                    </div>

                    {/* ── Investigation Section ── */}
                    <div style={{ borderTop: "1px solid #1a2a4a", paddingTop: "20px", marginTop: "4px" }}>
                        <div style={{ fontSize: "10px", color: "#00e5cc", letterSpacing: "2px", marginBottom: "14px" }}>INVESTIGATION</div>

                        {investigated ? (
                            <div style={{ background: "#060e1c", border: `1px solid ${investStatus === "Investigated" ? "#00e5cc" : investStatus === "Under Progress" ? "#ffd700" : "#4ade80"}`, borderRadius: "6px", padding: "16px" }}>
                                <div style={{ fontSize: "11px", color: "#4a6a8a", marginBottom: "6px" }}>STATUS</div>
                                <div style={{ fontSize: "14px", fontWeight: 700, color: investStatus === "Investigated" ? "#00e5cc" : investStatus === "Under Progress" ? "#ffd700" : "#4ade80", marginBottom: "10px" }}>
                                    {investStatus === "Investigated" ? "✓ INVESTIGATED" : investStatus === "Under Progress" ? "⟳ UNDER PROGRESS" : "✗ CLOSED"}
                                </div>
                                <div style={{ fontSize: "11px", color: "#4a6a8a" }}>Assigned to: <span style={{ color: "#00e5cc" }}>{alert.assigned_to || analystName}</span></div>
                                <div style={{ fontSize: "11px", color: "#4a6a8a", marginTop: "4px" }}>This alert has been removed from the main dashboard and priority panel.</div>
                            </div>
                        ) : (
                            <>
                                {!showInvestigateForm ? (
                                    <button onClick={() => setShowInvestigateForm(true)}
                                        style={{ background: "#1a2a4a", border: "1px solid #00e5cc44", color: "#00e5cc", borderRadius: "4px", padding: "10px 20px", fontFamily: "inherit", fontSize: "12px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                        + OPEN INVESTIGATION
                                    </button>
                                ) : (
                                    <div style={{ background: "#060e1c", border: "1px solid #1a3a5a", borderRadius: "6px", padding: "18px" }}>

                                        {/* Analyst name — REQUIRED */}
                                        <div style={{ marginBottom: "14px" }}>
                                            <div style={{ fontSize: "10px", color: "#4a6a8a", letterSpacing: "1px", marginBottom: "6px" }}>
                                                ANALYST NAME <span style={{ color: "#ff4d4d" }}>*</span>
                                            </div>
                                            <input
                                                value={analystName}
                                                onChange={e => setAnalystName(e.target.value)}
                                                placeholder="Enter your name to proceed..."
                                                style={{ width: "100%", background: "#0a1628", border: `1px solid ${analystName.trim() ? "#00e5cc44" : "#ff4d4d44"}`, borderRadius: "4px", padding: "10px 12px", color: "#e0e0e0", fontFamily: "inherit", fontSize: "12px", boxSizing: "border-box", outline: "none" }}
                                            />
                                            {!analystName.trim() && <div style={{ fontSize: "10px", color: "#ff4d4d", marginTop: "4px" }}>Analyst name is required to investigate</div>}
                                        </div>

                                        {/* Investigation notes */}
                                        <div style={{ marginBottom: "14px" }}>
                                            <div style={{ fontSize: "10px", color: "#4a6a8a", letterSpacing: "1px", marginBottom: "6px" }}>
                                                INVESTIGATION NOTES <span style={{ color: "#ff4d4d" }}>*</span>
                                            </div>
                                            <textarea
                                                value={investigateReason}
                                                onChange={e => setInvestigateReason(e.target.value)}
                                                placeholder="Describe findings, actions taken, or reason for closing..."
                                                rows={3}
                                                style={{ width: "100%", background: "#0a1628", border: "1px solid #1a3a5a", borderRadius: "4px", padding: "10px 12px", color: "#e0e0e0", fontFamily: "inherit", fontSize: "12px", resize: "vertical", boxSizing: "border-box", outline: "none" }}
                                            />
                                        </div>

                                        {investError && (
                                            <div style={{ color: "#ff4d4d", fontSize: "12px", marginBottom: "12px" }}>⚠ {investError}</div>
                                        )}

                                        {/* Status buttons */}
                                        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                                            <button onClick={() => submitInvestigation("Under Progress")} disabled={investLoading}
                                                style={{ background: "#ffd70022", border: "1px solid #ffd700", color: "#ffd700", borderRadius: "4px", padding: "10px 18px", fontFamily: "inherit", fontSize: "11px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                                ⟳ MARK UNDER PROGRESS
                                            </button>
                                            <button onClick={() => submitInvestigation("Investigated")} disabled={investLoading}
                                                style={{ background: "#00e5cc22", border: "1px solid #00e5cc", color: "#00e5cc", borderRadius: "4px", padding: "10px 18px", fontFamily: "inherit", fontSize: "11px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                                ✓ MARK INVESTIGATED
                                            </button>
                                            <button onClick={() => submitInvestigation("Closed")} disabled={investLoading}
                                                style={{ background: "#4ade8022", border: "1px solid #4ade80", color: "#4ade80", borderRadius: "4px", padding: "10px 18px", fontFamily: "inherit", fontSize: "11px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                                ✗ CLOSE ALERT
                                            </button>
                                            <button onClick={() => { setShowInvestigateForm(false); setInvestError(""); }}
                                                style={{ background: "transparent", border: "1px solid #1a2a4a", color: "#4a6a8a", borderRadius: "4px", padding: "10px 18px", fontFamily: "inherit", fontSize: "11px", cursor: "pointer" }}>
                                                CANCEL
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </>
                        )}
                    </div>
                </motion.div>
            </motion.div>
        </AnimatePresence>
    );
}