import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8001";

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

    const sevColor = { HIGH: "#b84636", MEDIUM: "#a97619", LOW: "#d65a35" }[alert.severity] || "#aaa";

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
                    style={{ background: "#faf9f4", border: "1px solid #d9d8ce", borderRadius: "8px", padding: "28px", width: "100%", maxWidth: "780px", maxHeight: "92vh", overflowY: "auto", fontFamily: "var(--mono)", color: "#282a25" }}
                >
                    {/* Header */}
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
                        <div>
                            <div style={{ color: "#d65a35", fontSize: "11px", letterSpacing: "2px", marginBottom: "6px" }}>THREAT ANALYSIS — ALERT #{alert.id}</div>
                            <div style={{ fontSize: "18px", fontWeight: 700, color: "#282a25" }}>{alert.attack_type?.replace(/_/g, " ").toUpperCase()}</div>
                        </div>
                        <button onClick={onClose} style={{ background: "transparent", border: "1px solid #d9d8ce", color: "#aaa", cursor: "pointer", padding: "6px 12px", fontFamily: "inherit", borderRadius: "4px" }}>✕ CLOSE</button>
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
                            ["ANOMALY", alert.is_anomaly ? "YES (ML flagged)" : "No", alert.is_anomaly ? "#a97619" : null],
                            ["TIMESTAMP", new Date(alert.timestamp).toLocaleString()],
                        ].map(([label, value, color]) => (
                            <div key={label} style={{ background: "#f1f0e9", border: "1px solid #d9d8ce", borderRadius: "6px", padding: "10px 14px" }}>
                                <div style={{ fontSize: "10px", color: "#707168", letterSpacing: "1px", marginBottom: "4px" }}>{label}</div>
                                <div style={{ fontSize: "13px", color: color || "#d65a35", fontWeight: 600 }}>{value}</div>
                            </div>
                        ))}
                    </div>

                    {/* Description */}
                    {alert.description && (
                        <div style={{ background: "#f1f0e9", border: "1px solid #1a3a2a", borderRadius: "6px", padding: "14px", marginBottom: "16px" }}>
                            <div style={{ fontSize: "10px", color: "#d65a35", letterSpacing: "1px", marginBottom: "8px" }}>EVENT DESCRIPTION (from real log fields)</div>
                            <div style={{ fontSize: "13px", color: "#c0d8c0", lineHeight: 1.6 }}>{alert.description}</div>
                        </div>
                    )}

                    {/* ── AI Analysis ── */}
                    <div style={{ marginTop: "20px" }}>
                        <div style={{ fontSize: "10px", color: "#d65a35", letterSpacing: "2px", marginBottom: "12px" }}>AI THREAT ANALYSIS</div>

                        {!report && !loading && (
                            <div style={{ background: "#f1f0e9", border: "1px dashed #d9d8ce", borderRadius: "6px", padding: "20px", textAlign: "center", color: "#707168", fontSize: "13px", marginBottom: "16px" }}>
                                Run the analysis service against this alert's recorded fields and available evidence.
                            </div>
                        )}

                        {loading && (
                            <div style={{ background: "#f1f0e9", border: "1px solid #d9d8ce", borderRadius: "6px", padding: "20px", color: "#d65a35", fontSize: "13px", marginBottom: "16px", display: "flex", alignItems: "center", gap: "10px" }}>
                                <motion.span animate={{ opacity: [1, 0.3, 1] }} transition={{ repeat: Infinity, duration: 1.2 }}>⬡</motion.span>
                                Analyzing real log context…
                            </div>
                        )}

                        {error && (
                            <div style={{ background: "#1a0a0a", border: "1px solid #b84636", borderRadius: "6px", padding: "14px", marginBottom: "16px", color: "#b84636", fontSize: "13px" }}>
                                ⚠ {error}
                            </div>
                        )}

                        {report && (
                            <div style={{ background: "#f1f0e9", border: "1px solid #d9d8ce", borderRadius: "6px", padding: "18px", marginBottom: "16px" }}>
                                <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-word", fontSize: "13px", color: "#42443d", lineHeight: 1.7, fontFamily: "var(--mono)" }}>
                                    {report}
                                </pre>
                            </div>
                        )}

                        {/* Run analysis + verdict buttons */}
                        <div style={{ display: "flex", gap: "10px", alignItems: "center", flexWrap: "wrap", marginBottom: "20px" }}>
                            <button onClick={runAnalysis} disabled={loading}
                                style={{ background: loading ? "#d9d8ce" : "#d65a35", color: loading ? "#707168" : "#f1f0e9", border: "none", borderRadius: "4px", padding: "10px 24px", fontFamily: "inherit", fontSize: "12px", fontWeight: 700, cursor: loading ? "not-allowed" : "pointer", letterSpacing: "1px" }}>
                                {loading ? "ANALYZING…" : report ? "RE-ANALYZE" : "RUN ANALYSIS"}
                            </button>

                            {report && !verdict && (
                                <>
                                    <button onClick={() => setVerdict("tp")}
                                        style={{ background: "#f5e3df", border: "1px solid #b84636", color: "#b84636", borderRadius: "4px", padding: "10px 20px", fontFamily: "inherit", fontSize: "12px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                        ✓ TRUE POSITIVE
                                    </button>
                                    <button onClick={() => setVerdict("fp")}
                                        style={{ background: "#73856b22", border: "1px solid #73856b", color: "#73856b", borderRadius: "4px", padding: "10px 20px", fontFamily: "inherit", fontSize: "12px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                        ✗ FALSE POSITIVE
                                    </button>
                                </>
                            )}

                            {verdict === "tp" && <div style={{ background: "#f5e3df", border: "1px solid #b84636", borderRadius: "4px", padding: "10px 20px", color: "#b84636", fontSize: "12px", fontWeight: 700 }}>✓ MARKED AS TRUE POSITIVE</div>}
                            {verdict === "fp" && <div style={{ background: "#73856b22", border: "1px solid #73856b", borderRadius: "4px", padding: "10px 20px", color: "#73856b", fontSize: "12px", fontWeight: 700 }}>✗ MARKED AS FALSE POSITIVE</div>}
                        </div>
                    </div>

                    {/* ── Investigation Section ── */}
                    <div style={{ borderTop: "1px solid #d9d8ce", paddingTop: "20px", marginTop: "4px" }}>
                        <div style={{ fontSize: "10px", color: "#d65a35", letterSpacing: "2px", marginBottom: "14px" }}>INVESTIGATION</div>

                        {investigated ? (
                            <div style={{ background: "#f1f0e9", border: `1px solid ${investStatus === "Investigated" ? "#d65a35" : investStatus === "Under Progress" ? "#a97619" : "#73856b"}`, borderRadius: "6px", padding: "16px" }}>
                                <div style={{ fontSize: "11px", color: "#707168", marginBottom: "6px" }}>STATUS</div>
                                <div style={{ fontSize: "14px", fontWeight: 700, color: investStatus === "Investigated" ? "#d65a35" : investStatus === "Under Progress" ? "#a97619" : "#73856b", marginBottom: "10px" }}>
                                    {investStatus === "Investigated" ? "✓ INVESTIGATED" : investStatus === "Under Progress" ? "⟳ UNDER PROGRESS" : "✗ CLOSED"}
                                </div>
                                <div style={{ fontSize: "11px", color: "#707168" }}>Assigned to: <span style={{ color: "#d65a35" }}>{alert.assigned_to || analystName}</span></div>
                                <div style={{ fontSize: "11px", color: "#707168", marginTop: "4px" }}>This alert has been removed from the main dashboard and priority panel.</div>
                            </div>
                        ) : (
                            <>
                                {!showInvestigateForm ? (
                                    <button onClick={() => setShowInvestigateForm(true)}
                                        style={{ background: "#d9d8ce", border: "1px solid #e5b8a6", color: "#d65a35", borderRadius: "4px", padding: "10px 20px", fontFamily: "inherit", fontSize: "12px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                        + OPEN INVESTIGATION
                                    </button>
                                ) : (
                                    <div style={{ background: "#f1f0e9", border: "1px solid #d9d8ce", borderRadius: "6px", padding: "18px" }}>

                                        {/* Analyst name — REQUIRED */}
                                        <div style={{ marginBottom: "14px" }}>
                                            <div style={{ fontSize: "10px", color: "#707168", letterSpacing: "1px", marginBottom: "6px" }}>
                                                ANALYST NAME <span style={{ color: "#b84636" }}>*</span>
                                            </div>
                                            <input
                                                value={analystName}
                                                onChange={e => setAnalystName(e.target.value)}
                                                placeholder="Enter your name to proceed..."
                                                style={{ width: "100%", background: "#faf9f4", border: `1px solid ${analystName.trim() ? "#e5b8a6" : "#b8463644"}`, borderRadius: "4px", padding: "10px 12px", color: "#282a25", fontFamily: "inherit", fontSize: "12px", boxSizing: "border-box", outline: "none" }}
                                            />
                                            {!analystName.trim() && <div style={{ fontSize: "10px", color: "#b84636", marginTop: "4px" }}>Analyst name is required to investigate</div>}
                                        </div>

                                        {/* Investigation notes */}
                                        <div style={{ marginBottom: "14px" }}>
                                            <div style={{ fontSize: "10px", color: "#707168", letterSpacing: "1px", marginBottom: "6px" }}>
                                                INVESTIGATION NOTES <span style={{ color: "#b84636" }}>*</span>
                                            </div>
                                            <textarea
                                                value={investigateReason}
                                                onChange={e => setInvestigateReason(e.target.value)}
                                                placeholder="Describe findings, actions taken, or reason for closing..."
                                                rows={3}
                                                style={{ width: "100%", background: "#faf9f4", border: "1px solid #d9d8ce", borderRadius: "4px", padding: "10px 12px", color: "#282a25", fontFamily: "inherit", fontSize: "12px", resize: "vertical", boxSizing: "border-box", outline: "none" }}
                                            />
                                        </div>

                                        {investError && (
                                            <div style={{ color: "#b84636", fontSize: "12px", marginBottom: "12px" }}>⚠ {investError}</div>
                                        )}

                                        {/* Status buttons */}
                                        <div style={{ display: "flex", gap: "10px", flexWrap: "wrap" }}>
                                            <button onClick={() => submitInvestigation("Under Progress")} disabled={investLoading}
                                                style={{ background: "#a9761922", border: "1px solid #a97619", color: "#a97619", borderRadius: "4px", padding: "10px 18px", fontFamily: "inherit", fontSize: "11px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                                ⟳ MARK UNDER PROGRESS
                                            </button>
                                            <button onClick={() => submitInvestigation("Investigated")} disabled={investLoading}
                                                style={{ background: "#f6e4dc", border: "1px solid #d65a35", color: "#d65a35", borderRadius: "4px", padding: "10px 18px", fontFamily: "inherit", fontSize: "11px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                                ✓ MARK INVESTIGATED
                                            </button>
                                            <button onClick={() => submitInvestigation("Closed")} disabled={investLoading}
                                                style={{ background: "#73856b22", border: "1px solid #73856b", color: "#73856b", borderRadius: "4px", padding: "10px 18px", fontFamily: "inherit", fontSize: "11px", fontWeight: 700, cursor: "pointer", letterSpacing: "1px" }}>
                                                ✗ CLOSE ALERT
                                            </button>
                                            <button onClick={() => { setShowInvestigateForm(false); setInvestError(""); }}
                                                style={{ background: "transparent", border: "1px solid #d9d8ce", color: "#707168", borderRadius: "4px", padding: "10px 18px", fontFamily: "inherit", fontSize: "11px", cursor: "pointer" }}>
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