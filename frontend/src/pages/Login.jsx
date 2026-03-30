import { useState } from "react";
import { useNavigate } from "react-router-dom";

export default function Login() {
    const navigate = useNavigate();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const handleLogin = async (e) => {
        e.preventDefault();
        setError("");
        setLoading(true);

        try {
            const response = await fetch("http://127.0.0.1:8001/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
                setError("ACCESS DENIED: Invalid credentials");
                setLoading(false);
                return;
            }

            const data = await response.json();
            localStorage.setItem("token", data.access_token);
            navigate("/dashboard");
        } catch {
            setError("CONNECTION FAILED: Unable to reach server");
            setLoading(false);
        }
    };

    return (
        <div style={styles.page}>
            {/* Scanlines overlay */}
            <div style={styles.scanlines} />

            {/* Grid background */}
            <div style={styles.grid} />

            <div style={styles.container}>
                {/* Logo area */}
                <div style={styles.logoArea}>
                    <div style={styles.logoRing}>
                        <div style={styles.logoInner} />
                        <div style={styles.logoPulse} />
                    </div>
                    <div style={styles.logoText}>AI SOC CONSOLE</div>
                    <div style={styles.logoSub}>Security Operations Platform v2.0</div>
                </div>

                {/* Terminal box */}
                <div style={styles.terminal}>
                    <div style={styles.termBar}>
                        <div style={styles.termDots}>
                            <span style={{ ...styles.termDot, background: "#ff4545" }} />
                            <span style={{ ...styles.termDot, background: "#f5a623" }} />
                            <span style={{ ...styles.termDot, background: "#4ade80" }} />
                        </div>
                        <span style={styles.termTitle}>auth@soc-console</span>
                    </div>

                    <div style={styles.termBody}>
                        <div style={styles.prompt}>
                            <span style={styles.promptGreen}>soc</span>
                            <span style={styles.promptBlue}>@console</span>
                            <span style={{ color: "#3b5268" }}>:~$ </span>
                            <span style={{ color: "#8aa8c0" }}>authenticate --user</span>
                        </div>

                        {error && (
                            <div style={styles.errorLine}>
                                <span style={{ color: "#ff4545" }}>✗ {error}</span>
                            </div>
                        )}

                        <form onSubmit={handleLogin} style={styles.form}>
                            <div style={styles.inputGroup}>
                                <label style={styles.label}>USERNAME</label>
                                <input
                                    type="text"
                                    value={username}
                                    onChange={e => setUsername(e.target.value)}
                                    required
                                    style={styles.input}
                                    autoComplete="username"
                                    spellCheck={false}
                                />
                            </div>

                            <div style={styles.inputGroup}>
                                <label style={styles.label}>PASSWORD</label>
                                <input
                                    type="password"
                                    value={password}
                                    onChange={e => setPassword(e.target.value)}
                                    required
                                    style={styles.input}
                                    autoComplete="current-password"
                                />
                            </div>

                            <button type="submit" style={styles.submitBtn} disabled={loading}>
                                {loading ? "AUTHENTICATING..." : "AUTHENTICATE →"}
                            </button>
                        </form>

                        <div style={styles.footer}>
                            <span style={{ color: "#1e3a5f" }}>Default: admin / admin123</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

const styles = {
    page: {
        height: "100vh", background: "#030a14",
        display: "flex", justifyContent: "center", alignItems: "center",
        fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
        position: "relative", overflow: "hidden",
    },
    scanlines: {
        position: "absolute", inset: 0, pointerEvents: "none",
        background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.08) 2px, rgba(0,0,0,0.08) 4px)",
        zIndex: 1,
    },
    grid: {
        position: "absolute", inset: 0,
        backgroundImage: "linear-gradient(rgba(0,229,204,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,229,204,0.03) 1px, transparent 1px)",
        backgroundSize: "40px 40px",
        zIndex: 0,
    },
    container: { position: "relative", zIndex: 2, width: 400, display: "flex", flexDirection: "column", alignItems: "center", gap: 32 },
    logoArea: { textAlign: "center" },
    logoRing: { position: "relative", width: 56, height: 56, margin: "0 auto 12px" },
    logoInner: { position: "absolute", inset: 8, background: "#00e5cc", borderRadius: "50%", opacity: 0.8 },
    logoPulse: { position: "absolute", inset: 0, border: "1.5px solid #00e5cc", borderRadius: "50%", opacity: 0.4 },
    logoText: { fontSize: 16, fontWeight: 700, letterSpacing: "0.3em", color: "#00e5cc" },
    logoSub: { fontSize: 10, color: "#2a4a6a", letterSpacing: "0.15em", marginTop: 4 },
    terminal: { width: "100%", background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 8, overflow: "hidden" },
    termBar: { display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", background: "#060e1c", borderBottom: "1px solid #0f2540" },
    termDots: { display: "flex", gap: 6 },
    termDot: { width: 10, height: 10, borderRadius: "50%" },
    termTitle: { fontSize: 11, color: "#2a4a6a", flex: 1, textAlign: "center" },
    termBody: { padding: "20px" },
    prompt: { fontSize: 12, marginBottom: 16 },
    promptGreen: { color: "#4ade80" },
    promptBlue: { color: "#00e5cc" },
    errorLine: { background: "#ff454512", border: "1px solid #ff454530", borderRadius: 4, padding: "8px 10px", marginBottom: 12, fontSize: 11 },
    form: { display: "flex", flexDirection: "column", gap: 12 },
    inputGroup: { display: "flex", flexDirection: "column", gap: 5 },
    label: { fontSize: 9, letterSpacing: "0.2em", color: "#2a4a6a" },
    input: {
        background: "#060e1c", border: "1px solid #1e3a5f", color: "#8aa8c0",
        padding: "10px 12px", borderRadius: 4, fontSize: 13,
        fontFamily: "monospace", outline: "none", boxSizing: "border-box",
    },
    submitBtn: {
        marginTop: 6, background: "#00e5cc", color: "#030a14",
        border: "none", padding: "12px", borderRadius: 4,
        cursor: "pointer", fontSize: 12, fontWeight: 700,
        letterSpacing: "0.15em", fontFamily: "monospace",
    },
    footer: { marginTop: 16, fontSize: 10, textAlign: "center" },
};