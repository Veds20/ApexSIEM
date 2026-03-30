import { useNavigate, useLocation } from "react-router-dom";

function Navbar() {
    const navigate = useNavigate();
    const location = useLocation();

    const logout = () => {
        localStorage.removeItem("token");
        navigate("/");
    };

    const navItems = [
        { label: "DASHBOARD", path: "/dashboard" },
        { label: "PRIORITY", path: "/priority" },
        { label: "INVESTIGATIONS", path: "/investigations" },
    ];

    return (
        <nav style={styles.nav}>
            {/* Brand */}
            <div style={styles.brand} onClick={() => navigate("/dashboard")}>
                <div style={styles.brandIcon}>
                    <div style={styles.iconRing} />
                    <div style={styles.iconDot} />
                </div>
                <div>
                    <div style={styles.brandName}>AI SOC CONSOLE</div>
                    <div style={styles.brandSub}>Security Operations Platform</div>
                </div>
            </div>

            {/* Navigation */}
            <div style={styles.navLinks}>
                {navItems.map(({ label, path }) => {
                    const active = location.pathname === path;
                    return (
                        <button
                            key={path}
                            onClick={() => navigate(path)}
                            style={{ ...styles.navBtn, ...(active ? styles.navBtnActive : {}) }}
                        >
                            {active && <span style={styles.activeBar} />}
                            {label}
                        </button>
                    );
                })}
            </div>

            {/* Right side */}
            <div style={styles.right}>
                <div style={styles.userPill}>
                    <span style={styles.userDot} />
                    admin
                </div>
                <button onClick={logout} style={styles.logoutBtn}>LOGOUT</button>
            </div>
        </nav>
    );
}

const styles = {
    nav: {
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0 24px", height: 56,
        background: "#060e1c",
        borderBottom: "1px solid #0f2540",
        position: "sticky", top: 0, zIndex: 100,
    },
    brand: { display: "flex", alignItems: "center", gap: 12, cursor: "pointer" },
    brandIcon: { position: "relative", width: 28, height: 28 },
    iconRing: { position: "absolute", inset: 0, border: "1.5px solid #00e5cc", borderRadius: "50%", opacity: 0.5 },
    iconDot: { position: "absolute", inset: 8, background: "#00e5cc", borderRadius: "50%" },
    brandName: { fontSize: 13, fontWeight: 700, letterSpacing: "0.2em", color: "#00e5cc", fontFamily: "monospace" },
    brandSub: { fontSize: 10, color: "#2a4a6a", letterSpacing: "0.1em" },
    navLinks: { display: "flex", gap: 4 },
    navBtn: {
        position: "relative", background: "transparent", border: "none",
        color: "#3b5268", padding: "0 14px", height: 56,
        cursor: "pointer", fontSize: 11, letterSpacing: "0.15em",
        fontFamily: "monospace", fontWeight: 600, transition: "color 0.15s",
    },
    navBtnActive: { color: "#00e5cc" },
    activeBar: {
        position: "absolute", bottom: 0, left: 8, right: 8,
        height: 2, background: "#00e5cc", borderRadius: "2px 2px 0 0",
    },
    right: { display: "flex", alignItems: "center", gap: 12 },
    userPill: {
        display: "flex", alignItems: "center", gap: 7,
        background: "#0a1628", border: "1px solid #1e3a5f",
        borderRadius: 20, padding: "4px 12px",
        fontSize: 11, color: "#5b8ab0", fontFamily: "monospace",
    },
    userDot: { width: 7, height: 7, borderRadius: "50%", background: "#4ade80" },
    logoutBtn: {
        background: "transparent", border: "1px solid #1e3a5f",
        color: "#3b5268", padding: "5px 14px", borderRadius: 4,
        cursor: "pointer", fontSize: 11, letterSpacing: "0.15em",
        fontFamily: "monospace", transition: "all 0.15s",
    },
};

export default Navbar;