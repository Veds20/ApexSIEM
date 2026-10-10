import { useLocation, useNavigate } from "react-router-dom";

const NAV_ITEMS = [
  { label: "Overview", path: "/dashboard", mark: "01" },
  { label: "Priority queue", path: "/priority", mark: "02" },
  { label: "Investigations", path: "/investigations", mark: "03" },
];

export default function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();

  const logout = () => {
    localStorage.removeItem("token");
    navigate("/", { replace: true });
  };

  return (
    <aside className="app-sidebar" aria-label="Primary navigation">
      <div className="brand-lockup">
        <span className="brand-symbol" aria-hidden="true">A</span>
        <div>
          <div className="brand-name">APEXSIEM</div>
          <div className="brand-subtitle">Security operations</div>
        </div>
      </div>

      <div className="nav-section-label">Workspace</div>
      <nav className="nav-links" aria-label="Workspace">
        {NAV_ITEMS.map(({ label, path, mark }) => (
          <button
            className="nav-link"
            key={path}
            type="button"
            aria-current={location.pathname === path ? "page" : undefined}
            onClick={() => navigate(path)}
          >
            <span className="nav-mark" aria-hidden="true">{mark}</span>
            <span>{label}</span>
          </button>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="sidebar-rule" />
        <div className="sidebar-caption">
          Evidence first.<br />
          Decisions grounded in telemetry.
        </div>
        <div className="sidebar-version">ANALYST WORKSPACE · LOCAL INSTANCE</div>
        <button className="logout-button" type="button" onClick={logout}>
          Sign out <span aria-hidden="true">↗</span>
        </button>
      </div>
    </aside>
  );
}