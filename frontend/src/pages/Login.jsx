import { useState } from "react";
import { useNavigate } from "react-router-dom";

const API = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8001";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLogin = async (event) => {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await fetch(API + "/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      if (!response.ok) {
        setError(response.status === 401 ? "The username or password was not accepted." : "Sign-in could not be completed. Check the service and try again.");
        return;
      }

      const data = await response.json();
      if (!data.access_token) {
        setError("The server response did not include a session token.");
        return;
      }

      localStorage.setItem("token", data.access_token);
      navigate("/dashboard", { replace: true });
    } catch {
      setError("ApexSIEM API could not be reached. Confirm that the backend is running.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <section className="login-aside">
        <div className="login-brand">
          <span className="brand-symbol" aria-hidden="true">A</span>
          <div>
            <div className="login-brand-name">APEXSIEM</div>
            <div className="login-brand-line">Security operations workspace</div>
          </div>
        </div>

        <div className="login-editorial">
          <div className="login-overline">Field notes / 001</div>
          <h1 className="login-headline">See the signal.<br /><em>Keep the evidence.</em></h1>
          <p className="login-description">
            A focused workspace for reviewing security alerts, tracing activity, and recording analyst decisions.
            Every conclusion should lead back to the underlying event.
          </p>
        </div>

        <div className="login-aside-foot">
          <span>LOCAL SECURITY WORKSPACE</span>
          <span>AUTHENTICATED ACCESS</span>
        </div>
      </section>

      <main className="login-main">
        <section className="login-card" aria-labelledby="signin-title">
          <div className="eyebrow">Analyst access</div>
          <h2 className="login-form-title" id="signin-title">Sign in to ApexSIEM</h2>
          <p className="login-form-copy">Use the account configured for this instance. Access is checked by the backend service.</p>

          {error && <div className="login-error" role="alert">{error}</div>}

          <form onSubmit={handleLogin}>
            <div className="field-group">
              <label className="field-label" htmlFor="username">Username</label>
              <input
                className="field-input"
                id="username"
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                required
              />
            </div>

            <div className="field-group">
              <label className="field-label" htmlFor="password">Password</label>
              <input
                className="field-input"
                id="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                required
              />
            </div>

            <button className="button-primary login-submit" type="submit" disabled={loading}>
              {loading ? "Checking credentials…" : "Continue to workspace"}
              {!loading && <span aria-hidden="true">→</span>}
            </button>
          </form>

          <div className="login-footer">Session access is validated by the configured API. Do not share account credentials.</div>
        </section>
      </main>
    </div>
  );
}