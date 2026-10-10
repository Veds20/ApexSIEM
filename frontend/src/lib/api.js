export const API = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://127.0.0.1:8001";

export function authHeaders(extra = {}) {
  return { Authorization: `Bearer ${localStorage.getItem("token")}`, ...extra };
}

export async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: authHeaders(options.headers),
  });

  if (!response.ok) {
    let detail = "Request failed";
    try {
      detail = (await response.json()).detail || detail;
    } catch {
      // The response did not contain a JSON error body.
    }
    throw new Error(detail);
  }

  return response.status === 204 ? null : response.json();
}

export function currentAnalyst() {
  try {
    const payload = localStorage.getItem("token")?.split(".")[1];
    return payload ? JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/"))).sub : "Analyst";
  } catch {
    return "Analyst";
  }
}
