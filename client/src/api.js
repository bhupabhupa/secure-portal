import { keycloak } from "./keycloak.js";

// Dev default hits the API port; production sets VITE_API_URL="" so calls
// are same-origin relative, routed by the reverse proxy (no CORS needed).
const BASE = import.meta.env.VITE_API_URL ?? "http://localhost:4000";

export async function api(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${keycloak.token}`,
      ...options.headers,
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return res.json();
}
