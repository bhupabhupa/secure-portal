import Keycloak from "keycloak-js";

// Public SPA client — secured with Authorization Code Flow + PKCE.
// No client secret in the browser, ever.
export const keycloak = new Keycloak({
  url: "http://localhost:8080",
  realm: "secure-portal",
  clientId: "portal-web",
});

export async function initAuth() {
  const authenticated = await keycloak.init({
    onLoad: "login-required", // redirect to Keycloak login if not authenticated
    pkceMethod: "S256",
    checkLoginIframe: false,
  });

  // Refresh the access token automatically before it expires.
  // Access tokens are short-lived (5 min default) — the refresh token
  // stays with keycloak-js and rotates. Nothing sensitive in localStorage.
  setInterval(() => {
    keycloak.updateToken(30).catch(() => keycloak.login());
  }, 25000);

  return authenticated;
}

export function hasRole(role) {
  return keycloak.hasRealmRole(role);
}
