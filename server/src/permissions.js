// Role → permission mapping (FR-8).
//
// Endpoints declare the PERMISSION they need (runs:create), never a role.
// This one config file is the only place where roles and capabilities meet:
// adding a role (e.g. "auditor" who may read audit but not runs) is a config
// change here + a role in Keycloak — zero code changes in middleware/routes.
//
// At real scale this table lives in a database or a policy engine (OPA,
// Keycloak authorization services); the shape stays the same.

export const ROLE_PERMISSIONS = {
  viewer: ["runs:read"],
  manager: ["runs:read", "runs:create"],
  admin: ["runs:read", "runs:create", "audit:read"],
};

/** Union of permissions granted by a set of realm roles. */
export function permissionsForRoles(roles = []) {
  const permissions = new Set();
  for (const role of roles) {
    for (const permission of ROLE_PERMISSIONS[role] || []) {
      permissions.add(permission);
    }
  }
  return [...permissions];
}
