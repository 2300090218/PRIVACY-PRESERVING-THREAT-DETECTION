/**
 * Application Runtime Configuration & Security Mode
 * Controlled strictly by NEXT_PUBLIC_DEMO_MODE environment variable.
 * 
 * NEXT_PUBLIC_DEMO_MODE=true:
 *   - /dashboard and public routes open directly without login
 *   - Sanitized, synthetic telemetry only (is_test=true)
 *   - Administrative mutations (org creation, policy updates, agent registration) are locked for unauthenticated users
 *   - No real organization credentials, API keys, JWT secrets, or DB info are exposed
 * 
 * NEXT_PUBLIC_DEMO_MODE=false:
 *   - Private enterprise deployment mode
 *   - Unauthenticated visitors are redirected to /login
 */

export const IS_DEMO_MODE = process.env.NEXT_PUBLIC_DEMO_MODE === "true";

export function isDemoMode(): boolean {
  return IS_DEMO_MODE;
}

export function isAuthenticated(): boolean {
  if (typeof window === "undefined") return false;
  return Boolean(localStorage.getItem("token"));
}

export const DEMO_CONFIG = {
  badge: "PUBLIC DEMO MODE",
  tag: "TEST DATA ONLY",
  notice: "Public demonstration mode active. Telemetry is synthetic and sanitized. Enterprise boundaries and production keys are isolated.",
};
