import {
  SecurityEvent,
  Detection,
  Alert,
  Incident,
  ClientDevice,
  FederatedStatus,
  TrainingRound,
  PrivacyStatus,
  PrivacyEvent,
  AuditLog,
  SystemMetrics,
  HealthCheck,
} from "@/types";

export const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000").replace(/\/+$/, "");

async function fetchJson<T>(url: string, options: RequestInit = {}): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    let errorMsg = `HTTP Error ${res.status}`;
    try {
      const errBody = await res.json();
      errorMsg = errBody.message || errBody.detail || errorMsg;
    } catch (_) {}
    throw new Error(errorMsg);
  }

  return res.json();
}

export const api = {
  // Health & Status
  getHealth: () => fetchJson<HealthCheck>("/api/health"),
  getStatus: () => fetchJson<HealthCheck>("/api/status"),

  // System Metrics
  getMetrics: () => fetchJson<SystemMetrics>("/api/metrics"),
  getDetectionMetrics: () => fetchJson<any>("/api/metrics/detection"),
  getTrainingMetrics: () => fetchJson<any[]>("/api/metrics/training"),

  // Events
  getEvents: (params?: { limit?: number; offset?: number; client_id?: string; is_test?: boolean }) => {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.client_id) q.set("client_id", params.client_id);
    if (params?.is_test !== undefined) q.set("is_test", String(params.is_test));
    return fetchJson<SecurityEvent[]>(`/api/events?${q.toString()}`);
  },
  getRecentEvents: (limit: number = 10) => fetchJson<SecurityEvent[]>(`/api/events/recent?limit=${limit}`),
  ingestEvent: (eventData: any) =>
    fetchJson<any>("/api/events", {
      method: "POST",
      body: JSON.stringify(eventData),
    }),

  // Detections
  getDetections: (params?: { limit?: number; offset?: number; attack_type?: string; severity?: string }) => {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.attack_type) q.set("attack_type", params.attack_type);
    if (params?.severity) q.set("severity", params.severity);
    return fetchJson<Detection[]>(`/api/detections?${q.toString()}`);
  },

  // Alerts
  getAlerts: (status?: string, severity?: string) => {
    const q = new URLSearchParams();
    if (status) q.set("status", status);
    if (severity) q.set("severity", severity);
    return fetchJson<Alert[]>(`/api/alerts?${q.toString()}`);
  },
  acknowledgeAlert: (alertId: string) =>
    fetchJson<Alert>(`/api/alerts/${alertId}/acknowledge`, { method: "POST" }),
  resolveAlert: (alertId: string) =>
    fetchJson<Alert>(`/api/alerts/${alertId}/resolve`, { method: "POST" }),

  // Incidents
  getIncidents: () => fetchJson<Incident[]>("/api/incidents"),
  createIncident: (data: any) =>
    fetchJson<Incident>("/api/incidents", {
      method: "POST",
      body: JSON.stringify(data),
    }),
  updateIncident: (incidentId: string, data: any) =>
    fetchJson<Incident>(`/api/incidents/${incidentId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  // Clients
  getClients: () => fetchJson<ClientDevice[]>("/api/clients"),
  registerClient: (data: any) =>
    fetchJson<ClientDevice>("/api/clients/register", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  // Federated Learning
  getFederatedStatus: () => fetchJson<FederatedStatus>("/api/federated/status"),
  startFederatedRound: () => fetchJson<any>("/api/federated/start", { method: "POST" }),
  stopFederatedRound: () => fetchJson<any>("/api/federated/stop", { method: "POST" }),
  getTrainingRounds: () => fetchJson<TrainingRound[]>("/api/federated/rounds"),

  // Privacy
  getPrivacyStatus: () => fetchJson<PrivacyStatus>("/api/privacy/status"),
  getPrivacyEvents: (limit: number = 50) => fetchJson<PrivacyEvent[]>(`/api/privacy/events?limit=${limit}`),

  // Audit
  getAuditLogs: (limit: number = 50) => fetchJson<AuditLog[]>(`/api/audit?limit=${limit}`),

  // Test Mode
  runSecurityTest: (scenarioIdx?: number) => {
    const q = scenarioIdx !== undefined ? `?scenario_idx=${scenarioIdx}` : "";
    return fetchJson<any>(`/api/test/run${q}`, { method: "POST" });
  },
  startContinuousMonitoring: (interval: number = 3.0) => {
    return fetchJson<any>(`/api/test/continuous/start?interval=${interval}`, { method: "POST" });
  },
  stopContinuousMonitoring: () => {
    return fetchJson<any>("/api/test/continuous/stop", { method: "POST" });
  },
  getContinuousMonitoringStatus: () => {
    return fetchJson<any>("/api/test/continuous/status");
  },
};

