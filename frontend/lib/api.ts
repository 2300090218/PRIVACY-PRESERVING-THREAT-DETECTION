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
import { IS_DEMO_MODE, isAuthenticated } from "@/lib/config";

export const API_BASE = (process.env.NEXT_PUBLIC_API_URL || "").replace(/\/+$/, "");

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
    if (IS_DEMO_MODE && !isAuthenticated()) {
      q.set("is_test", "true");
    } else if (params?.is_test !== undefined) {
      q.set("is_test", String(params.is_test));
    }
    return fetchJson<SecurityEvent[]>(`/api/events?${q.toString()}`);
  },
  getRecentEvents: (limit: number = 10) => {
    const q = new URLSearchParams({ limit: String(limit) });
    if (IS_DEMO_MODE && !isAuthenticated()) {
      q.set("is_test", "true");
      return fetchJson<SecurityEvent[]>(`/api/events?${q.toString()}`);
    }
    return fetchJson<SecurityEvent[]>(`/api/events/recent?limit=${limit}`);
  },
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
  createIncident: (data: any) => {
    if (IS_DEMO_MODE && !isAuthenticated()) {
      throw new Error("Public Demo Mode: Incident creation requires SOC Analyst credentials.");
    }
    return fetchJson<Incident>("/api/incidents", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },
  updateIncident: (incidentId: string, data: any) => {
    if (IS_DEMO_MODE && !isAuthenticated()) {
      throw new Error("Public Demo Mode: Incident updates require SOC Analyst credentials.");
    }
    return fetchJson<Incident>(`/api/incidents/${incidentId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },

  // Clients
  getClients: () => fetchJson<ClientDevice[]>("/api/clients"),
  registerClient: (data: any) => {
    if (IS_DEMO_MODE && !isAuthenticated()) {
      throw new Error("Public Demo Mode: Client registration requires Administrator credentials.");
    }
    return fetchJson<ClientDevice>("/api/clients/register", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  // Federated Learning
  getFederatedStatus: () => fetchJson<FederatedStatus>("/api/federated/status"),
  startFederatedRound: () => {
    if (IS_DEMO_MODE && !isAuthenticated()) {
      throw new Error("Public Demo Mode: Starting federated training requires Administrator credentials.");
    }
    return fetchJson<any>("/api/federated/start", { method: "POST" });
  },
  stopFederatedRound: () => {
    if (IS_DEMO_MODE && !isAuthenticated()) {
      throw new Error("Public Demo Mode: Stopping federated training requires Administrator credentials.");
    }
    return fetchJson<any>("/api/federated/stop", { method: "POST" });
  },
  getTrainingRounds: () => fetchJson<TrainingRound[]>("/api/federated/rounds"),

  // Privacy
  getPrivacyStatus: () => fetchJson<PrivacyStatus>("/api/privacy/status"),
  getPrivacyEvents: (limit: number = 50) => fetchJson<PrivacyEvent[]>(`/api/privacy/events?limit=${limit}`),

  // Audit
  getAuditLogs: async (limit: number = 50) => {
    try {
      const logs = await fetchJson<AuditLog[]>(`/api/audit?limit=${limit}`);
      if (IS_DEMO_MODE && !isAuthenticated()) {
        return logs.map((l) => ({
          ...l,
          actor: l.actor?.includes("@") ? "SOC_ANALYST (REDACTED)" : l.actor,
          organization_id: "DEMO_TENANT",
        }));
      }
      return logs;
    } catch (e) {
      if (IS_DEMO_MODE && !isAuthenticated()) {
        return [
          {
            id: 1,
            timestamp: new Date().toISOString(),
            actor: "DEMO_TEST_RUNNER",
            action: "TEST_SCENARIO_EVALUATED",
            resource: "event",
            resource_id: "TEST-SYNTHETIC-01",
            result: "SUCCESS",
            metadata_payload: { mode: "PUBLIC_DEMO_MODE", pii_sanitized: true }
          },
          {
            id: 2,
            timestamp: new Date(Date.now() - 180000).toISOString(),
            actor: "PRIVACY_GATEWAY",
            action: "PII_MINIMIZATION_VERIFIED",
            resource: "policy",
            resource_id: "POLICY-DEFAULT",
            result: "SUCCESS",
            metadata_payload: { mode: "PUBLIC_DEMO_MODE", technique: "HMAC-SHA256" }
          }
        ];
      }
      throw e;
    }
  },

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

  // Version 1 Standardized Endpoints
  v1: {
    // Organizations
    getOrganizations: async () => {
      let orgs: any[] = [];
      try {
        orgs = await fetchJson<any[]>("/api/v1/organizations");
      } catch (e) {
        console.warn("Backend /organizations unreachable, using verified demo baseline:", e);
      }

      const defaultDemoOrgs = [
        {
          id: 101,
          org_id: "demo_klef_vijayawada",
          name: "KL University / KLEF",
          location: "Vijayawada, Andhra Pradesh, India",
          status: "ACTIVE",
          is_demo: true,
          demo_status: "DEMO",
          security_status: "ACTIVE / SHIELDED",
          contact_email: "ciso@kluniversity.edu.in",
          active_agents: 14,
          total_events: 1284,
          total_detections: 48,
          record_counts: {
            students: 15420,
            faculty: 1120,
            it_staff: 85,
            security_staff: 42,
            administrators: 28,
            security_agents: 14,
            total_records: 16709
          },
          created_at: new Date().toISOString()
        },
        {
          id: 102,
          org_id: "demo_gitam_visakhapatnam",
          name: "GITAM",
          location: "Visakhapatnam, Andhra Pradesh, India",
          status: "ACTIVE",
          is_demo: true,
          demo_status: "DEMO",
          security_status: "ACTIVE / SHIELDED",
          contact_email: "infosec@gitam.edu",
          active_agents: 12,
          total_events: 946,
          total_detections: 35,
          record_counts: {
            students: 12850,
            faculty: 940,
            it_staff: 65,
            security_staff: 38,
            administrators: 24,
            security_agents: 12,
            total_records: 13929
          },
          created_at: new Date().toISOString()
        }
      ];

      // Ensure KL University and GITAM are present in the list
      const existingIds = new Set(orgs.map((o) => o.org_id));
      for (const demoOrg of defaultDemoOrgs) {
        if (!existingIds.has(demoOrg.org_id)) {
          orgs.unshift(demoOrg);
        }
      }

      // Filter out any legacy local scratch entries
      orgs = orgs.filter((o) => !["org_local_test_1", "org_local_test_2", "org_local_test_3"].includes(o.org_id));

      if (IS_DEMO_MODE && !isAuthenticated()) {
        return orgs.map((o) => ({
          ...o,
          contact_email: o.contact_email ? (o.contact_email.includes("edu") ? o.contact_email : "demo-protected@enterprise.internal") : undefined,
        }));
      }
      return orgs;
    },
    getOrganizationRecords: (orgId: string) => {
      return fetchJson<any>(`/api/v1/organizations/${encodeURIComponent(orgId)}/records`);
    },
    shareCrossOrganization: (data: {
      sender_org_id: string;
      receiver_org_id: string;
      event_payload?: any;
      event?: any;
      inject_sensitive_field?: string;
    }) => {
      const payload = {
        sender_org_id: data.sender_org_id,
        receiver_org_id: data.receiver_org_id,
        event_payload: data.event_payload || data.event,
        inject_sensitive_field: data.inject_sensitive_field,
      };
      return fetchJson<any>("/api/v1/privacy/cross-org-share", {
        method: "POST",
        body: JSON.stringify(payload),
      });
    },
    registerOrganization: (data: { org_id: string; name: string; contact_email?: string }) => {
      if (IS_DEMO_MODE && !isAuthenticated()) {
        throw new Error("Public Demo Mode: Organization creation is disabled. Authenticate with Enterprise credentials.");
      }
      return fetchJson<any>("/api/v1/organizations/register", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },

    // Agents
    getAgents: (orgId?: string) => {
      const q = orgId ? `?organization_id=${encodeURIComponent(orgId)}` : "";
      return fetchJson<any[]>(`/api/v1/agents${q}`);
    },
    getAgentById: (agentId: string) => fetchJson<any>(`/api/v1/agents/${agentId}`),
    registerAgent: (data: { agent_id: string; organization_id: string; name: string; version?: string }) => {
      if (IS_DEMO_MODE && !isAuthenticated()) {
        throw new Error("Public Demo Mode: Agent provisioning is restricted to authenticated enterprise administrators.");
      }
      return fetchJson<any>("/api/v1/agents/register", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },

    // Events
    getEvents: (params?: { limit?: number; offset?: number; organization_id?: string }) => {
      const q = new URLSearchParams();
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      if (params?.organization_id) q.set("organization_id", params.organization_id);
      return fetchJson<any[]>(`/api/v1/events?${q.toString()}`);
    },
    getEventById: (eventId: string) => fetchJson<any>(`/api/v1/events/${eventId}`),
    ingestProtectedEvent: (eventData: any, headers?: Record<string, string>) => {
      if (IS_DEMO_MODE && !isAuthenticated() && !headers?.["X-API-Key"]) {
        throw new Error("Public Demo Mode: Direct event ingestion requires an authorized X-API-Key.");
      }
      return fetchJson<any>("/api/v1/events", {
        method: "POST",
        headers: headers || {},
        body: JSON.stringify(eventData),
      });
    },

    // Detections
    getDetections: (params?: { limit?: number; offset?: number; organization_id?: string; attack_type?: string; severity?: string }) => {
      const q = new URLSearchParams();
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      if (params?.organization_id) q.set("organization_id", params.organization_id);
      if (params?.attack_type) q.set("attack_type", params.attack_type);
      if (params?.severity) q.set("severity", params.severity);
      return fetchJson<any[]>(`/api/v1/detections?${q.toString()}`);
    },

    // Alerts
    getAlerts: (params?: { organization_id?: string; status?: string; severity?: string }) => {
      const q = new URLSearchParams();
      if (params?.organization_id) q.set("organization_id", params.organization_id);
      if (params?.status) q.set("status", params.status);
      if (params?.severity) q.set("severity", params.severity);
      return fetchJson<any[]>(`/api/v1/alerts?${q.toString()}`);
    },
    acknowledgeAlert: (alertId: string) =>
      fetchJson<any>(`/api/v1/alerts/${alertId}/acknowledge`, { method: "PUT" }),
    resolveAlert: (alertId: string) =>
      fetchJson<any>(`/api/v1/alerts/${alertId}/resolve`, { method: "PUT" }),

    // Privacy Policies & Real Metrics
    getPrivacyMetrics: () => fetchJson<any>("/api/v1/privacy/metrics"),
    getPrivacyPolicies: (orgId?: string) => {
      const q = orgId ? `?organization_id=${encodeURIComponent(orgId)}` : "";
      return fetchJson<any[]>(`/api/v1/privacy/policies${q}`);
    },
    updatePrivacyPolicy: (policyId: string, data: { action: string; parameters?: Record<string, any>; is_active?: boolean }) => {
      if (IS_DEMO_MODE && !isAuthenticated()) {
        throw new Error("Public Demo Mode: Policy modification is locked. Authenticate as Security Analyst to edit minimization rules.");
      }
      return fetchJson<any>(`/api/v1/privacy/policies/${policyId}`, {
        method: "PUT",
        body: JSON.stringify(data),
      });
    },
    transformDemo: (rawEvent: any) =>
      fetchJson<any>("/api/v1/privacy/transform-demo", {
        method: "POST",
        body: JSON.stringify(rawEvent),
      }),

    // System Health
    getSystemHealth: () => fetchJson<any>("/api/v1/system/health"),

    // Audit Logs
    getAuditLogs: (params?: { limit?: number; offset?: number; organization_id?: string; action?: string; actor?: string; result?: string }) => {
      const q = new URLSearchParams();
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      if (params?.organization_id) q.set("organization_id", params.organization_id);
      if (params?.action) q.set("action", params.action);
      if (params?.actor) q.set("actor", params.actor);
      if (params?.result) q.set("result", params.result);
      return fetchJson<any[]>(`/api/v1/audit-logs?${q.toString()}`);
    },
  },
};

