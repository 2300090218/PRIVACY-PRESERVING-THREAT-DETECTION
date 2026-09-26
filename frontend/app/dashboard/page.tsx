"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  ShieldAlert,
  Activity,
  Target,
  Wifi,
  Lock,
  Flame,
  AlertTriangle,
  Radio,
  Share2,
  Clock,
  CheckCircle,
  FileText,
  Server,
  RefreshCw,
  ExternalLink,
} from "lucide-react";
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

import { ClientShell } from "@/components/ClientShell";
import { MetricCard } from "@/components/MetricCard";
import { ThreatMap } from "@/components/ThreatMap";
import { api } from "@/lib/api";
import { useWebSocketTelemetry, WSEventMessage } from "@/lib/websocket";
import {
  SecurityEvent,
  Detection,
  Alert,
  Incident,
  ClientDevice,
  FederatedStatus,
  SystemMetrics,
  HealthCheck,
  PrivacyStatus,
} from "@/types";

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [detectionMetrics, setDetectionMetrics] = useState<any>(null);
  const [trainingMetrics, setTrainingMetrics] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [recentDetections, setRecentDetections] = useState<Detection[]>([]);
  const [recentEvents, setRecentEvents] = useState<SecurityEvent[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [clients, setClients] = useState<ClientDevice[]>([]);
  const [flStatus, setFlStatus] = useState<FederatedStatus | null>(null);
  const [privacyStatus, setPrivacyStatus] = useState<PrivacyStatus | null>(null);
  const [health, setHealth] = useState<HealthCheck | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const loadAllData = useCallback(async () => {
    try {
      const [
        metricsRes,
        detMetricsRes,
        trainMetricsRes,
        alertsRes,
        detectionsRes,
        eventsRes,
        incidentsRes,
        clientsRes,
        flRes,
        privacyRes,
        healthRes,
      ] = await Promise.all([
        api.getMetrics().catch(() => null),
        api.getDetectionMetrics().catch(() => null),
        api.getTrainingMetrics().catch(() => []),
        api.getAlerts().catch(() => []),
        api.getDetections({ limit: 10 }).catch(() => []),
        api.getRecentEvents(10).catch(() => []),
        api.getIncidents().catch(() => []),
        api.getClients().catch(() => []),
        api.getFederatedStatus().catch(() => null),
        api.getPrivacyStatus().catch(() => null),
        api.getHealth().catch(() => null),
      ]);

      setMetrics(metricsRes);
      setDetectionMetrics(detMetricsRes);
      setTrainingMetrics(trainMetricsRes);
      setAlerts(alertsRes);
      setRecentDetections(detectionsRes);
      setRecentEvents(eventsRes);
      setIncidents(incidentsRes);
      setClients(clientsRes);
      setFlStatus(flRes);
      setPrivacyStatus(privacyRes);
      setHealth(healthRes);
    } catch (e) {
      console.error("Failed to load dashboard data:", e);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Real-time WebSocket / HTTP Polling telemetry event handler
  const { status: wsStatus } = useWebSocketTelemetry(
    useCallback((msg: WSEventMessage) => {
      if (msg.type === "alert.created") {
        setAlerts((prev) => [msg.data, ...prev.filter((a) => a.alert_id !== msg.data.alert_id)]);
      } else if (msg.type === "detection.created") {
        setRecentDetections((prev) => [
          msg.data,
          ...prev.filter((d) => d.event_id !== (msg.data.event_id || (msg.data as any).detection_id)).slice(0, 9),
        ]);
      } else if (msg.type === "event.received") {
        setRecentEvents((prev) => [
          msg.data,
          ...prev.filter((e) => e.event_id !== msg.data.event_id).slice(0, 9),
        ]);
      } else if (msg.type === "training.completed") {
        loadAllData();
      }
    }, [loadAllData])
  );

  useEffect(() => {
    loadAllData();
    // When WebSocket is connected, background polling can be slower (15s)
    // When WebSocket is disconnected (such as on Vercel Serverless), fall back to active HTTP polling (3.5s)
    const pollInterval = wsStatus === "CONNECTED" ? 15000 : 3500;
    const interval = setInterval(loadAllData, pollInterval);
    return () => clearInterval(interval);
  }, [loadAllData, wsStatus]);

  // Instant refresh on security test execution dispatched by the Navbar
  useEffect(() => {
    const handleTestExecuted = () => {
      loadAllData();
    };
    if (typeof window !== "undefined") {
      window.addEventListener("threat-detection:test-executed", handleTestExecuted);
      return () => window.removeEventListener("threat-detection:test-executed", handleTestExecuted);
    }
  }, [loadAllData]);

  // Derive dynamic overall threat level
  const activeAlerts = alerts.filter((a) => a.status === "NEW");
  const hasCritical = activeAlerts.some((a) => a.severity === "CRITICAL");
  const hasHigh = activeAlerts.some((a) => a.severity === "HIGH");
  const threatLevel = hasCritical ? "CRITICAL" : hasHigh ? "ELEVATED" : activeAlerts.length > 0 ? "GUARDED" : "LOW";
  const threatBadgeType = hasCritical ? "danger" : hasHigh ? "warning" : activeAlerts.length > 0 ? "info" : "success";

  // Format accuracy for display (Strict no-fabrication: show actual or empty)
  const accuracyVal = detectionMetrics?.model_accuracy
    ? `${(detectionMetrics.model_accuracy * 100).toFixed(2)}%`
    : "Evaluating";

  // Attack distribution data for BarChart
  const attackDistData = detectionMetrics?.attack_type_distribution
    ? Object.entries(detectionMetrics.attack_type_distribution).map(([k, v]) => ({
        name: k,
        count: v,
      }))
    : [];

  return (
    <ClientShell>
      {/* SECTION 1: TOP STATS ROW */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <MetricCard
          title="Threat Level"
          value={threatLevel}
          badge={`${activeAlerts.length} Active Alerts`}
          badgeType={threatBadgeType}
          icon={ShieldAlert}
          iconColor={hasCritical ? "text-rose-600" : hasHigh ? "text-amber-600" : "text-emerald-600"}
          subtitle="Dynamic composite risk posture"
        />
        <MetricCard
          title="System Status"
          value={health?.overall_status || "ACTIVE"}
          badge={health?.mode === "TEST" ? "TEST MODE" : "LIVE"}
          badgeType="info"
          icon={Activity}
          iconColor="text-blue-600"
          subtitle="All core subsystems responding"
        />
        <MetricCard
          title="Detection Accuracy"
          value={accuracyVal}
          badge={detectionMetrics?.active_model_version || "global-v1"}
          badgeType="success"
          icon={Target}
          iconColor="text-emerald-600"
          subtitle="Evaluated on held-out test split"
        />
        <MetricCard
          title="Network Health"
          value={metrics?.network_health || "GOOD"}
          badge={`${metrics?.avg_processing_latency_ms || 0} ms Latency`}
          badgeType="neutral"
          icon={Wifi}
          iconColor="text-indigo-600"
          subtitle={`${metrics?.total_events || 0} events normalized`}
        />
        <MetricCard
          title="Privacy Status"
          value={privacyStatus?.data_minimization === "ACTIVE" ? "PROTECTED" : "ACTIVE"}
          badge="Raw Data Local"
          badgeType="success"
          icon={Lock}
          iconColor="text-emerald-600"
          subtitle={`${privacyStatus?.total_privacy_transformations || 0} PII fields sanitized`}
        />
      </div>

      {/* SECTION 2: MAIN (GLOBAL THREAT INTELLIGENCE & REAL-TIME ALERTS) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Global Threat Intelligence & Threat Map (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <ThreatMap events={recentEvents} detections={recentDetections} />

          {/* External Threat Intelligence Feed Panel */}
          <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm flex items-center justify-between">
            <div className="space-y-0.5">
              <span className="text-xs font-bold text-slate-700 uppercase tracking-wide">
                External Threat Intelligence Feeds
              </span>
              <p className="text-xs text-slate-500">
                Commercial and open-source STIX/TAXII threat intel provider integrations
              </p>
            </div>
            <span className="text-xs font-semibold px-2.5 py-1 rounded bg-slate-100 text-slate-600 border border-slate-200">
              NOT CONFIGURED
            </span>
          </div>
        </div>

        {/* Real-Time Alerts Feed (5 cols) */}
        <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-600" />
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                  Real-Time Alerts
                </h2>
              </div>
              <span className="text-[11px] font-semibold text-slate-500">
                Live WebSocket Stream
              </span>
            </div>

            <div className="mt-4 space-y-2.5 max-h-[340px] overflow-y-auto pr-1">
              {alerts.length === 0 ? (
                <div className="py-12 text-center text-slate-400 space-y-2">
                  <CheckCircle className="h-8 w-8 mx-auto text-slate-300" />
                  <p className="text-xs font-medium">No alerts yet</p>
                  <p className="text-[11px] text-slate-400">
                    Click &quot;RUN SECURITY TEST&quot; above to simulate an attack vector safely.
                  </p>
                </div>
              ) : (
                alerts.slice(0, 5).map((alert) => (
                  <div
                    key={alert.alert_id}
                    className="p-3 rounded-lg border border-slate-200 bg-slate-50/70 hover:bg-white hover:border-slate-300 transition-all space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            alert.severity === "CRITICAL"
                              ? "bg-rose-100 text-rose-800"
                              : alert.severity === "HIGH"
                              ? "bg-amber-100 text-amber-800"
                              : "bg-blue-100 text-blue-800"
                          }`}
                        >
                          {alert.severity}
                        </span>
                        <span className="font-bold text-slate-800">{alert.attack_type}</span>
                        {alert.is_test && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-semibold bg-amber-200 text-amber-900">
                            TEST
                          </span>
                        )}
                      </div>
                      <span className="text-[11px] font-semibold text-slate-700">
                        Risk: {alert.risk_score}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-500">
                      <span>Origin: {alert.client_id}</span>
                      <span>Conf: {(alert.confidence * 100).toFixed(1)}%</span>
                      <span className="text-[10px] text-slate-400">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Total Alerts: {alerts.length}</span>
            <a href="/alerts" className="text-indigo-600 hover:underline font-semibold flex items-center gap-1">
              View All Alerts <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
      </div>

      {/* SECTION 3: SECONDARY (THREAT STATISTICS & RECENT THREATS) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Threat Distribution Chart (6 cols) */}
        <div className="lg:col-span-6 bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-rose-600" />
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                Detected Attack Profiles
              </h2>
            </div>
            <span className="text-[11px] font-medium text-slate-500">
              Categorized by Scikit-Learn Model
            </span>
          </div>

          <div className="h-56">
            {attackDistData.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">
                No threat statistics recorded yet
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attackDistData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                  <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                  <YAxis tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      color: "#fff",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Recent Threat Detections Ledger (6 cols) */}
        <div className="lg:col-span-6 bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Radio className="h-4 w-4 text-indigo-600" />
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                  Recent Threat Detections
                </h2>
              </div>
              <span className="text-[11px] font-semibold text-slate-500">
                Dual Rule + ML Layer
              </span>
            </div>

            <div className="mt-3 space-y-2 max-h-52 overflow-y-auto">
              {recentDetections.length === 0 ? (
                <div className="py-8 text-center text-xs text-slate-400">
                  No detections yet
                </div>
              ) : (
                recentDetections.slice(0, 4).map((d) => (
                  <div
                    key={d.id}
                    className="flex items-center justify-between p-2.5 rounded-lg border border-slate-100 bg-slate-50 text-xs"
                  >
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900">{d.attack_type}</span>
                        <span
                          className={`text-[10px] font-semibold px-1.5 py-0.2 rounded ${
                            d.prediction === "MALICIOUS"
                              ? "bg-rose-100 text-rose-700"
                              : d.prediction === "SUSPICIOUS"
                              ? "bg-amber-100 text-amber-700"
                              : "bg-emerald-100 text-emerald-700"
                          }`}
                        >
                          {d.prediction}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400">
                        Event: {d.event_id} | Model: {d.model_version}
                      </p>
                    </div>
                    <div className="text-right">
                      <span className="font-semibold text-slate-700">
                        {(d.confidence * 100).toFixed(1)}% Conf
                      </span>
                      <p className="text-[10px] text-slate-400">{d.processing_latency_ms} ms</p>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
            <span>Active Incidents: {incidents.length}</span>
            <a href="/threats" className="text-indigo-600 hover:underline font-semibold flex items-center gap-1">
              View All Detections <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>
      </div>

      {/* SECTION 4: FEDERATED LEARNING OVERVIEW */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Share2 className="h-4 w-4 text-indigo-600" />
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                Federated Learning Cluster
              </h2>
              <p className="text-xs text-slate-500">
                Decentralized collaborative training using FedAvg parameter aggregation without moving raw data
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-semibold px-2.5 py-1 rounded bg-indigo-50 text-indigo-700 border border-indigo-200">
              Round: {flStatus?.current_round || 1} / {flStatus?.max_rounds || 5}
            </span>
            <span className="text-xs font-semibold px-2.5 py-1 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
              Model: {flStatus?.global_model_version || "global-v1"}
            </span>
          </div>
        </div>

        {/* Federated Clients Status Tiles */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {clients.length === 0 ? (
            <div className="col-span-3 py-6 text-center text-xs text-slate-400">
              No federated clients connected
            </div>
          ) : (
            clients.map((c) => (
              <div
                key={c.client_id}
                className="p-3.5 rounded-lg border border-slate-200 bg-slate-50/80 space-y-2"
              >
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <Server className="h-3.5 w-3.5 text-indigo-600" />
                    <span className="font-bold text-slate-900">{c.name}</span>
                  </div>
                  <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800">
                    {c.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 space-y-0.5">
                  <div className="flex justify-between">
                    <span>ID: {c.client_id}</span>
                    <span className="font-mono text-[10px]">{c.ip_address || "Internal Subnet"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Local Model:</span>
                    <span className="font-semibold text-slate-700">{c.model_version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Raw Data Shared:</span>
                    <span className="font-bold text-emerald-600">NO (Local Only)</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Federated Training Loss & Accuracy Chart */}
        {trainingMetrics.length > 0 && (
          <div className="pt-2">
            <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wide mb-2">
              Global Model Evolution (FedAvg Test Evaluation)
            </h3>
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trainingMetrics}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                  <XAxis dataKey="round" tick={{ fontSize: 11 }} label={{ value: "Round", position: "insideBottom", offset: -2 }} />
                  <YAxis tick={{ fontSize: 11 }} domain={[0.7, 1.0]} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      color: "#fff",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Line type="monotone" dataKey="accuracy" stroke="#10b981" strokeWidth={2} name="Accuracy" />
                  <Line type="monotone" dataKey="f1" stroke="#6366f1" strokeWidth={2} name="F1-Score" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>
    </ClientShell>
  );
}
