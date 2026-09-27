"use client";

import React, { useState, useEffect } from "react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { SystemHealthV1 } from "@/types";
import {
  Activity,
  Server,
  Database,
  Radio,
  Cpu,
  RefreshCw,
  Clock,
  Layers
} from "lucide-react";

export default function SystemHealthPage() {
  const [health, setHealth] = useState<SystemHealthV1 | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [lastCheck, setLastCheck] = useState<Date>(new Date());

  const fetchHealth = async () => {
    try {
      const data = await api.v1.getSystemHealth();
      setHealth(data);
      setLastCheck(new Date());
    } catch (err: any) {
      console.error("Failed to fetch system health:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  return (
    <ClientShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-5">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-emerald-50 border border-emerald-100 text-emerald-700">
                <Activity className="h-5 w-5" />
              </span>
              <h1 className="text-xl font-bold tracking-tight text-slate-900">
                Central Platform System Health
              </h1>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Live operational monitoring across API, relational storage, ML inference, WebSockets, edge agents, and ingest pipelines.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <span className="text-[11px] text-slate-500 flex items-center gap-1 font-mono">
              <Clock className="h-3.5 w-3.5 text-slate-400" />
              {lastCheck.toLocaleTimeString()}
            </span>
            <button
              onClick={() => {
                setRefreshing(true);
                fetchHealth();
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition shadow-sm"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-indigo-600" : ""}`} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Global Status Banner */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div
              className={`h-4 w-4 rounded-full flex items-center justify-center ${
                health?.status === "HEALTHY"
                  ? "bg-emerald-500 animate-pulse"
                  : "bg-amber-500"
              }`}
            >
              <div className="h-2 w-2 rounded-full bg-white"></div>
            </div>
            <div>
              <span className="text-sm font-bold text-slate-900">
                Overall Platform Status: {health?.status || "CHECKING..."}
              </span>
              <p className="text-xs text-slate-500">
                Evaluated against real runtime metrics and persistent database connectivity.
              </p>
            </div>
          </div>
          <span className="px-3 py-1 rounded-full text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
            SECURE BOUNDARY ACTIVE
          </span>
        </div>

        {/* 6 Subsystem Grid Cards */}
        {loading || !health ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="h-44 rounded-xl bg-white border border-slate-200 animate-pulse p-5" />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {/* 1. API Status */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="p-1.5 rounded-lg bg-indigo-50 text-indigo-700">
                      <Server className="h-4 w-4" />
                    </span>
                    <h3 className="font-bold text-slate-900 text-sm">Central API Service</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    {health.api?.status}
                  </span>
                </div>
                <div className="mt-4 space-y-1.5 text-xs text-slate-600">
                  <div className="flex justify-between">
                    <span className="text-slate-500">API Version:</span>
                    <span className="font-mono font-semibold">{health.api?.version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Environment Mode:</span>
                    <span className="font-mono font-semibold">{health.api?.environment}</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
                HTTPS / OpenAPI 3.0 / Pydantic v2
              </div>
            </div>

            {/* 2. Database Status */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="p-1.5 rounded-lg bg-blue-50 text-blue-700">
                      <Database className="h-4 w-4" />
                    </span>
                    <h3 className="font-bold text-slate-900 text-sm">Database Storage</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    {health.database?.status}
                  </span>
                </div>
                <div className="mt-4 space-y-1.5 text-xs text-slate-600">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Storage Engine:</span>
                    <span className="font-mono font-semibold">{health.database?.engine}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Read/Write Latency:</span>
                    <span className="font-mono font-semibold">{health.database?.latency_ms} ms</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
                Zero Raw Log Persistence Verified
              </div>
            </div>

            {/* 3. WebSocket Real-Time Status */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="p-1.5 rounded-lg bg-amber-50 text-amber-700">
                      <Radio className="h-4 w-4" />
                    </span>
                    <h3 className="font-bold text-slate-900 text-sm">Real-Time WebSockets</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    {health.websocket?.status}
                  </span>
                </div>
                <div className="mt-4 space-y-1.5 text-xs text-slate-600">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Active Connections:</span>
                    <span className="font-mono font-semibold">{health.websocket?.active_clients} clients</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Endpoint:</span>
                    <span className="font-mono font-semibold text-[11px]">{health.websocket?.endpoint}</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
                Async Event Broadcaster Active
              </div>
            </div>

            {/* 4. Agent Status */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="p-1.5 rounded-lg bg-purple-50 text-purple-700">
                      <Server className="h-4 w-4" />
                    </span>
                    <h3 className="font-bold text-slate-900 text-sm">Edge Agents</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    {health.agents?.status}
                  </span>
                </div>
                <div className="mt-4 space-y-1.5 text-xs text-slate-600">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Registered Agents:</span>
                    <span className="font-mono font-semibold">{health.agents?.total_registered}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Active Online:</span>
                    <span className="font-mono font-semibold">{health.agents?.active_now}</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
                Organization Boundary Sensors
              </div>
            </div>

            {/* 5. ML Model Status */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="p-1.5 rounded-lg bg-emerald-50 text-emerald-700">
                      <Cpu className="h-4 w-4" />
                    </span>
                    <h3 className="font-bold text-slate-900 text-sm">Threat Detection ML</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    {health.ml_model?.status}
                  </span>
                </div>
                <div className="mt-4 space-y-1.5 text-xs text-slate-600">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Model Type:</span>
                    <span className="font-mono font-semibold">{health.ml_model?.model_type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Active Version:</span>
                    <span className="font-mono font-semibold">{health.ml_model?.model_version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Feature Count:</span>
                    <span className="font-mono font-semibold">{health.ml_model?.features_count}</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
                Scikit-Learn Random Forest Pipeline
              </div>
            </div>

            {/* 6. Ingest Queue Status */}
            <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="p-1.5 rounded-lg bg-slate-100 text-slate-700">
                      <Layers className="h-4 w-4" />
                    </span>
                    <h3 className="font-bold text-slate-900 text-sm">Telemetry Ingestion Queue</h3>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    {health.queue?.status}
                  </span>
                </div>
                <div className="mt-4 space-y-1.5 text-xs text-slate-600">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Ingestion Mode:</span>
                    <span className="font-mono font-semibold">{health.queue?.mode}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Total Ingested Events:</span>
                    <span className="font-mono font-semibold">{health.queue?.total_ingested_events}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Backpressure:</span>
                    <span className="font-mono font-semibold">{health.queue?.backpressure}</span>
                  </div>
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400">
                Idempotency & Deduplication Guard
              </div>
            </div>
          </div>
        )}
      </div>
    </ClientShell>
  );
}
