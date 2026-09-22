"use client";

import React, { useState } from "react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { Eye, ArrowRight, ShieldCheck, Lock, Play, RefreshCw, CheckCircle, FileCode } from "lucide-react";

const PRESET_EVENTS = {
  FAILED_LOGIN: {
    title: "Brute Force Authentication Storm",
    event: {
      username: "corporate_admin",
      source_ip: "192.168.1.105",
      device_id: "CORP-LAPTOP-WS-9912",
      location: "Building 4, Floor 2, Frankfurt, DE",
      event_type: "auth_attempt",
      failed_attempts: 12,
      destination_port: 22,
      protocol: "SSH",
      attack_indicators: ["FAILED_PASSWORD_BURST", "DICTIONARY_SIGNATURE"],
      timestamp: new Date().toISOString(),
    },
  },
  PORT_SCAN: {
    title: "Reconnaissance Port Sweep",
    event: {
      username: "svc_network_probe",
      source_ip: "10.0.4.55",
      device_id: "DMZ-SCAN-NODE-01",
      location: "Data Center East, Rack 12",
      event_type: "network_sweep",
      failed_attempts: 0,
      destination_port: 4444,
      protocol: "TCP",
      attack_indicators: ["SYN_FLOOD", "SUSPICIOUS_C2_PORT_4444"],
      timestamp: new Date().toISOString(),
    },
  },
  BENIGN_TRAFFIC: {
    title: "Benign Corporate Web Flow",
    event: {
      username: "j.doe@enterprise.internal",
      source_ip: "172.16.0.42",
      device_id: "EMPLOYEE-MACBOOK-77",
      location: "San Jose, CA Office",
      event_type: "network_flow",
      failed_attempts: 0,
      destination_port: 443,
      protocol: "TLS",
      attack_indicators: [],
      timestamp: new Date().toISOString(),
    },
  },
};

export default function PrivacyViewerPage() {
  const [selectedPreset, setSelectedPreset] = useState<keyof typeof PRESET_EVENTS>("FAILED_LOGIN");
  const [rawJson, setRawJson] = useState<string>(
    JSON.stringify(PRESET_EVENTS.FAILED_LOGIN.event, null, 2)
  );
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleSelectPreset = (key: keyof typeof PRESET_EVENTS) => {
    setSelectedPreset(key);
    setRawJson(JSON.stringify(PRESET_EVENTS[key].event, null, 2));
    setResult(null);
    setError(null);
  };

  const handleRunTransformation = async () => {
    setLoading(true);
    setError(null);
    try {
      const parsed = JSON.parse(rawJson);
      const res = await api.v1.transformDemo(parsed);
      setResult(res);
    } catch (err: any) {
      setError(err.message || "Failed to execute privacy transformation demo");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ClientShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-5">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-emerald-50 border border-emerald-100 text-emerald-700">
                <Eye className="h-5 w-5" />
              </span>
              <h1 className="text-xl font-bold tracking-tight text-slate-900">
                Privacy Transformation Viewer
              </h1>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Interactive demonstration of edge-side data minimization, field redaction, and salted HMAC pseudonymization.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-3 py-1 bg-emerald-50 border border-emerald-200 rounded-lg text-xs font-bold text-emerald-800 flex items-center gap-1.5">
              <ShieldCheck className="h-4 w-4 text-emerald-600" />
              <span>Boundary Guard Enforced</span>
            </span>
          </div>
        </div>

        {/* Preset Selector */}
        <div className="flex flex-wrap items-center gap-2 bg-slate-50 p-2 rounded-xl border border-slate-200">
          <span className="text-xs font-bold text-slate-500 px-2">Preset Telemetry Scenarios:</span>
          {(Object.keys(PRESET_EVENTS) as Array<keyof typeof PRESET_EVENTS>).map((key) => (
            <button
              key={key}
              onClick={() => handleSelectPreset(key)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                selectedPreset === key
                  ? "bg-white text-indigo-700 shadow-sm border border-slate-200 font-bold"
                  : "text-slate-600 hover:text-slate-900 hover:bg-slate-200/50"
              }`}
            >
              {PRESET_EVENTS[key].title}
            </button>
          ))}
        </div>

        {/* 3-Stage Pipeline Display */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Stage 1: Raw Local Event */}
          <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col h-[520px]">
            <div className="p-3.5 border-b border-slate-200 bg-slate-50/50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-rose-600" />
                <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Stage 1: Local Raw Event (Inside Org A Boundary)
                </span>
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
                Contains PII
              </span>
            </div>

            <div className="p-3 flex-1 flex flex-col">
              <p className="text-[11px] text-slate-500 mb-2">
                Editable local telemetry. Sensitive identifiers will be stripped or masked by the gateway.
              </p>
              <textarea
                value={rawJson}
                onChange={(e) => setRawJson(e.target.value)}
                className="flex-1 w-full p-3 font-mono text-xs text-slate-800 bg-slate-900/5 rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-none font-medium leading-relaxed"
                spellCheck={false}
              />
            </div>

            <div className="p-3 border-t border-slate-200 bg-slate-50/50 flex justify-between items-center">
              <span className="text-[11px] text-slate-500">
                Sensitive: username, IP, location, device ID
              </span>
              <button
                onClick={handleRunTransformation}
                disabled={loading}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition shadow-sm disabled:opacity-50"
              >
                {loading ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Play className="h-3.5 w-3.5" />
                )}
                <span>Pass Through Gateway</span>
              </button>
            </div>
          </div>

          {/* Transition / Gateway Column */}
          <div className="lg:col-span-2 flex flex-col items-center justify-center space-y-4 py-8">
            <div className="h-14 w-14 rounded-2xl bg-indigo-50 border-2 border-indigo-200 flex items-center justify-center text-indigo-700 shadow-md">
              <Lock className="h-7 w-7" />
            </div>
            <div className="text-center">
              <span className="text-xs font-bold text-slate-900 block">Privacy Gateway</span>
              <span className="text-[10px] text-slate-500 font-mono">HMAC-SHA256 Engine</span>
            </div>
            <div className="flex items-center gap-1 text-indigo-600">
              <ArrowRight className="h-5 w-5 animate-pulse" />
            </div>
            <div className="w-full bg-slate-100 p-2.5 rounded-lg border border-slate-200 text-[10px] text-slate-600 space-y-1">
              <div className="font-bold text-slate-700">Policies Applied:</div>
              <div>• username → REMOVE</div>
              <div>• source_ip → REMOVE</div>
              <div>• location → REMOVE</div>
              <div>• device_id → PSEUDO</div>
            </div>
          </div>

          {/* Stage 3: Protected Transmitted Event */}
          <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col h-[520px]">
            <div className="p-3.5 border-b border-slate-200 bg-slate-50/50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-600" />
                <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Stage 3: Protected Event (Central Server Wire)
                </span>
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                Zero PII
              </span>
            </div>

            <div className="p-3 flex-1 flex flex-col">
              <p className="text-[11px] text-slate-500 mb-2">
                This minimized payload is the ONLY data permitted across HTTPS to the central server.
              </p>
              {error ? (
                <div className="p-4 bg-rose-50 text-rose-800 rounded-lg text-xs font-medium border border-rose-200">
                  {error}
                </div>
              ) : result ? (
                <pre className="flex-1 w-full p-3 font-mono text-xs text-emerald-950 bg-emerald-50/40 rounded-lg border border-emerald-200 overflow-auto font-medium leading-relaxed">
                  {JSON.stringify(result.protected_event, null, 2)}
                </pre>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 rounded-lg p-6 text-center text-slate-400">
                  <Lock className="h-8 w-8 mb-2 stroke-1 text-slate-300" />
                  <span className="text-xs font-semibold text-slate-600">No Transformation Executed Yet</span>
                  <span className="text-[11px] text-slate-400 mt-1 max-w-xs">
                    Click &apos;Pass Through Gateway&apos; to view how the Privacy Policy minimizes this event.
                  </span>
                </div>
              )}
            </div>

            <div className="p-3 border-t border-slate-200 bg-slate-50/50 flex justify-between items-center text-[11px] text-slate-500">
              {result ? (
                <span className="flex items-center gap-1.5 text-emerald-700 font-bold">
                  <CheckCircle className="h-4 w-4" />
                  <span>Validation Passed ({result.transformations_count || 4} fields minimized)</span>
                </span>
              ) : (
                <span>Awaiting pipeline execution</span>
              )}
              <span className="font-mono text-[10px]">Policy: Enterprise-v1.0</span>
            </div>
          </div>
        </div>
      </div>
    </ClientShell>
  );
}
