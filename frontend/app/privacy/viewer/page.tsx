"use client";

import React, { useState } from "react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { runPreSendPipeline, PreSendPipelineReport } from "@/lib/preSendPipeline";
import {
  Eye,
  ArrowRight,
  ShieldCheck,
  Lock,
  Play,
  RefreshCw,
  CheckCircle,
  FileCode,
  AlertTriangle,
  XCircle,
  Send,
  Zap,
} from "lucide-react";

const PRESET_EVENTS = {
  FAILED_LOGIN: {
    title: "Brute Force Authentication Storm",
    event: {
      username: "corporate_admin",
      source_ip: "192.168.1.105",
      device_id: "CORP-LAPTOP-WS-9912",
      location: "Building 4, Floor 2, Frankfurt, DE",
      event_type: "brute_force_attack",
      failed_attempts: 18,
      destination_port: 22,
      protocol: "SSH",
      attack_indicators: ["FAILED_PASSWORD_BURST", "DICTIONARY_SIGNATURE"],
      duration_seconds: 45,
      bytes_transferred: 18400,
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
      event_type: "port_scan_recon",
      failed_attempts: 0,
      destination_port: 4444,
      protocol: "TCP",
      attack_indicators: ["SYN_FLOOD", "SUSPICIOUS_C2_PORT_4444"],
      duration_seconds: 4,
      bytes_transferred: 1200,
      timestamp: new Date().toISOString(),
    },
  },
  LEAKAGE_TEST: {
    title: "Raw Secret Leakage Attempt (Must Block)",
    event: {
      username: "admin_tester",
      source_ip: "172.16.0.42",
      device_id: "TEST-AGENT-ROGUE",
      api_key: "AKIAIOSFODNN7EXAMPLE",
      password: "SuperSecretPassword123!",
      event_type: "unauthorized_probe",
      payload_dump: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_jwt_token_signature_here",
      failed_attempts: 1,
      destination_port: 443,
      protocol: "TLS",
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
  const [report, setReport] = useState<PreSendPipelineReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sendSuccess, setSendSuccess] = useState<string | null>(null);
  const [sending, setSending] = useState<boolean>(false);

  const handleSelectPreset = (key: keyof typeof PRESET_EVENTS) => {
    setSelectedPreset(key);
    setRawJson(JSON.stringify(PRESET_EVENTS[key].event, null, 2));
    setReport(null);
    setError(null);
    setSendSuccess(null);
  };

  const handleRunPreSendPipeline = () => {
    setLoading(true);
    setError(null);
    setSendSuccess(null);
    try {
      const parsed = JSON.parse(rawJson);
      // Run the complete Edge Pre-Send Security & Privacy Pipeline client-side!
      // Raw sensitive telemetry is NEVER sent across the network.
      const result = runPreSendPipeline(parsed);
      setReport(result);
    } catch (err: any) {
      setError(err.message || "Failed to parse JSON input");
    } finally {
      setLoading(false);
    }
  };

  const handleDispatchSafeArtifact = async () => {
    if (!report || report.finalDecision !== "SAFE TO SEND" || !report.safeArtifact) {
      return;
    }
    setSending(true);
    setSendSuccess(null);
    setError(null);
    try {
      // ONLY the verified safe artifact is dispatched to the central server
      const res = await api.v1.ingestProtectedEvent(report.safeArtifact);
      setSendSuccess(
        `Successfully dispatched verified safe artifact to Central Server! Server acknowledged event '${report.safeArtifact.event_id}'.`
      );
    } catch (err: any) {
      setError(err.message || "Central Server rejected payload.");
    } finally {
      setSending(false);
    }
  };

  return (
    <ClientShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-5">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-indigo-50 border border-indigo-100 text-indigo-700">
                <ShieldCheck className="h-5 w-5" />
              </span>
              <h1 className="text-xl font-bold tracking-tight text-slate-900">
                Edge Pre-Send Security & Privacy Pipeline
              </h1>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Interactive demonstration of edge-side threat inspection, PII sanitization, telemetry optimization, and pre-send safety gating.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-3 py-1 bg-emerald-50 border border-emerald-200 rounded-lg text-xs font-bold text-emerald-800 flex items-center gap-1.5">
              <Lock className="h-4 w-4 text-emerald-600" />
              <span>Zero Raw Data Egress Enforced</span>
            </span>
          </div>
        </div>

        {/* Preset Selector */}
        <div className="flex flex-wrap items-center gap-2 bg-slate-50 p-2 rounded-xl border border-slate-200">
          <span className="text-xs font-bold text-slate-500 px-2">Preset Scenarios:</span>
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
          <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col h-[560px]">
            <div className="p-3.5 border-b border-slate-200 bg-slate-50/50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-rose-600" />
                <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  1. Local Raw Event (Inside Organization Boundary)
                </span>
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
                Local Memory Only
              </span>
            </div>

            <div className="p-3 flex-1 flex flex-col">
              <p className="text-[11px] text-slate-500 mb-2">
                Edit raw telemetry below. Sensitive fields will be inspected, sanitized, and minimized locally before any transmission.
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
                Evaluates: PII, credentials, schema, size, attacks
              </span>
              <button
                onClick={handleRunPreSendPipeline}
                disabled={loading}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition shadow-sm disabled:opacity-50"
              >
                {loading ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Play className="h-3.5 w-3.5" />
                )}
                <span>Run Pre-Send Pipeline</span>
              </button>
            </div>
          </div>

          {/* Middle: Pre-Send Security Status Panel */}
          <div className="lg:col-span-3 bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col h-[560px] p-4 justify-between">
            <div>
              <div className="flex items-center gap-2 border-b border-slate-100 pb-3 mb-3">
                <Zap className="h-4 w-4 text-indigo-600" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Pre-Send Security Check
                </h3>
              </div>

              {!report ? (
                <div className="text-center py-16 text-slate-400 space-y-2">
                  <Lock className="h-8 w-8 mx-auto text-slate-300 stroke-1" />
                  <p className="text-xs font-semibold text-slate-600">Awaiting Inspection</p>
                  <p className="text-[10px] text-slate-400">
                    Click &apos;Run Pre-Send Pipeline&apos; to execute edge-side privacy and safety verification.
                  </p>
                </div>
              ) : (
                <div className="space-y-2.5 text-xs">
                  <div className="flex justify-between items-center py-1 border-b border-slate-100">
                    <span className="text-slate-600 font-medium">Privacy Status:</span>
                    <span
                      className={`font-bold flex items-center gap-1 ${
                        report.privacyStatus === "SAFE" ? "text-emerald-600" : "text-rose-600"
                      }`}
                    >
                      {report.privacyStatus === "SAFE" ? (
                        <CheckCircle className="h-3.5 w-3.5" />
                      ) : (
                        <XCircle className="h-3.5 w-3.5" />
                      )}
                      <span>{report.privacyStatus}</span>
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-1 border-b border-slate-100">
                    <span className="text-slate-600 font-medium">Threat Check:</span>
                    <span
                      className={`font-bold flex items-center gap-1 ${
                        report.threatStatus === "SAFE"
                          ? "text-emerald-600"
                          : report.threatStatus === "SUSPICIOUS"
                          ? "text-amber-600"
                          : "text-rose-600"
                      }`}
                    >
                      {report.threatStatus === "SAFE" && <CheckCircle className="h-3.5 w-3.5" />}
                      {report.threatStatus === "SUSPICIOUS" && <AlertTriangle className="h-3.5 w-3.5" />}
                      {report.threatStatus === "BLOCKED" && <XCircle className="h-3.5 w-3.5" />}
                      <span>{report.threatStatus}</span>
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-1 border-b border-slate-100">
                    <span className="text-slate-600 font-medium">Sensitive Data:</span>
                    <span className="font-semibold text-slate-800">
                      {report.sensitiveFieldsCount} fields minimized
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-1 border-b border-slate-100">
                    <span className="text-slate-600 font-medium">Optimization:</span>
                    <span className="font-semibold text-slate-800">
                      {report.optimizationActionsCount} actions applied
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-1 border-b border-slate-100">
                    <span className="text-slate-600 font-medium">Schema Integrity:</span>
                    <span
                      className={`font-bold ${
                        report.schemaValid ? "text-emerald-600" : "text-rose-600"
                      }`}
                    >
                      {report.schemaValid ? "VALID" : "INVALID"}
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-1 border-b border-slate-100">
                    <span className="text-slate-600 font-medium">Secrets Check:</span>
                    <span
                      className={`font-bold ${
                        report.secretsDetected.length === 0 ? "text-emerald-600" : "text-rose-600"
                      }`}
                    >
                      {report.secretsDetected.length === 0
                        ? "None detected"
                        : `${report.secretsDetected.length} detected`}
                    </span>
                  </div>

                  <div className="flex justify-between items-center py-1 border-b border-slate-100">
                    <span className="text-slate-600 font-medium">Payload Footprint:</span>
                    <span className="font-mono text-slate-700">{report.payloadSizeBytes} B</span>
                  </div>
                </div>
              )}
            </div>

            {/* Final Decision Box */}
            <div className="border-t border-slate-100 pt-3">
              {report && (
                <div
                  className={`p-3 rounded-xl mb-3 text-center border ${
                    report.finalDecision === "SAFE TO SEND"
                      ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                      : "bg-rose-50 border-rose-200 text-rose-800"
                  }`}
                >
                  <span className="text-[10px] uppercase font-bold tracking-wider block">
                    Final Pre-Send Decision
                  </span>
                  <span className="text-sm font-black flex items-center justify-center gap-1.5 mt-0.5">
                    {report.finalDecision === "SAFE TO SEND" ? (
                      <CheckCircle className="h-4 w-4 text-emerald-600" />
                    ) : (
                      <XCircle className="h-4 w-4 text-rose-600" />
                    )}
                    <span>{report.finalDecision}</span>
                  </span>
                  {report.violations.length > 0 && (
                    <div className="mt-1 text-[10px] text-rose-700 text-left font-normal bg-white/60 p-1.5 rounded">
                      <span className="font-bold">Reasons:</span>
                      <ul className="list-disc pl-3">
                        {report.violations.slice(0, 3).map((v, i) => (
                          <li key={i}>{v}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* The Send Button */}
              <button
                onClick={handleDispatchSafeArtifact}
                disabled={!report || report.finalDecision !== "SAFE TO SEND" || sending}
                className={`w-full py-2.5 px-4 rounded-xl text-xs font-bold flex items-center justify-center gap-2 transition shadow-sm ${
                  report && report.finalDecision === "SAFE TO SEND" && !sending
                    ? "bg-emerald-600 hover:bg-emerald-700 text-white cursor-pointer"
                    : "bg-slate-200 text-slate-400 cursor-not-allowed"
                }`}
              >
                {sending ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
                <span>
                  {sending
                    ? "Transmitting Safe Artifact..."
                    : report?.finalDecision === "SAFE TO SEND"
                    ? "SEND TO CENTRAL SERVER"
                    : "SEND BLOCKED"}
                </span>
              </button>
            </div>
          </div>

          {/* Stage 3: Protected Safe Artifact View */}
          <div className="lg:col-span-4 bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col h-[560px]">
            <div className="p-3.5 border-b border-slate-200 bg-slate-50/50 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-600" />
                <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                  Verified Safe Artifact
                </span>
              </div>
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                Wire Payload
              </span>
            </div>

            <div className="p-3 flex-1 flex flex-col">
              <p className="text-[11px] text-slate-500 mb-2">
                This sanitized, minimized representation is the ONLY artifact permitted across the network.
              </p>
              {sendSuccess && (
                <div className="mb-2 p-2 bg-emerald-50 text-emerald-800 rounded border border-emerald-200 text-[11px] font-medium flex items-center gap-1.5">
                  <CheckCircle className="h-4 w-4 flex-shrink-0 text-emerald-600" />
                  <span>{sendSuccess}</span>
                </div>
              )}
              {error && (
                <div className="mb-2 p-2 bg-rose-50 text-rose-800 rounded border border-rose-200 text-[11px] font-medium">
                  {error}
                </div>
              )}
              {report?.safeArtifact ? (
                <pre className="flex-1 w-full p-3 font-mono text-xs text-emerald-950 bg-emerald-50/40 rounded-lg border border-emerald-200 overflow-auto font-medium leading-relaxed">
                  {JSON.stringify(report.safeArtifact, null, 2)}
                </pre>
              ) : (
                <div className="flex-1 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 rounded-lg p-6 text-center text-slate-400">
                  <Lock className="h-8 w-8 mb-2 stroke-1 text-slate-300" />
                  <span className="text-xs font-semibold text-slate-600">No Safe Artifact Emitted</span>
                  <span className="text-[11px] text-slate-400 mt-1 max-w-xs">
                    Execute the pipeline. If any blocking violation exists, no artifact is created and transmission remains locked.
                  </span>
                </div>
              )}
            </div>

            <div className="p-3 border-t border-slate-200 bg-slate-50/50 flex justify-between items-center text-[11px] text-slate-500">
              <span className="font-mono text-[10px]">Destination: POST /api/v1/events</span>
              <span className="font-mono text-[10px]">Zero PII Wire Invariant</span>
            </div>
          </div>
        </div>
      </div>
    </ClientShell>
  );
}
