"use client";

import React, { useState } from "react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { runPreSendPipeline, PreSendPipelineReport } from "@/lib/preSendPipeline";
import {
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
  Globe,
  Key,
  Database,
  ArrowRight,
  Server,
  Layers,
  HelpCircle,
  Check,
} from "lucide-react";

const PRESET_EVENTS = {
  KL_UNIVERSITY: {
    title: "KL University Port Scan (Part 30 Standard)",
    event: {
      username: "Demo Student",
      source_ip: "192.168.25.44",
      device_id: "device-123",
      latitude: 16.5062,
      longitude: 80.6480,
      sensitive_location: "Regional Datacenter KL (Vaddeswaram)",
      event_type: "Port Scan",
      severity: "HIGH",
      failed_attempts: 0,
      destination_port: 4444,
      protocol: "TCP",
      attack_indicators: ["SYN_PORT_SWEEP", "SUSPICIOUS_C2_PORT_4444"],
      duration_seconds: 4,
      bytes_transferred: 1200,
      timestamp: new Date().toISOString(),
    },
  },
  FAILED_LOGIN: {
    title: "Brute Force Authentication Storm",
    event: {
      username: "corporate_admin",
      source_ip: "192.168.1.105",
      device_id: "CORP-LAPTOP-WS-9912",
      latitude: 50.1109,
      longitude: 8.6821,
      sensitive_location: "Building 4, Floor 2, Frankfurt, DE",
      event_type: "brute_force_attack",
      severity: "HIGH",
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
      latitude: 17.3850,
      longitude: 78.4867,
      sensitive_location: "Hyderabad Campus Datacenter Rack 12",
      event_type: "port_scan_recon",
      severity: "MEDIUM",
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
      latitude: 16.5062,
      longitude: 80.6480,
      api_key: "AKIAIOSFODNN7EXAMPLE",
      password: "SuperSecretPassword123!",
      event_type: "unauthorized_probe",
      severity: "CRITICAL",
      payload_dump: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_jwt_token_signature_here",
      failed_attempts: 1,
      destination_port: 443,
      protocol: "TLS",
      timestamp: new Date().toISOString(),
    },
  },
};

export default function PrivacyViewerPage() {
  const [selectedPreset, setSelectedPreset] = useState<keyof typeof PRESET_EVENTS>("KL_UNIVERSITY");
  const [rawJson, setRawJson] = useState<string>(
    JSON.stringify(PRESET_EVENTS.KL_UNIVERSITY.event, null, 2)
  );
  const [ipMode, setIpMode] = useState<"HMAC-SHA-256" | "AES-256-GCM" | "REMOVE">("HMAC-SHA-256");
  const [locationMode, setLocationMode] = useState<"COARSEN" | "AES-256-GCM" | "REMOVE">("COARSEN");
  const [loading, setLoading] = useState<boolean>(false);
  const [report, setReport] = useState<PreSendPipelineReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sendSuccess, setSendSuccess] = useState<string | null>(null);
  const [sending, setSending] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<"pipeline" | "table" | "checks" | "cross_org">("pipeline");

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
      // Enforces AES-256-GCM encryption, HMAC-SHA-256 pseudonymization, and 15 Pre-Send Security Validation checks.
      const result = runPreSendPipeline(parsed, {
        ipMode,
        locationMode,
      });
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
      await api.v1.ingestProtectedEvent(report.safeArtifact);
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
                Part 30 — AES-256-GCM Protection & Transformation Viewer
              </h1>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Field-level AES-256-GCM encryption, keyed HMAC-SHA-256 correlation, privacy-preserving geolocation coarsening, and 15 pre-send checks.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="px-3 py-1 bg-emerald-50 border border-emerald-200 rounded-lg text-xs font-bold text-emerald-800 flex items-center gap-1.5">
              <Lock className="h-4 w-4 text-emerald-600" />
              <span>Zero Raw Data Egress Enforced</span>
            </span>
          </div>
        </div>

        {/* Security Terminology Banner (Part 30 Mandatory Distinction) */}
        <div className="bg-gradient-to-r from-slate-900 to-indigo-950 rounded-xl p-4 text-white shadow-md border border-indigo-900/50">
          <div className="flex items-center gap-2 mb-2 text-indigo-300">
            <Key className="h-4 w-4" />
            <span className="text-xs font-bold uppercase tracking-wider">
              Important Security Terminology & Primitive Architecture
            </span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            <div className="bg-white/10 rounded-lg p-2.5 border border-white/10">
              <span className="font-bold text-amber-300 block mb-0.5">AES = Encryption</span>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                <span className="font-semibold text-white">AES-256-GCM</span> provides authenticated encryption for sensitive fields that must be recovered by authorized components. Nonce/IV is unique per operation. <em className="text-amber-200">Never describe as &quot;AES hashing&quot;.</em>
              </p>
            </div>
            <div className="bg-white/10 rounded-lg p-2.5 border border-white/10">
              <span className="font-bold text-sky-300 block mb-0.5">SHA-256 = Hashing</span>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                Cryptographic one-way integrity digest. Does not preserve key correlation alone, and plain SHA-256 is vulnerable to IP dictionary reversing.
              </p>
            </div>
            <div className="bg-white/10 rounded-lg p-2.5 border border-white/10">
              <span className="font-bold text-emerald-300 block mb-0.5">HMAC-SHA-256 = Keyed Pseudonymization</span>
              <p className="text-slate-300 text-[11px] leading-relaxed">
                Keyed deterministic one-way pseudonymization: <span className="font-mono text-emerald-200">HMAC-SHA-256(secret, normalized_ip)</span>. Enables cross-event correlation without revealing raw IP.
              </p>
            </div>
          </div>
        </div>

        {/* Controls: Presets & Protection Policies */}
        <div className="bg-slate-50 p-3.5 rounded-xl border border-slate-200 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-bold text-slate-500">Preset Scenario:</span>
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

            {/* Policy Selectors */}
            <div className="flex flex-wrap items-center gap-4 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="text-slate-500 font-bold">IP Protection:</span>
                <select
                  value={ipMode}
                  onChange={(e: any) => setIpMode(e.target.value)}
                  className="bg-white border border-slate-200 rounded-lg px-2 py-1 font-semibold text-slate-800 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                >
                  <option value="HMAC-SHA-256">HMAC-SHA-256 (Default)</option>
                  <option value="AES-256-GCM">AES-256-GCM (Encrypted)</option>
                  <option value="REMOVE">REMOVE (Strip)</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-slate-500 font-bold">Location Protection:</span>
                <select
                  value={locationMode}
                  onChange={(e: any) => setLocationMode(e.target.value)}
                  className="bg-white border border-slate-200 rounded-lg px-2 py-1 font-semibold text-slate-800 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                >
                  <option value="COARSEN">COARSEN (AP_REGION_01)</option>
                  <option value="AES-256-GCM">AES-256-GCM (Encrypted)</option>
                  <option value="REMOVE">REMOVE (Strip)</option>
                </select>
              </div>
            </div>
          </div>
        </div>

        {/* View Navigation Tabs */}
        <div className="flex border-b border-slate-200 text-xs font-bold gap-6">
          <button
            onClick={() => setActiveTab("pipeline")}
            className={`pb-2.5 transition flex items-center gap-1.5 border-b-2 ${
              activeTab === "pipeline"
                ? "border-indigo-600 text-indigo-600"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <Layers className="h-4 w-4" />
            <span>Interactive 3-Stage Pipeline</span>
          </button>
          <button
            onClick={() => setActiveTab("table")}
            className={`pb-2.5 transition flex items-center gap-1.5 border-b-2 ${
              activeTab === "table"
                ? "border-indigo-600 text-indigo-600"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <Database className="h-4 w-4" />
            <span>Transformation Viewer Table</span>
          </button>
          <button
            onClick={() => setActiveTab("checks")}
            className={`pb-2.5 transition flex items-center gap-1.5 border-b-2 ${
              activeTab === "checks"
                ? "border-indigo-600 text-indigo-600"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <ShieldCheck className="h-4 w-4" />
            <span>15 Pre-Send Security Checks</span>
            {report && (
              <span
                className={`ml-1 text-[10px] px-1.5 py-0.2 rounded font-bold ${
                  report.preSendValidation.status === "SAFE"
                    ? "bg-emerald-100 text-emerald-800"
                    : "bg-rose-100 text-rose-800"
                }`}
              >
                {report.preSendValidation.checksPassed}/15
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab("cross_org")}
            className={`pb-2.5 transition flex items-center gap-1.5 border-b-2 ${
              activeTab === "cross_org"
                ? "border-indigo-600 text-indigo-600"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <Globe className="h-4 w-4" />
            <span>Cross-Organization Architecture</span>
          </button>
        </div>

        {/* Tab 1: Interactive 3-Stage Pipeline Display */}
        {activeTab === "pipeline" && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
            {/* Stage 1: Raw Local Event */}
            <div className="lg:col-span-5 bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col h-[580px]">
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
                  Raw telemetry with sensitive IP and location. Evaluated and sanitized locally before any transmission.
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
                  Mode: IP = <strong className="text-indigo-600">{ipMode}</strong>, Geo = <strong className="text-indigo-600">{locationMode}</strong>
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
            <div className="lg:col-span-3 bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col h-[580px] p-4 justify-between">
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
                      Click &apos;Run Pre-Send Pipeline&apos; to execute field encryption, pseudonymization, and 15 validation checks.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between items-center py-1 border-b border-slate-100">
                      <span className="text-slate-600 font-medium">15 Pre-Send Checks:</span>
                      <span
                        className={`font-bold flex items-center gap-1 ${
                          report.preSendValidation.status === "SAFE" ? "text-emerald-600" : "text-rose-600"
                        }`}
                      >
                        {report.preSendValidation.status === "SAFE" ? (
                          <CheckCircle className="h-3.5 w-3.5" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5" />
                        )}
                        <span>{report.preSendValidation.checksPassed} / 15 Passed</span>
                      </span>
                    </div>

                    <div className="flex justify-between items-center py-1 border-b border-slate-100">
                      <span className="text-slate-600 font-medium">IP Protection:</span>
                      <span className="font-semibold text-indigo-700">{ipMode}</span>
                    </div>

                    <div className="flex justify-between items-center py-1 border-b border-slate-100">
                      <span className="text-slate-600 font-medium">Geolocation:</span>
                      <span className="font-semibold text-indigo-700">{locationMode}</span>
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
                      <span className="text-slate-600 font-medium">Sensitive Fields:</span>
                      <span className="font-semibold text-slate-800">
                        {report.sensitiveFieldsCount} protected
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
            <div className="lg:col-span-4 bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col h-[580px]">
              <div className="p-3.5 border-b border-slate-200 bg-slate-50/50 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-600" />
                  <span className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                    Verified Safe Artifact
                  </span>
                </div>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200">
                  Protected Representation
                </span>
              </div>

              <div className="p-3 flex-1 flex flex-col">
                <p className="text-[11px] text-slate-500 mb-2">
                  Sanitized, encrypted, coarsened artifact. Raw IPs and GPS coordinates never cross the boundary.
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
                      Execute the pipeline. If any blocking check fails, no artifact is created and transmission is strictly blocked.
                    </span>
                  </div>
                )}
              </div>

              <div className="p-3 border-t border-slate-200 bg-slate-50/50 flex justify-between items-center text-[11px] text-slate-500">
                <span className="font-mono text-[10px]">Wire: POST /api/v1/events</span>
                <span className="font-mono text-[10px]">AES-256-GCM + HMAC-SHA-256</span>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Transformation Viewer Table (Part 30 Requirement) */}
        {activeTab === "table" && (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-200 bg-slate-50 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-800">
                  Field-Level Transformation Comparison Table
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Demonstrating raw input telemetry vs protected representation dispatched to the Central Server.
                </p>
              </div>
              <span className="px-2.5 py-1 bg-indigo-50 border border-indigo-200 text-indigo-700 text-xs font-bold rounded-lg">
                Part 30 Specification
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-100/60 font-bold text-slate-700 uppercase tracking-wider text-[11px]">
                    <th className="py-3 px-4">Field</th>
                    <th className="py-3 px-4">Original (Raw Input)</th>
                    <th className="py-3 px-4">Transformation</th>
                    <th className="py-3 px-4">Protected Representation</th>
                    <th className="py-3 px-4">Security Type</th>
                    <th className="py-3 px-4">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {report?.transformationTable?.map((row, idx) => (
                    <tr key={idx} className="hover:bg-slate-50/80 transition">
                      <td className="py-3 px-4 font-bold text-slate-800">{row.field}</td>
                      <td className="py-3 px-4 font-mono text-slate-600 bg-rose-50/40 rounded">
                        {row.original}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded font-bold text-[11px] ${
                            row.transformation === "AES-256-GCM"
                              ? "bg-amber-100 text-amber-800 border border-amber-200"
                              : row.transformation === "HMAC-SHA-256"
                              ? "bg-indigo-100 text-indigo-800 border border-indigo-200"
                              : row.transformation === "COARSENED"
                              ? "bg-emerald-100 text-emerald-800 border border-emerald-200"
                              : row.transformation === "REMOVED"
                              ? "bg-rose-100 text-rose-800 border border-rose-200"
                              : "bg-slate-100 text-slate-700"
                          }`}
                        >
                          {row.transformation}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-800 max-w-xs truncate" title={row.protected}>
                        {row.protected}
                      </td>
                      <td className="py-3 px-4 text-slate-600">{row.securityType}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                            row.status === "ENCRYPTED"
                              ? "bg-amber-50 text-amber-700"
                              : row.status === "PSEUDONYMIZED"
                              ? "bg-indigo-50 text-indigo-700"
                              : row.status === "COARSENED"
                              ? "bg-emerald-50 text-emerald-700"
                              : row.status === "REMOVED"
                              ? "bg-rose-50 text-rose-700"
                              : "bg-slate-50 text-slate-700"
                          }`}
                        >
                          {row.status}
                        </span>
                      </td>
                    </tr>
                  )) || (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-400">
                        Please run the Pre-Send Pipeline to populate the live transformation viewer table.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="p-3 bg-slate-50 border-t border-slate-200 text-slate-500 text-[11px] flex items-center justify-between">
              <span>Actual encryption keys and HMAC secrets are stored strictly server-side and never displayed.</span>
              <span className="font-mono text-slate-700 font-semibold">Key ID: privacy-key-v1</span>
            </div>
          </div>
        )}

        {/* Tab 3: 15 Pre-Send Security Checks (Part 30 Requirement) */}
        {activeTab === "checks" && (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
              <div>
                <h2 className="text-sm font-bold text-slate-800">
                  Pre-Send Security Validation Engine (15 Strict Checks)
                </h2>
                <p className="text-xs text-slate-500">
                  Before any event is emitted outside the organization, the final outgoing payload is inspected against all 15 privacy boundaries.
                </p>
              </div>
              {report && (
                <div
                  className={`px-3 py-1 rounded-lg text-xs font-bold border flex items-center gap-1.5 ${
                    report.preSendValidation.status === "SAFE"
                      ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                      : "bg-rose-50 text-rose-800 border-rose-200"
                  }`}
                >
                  {report.preSendValidation.status === "SAFE" ? (
                    <CheckCircle className="h-4 w-4 text-emerald-600" />
                  ) : (
                    <XCircle className="h-4 w-4 text-rose-600" />
                  )}
                  <span>
                    Status: {report.preSendValidation.status} ({report.preSendValidation.checksPassed}/15 Passed)
                  </span>
                </div>
              )}
            </div>

            {!report ? (
              <div className="text-center py-12 text-slate-400">
                <Lock className="h-8 w-8 mx-auto mb-2 text-slate-300 stroke-1" />
                <p className="text-xs font-semibold text-slate-600">No Check Data Available</p>
                <p className="text-[11px] text-slate-400">Click &apos;Run Pre-Send Pipeline&apos; to run the 15 security checks.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                {report.preSendValidation.checks.map((chk) => (
                  <div
                    key={chk.id}
                    className={`p-3 rounded-lg border transition ${
                      chk.passed
                        ? "bg-emerald-50/40 border-emerald-200 text-slate-800"
                        : "bg-rose-50/60 border-rose-200 text-slate-900"
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold flex items-center gap-1.5">
                        <span className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold bg-white border border-slate-200">
                          {chk.id}
                        </span>
                        <span>{chk.name}</span>
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1 ${
                          chk.passed
                            ? "bg-emerald-100 text-emerald-800"
                            : "bg-rose-100 text-rose-800"
                        }`}
                      >
                        {chk.passed ? <Check className="h-3 w-3" /> : <XCircle className="h-3 w-3" />}
                        <span>{chk.passed ? "PASSED" : "FAILED"}</span>
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-600 pl-6">{chk.details}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Cross-Organization Example Architecture (KL University -> GITAM) */}
        {activeTab === "cross_org" && (
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-5 space-y-6">
            <div>
              <h2 className="text-sm font-bold text-slate-800">
                Cross-Organization Threat Sharing Workflow
              </h2>
              <p className="text-xs text-slate-500 mt-0.5">
                Demonstrating secure collaborative threat detection between KL University, the Central Server, and GITAM without raw IP or precise GPS exposure.
              </p>
            </div>

            {/* Visual Architecture Flow */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center">
              {/* Node 1: KL University */}
              <div className="bg-indigo-50/60 rounded-xl p-4 border border-indigo-100 space-y-2">
                <div className="flex items-center gap-2 text-indigo-900 font-bold text-xs uppercase tracking-wider">
                  <Server className="h-4 w-4 text-indigo-600" />
                  <span>KL University (Origin)</span>
                </div>
                <div className="bg-white p-2.5 rounded-lg border border-indigo-100 font-mono text-[11px] space-y-1">
                  <div className="text-rose-600 font-semibold">RAW EVENT:</div>
                  <div>source_ip: 192.168.25.44</div>
                  <div>lat/lon: 16.5062, 80.6480</div>
                  <div>event: Port Scan</div>
                </div>
                <span className="text-[10px] text-indigo-700 block font-medium">Local DMZ Edge Agent</span>
              </div>

              {/* Arrow 1 */}
              <div className="hidden md:flex flex-col items-center justify-center text-slate-400 space-y-1">
                <span className="text-[10px] font-bold uppercase text-slate-500">Local Egress Gate</span>
                <ArrowRight className="h-6 w-6 text-indigo-500" />
                <span className="text-[9px] text-center text-slate-400">Zero Raw Egress</span>
              </div>

              {/* Node 2: Privacy Gateway */}
              <div className="bg-amber-50/60 rounded-xl p-4 border border-amber-100 space-y-2">
                <div className="flex items-center gap-2 text-amber-900 font-bold text-xs uppercase tracking-wider">
                  <ShieldCheck className="h-4 w-4 text-amber-600" />
                  <span>Privacy Gateway</span>
                </div>
                <div className="bg-white p-2.5 rounded-lg border border-amber-100 font-mono text-[11px] space-y-1">
                  <div className="text-amber-700 font-semibold">TRANSFORM:</div>
                  <div className="text-indigo-700">HMAC-SHA-256 (IP)</div>
                  <div className="text-emerald-700">COARSEN (AP_REGION_01)</div>
                  <div className="text-amber-700">AES-256-GCM (Location)</div>
                </div>
                <span className="text-[10px] text-amber-700 block font-medium">Boundary Protection</span>
              </div>

              {/* Arrow 2 */}
              <div className="hidden md:flex flex-col items-center justify-center text-slate-400 space-y-1">
                <span className="text-[10px] font-bold uppercase text-slate-500">Dispatched Wire</span>
                <ArrowRight className="h-6 w-6 text-emerald-500" />
                <span className="text-[9px] text-center text-slate-400">Protected Token Only</span>
              </div>

              {/* Node 3: Central Server */}
              <div className="bg-emerald-50/60 rounded-xl p-4 border border-emerald-100 space-y-2">
                <div className="flex items-center gap-2 text-emerald-900 font-bold text-xs uppercase tracking-wider">
                  <Database className="h-4 w-4 text-emerald-600" />
                  <span>Central Server</span>
                </div>
                <div className="bg-white p-2.5 rounded-lg border border-emerald-100 font-mono text-[11px] space-y-1">
                  <div className="text-emerald-700 font-semibold">STORED DATA:</div>
                  <div className="truncate" title="hmac-sha256:v1:7f3b...">source: hmac-sha256:v1:...</div>
                  <div>location_zone: AP_REGION_01</div>
                  <div>threat: Port Scan (HIGH)</div>
                </div>
                <span className="text-[10px] text-emerald-700 block font-medium">Zero Raw Retention</span>
              </div>

              {/* Node 4: GITAM (Peer View) */}
              <div className="bg-purple-50/60 rounded-xl p-4 border border-purple-100 space-y-2">
                <div className="flex items-center gap-2 text-purple-900 font-bold text-xs uppercase tracking-wider">
                  <Globe className="h-4 w-4 text-purple-600" />
                  <span>GITAM (Peer University)</span>
                </div>
                <div className="bg-white p-2.5 rounded-lg border border-purple-100 font-mono text-[11px] space-y-1">
                  <div className="text-purple-700 font-semibold">PEER VISIBILITY:</div>
                  <div className="text-rose-600 font-bold">X NO RAW IP</div>
                  <div className="text-rose-600 font-bold">X NO PRECISE GPS</div>
                  <div className="text-emerald-700">Protected Correlation ID</div>
                  <div className="text-emerald-700">Zone: AP_REGION_01</div>
                </div>
                <span className="text-[10px] text-purple-700 block font-medium">Collaborative Defense</span>
              </div>
            </div>

            {/* Deep-Dive Technical Explanation */}
            <div className="bg-slate-50 rounded-xl p-4 border border-slate-200 text-xs text-slate-700 space-y-2 leading-relaxed">
              <h3 className="font-bold text-slate-900 flex items-center gap-1.5">
                <HelpCircle className="h-4 w-4 text-indigo-600" />
                <span>Why HMAC-SHA-256 for IP and Coarsening for Geolocation?</span>
              </h3>
              <p>
                When collaborative threat intelligence is shared between distinct institutions (e.g. KL University and GITAM), neither organization permits the other to inspect its internal network topology or track student identities.
              </p>
              <ul className="list-disc pl-4 space-y-1 text-slate-600">
                <li>
                  <strong>Deterministic Correlation:</strong> <span className="font-mono">HMAC-SHA-256</span> ensures that multiple attack events originating from the exact same adversary IP will map to the identical pseudonym across time, permitting anomaly detection and reputation scoring without disclosing the raw IP address.
                </li>
                <li>
                  <strong>Privacy-Preserving Geolocation:</strong> Instead of transmitting precise GPS coordinates (<span className="font-mono">16.5062, 80.6480</span>), coordinates are coarsened to the regional zone <span className="font-mono font-bold text-emerald-700">AP_REGION_01</span>. Threat detection models recognize regional threat waves without compromising exact location privacy.
                </li>
                <li>
                  <strong>Authorized Recovery with AES-256-GCM:</strong> If exact location must be retained for emergency incident response by an authorized component, it is encrypted using authenticated <span className="font-mono">AES-256-GCM</span> with unique nonces (<span className="font-mono">enc:aes256gcm:v1:...</span>), remaining unreadable to unauthorized peers.
                </li>
              </ul>
            </div>
          </div>
        )}
      </div>
    </ClientShell>
  );
}
