"use client";

import React, { useState, useEffect, useCallback } from "react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import {
  Shield,
  ShieldCheck,
  Building2,
  ArrowRight,
  ArrowLeftRight,
  Lock,
  Eye,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Send,
  Zap,
  Server,
  FileCode,
  Radio,
  Sliders,
  Check,
  ChevronRight,
  Info
} from "lucide-react";

interface TransformationRow {
  field: string;
  original: string;
  transformation: string;
  protected: string;
  status: string;
  security_type: string;
}

interface ShareResponseData {
  sender_organization: {
    org_id: string;
    name: string;
    location: string;
    security_status: string;
    is_demo: boolean;
  };
  receiver_organization: {
    org_id: string;
    name: string;
    location: string;
    security_status: string;
    is_demo: boolean;
  };
  synthetic_input_event: any;
  detected_sensitive_fields: string[];
  privacy_transformations: TransformationRow[];
  threat_inspection_result: {
    threat_type: string;
    severity: string;
    risk_score: number;
    confidence: number;
    classification: string;
    mitre_tactic: string;
    protocol: string;
    destination_port: number;
    attack_indicators: string[];
    model_version: string;
  };
  final_outgoing_payload: any;
  presend_validation: any;
  decision: "SEND" | "BLOCK";
  reason: string;
  receiver_view: any;
}

export default function CrossOrgSharingPage() {
  // Routes: KL to GITAM or GITAM to KL
  const [direction, setDirection] = useState<"KL_TO_GITAM" | "GITAM_TO_KL">("KL_TO_GITAM");
  const [simulatedInjection, setSimulatedInjection] = useState<string>("none");
  const [loading, setLoading] = useState<boolean>(true);
  const [sharingResult, setSharingResult] = useState<ShareResponseData | null>(null);
  const [activeTab, setActiveTab] = useState<"transformations" | "raw_event" | "outgoing_payload" | "receiver_view">("transformations");

  const senderOrgId = direction === "KL_TO_GITAM" ? "demo_klef_vijayawada" : "demo_gitam_visakhapatnam";
  const receiverOrgId = direction === "KL_TO_GITAM" ? "demo_gitam_visakhapatnam" : "demo_klef_vijayawada";

  const executeCrossOrgShare = useCallback(async () => {
    setLoading(true);
    try {
      const payload: any = {
        sender_org_id: senderOrgId,
        receiver_org_id: receiverOrgId,
      };

      if (simulatedInjection !== "none") {
        payload.inject_sensitive_field = simulatedInjection;
      }

      const res = await api.v1.shareCrossOrganization(payload);
      setSharingResult(res);
    } catch (err: any) {
      console.error("Cross-organization sharing demonstration failed:", err);
    } finally {
      setLoading(false);
    }
  }, [senderOrgId, receiverOrgId, simulatedInjection]);

  useEffect(() => {
    executeCrossOrgShare();
  }, [executeCrossOrgShare]);

  const handleSwapDirection = () => {
    setDirection((prev) => (prev === "KL_TO_GITAM" ? "GITAM_TO_KL" : "KL_TO_GITAM"));
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
                Cross-Organization Threat Telemetry Sharing
              </h1>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Interactive demonstration of privacy-preserving inter-tenant event sharing between KL University and GITAM.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={executeCrossOrgShare}
              disabled={loading}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition shadow-sm disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin text-indigo-600" : ""}`} />
              <span>Re-run Pipeline</span>
            </button>
            <button
              onClick={handleSwapDirection}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition shadow-sm"
            >
              <ArrowLeftRight className="h-3.5 w-3.5" />
              <span>Swap Sender / Receiver</span>
            </button>
          </div>
        </div>

        {/* Direction Selector & Pre-Send Security Testing Controls */}
        <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-sm flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3 w-full md:w-auto">
            <span className="text-xs font-bold text-slate-700 whitespace-nowrap">Sharing Route:</span>
            <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-lg text-xs font-semibold">
              <button
                onClick={() => setDirection("KL_TO_GITAM")}
                className={`px-3 py-1.5 rounded-md transition ${
                  direction === "KL_TO_GITAM"
                    ? "bg-white text-indigo-700 shadow-sm border border-slate-200 font-bold"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                KL University &rarr; GITAM
              </button>
              <button
                onClick={() => setDirection("GITAM_TO_KL")}
                className={`px-3 py-1.5 rounded-md transition ${
                  direction === "GITAM_TO_KL"
                    ? "bg-white text-indigo-700 shadow-sm border border-slate-200 font-bold"
                    : "text-slate-600 hover:text-slate-900"
                }`}
              >
                GITAM &rarr; KL University
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2.5 w-full md:w-auto justify-end">
            <span className="text-xs font-bold text-slate-700 whitespace-nowrap">Pre-Send Validation Test:</span>
            <select
              value={simulatedInjection}
              onChange={(e) => setSimulatedInjection(e.target.value)}
              className="text-xs font-medium border border-slate-200 rounded-lg px-2.5 py-1.5 bg-white text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="none">Standard Policy (Pass 15 Checks - SEND)</option>
              <option value="password">Inject Prohibited Password (Trigger BLOCK)</option>
              <option value="raw_ip">Inject Plaintext Raw IP (Trigger BLOCK)</option>
              <option value="jwt">Inject Exposed JWT/Token (Trigger BLOCK)</option>
              <option value="precise_gps">Inject Precise GPS Coordinates (Trigger BLOCK)</option>
            </select>
          </div>
        </div>

        {/* Architecture Flow Representation */}
        <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 rounded-2xl p-5 text-white shadow-md">
          <div className="flex flex-col lg:flex-row items-center justify-between gap-4">
            {/* Sender Node */}
            <div className="flex-1 bg-white/10 backdrop-blur-sm border border-white/15 rounded-xl p-4 w-full">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/30 text-indigo-200 border border-indigo-400/30 uppercase tracking-wide">
                  Sender Organization
                </span>
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
              </div>
              <h3 className="text-sm font-bold text-white mt-2">
                {direction === "KL_TO_GITAM" ? "KL University / KLEF" : "GITAM"}
              </h3>
              <p className="text-[11px] text-slate-300 font-mono mt-0.5">
                {direction === "KL_TO_GITAM" ? "demo_klef_vijayawada" : "demo_gitam_visakhapatnam"}
              </p>
              <p className="text-[11px] text-indigo-200 mt-1">
                📍 {direction === "KL_TO_GITAM" ? "Vijayawada, Andhra Pradesh" : "Visakhapatnam, Andhra Pradesh"}
              </p>
              <div className="mt-2.5 pt-2 border-t border-white/10 text-[10px] text-slate-300 flex items-center justify-between">
                <span>Originating Sensor Lab</span>
                <span className="font-mono text-emerald-300">SHIELDED LOCAL</span>
              </div>
            </div>

            {/* Gateway & Central API Nodes */}
            <div className="flex flex-col items-center gap-2 shrink-0 px-2 py-2 lg:py-0">
              <div className="flex items-center gap-2 text-indigo-300">
                <ArrowRight className="h-4 w-4 hidden lg:block" />
                <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-indigo-900/60 border border-indigo-400/40 text-indigo-200 text-center">
                  PRIVACY GATEWAY
                  <br />
                  <span className="text-[9px] text-indigo-300 font-normal">AES-256-GCM &bull; HMAC-SHA-256</span>
                </span>
                <ArrowRight className="h-4 w-4 hidden lg:block" />
              </div>
              <div className="flex items-center gap-1.5 text-[10px] text-slate-400 font-mono">
                <Lock className="h-3 w-3 text-emerald-400" />
                <span>15 Pre-Send Checks Enforced</span>
              </div>
            </div>

            {/* Receiver Node */}
            <div className="flex-1 bg-white/10 backdrop-blur-sm border border-white/15 rounded-xl p-4 w-full">
              <div className="flex items-center justify-between">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/30 text-purple-200 border border-purple-400/30 uppercase tracking-wide">
                  Receiver Organization
                </span>
                <span className="px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-400/30">
                  ZERO RAW ACCESS
                </span>
              </div>
              <h3 className="text-sm font-bold text-white mt-2">
                {direction === "KL_TO_GITAM" ? "GITAM" : "KL University / KLEF"}
              </h3>
              <p className="text-[11px] text-slate-300 font-mono mt-0.5">
                {direction === "KL_TO_GITAM" ? "demo_gitam_visakhapatnam" : "demo_klef_vijayawada"}
              </p>
              <p className="text-[11px] text-purple-200 mt-1">
                📍 {direction === "KL_TO_GITAM" ? "Visakhapatnam, Andhra Pradesh" : "Vijayawada, Andhra Pradesh"}
              </p>
              <div className="mt-2.5 pt-2 border-t border-white/10 text-[10px] text-slate-300 flex items-center justify-between">
                <span>Ingestion Boundary</span>
                <span className="font-mono text-purple-300">PROTECTED PAYLOAD ONLY</span>
              </div>
            </div>
          </div>
        </div>

        {/* Transmission Decision Banner */}
        {sharingResult && (
          <div
            className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs ${
              sharingResult.decision === "SEND"
                ? "bg-emerald-50/80 border-emerald-200 text-emerald-900"
                : "bg-rose-50/90 border-rose-200 text-rose-900"
            }`}
          >
            <div className="flex items-start sm:items-center gap-3">
              <div
                className={`p-2 rounded-lg shrink-0 ${
                  sharingResult.decision === "SEND" ? "bg-emerald-100 text-emerald-700" : "bg-rose-100 text-rose-700"
                }`}
              >
                {sharingResult.decision === "SEND" ? (
                  <CheckCircle2 className="h-5 w-5" />
                ) : (
                  <XCircle className="h-5 w-5" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-black tracking-wide uppercase">
                    Decision: {sharingResult.decision}
                  </span>
                  <span
                    className={`px-2 py-0.2 rounded text-[10px] font-bold ${
                      sharingResult.decision === "SEND"
                        ? "bg-emerald-200 text-emerald-800"
                        : "bg-rose-200 text-rose-800"
                    }`}
                  >
                    {sharingResult.decision === "SEND" ? "AUTHORIZED FOR EGRESS" : "BLOCKED BY PRIVACY GATEWAY"}
                  </span>
                </div>
                <p className="text-xs mt-0.5 opacity-90 leading-relaxed">{sharingResult.reason}</p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-end sm:self-auto shrink-0 font-mono text-[11px]">
              <span className="px-2.5 py-1 rounded bg-white/80 border border-slate-200 font-semibold">
                Risk Score: {sharingResult.threat_inspection_result.risk_score}
              </span>
              <span className="px-2.5 py-1 rounded bg-white/80 border border-slate-200 font-semibold">
                {sharingResult.threat_inspection_result.classification}
              </span>
            </div>
          </div>
        )}

        {/* Main Content Tabs */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
          {/* Tab Navigation */}
          <div className="border-b border-slate-200 bg-slate-50/70 px-4 flex items-center gap-2 overflow-x-auto">
            {[
              { id: "transformations", label: "Visible Transformation Viewer", icon: Eye },
              { id: "raw_event", label: "Synthetic Input Event", icon: FileCode },
              { id: "outgoing_payload", label: "Final Outgoing Payload", icon: Send },
              { id: "receiver_view", label: "Receiver Ingestion View", icon: ShieldCheck },
            ].map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center gap-2 py-3 px-3 text-xs font-semibold border-b-2 transition whitespace-nowrap ${
                    isActive
                      ? "border-indigo-600 text-indigo-700 bg-white"
                      : "border-transparent text-slate-600 hover:text-slate-900"
                  }`}
                >
                  <Icon className={`h-3.5 w-3.5 ${isActive ? "text-indigo-600" : "text-slate-400"}`} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* Tab Content */}
          <div className="p-5">
            {loading ? (
              <div className="py-16 text-center space-y-3">
                <RefreshCw className="h-6 w-6 animate-spin text-indigo-600 mx-auto" />
                <p className="text-xs text-slate-500 font-medium">
                  Executing cryptographic transformations and 15 pre-send checks...
                </p>
              </div>
            ) : !sharingResult ? (
              <div className="py-12 text-center text-xs text-slate-500">
                Failed to load sharing telemetry. Please re-run the pipeline.
              </div>
            ) : (
              <div>
                {/* TAB 1: VISIBLE TRANSFORMATION VIEWER */}
                {activeTab === "transformations" && (
                  <div className="space-y-5">
                    {/* Sensitive Fields Detected Summary */}
                    <div className="bg-slate-50 rounded-xl p-3 border border-slate-200 space-y-2">
                      <div className="flex items-center justify-between text-xs font-bold text-slate-800">
                        <span className="flex items-center gap-1.5">
                          <Info className="h-3.5 w-3.5 text-indigo-600" />
                          <span>Detected Sensitive Fields Requiring Transformation</span>
                        </span>
                        <span className="text-[11px] font-mono text-indigo-700">
                          {sharingResult.detected_sensitive_fields.length} sensitive parameters identified
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {sharingResult.detected_sensitive_fields.map((f, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-white border border-slate-200 text-slate-700"
                          >
                            {f}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Transformation Table */}
                    <div className="border border-slate-200 rounded-xl overflow-hidden shadow-2xs">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold text-slate-700">
                            <th className="py-2.5 px-3">Field Name</th>
                            <th className="py-2.5 px-3">Synthetic Original (Local Only)</th>
                            <th className="py-2.5 px-3">Action</th>
                            <th className="py-2.5 px-3">Privacy-Protected Value (Egress)</th>
                            <th className="py-2.5 px-3">Security & Cryptographic Standard</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-100">
                          {sharingResult.privacy_transformations.map((row, idx) => (
                            <tr key={idx} className="hover:bg-slate-50/60 transition">
                              <td className="py-2.5 px-3 font-semibold text-slate-800 whitespace-nowrap">
                                {row.field}
                              </td>
                              <td className="py-2.5 px-3 font-mono text-slate-600 text-[11px] max-w-[180px] truncate">
                                {row.original}
                              </td>
                              <td className="py-2.5 px-3 whitespace-nowrap">
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                                    row.status === "PSEUDONYMIZED"
                                      ? "bg-blue-50 text-blue-700 border border-blue-200"
                                      : row.status === "COARSENED"
                                      ? "bg-amber-50 text-amber-800 border border-amber-200"
                                      : row.status === "REMOVED"
                                      ? "bg-rose-50 text-rose-700 border border-rose-200"
                                      : row.status === "ENCRYPTED"
                                      ? "bg-purple-50 text-purple-700 border border-purple-200"
                                      : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                                  }`}
                                >
                                  {row.status}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 font-mono text-[11px] text-slate-800 max-w-[260px] truncate">
                                <span className="bg-slate-100 px-1.5 py-0.5 rounded text-indigo-700">
                                  {row.protected}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 text-[11px] text-slate-500">
                                {row.security_type}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {/* Threat Inspection Result */}
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-3 bg-slate-50 rounded-xl p-4 border border-slate-200">
                      <div>
                        <span className="text-[10px] font-semibold text-slate-400 block uppercase">Threat Classification</span>
                        <span className="text-xs font-bold text-rose-600 font-mono">
                          {sharingResult.threat_inspection_result.classification}
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] font-semibold text-slate-400 block uppercase">Threat Type</span>
                        <span className="text-xs font-bold text-slate-800 font-mono">
                          {sharingResult.threat_inspection_result.threat_type}
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] font-semibold text-slate-400 block uppercase">ML Confidence</span>
                        <span className="text-xs font-bold text-indigo-600 font-mono">
                          {(sharingResult.threat_inspection_result.confidence * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div>
                        <span className="text-[10px] font-semibold text-slate-400 block uppercase">MITRE ATT&CK Mapping</span>
                        <span className="text-xs font-bold text-slate-800">
                          {sharingResult.threat_inspection_result.mitre_tactic}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* TAB 2: SYNTHETIC INPUT EVENT */}
                {activeTab === "raw_event" && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs text-slate-600">
                      <span className="font-semibold">Local Originating Event at {sharingResult.sender_organization.name}</span>
                      <span className="font-mono text-[11px] text-indigo-600">Strictly Local Boundary</span>
                    </div>
                    <pre className="p-4 bg-slate-900 text-slate-100 rounded-xl text-xs font-mono overflow-x-auto leading-relaxed border border-slate-800">
                      {JSON.stringify(sharingResult.synthetic_input_event, null, 2)}
                    </pre>
                  </div>
                )}

                {/* TAB 3: FINAL OUTGOING PAYLOAD */}
                {activeTab === "outgoing_payload" && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs text-slate-600">
                      <span className="font-semibold">
                        {sharingResult.decision === "SEND"
                          ? "Authorized Outgoing Payload for Central Transit"
                          : "Transmission Blocked - Zero Egress"}
                      </span>
                      <span
                        className={`font-mono text-[11px] font-bold ${
                          sharingResult.decision === "SEND" ? "text-emerald-600" : "text-rose-600"
                        }`}
                      >
                        Status: {sharingResult.decision}
                      </span>
                    </div>
                    {sharingResult.final_outgoing_payload ? (
                      <pre className="p-4 bg-slate-900 text-slate-100 rounded-xl text-xs font-mono overflow-x-auto leading-relaxed border border-slate-800">
                        {JSON.stringify(sharingResult.final_outgoing_payload, null, 2)}
                      </pre>
                    ) : (
                      <div className="p-8 text-center bg-rose-50 border border-rose-200 rounded-xl text-rose-800 text-xs">
                        <AlertTriangle className="h-6 w-6 mx-auto mb-2 text-rose-600" />
                        <p className="font-bold">Transmission Halted</p>
                        <p className="mt-1">{sharingResult.reason}</p>
                      </div>
                    )}
                  </div>
                )}

                {/* TAB 4: RECEIVER VIEW */}
                {activeTab === "receiver_view" && (
                  <div className="space-y-4">
                    <div className="flex items-center justify-between text-xs text-slate-600">
                      <span className="font-semibold">
                        What {sharingResult.receiver_organization.name} Actually Receives and Ingests:
                      </span>
                      <span className="font-mono text-[11px] text-purple-700 font-bold">
                        Privacy Guarantees Verified
                      </span>
                    </div>

                    {sharingResult.receiver_view ? (
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-purple-50/50 p-4 rounded-xl border border-purple-100 text-xs">
                          <div>
                            <span className="text-[10px] text-purple-900 font-semibold block">Raw IP Accessible?</span>
                            <span className="font-mono font-bold text-emerald-700">NO (Pseudonymized)</span>
                          </div>
                          <div>
                            <span className="text-[10px] text-purple-900 font-semibold block">Exact GPS Accessible?</span>
                            <span className="font-mono font-bold text-emerald-700">NO (Coarsened)</span>
                          </div>
                          <div>
                            <span className="text-[10px] text-purple-900 font-semibold block">Personal Identity?</span>
                            <span className="font-mono font-bold text-emerald-700">NO (Zero Egress)</span>
                          </div>
                          <div>
                            <span className="text-[10px] text-purple-900 font-semibold block">Datacenter Decryptable?</span>
                            <span className="font-mono font-bold text-emerald-700">NO (Key Protected)</span>
                          </div>
                        </div>

                        <pre className="p-4 bg-slate-900 text-slate-100 rounded-xl text-xs font-mono overflow-x-auto leading-relaxed border border-slate-800">
                          {JSON.stringify(sharingResult.receiver_view, null, 2)}
                        </pre>
                      </div>
                    ) : (
                      <div className="p-8 text-center bg-slate-50 border border-slate-200 rounded-xl text-slate-500 text-xs">
                        No payload reached {sharingResult.receiver_organization.name} because transmission was blocked at the sender&apos;s gateway.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Security & Multi-Tenant Guarantees Footnote */}
        <div className="bg-slate-50 rounded-xl border border-slate-200 p-4 text-xs text-slate-600 flex items-start gap-3">
          <Shield className="h-5 w-5 text-indigo-600 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-slate-900">Cryptographic Egress Protection Standards</span>
            <p className="leading-relaxed text-[11px]">
              Every event transmitted between participating educational institutions (KL University and GITAM) passes through the isolated local Privacy Gateway.
              Reversible fields utilize <strong>AES-256-GCM</strong> with unique 96-bit nonces. Identifiers utilize <strong>HMAC-SHA-256</strong> keyed pseudonymization.
              Geolocations are generalized to regional zones, and zero personal credentials or student/faculty PII are permitted to egress.
            </p>
          </div>
        </div>
      </div>
    </ClientShell>
  );
}
