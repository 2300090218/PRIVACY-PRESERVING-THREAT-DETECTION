"use client";

import React, { useState, useEffect } from "react";
import {
  Lock,
  ShieldCheck,
  EyeOff,
  Database,
  FileCheck,
  AlertCircle,
  Hash,
  Key,
} from "lucide-react";
import { ClientShell } from "@/components/ClientShell";
import { MetricCard } from "@/components/MetricCard";
import { api } from "@/lib/api";
import { PrivacyStatus, PrivacyEvent } from "@/types";

export default function PrivacyPage() {
  const [privacy, setPrivacy] = useState<PrivacyStatus | null>(null);
  const [events, setEvents] = useState<PrivacyEvent[]>([]);

  useEffect(() => {
    api.getPrivacyStatus().then(setPrivacy).catch(console.error);
    api.getPrivacyEvents(30).then(setEvents).catch(console.error);
  }, []);

  return (
    <ClientShell>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Privacy Center & Telemetry Sanitization</h1>
          <p className="text-xs text-slate-500">
            Real-time verification of data minimization, salted pseudonymization, credential redaction, and local isolation
          </p>
        </div>

        {/* SECTION 36: PRIVACY DASHBOARD TILES */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <MetricCard
            title="Raw Data Shared"
            value="NO"
            subtitle="Strictly Client-Local"
            badge="Local Partition Only"
            badgeType="success"
            icon={Lock}
            iconColor="text-emerald-600"
          />
          <MetricCard
            title="Local Training"
            value="ACTIVE"
            subtitle="Nodes train locally"
            badge="FedAvg Only"
            badgeType="success"
            icon={Database}
            iconColor="text-indigo-600"
          />
          <MetricCard
            title="PII Detection"
            value="ACTIVE"
            subtitle="Regex + Token scanner"
            badge={`${privacy?.total_privacy_transformations || 0} Filtered`}
            badgeType="info"
            icon={EyeOff}
            iconColor="text-blue-600"
          />
          <MetricCard
            title="Pseudonymization"
            value="ACTIVE"
            subtitle="HMAC-SHA256 Salted"
            badge={`${privacy?.pseudonymized_fields_count || 0} Tokens`}
            badgeType="success"
            icon={Hash}
            iconColor="text-purple-600"
          />
          <MetricCard
            title="Audit Logging"
            value="ACTIVE"
            subtitle="Immutable Audit Trail"
            badge="Append-Only"
            badgeType="neutral"
            icon={FileCheck}
            iconColor="text-slate-700"
          />
        </div>

        {/* SECTION 37: TECHNICAL CONTROL MAPPING */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                Privacy Controls Implemented
              </h2>
              <p className="text-xs text-slate-500">
                Technical control mapping (Ground-truth architecture; not a legal certification)
              </p>
            </div>
            <span className="text-xs font-semibold px-2.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
              Technical control mapping
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                <ShieldCheck className="h-4 w-4 text-emerald-600" />
                <span>1. Data Minimization</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Raw payloads are stripped prior to storage. Only normalized network flow feature vectors
                (duration, bytes, flags) and derived rates are stored.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                <Key className="h-4 w-4 text-purple-600" />
                <span>2. Salted Pseudonymization</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                User identifiers and internal IPs are deterministically transformed via HMAC-SHA256 using an isolated
                environment secret salt into non-reversible tokens like <code className="text-indigo-600 font-bold">USER-7F31A</code>.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                <Lock className="h-4 w-4 text-rose-600" />
                <span>3. Credential Redaction</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Passwords, secrets, authorization headers, and API keys are strictly masked with <code className="text-rose-600 font-bold">[REDACTED]</code> before any persistence.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                <Database className="h-4 w-4 text-indigo-600" />
                <span>4. Local Federated Training</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Participating clients train local estimators exclusively on their local machines. Only weight parameter updates are shared with the aggregator.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                <FileCheck className="h-4 w-4 text-blue-600" />
                <span>5. Immutable Audit Logging</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Every transformation, authentication attempt, detection, and model update generates an append-only audit trail entry.
              </p>
            </div>

            <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
                <AlertCircle className="h-4 w-4 text-amber-600" />
                <span>6. Retention Controls</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Configurable retention policies (default: 90 days for events, 180 days for alerts) purge aged telemetry automatically.
              </p>
            </div>
          </div>
        </div>

        {/* Live Privacy Transformation Audit Log */}
        <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-3">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
              Recent Privacy Transformation Log
            </h2>
            <span className="text-xs font-medium text-slate-500">
              Audit records generated by the Privacy Engine
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase font-semibold">
                <tr>
                  <th className="px-4 py-2.5">Event ID</th>
                  <th className="px-4 py-2.5">Transformation Action</th>
                  <th className="px-4 py-2.5">Fields Sanitized</th>
                  <th className="px-4 py-2.5">Technique</th>
                  <th className="px-4 py-2.5">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-400">
                      No privacy transformation events logged yet
                    </td>
                  </tr>
                ) : (
                  events.slice(0, 8).map((pe) => (
                    <tr key={pe.id} className="hover:bg-slate-50/80">
                      <td className="px-4 py-2.5 font-mono font-bold text-slate-800">{pe.event_id}</td>
                      <td className="px-4 py-2.5">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            pe.action === "REDACTED"
                              ? "bg-rose-100 text-rose-800"
                              : "bg-purple-100 text-purple-800"
                          }`}
                        >
                          {pe.action}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-slate-600">
                        {pe.fields_transformed?.join(", ")}
                      </td>
                      <td className="px-4 py-2.5 text-slate-600 font-mono text-[11px]">{pe.technique}</td>
                      <td className="px-4 py-2.5 text-slate-400">
                        {new Date(pe.timestamp).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </ClientShell>
  );
}
