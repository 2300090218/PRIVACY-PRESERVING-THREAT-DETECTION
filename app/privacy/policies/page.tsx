"use client";

import React, { useState, useEffect } from "react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { PrivacyPolicyItem } from "@/types";
import { Sliders, Shield, Save, CheckCircle, AlertCircle, RefreshCw } from "lucide-react";

const ACTIONS: Array<"ALLOW" | "REMOVE" | "MASK" | "PSEUDONYMIZE" | "AGGREGATE"> = [
  "ALLOW",
  "REMOVE",
  "MASK",
  "PSEUDONYMIZE",
  "AGGREGATE",
];

const ACTION_DESCRIPTIONS: Record<string, string> = {
  ALLOW: "Permitted through the privacy boundary unmodified if safe.",
  REMOVE: "Completely stripped from telemetry before leaving local boundary.",
  MASK: "Sensitive parts obscured (e.g. 192.168.1.0/24 or user***).",
  PSEUDONYMIZE: "Replaced with cryptographic salted HMAC-SHA256 token.",
  AGGREGATE: "Numeric quantities binned into coarse duration/volume tiers.",
};

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PrivacyPolicyItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [savingId, setSavingId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const fetchPolicies = async () => {
    try {
      const data = await api.v1.getPrivacyPolicies();
      setPolicies(data);
    } catch (err: any) {
      console.error("Failed to load privacy policies:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleActionChange = (policyId: string, newAction: any) => {
    setPolicies((prev) =>
      prev.map((p) => (p.policy_id === policyId ? { ...p, action: newAction } : p))
    );
  };

  const handleSavePolicy = async (policy: PrivacyPolicyItem) => {
    setSavingId(policy.policy_id);
    setFeedback(null);
    try {
      await api.v1.updatePrivacyPolicy(policy.policy_id, {
        action: policy.action,
        parameters: policy.parameters || {},
        is_active: policy.is_active,
      });
      setFeedback({
        type: "success",
        text: `Policy for field '${policy.field_name}' updated to '${policy.action}'!`,
      });
    } catch (err: any) {
      setFeedback({
        type: "error",
        text: err.message || `Failed to update policy for ${policy.field_name}`,
      });
    } finally {
      setSavingId(null);
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
                <Sliders className="h-5 w-5" />
              </span>
              <h1 className="text-xl font-bold tracking-tight text-slate-900">
                Data Minimization Policies
              </h1>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Configure per-field transformation rules executed by the edge Privacy Gateway before central transmission.
            </p>
          </div>

          <button
            onClick={() => {
              setRefreshing(true);
              fetchPolicies();
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition shadow-sm self-start sm:self-auto"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-indigo-600" : ""}`} />
            <span>Refresh Policies</span>
          </button>
        </div>

        {feedback && (
          <div
            className={`p-3 rounded-lg text-xs font-medium flex items-center gap-2 ${
              feedback.type === "success"
                ? "bg-emerald-50 text-emerald-800 border border-emerald-200"
                : "bg-rose-50 text-rose-800 border border-rose-200"
            }`}
          >
            {feedback.type === "success" ? (
              <CheckCircle className="h-4 w-4 text-emerald-600 shrink-0" />
            ) : (
              <AlertCircle className="h-4 w-4 text-rose-600 shrink-0" />
            )}
            <span>{feedback.text}</span>
          </div>
        )}

        {/* Policies Table */}
        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <div className="p-4 border-b border-slate-200 bg-slate-50/50 flex items-center justify-between">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wider">
              Configured Field Transformations ({policies.length})
            </span>
            <span className="text-[11px] text-slate-500">Organization: org_enterprise_a</span>
          </div>

          {loading ? (
            <div className="p-8 text-center space-y-3">
              <RefreshCw className="mx-auto h-6 w-6 text-indigo-600 animate-spin" />
              <p className="text-xs text-slate-500">Loading privacy policies...</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-slate-600 font-bold">
                    <th className="py-3 px-4">Field Name</th>
                    <th className="py-3 px-4">Current Action</th>
                    <th className="py-3 px-4">Behavior Description</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {policies.map((p) => {
                    const isSaving = savingId === p.policy_id;
                    const isForbiddenRaw = ["username", "source_ip", "exact_location"].includes(p.field_name);

                    return (
                      <tr key={p.policy_id} className="hover:bg-slate-50/80 transition">
                        <td className="py-3.5 px-4 font-mono font-bold text-slate-900">
                          {p.field_name}
                          {isForbiddenRaw && (
                            <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-sans font-semibold">
                              Protected PII
                            </span>
                          )}
                        </td>
                        <td className="py-3.5 px-4">
                          <select
                            value={p.action}
                            onChange={(e) => handleActionChange(p.policy_id, e.target.value)}
                            className="px-2.5 py-1 text-xs border border-slate-200 rounded-md bg-white font-semibold text-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                          >
                            {ACTIONS.map((act) => (
                              <option key={act} value={act}>
                                {act}
                              </option>
                            ))}
                          </select>
                        </td>
                        <td className="py-3.5 px-4 text-slate-500 max-w-xs">
                          {ACTION_DESCRIPTIONS[p.action] || "Custom action behavior."}
                        </td>
                        <td className="py-3.5 px-4">
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold ${
                              p.is_active
                                ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                                : "bg-slate-100 text-slate-600"
                            }`}
                          >
                            <span
                              className={`h-1.5 w-1.5 rounded-full ${
                                p.is_active ? "bg-emerald-500" : "bg-slate-400"
                              }`}
                            ></span>
                            {p.is_active ? "ACTIVE" : "INACTIVE"}
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <button
                            onClick={() => handleSavePolicy(p)}
                            disabled={isSaving}
                            className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-lg hover:bg-indigo-100 transition disabled:opacity-50"
                          >
                            <Save className="h-3 w-3" />
                            <span>{isSaving ? "Saving..." : "Save"}</span>
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Policy Principle Banner */}
        <div className="bg-slate-50 rounded-xl border border-slate-200 p-5 flex items-start gap-3">
          <Shield className="h-5 w-5 text-indigo-600 shrink-0 mt-0.5" />
          <div className="text-xs text-slate-600 leading-relaxed space-y-1">
            <span className="font-bold text-slate-900 block">Server-Side Second Safety Boundary Guarantee</span>
            <p>
              Even if a local administrator configures a sensitive field like <code className="font-mono bg-white px-1 py-0.5 rounded border border-slate-200">source_ip</code> or <code className="font-mono bg-white px-1 py-0.5 rounded border border-slate-200">username</code> as <code className="font-mono font-bold text-indigo-600">ALLOW</code>,
              the Central Server API will actively reject the payload with an HTTP 400 Bad Request and record a security violation in the central audit trail.
            </p>
          </div>
        </div>
      </div>
    </ClientShell>
  );
}
