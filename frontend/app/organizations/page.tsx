"use client";

import React, { useState, useEffect } from "react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { Organization } from "@/types";
import { Building2, Shield, Plus, CheckCircle, RefreshCw, Server, AlertCircle } from "lucide-react";

export default function OrganizationsPage() {
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [showModal, setShowModal] = useState<boolean>(false);
  const [newOrgId, setNewOrgId] = useState<string>("");
  const [newOrgName, setNewOrgName] = useState<string>("");
  const [newOrgEmail, setNewOrgEmail] = useState<string>("");
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const fetchOrgs = async () => {
    try {
      const data = await api.v1.getOrganizations();
      setOrganizations(data);
    } catch (err: any) {
      console.error("Failed to load organizations:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchOrgs();
  }, []);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newOrgId || !newOrgName) return;
    setSubmitting(true);
    setFeedback(null);
    try {
      await api.v1.registerOrganization({
        org_id: newOrgId.trim(),
        name: newOrgName.trim(),
        contact_email: newOrgEmail.trim() || undefined,
      });
      setFeedback({ type: "success", text: `Organization ${newOrgName} successfully registered!` });
      setNewOrgId("");
      setNewOrgName("");
      setNewOrgEmail("");
      setShowModal(false);
      fetchOrgs();
    } catch (err: any) {
      setFeedback({ type: "error", text: err.message || "Failed to register organization" });
    } finally {
      setSubmitting(false);
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
                <Building2 className="h-5 w-5" />
              </span>
              <h1 className="text-xl font-bold tracking-tight text-slate-900">
                Multi-Tenant Organizations
              </h1>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              Manage participating enterprise entities, isolated edge agents, and strict boundary scopes.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setRefreshing(true);
                fetchOrgs();
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-white border border-slate-200 rounded-lg hover:bg-slate-50 transition shadow-sm"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin text-indigo-600" : ""}`} />
              <span>Refresh</span>
            </button>
            <button
              onClick={() => setShowModal(true)}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition shadow-sm"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>Register Organization</span>
            </button>
          </div>
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

        {/* Organizations Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {loading ? (
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-48 rounded-xl bg-white border border-slate-200 animate-pulse p-5 space-y-4" />
            ))
          ) : organizations.length === 0 ? (
            <div className="col-span-3 text-center py-12 bg-white rounded-xl border border-slate-200">
              <Building2 className="mx-auto h-8 w-8 text-slate-400" />
              <p className="mt-2 text-sm font-semibold text-slate-800">No organizations found</p>
              <p className="text-xs text-slate-500">Register an organization to begin routing edge telemetry.</p>
            </div>
          ) : (
            organizations.map((org) => (
              <div
                key={org.org_id}
                className="bg-white rounded-xl border border-slate-200 hover:border-indigo-300 transition shadow-sm p-5 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="font-bold text-slate-900 text-sm">{org.name}</h3>
                      <p className="text-[11px] font-mono text-slate-500 mt-0.5">{org.org_id}</p>
                    </div>
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
                      {org.status}
                    </span>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-100 grid grid-cols-3 gap-2 text-center">
                    <div className="bg-slate-50 rounded-lg p-2">
                      <span className="block text-[10px] text-slate-500 font-semibold">Agents</span>
                      <span className="text-sm font-bold text-slate-900">{org.active_agents ?? 1}</span>
                    </div>
                    <div className="bg-slate-50 rounded-lg p-2">
                      <span className="block text-[10px] text-slate-500 font-semibold">Events</span>
                      <span className="text-sm font-bold text-slate-900">{org.total_events ?? 0}</span>
                    </div>
                    <div className="bg-slate-50 rounded-lg p-2">
                      <span className="block text-[10px] text-slate-500 font-semibold">Threats</span>
                      <span className="text-sm font-bold text-indigo-700">{org.total_detections ?? 0}</span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
                  <span className="truncate max-w-[150px]">{org.contact_email || "No email"}</span>
                  <span className="text-[10px] font-mono">{new Date(org.created_at).toLocaleDateString()}</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Multi-Tenancy Architecture Guarantee Banner */}
        <div className="bg-gradient-to-r from-slate-50 to-indigo-50/40 rounded-xl border border-slate-200 p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs font-bold text-slate-900">
              <Shield className="h-4 w-4 text-indigo-600" />
              <span>Strict Multi-Organization Tenant Isolation</span>
            </div>
            <p className="text-xs text-slate-600 max-w-2xl leading-relaxed">
              Every protected event, alert, and detection is bound to its originating tenant ID. Edge agents authenticate
              via dedicated HMAC API keys, and analyst access is restricted to authorized organizational boundaries.
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="px-3 py-1 bg-white border border-slate-200 rounded-md text-[11px] font-bold text-slate-700 shadow-sm flex items-center gap-1.5">
              <Server className="h-3 w-3 text-emerald-600" />
              <span>Zero Cross-Tenant Leakage</span>
            </span>
          </div>
        </div>

        {/* Registration Modal */}
        {showModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 backdrop-blur-sm p-4">
            <div className="bg-white rounded-xl border border-slate-200 shadow-2xl max-w-md w-full p-6 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-base font-bold text-slate-900">Register New Organization</h3>
                <button
                  onClick={() => setShowModal(false)}
                  className="text-slate-400 hover:text-slate-600 text-sm font-bold"
                >
                  ✕
                </button>
              </div>

              <form onSubmit={handleRegister} className="space-y-3.5">
                <div>
                  <label className="block text-xs font-bold text-slate-700 mb-1">Organization ID</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. org_logistics_d"
                    value={newOrgId}
                    onChange={(e) => setNewOrgId(e.target.value)}
                    className="w-full px-3 py-2 text-xs border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono"
                  />
                  <span className="text-[10px] text-slate-400">Lowercase, alphanumeric, underscores only.</span>
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-700 mb-1">Organization Display Name</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Global Logistics D"
                    value={newOrgName}
                    onChange={(e) => setNewOrgName(e.target.value)}
                    className="w-full px-3 py-2 text-xs border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold text-slate-700 mb-1">Contact Email</label>
                  <input
                    type="email"
                    placeholder="soc@logistics-d.internal"
                    value={newOrgEmail}
                    onChange={(e) => setNewOrgEmail(e.target.value)}
                    className="w-full px-3 py-2 text-xs border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>

                <div className="pt-3 flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowModal(false)}
                    className="px-3 py-1.5 text-xs font-semibold text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-lg transition"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="px-4 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition shadow-sm disabled:opacity-50"
                  >
                    {submitting ? "Registering..." : "Confirm Registration"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </ClientShell>
  );
}
