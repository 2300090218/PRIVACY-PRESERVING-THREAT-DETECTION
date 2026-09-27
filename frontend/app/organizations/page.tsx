"use client";

import React, { useState, useEffect } from "react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { Organization, SyntheticPersonRecord } from "@/types";
import { IS_DEMO_MODE, isAuthenticated } from "@/lib/config";
import { Building2, Shield, Plus, CheckCircle, RefreshCw, Server, AlertCircle, Users, GraduationCap, Laptop, Lock, X } from "lucide-react";

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

  // Synthetic records inspection modal state
  const [selectedOrgForRecords, setSelectedOrgForRecords] = useState<Organization | null>(null);
  const [records, setRecords] = useState<SyntheticPersonRecord[]>([]);
  const [loadingRecords, setLoadingRecords] = useState<boolean>(false);
  const [recordsModalOpen, setRecordsModalOpen] = useState<boolean>(false);

  const handleInspectRecords = async (org: Organization) => {
    setSelectedOrgForRecords(org);
    setRecordsModalOpen(true);
    setLoadingRecords(true);
    try {
      const data = await api.v1.getOrganizationRecords(org.org_id);
      setRecords(data.records || []);
    } catch (err) {
      console.error("Failed to fetch synthetic records:", err);
      setRecords([]);
    } finally {
      setLoadingRecords(false);
    }
  };

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
    if (IS_DEMO_MODE && !isAuthenticated()) {
      setFeedback({
        type: "error",
        text: "Organization registration is disabled in Public Demo Mode. Authenticate with Enterprise credentials.",
      });
      return;
    }
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

        {IS_DEMO_MODE && !isAuthenticated() && (
          <div className="bg-amber-50 border border-amber-200 text-amber-900 text-xs px-4 py-3 rounded-xl flex items-center justify-between shadow-xs">
            <div className="flex items-center gap-2.5">
              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-200 text-amber-900 font-mono">
                PUBLIC DEMO MODE
              </span>
              <span>
                Organization provisioning and API key generation are disabled in Public Demo Mode. Authenticate with Enterprise Administrator credentials to register organizations or generate sensor keys.
              </span>
            </div>
            <a
              href="/login"
              className="text-xs font-semibold text-indigo-700 hover:text-indigo-900 underline whitespace-nowrap ml-4"
            >
              Sign In &rarr;
            </a>
          </div>
        )}

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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {loading ? (
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-64 rounded-xl bg-white border border-slate-200 animate-pulse p-5 space-y-4" />
            ))
          ) : organizations.length === 0 ? (
            <div className="col-span-3 text-center py-12 bg-white rounded-xl border border-slate-200">
              <Building2 className="mx-auto h-8 w-8 text-slate-400" />
              <p className="mt-2 text-sm font-semibold text-slate-800">No organizations found</p>
              <p className="text-xs text-slate-500">Register an organization to begin routing edge telemetry.</p>
            </div>
          ) : (
            organizations.map((org) => {
              const isAcademic = org.org_id.includes("klef") || org.org_id.includes("gitam") || org.name.toLowerCase().includes("university");
              return (
                <div
                  key={org.org_id}
                  className={`bg-white rounded-xl border transition shadow-sm p-5 flex flex-col justify-between ${
                    isAcademic ? "border-indigo-200 ring-1 ring-indigo-50 hover:border-indigo-400" : "border-slate-200 hover:border-indigo-300"
                  }`}
                >
                  <div className="space-y-4">
                    {/* Header: Name, ID, Badges */}
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-bold text-slate-900 text-sm">{org.name}</h3>
                        </div>
                        <p className="text-[11px] font-mono text-slate-500 mt-0.5">{org.org_id}</p>
                        
                        {/* Location */}
                        <div className="flex items-center gap-1.5 mt-2 text-[11px] font-medium text-slate-600">
                          <span className="text-indigo-600">📍</span>
                          <span>{org.location || "Andhra Pradesh, India"}</span>
                        </div>
                      </div>

                      <div className="flex flex-col items-end gap-1.5">
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
                          {org.status}
                        </span>
                        {org.demo_status && (
                          <span className="px-2 py-0.5 rounded-full text-[9px] font-bold bg-amber-50 text-amber-800 border border-amber-200 uppercase tracking-wide">
                            {org.demo_status}
                          </span>
                        )}
                        <span className="px-2 py-0.5 rounded text-[9px] font-mono font-semibold bg-indigo-50 text-indigo-700 border border-indigo-100">
                          {org.security_status || "ACTIVE / SHIELDED"}
                        </span>
                      </div>
                    </div>

                    {/* Record Counts Breakdown (Part 1 Mandate) */}
                    <div className="bg-slate-50 rounded-lg p-3 border border-slate-100 space-y-2">
                      <div className="flex items-center justify-between text-[11px] font-bold text-slate-700 pb-1 border-b border-slate-200">
                        <span>Synthetic Records</span>
                        <span className="font-mono text-indigo-700">
                          {org.record_counts?.total_records ? org.record_counts.total_records.toLocaleString() : "Demonstration"}
                        </span>
                      </div>

                      <div className="grid grid-cols-3 gap-2 text-[10px]">
                        <div>
                          <span className="text-slate-400 block font-medium">Students</span>
                          <span className="font-bold text-slate-800">
                            {org.record_counts?.students ? org.record_counts.students.toLocaleString() : "-"}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400 block font-medium">Faculty</span>
                          <span className="font-bold text-slate-800">
                            {org.record_counts?.faculty ? org.record_counts.faculty.toLocaleString() : "-"}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400 block font-medium">IT Staff</span>
                          <span className="font-bold text-slate-800">
                            {org.record_counts?.it_staff ? org.record_counts.it_staff.toLocaleString() : "-"}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400 block font-medium">Sec Staff</span>
                          <span className="font-bold text-slate-800">
                            {org.record_counts?.security_staff ? org.record_counts.security_staff.toLocaleString() : "-"}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400 block font-medium">Admins</span>
                          <span className="font-bold text-slate-800">
                            {org.record_counts?.administrators ? org.record_counts.administrators.toLocaleString() : "-"}
                          </span>
                        </div>
                        <div>
                          <span className="text-slate-400 block font-medium">Agents</span>
                          <span className="font-bold text-emerald-700">
                            {org.record_counts?.security_agents ?? org.active_agents ?? 1}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Operational Telemetry Summary */}
                    <div className="pt-2 grid grid-cols-3 gap-2 text-center">
                      <div className="bg-slate-50/60 rounded-lg p-2 border border-slate-100">
                        <span className="block text-[10px] text-slate-400 font-semibold">Active Agents</span>
                        <span className="text-xs font-bold text-slate-800">{org.active_agents ?? 1}</span>
                      </div>
                      <div className="bg-slate-50/60 rounded-lg p-2 border border-slate-100">
                        <span className="block text-[10px] text-slate-400 font-semibold">Total Events</span>
                        <span className="text-xs font-bold text-slate-800">{org.total_events ?? 0}</span>
                      </div>
                      <div className="bg-slate-50/60 rounded-lg p-2 border border-slate-100">
                        <span className="block text-[10px] text-slate-400 font-semibold">Threats</span>
                        <span className="text-xs font-bold text-indigo-700">{org.total_detections ?? 0}</span>
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
                    <span className="truncate max-w-[150px] font-mono text-[10px]">{org.contact_email || "No email"}</span>
                    <button
                      onClick={() => handleInspectRecords(org)}
                      className="px-2.5 py-1 text-[10px] font-semibold text-indigo-700 bg-indigo-50 border border-indigo-100 hover:bg-indigo-100 rounded-md transition"
                    >
                      Inspect Records &rarr;
                    </button>
                  </div>
                </div>
              );
            })
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

        {/* Synthetic Records Inspection Modal */}
        {recordsModalOpen && selectedOrgForRecords && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm p-4 overflow-y-auto">
            <div className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-3xl w-full p-6 space-y-5 my-8">
              {/* Modal Header */}
              <div className="flex items-start justify-between border-b border-slate-100 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="p-1 rounded bg-indigo-50 border border-indigo-100 text-indigo-600">
                      <Building2 className="h-4 w-4" />
                    </span>
                    <h3 className="text-base font-bold text-slate-900">
                      {selectedOrgForRecords.name}
                    </h3>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200">
                      SYNTHETIC DEMO
                    </span>
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-xs text-slate-500">
                    <span className="font-mono text-indigo-600">{selectedOrgForRecords.org_id}</span>
                    <span>•</span>
                    <span>📍 {selectedOrgForRecords.location}</span>
                    <span>•</span>
                    <span className="text-emerald-700 font-semibold">{selectedOrgForRecords.security_status}</span>
                  </div>
                </div>
                <button
                  onClick={() => {
                    setRecordsModalOpen(false);
                    setSelectedOrgForRecords(null);
                    setRecords([]);
                  }}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Privacy Notice Banner */}
              <div className="bg-indigo-50/70 border border-indigo-100 rounded-xl p-3 flex items-start gap-2.5 text-xs text-indigo-950">
                <Shield className="h-4 w-4 text-indigo-600 shrink-0 mt-0.5" />
                <div className="space-y-0.5">
                  <p className="font-semibold text-indigo-900">Zero Real Personal Data Guarantee</p>
                  <p className="text-indigo-800/80 text-[11px] leading-relaxed">
                    All individuals below are synthetically generated for privacy-preserving demonstration.
                    In accordance with data minimization policies, identifiers are pseudonymized with HMAC-SHA-256
                    before any cross-boundary analysis.
                  </p>
                </div>
              </div>

              {/* Record Category Summary Badges */}
              <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
                {[
                  { label: "Students", count: selectedOrgForRecords.record_counts?.students ?? 0, icon: GraduationCap, color: "text-blue-700 bg-blue-50 border-blue-100" },
                  { label: "Faculty", count: selectedOrgForRecords.record_counts?.faculty ?? 0, icon: Users, color: "text-purple-700 bg-purple-50 border-purple-100" },
                  { label: "IT Staff", count: selectedOrgForRecords.record_counts?.it_staff ?? 0, icon: Laptop, color: "text-amber-700 bg-amber-50 border-amber-100" },
                  { label: "Security Staff", count: selectedOrgForRecords.record_counts?.security_staff ?? 0, icon: Shield, color: "text-emerald-700 bg-emerald-50 border-emerald-100" },
                  { label: "Administrators", count: selectedOrgForRecords.record_counts?.administrators ?? 0, icon: Lock, color: "text-rose-700 bg-rose-50 border-rose-100" },
                  { label: "Agents", count: selectedOrgForRecords.record_counts?.security_agents ?? 1, icon: Server, color: "text-indigo-700 bg-indigo-50 border-indigo-100" },
                ].map((cat, i) => (
                  <div key={i} className={`p-2 rounded-lg border text-center ${cat.color}`}>
                    <span className="block text-[10px] font-medium opacity-80">{cat.label}</span>
                    <span className="text-xs font-bold font-mono">{cat.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>

              {/* Records Table */}
              <div className="border border-slate-200 rounded-xl overflow-hidden">
                <div className="bg-slate-50 px-4 py-2 border-b border-slate-200 flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-700">Synthetic Entity Samples</span>
                  <span className="text-[11px] text-slate-500 font-mono">
                    {records.length} sample records loaded
                  </span>
                </div>

                {loadingRecords ? (
                  <div className="p-8 text-center text-xs text-slate-500 space-y-2">
                    <RefreshCw className="h-5 w-5 animate-spin mx-auto text-indigo-600" />
                    <p>Loading synthetic records from secure repository...</p>
                  </div>
                ) : records.length === 0 ? (
                  <div className="p-8 text-center text-xs text-slate-500">
                    No individual sample records loaded for this organization.
                  </div>
                ) : (
                  <div className="max-h-72 overflow-y-auto divide-y divide-slate-100">
                    {records.map((rec) => (
                      <div key={rec.record_id} className="px-4 py-2.5 flex items-center justify-between hover:bg-slate-50 transition text-xs">
                        <div className="space-y-0.5">
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-semibold text-slate-800 text-[11px]">{rec.record_id}</span>
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-100 text-slate-700 border border-slate-200">
                              {rec.role}
                            </span>
                            <span className="text-[9px] font-mono text-indigo-600 bg-indigo-50 px-1 py-0.5 rounded">
                              {rec.pseudonym}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-500">
                            {rec.department} &bull; {rec.campus}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            {rec.status}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-50 text-amber-800 border border-amber-200">
                            DEMO
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Modal Footer */}
              <div className="flex justify-end pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setRecordsModalOpen(false);
                    setSelectedOrgForRecords(null);
                    setRecords([]);
                  }}
                  className="px-4 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition"
                >
                  Close Inspection
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </ClientShell>
  );
}
