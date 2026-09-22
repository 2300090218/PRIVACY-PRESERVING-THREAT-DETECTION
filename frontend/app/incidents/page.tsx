"use client";

import React, { useState, useEffect } from "react";
import { FolderGit2, AlertTriangle, ShieldCheck, CheckCircle2 } from "lucide-react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { Incident } from "@/types";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);

  useEffect(() => {
    api.getIncidents().then(setIncidents).catch(console.error);
  }, []);

  return (
    <ClientShell>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Active Security Incidents</h1>
          <p className="text-xs text-slate-500">
            Automated correlation grouping high-confidence alerts into actionable investigation cases
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {incidents.length === 0 ? (
            <div className="col-span-2 bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-400 space-y-2">
              <CheckCircle2 className="h-8 w-8 mx-auto text-slate-300" />
              <p className="text-xs font-semibold">No active security incidents</p>
              <p className="text-[11px]">High severity attacks will automatically correlate here.</p>
            </div>
          ) : (
            incidents.map((inc) => (
              <div
                key={inc.incident_id}
                className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-3"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-100">
                    {inc.incident_id}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      inc.severity === "CRITICAL"
                        ? "bg-rose-100 text-rose-800"
                        : "bg-amber-100 text-amber-800"
                    }`}
                  >
                    {inc.severity}
                  </span>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-slate-900">{inc.title}</h3>
                  <p className="text-xs text-slate-500 mt-1">{inc.summary}</p>
                </div>

                <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
                  <span>Linked Alerts: {inc.related_alerts?.length || 0}</span>
                  <span className="font-semibold text-slate-700">Status: {inc.status}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </ClientShell>
  );
}
