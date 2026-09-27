"use client";

import React, { useState, useEffect } from "react";
import { FileText, Shield, Filter } from "lucide-react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { AuditLog } from "@/types";
import { IS_DEMO_MODE, isAuthenticated } from "@/lib/config";

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);

  useEffect(() => {
    api.getAuditLogs(50).then(setLogs).catch(console.error);
  }, []);

  return (
    <ClientShell>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Security Audit Log</h1>
          <p className="text-xs text-slate-500">
            Immutable, append-only operational log recording all security, privacy, and training transactions
          </p>
        </div>

        {IS_DEMO_MODE && !isAuthenticated() && (
          <div className="bg-amber-50 border border-amber-200 text-amber-900 text-xs px-4 py-3 rounded-xl flex items-center justify-between shadow-xs">
            <div className="flex items-center gap-2.5">
              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-200 text-amber-900 font-mono">
                PUBLIC DEMO MODE
              </span>
              <span>
                Displaying sanitized public demonstration audit records. Enterprise employee audit trails, internal resource identifiers, and private forensic history require SOC Analyst credentials.
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

        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase tracking-wider font-semibold">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Actor</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Resource</th>
                <th className="px-4 py-3">Resource ID</th>
                <th className="px-4 py-3">Result</th>
                <th className="px-4 py-3">Metadata</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {logs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400">
                    No audit records logged yet
                  </td>
                </tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-4 py-3 text-slate-500 font-mono text-[11px]">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 font-semibold text-slate-800">{log.actor}</td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-indigo-700 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-100 text-[11px]">
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-600">{log.resource}</td>
                    <td className="px-4 py-3 font-mono text-slate-500 text-[11px]">
                      {log.resource_id || "-"}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.result === "SUCCESS"
                            ? "bg-emerald-100 text-emerald-800"
                            : "bg-rose-100 text-rose-800"
                        }`}
                      >
                        {log.result}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-500 font-mono text-[10px] max-w-xs truncate">
                      {JSON.stringify(log.metadata_payload)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </ClientShell>
  );
}
