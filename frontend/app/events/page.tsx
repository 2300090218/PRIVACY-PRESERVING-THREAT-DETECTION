"use client";

import React, { useState, useEffect } from "react";
import { Radio, Lock, ShieldCheck, Clock } from "lucide-react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { SecurityEvent } from "@/types";

export default function EventsPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);

  useEffect(() => {
    api.getEvents({ limit: 50 }).then(setEvents).catch(console.error);
  }, []);

  return (
    <ClientShell>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Security Telemetry Stream</h1>
          <p className="text-xs text-slate-500">
            Authorized network flow events normalized and sanitized through the Privacy Engine
          </p>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase tracking-wider font-semibold">
              <tr>
                <th className="px-4 py-3">Event ID</th>
                <th className="px-4 py-3">Client Origin</th>
                <th className="px-4 py-3">Event Type</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Destination</th>
                <th className="px-4 py-3">Protocol</th>
                <th className="px-4 py-3">Privacy Status</th>
                <th className="px-4 py-3">Latency</th>
                <th className="px-4 py-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {events.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400">
                    No security events received yet
                  </td>
                </tr>
              ) : (
                events.map((e) => (
                  <tr key={e.event_id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-4 py-3 font-mono font-bold text-slate-800">
                      {e.event_id}
                      {e.is_test && (
                        <span className="ml-1.5 px-1 py-0.2 rounded text-[9px] font-bold bg-amber-100 text-amber-800">
                          TEST
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-700">{e.client_id}</td>
                    <td className="px-4 py-3 font-semibold text-slate-900">{e.event_type}</td>
                    <td className="px-4 py-3 font-mono text-slate-600">{e.source}</td>
                    <td className="px-4 py-3 font-mono text-slate-600">{e.destination}</td>
                    <td className="px-4 py-3 text-slate-500 font-semibold">{e.protocol}</td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                        <Lock className="h-3 w-3" />
                        <span>Sanitized & Masked</span>
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-slate-600">{e.processing_latency_ms} ms</td>
                    <td className="px-4 py-3 text-slate-400">
                      {new Date(e.timestamp).toLocaleTimeString()}
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
