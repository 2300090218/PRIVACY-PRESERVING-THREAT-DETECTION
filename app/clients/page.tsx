"use client";

import React, { useState, useEffect } from "react";
import { Network, Server, ShieldCheck, Clock, Activity, Cpu } from "lucide-react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { ClientDevice } from "@/types";

export default function ClientsPage() {
  const [clients, setClients] = useState<ClientDevice[]>([]);

  useEffect(() => {
    api.getClients().then(setClients).catch(console.error);
  }, []);

  return (
    <ClientShell>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Security Sensor Fleet</h1>
          <p className="text-xs text-slate-500">
            Registered distributed sensor clients participating in telemetry ingestion and federated learning
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {clients.length === 0 ? (
            <div className="col-span-3 bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-400">
              No federated clients registered yet
            </div>
          ) : (
            clients.map((c) => (
              <div
                key={c.client_id}
                className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4 hover:border-slate-300 transition-all"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="p-2 rounded-lg bg-indigo-50 border border-indigo-100 text-indigo-600">
                      <Server className="h-5 w-5" />
                    </div>
                    <div>
                      <h2 className="text-sm font-bold text-slate-900">{c.name}</h2>
                      <span className="text-[11px] font-mono text-slate-400">{c.client_id}</span>
                    </div>
                  </div>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800">
                    {c.status}
                  </span>
                </div>

                <div className="space-y-2 text-xs text-slate-600 bg-slate-50 p-3 rounded-lg border border-slate-100">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Network Subnet:</span>
                    <span className="font-mono text-slate-800 font-semibold">{c.ip_address || "Private VLAN"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Active Model:</span>
                    <span className="font-mono font-bold text-indigo-600">{c.model_version}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Training State:</span>
                    <span className="font-semibold text-slate-800">{c.training_status}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Raw Data Retained:</span>
                    <span className="font-bold text-emerald-600">100% Client Local</span>
                  </div>
                </div>

                <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-400">
                  <span>Last Seen:</span>
                  <span>{new Date(c.last_seen).toLocaleTimeString()}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </ClientShell>
  );
}
