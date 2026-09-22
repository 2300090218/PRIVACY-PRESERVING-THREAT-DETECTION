"use client";

import React from "react";
import { Sliders, Database, Shield, Radio, Key } from "lucide-react";
import { ClientShell } from "@/components/ClientShell";

export default function SettingsPage() {
  return (
    <ClientShell>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">Platform Configuration & Policies</h1>
          <p className="text-xs text-slate-500">
            System retention rules, detection parameters, and privacy engine policy thresholds
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Retention Policies */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
              <Database className="h-4 w-4 text-indigo-600" />
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                Configurable Retention Policies
              </h2>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex justify-between items-center p-3 rounded-lg bg-slate-50 border border-slate-100">
                <div>
                  <span className="font-bold text-slate-800">Event Telemetry Retention</span>
                  <p className="text-[11px] text-slate-500">Normalized network flow records</p>
                </div>
                <span className="font-mono font-bold text-indigo-600 bg-white px-2.5 py-1 rounded border border-slate-200">
                  90 Days
                </span>
              </div>

              <div className="flex justify-between items-center p-3 rounded-lg bg-slate-50 border border-slate-100">
                <div>
                  <span className="font-bold text-slate-800">Security Alert Retention</span>
                  <p className="text-[11px] text-slate-500">Alert and incident correlation records</p>
                </div>
                <span className="font-mono font-bold text-indigo-600 bg-white px-2.5 py-1 rounded border border-slate-200">
                  180 Days
                </span>
              </div>

              <div className="flex justify-between items-center p-3 rounded-lg bg-slate-50 border border-slate-100">
                <div>
                  <span className="font-bold text-slate-800">Audit Trail Retention</span>
                  <p className="text-[11px] text-slate-500">Compliance and administrative logs</p>
                </div>
                <span className="font-mono font-bold text-indigo-600 bg-white px-2.5 py-1 rounded border border-slate-200">
                  365 Days
                </span>
              </div>
            </div>
          </div>

          {/* Privacy & Detection Thresholds */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
              <Shield className="h-4 w-4 text-indigo-600" />
              <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                Detection & Privacy Thresholds
              </h2>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex justify-between items-center p-3 rounded-lg bg-slate-50 border border-slate-100">
                <div>
                  <span className="font-bold text-slate-800">Pseudonymization Algorithm</span>
                  <p className="text-[11px] text-slate-500">Deterministic isolated salt hashing</p>
                </div>
                <span className="font-mono font-bold text-slate-700 bg-white px-2 py-1 rounded border border-slate-200">
                  HMAC-SHA256
                </span>
              </div>

              <div className="flex justify-between items-center p-3 rounded-lg bg-slate-50 border border-slate-100">
                <div>
                  <span className="font-bold text-slate-800">Alert Risk Threshold</span>
                  <p className="text-[11px] text-slate-500">Minimum risk score required for alert creation</p>
                </div>
                <span className="font-mono font-bold text-amber-700 bg-amber-50 px-2.5 py-1 rounded border border-amber-200">
                  38.0 / 100
                </span>
              </div>

              <div className="flex justify-between items-center p-3 rounded-lg bg-slate-50 border border-slate-100">
                <div>
                  <span className="font-bold text-slate-800">Federated Strategy</span>
                  <p className="text-[11px] text-slate-500">Sample-weighted parameter aggregation</p>
                </div>
                <span className="font-mono font-bold text-indigo-700 bg-indigo-50 px-2.5 py-1 rounded border border-indigo-200">
                  FedAvg + DP Clip
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </ClientShell>
  );
}
