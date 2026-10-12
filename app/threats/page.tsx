"use client";

import React, { useState, useEffect } from "react";
import { Flame, ShieldAlert, Cpu, Filter } from "lucide-react";
import { ClientShell } from "@/components/ClientShell";
import { api } from "@/lib/api";
import { Detection } from "@/types";

export default function ThreatsPage() {
  const [detections, setDetections] = useState<Detection[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string>("");

  useEffect(() => {
    api.getDetections({ severity: severityFilter || undefined }).then(setDetections).catch(console.error);
  }, [severityFilter]);

  return (
    <ClientShell>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-900 tracking-tight">Threat Detections Ledger</h1>
            <p className="text-xs text-slate-500">
              Machine learning inference predictions and rule-based heuristic correlations
            </p>
          </div>

          <div className="flex items-center gap-2">
            <Filter className="h-3.5 w-3.5 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-white border border-slate-200 text-slate-700 text-xs rounded-md px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            >
              <option value="">All Severities</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase tracking-wider font-semibold">
              <tr>
                <th className="px-4 py-3">Event ID</th>
                <th className="px-4 py-3">Prediction</th>
                <th className="px-4 py-3">Attack Classification</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">XAI Factors</th>
                <th className="px-4 py-3">Rule Heuristic Matches</th>
                <th className="px-4 py-3">Model Version</th>
                <th className="px-4 py-3">Latency</th>
                <th className="px-4 py-3">Detected At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {detections.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-slate-400">
                    No detections yet
                  </td>
                </tr>
              ) : (
                detections.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="px-4 py-3 font-mono font-bold text-slate-800">{d.event_id}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          d.prediction === "MALICIOUS"
                            ? "bg-rose-100 text-rose-800"
                            : d.prediction === "SUSPICIOUS"
                            ? "bg-amber-100 text-amber-800"
                            : "bg-emerald-100 text-emerald-800"
                        }`}
                      >
                        {d.prediction}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-semibold text-slate-900">{d.attack_type}</td>
                    <td className="px-4 py-3 font-medium text-slate-700">
                      {(d.confidence * 100).toFixed(2)}%
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          d.severity === "CRITICAL"
                            ? "bg-rose-50 text-rose-700 border border-rose-200"
                            : d.severity === "HIGH"
                            ? "bg-amber-50 text-amber-700 border border-amber-200"
                            : "bg-slate-100 text-slate-700"
                        }`}
                      >
                        {d.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      {d.explainability?.top_features && d.explainability.top_features.length > 0 ? (
                        <div className="flex flex-wrap gap-1 max-w-xs">
                          {d.explainability.top_features.slice(0, 2).map((f, i) => (
                            <span
                              key={i}
                              className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-50 text-indigo-700 border border-indigo-200"
                              title={`Contribution: ${f.percentage}, Value: ${f.value}`}
                            >
                              {f.feature.replace(/_/g, " ")}: <b>{f.percentage}</b>
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-slate-400 text-[11px]">Nominal baseline</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-600 max-w-xs truncate">
                      {d.rule_matches && d.rule_matches.length > 0 ? (
                        <span className="text-[11px] text-amber-700 font-mono bg-amber-50 px-1.5 py-0.5 rounded border border-amber-200">
                          {d.rule_matches.join("; ")}
                        </span>
                      ) : (
                        <span className="text-slate-400">None (Pure ML)</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-500 font-mono">{d.model_version}</td>
                    <td className="px-4 py-3 font-mono text-slate-600">{d.processing_latency_ms} ms</td>
                    <td className="px-4 py-3 text-slate-400">
                      {new Date(d.created_at).toLocaleTimeString()}
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
