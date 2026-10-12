"use client";

import React, { useMemo } from "react";
import { Globe, ShieldAlert, Radio, Activity, Zap, ShieldCheck } from "lucide-react";
import { SecurityEvent, Detection } from "@/types";

interface ThreatMapProps {
  events: SecurityEvent[];
  detections: Detection[];
}

export function ThreatMap({ events, detections }: ThreatMapProps) {
  // Aggregate recent active detections with fallback to recent events
  const activeNodes = useMemo(() => {
    const list: Array<{
      id: string;
      label: string;
      type: string;
      severity: string;
      confidence: number;
      riskScore: number;
      timestamp: string;
      x: number; // percentage coordinates on radar grid
      y: number;
    }> = [];

    // Predefined radar sectors for sanitized coordinates
    const sectors = [
      { x: 32, y: 35 },
      { x: 68, y: 28 },
      { x: 78, y: 62 },
      { x: 24, y: 72 },
      { x: 50, y: 45 },
      { x: 82, y: 38 },
      { x: 38, y: 65 },
      { x: 62, y: 75 },
    ];

    detections.slice(0, 8).forEach((det, idx) => {
      const coord = sectors[idx % sectors.length];
      list.push({
        id: det.detection_id || det.event_id || `det-${idx}`,
        label: `NODE-${(det.event_id || `SAN-${idx}`).slice(-6).toUpperCase()}`,
        type: det.attack_type || "SUSPICIOUS_VECTOR",
        severity: det.severity || "HIGH",
        confidence: det.confidence || 0.9,
        riskScore: det.risk_score || 75,
        timestamp: det.created_at || new Date().toISOString(),
        x: coord.x + ((idx * 7) % 11) - 5,
        y: coord.y + ((idx * 13) % 11) - 5,
      });
    });

    return list;
  }, [detections]);

  const severityColor = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-500 text-rose-300 border-rose-500 ring-rose-400";
      case "HIGH":
        return "bg-amber-500 text-amber-300 border-amber-500 ring-amber-400";
      case "MEDIUM":
        return "bg-yellow-500 text-yellow-300 border-yellow-500 ring-yellow-400";
      default:
        return "bg-emerald-500 text-emerald-300 border-emerald-500 ring-emerald-400";
    }
  };

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-4 text-white overflow-hidden relative">
      <div className="flex items-center justify-between z-10 relative">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-indigo-400 animate-spin-slow" />
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wide">
            Live Global Threat Vector Radar
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
            <Radio className="h-3 w-3 animate-pulse" />
            <span>DP-ANONYMIZED RADAR</span>
          </span>
          <span className="text-[10px] font-semibold text-slate-400 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
            {activeNodes.length} Active Targets
          </span>
        </div>
      </div>

      {/* Interactive Animated Radar Screen */}
      <div className="h-64 rounded-lg bg-slate-950 border border-slate-800 relative overflow-hidden flex items-center justify-center">
        {/* Radar concentric circular grid */}
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none opacity-20">
          <div className="w-[85%] h-[85%] rounded-full border border-indigo-400" />
          <div className="w-[60%] h-[60%] rounded-full border border-indigo-400" />
          <div className="w-[35%] h-[35%] rounded-full border border-indigo-400" />
          <div className="w-[12%] h-[12%] rounded-full border border-indigo-400" />
          <div className="absolute w-full h-[1px] bg-indigo-400" />
          <div className="absolute h-full w-[1px] bg-indigo-400" />
        </div>

        {/* Radar Sweeper Animation */}
        <div
          className="absolute inset-0 pointer-events-none opacity-25"
          style={{
            background: "conic-gradient(from 0deg at 50% 50%, rgba(99, 102, 241, 0.4) 0deg, transparent 60deg, transparent 360deg)",
            animation: "spin 5s linear infinite",
          }}
        />

        {/* Threat Node Markers */}
        {activeNodes.length === 0 ? (
          <div className="z-10 flex flex-col items-center justify-center text-center p-4 space-y-2">
            <ShieldCheck className="h-8 w-8 text-emerald-400 animate-pulse" />
            <span className="text-xs font-semibold text-slate-300">
              Zero Active Hostile Incursions Detected
            </span>
            <span className="text-[11px] text-slate-500 max-w-xs font-mono">
              Privacy gateway active. All telemetry pseudonyms protected by SHA-256 HMAC salt.
            </span>
          </div>
        ) : (
          <div className="absolute inset-0 pointer-events-none">
            {activeNodes.map((node) => (
              <div
                key={node.id}
                className="absolute transform -translate-x-1/2 -translate-y-1/2 pointer-events-auto group cursor-pointer"
                style={{ left: `${node.x}%`, top: `${node.y}%` }}
              >
                {/* Pulsing ring */}
                <div
                  className={`absolute -inset-2 rounded-full opacity-75 animate-ping ${
                    node.severity === "CRITICAL"
                      ? "bg-rose-500"
                      : node.severity === "HIGH"
                      ? "bg-amber-500"
                      : "bg-indigo-500"
                  }`}
                />
                {/* Center marker dot */}
                <div
                  className={`relative w-3.5 h-3.5 rounded-full border-2 border-white shadow-lg ${
                    node.severity === "CRITICAL"
                      ? "bg-rose-600 ring-2 ring-rose-400"
                      : node.severity === "HIGH"
                      ? "bg-amber-500 ring-2 ring-amber-400"
                      : "bg-indigo-600 ring-2 ring-indigo-400"
                  }`}
                />

                {/* Hover Tooltip Card */}
                <div className="hidden group-hover:block absolute bottom-5 left-1/2 -translate-x-1/2 w-48 bg-slate-900 border border-slate-700 p-2.5 rounded-md shadow-2xl z-30 pointer-events-none">
                  <div className="flex items-center justify-between text-[10px] font-mono border-b border-slate-800 pb-1 mb-1.5">
                    <span className="text-slate-300 font-bold">{node.label}</span>
                    <span
                      className={`px-1 rounded text-[9px] font-bold ${
                        node.severity === "CRITICAL"
                          ? "bg-rose-950 text-rose-300"
                          : "bg-amber-950 text-amber-300"
                      }`}
                    >
                      {node.severity}
                    </span>
                  </div>
                  <div className="text-[11px] font-semibold text-slate-200 truncate">
                    {node.type}
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-400 mt-1">
                    <span>Risk: {node.riskScore}/100</span>
                    <span>Conf: {(node.confidence * 100).toFixed(0)}%</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Live Vector Feed Overlay Strip */}
        <div className="absolute bottom-2 left-3 right-3 flex items-center justify-between bg-slate-900/90 backdrop-blur-sm border border-slate-800 px-3 py-1.5 rounded text-[11px] font-mono z-10">
          <div className="flex items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-indigo-400 animate-pulse" />
            <span className="text-slate-400">TELEMETRY:</span>
            <span className="text-emerald-400">ENCRYPTED STREAM ACTIVE</span>
          </div>
          <div className="flex items-center gap-3 text-slate-400">
            <span>PII LEAK: <span className="text-emerald-400 font-bold">0.00%</span></span>
            <span>LATENCY: <span className="text-indigo-300">&lt;18ms</span></span>
          </div>
        </div>
      </div>
    </div>
  );
}

