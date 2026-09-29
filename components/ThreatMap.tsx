"use client";

import React, { useState } from "react";
import { Globe, Shield, Activity, Radio, Lock } from "lucide-react";
import { SecurityEvent, Detection } from "@/types";

interface ThreatMapProps {
  events: SecurityEvent[];
  detections: Detection[];
}

interface RegionNode {
  id: string;
  name: string;
  hub: string;
  volumePct: string;
  eventsPerSec: string;
  status: "Guarded" | "Normal" | "Elevated";
  statusColor: string;
  privacyMode: string;
  x: number;
  y: number;
}

const REGION_NODES: RegionNode[] = [
  {
    id: "us-east",
    name: "US East (Ashburn)",
    hub: "Primary Gateway",
    volumePct: "48.2%",
    eventsPerSec: "1,420 ev/s",
    status: "Guarded",
    statusColor: "emerald",
    privacyMode: "Zero-Trust Minimization",
    x: 270,
    y: 135,
  },
  {
    id: "eu-west",
    name: "EU West (Frankfurt)",
    hub: "Federated Relay",
    volumePct: "31.4%",
    eventsPerSec: "890 ev/s",
    status: "Guarded",
    statusColor: "amber",
    privacyMode: "Pseudonymized Tokenization",
    x: 505,
    y: 115,
  },
  {
    id: "apac-east",
    name: "APAC (Tokyo)",
    hub: "Edge Aggregator",
    volumePct: "20.4%",
    eventsPerSec: "640 ev/s",
    status: "Normal",
    statusColor: "indigo",
    privacyMode: "Differential Privacy (ε=0.8)",
    x: 775,
    y: 165,
  },
];

export function ThreatMap({ events, detections }: ThreatMapProps) {
  const [selectedNode, setSelectedNode] = useState<RegionNode>(REGION_NODES[0]);

  return (
    <div className="bg-slate-900/80 rounded-xl border border-slate-800/80 p-5 shadow-sm space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-indigo-400" />
          <h2 className="text-xs font-semibold tracking-wider text-slate-400 uppercase">
            Global Telemetry Origins & Threat Distribution
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-[11px] font-medium text-slate-400 bg-slate-800/80 px-2.5 py-0.5 rounded-full border border-slate-700/60">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            3 Ingestion Regions Online
          </span>
        </div>
      </div>

      {/* SVG World Map Canvas */}
      <div className="relative w-full h-64 sm:h-72 rounded-lg bg-slate-950/90 border border-slate-800/80 overflow-hidden flex items-center justify-center p-2">
        <svg
          viewBox="0 0 1000 440"
          className="w-full h-full select-none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="arcGradient1" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#6366f1" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="arcGradient2" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#a855f7" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#818cf8" stopOpacity="0.8" />
            </linearGradient>
            <radialGradient id="glowUsEast" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="glowEuWest" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="glowApac" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#818cf8" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#818cf8" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Coordinate Grid Lines */}
          <g stroke="#1e293b" strokeWidth="0.8" opacity="0.6">
            <line x1="0" y1="110" x2="1000" y2="110" strokeDasharray="4 6" />
            <line x1="0" y1="220" x2="1000" y2="220" />
            <line x1="0" y1="330" x2="1000" y2="330" strokeDasharray="4 6" />
            <line x1="250" y1="0" x2="250" y2="440" strokeDasharray="4 6" />
            <line x1="500" y1="0" x2="500" y2="440" />
            <line x1="750" y1="0" x2="750" y2="440" strokeDasharray="4 6" />
          </g>

          {/* World Landmass Silhouettes (Accurate stylized low-poly dark slate vector continents) */}
          <g fill="#1e293b" stroke="#334155" strokeWidth="0.75" opacity="0.85">
            {/* North America */}
            <path d="M 120 70 L 150 50 L 220 50 L 280 80 L 310 110 L 290 150 L 260 170 L 230 220 L 205 180 L 170 170 L 140 140 L 110 110 Z" />
            <path d="M 170 45 L 210 30 L 250 40 L 230 48 Z" />
            {/* Greenland */}
            <path d="M 330 35 L 390 28 L 400 65 L 350 75 Z" />
            {/* South America */}
            <path d="M 260 225 L 310 215 L 360 250 L 380 300 L 340 390 L 300 400 L 270 320 L 250 250 Z" />
            {/* Europe */}
            <path d="M 450 65 L 530 60 L 550 95 L 520 135 L 460 135 L 440 100 Z" />
            <path d="M 435 85 L 450 80 L 445 105 L 430 95 Z" />
            {/* Africa */}
            <path d="M 450 155 L 550 150 L 575 220 L 540 330 L 490 330 L 440 240 L 435 180 Z" />
            <path d="M 570 290 L 585 300 L 575 330 L 565 310 Z" />
            {/* Asia */}
            <path d="M 550 60 L 760 55 L 850 90 L 890 140 L 860 180 L 820 180 L 780 230 L 710 230 L 660 180 L 580 150 L 550 100 Z" />
            {/* Japan */}
            <path d="M 855 130 L 875 140 L 865 170 L 845 150 Z" />
            {/* Southeast Asia / Indonesia */}
            <path d="M 720 250 L 765 250 L 805 270 L 755 285 Z" />
            <path d="M 780 285 L 825 285 L 815 305 L 775 300 Z" />
            {/* Australia */}
            <path d="M 750 310 L 850 305 L 865 375 L 815 390 L 760 370 L 740 330 Z" />
            <path d="M 865 375 L 880 390 L 870 405 Z" />
          </g>

          {/* Inter-Region Ingestion & Federated Sync Connection Arcs */}
          <g>
            <path
              d="M 270 135 Q 385 75 505 115"
              fill="none"
              stroke="url(#arcGradient1)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
            />
            <path
              d="M 505 115 Q 640 85 775 165"
              fill="none"
              stroke="url(#arcGradient2)"
              strokeWidth="1.5"
              strokeDasharray="4 4"
            />
            <path
              d="M 270 135 Q 260 210 320 290"
              fill="none"
              stroke="#475569"
              strokeWidth="1"
              strokeDasharray="3 3"
              opacity="0.4"
            />
          </g>

          {/* Regional Nodes / Threat Telemetry Dots */}
          {/* US West Auxiliary Dot */}
          <g>
            <circle cx="190" cy="120" r="4" fill="#38bdf8" opacity="0.8" />
            <text x="190" y="108" fill="#64748b" fontSize="9" fontWeight="500" textAnchor="middle">
              US-West
            </text>
          </g>

          {/* South America Relay Dot */}
          <g>
            <circle cx="320" cy="290" r="4" fill="#64748b" opacity="0.7" />
            <text x="320" y="308" fill="#64748b" fontSize="9" fontWeight="500" textAnchor="middle">
              SA-East
            </text>
          </g>

          {/* Primary Nodes with Active Radar Pulse */}
          {REGION_NODES.map((node) => {
            const isSelected = selectedNode.id === node.id;
            return (
              <g
                key={node.id}
                className="cursor-pointer group"
                onClick={() => setSelectedNode(node)}
              >
                {/* Radar Pulse Circle */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r="16"
                  fill={`url(#${
                    node.statusColor === "emerald"
                      ? "glowUsEast"
                      : node.statusColor === "amber"
                      ? "glowEuWest"
                      : "glowApac"
                  })`}
                  className="animate-pulse"
                />
                {/* Outer selection ring */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={isSelected ? "9" : "7"}
                  fill="none"
                  stroke={
                    node.statusColor === "emerald"
                      ? "#10b981"
                      : node.statusColor === "amber"
                      ? "#f59e0b"
                      : "#818cf8"
                  }
                  strokeWidth={isSelected ? "2" : "1.5"}
                />
                {/* Center Core Dot */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r="3.5"
                  fill="#ffffff"
                />
                {/* Region Label Pill */}
                <text
                  x={node.x}
                  y={node.y + 18}
                  fill={isSelected ? "#ffffff" : "#94a3b8"}
                  fontSize="10"
                  fontWeight="600"
                  textAnchor="middle"
                >
                  {node.name.split(" ")[0]} ({node.volumePct})
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Real-time Telemetry Flyout */}
        <div className="absolute bottom-3 left-3 bg-slate-900/90 backdrop-blur border border-slate-800 rounded-lg px-3 py-2 text-xs flex items-center gap-3 shadow-md">
          <div className="flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                selectedNode.statusColor === "emerald"
                  ? "bg-emerald-400"
                  : selectedNode.statusColor === "amber"
                  ? "bg-amber-400"
                  : "bg-indigo-400"
              }`}
            />
            <span className="font-semibold text-slate-200">{selectedNode.name}</span>
          </div>
          <span className="text-slate-500">|</span>
          <span className="text-slate-400 font-mono text-[11px]">{selectedNode.eventsPerSec}</span>
          <span className="text-slate-500">|</span>
          <span className="text-emerald-400 text-[11px] font-medium flex items-center gap-1">
            <Lock className="h-2.5 w-2.5" />
            {selectedNode.privacyMode}
          </span>
        </div>
      </div>

      {/* Regional Origin Distribution Breakdown Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {REGION_NODES.map((node) => {
          const isSelected = selectedNode.id === node.id;
          return (
            <button
              key={node.id}
              onClick={() => setSelectedNode(node)}
              className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                isSelected
                  ? "bg-slate-800/80 border-slate-700 shadow-xs"
                  : "bg-slate-950/50 border-slate-800/60 hover:bg-slate-900/60 hover:border-slate-700/60"
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-200">{node.name}</span>
                <span className="font-mono text-[11px] font-bold text-indigo-400">
                  {node.volumePct}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between text-[11px] text-slate-400">
                <span>{node.hub}</span>
                <span className="font-mono text-[10px] text-slate-500">{node.eventsPerSec}</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
