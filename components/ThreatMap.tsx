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
    <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-indigo-600" />
          <h2 className="text-xs font-bold tracking-wider text-slate-500 uppercase">
            Global Telemetry Origins & Threat Distribution
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1.5 text-[11px] font-medium text-slate-600 bg-slate-100 px-2.5 py-0.5 rounded-full border border-slate-200">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
            3 Ingestion Regions Online
          </span>
        </div>
      </div>

      {/* SVG World Map Canvas */}
      <div className="relative w-full h-64 sm:h-72 rounded-lg bg-slate-50/70 border border-slate-200 overflow-hidden flex items-center justify-center p-2">
        <svg
          viewBox="0 0 1000 440"
          className="w-full h-full select-none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="arcGradientLight1" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#6366f1" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="arcGradientLight2" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#8b5cf6" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#6366f1" stopOpacity="0.8" />
            </linearGradient>
            <radialGradient id="glowUsEastLight" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="glowEuWestLight" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#f59e0b" stopOpacity="0" />
            </radialGradient>
            <radialGradient id="glowApacLight" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#6366f1" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#6366f1" stopOpacity="0" />
            </radialGradient>
          </defs>

          {/* Coordinate Grid Lines */}
          <g stroke="#e2e8f0" strokeWidth="0.8" opacity="0.8">
            <line x1="0" y1="110" x2="1000" y2="110" strokeDasharray="4 6" />
            <line x1="0" y1="220" x2="1000" y2="220" />
            <line x1="0" y1="330" x2="1000" y2="330" strokeDasharray="4 6" />
            <line x1="250" y1="0" x2="250" y2="440" strokeDasharray="4 6" />
            <line x1="500" y1="0" x2="500" y2="440" />
            <line x1="750" y1="0" x2="750" y2="440" strokeDasharray="4 6" />
          </g>

          {/* World Landmass Silhouettes (Crisp clean vector landmasses in slate-200) */}
          <g fill="#e2e8f0" stroke="#cbd5e1" strokeWidth="0.75">
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
              stroke="url(#arcGradientLight1)"
              strokeWidth="2"
              strokeDasharray="4 4"
            />
            <path
              d="M 505 115 Q 640 85 775 165"
              fill="none"
              stroke="url(#arcGradientLight2)"
              strokeWidth="2"
              strokeDasharray="4 4"
            />
            <path
              d="M 270 135 Q 260 210 320 290"
              fill="none"
              stroke="#94a3b8"
              strokeWidth="1.2"
              strokeDasharray="3 3"
              opacity="0.6"
            />
          </g>

          {/* Regional Nodes / Threat Telemetry Dots */}
          {/* US West Auxiliary Dot */}
          <g>
            <circle cx="190" cy="120" r="4" fill="#0284c7" opacity="0.8" />
            <text x="190" y="108" fill="#64748b" fontSize="9" fontWeight="600" textAnchor="middle">
              US-West
            </text>
          </g>

          {/* South America Relay Dot */}
          <g>
            <circle cx="320" cy="290" r="4" fill="#64748b" opacity="0.8" />
            <text x="320" y="308" fill="#64748b" fontSize="9" fontWeight="600" textAnchor="middle">
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
                  r="18"
                  fill={`url(#${
                    node.statusColor === "emerald"
                      ? "glowUsEastLight"
                      : node.statusColor === "amber"
                      ? "glowEuWestLight"
                      : "glowApacLight"
                  })`}
                  className="animate-pulse"
                />
                {/* Outer selection ring */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={isSelected ? "9" : "7"}
                  fill="#ffffff"
                  stroke={
                    node.statusColor === "emerald"
                      ? "#10b981"
                      : node.statusColor === "amber"
                      ? "#f59e0b"
                      : "#6366f1"
                  }
                  strokeWidth={isSelected ? "2.5" : "2"}
                />
                {/* Center Core Dot */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r="4"
                  fill={
                    node.statusColor === "emerald"
                      ? "#10b981"
                      : node.statusColor === "amber"
                      ? "#f59e0b"
                      : "#6366f1"
                  }
                />
                {/* Region Label Pill */}
                <text
                  x={node.x}
                  y={node.y + 19}
                  fill={isSelected ? "#0f172a" : "#475569"}
                  fontSize="10"
                  fontWeight="700"
                  textAnchor="middle"
                >
                  {node.name.split(" ")[0]} ({node.volumePct})
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Real-time Telemetry Flyout */}
        <div className="absolute bottom-3 left-3 bg-white/95 backdrop-blur border border-slate-200 rounded-lg px-3 py-2 text-xs flex items-center gap-3 shadow-md text-slate-800">
          <div className="flex items-center gap-2">
            <span
              className={`h-2.5 w-2.5 rounded-full ${
                selectedNode.statusColor === "emerald"
                  ? "bg-emerald-500 ring-2 ring-emerald-100"
                  : selectedNode.statusColor === "amber"
                  ? "bg-amber-500 ring-2 ring-amber-100"
                  : "bg-indigo-500 ring-2 ring-indigo-100"
              }`}
            />
            <span className="font-bold text-slate-900">{selectedNode.name}</span>
          </div>
          <span className="text-slate-300">|</span>
          <span className="text-slate-600 font-mono text-[11px] font-semibold">{selectedNode.eventsPerSec}</span>
          <span className="text-slate-300">|</span>
          <span className="text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded text-[11px] font-semibold flex items-center gap-1">
            <Lock className="h-3 w-3" />
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
                  ? "bg-indigo-50/70 border-indigo-200 shadow-xs"
                  : "bg-slate-50 border-slate-200/80 hover:bg-slate-100/80"
              }`}
            >
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-slate-800">{node.name}</span>
                <span className="font-mono text-[11px] font-bold text-indigo-600">
                  {node.volumePct}
                </span>
              </div>
              <div className="mt-1 flex items-center justify-between text-[11px] text-slate-500">
                <span>{node.hub}</span>
                <span className="font-mono text-[10px] text-slate-400">{node.eventsPerSec}</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
