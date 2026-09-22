"use client";

import React from "react";
import { Globe, MapPin, ShieldAlert, AlertCircle } from "lucide-react";
import { SecurityEvent, Detection } from "@/types";

interface ThreatMapProps {
  events: SecurityEvent[];
  detections: Detection[];
}

export function ThreatMap({ events, detections }: ThreatMapProps) {
  // Check if any event possesses verified coarse geographic coordinates
  const eventsWithGeo = events.filter((e) => {
    const meta = e.metadata_payload || {};
    return meta.latitude && meta.longitude && meta.country;
  });

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-indigo-600" />
          <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
            Global Threat Origin Intelligence
          </h2>
        </div>
        <span className="text-[11px] font-semibold text-slate-500 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
          Coarse Geolocation Only
        </span>
      </div>

      {eventsWithGeo.length === 0 ? (
        <div className="h-60 rounded-lg bg-slate-50 border-2 border-dashed border-slate-200 flex flex-col items-center justify-center p-6 text-center space-y-2">
          <div className="p-3 rounded-full bg-slate-100 text-slate-400">
            <MapPin className="h-6 w-6" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-700 tracking-wide uppercase">
              LOCATION UNAVAILABLE
            </h3>
            <p className="text-xs text-slate-500 max-w-sm mt-1">
              Active telemetry origins are internal RFC-1918 private subnets or unmapped IP ranges.
              No synthetic countries are invented.
            </p>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded border border-emerald-200 font-medium">
            <AlertCircle className="h-3 w-3" />
            <span>Private IP addresses are salted and pseudonymized locally</span>
          </div>
        </div>
      ) : (
        <div className="h-60 rounded-lg bg-slate-950 p-4 text-white flex flex-col justify-between overflow-hidden relative">
          <div className="space-y-2 z-10">
            <span className="text-xs font-bold uppercase tracking-wider text-indigo-400">
              Resolved Geographic Threat Origins
            </span>
            <div className="space-y-1.5 max-h-40 overflow-y-auto">
              {eventsWithGeo.map((e) => (
                <div
                  key={e.event_id}
                  className="flex items-center justify-between text-xs bg-slate-900/80 px-2.5 py-1.5 rounded border border-slate-800"
                >
                  <div className="flex items-center gap-2">
                    <MapPin className="h-3.5 w-3.5 text-rose-400" />
                    <span className="font-semibold">{e.metadata_payload.country}</span>
                    <span className="text-slate-400">({e.source})</span>
                  </div>
                  <span className="text-[10px] font-mono text-amber-300">
                    {e.metadata_payload.city || "Coarse Region"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
