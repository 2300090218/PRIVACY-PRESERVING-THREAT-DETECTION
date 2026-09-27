"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Navbar } from "@/components/Navbar";
import { Sidebar } from "@/components/Sidebar";
import { useWebSocketTelemetry, WSEventMessage } from "@/lib/websocket";
import { api } from "@/lib/api";
import { HealthCheck } from "@/types";

import { IS_DEMO_MODE } from "@/lib/config";

export function ClientShell({ children }: { children: React.ReactNode }) {
  const [health, setHealth] = useState<HealthCheck | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const fetchHealth = useCallback(async () => {
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch (e) {
      // Backend might be starting
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, 10000);
    return () => clearInterval(interval);
  }, [fetchHealth]);

  const { status: wsStatus } = useWebSocketTelemetry(
    useCallback((msg: WSEventMessage) => {
      // If a new detection or alert arrives, update health / trigger refresh
      if (
        msg.type === "detection.created" ||
        msg.type === "alert.created" ||
        msg.type === "training.completed"
      ) {
        setRefreshTrigger((prev) => prev + 1);
      }
    }, [])
  );

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {IS_DEMO_MODE && (
        <div className="bg-slate-900 border-b border-indigo-500/30 px-6 py-2 flex items-center justify-between text-xs text-slate-300 shrink-0">
          <div className="flex items-center gap-2.5">
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-400 text-slate-950 uppercase tracking-wider font-mono">
              PUBLIC DEMO MODE
            </span>
            <span className="font-medium text-slate-300">
              Sanitized interactive demonstration active. Live organization data & administrative controls are isolated.
            </span>
            <span className="hidden md:inline-block px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-amber-400 border border-slate-700">
              TEST DATA ONLY
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-slate-400 hidden sm:inline">Protected Ingestion Pipeline: ACTIVE</span>
            <a
              href="/login"
              className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 underline underline-offset-2 transition-colors"
            >
              Enterprise Sign In &rarr;
            </a>
          </div>
        </div>
      )}
      <Navbar
        wsStatus={wsStatus}
        mode={health?.mode || "TEST"}
        systemStatus={health?.overall_status || "ACTIVE"}
        onTestExecuted={() => setRefreshTrigger((prev) => prev + 1)}
      />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto bg-slate-50 p-6">
          <div className="max-w-7xl mx-auto space-y-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
