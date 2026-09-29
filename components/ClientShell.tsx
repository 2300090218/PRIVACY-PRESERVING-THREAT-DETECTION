"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Navbar } from "@/components/Navbar";
import { Sidebar } from "@/components/Sidebar";
import { useWebSocketTelemetry, WSEventMessage } from "@/lib/websocket";
import { api } from "@/lib/api";
import { HealthCheck } from "@/types";


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
    <div className="flex flex-col h-full overflow-hidden bg-slate-50 text-slate-900">
      <Navbar
        wsStatus={wsStatus}
        mode={health?.mode || "TEST"}
        systemStatus={health?.overall_status || "ACTIVE"}
        onTestExecuted={() => setRefreshTrigger((prev) => prev + 1)}
      />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto bg-slate-50 p-6 text-slate-900">
          <div className="max-w-7xl mx-auto space-y-6">{children}</div>
        </main>
      </div>
    </div>
  );
}
