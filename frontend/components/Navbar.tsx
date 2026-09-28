"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  Play,
  Activity,
  Wifi,
  WifiOff,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Square,
  Radio,
  User,
  LogOut,
  LogIn
} from "lucide-react";
import { api, API_BASE } from "@/lib/api";
import { WSStatus } from "@/types";
import { IS_DEMO_MODE } from "@/lib/config";

interface NavbarProps {
  wsStatus: WSStatus;
  mode: string;
  systemStatus: string;
  onTestExecuted?: () => void;
}

export function Navbar({ wsStatus, mode, systemStatus, onTestExecuted }: NavbarProps) {
  const router = useRouter();
  const [currentUser, setCurrentUser] = useState<string | null>(null);
  const [currentRole, setCurrentRole] = useState<string | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [scanCount, setScanCount] = useState(0);
  const [isLoadingToggle, setIsLoadingToggle] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [lastScenario, setLastScenario] = useState<string | null>(null);
  const clientMonitorIntervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    const syncAuth = () => {
      if (typeof window !== "undefined") {
        const token = localStorage.getItem("token");
        if (token) {
          setCurrentUser(localStorage.getItem("display_name") || localStorage.getItem("user") || "Operator");
          setCurrentRole(localStorage.getItem("role") || "VIEWER");
        } else {
          setCurrentUser(null);
          setCurrentRole(null);
        }
      }
    };
    syncAuth();
    window.addEventListener("auth-change", syncAuth);
    return () => window.removeEventListener("auth-change", syncAuth);
  }, []);

  const handleLogout = async () => {
    try {
      const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;
      await fetch(`${API_BASE}/api/auth/logout`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        credentials: "include",
      }).catch(() => {});
    } finally {
      if (typeof window !== "undefined") {
        localStorage.removeItem("token");
        localStorage.removeItem("role");
        localStorage.removeItem("user");
        localStorage.removeItem("email");
        localStorage.removeItem("display_name");
        window.dispatchEvent(new Event("auth-change"));
      }
      router.push("/login");
    }
  };

  const triggerSingleScan = async () => {
    try {
      const scanResult = await api.runSecurityTest();
      setLastScenario(scanResult.scenario_name);
      setScanCount((prev) => prev + 1);
      setToastMessage(
        `Security Test Executed: ${scanResult.scenario_name} (${scanResult.attack_type}) -> Risk ${scanResult.risk_score}`
      );
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent("threat-detection:test-executed", { detail: scanResult }));
      }
      if (onTestExecuted) {
        onTestExecuted();
      }
      setTimeout(() => setToastMessage(null), 4500);
      return scanResult;
    } catch (err: any) {
      setToastMessage(`Security test failed: ${err.message}`);
      setTimeout(() => setToastMessage(null), 4000);
    }
  };

  // Sync continuous monitoring status with the backend engine
  useEffect(() => {
    let isMounted = true;
    const checkMonitoringStatus = async () => {
      try {
        const status = await api.getContinuousMonitoringStatus();
        if (isMounted && status && status.is_running) {
          setIsMonitoring(true);
          setScanCount(status.total_scans);
          if (status.last_scan) {
            setLastScenario(status.last_scan.scenario_name);
          }
        }
      } catch (_) {}
    };

    checkMonitoringStatus();
    const interval = setInterval(checkMonitoringStatus, 3500);
    return () => {
      isMounted = false;
      clearInterval(interval);
      if (clientMonitorIntervalRef.current) {
        clearInterval(clientMonitorIntervalRef.current);
      }
    };
  }, []);

  const handleToggleSecurityMonitoring = async () => {
    setIsLoadingToggle(true);
    try {
      if (isMonitoring) {
        // Stop continuous monitoring
        if (clientMonitorIntervalRef.current) {
          clearInterval(clientMonitorIntervalRef.current);
          clientMonitorIntervalRef.current = null;
        }
        await api.stopContinuousMonitoring().catch(() => {});
        setIsMonitoring(false);
        setToastMessage(`Security Monitoring Stopped (Completed ${scanCount} scans)`);
        setTimeout(() => setToastMessage(null), 4000);
      } else {
        // Start continuous monitoring
        // 1. Immediate scan for instantaneous dashboard feedback
        await triggerSingleScan();

        // 2. Start server-side continuous monitoring (works when persistent backend is running)
        try {
          await api.startContinuousMonitoring(3.0);
        } catch (_) {}

        setIsMonitoring(true);

        // 3. Fallback: Drive continuous scanning from client to guarantee continuous telemetry on Vercel Serverless
        if (clientMonitorIntervalRef.current) {
          clearInterval(clientMonitorIntervalRef.current);
        }
        clientMonitorIntervalRef.current = setInterval(async () => {
          await triggerSingleScan();
        }, 3500);
      }
    } catch (err: any) {
      setToastMessage(`Monitoring operation failed: ${err.message}`);
      setTimeout(() => setToastMessage(null), 4000);
    } finally {
      setIsLoadingToggle(false);
    }
  };

  return (
    <>
      <header className="sticky top-0 z-40 w-full bg-white/95 backdrop-blur border-b border-slate-200 px-6 py-3 flex items-center justify-between shadow-sm">
        {/* Left: Branding & Subtitle */}
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-indigo-600 flex items-center justify-center text-white shadow-sm shadow-indigo-200">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-slate-900 tracking-tight">
                PRIVACY-PRESERVING THREAT DETECTION
              </h1>
              <span className="text-[10px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
                Enterprise v1.0
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Collaborative Federated IDS with PII Sanitization & Real-Time Alerts
            </p>
          </div>
        </div>

        {/* Right: Operational Status Badges & Test Mode Action Button */}
        <div className="flex items-center gap-3">
          {/* Operational Mode Badge */}
          {IS_DEMO_MODE ? (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-50 text-amber-800 border border-amber-300 shadow-sm">
              <span className="h-2 w-2 rounded-full bg-amber-500 animate-pulse"></span>
              <span>PUBLIC DEMO MODE</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-amber-100 rounded text-amber-900 border border-amber-200">
                TEST DATA ONLY
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-50 text-amber-800 border border-amber-200">
              <span className="h-2 w-2 rounded-full bg-amber-500 animate-pulse"></span>
              <span>{mode === "TEST" ? "TEST MODE" : "LIVE MODE"}</span>
            </div>
          )}

          {/* Continuous Monitoring Active Live Indicator */}
          {isMonitoring && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200 animate-in fade-in duration-300">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span className="font-mono text-[11px] font-bold">LIVE SCANS: #{scanCount}</span>
              {lastScenario && (
                <span className="hidden sm:inline max-w-[130px] truncate text-[10px] text-emerald-600 border-l border-emerald-300 pl-1.5">
                  {lastScenario}
                </span>
              )}
            </div>
          )}

          {/* Real-time Connection / Telemetry Status Badge */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border ${
              wsStatus === "CONNECTED"
                ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                : wsStatus === "RECONNECTING"
                ? "bg-amber-50 text-amber-700 border-amber-200"
                : "bg-indigo-50 text-indigo-700 border-indigo-200"
            }`}
            title={
              wsStatus === "CONNECTED"
                ? "Connected via bidirectional WebSocket stream"
                : "Live telemetry streaming via active HTTP polling fallback"
            }
          >
            {wsStatus === "CONNECTED" ? (
              <Wifi className="h-3.5 w-3.5 text-emerald-600" />
            ) : wsStatus === "RECONNECTING" ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin text-amber-600" />
            ) : (
              <Activity className="h-3.5 w-3.5 text-indigo-600" />
            )}
            <span>{wsStatus === "CONNECTED" ? "WS: LIVE" : "HTTP: POLLING"}</span>
          </div>

          {/* System Health */}
          <div
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border ${
              systemStatus === "ACTIVE"
                ? "bg-blue-50 text-blue-700 border-blue-200"
                : "bg-amber-50 text-amber-700 border-amber-200"
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            <span>SYS: {systemStatus}</span>
          </div>

          {/* Continuous Security Test Monitoring Action Button */}
          <button
            onClick={handleToggleSecurityMonitoring}
            disabled={isLoadingToggle}
            className={`group relative flex items-center gap-2 px-3.5 py-1.5 rounded-md text-xs font-semibold transition-all shadow-sm active:scale-[0.98] disabled:opacity-60 cursor-pointer ${
              isMonitoring
                ? "bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-rose-600 hover:to-red-600 text-white shadow-emerald-200 hover:shadow-rose-200 ring-2 ring-emerald-400/40"
                : "bg-indigo-600 hover:bg-indigo-700 text-white shadow-indigo-200"
            }`}
            title={
              isMonitoring
                ? "Continuous Threat Monitoring is ACTIVE. Click to stop monitoring."
                : "Click to begin continuous live security telemetry monitoring"
            }
          >
            {isLoadingToggle ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : isMonitoring ? (
              <>
                {/* Active monitoring state (Default view) */}
                <span className="flex items-center gap-1.5 group-hover:hidden">
                  <Radio className="h-3.5 w-3.5 animate-pulse text-emerald-200" />
                  <span>MONITORING ACTIVE</span>
                  <span className="px-1.5 py-0.5 rounded bg-black/25 text-[10px] font-mono font-bold tracking-tight">
                    #{scanCount}
                  </span>
                </span>
                {/* Hover state: click to stop */}
                <span className="hidden group-hover:flex items-center gap-1.5">
                  <Square className="h-3.5 w-3.5 fill-current text-rose-200" />
                  <span>STOP MONITORING</span>
                  <span className="px-1.5 py-0.5 rounded bg-black/25 text-[10px] font-mono font-bold tracking-tight">
                    #{scanCount}
                  </span>
                </span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>RUN SECURITY TEST</span>
              </>
            )}
          </button>

          {/* Authenticated User & Session Status */}
          {currentUser ? (
            <div className="flex items-center gap-1.5 pl-2 border-l border-slate-200">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
                <User className="h-3.5 w-3.5 text-indigo-600" />
                <span className="font-mono text-[11px] max-w-[120px] truncate">{currentUser}</span>
                <span className="text-[9px] px-1 py-0.5 rounded bg-indigo-100 text-indigo-800 font-bold uppercase tracking-tight">
                  {currentRole}
                </span>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium text-slate-600 hover:text-rose-600 hover:bg-rose-50 border border-slate-200 transition-colors cursor-pointer"
                title="Sign Out of Operations Console"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Sign Out</span>
              </button>
            </div>
          ) : (
            <Link
              href="/login"
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-semibold bg-indigo-50 text-indigo-700 hover:bg-indigo-100 border border-indigo-200 transition-colors"
            >
              <LogIn className="h-3.5 w-3.5" />
              <span>Sign In</span>
            </Link>
          )}
        </div>
      </header>

      {/* Floating Test Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 text-white text-xs px-4 py-3 rounded-lg shadow-xl border border-slate-700 flex items-center gap-3 animate-in fade-in slide-in-from-bottom-3 duration-200">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
          <span className="font-medium">{toastMessage}</span>
          <span
            className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${
              isMonitoring
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                : "bg-amber-500/20 text-amber-300"
            }`}
          >
            {isMonitoring ? "CONTINUOUS MONITORING" : "TEST MODE"}
          </span>
        </div>
      )}
    </>
  );
}

