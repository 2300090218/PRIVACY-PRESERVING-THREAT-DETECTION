"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  Play,
  RefreshCw,
  CheckCircle2,
  Radio,
  User,
  LogOut,
  LogIn,
} from "lucide-react";
import { api, API_BASE } from "@/lib/api";
import { WSStatus } from "@/types";

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
        if (typeof window !== "undefined") {
          window.dispatchEvent(new CustomEvent("threat-detection:monitoring-toggled", { detail: { isMonitoring: false } }));
        }
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
        if (typeof window !== "undefined") {
          window.dispatchEvent(new CustomEvent("threat-detection:monitoring-toggled", { detail: { isMonitoring: true } }));
        }

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
      <header className="sticky top-0 z-40 w-full bg-slate-900/95 backdrop-blur border-b border-slate-800/80 px-6 py-3 flex items-center justify-between shadow-sm">
        {/* Left: Branding & Subtitle */}
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center justify-center shadow-xs">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-white tracking-tight">
                PRIVACY-PRESERVING THREAT DETECTION
              </h1>
              <span className="text-[10px] font-semibold tracking-wider uppercase px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700">
                Enterprise v1.0
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Collaborative Federated IDS with PII Sanitization & Real-Time Alerts
            </p>
          </div>
        </div>

        {/* Right: Consolidated Environment Indicator, Run Test Action & Single Auth Button */}
        <div className="flex items-center gap-3">
          {/* Consolidated Single Environment Indicator */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-800 text-slate-400 border border-slate-700">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
            <span>Demo Environment</span>
          </div>

          {/* Security Test / Live Telemetry Action Button */}
          <button
            onClick={handleToggleSecurityMonitoring}
            disabled={isLoadingToggle}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all shadow-xs active:scale-[0.98] disabled:opacity-60 cursor-pointer ${
              isMonitoring
                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-rose-500/10 hover:text-rose-400 hover:border-rose-500/30"
                : "bg-indigo-600 hover:bg-indigo-500 text-white"
            }`}
            title={
              isMonitoring
                ? "Continuous Threat Monitoring is active. Click to stop."
                : "Click to run security test simulation"
            }
          >
            {isLoadingToggle ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : isMonitoring ? (
              <span className="flex items-center gap-1.5">
                <Radio className="h-3.5 w-3.5 animate-pulse text-emerald-400" />
                <span>Monitoring Active</span>
                <span className="font-mono text-[10px] text-emerald-300 bg-emerald-950/60 px-1 rounded">
                  #{scanCount}
                </span>
              </span>
            ) : (
              <span className="flex items-center gap-1.5">
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Run Security Test</span>
              </span>
            )}
          </button>

          {/* Single Header Top-Right Auth Button */}
          {currentUser ? (
            <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700">
                <User className="h-3.5 w-3.5 text-indigo-400" />
                <span className="font-mono text-[11px] max-w-[120px] truncate">{currentUser}</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-semibold uppercase tracking-wider">
                  {currentRole}
                </span>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-medium text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 border border-slate-800 hover:border-rose-500/30 transition-colors cursor-pointer"
                title="Sign Out of Operations Console"
              >
                <LogOut className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Sign Out</span>
              </button>
            </div>
          ) : (
            <Link
              href="/login"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors shadow-xs"
            >
              <LogIn className="h-3.5 w-3.5 text-slate-400" />
              <span>Sign In</span>
            </Link>
          )}
        </div>
      </header>

      {/* Floating Test Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 text-white text-xs px-4 py-3 rounded-lg shadow-xl border border-slate-800 flex items-center gap-3 animate-in fade-in slide-in-from-bottom-3 duration-200">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
          <span className="font-medium text-slate-200">{toastMessage}</span>
          <span
            className={`px-1.5 py-0.5 text-[10px] font-medium rounded ${
              isMonitoring
                ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                : "bg-slate-800 text-slate-300 border border-slate-700"
            }`}
          >
            {isMonitoring ? "CONTINUOUS MONITORING" : "TEST MODE"}
          </span>
        </div>
      )}
    </>
  );
}

