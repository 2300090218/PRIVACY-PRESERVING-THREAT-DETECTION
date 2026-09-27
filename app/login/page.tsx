"use client";

import React, { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Shield, Lock, User, Key, CheckCircle2, AlertCircle } from "lucide-react";
import { API_BASE } from "@/lib/api";
import { IS_DEMO_MODE } from "@/lib/config";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("AdminPass123!");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [adminNotice, setAdminNotice] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (params.get("reason") === "admin_required") {
        setAdminNotice(
          "Enterprise Administrator credentials required. Multi-tenant organization management, minimization policy configurations, and private audit trails are restricted."
        );
      }
    }
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || err.detail || "Login failed");
      }
      const data = await res.json();
      localStorage.setItem("token", data.access_token);
      localStorage.setItem("role", data.role);
      localStorage.setItem("user", data.username);
      router.push("/dashboard");
    } catch (err: any) {
      setError(err.message || "Failed to authenticate");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-100 flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md bg-white rounded-2xl border border-slate-200 p-8 shadow-sm space-y-6">
        <div className="text-center space-y-2">
          <div className="h-12 w-12 rounded-xl bg-indigo-600 flex items-center justify-center text-white mx-auto shadow-md shadow-indigo-200">
            <Shield className="h-6 w-6" />
          </div>
          <h1 className="text-lg font-bold text-slate-900 tracking-tight">
            PRIVACY-PRESERVING THREAT DETECTION
          </h1>
          <p className="text-xs text-slate-500">
            Enterprise Security Operations & Federated Learning Console
          </p>
        </div>

        {adminNotice && (
          <div className="bg-amber-50 border border-amber-300 text-amber-950 text-xs px-3.5 py-3 rounded-xl flex items-start gap-2.5 shadow-xs">
            <Lock className="h-4 w-4 shrink-0 text-amber-700 mt-0.5" />
            <div className="space-y-1">
              <span className="font-bold tracking-tight block text-amber-900">Enterprise Authentication Required</span>
              <p className="text-[11px] text-amber-800 leading-relaxed">{adminNotice}</p>
            </div>
          </div>
        )}

        {error && (
          <div className="bg-rose-50 border border-rose-200 text-rose-800 text-xs px-3.5 py-2.5 rounded-lg flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0 text-rose-600" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleLogin} className="space-y-4">
          <div className="space-y-1">
            <label className="text-xs font-semibold text-slate-700">Username</label>
            <div className="relative">
              <User className="h-4 w-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-xs font-semibold text-slate-700">Password</label>
            <div className="relative">
              <Key className="h-4 w-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition-colors shadow-sm shadow-indigo-200 disabled:opacity-60"
          >
            {isLoading ? "Authenticating..." : "Sign In to Operations Console"}
          </button>
        </form>

        {IS_DEMO_MODE && (
          <div className="pt-2 border-t border-slate-200 space-y-2">
            <button
              type="button"
              onClick={() => router.push("/dashboard")}
              className="w-full py-2.5 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-900 border border-amber-300 font-semibold text-xs transition-colors flex items-center justify-center gap-2 cursor-pointer shadow-xs"
            >
              <Shield className="h-4 w-4 text-amber-600" />
              <span>Enter Public Demo Mode &rarr;</span>
            </button>
            <p className="text-[10px] text-center text-slate-500 font-medium">
              Access the interactive dashboard with sanitized test data without logging in
            </p>
          </div>
        )}

        <div className="pt-2 border-t border-slate-100 text-center">
          <p className="text-[11px] text-slate-400">
            Pre-configured credentials: <code className="font-semibold text-slate-600">admin</code> / <code className="font-semibold text-slate-600">AdminPass123!</code>
          </p>
        </div>
      </div>
    </div>
  );
}
