"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  AlertTriangle,
  Flame,
  Radio,
  Building2,
  Lock,
  Eye,
  Sliders,
  FileText,
  Activity,
  Network,
  Share2,
} from "lucide-react";

const NAV_ITEMS = [
  { label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
  { label: "Live Threats", href: "/threats", icon: Flame },
  { label: "Real-Time Alerts", href: "/alerts", icon: AlertTriangle },
  { label: "Organizations", href: "/organizations", icon: Building2 },
  { label: "Privacy Center", href: "/privacy", icon: Lock },
  { label: "Transformation Viewer", href: "/privacy/viewer", icon: Eye },
  { label: "Cross-Org Sharing", href: "/privacy/sharing", icon: Share2 },
  { label: "Minimization Policies", href: "/privacy/policies", icon: Sliders },
  { label: "Audit Logs", href: "/audit", icon: FileText },
  { label: "System Health", href: "/health", icon: Activity },
  { label: "Event Telemetry", href: "/events", icon: Radio },
  { label: "Sensor Clients", href: "/clients", icon: Network },
  { label: "Federated Learning", href: "/federated-learning", icon: Share2 },
];

import { IS_DEMO_MODE, isAuthenticated } from "@/lib/config";

const ADMIN_PATHS = ["/organizations", "/privacy/policies", "/audit"];

export function Sidebar() {
  const pathname = usePathname();
  const authed = isAuthenticated();

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col justify-between shrink-0 select-none text-slate-600">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
          Navigation
        </div>
        <nav className="space-y-0.5">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
            const isProtectedAdmin = ADMIN_PATHS.includes(item.href);

            return (
              <Link
                key={item.href}
                href={item.href}
                className={`group flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  isActive
                    ? "bg-indigo-50 text-indigo-700 border border-indigo-100 shadow-xs"
                    : "text-slate-600 hover:text-slate-900 hover:bg-slate-50"
                }`}
              >
                <Icon className={`h-4 w-4 shrink-0 ${isActive ? "text-indigo-600" : "text-slate-400 group-hover:text-slate-600"}`} />
                <span>{item.label}</span>
                {IS_DEMO_MODE && !authed && isProtectedAdmin && (
                  <span
                    className="ml-auto flex items-center text-slate-400 group-hover:text-slate-600 transition-colors"
                    title="Restricted Admin Route"
                    aria-label="Restricted Admin Route"
                  >
                    <Lock className="h-3 w-3" />
                  </span>
                )}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Privacy Guarantee Footer Pill */}
      <div className="p-4 border-t border-slate-200/80">
        <div className="bg-slate-50 p-3 rounded-lg border border-slate-200/80 shadow-xs space-y-1.5">
          <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
            <Lock className="h-3.5 w-3.5 text-emerald-600" />
            <span>Privacy Guard Active</span>
          </div>
          <p className="text-[11px] text-slate-500 leading-tight">
            Telemetry is sanitized locally. Raw training records never leave participating clients.
          </p>
        </div>
      </div>
    </aside>
  );
}
