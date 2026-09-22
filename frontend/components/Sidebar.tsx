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
  { label: "Minimization Policies", href: "/privacy/policies", icon: Sliders },
  { label: "Audit Logs", href: "/audit", icon: FileText },
  { label: "System Health", href: "/health", icon: Activity },
  { label: "Event Telemetry", href: "/events", icon: Radio },
  { label: "Sensor Clients", href: "/clients", icon: Network },
  { label: "Federated Learning", href: "/federated-learning", icon: Share2 },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-64 bg-slate-50/80 border-r border-slate-200 flex flex-col justify-between shrink-0 select-none">
      <div className="p-4 space-y-1">
        <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
          Navigation
        </div>
        <nav className="space-y-0.5">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-semibold transition-colors ${
                  isActive
                    ? "bg-white text-indigo-700 shadow-sm border border-slate-200"
                    : "text-slate-600 hover:text-slate-900 hover:bg-slate-100/80"
                }`}
              >
                <Icon className={`h-4 w-4 ${isActive ? "text-indigo-600" : "text-slate-400"}`} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Privacy Guarantee Footer Pill */}
      <div className="p-4 border-t border-slate-200/80">
        <div className="bg-white p-3 rounded-lg border border-slate-200 shadow-sm space-y-1.5">
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
