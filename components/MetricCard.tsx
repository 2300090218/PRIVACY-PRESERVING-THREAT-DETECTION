import React from "react";
import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  badge?: string;
  badgeType?: "success" | "warning" | "danger" | "neutral" | "info";
  statusColor?: "green" | "yellow" | "red" | "blue";
  icon?: LucideIcon;
  iconColor?: string;
}

export function MetricCard({
  title,
  value,
  subtitle,
  badge,
  badgeType = "neutral",
  statusColor,
  icon: Icon,
  iconColor = "text-indigo-600",
}: MetricCardProps) {
  const badgeStyles = {
    success: "bg-emerald-50 text-emerald-700 border-emerald-200",
    warning: "bg-amber-50 text-amber-700 border-amber-200",
    danger: "bg-rose-50 text-rose-700 border-rose-200",
    info: "bg-blue-50 text-blue-700 border-blue-200",
    neutral: "bg-slate-100 text-slate-700 border-slate-200",
  };

  const statusDotStyles = {
    green: "bg-emerald-500 ring-4 ring-emerald-50",
    yellow: "bg-amber-500 ring-4 ring-amber-50",
    red: "bg-rose-500 ring-4 ring-rose-50",
    blue: "bg-blue-500 ring-4 ring-blue-50",
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs hover:border-slate-300 hover:shadow-sm transition-all flex flex-col justify-between">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">
          {title}
        </span>
        {Icon && (
          <div className="p-2 rounded-lg bg-slate-50 border border-slate-100">
            <Icon className={`h-4 w-4 ${iconColor}`} />
          </div>
        )}
      </div>

      <div className="mt-3 flex items-baseline justify-between gap-2">
        <div className="flex items-center gap-2">
          {statusColor && (
            <span
              className={`h-2.5 w-2.5 rounded-full ${statusDotStyles[statusColor]}`}
            />
          )}
          <span className="text-2xl font-bold tracking-tight text-slate-900">
            {value}
          </span>
        </div>
        {badge && (
          <span
            className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${badgeStyles[badgeType]}`}
          >
            {badge}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="mt-1.5 text-xs text-slate-500 font-medium">
          {subtitle}
        </p>
      )}
    </div>
  );
}
