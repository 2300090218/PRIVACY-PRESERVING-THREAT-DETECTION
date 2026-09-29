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
  iconColor = "text-indigo-400",
}: MetricCardProps) {
  const badgeStyles = {
    success: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    warning: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    danger: "bg-rose-500/10 text-rose-400 border-rose-500/20",
    info: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    neutral: "bg-slate-800 text-slate-400 border-slate-700",
  };

  const statusDotStyles = {
    green: "bg-emerald-400 shadow-xs shadow-emerald-400/50",
    yellow: "bg-amber-400 shadow-xs shadow-amber-400/50",
    red: "bg-rose-400 shadow-xs shadow-rose-400/50",
    blue: "bg-blue-400 shadow-xs shadow-blue-400/50",
  };

  return (
    <div className="bg-slate-900/80 rounded-xl border border-slate-800/80 p-5 shadow-sm hover:border-slate-700/80 transition-all flex flex-col justify-between">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          {title}
        </span>
        {Icon && (
          <div className="p-2 rounded-lg bg-slate-800/80 border border-slate-700/60">
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
          <span className="text-2xl font-bold tracking-tight text-white">
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
        <p className="mt-1.5 text-xs text-slate-400 font-medium">
          {subtitle}
        </p>
      )}
    </div>
  );
}
