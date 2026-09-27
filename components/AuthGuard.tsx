"use client";

import React, { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { IS_DEMO_MODE, isAuthenticated } from "@/lib/config";

// Administrative routes restricted to authenticated Enterprise / SOC Analyst personnel
const ADMIN_RESTRICTED_ROUTES = [
  "/organizations",
  "/privacy/policies",
  "/audit",
  "/settings",
];

export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    const authed = isAuthenticated();

    // Mode 1: Production Public Demo Mode (NEXT_PUBLIC_DEMO_MODE=true)
    if (IS_DEMO_MODE) {
      const isAdminRoute = ADMIN_RESTRICTED_ROUTES.some(
        (r) => pathname === r || pathname.startsWith(r + "/")
      );
      if (isAdminRoute && !authed) {
        // Prevent unauthenticated access to organization management, private audit logs, & policies
        router.push("/login?reason=admin_required");
      } else {
        setChecked(true);
      }
      return;
    }

    // Mode 2: Private Enterprise Deployment (NEXT_PUBLIC_DEMO_MODE=false)
    if (!authed && pathname !== "/login") {
      router.push("/login");
    } else {
      setChecked(true);
    }
  }, [pathname, router]);

  // If in demo mode and on a public route, permit instant render without blocking screen
  const isPublicDemoRoute =
    IS_DEMO_MODE &&
    !ADMIN_RESTRICTED_ROUTES.some(
      (r) => pathname === r || pathname.startsWith(r + "/")
    );

  if (!checked && !isPublicDemoRoute && pathname !== "/login") {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center text-slate-400 text-xs font-mono">
        Verifying Security Boundaries...
      </div>
    );
  }

  return <>{children}</>;
}
