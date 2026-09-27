import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Privacy-Preserving Threat Detection Platform",
  description: "Enterprise Collaborative Cybersecurity with Federated Learning & PII Pseudonymization",
};

import { AuthGuard } from "@/components/AuthGuard";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="h-full bg-slate-100">
      <body className={`${inter.className} h-full flex flex-col antialiased text-slate-800`}>
        <AuthGuard>{children}</AuthGuard>
      </body>
    </html>
  );
}
