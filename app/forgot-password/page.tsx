"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  KeyRound,
  Mail,
  Lock,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  ArrowRight,
  Eye,
  EyeOff,
} from "lucide-react";
import { API_BASE } from "@/lib/api";

type ForgotStep = "REQUEST_CODE" | "SUBMIT_NEW_PASSWORD" | "SUCCESS";

export default function ForgotPasswordPage() {
  const router = useRouter();

  const [step, setStep] = useState<ForgotStep>("REQUEST_CODE");
  const [isLoading, setIsLoading] = useState(false);

  // Form states
  const [email, setEmail] = useState("");
  const [resetCode, setResetCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  // Status & error messages
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Request Reset Code
  const handleRequestCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !trimmedEmail.includes("@")) {
      setErrorMessage("Please enter a valid email address.");
      return;
    }

    setIsLoading(true);
    setStatusMessage("Sending password reset code to your Gmail address...");

    try {
      const res = await fetch(`${API_BASE}/api/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: trimmedEmail }),
      });

      const data = await res.json().catch(() => ({}));

      setSuccessMessage("Password reset code dispatched to your Gmail address.");
      setStep("SUBMIT_NEW_PASSWORD");
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to submit request.");
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  // Submit New Password with Code
  const handleResetSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    const trimmedCode = resetCode.trim();
    if (!trimmedCode) {
      setErrorMessage("Please enter the 6-digit code or reset token sent to your email.");
      return;
    }
    if (newPassword.length < 8) {
      setErrorMessage("New password must be at least 8 characters long.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setErrorMessage("Passwords do not match.");
      return;
    }

    setIsLoading(true);
    setStatusMessage("Validating reset code and updating password...");

    try {
      const res = await fetch(`${API_BASE}/api/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: trimmedCode,
          code: trimmedCode,
          new_password: newPassword,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setErrorMessage(data.detail || data.message || "Invalid or expired reset code.");
        return;
      }

      setStep("SUCCESS");
      setSuccessMessage("Password updated successfully! Redirecting to login...");
      setTimeout(() => {
        router.push("/login");
      }, 2000);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to reset password.");
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-indigo-950 flex items-center justify-center p-4 selection:bg-indigo-500 selection:text-white">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl border border-slate-100 overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-slate-800 via-indigo-900 to-slate-900 p-6 text-white text-center relative overflow-hidden">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-white/10 backdrop-blur-md mb-3">
            <KeyRound className="w-6 h-6 text-indigo-300" />
          </div>
          <h1 className="text-xl font-bold tracking-tight">Reset Password</h1>
          <p className="text-xs text-slate-300 mt-1">
            Privacy-Preserving Threat Detection Platform
          </p>
        </div>

        {/* Form Body */}
        <div className="p-6 sm:p-8">
          {/* Notifications */}
          {statusMessage && (
            <div className="mb-4 p-3 bg-indigo-50 border border-indigo-200 text-indigo-800 rounded-lg text-xs flex items-center gap-2 animate-in fade-in">
              <RefreshCw className="w-4 h-4 animate-spin shrink-0 text-indigo-600" />
              <span>{statusMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="mb-4 p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-lg text-xs flex items-center gap-2 animate-in fade-in">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
              <span>{successMessage}</span>
            </div>
          )}

          {errorMessage && (
            <div className="mb-4 p-3 bg-rose-50 border border-rose-200 text-rose-800 rounded-lg text-xs flex items-center gap-2 animate-in fade-in">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* STEP 1: Enter Email */}
          {step === "REQUEST_CODE" && (
            <form onSubmit={handleRequestCode} className="space-y-4">
              <p className="text-xs text-slate-600">
                Enter your account email address. We will dispatch a 6-digit password-reset verification code to your Gmail address.
              </p>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                  <input
                    type="email"
                    required
                    placeholder="user@gmail.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-slate-900 bg-slate-50/50"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg shadow-sm shadow-indigo-200 transition-all flex items-center justify-center gap-2 disabled:opacity-60 cursor-pointer"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Sending Reset Code...</span>
                  </>
                ) : (
                  <>
                    <span>Send Reset Code</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>
          )}

          {/* STEP 2: Enter Code and New Password */}
          {step === "SUBMIT_NEW_PASSWORD" && (
            <form onSubmit={handleResetSubmit} className="space-y-4">
              <p className="text-xs text-slate-600">
                Enter the 6-digit reset code received at <span className="font-mono font-bold text-slate-800">{email}</span> and choose a new password.
              </p>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
                  6-Digit Reset Code or Token
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 582194"
                  value={resetCode}
                  onChange={(e) => setResetCode(e.target.value)}
                  className="w-full px-3 py-2 text-sm font-mono font-bold border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-slate-900 bg-slate-50/50"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
                  New Password (min. 8 characters)
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    placeholder="••••••••••••"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className="w-full pl-9 pr-10 py-2 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-slate-900 bg-slate-50/50"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
                  Confirm New Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    placeholder="••••••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-slate-900 bg-slate-50/50"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg shadow-sm shadow-indigo-200 transition-all flex items-center justify-center gap-2 disabled:opacity-60 cursor-pointer"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Updating Password...</span>
                  </>
                ) : (
                  <>
                    <span>Update Password</span>
                    <CheckCircle2 className="w-4 h-4" />
                  </>
                )}
              </button>

              <div className="text-center pt-1">
                <button
                  type="button"
                  onClick={() => setStep("REQUEST_CODE")}
                  className="text-xs text-slate-500 hover:text-slate-800"
                >
                  &larr; Request code again
                </button>
              </div>
            </form>
          )}

          {/* STEP 3: Success */}
          {step === "SUCCESS" && (
            <div className="text-center py-6 space-y-3">
              <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-emerald-100 text-emerald-600">
                <CheckCircle2 className="w-8 h-8" />
              </div>
              <h2 className="text-lg font-bold text-slate-900">Password Reset Complete!</h2>
              <p className="text-xs text-slate-600">
                You may now sign in with your updated credentials. Redirecting to login...
              </p>
            </div>
          )}

          {/* Footer Back Link */}
          <div className="mt-6 pt-5 border-t border-slate-100 text-center text-xs text-slate-500">
            Remember your credentials?{" "}
            <Link href="/login" className="font-semibold text-indigo-600 hover:text-indigo-800">
              Sign In &rarr;
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
