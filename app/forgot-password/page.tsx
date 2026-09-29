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
  Sparkles,
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
  const [receivedOtp, setReceivedOtp] = useState<string | null>(null);

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

      if (data.demo_otp || data.test_otp) {
        const code = String(data.demo_otp || data.test_otp);
        setReceivedOtp(code);
        setResetCode(code);
      }

      setSuccessMessage(data.message || "Password reset code dispatched to your Gmail address.");
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
      }, 1500);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to reset password.");
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-4 selection:bg-indigo-500 selection:text-white">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-sm border border-slate-200 overflow-hidden">
        {/* Header */}
        <div className="p-6 text-center border-b border-slate-100 bg-white">
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-indigo-600 text-white mb-3 shadow-md shadow-indigo-100">
            <KeyRound className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-slate-900">
            Reset Password
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Privacy-Preserving Threat Detection Platform
          </p>
        </div>

        {/* Form Body */}
        <div className="p-6 sm:p-8">
          {/* Notifications */}
          {statusMessage && (
            <div className="mb-4 p-3 bg-indigo-50 border border-indigo-200 text-indigo-900 rounded-lg text-xs flex items-center gap-2 animate-in fade-in">
              <RefreshCw className="w-4 h-4 animate-spin shrink-0 text-indigo-600" />
              <span>{statusMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="mb-4 p-3 bg-emerald-50 border border-emerald-200 text-emerald-900 rounded-lg text-xs flex items-center gap-2 animate-in fade-in">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
              <span>{successMessage}</span>
            </div>
          )}

          {errorMessage && (
            <div className="mb-4 p-3 bg-rose-50 border border-rose-200 text-rose-900 rounded-lg text-xs flex items-center gap-2 animate-in fade-in">
              <AlertCircle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* STEP 1: Enter Email */}
          {step === "REQUEST_CODE" && (
            <form onSubmit={handleRequestCode} className="space-y-4">
              <p className="text-xs text-slate-600 leading-relaxed">
                Enter your account email address. We will dispatch a 6-digit password-reset verification code.
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
                Enter the 6-digit reset code received for <span className="font-mono font-bold text-slate-800">{email}</span> and choose a new password.
              </p>

              {receivedOtp && (
                <div className="p-3 bg-indigo-50 border border-indigo-200 rounded-xl space-y-1.5 text-center">
                  <div className="flex items-center justify-center gap-1.5 text-xs font-bold text-indigo-900">
                    <Sparkles className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                    <span>Demo Mode Reset Code</span>
                  </div>
                  <div className="flex items-center justify-center gap-2">
                    <span className="bg-white px-3 py-1 rounded border border-indigo-200 font-mono text-base font-extrabold text-indigo-700 tracking-wider">
                      {receivedOtp}
                    </span>
                    <button
                      type="button"
                      onClick={() => setResetCode(receivedOtp)}
                      className="px-2.5 py-1 bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold rounded transition-colors"
                    >
                      Auto-Fill
                    </button>
                  </div>
                </div>
              )}

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
