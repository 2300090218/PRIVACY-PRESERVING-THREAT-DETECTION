"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  Lock,
  Mail,
  User,
  Building,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Clock,
  ArrowRight,
  Eye,
  EyeOff,
  Sparkles,
} from "lucide-react";
import { API_BASE } from "@/lib/api";

type SignupStep = "DETAILS" | "OTP_VERIFY" | "COMPLETED";

export default function SignupPage() {
  const router = useRouter();

  // Step state
  const [step, setStep] = useState<SignupStep>("DETAILS");
  const [isLoading, setIsLoading] = useState(false);

  // Form inputs
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [organization, setOrganization] = useState("Enterprise Global");
  const [showPassword, setShowPassword] = useState(false);

  // OTP state
  const [otpDigits, setOtpDigits] = useState<string[]>(["", "", "", "", "", ""]);
  const otpInputRefs = useRef<(HTMLInputElement | null)[]>([]);
  const [sessionNonce, setSessionNonce] = useState("");
  const [maskedEmail, setMaskedEmail] = useState("");

  // Timers
  const [expiresCountdown, setExpiresCountdown] = useState(300); // 5 minutes
  const [resendCooldown, setResendCooldown] = useState(0);

  // Feedback messages
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Expiration Countdown
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    if (step === "OTP_VERIFY" && expiresCountdown > 0) {
      timer = setInterval(() => {
        setExpiresCountdown((prev) => {
          if (prev <= 1) {
            setErrorMessage("Verification code expired. Please request a new code.");
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [step, expiresCountdown]);

  // Resend Cooldown Countdown
  useEffect(() => {
    let cooldownTimer: NodeJS.Timeout | null = null;
    if (resendCooldown > 0) {
      cooldownTimer = setInterval(() => {
        setResendCooldown((prev) => Math.max(0, prev - 1));
      }, 1000);
    }
    return () => {
      if (cooldownTimer) clearInterval(cooldownTimer);
    };
  }, [resendCooldown]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
  };

  // Submit registration form and request OTP
  const handleSignupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    const trimmedEmail = email.trim();
    if (!trimmedEmail || !trimmedEmail.includes("@")) {
      setErrorMessage("Please enter a valid Gmail or enterprise email address.");
      return;
    }
    if (password.length < 8) {
      setErrorMessage("Password must be at least 8 characters long.");
      return;
    }

    setIsLoading(true);
    setStatusMessage("Sending 6-digit confirmation code to your Gmail address...");

    try {
      const res = await fetch(`${API_BASE}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          email: trimmedEmail,
          password: password,
          display_name: displayName.trim() || trimmedEmail.split("@")[0],
          organization_id: organization,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setErrorMessage(data.detail || data.message || "Failed to create account. Please verify your details.");
        return;
      }

      setSessionNonce(data.session_nonce || "");
      setMaskedEmail(data.email_masked || data.masked_email || trimmedEmail);
      setExpiresCountdown(data.expires_in_seconds || 300);
      setResendCooldown(30);
      setSuccessMessage("Confirmation code dispatched to your Gmail address!");
      setStep("OTP_VERIFY");
      setTimeout(() => {
        otpInputRefs.current[0]?.focus();
      }, 150);
    } catch (err: any) {
      setErrorMessage(err.message || "Network error. Unable to reach server.");
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  // OTP Input handlers
  const handleOtpDigitChange = (index: number, value: string) => {
    const cleaned = value.replace(/\D/g, "");
    if (!cleaned) {
      const updated = [...otpDigits];
      updated[index] = "";
      setOtpDigits(updated);
      return;
    }

    const digit = cleaned.slice(-1);
    const updated = [...otpDigits];
    updated[index] = digit;
    setOtpDigits(updated);

    if (index < 5) {
      otpInputRefs.current[index + 1]?.focus();
    } else {
      const fullOtp = updated.join("");
      if (fullOtp.length === 6) {
        verifySignupOtp(fullOtp);
      }
    }
  };

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Backspace" && !otpDigits[index] && index > 0) {
      otpInputRefs.current[index - 1]?.focus();
    }
  };

  const handleOtpPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pasteData = e.clipboardData.getData("text").replace(/\D/g, "").slice(0, 6);
    if (!pasteData) return;

    const digits = pasteData.split("");
    const updated = [...otpDigits];
    for (let i = 0; i < 6; i++) {
      updated[i] = digits[i] || "";
    }
    setOtpDigits(updated);

    if (pasteData.length === 6) {
      otpInputRefs.current[5]?.focus();
      verifySignupOtp(pasteData);
    } else {
      const nextIdx = Math.min(pasteData.length, 5);
      otpInputRefs.current[nextIdx]?.focus();
    }
  };

  // Verify OTP and complete activation
  const verifySignupOtp = async (otpCode: string) => {
    if (otpCode.length !== 6) {
      setErrorMessage("Please enter all 6 digits of your verification code.");
      return;
    }

    setIsLoading(true);
    setStatusMessage("Verifying code and activating account...");
    setErrorMessage(null);

    try {
      const res = await fetch(`${API_BASE}/api/auth/verify-signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          session_nonce: sessionNonce,
          otp: otpCode,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setErrorMessage(data.detail || data.message || "Invalid or expired confirmation code.");
        return;
      }

      if (data.access_token && typeof window !== "undefined") {
        localStorage.setItem("token", data.access_token);
        localStorage.setItem(
          "user",
          JSON.stringify({
            username: data.username,
            email: data.email,
            display_name: data.display_name,
            role: data.role,
            organization_id: data.organization_id,
          })
        );
      }

      setStep("COMPLETED");
      setSuccessMessage("Account verified and activated successfully! Redirecting to Dashboard...");
      setTimeout(() => {
        router.push("/dashboard");
      }, 1500);
    } catch (err: any) {
      setErrorMessage(err.message || "Verification request failed.");
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  const handleResendOtp = async () => {
    if (resendCooldown > 0 || isLoading) return;
    setIsLoading(true);
    setStatusMessage("Dispatching fresh 6-digit confirmation code...");
    setErrorMessage(null);

    try {
      const res = await fetch(`${API_BASE}/api/auth/resend-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ session_nonce: sessionNonce }),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setErrorMessage(data.detail || "Unable to resend confirmation code.");
        return;
      }

      setResendCooldown(30);
      setExpiresCountdown(300);
      setSuccessMessage("A fresh confirmation code has been dispatched to your Gmail address.");
      setOtpDigits(["", "", "", "", "", ""]);
      setTimeout(() => {
        otpInputRefs.current[0]?.focus();
      }, 100);
    } catch (err: any) {
      setErrorMessage(err.message || "Network error. Please try again.");
    } finally {
      setIsLoading(false);
      setStatusMessage(null);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-indigo-950 flex items-center justify-center p-4 selection:bg-indigo-500 selection:text-white">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl border border-slate-100 overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-indigo-600 via-indigo-700 to-teal-600 p-6 text-white text-center relative overflow-hidden">
          <div className="absolute -top-12 -right-12 w-32 h-32 bg-white/10 rounded-full blur-2xl"></div>
          <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-white/20 backdrop-blur-md mb-3 shadow-inner">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-xl font-bold tracking-tight">Create Account</h1>
          <p className="text-xs text-indigo-100 mt-1">
            Privacy-Preserving Threat Detection Platform
          </p>
        </div>

        {/* Content Body */}
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

          {/* STEP 1: Registration Details */}
          {step === "DETAILS" && (
            <form onSubmit={handleSignupSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
                  Email Address (Gmail / Corporate)
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

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
                  Full Name / Display Name
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                  <input
                    type="text"
                    placeholder="Security Analyst"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-slate-900 bg-slate-50/50"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
                  Organization
                </label>
                <div className="relative">
                  <Building className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                  <select
                    value={organization}
                    onChange={(e) => setOrganization(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-slate-900 bg-slate-50/50"
                  >
                    <option value="org_enterprise_a">Enterprise Global A (Default)</option>
                    <option value="org_finance_b">Financial Services B</option>
                    <option value="org_cloud_c">Cloud Infrastructure C</option>
                    <option value="demo_gitam_visakhapatnam">GITAM University</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 uppercase tracking-wider mb-1">
                  Password (min. 8 characters)
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                  <input
                    type={showPassword ? "text" : "password"}
                    required
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
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

              <button
                type="submit"
                disabled={isLoading}
                className="w-full mt-2 py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg shadow-sm shadow-indigo-200 transition-all flex items-center justify-center gap-2 disabled:opacity-60 cursor-pointer"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Sending Confirmation Code...</span>
                  </>
                ) : (
                  <>
                    <span>Create Account & Send Code</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>
          )}

          {/* STEP 2: 6-Digit OTP Verification */}
          {step === "OTP_VERIFY" && (
            <div className="space-y-5">
              <div className="text-center space-y-1">
                <span className="text-xs font-semibold text-indigo-600 uppercase tracking-wider bg-indigo-50 px-2.5 py-1 rounded-full border border-indigo-200 inline-block">
                  Confirmation Code Sent
                </span>
                <p className="text-xs text-slate-600 pt-1">
                  Enter the 6-digit confirmation code delivered to:
                </p>
                <p className="text-sm font-mono font-bold text-slate-900">{maskedEmail}</p>
              </div>

              {/* 6 Digit Inputs */}
              <div className="flex justify-center gap-2 sm:gap-3 py-2">
                {otpDigits.map((digit, idx) => (
                  <input
                    key={idx}
                    ref={(el) => {
                      otpInputRefs.current[idx] = el;
                    }}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleOtpDigitChange(idx, e.target.value)}
                    onKeyDown={(e) => handleOtpKeyDown(idx, e)}
                    onPaste={handleOtpPaste}
                    className="w-10 h-12 sm:w-12 sm:h-14 text-center text-xl font-bold font-mono border-2 border-slate-200 rounded-lg focus:border-indigo-600 focus:ring-2 focus:ring-indigo-100 outline-none text-slate-900 transition-all bg-slate-50/50"
                  />
                ))}
              </div>

              {/* Timer & Resend */}
              <div className="flex items-center justify-between text-xs text-slate-500 pt-1">
                <div className="flex items-center gap-1.5 font-mono">
                  <Clock className="w-3.5 h-3.5 text-slate-400" />
                  <span>Expires in: {formatTime(expiresCountdown)}</span>
                </div>

                <button
                  type="button"
                  onClick={handleResendOtp}
                  disabled={resendCooldown > 0 || isLoading}
                  className="font-semibold text-indigo-600 hover:text-indigo-800 disabled:opacity-50 cursor-pointer"
                >
                  {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : "Resend Code"}
                </button>
              </div>

              <button
                type="button"
                onClick={() => verifySignupOtp(otpDigits.join(""))}
                disabled={isLoading || otpDigits.join("").length !== 6}
                className="w-full py-2.5 px-4 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold rounded-lg shadow-sm shadow-indigo-200 transition-all flex items-center justify-center gap-2 disabled:opacity-60 cursor-pointer"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Verifying Code...</span>
                  </>
                ) : (
                  <>
                    <span>Confirm & Activate Account</span>
                    <CheckCircle2 className="w-4 h-4" />
                  </>
                )}
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => setStep("DETAILS")}
                  className="text-xs text-slate-500 hover:text-slate-800"
                >
                  &larr; Back to account details
                </button>
              </div>
            </div>
          )}

          {/* STEP 3: Completed */}
          {step === "COMPLETED" && (
            <div className="text-center py-6 space-y-3 animate-in zoom-in-95">
              <div className="inline-flex items-center justify-center w-14 h-14 rounded-full bg-emerald-100 text-emerald-600">
                <CheckCircle2 className="w-8 h-8" />
              </div>
              <h2 className="text-lg font-bold text-slate-900">Welcome to Threat Detection!</h2>
              <p className="text-xs text-slate-600 max-w-xs mx-auto">
                Your account has been confirmed and activated. Logging you in now...
              </p>
              <div className="pt-2">
                <RefreshCw className="w-5 h-5 text-indigo-600 animate-spin mx-auto" />
              </div>
            </div>
          )}

          {/* Footer Link */}
          <div className="mt-6 pt-5 border-t border-slate-100 text-center text-xs text-slate-500">
            Already have an account?{" "}
            <Link href="/login" className="font-semibold text-indigo-600 hover:text-indigo-800">
              Sign In &rarr;
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
