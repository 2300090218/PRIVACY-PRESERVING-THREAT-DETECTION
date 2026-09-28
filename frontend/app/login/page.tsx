"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Shield,
  Lock,
  Mail,
  Key,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Clock,
  ArrowLeft,
  ArrowRight,
  Eye,
  EyeOff,
  HelpCircle,
} from "lucide-react";
import { API_BASE } from "@/lib/api";
import { IS_DEMO_MODE } from "@/lib/config";

type AuthStep = "CREDENTIALS" | "OTP_VERIFY" | "FORGOT_PASSWORD" | "RESET_PASSWORD";
type AuthStatus =
  | "IDLE"
  | "VALIDATING"
  | "AUTHENTICATING"
  | "OTP_SENT"
  | "VERIFYING_OTP"
  | "AUTHENTICATED"
  | "ERROR"
  | "RATE_LIMITED";

export default function LoginPage() {
  const router = useRouter();

  // Step state
  const [step, setStep] = useState<AuthStep>("CREDENTIALS");
  const [status, setStatus] = useState<AuthStatus>("IDLE");

  // Form inputs
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  // OTP inputs: 6 individual digits
  const [otpDigits, setOtpDigits] = useState<string[]>(["", "", "", "", "", ""]);
  const otpInputRefs = useRef<(HTMLInputElement | null)[]>([]);

  // Verification metadata from backend
  const [sessionNonce, setSessionNonce] = useState("");
  const [maskedEmail, setMaskedEmail] = useState("");
  const [displayName, setDisplayName] = useState("");

  // Timers
  const [expiresCountdown, setExpiresCountdown] = useState(300); // 5 minutes (05:00)
  const [resendCooldown, setResendCooldown] = useState(0);

  // Password reset state
  const [resetEmail, setResetEmail] = useState("");
  const [resetToken, setResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  // Feedback messages
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [adminNotice, setAdminNotice] = useState<string | null>(null);

  // Handle URL query parameters (e.g., admin_required or reset token)
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      if (params.get("reason") === "admin_required") {
        setAdminNotice(
          "Enterprise Administrator credentials required. Multi-tenant organization management, minimization policy configurations, and private audit trails are restricted."
        );
      }
      const token = params.get("reset_token");
      if (token) {
        setResetToken(token);
        setStep("RESET_PASSWORD");
      }
    }
  }, []);

  // OTP Expiration Countdown (05:00)
  useEffect(() => {
    let timer: NodeJS.Timeout | null = null;
    if (step === "OTP_VERIFY" && expiresCountdown > 0) {
      timer = setInterval(() => {
        setExpiresCountdown((prev) => {
          if (prev <= 1) {
            setStatus("ERROR");
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

  // STEP 2: Email + Password Submission
  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    // Client-side validation
    const trimmedEmail = email.trim();
    if (!trimmedEmail) {
      setErrorMessage("Please enter your email address.");
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail) && !trimmedEmail.includes("@")) {
      setErrorMessage("Please enter a valid email address format.");
      return;
    }
    if (!password) {
      setErrorMessage("Password is required.");
      return;
    }

    setStatus("AUTHENTICATING");
    setStatusMessage("Checking credentials...");

    try {
      const res = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          email: trimmedEmail,
          password: password,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        if (res.status === 429) {
          setStatus("RATE_LIMITED");
          setErrorMessage(data.detail || "Too many attempts. Try again later.");
        } else {
          setStatus("ERROR");
          setErrorMessage(data.detail || data.message || "Invalid email or password.");
        }
        return;
      }

      // Check if 2FA OTP is required (standard production flow)
      if (data.requires_2fa || data.session_nonce) {
        setSessionNonce(data.session_nonce);
        setMaskedEmail(data.masked_email || trimmedEmail);
        setExpiresCountdown(data.expires_in_seconds || 300);
        setResendCooldown(30);
        setStatus("OTP_SENT");
        setStatusMessage("Verification code sent to your registered email.");
        setStep("OTP_VERIFY");
        // Focus first OTP digit
        setTimeout(() => {
          otpInputRefs.current[0]?.focus();
        }, 100);
      } else if (data.access_token) {
        // Direct authenticated session (fallback if 2FA disabled for account)
        handleSuccessfulAuth(data);
      }
    } catch (err: any) {
      setStatus("ERROR");
      setErrorMessage(err.message || "Network error. Unable to reach authentication service.");
    }
  };

  // OTP Input handlers
  const handleOtpDigitChange = (index: number, value: string) => {
    // Only allow single digit
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

    // Auto-advance to next input
    if (index < 5) {
      otpInputRefs.current[index + 1]?.focus();
    } else {
      // All 6 digits filled: auto trigger verify
      const fullOtp = updated.join("");
      if (fullOtp.length === 6) {
        verifyOtpCode(fullOtp);
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
      verifyOtpCode(pasteData);
    } else {
      const nextIdx = Math.min(pasteData.length, 5);
      otpInputRefs.current[nextIdx]?.focus();
    }
  };

  // STEP 3: OTP Verification
  const verifyOtpCode = async (otpCode: string) => {
    if (otpCode.length !== 6) {
      setErrorMessage("Please enter all 6 digits of your verification code.");
      return;
    }
    if (expiresCountdown <= 0) {
      setErrorMessage("Verification code expired. Please request a new code.");
      return;
    }

    setStatus("VERIFYING_OTP");
    setStatusMessage("Verifying code...");
    setErrorMessage(null);

    try {
      const res = await fetch(`${API_BASE}/api/auth/verify-otp`, {
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
        if (res.status === 429) {
          setStatus("RATE_LIMITED");
          setErrorMessage(data.detail || "Too many attempts. Account locked.");
        } else {
          setStatus("ERROR");
          setErrorMessage(data.detail || data.message || "Invalid verification code.");
        }
        return;
      }

      handleSuccessfulAuth(data);
    } catch (err: any) {
      setStatus("ERROR");
      setErrorMessage(err.message || "Verification request failed.");
    }
  };

  // STEP 4: Session Creation & Redirect
  const handleSuccessfulAuth = (data: any) => {
    setStatus("AUTHENTICATED");
    const safeName = data.user?.display_name || data.user?.username || data.username || "Operator";
    setDisplayName(safeName);
    setStatusMessage(`Authenticated successfully. Welcome, ${safeName}`);

    // Persist client state for session & role-based routing
    if (typeof window !== "undefined") {
      if (data.access_token) {
        localStorage.setItem("token", data.access_token);
      }
      const role = data.user?.role || data.role || "VIEWER";
      localStorage.setItem("role", role);
      localStorage.setItem("user", data.user?.username || safeName);
      if (data.user?.email) {
        localStorage.setItem("email", data.user.email);
      }
      localStorage.setItem("display_name", safeName);
      window.dispatchEvent(new Event("auth-change"));
    }

    setTimeout(() => {
      router.push("/dashboard");
    }, 1000);
  };

  // Resend OTP
  const handleResendOtp = async () => {
    if (resendCooldown > 0) return;
    setErrorMessage(null);
    setStatus("AUTHENTICATING");
    setStatusMessage("Resending verification code...");

    try {
      const res = await fetch(`${API_BASE}/api/auth/resend-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          session_nonce: sessionNonce,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setStatus("ERROR");
        setErrorMessage(data.detail || "Unable to resend verification code.");
        return;
      }

      setExpiresCountdown(data.expires_in_seconds || 300);
      setResendCooldown(45);
      setOtpDigits(["", "", "", "", "", ""]);
      setStatus("OTP_SENT");
      setStatusMessage("A new verification code has been dispatched to your email.");
      otpInputRefs.current[0]?.focus();
    } catch (err: any) {
      setStatus("ERROR");
      setErrorMessage(err.message || "Failed to resend code.");
    }
  };

  // Forgot Password handler
  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!resetEmail.trim()) {
      setErrorMessage("Please enter your registered email address.");
      return;
    }

    setStatus("AUTHENTICATING");
    setStatusMessage("Dispatching password reset instructions...");

    try {
      const res = await fetch(`${API_BASE}/api/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ email: resetEmail.trim() }),
      });

      const data = await res.json().catch(() => ({}));

      setStatus("IDLE");
      setSuccessMessage(
        data.message ||
          "If the account exists, secure password reset instructions have been dispatched to the provided email."
      );
    } catch (err: any) {
      setStatus("ERROR");
      setErrorMessage(err.message || "Password reset request failed.");
    }
  };

  // Reset Password handler
  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!resetToken.trim()) {
      setErrorMessage("Password reset token is required.");
      return;
    }
    if (newPassword.length < 8) {
      setErrorMessage("Password must be at least 8 characters long.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setErrorMessage("Passwords do not match.");
      return;
    }

    setStatus("AUTHENTICATING");
    setStatusMessage("Updating password securely...");

    try {
      const res = await fetch(`${API_BASE}/api/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          token: resetToken.trim(),
          new_password: newPassword,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        setStatus("ERROR");
        setErrorMessage(data.detail || "Password reset failed. Token may be invalid or expired.");
        return;
      }

      setStatus("IDLE");
      setSuccessMessage("Password reset successfully. You may now sign in with your new password.");
      setStep("CREDENTIALS");
      setPassword("");
    } catch (err: any) {
      setStatus("ERROR");
      setErrorMessage(err.message || "Failed to reset password.");
    }
  };

  const isSubmitting = status === "AUTHENTICATING" || status === "VERIFYING_OTP";

  return (
    <div className="min-h-screen bg-slate-100 flex flex-col justify-center items-center p-4">
      <div className="w-full max-w-md bg-white rounded-2xl border border-slate-200 p-8 shadow-sm space-y-6">
        {/* Header / Brand */}
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

        {/* Admin Route Protection Notice */}
        {adminNotice && (
          <div className="bg-amber-50 border border-amber-300 text-amber-950 text-xs px-3.5 py-3 rounded-xl flex items-start gap-2.5 shadow-xs">
            <Lock className="h-4 w-4 shrink-0 text-amber-700 mt-0.5" />
            <div className="space-y-1">
              <span className="font-bold tracking-tight block text-amber-900">
                Enterprise Authentication Required
              </span>
              <p className="text-[11px] text-amber-800 leading-relaxed">{adminNotice}</p>
            </div>
          </div>
        )}

        {/* Real-Time Status / Feedback */}
        {statusMessage && status !== "ERROR" && status !== "RATE_LIMITED" && (
          <div
            className={`text-xs px-3.5 py-2.5 rounded-lg flex items-center gap-2 border ${
              status === "AUTHENTICATED"
                ? "bg-emerald-50 border-emerald-200 text-emerald-800"
                : "bg-indigo-50 border-indigo-200 text-indigo-800"
            }`}
          >
            {status === "AUTHENTICATED" ? (
              <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" />
            ) : (
              <RefreshCw className="h-4 w-4 shrink-0 text-indigo-600 animate-spin" />
            )}
            <span className="font-medium">{statusMessage}</span>
          </div>
        )}

        {/* Error Notice */}
        {errorMessage && (
          <div className="bg-rose-50 border border-rose-200 text-rose-800 text-xs px-3.5 py-2.5 rounded-lg flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0 text-rose-600" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Success Notice */}
        {successMessage && (
          <div className="bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs px-3.5 py-2.5 rounded-lg flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" />
            <span>{successMessage}</span>
          </div>
        )}

        {/* STEP 1: Email + Password Form */}
        {step === "CREDENTIALS" && (
          <form onSubmit={handleLoginSubmit} className="space-y-4">
            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-700">Email</label>
              <div className="relative">
                <Mail className="h-4 w-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="user@example.com"
                  autoComplete="email"
                  required
                  disabled={isSubmitting}
                  className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium disabled:opacity-60"
                />
              </div>
            </div>

            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-700">Password</label>
                <button
                  type="button"
                  onClick={() => {
                    setStep("FORGOT_PASSWORD");
                    setErrorMessage(null);
                    setSuccessMessage(null);
                  }}
                  className="text-[11px] font-medium text-indigo-600 hover:text-indigo-800 transition-colors"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative">
                <Key className="h-4 w-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  required
                  disabled={isSubmitting}
                  className="w-full pl-9 pr-10 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium disabled:opacity-60"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting || status === "AUTHENTICATED"}
              className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition-colors shadow-sm shadow-indigo-200 disabled:opacity-60 flex items-center justify-center gap-2 cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  <span>Checking credentials...</span>
                </>
              ) : status === "AUTHENTICATED" ? (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span>Authenticated</span>
                </>
              ) : (
                <span>Sign In</span>
              )}
            </button>
          </form>
        )}

        {/* STEP 3: Email Two-Step Verification (OTP) */}
        {step === "OTP_VERIFY" && (
          <div className="space-y-5 animate-in fade-in duration-200">
            <div className="text-center space-y-1">
              <h2 className="text-sm font-bold text-slate-900 tracking-tight">
                Two-Step Verification
              </h2>
              <p className="text-xs text-slate-500">
                We sent a 6-digit verification code to:
              </p>
              <div className="inline-block bg-slate-100 border border-slate-200 px-2.5 py-1 rounded-md text-xs font-mono font-bold text-slate-700">
                {maskedEmail || email}
              </div>
            </div>

            {/* 6 Digit Verification Code Boxes */}
            <div className="space-y-2">
              <label className="text-[11px] font-semibold text-slate-600 block text-center uppercase tracking-wider">
                Verification Code
              </label>
              <div className="flex justify-center gap-2">
                {otpDigits.map((digit, index) => (
                  <input
                    key={index}
                    ref={(el) => {
                      otpInputRefs.current[index] = el;
                    }}
                    type="text"
                    inputMode="numeric"
                    maxLength={1}
                    value={digit}
                    onChange={(e) => handleOtpDigitChange(index, e.target.value)}
                    onKeyDown={(e) => handleOtpKeyDown(index, e)}
                    onPaste={handleOtpPaste}
                    disabled={isSubmitting}
                    className="w-11 h-12 text-center text-lg font-mono font-bold bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 disabled:opacity-60 shadow-xs"
                  />
                ))}
              </div>
            </div>

            {/* Countdown timer */}
            <div className="flex items-center justify-center gap-1.5 text-xs text-slate-500">
              <Clock className="h-3.5 w-3.5 text-slate-400" />
              <span>
                Code expires in:{" "}
                <span className="font-mono font-bold text-slate-800">
                  {formatTime(expiresCountdown)}
                </span>
              </span>
            </div>

            {/* Actions: Verify, Resend, Change Email */}
            <div className="space-y-2 pt-1">
              <button
                type="button"
                onClick={() => verifyOtpCode(otpDigits.join(""))}
                disabled={isSubmitting || otpDigits.join("").length !== 6}
                className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition-colors shadow-sm shadow-indigo-200 disabled:opacity-60 flex items-center justify-center gap-2 cursor-pointer"
              >
                {status === "VERIFYING_OTP" ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    <span>Verifying code...</span>
                  </>
                ) : (
                  <span>Verify Code</span>
                )}
              </button>

              <div className="flex items-center justify-between text-xs pt-1">
                <button
                  type="button"
                  onClick={handleResendOtp}
                  disabled={resendCooldown > 0 || isSubmitting}
                  className="font-medium text-indigo-600 hover:text-indigo-800 disabled:text-slate-400 transition-colors cursor-pointer"
                >
                  {resendCooldown > 0 ? `Resend Code (${resendCooldown}s)` : "Resend Code"}
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setStep("CREDENTIALS");
                    setOtpDigits(["", "", "", "", "", ""]);
                    setErrorMessage(null);
                    setStatusMessage(null);
                  }}
                  className="font-medium text-slate-600 hover:text-slate-800 transition-colors cursor-pointer"
                >
                  Change Email
                </button>
              </div>
            </div>
          </div>
        )}

        {/* FORGOT PASSWORD VIEW */}
        {step === "FORGOT_PASSWORD" && (
          <form onSubmit={handleForgotPassword} className="space-y-4 animate-in fade-in duration-200">
            <div className="text-center space-y-1">
              <h2 className="text-sm font-bold text-slate-900 tracking-tight">
                Reset Password
              </h2>
              <p className="text-xs text-slate-500">
                Enter your registered email to receive password reset instructions.
              </p>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-700">Account Email</label>
              <div className="relative">
                <Mail className="h-4 w-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="email"
                  value={resetEmail}
                  onChange={(e) => setResetEmail(e.target.value)}
                  placeholder="user@example.com"
                  required
                  disabled={isSubmitting}
                  className="w-full pl-9 pr-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition-colors shadow-sm shadow-indigo-200 disabled:opacity-60 flex items-center justify-center gap-2 cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  <span>Dispatching instructions...</span>
                </>
              ) : (
                <span>Send Reset Instructions</span>
              )}
            </button>

            <div className="flex items-center justify-between text-xs pt-1">
              <button
                type="button"
                onClick={() => {
                  setStep("CREDENTIALS");
                  setErrorMessage(null);
                  setSuccessMessage(null);
                }}
                className="inline-flex items-center gap-1 font-medium text-slate-600 hover:text-slate-800 transition-colors"
              >
                <ArrowLeft className="h-3 w-3" />
                <span>Back to Sign In</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setStep("RESET_PASSWORD");
                  setErrorMessage(null);
                  setSuccessMessage(null);
                }}
                className="font-medium text-indigo-600 hover:text-indigo-800 transition-colors"
              >
                Have a token?
              </button>
            </div>
          </form>
        )}

        {/* RESET PASSWORD VIEW */}
        {step === "RESET_PASSWORD" && (
          <form onSubmit={handleResetPassword} className="space-y-4 animate-in fade-in duration-200">
            <div className="text-center space-y-1">
              <h2 className="text-sm font-bold text-slate-900 tracking-tight">
                Enter New Password
              </h2>
              <p className="text-xs text-slate-500">
                Provide your security reset token and choose a new password.
              </p>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-700">Reset Token</label>
              <input
                type="text"
                value={resetToken}
                onChange={(e) => setResetToken(e.target.value)}
                placeholder="Paste reset token from email"
                required
                disabled={isSubmitting}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-700">New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="At least 8 characters"
                required
                minLength={8}
                disabled={isSubmitting}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-700">Confirm Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Re-enter password"
                required
                minLength={8}
                disabled={isSubmitting}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs text-slate-900 placeholder-slate-400 focus:bg-white focus:outline-none focus:ring-1 focus:ring-indigo-500 font-medium"
              />
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs transition-colors shadow-sm shadow-indigo-200 disabled:opacity-60 flex items-center justify-center gap-2 cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  <span>Updating password...</span>
                </>
              ) : (
                <span>Set New Password</span>
              )}
            </button>

            <div className="text-center pt-1">
              <button
                type="button"
                onClick={() => {
                  setStep("CREDENTIALS");
                  setErrorMessage(null);
                  setSuccessMessage(null);
                }}
                className="inline-flex items-center gap-1 text-xs font-medium text-slate-600 hover:text-slate-800 transition-colors"
              >
                <ArrowLeft className="h-3 w-3" />
                <span>Back to Sign In</span>
              </button>
            </div>
          </form>
        )}

        {/* Public Demo Mode - Isolated and strictly for test data */}
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
      </div>
    </div>
  );
}
