"""
Enterprise Email Delivery Service
Handles secure, real-time server-side delivery of two-step verification codes (OTP)
for Account Registration, Login 2FA, and Password Reset via Gmail SMTP / TLS.
"""

import asyncio
import smtplib
import socket
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, Tuple, Any

from backend.app.config import settings

logger = logging.getLogger(__name__)

# In-memory test registry accessible during automated testing or diagnostic scripts
_test_dispatched_otps: Dict[str, str] = {}
_test_dispatched_nonces: Dict[str, str] = {}
_last_smtp_status: Dict[str, Any] = {"success": True, "error": None}

class EmailService:
    @staticmethod
    def get_last_dispatched_otp(identifier: Optional[str] = None) -> Optional[str]:
        """
        Retrieves the last dispatched OTP for an email, session nonce, or most recent.
        Used strictly during automated testing or diagnostic scripts.
        """
        if identifier:
            if identifier in _test_dispatched_nonces:
                return _test_dispatched_nonces[identifier]
            if identifier in _test_dispatched_otps:
                return _test_dispatched_otps[identifier]
        if _test_dispatched_nonces:
            return list(_test_dispatched_nonces.values())[-1]
        if _test_dispatched_otps:
            return list(_test_dispatched_otps.values())[-1]
        return None

    @staticmethod
    def clear_test_registry():
        _test_dispatched_otps.clear()
        _test_dispatched_nonces.clear()

email_service = EmailService()

def mask_email(email: str) -> str:
    """Masks an email for safe display in UI/logs, e.g. 'u***@domain.com'."""
    if not email or "@" not in email:
        return "u***@domain.com"
    parts = email.split("@")
    user_part = parts[0]
    domain_part = parts[1]
    if len(user_part) <= 2:
        masked_user = user_part[0] + "***"
    else:
        masked_user = user_part[:2] + "***" + user_part[-1]
    return f"{masked_user}@{domain_part}"

def _send_smtp_email_sync(to_email: str, subject: str, text_body: str, html_body: str) -> Tuple[bool, Optional[str]]:
    """
    Synchronous SMTP worker connecting to Gmail SMTP (587 TLS or 465 SSL).
    Invoked via asyncio.to_thread to prevent blocking the async event loop.
    """
    host = settings.smtp_host
    user = settings.smtp_username
    password = settings.smtp_password
    port = settings.smtp_port
    from_email = settings.smtp_from_email or user or "no-reply@threat-detection.internal"

    if not host or not user:
        logger.info(f"[EmailService] SMTP not fully configured (host={host}, user={user}). Falling back to local test registry.")
        return True, None

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    part1 = MIMEText(text_body, "plain", "utf-8")
    part2 = MIMEText(html_body, "html", "utf-8")
    msg.attach(part1)
    msg.attach(part2)

    masked_to = mask_email(to_email)
    logger.info(f"[EmailService] Initiating real-time SMTP connection to {host}:{port} for {masked_to}...")

    server = None
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=15.0)
            server.ehlo()
        else:
            server = smtplib.SMTP(host, port, timeout=15.0)
            server.ehlo()
            if settings.AUTH_SMTP_USE_TLS:
                server.starttls()
                server.ehlo()

        if password:
            server.login(user, password)
            logger.info(f"[EmailService] Authenticated successfully with SMTP server as {mask_email(user)}")

        server.send_message(msg)
        logger.info(f"[EmailService] Successfully delivered real-time email to {masked_to} via {host}:{port}")
        return True, None

    except smtplib.SMTPAuthenticationError as auth_err:
        err_msg = f"Gmail SMTP Authentication Failed. Verify SMTP_USERNAME and 16-digit Google App Password: {auth_err}"
        logger.error(f"[EmailService] {err_msg}")
        return False, err_msg
    except (smtplib.SMTPConnectError, socket.timeout, TimeoutError) as conn_err:
        err_msg = f"Failed to connect to SMTP server {host}:{port}: {conn_err}"
        logger.error(f"[EmailService] {err_msg}")
        return False, err_msg
    except smtplib.SMTPException as smtp_err:
        err_msg = f"SMTP protocol error during dispatch to {masked_to}: {smtp_err}"
        logger.error(f"[EmailService] {err_msg}")
        return False, err_msg
    except Exception as exc:
        err_msg = f"Unexpected failure sending email to {masked_to}: {exc}"
        logger.error(f"[EmailService] {err_msg}", exc_info=True)
        return False, err_msg
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass

async def send_verification_otp(
    to_email: str,
    otp_code: str,
    expires_minutes: int = 5,
    session_nonce: Optional[str] = None,
    purpose: str = "LOGIN_2FA"
) -> Tuple[bool, Optional[str]]:
    """
    Sends a cryptographically secure 6-digit verification code to the user's email.
    Supports Signup Confirmation and Login 2FA.
    """
    masked = mask_email(to_email)

    # Record in test registry for unit tests and local scripts
    _test_dispatched_otps[to_email] = otp_code
    if session_nonce:
        _test_dispatched_nonces[session_nonce] = otp_code

    if purpose in ["SIGNUP", "SIGNUP_VERIFY"]:
        subject = f"Your Account Confirmation Code: {otp_code} (Valid for {expires_minutes} min)"
        badge_title = "Account Confirmation"
        heading = "Confirm Your Account Registration"
        body_text = "Thank you for creating an account on the Privacy-Preserving Threat Detection Platform. Please enter the 6-digit confirmation code below to verify your email and activate your account:"
        action_note = "If you did not initiate this account creation, please ignore this email."
    else:
        subject = f"Your Security Verification Code: {otp_code} (Valid for {expires_minutes} min)"
        badge_title = "Two-Step Verification"
        heading = "Security Operations Console"
        body_text = "A login attempt requires verification for your account. Please enter the one-time code below to complete sign in:"
        action_note = "If you did not request this login attempt, please notify your SOC administrator immediately."

    text_content = (
        f"PRIVACY-PRESERVING THREAT DETECTION PLATFORM\n"
        f"{heading}\n\n"
        f"Your single-use verification code is: {otp_code}\n\n"
        f"This code will expire in {expires_minutes} minutes.\n"
        f"{action_note}\n\n"
        f"Zero Raw Telemetry Sharing &bull; Collaborative Federated IDS"
    )

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #1e293b; padding: 20px; }}
        .card {{ max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }}
        .header {{ text-align: center; border-bottom: 1px solid #f1f5f9; padding-bottom: 20px; margin-bottom: 24px; }}
        .badge {{ background-color: #e0e7ff; color: #4338ca; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }}
        .otp-box {{ background-color: #f1f5f9; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0; }}
        .otp-code {{ font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #4338ca; font-family: 'Courier New', monospace; }}
        .footer {{ font-size: 11px; color: #64748b; margin-top: 24px; border-top: 1px solid #f1f5f9; padding-top: 16px; text-align: center; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <span class="badge">{badge_title}</span>
          <h2 style="margin: 12px 0 4px 0; color: #0f172a; font-size: 18px;">{heading}</h2>
          <p style="margin: 0; font-size: 12px; color: #64748b;">Privacy-Preserving Threat Detection Platform</p>
        </div>
        <p style="font-size: 14px; line-height: 1.5; color: #334155;">
          {body_text}
        </p>
        <div class="otp-box">
          <div class="otp-code">{otp_code}</div>
          <p style="margin: 8px 0 0 0; font-size: 12px; color: #64748b;">Expires in {expires_minutes} minutes</p>
        </div>
        <p style="font-size: 12px; color: #64748b; line-height: 1.5;">
          Security Notice: Never share this code with anyone. Platform operators will never request your verification code.
        </p>
        <div class="footer">
          Automated security dispatch from Privacy-Preserving Threat Detection &bull; Zero Raw Telemetry Sharing
        </div>
      </div>
    </body>
    </html>
    """

    if settings.smtp_host and settings.smtp_username:
        success, err = await asyncio.to_thread(
            _send_smtp_email_sync, to_email, subject, text_content, html_content
        )
        if not success:
            logger.warning(f"[EmailService] Real-time SMTP delivery unsuccessful for {masked}: {err}")
            return False, err
        return True, None

    # Local development / test mode fallback
    logger.info(f"[EmailService] Verification OTP [{purpose}] generated and recorded for {masked} (Expires in {expires_minutes}m)")
    return True, None

async def send_password_reset_email(
    to_email: str,
    reset_token: str,
    otp_code: Optional[str] = None,
    expires_minutes: int = 15
) -> Tuple[bool, Optional[str]]:
    """
    Sends a password reset notification with both a 6-digit OTP code and a single-use token.
    """
    masked = mask_email(to_email)
    display_code = otp_code or (reset_token[:6].upper() if len(reset_token) >= 6 else "RESET")
    subject = f"Your Password Reset Code: {display_code} (Valid for {expires_minutes} min)"

    # Record in test registry
    if otp_code:
        _test_dispatched_otps[to_email] = otp_code

    text_content = (
        f"PRIVACY-PRESERVING THREAT DETECTION PLATFORM\n"
        f"Password Reset Request\n\n"
        f"Your single-use password reset code is: {display_code}\n\n"
        f"Reset Token: {reset_token}\n\n"
        f"This code will expire in {expires_minutes} minutes. "
        f"If you did not request this password reset, please contact your SOC administrator immediately.\n"
    )

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; color: #1e293b; padding: 20px; }}
        .card {{ max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 32px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }}
        .header {{ text-align: center; border-bottom: 1px solid #f1f5f9; padding-bottom: 20px; margin-bottom: 24px; }}
        .badge {{ background-color: #fee2e2; color: #b91c1c; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }}
        .otp-box {{ background-color: #f1f5f9; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 18px; text-align: center; margin: 24px 0; }}
        .otp-code {{ font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #b91c1c; font-family: 'Courier New', monospace; }}
        .footer {{ font-size: 11px; color: #64748b; margin-top: 24px; border-top: 1px solid #f1f5f9; padding-top: 16px; text-align: center; }}
      </style>
    </head>
    <body>
      <div class="card">
        <div class="header">
          <span class="badge">Password Reset</span>
          <h2 style="margin: 12px 0 4px 0; color: #0f172a; font-size: 18px;">Security Operations Console</h2>
          <p style="margin: 0; font-size: 12px; color: #64748b;">Privacy-Preserving Threat Detection Platform</p>
        </div>
        <p style="font-size: 14px; line-height: 1.5; color: #334155;">
          A password reset was requested for your account. Please enter the 6-digit code below to reset your password:
        </p>
        <div class="otp-box">
          <div class="otp-code">{display_code}</div>
          <p style="margin: 8px 0 0 0; font-size: 12px; color: #64748b;">Expires in {expires_minutes} minutes</p>
        </div>
        <p style="font-size: 11px; color: #64748b; line-height: 1.5; word-break: break-all;">
          Direct Token: <code>{reset_token}</code>
        </p>
        <div class="footer">
          Automated security dispatch from Privacy-Preserving Threat Detection &bull; Zero Raw Telemetry Sharing
        </div>
      </div>
    </body>
    </html>
    """

    if settings.smtp_host and settings.smtp_username:
        success, err = await asyncio.to_thread(
            _send_smtp_email_sync, to_email, subject, text_content, html_content
        )
        if not success:
            logger.warning(f"[EmailService] Real-time password reset SMTP delivery failed for {masked}: {err}")
            return False, err
        return True, None

    logger.info(f"[EmailService] Password reset token generated for {masked}")
    return True, None
