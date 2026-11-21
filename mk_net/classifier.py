"""Seven-state OSINT response classifier for M.K v2.2.

Accurately distinguishes:
  - FOUND
  - SUSPENDED_OR_DELETED (Account suspended, banned, deactivated, or deleted)
  - NOT_FOUND
  - BLOCKED (Cloudflare, WAF, CAPTCHA, Verification Wall, Login Wall, 403)
  - RATE_LIMITED (HTTP 429)
  - ERROR (Timeout, SSL, DNS, HTTP 5xx)
  - PASSIVE_DORK
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from mk_core.models import ScanStatus


WAF_SIGNATURES: List[Tuple[str, str]] = [
    ("attention required! | cloudflare", "Cloudflare WAF"),
    ("just a moment...", "Cloudflare JS Challenge"),
    ("checking your browser before accessing", "DDoS/Bot Protection"),
    ("access denied | ", "WAF Access Denied"),
    ("akamai reference", "Akamai WAF"),
    ("incapsula incident", "Imperva/Incapsula WAF"),
    ("datadome", "DataDome Protection"),
    ("verify you are human", "Human Verification Skipped"),
    ("unusual traffic from your computer", "Search Verification Skipped"),
    ("captcha", "CAPTCHA Required"),
    ("recaptcha", "reCAPTCHA Challenge"),
    ("hcaptcha", "hCaptcha Challenge"),
]

LOGIN_WALL_SIGNATURES: List[Tuple[str, str]] = [
    ("log in to continue", "Login Wall"),
    ("sign in to view", "Login Wall"),
    ("you must log in first", "Login Wall"),
    ("تسجيل الدخول للمتابعة", "Login Wall (AR)"),
    ("الرجاء تسجيل الدخول", "Login Wall (AR)"),
]

SUSPENDED_OR_DELETED_SIGNATURES: List[Tuple[str, str]] = [
    ("account suspended", "Account Suspended"),
    ("this account has been suspended", "Account Suspended"),
    ("account has been banned", "Account Banned"),
    ("user has been banned", "Account Banned"),
    ("user is banned", "Account Banned"),
    ("account has been terminated", "Account Terminated"),
    ("account deactivated", "Account Deactivated"),
    ("this account was deleted", "Account Deleted"),
    ("user deleted their account", "Account Deleted"),
    ("channel was closed due to a violation", "Channel Banned"),
    ("حساب معلق", "حساب معلق / محظور"),
    ("تم إيقاف هذا الحساب", "تم إيقاف الحساب"),
    ("تم حظر هذا الحساب", "تم حظر الحساب"),
    ("تم حذف هذا الحساب", "تم حذف الحساب"),
    ("الحساب محذوف", "الحساب محذوف"),
]


@dataclass
class SiteRule:
    """Per-site extraction and verification rule loaded from mena_sites.json."""

    name: str
    url_template: str
    category: str
    detection_mode: str = "status_code"
    found_codes: List[int] = field(default_factory=lambda: [200])
    not_found_codes: List[int] = field(default_factory=lambda: [404, 410])
    found_markers: List[str] = field(default_factory=list)
    not_found_markers: List[str] = field(default_factory=list)
    redirect_not_found_substrings: List[str] = field(default_factory=list)


class ResponseClassifier:
    """Classifies HTTP responses into M.K's 7-state ScanStatus + parenthesized reason."""

    @staticmethod
    def classify(
        rule: SiteRule,
        status_code: Optional[int],
        body_text: str = "",
        headers: Optional[Dict[str, str]] = None,
        final_url: Optional[str] = None,
        error_reason: Optional[str] = None,
    ) -> Tuple[ScanStatus, Optional[str]]:
        if rule.detection_mode == "passive_dork":
            return ScanStatus.PASSIVE_DORK, "Protected Platform - Passive Search Ready"

        if error_reason is not None or status_code is None:
            return ScanStatus.ERROR, error_reason or "Unknown Network Error"

        norm_headers = {k.lower(): v.lower() for k, v in (headers or {}).items()}
        body_lower = (body_text or "").lower()

        # 1. Rate limiting
        if status_code == 429:
            retry_after = norm_headers.get("retry-after")
            reason = f"HTTP 429 - Retry-After {retry_after}s" if retry_after else "HTTP 429 Too Many Requests"
            return ScanStatus.RATE_LIMITED, reason

        # 2. Server errors
        if 500 <= status_code <= 599:
            return ScanStatus.ERROR, f"HTTP {status_code} Server Error"

        # 3. Suspended / Banned / Deleted detection (checked BEFORE generic 404/410!)
        for marker, label in SUSPENDED_OR_DELETED_SIGNATURES:
            if marker in body_lower:
                return ScanStatus.SUSPENDED_OR_DELETED, label
        if status_code == 410:
            return ScanStatus.SUSPENDED_OR_DELETED, "HTTP 410 Gone (Deleted Account)"

        # 4. WAF / Bot / Verification / CAPTCHA detection
        if status_code in {401, 403, 406, 451}:
            waf_hit = ResponseClassifier._detect_waf(norm_headers, body_lower)
            if waf_hit:
                return ScanStatus.BLOCKED, f"{waf_hit} / HTTP {status_code}"
            if status_code == 451:
                return ScanStatus.BLOCKED, "HTTP 451 Unavailable For Legal Reasons"
            if status_code == 401:
                return ScanStatus.BLOCKED, "HTTP 401 Authentication Required"
            return ScanStatus.BLOCKED, f"HTTP {status_code} Forbidden"

        waf_hit = ResponseClassifier._detect_waf(norm_headers, body_lower)
        if waf_hit and status_code not in rule.not_found_codes:
            return ScanStatus.BLOCKED, waf_hit

        # 5. Login wall detection
        if final_url and any(tok in final_url.lower() for tok in ("/login", "/signin", "accounts/login")):
            return ScanStatus.BLOCKED, "Redirected to Login Wall"
        for marker, label in LOGIN_WALL_SIGNATURES:
            if marker in body_lower:
                return ScanStatus.BLOCKED, label

        # 6. Redirect-based NOT_FOUND
        if final_url and rule.redirect_not_found_substrings:
            final_lower = final_url.lower()
            for sub in rule.redirect_not_found_substrings:
                if sub.lower() in final_lower:
                    return ScanStatus.NOT_FOUND, None

        # 7. Explicit NOT_FOUND
        if status_code in rule.not_found_codes:
            return ScanStatus.NOT_FOUND, None
        for marker in rule.not_found_markers:
            if marker.lower() in body_lower:
                return ScanStatus.NOT_FOUND, None

        # 8. FOUND
        if rule.detection_mode == "text_match" and rule.found_markers:
            if any(m.lower() in body_lower for m in rule.found_markers):
                return ScanStatus.FOUND, None
            return ScanStatus.NOT_FOUND, None

        if status_code in rule.found_codes:
            return ScanStatus.FOUND, None

        return ScanStatus.ERROR, f"Unexpected HTTP {status_code}"

    @staticmethod
    def _detect_waf(norm_headers: Dict[str, str], body_lower: str) -> Optional[str]:
        if "cf-mitigated" in norm_headers:
            return "Cloudflare Mitigation"
        if "cf-ray" in norm_headers and ("just a moment" in body_lower or "attention required" in body_lower):
            return "Cloudflare Challenge"
        for sig, label in WAF_SIGNATURES:
            if sig in body_lower:
                return label
        return None
