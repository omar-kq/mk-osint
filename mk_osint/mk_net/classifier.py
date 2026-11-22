"""Seven-state OSINT response classifier for M.K v2.3 (Anti-False-Positive Edition).

Accurately distinguishes:
  - FOUND (verified real profile, not a redirect to /404, /signup, or bare homepage)
  - SUSPENDED_OR_DELETED (banned, suspended, deactivated, /account-deleted, HTTP 410)
  - NOT_FOUND (404, /404 redirect, /signup?new_domain=..., bare homepage redirect, or text marker)
  - BLOCKED (Cloudflare, WAF, HTTP 202 AWS WAF challenge, CAPTCHA, Login Wall, 403)
  - RATE_LIMITED (HTTP 429)
  - ERROR (Timeout, SSL, DNS, HTTP 5xx)
  - PASSIVE_DORK
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

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

GENERIC_NOT_FOUND_MARKERS: List[str] = [
    "page not found",
    "user not found",
    "profile not found",
    "couldn't find this account",
    "this page isn't available",
    "sorry, nobody on reddit goes by that name",
    "الصفحة غير موجودة",
    "المستخدم غير موجود",
    "الحساب غير موجود",
    "404 not found",
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
    """Classifies HTTP responses into M.K's 7-state ScanStatus with strict anti-false-positive checks."""

    @staticmethod
    def classify(
        rule: SiteRule,
        status_code: Optional[int],
        body_text: str = "",
        headers: Optional[Dict[str, str]] = None,
        final_url: Optional[str] = None,
        error_reason: Optional[str] = None,
        target: Optional[str] = None,
    ) -> Tuple[ScanStatus, Optional[str]]:
        if rule.detection_mode == "passive_dork":
            return ScanStatus.PASSIVE_DORK, "Protected Platform - Passive Search Ready"

        if error_reason is not None or status_code is None:
            return ScanStatus.ERROR, error_reason or "Unknown Network Error"

        norm_headers = {k.lower(): v.lower() for k, v in (headers or {}).items()}
        body_lower = (body_text or "").lower()
        final_lower = (final_url or "").lower()

        # 1. Rate limiting
        if status_code == 429:
            retry_after = norm_headers.get("retry-after")
            reason = f"HTTP 429 - Retry-After {retry_after}s" if retry_after else "HTTP 429 Too Many Requests"
            return ScanStatus.RATE_LIMITED, reason

        # 2. HTTP 202 AWS WAF / Bot JS Challenge (e.g., Khamsat / Mostaql)
        if status_code == 202:
            return ScanStatus.BLOCKED, "WAF JS Challenge / HTTP 202"

        # 3. Server errors
        if 500 <= status_code <= 599:
            return ScanStatus.ERROR, f"HTTP {status_code} Server Error"

        # 4. Suspended / Banned / Deleted detection (URL + body + HTTP 410)
        if any(tok in final_lower for tok in ("/account-deleted", "/deleted", "/suspended", "/banned")):
            return ScanStatus.SUSPENDED_OR_DELETED, "Redirected to Deleted/Suspended Page"
        for marker, label in SUSPENDED_OR_DELETED_SIGNATURES:
            if marker in body_lower:
                return ScanStatus.SUSPENDED_OR_DELETED, label
        if status_code == 410:
            return ScanStatus.SUSPENDED_OR_DELETED, "HTTP 410 Gone (Deleted Account)"

        # 5. WAF / Bot / Verification / CAPTCHA detection
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

        # 6. Login / Signup / 404 / Bare Homepage Redirect Anti-False-Positive Checks
        if final_lower:
            if any(tok in final_lower for tok in ("/login", "/signin", "accounts/login", "/users/sign_in")):
                return ScanStatus.BLOCKED, "Redirected to Login Wall"
            if any(tok in final_lower for tok in ("/404", "/not-found", "/notfound", "/signup", "/register")):
                return ScanStatus.NOT_FOUND, None
            # Detect redirect to a bare root homepage (e.g. bento.me -> linktr.ee, taplink.cc/x -> taplink.at/en/)
            parsed_final = urlparse(final_lower)
            clean_path = parsed_final.path.strip("/")
            if clean_path in {"", "en", "ar", "home", "index.html"} and target and target.lower() not in parsed_final.netloc:
                return ScanStatus.NOT_FOUND, None

        # 7. Custom redirect NOT_FOUND substrings
        if final_lower and rule.redirect_not_found_substrings:
            for sub in rule.redirect_not_found_substrings:
                if sub.lower() in final_lower:
                    return ScanStatus.NOT_FOUND, None

        # 8. Explicit NOT_FOUND status code or body markers
        if status_code in rule.not_found_codes:
            return ScanStatus.NOT_FOUND, None
        for marker in rule.not_found_markers + GENERIC_NOT_FOUND_MARKERS:
            if marker.lower() in body_lower:
                return ScanStatus.NOT_FOUND, None

        # 9. FOUND verification (with SPA sanity check when target is known)
        if rule.detection_mode == "text_match" and rule.found_markers:
            if any(m.lower() in body_lower for m in rule.found_markers):
                return ScanStatus.FOUND, None
            return ScanStatus.NOT_FOUND, None

        if status_code in rule.found_codes:
            # If we have a large HTML response AND a target username, verify username appears in body or final_url
            if target and len(body_lower) > 500:
                t_low = target.lower()
                if t_low not in body_lower and t_low not in final_lower:
                    return ScanStatus.NOT_FOUND, None
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
