"""Curated email domain intelligence lists (disposable, webmail, and MENA regional TLDs)."""

from __future__ import annotations

from typing import Dict, Set


DISPOSABLE_DOMAINS: Set[str] = {
    "mailinator.com",
    "guerrillamail.com",
    "guerrillamailblock.com",
    "10minutemail.com",
    "tempmail.com",
    "temp-mail.org",
    "yopmail.com",
    "throwawaymail.com",
    "trashmail.com",
    "sharklasers.com",
    "getnada.com",
    "mohmal.com",        # Popular Arabic disposable mail service
    "mohmal.im",
    "mohmal.in",
    "dispostable.com",
    "maildrop.cc",
    "fakeinbox.com",
    "mintemail.com",
    "getairmail.com",
    "mytemp.email",
    "emailondeck.com",
    "burnermail.io",
}

FREE_WEBMAIL_PROVIDERS: Set[str] = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "me.com",
    "proton.me",
    "protonmail.com",
    "zoho.com",
    "aol.com",
    "gmx.com",
    "mail.com",
    "maktoob.com",       # Legacy Arab webmail (Yahoo Maktoob)
    "walla.co.il",       # Israeli webmail
}

MENA_COUNTRY_TLDS: Dict[str, str] = {
    ".eg": "Egypt",
    ".sa": "Saudi Arabia",
    ".ae": "United Arab Emirates",
    ".kw": "Kuwait",
    ".qa": "Qatar",
    ".bh": "Bahrain",
    ".om": "Oman",
    ".jo": "Jordan",
    ".lb": "Lebanon",
    ".iq": "Iraq",
    ".ps": "Palestine",
    ".il": "Israel",
    ".sy": "Syria",
    ".ye": "Yemen",
    ".ly": "Libya",
    ".tn": "Tunisia",
    ".dz": "Algeria",
    ".ma": "Morocco",
    ".sd": "Sudan",
}
