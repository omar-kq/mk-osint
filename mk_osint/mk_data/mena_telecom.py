"""Offline MENA + Israel telecom numbering plans, carrier prefixes, and Arabic numeral normalization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


ARABIC_INDIC_TRANS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")


@dataclass(frozen=True)
class CountryTelecomProfile:
    iso2: str
    country_name: str
    country_name_ar: str
    dial_code: str
    timezone: str
    national_prefix: str
    mobile_prefixes: Dict[str, str]
    landline_prefixes: Dict[str, str]
    expected_nsn_lengths: Tuple[int, ...]


MENA_TELECOM_DB: Dict[str, CountryTelecomProfile] = {
    "20": CountryTelecomProfile(
        iso2="EG",
        country_name="Egypt",
        country_name_ar="مصر",
        dial_code="20",
        timezone="Africa/Cairo (UTC+2)",
        national_prefix="0",
        mobile_prefixes={
            "10": "Vodafone Egypt",
            "11": "e& Egypt (Etisalat)",
            "12": "Orange Egypt",
            "15": "WE (Telecom Egypt)",
        },
        landline_prefixes={
            "2": "Cairo / Giza",
            "3": "Alexandria",
            "50": "Dakahlia",
            "62": "Suez",
            "64": "Ismailia",
            "65": "Red Sea",
            "66": "Port Said",
            "68": "North Sinai",
            "69": "South Sinai",
            "88": "Assiut",
            "95": "Luxor",
            "97": "Aswan",
        },
        expected_nsn_lengths=(8, 9, 10),
    ),
    "966": CountryTelecomProfile(
        iso2="SA",
        country_name="Saudi Arabia",
        country_name_ar="السعودية",
        dial_code="966",
        timezone="Asia/Riyadh (UTC+3)",
        national_prefix="0",
        mobile_prefixes={
            "50": "STC",
            "53": "STC",
            "55": "STC",
            "54": "Mobily",
            "56": "Mobily",
            "58": "Zain KSA",
            "59": "Zain KSA",
            "57": "Virgin Mobile / Lebara KSA",
        },
        landline_prefixes={
            "11": "Riyadh",
            "12": "Makkah / Jeddah",
            "13": "Eastern Province",
            "14": "Madinah / Tabuk",
            "16": "Qassim / Hail",
            "17": "Asir / Jazan",
        },
        expected_nsn_lengths=(9,),
    ),
    "971": CountryTelecomProfile(
        iso2="AE",
        country_name="United Arab Emirates",
        country_name_ar="الإمارات",
        dial_code="971",
        timezone="Asia/Dubai (UTC+4)",
        national_prefix="0",
        mobile_prefixes={
            "50": "e& (Etisalat UAE)",
            "54": "e& (Etisalat UAE)",
            "56": "e& (Etisalat UAE)",
            "52": "du",
            "55": "du",
            "58": "du",
        },
        landline_prefixes={
            "2": "Abu Dhabi",
            "3": "Al Ain",
            "4": "Dubai",
            "6": "Sharjah / Ajman",
            "7": "Ras Al Khaimah",
            "9": "Fujairah",
        },
        expected_nsn_lengths=(8, 9),
    ),
    "972": CountryTelecomProfile(
        iso2="IL",
        country_name="Israel",
        country_name_ar="إسرائيل",
        dial_code="972",
        timezone="Asia/Jerusalem (UTC+2/+3)",
        national_prefix="0",
        mobile_prefixes={
            "50": "Pelephone",
            "52": "Cellcom",
            "53": "HOT Mobile",
            "54": "Partner",
            "55": "MVNO (Rami Levy / We4G)",
            "58": "Golan Telecom",
        },
        landline_prefixes={
            "2": "Jerusalem",
            "3": "Tel Aviv / Central",
            "4": "Haifa / North",
            "8": "South / Beersheba",
            "9": "Sharon",
        },
        expected_nsn_lengths=(8, 9),
    ),
    "970": CountryTelecomProfile(
        iso2="PS",
        country_name="Palestine",
        country_name_ar="فلسطين",
        dial_code="970",
        timezone="Asia/Gaza (UTC+2/+3)",
        national_prefix="0",
        mobile_prefixes={"59": "Jawwal", "56": "Ooredoo Palestine"},
        landline_prefixes={"2": "Jerusalem / Ramallah", "4": "Jenin", "8": "Gaza", "9": "Nablus"},
        expected_nsn_lengths=(8, 9),
    ),
    "962": CountryTelecomProfile(
        iso2="JO",
        country_name="Jordan",
        country_name_ar="الأردن",
        dial_code="962",
        timezone="Asia/Amman (UTC+3)",
        national_prefix="0",
        mobile_prefixes={"77": "Orange Jordan", "78": "Umniah", "79": "Zain Jordan"},
        landline_prefixes={"6": "Amman", "2": "Irbid", "3": "Aqaba", "5": "Zarqa"},
        expected_nsn_lengths=(8, 9),
    ),
    "965": CountryTelecomProfile(
        iso2="KW",
        country_name="Kuwait",
        country_name_ar="الكويت",
        dial_code="965",
        timezone="Asia/Kuwait (UTC+3)",
        national_prefix="",
        mobile_prefixes={"9": "Zain Kuwait", "6": "Ooredoo Kuwait", "5": "stc Kuwait"},
        landline_prefixes={"2": "Kuwait Landline"},
        expected_nsn_lengths=(8,),
    ),
    "974": CountryTelecomProfile(
        iso2="QA",
        country_name="Qatar",
        country_name_ar="قطر",
        dial_code="974",
        timezone="Asia/Qatar (UTC+3)",
        national_prefix="",
        mobile_prefixes={"5": "Ooredoo Qatar", "6": "Ooredoo Qatar", "3": "Vodafone Qatar", "7": "Vodafone Qatar"},
        landline_prefixes={"4": "Qatar Landline"},
        expected_nsn_lengths=(8,),
    ),
    "964": CountryTelecomProfile(
        iso2="IQ",
        country_name="Iraq",
        country_name_ar="العراق",
        dial_code="964",
        timezone="Asia/Baghdad (UTC+3)",
        national_prefix="0",
        mobile_prefixes={"77": "Asiacell", "78": "Zain Iraq", "79": "Zain Iraq", "75": "Korek Telecom"},
        landline_prefixes={"1": "Baghdad", "40": "Basra", "66": "Erbil"},
        expected_nsn_lengths=(8, 10),
    ),
    "961": CountryTelecomProfile(
        iso2="LB",
        country_name="Lebanon",
        country_name_ar="لبنان",
        dial_code="961",
        timezone="Asia/Beirut (UTC+2/+3)",
        national_prefix="0",
        mobile_prefixes={"70": "Alfa / touch", "71": "Alfa / touch", "76": "touch", "78": "touch", "79": "touch", "81": "Alfa", "3": "Alfa / touch"},
        landline_prefixes={"1": "Beirut", "4": "Mount Lebanon", "6": "North Lebanon"},
        expected_nsn_lengths=(7, 8),
    ),
    "212": CountryTelecomProfile(
        iso2="MA",
        country_name="Morocco",
        country_name_ar="المغرب",
        dial_code="212",
        timezone="Africa/Casablanca (UTC+1)",
        national_prefix="0",
        mobile_prefixes={"6": "Maroc Telecom / Orange / Inwi", "7": "Orange / Inwi"},
        landline_prefixes={"5": "Morocco Landline"},
        expected_nsn_lengths=(9,),
    ),
    "213": CountryTelecomProfile(
        iso2="DZ",
        country_name="Algeria",
        country_name_ar="الجزائر",
        dial_code="213",
        timezone="Africa/Algiers (UTC+1)",
        national_prefix="0",
        mobile_prefixes={"5": "Ooredoo Algeria", "6": "Mobilis", "7": "Djezzy"},
        landline_prefixes={"2": "Algiers / North", "3": "East", "4": "West"},
        expected_nsn_lengths=(8, 9),
    ),
    "216": CountryTelecomProfile(
        iso2="TN",
        country_name="Tunisia",
        country_name_ar="تونس",
        dial_code="216",
        timezone="Africa/Tunis (UTC+1)",
        national_prefix="",
        mobile_prefixes={"2": "Ooredoo Tunisia", "5": "Orange Tunisia", "9": "Tunisie Telecom"},
        landline_prefixes={"7": "Tunisia Landline"},
        expected_nsn_lengths=(8,),
    ),
}

ISO2_TO_DIAL = {profile.iso2: code for code, profile in MENA_TELECOM_DB.items()}


def normalize_digits(raw_phone: str) -> str:
    """Convert Arabic-Indic digits to ASCII and strip whitespace/punctuation."""
    translated = raw_phone.translate(ARABIC_INDIC_TRANS).strip()
    has_plus = translated.startswith("+")
    digits = "".join(ch for ch in translated if ch.isdigit())
    if has_plus:
        return f"+{digits}"
    if digits.startswith("00") and len(digits) > 8:
        return f"+{digits[2:]}"
    return digits


def analyze_mena_phone(raw_phone: str, default_region: str = "EG") -> Dict[str, object]:
    """Parse and profile a MENA / Israel phone number offline."""
    norm = normalize_digits(raw_phone)
    digits_only = norm.lstrip("+")

    if len(digits_only) < 7 or len(digits_only) > 15:
        return {"valid": False, "reason": "Phone length out of ITU-T E.164 range (7-15 digits)"}

    profile: Optional[CountryTelecomProfile] = None
    nsn: str = ""

    if norm.startswith("+"):
        for code in sorted(MENA_TELECOM_DB.keys(), key=len, reverse=True):
            if digits_only.startswith(code):
                profile = MENA_TELECOM_DB[code]
                nsn = digits_only[len(code):]
                break
    else:
        # Local format using default_region (e.g. 010xxxxxxxx in EG)
        dial_code = ISO2_TO_DIAL.get(default_region.upper())
        if dial_code and dial_code in MENA_TELECOM_DB:
            profile = MENA_TELECOM_DB[dial_code]
            if profile.national_prefix and digits_only.startswith(profile.national_prefix):
                nsn = digits_only[len(profile.national_prefix):]
            else:
                nsn = digits_only

    if profile is None:
        return {
            "valid": True,
            "e164": f"+{digits_only}" if norm.startswith("+") else digits_only,
            "country": "Non-MENA / International",
            "country_ar": "دولي / خارج الشرق الأوسط",
            "iso2": "INTL",
            "line_type": "Unknown",
            "carrier_or_region": "Use phonenumbers library for non-MENA carrier metadata",
            "timezone": "Unknown",
            "search_variants": [f"+{digits_only}", digits_only],
        }

    # Match mobile prefix first, then landline area code (longest prefix first)
    line_type = "Unknown"
    carrier_or_region = "Unmapped Prefix"
    for pfx in sorted(profile.mobile_prefixes.keys(), key=len, reverse=True):
        if nsn.startswith(pfx):
            line_type = "Mobile"
            carrier_or_region = profile.mobile_prefixes[pfx]
            break
    if line_type == "Unknown":
        for pfx in sorted(profile.landline_prefixes.keys(), key=len, reverse=True):
            if nsn.startswith(pfx):
                line_type = "Landline"
                carrier_or_region = profile.landline_prefixes[pfx]
                break

    e164 = f"+{profile.dial_code}{nsn}"
    local_fmt = f"{profile.national_prefix}{nsn}"
    intl_00 = f"00{profile.dial_code}{nsn}"
    variants: List[str] = []
    for v in (e164, local_fmt, intl_00, f"+{profile.dial_code} {nsn}"):
        if v not in variants:
            variants.append(v)

    length_ok = len(nsn) in profile.expected_nsn_lengths
    return {
        "valid": True,
        "length_valid": length_ok,
        "e164": e164,
        "local_format": local_fmt,
        "country": profile.country_name,
        "country_ar": profile.country_name_ar,
        "iso2": profile.iso2,
        "dial_code": f"+{profile.dial_code}",
        "line_type": line_type,
        "carrier_or_region": carrier_or_region,
        "timezone": profile.timezone,
        "search_variants": variants,
    }
