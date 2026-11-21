"""M.K Phase 11 — Arabic-to-Latin, Franco-Arab & MENA Username Permutation Engine."""

from __future__ import annotations

import re
from typing import Dict, List, Sequence, Set


COMMON_ARABIC_NAMES: Dict[str, List[str]] = {
    "احمد": ["ahmed", "ahmad", "a7med", "a7mad"],
    "أحمد": ["ahmed", "ahmad", "a7med", "a7mad"],
    "محمد": ["mohamed", "mohammed", "muhammad", "m7md", "mo7amed"],
    "محمود": ["mahmoud", "mahmud", "ma7moud"],
    "عمر": ["omar", "amr", "3omar", "3mr"],
    "عمرو": ["amr", "amro", "3mr"],
    "علي": ["ali", "aly", "3li", "3ly"],
    "خالد": ["khaled", "khalid", "5aled"],
    "يوسف": ["youssef", "yousef", "yusuf", "youssif"],
    "مصطفى": ["mostafa", "mustafa", "mo9tafa"],
    "مصطفي": ["mostafa", "mustafa"],
    "كريم": ["karim", "kareem"],
    "طارق": ["tarek", "tariq", "6arek"],
    "حسين": ["hussein", "hossein", "7ussein"],
    "حسن": ["hassan", "hasan", "7assan"],
    "ابراهيم": ["ibrahim", "ebrahim", "ibrahem"],
    "إبراهيم": ["ibrahim", "ebrahim", "ibrahem"],
    "عبدالله": ["abdullah", "abdallah", "3bdullah"],
    "عبدالرحمن": ["abdelrahman", "abdulrahman", "3bdelrahman"],
    "سارة": ["sara", "sarah"],
    "ساره": ["sara", "sarah"],
    "مريم": ["mariam", "maryam"],
    "نور": ["nour", "noor", "nor"],
    "فاطمة": ["fatma", "fatima"],
    "سلمى": ["salma"],
    "صلاح": ["salah", "sala7"],
    "سعيد": ["saeed", "said", "sa3eed"],
    "ياسر": ["yasser", "yaser"],
    "زياد": ["ziad", "zyad", "zeyad"],
    "رامي": ["rami", "ramy"],
    "تامر": ["tamer", "tamir"],
    "شريف": ["sherif", "sharif"],
    "وليد": ["waleed", "walid"],
    "هشام": ["hesham", "hisham"],
    "أشرف": ["ashraf"],
    "اشرف": ["ashraf"],
}

ARABIC_TO_LATIN_MAP: Dict[str, str] = {
    "ا": "a", "أ": "a", "إ": "e", "آ": "a", "ب": "b", "ت": "t", "ث": "th",
    "ج": "g", "ح": "h", "خ": "kh", "د": "d", "ذ": "z", "ر": "r", "ز": "z",
    "س": "s", "ش": "sh", "ص": "s", "ض": "d", "ط": "t", "ظ": "z", "ع": "a",
    "غ": "gh", "ف": "f", "ق": "q", "ك": "k", "ل": "l", "م": "m", "ن": "n",
    "ه": "h", "ة": "a", "و": "w", "ي": "y", "ى": "a", "ئ": "e", "ؤ": "o", "ء": "",
}

ARABIC_TO_FRANCO_MAP: Dict[str, str] = {
    **ARABIC_TO_LATIN_MAP,
    "ح": "7",
    "ع": "3",
    "خ": "5",
    "ط": "6",
    "ص": "9",
    "ق": "2",
    "غ": "3'",
}

ARABIC_CHAR_RE = re.compile(r"[\u0600-\u06FF]")
DIACRITICS_RE = re.compile(r"[\u064B-\u065F\u0670]")
MENA_SUFFIXES = ("eg", "sa", "ae", "kw", "jo", "ma", "il", "dev", "official")


def has_arabic(text: str) -> bool:
    return bool(ARABIC_CHAR_RE.search(text))


def transliterate_arabic_word(word: str) -> List[str]:
    """Return prioritized Latin & Franco-Arab spellings for a single Arabic word."""
    cleaned = DIACRITICS_RE.sub("", word.strip())
    if not cleaned:
        return []
    variants: List[str] = []
    if cleaned in COMMON_ARABIC_NAMES:
        variants.extend(COMMON_ARABIC_NAMES[cleaned])

    latin = "".join(ARABIC_TO_LATIN_MAP.get(ch, ch) for ch in cleaned)
    franco = "".join(ARABIC_TO_FRANCO_MAP.get(ch, ch) for ch in cleaned).replace("'", "")
    for v in (latin, franco):
        v_clean = re.sub(r"[^a-zA-Z0-9]", "", v).lower()
        if v_clean and v_clean not in variants:
            variants.append(v_clean)
    return variants


def generate_username_permutations(
    raw_input: str,
    region_code: str = "eg",
    max_variants: int = 35,
    include_years: Sequence[str] = (),
) -> List[str]:
    """Generate clean, prioritized MENA username permutations from Arabic or Latin input."""
    cleaned = raw_input.strip().lstrip("@")
    if not cleaned:
        return []

    tokens = [t for t in re.split(r"[\s._\-]+", cleaned) if t]
    seen: Set[str] = set()
    out: List[str] = []

    def _add(handle: str) -> None:
        h = handle.strip("._-").lower()
        if len(h) >= 2 and h not in seen and len(out) < max_variants:
            seen.add(h)
            out.append(h)

    if has_arabic(cleaned):
        word_variants = [transliterate_arabic_word(t) for t in tokens]
        if len(word_variants) == 1:
            for base in word_variants[0]:
                _add(base)
                _add(f"{base}_{region_code.lower()}")
                _add(f"{base}.{region_code.lower()}")
                _add(f"_{base}")
                _add(f"{base}_")
        else:
            first_list = word_variants[0][:3]
            last_list = word_variants[-1][:3]
            # High-priority primary combinations + regional suffix first
            f0, l0 = first_list[0], last_list[0]
            for c in (f"{f0}_{l0}", f"{f0}.{l0}", f"{f0}{l0}", f"{f0}_{region_code.lower()}", f"{f0[0]}_{l0}", f"{l0}_{f0}"):
                _add(c)
            # Secondary spelling & Franco-Arab combinations
            for f in first_list:
                for l in last_list:
                    _add(f"{f}_{l}")
                    _add(f"{f}.{l}")
                    _add(f"{f}{l}")
                    _add(f"{l}_{f}")
    else:
        base_clean = re.sub(r"[^a-zA-Z0-9._-]", "", cleaned).lower()
        _add(base_clean)
        joined = "".join(tokens).lower()
        _add(joined)
        if len(tokens) >= 2:
            f, l = tokens[0].lower(), tokens[-1].lower()
            for candidate in (f"{f}_{l}", f"{f}.{l}", f"{f}-{l}", f"{f}{l}", f"{f[0]}_{l}", f"{f[0]}{l}", f"{l}_{f}"):
                _add(candidate)
        else:
            b = tokens[0].lower()
            _add(f"{b}_{region_code.lower()}")
            _add(f"{b}.{region_code.lower()}")
            _add(f"{b}{region_code.lower()}")
            _add(f"_{b}")
            _add(f"{b}_")
            _add(f"real_{b}")
            _add(f"the_{b}")
            for sfx in MENA_SUFFIXES:
                if sfx != region_code.lower():
                    _add(f"{b}_{sfx}")

    if include_years and out:
        primary = out[0]
        for yr in include_years:
            _add(f"{primary}{yr}")
            _add(f"{primary}_{yr}")

    return out
