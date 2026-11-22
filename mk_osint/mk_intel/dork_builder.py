"""Advanced MENA Bilingual (Arabic + English + Regional) Passive Dork Builder."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List
from urllib.parse import quote_plus


@dataclass(frozen=True)
class DorkQuery:
    title: str
    engine: str
    category: str
    query: str
    url: str


class MENADorkBuilder:
    """Generates clean, targeted passive search queries across Google, Bing, and Yandex."""

    @staticmethod
    def build_for_target(
        target: str,
        include_optional_academic_gov: bool = False,
    ) -> List[DorkQuery]:
        clean = target.strip()
        q_exact = f'"{clean}"'
        queries: List[DorkQuery] = []

        def _add(title: str, engine: str, category: str, query_str: str) -> None:
            enc = quote_plus(query_str)
            if engine == "google":
                url = f"https://www.google.com/search?q={enc}"
            elif engine == "bing":
                url = f"https://www.bing.com/search?q={enc}"
            elif engine == "yandex":
                url = f"https://yandex.com/search/?text={enc}"
            else:
                url = f"https://duckduckgo.com/?q={enc}"
            queries.append(DorkQuery(title=title, engine=engine, category=category, query=query_str, url=url))

        # 1. Social & Arab Forums
        _add(
            "MENA Social Profiles (FB/IG/X/LinkedIn)",
            "google",
            "social_protected",
            f'(site:facebook.com OR site:instagram.com OR site:x.com OR site:linkedin.com) {q_exact}',
        )
        _add(
            "Arab Tech & Freelance Communities",
            "google",
            "mena_freelance_tech",
            f'(site:khamsat.com OR site:mostaql.com OR site:io.hsoub.com OR site:adslgate.com OR site:nafezly.com) {q_exact}',
        )
        _add(
            "MENA + Israel Classifieds & Marketplaces",
            "google",
            "mena_classifieds",
            f'(site:haraj.com.sa OR site:dubizzle.com.eg OR site:opensooq.com OR site:yad2.co.il OR site:avito.ma) {q_exact}',
        )
        _add(
            "Live Streaming & Voice Apps Mentions (Tango/Timo/Xena/Bigo/Yalla)",
            "google",
            "live_streaming",
            f'("tango" OR "timo" OR "تيمو" OR "xena live" OR "زينا" OR "bigo" OR "yalla") {q_exact}',
        )
        _add(
            "Public CVs, PDFs & Spreadsheets",
            "google",
            "public_documents",
            f'{q_exact} (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)',
        )
        _add(
            "Arabic News & Press Mentions",
            "google",
            "mena_news",
            f'(site:youm7.com OR site:almasryalyoum.com OR site:alarabiya.net OR site:aljazeera.net OR site:sabq.org) {q_exact}',
        )
        _add(
            "Cross-Engine Backup (Yandex Index)",
            "yandex",
            "cross_engine",
            q_exact,
        )
        _add(
            "Cross-Engine Backup (Bing Index)",
            "bing",
            "cross_engine",
            q_exact,
        )

        # Optional Category 15 (strictly opt-in via config)
        if include_optional_academic_gov:
            _add(
                "Academic Research & EKB (Optional)",
                "google",
                "15_academic_public_dorks",
                f'(site:scholar.google.com OR site:researchgate.net OR site:ekb.eg OR site:.edu.eg OR site:.edu.sa OR site:.ac.il) {q_exact}',
            )
            _add(
                "Public Indexed Gov Publications (Optional)",
                "google",
                "15_academic_public_dorks",
                f'(site:.gov.eg OR site:.gov.sa OR site:.gov.ae OR site:.gov.jo OR site:.gov.il) {q_exact}',
            )

        return queries
