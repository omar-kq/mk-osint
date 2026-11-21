# ⚙ M.K v2.0.0 — MENA OSINT Intelligence Framework (15 Phases Complete)

إطار عمل OSINT معياري كامل مخصص للشرق الأوسط وشمال أفريقيا (+ إسرائيل) ومصمم للعمل على أحدث إصدارات **Kali Linux** (متوافق مع PEP 668).

## التثبيت السريع على Kali Linux
```bash
git clone <your-repo-url>
cd mk_osint
chmod +x install_kali.sh
./install_kali.sh
```

## أبرز أوامر التشغيل في M.K v2.0
```bash
# عرض كل الوحدات المحمّلة تلقائيًا (12 وحدة)
mk --list-modules

# تشغيل لوحة التيرمنال التفاعلية الكاملة (Textual Split-Pane TUI)
mk --tui

# فحص يوزر نيم عبر 120+ منصة في 15 مجموعة + حفظ في قضية + تصدير كل التقارير
mk -t ahmed_eg -m username_mena --case "MENA Case" --export all

# تحويل اسم عربي لتنويعات لاتيني وفرانكو للبحث عن الحسابات البديلة
mk -t "أحمد صلاح" --type keyword -m username_permutations

# فحص جماعي من ملف مع حفظ التقدم والاستئناف (Checkpoint/Resume)
mk --batch targets.txt --case "Batch Ops" --export html

# مقارنة الفحص الجديد مع القديم في SQLite لكشف التغييرات فقط
mk -t ahmed_eg -m username_mena --diff

# استيراد قاعدة بياناتك الخاصة (CSV / JSON / SQLite) والبحث فيها بالـ AI المحلي
mk --import-db my_custom_db.csv --ai-ask "احمد القاهره"

# تشغيل عبر Tor / SOCKS5 لحماية خصوصية الباحث
mk -t ahmed_eg -m username_mena --proxy socks5h://127.0.0.1:9050
```
