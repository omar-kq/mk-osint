# متطلبات التشغيل والتثبيت قبل البدء على Kali Linux

لضمان الحصول على **أحدث إصدارات المكتبات** المتوافقة مع معمارية جهازك (`x86_64` أو `ARM64`) ونسخة Python على Kali Linux، لا يتم دمج ملفات الباينري الخاصة بالمكتبات داخل الكود، بل يقوم سكربت `install_kali.sh` بتثبيتها تلقائيًا بأحدث إصدار داخل بيئة معزولة `.venv` (متوافق مع PEP 668).

## المكتبات المطلوبة (تُثبّت تلقائيًا بأحدث إصدار)
1. **`rich`** — واجهة التيرمنال السايبر بانك، الألوان النيون الدلالية، والترس ثلاثي الأبعاد المتحرك.
2. **`textual`** — لوحة التيرمنال التفاعلية المقسّمة (`mk --tui`).
3. **`httpx[socks]`** — محرك الشبكة غير المتزامن مع دعم `Tor / SOCKS5`.
4. **`dnspython`** — فحص سجلات `DNS / MX / SPF / DMARC`.
5. **`phonenumbers`** — إثراء تحليل أرقام الهواتف الدولية (اختياري؛ الشرق الأوسط وإسرائيل مدمجان Offline).
6. **`Pillow`** — استخراج بيانات الصور `EXIF` وإحداثيات `GPS`.
7. **`pypdf`** — استخراج بيانات مستندات `PDF`.

## خطوات التثبيت على Kali Linux (أمر واحد)
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
chmod +x install_kali.sh
./install_kali.sh
```

## (اختياري) تفعيل Tor للـ OPSEC
```bash
sudo apt install -y tor
sudo systemctl start tor
mk -t ahmed_eg -m username_mena --proxy socks5h://127.0.0.1:9050
```
