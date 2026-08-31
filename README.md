<p align="center">
  <img src="app_logo.jpg" alt="USB Port Controller Shield Logo" width="160" style="border-radius: 20px; box-shadow: 0 4px 20px rgba(0,0,0,0.3);" />
</p>

<h1 align="center">🛡️ USB Port Controller Shield</h1>
<h3 align="center">درع أمني احترافي للتحكم في منافذ USB وحماية البيانات لنظام Windows</h3>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%207%20%7C%208%20%7C%2010%20%7C%2011%20%7C%20Server-blue.svg" alt="Platform" />
  <img src="https://img.shields.io/badge/.NET%20Framework-4.0%2B-green.svg" alt=".NET Version" />
  <img src="https://img.shields.io/badge/Language-C%23%20%7C%20Win32-purple.svg" alt="Languages" />
  <img src="https://img.shields.io/badge/UI-Arabic%20%2F%20English-orange.svg" alt="Multi-Language" />
  <img src="https://img.shields.io/badge/License-MIT-brightgreen.svg" alt="License" />
</p>

---

## 📖 حول المشروع (About The Project)

**USB Port Controller Shield** هو تطبيق أمني خفيف وقوي مصمم لحماية أجهزة الكمبيوتر ومحطات العمل من تسريب البيانات واختراق الفلاشات. يتيح لك البرنامج التحكم الكامل في منافذ الـ USB عبر إيقافها كلياً، أو تفعيل وضع **القراءة فقط (Read-Only)** لمنع نقل الملفات إلى وسائط التخزين الخارجية، وكل ذلك محمي بكلمة سر رئيسية مشفرة ونظام تشغيل دائم في الخلفية.

---

## ✨ أبرز المميزات (Features)

- 🔒 **حماية بكلمة سر رئيسية مشفرة**: تشفير قوي باستخدام خوارزمية **`SHA-256`** مع نظام التمليح **`Salt`** لمنع أي تلاعب غير مصرح به.
- 💾 **حظر وتمكين منافذ الفلاشات فورياً**: إيقاف تشغيل منافذ الـ USB التخزينية فورياً عبر سجل النظام `USBSTOR`.
- ✍️ **وضع الحماية من النسخ (Write-Protection)**: السماح بقراءة وتصفح الفلاشة مع منع كتابة أو نسخ أو تعديل أي ملف عليها منعاً لتسريب البيانات الحساسة.
- 🌐 **واجهة ثنائية اللغة (Arabic / English)**: تبديل فوري بنقرة زر واحدة مع ضبط اتجاه الواجهة (`RTL` / `LTR`) وتذكر لغة المستخدم المفضلة.
- 🔄 **حماية مستمرة مع إقلاع النظام (Auto-Start)**: تشغيل دائم في الخلفية مع شريط المهام بجانب الساعة (System Tray) لضمان استمرار الحماية بعد إعادة تشغيل الجهاز.
- 🔌 **مراقبة حية للأجهزة المتصلة**: اكتشاف تلقائي وتنبيه فوري عند إدخال أو فصل أي جهاز USB.
- 🖥️ **توافق مع دقة الشاشات (Per-Monitor High-DPI Scaling)**: واجهة واضحة ونقية بدون أي ضبابية على شاشات 1080p و 2K و 4K ومختلف نسب التكبير.
- 📦 **معالج تثبيت رسمي مدمج (Setup Installer)**: لتنصيب التطبيق في مسار برامج الويندوز وإنشاء الاختصارات ودعم إلغاء التثبيت النظيف (Add/Remove Programs).

---

## 🚀 طريقة التجميع والتشغيل (How to Build & Run)

المشروع مصمم ليعمل بدون الحاجة لتثبيت برامج ثقيلة، يمكنك تجميعه مباشرة عبر مترجم السي شارب المدمج في نظام ويندوز:

1. **حمّل المستودع أو انسخه**:
   ```bash
   git clone https://github.com/AzamAhmed77/USB-Port-Shield.git
   ```

2. **تجميع المشروع**:
   - شغّل الملف `build.bat` بالنقر المزدوج عليه.
   - سيتم تجميع البرنامجين تلقائياً:
     - `USBController.exe` : التطبيق الرئيسي (جاهز للعمل المباشر كأداة محمولة Portable).
     - `Setup.exe` : معالج التثبيت الرسمي لتنصيب البرنامج في النظام.

---

## 🛠️ متطلبات التشغيل (System Requirements)

- **أنظمة التشغيل المدعومة**: Windows 7 / 8 / 8.1 / 10 / 11 / Windows Server (32-bit & 64-bit).
- **بيئة التشغيل**: .NET Framework 4.0 أو أحدث (مدمج تلقائياً في جميع إصدارات ويندوز الحديثة).
- **صلاحيات التشغيل**: يتطلب صلاحيات مسؤول (Administrator) للتحكم في سجل النظام ومنافذ الـ USB.

---

## 👤 المطور (Developer)

- **GitHub**: [@AzamAhmed77](https://github.com/AzamAhmed77)
- **Project**: [USB-Port-Shield](https://github.com/AzamAhmed77/USB-Port-Shield)
