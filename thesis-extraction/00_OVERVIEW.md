# 00 — نظرة عامة على المشروع

## 1. اسم المشروع والوصف

**الاسم**: `keyring-api`، كما هو معرَّف في `pyproject.toml:6` (`name = "keyring-api"`، `version = "1.0.0"`).
اسم الحزمة البرمجية (package) هو `keyring` — دليل بايثون بنفس الاسم في جذر المستودع (`keyring/__init__.py`).

**الوصف الحرفي** من `pyproject.toml:8`:
> "Production-grade key-management / crypto-shredding backend"

**الوصف الموسّع** من الفقرة الافتتاحية لـ `README.md:1-8`:
> نظام إدارة مفاتيح (key-management) وcrypto-shredding من فئة الإنتاج (production-grade): تشفير أظرف
> (envelope encryption) بمفاتيح بيانات (DEK) أحادية الاستخدام لكل عنصر، تدوير KEK قابل للاستئناف
> (resumable rotation) مع rewrap في الخلفية، حق المحو (right-to-erasure) عبر crypto-shredding
> بشهادات موقّعة، سجل تدقيق (audit log) مسلسل بالهاش (hash-chained)، صلاحيات قائمة على الأدوار
> (RBAC) مع موافقة طرفين (two-party approval) للعمليات المدمِّرة، استرجاع السر الجذري (root secret)
> مدعوم بـ Shamir، أربعة مزوّدي مفاتيح (key providers) قابلين للتبديل، وتعريب كامل
> إنجليزي/عربي.

## 2. الهدف الوظيفي المستنتج من الكود

نظام Keyring مصمَّم كخدمة backend وسيطة (middleware service) تُستدعى من تطبيقات أخرى لتشفير/فك تشفير
بيانات حساسة نيابةً عنها، مع الحفاظ على القدرة على "محو" بيانات موضوع (subject) بعينه بشكل يجعلها
غير قابلة للاسترجاع تقنياً — دون الحاجة لحذف السجلات الفعلية من قاعدة البيانات (crypto-shredding).
يُستدل على هذا الغرض من:

- بنية تسلسل المفاتيح ثلاثي المستويات (root → KEK → subject key → DEK) الموثَّقة في
  `THREAT_MODEL.md:11-20` وiمُنفَّذة في `keyring/core/service.py` (انظر `03_ARCHITECTURE.md`).
- وجود نقطة نهاية `POST /api/subjects/{subject_id}/erasure` في `keyring/api/subjects.py:71-72` التي
  تُنتج شهادة محو موقّعة (`keyring/core/certificate.py`)، منسجمة مع سيناريوهات الامتثال لـ
  GDPR/CCPA المذكورة صراحةً في `THREAT_MODEL.md:59`.
- لوحة تحكم تشغيلية (operator console) كاملة في `web/` موجَّهة لمشغّلين بشرِيين (key-admin، auditor،
  operator) لا لاستهلاك آلي بحت — تتضمن شاشات Dashboard وKeyMap وAudit وPrivacy (انظر
  `09_UI_INVENTORY.md`).

## 3. نوع النظام

**نظام backend من نوع API خدمي (service API) بلوحة تحكم ويب مصاحبة** — وليس تطبيق سطح مكتب، ولا
خط أنابيب تعلّم آلي، ولا نظام مضمَّن (embedded). الدليل:
- `keyring/main.py` يبني تطبيق FastAPI عبر `FastAPI(...)`، وهو إطار عمل ASGI لبناء REST APIs.
- التشغيل الموثَّق في `README.md:41` هو `uvicorn keyring.main:app --reload` — خادم HTTP.
- `web/` تطبيق Single Page Application مبني بـ Vite يُقدَّم إما بخادم Vite تطويري منفصل أو مباشرة
  من عملية الـ API نفسها في الإنتاج (`README.md:75-76`؛ التركيب الفعلي في `keyring/main.py:126-128`
  حيث تُركَّب `web/dist` كملفات ثابتة تحت المسار `/`).

## 4. المعمارية العامة

**معمارية طبقية (layered) ضمن عملية واحدة (monolith)، مع فصل خادم/عميل (client-server) بين
`web/` والـ API** — وليست microservices (لا توجد خدمات متعددة منفصلة الاستضافة، ولا قوائم رسائل بين
عمليات، ولا اكتشاف خدمات). الدليل من بنية المجلدات:

- `keyring/api/` — طبقة النقل (transport layer): 10 وحدات موجّهات (routers) تستقبل طلبات HTTP وتُرجع
  استجابات JSON/ملفات، بلا منطق أعمال مباشر (انظر `05_API.md`).
- `keyring/core/` — طبقة منطق الأعمال (business/domain layer): 12 وحدة (`service.py`، `crypto.py`،
  `rbac.py`، `lifecycle.py`، `audit.py`، `shamir.py`، `certificate.py`، `backup.py`، `runtime.py`،
  `keystore.py`، `errors.py`، `threat_model.py`، `timeutil.py`). `KeyringService` في `service.py`
  هي النقطة المركزية الوحيدة التي تُنسّق بين التشفير وقاعدة البيانات ومزوّدي المفاتيح.
- `keyring/models/` — طبقة النموذج/البيانات (ORM layer): 10 ملفات تعريف جداول SQLAlchemy.
- `keyring/providers/` — طبقة تجريد المزوّدين (provider abstraction): واجهة `base.py` وأربع تنفيذات
  (`file_provider.py`، `env_provider.py`، `vault_provider.py`، `kms_provider.py`) — نمط Strategy
  فعلي (تفصيل في `03_ARCHITECTURE.md`).
- `keyring/i18n/` — طبقة تعريب مستقلة عن العرض، تُستهلك من طبقتَي API وcore.
- `alembic/` — طبقة ترحيل المخطط (schema migration)، منفصلة عن كود التطبيق.
- `web/src/` — تطبيق عميل منفصل تماماً (عملية Node.js/متصفح مستقلة)، يتواصل مع الـ API فقط عبر
  HTTP/JSON (`web/src/api/client.ts`) — لا استيراد مباشر لكود بايثون. هذا هو حد client-server.

هذا التصنيف (طبقي + عميل/خادم، بلا فصل خدمات) واضح لأن كل الطبقات الخلفية (`api`، `core`، `models`،
`providers`) تعمل داخل عملية Python واحدة (`uvicorn keyring.main:app`) وتتشارك نفس اتصال قاعدة
البيانات (`keyring/db.py`)، بينما `web/` عملية منفصلة تتصل فقط عبر HTTP.

## 5. شجرة المجلدات (حتى عمق 3 مستويات)

تُستثنى: `.venv/`, `node_modules/`, `dist/`, `__pycache__/`, `.pytest_cache/`, `.serena/`, `.claude/`.

```
.
├── alembic/                      ترحيلات قاعدة البيانات (Alembic)
│   ├── env.py                    سكربت بيئة Alembic (اتصال DB، استيراد النماذج)
│   ├── README                    توثيق Alembic القياسي
│   ├── script.py.mako            قالب توليد ترحيلات جديدة
│   └── versions/
│       └── e1a463aef094_initial_schema.py   الترحيل الوحيد — المخطط الكامل (258 سطراً)
├── data/                          مواد السر الجذري (root secret) — خارج قاعدة البيانات عمداً
│   ├── kek_store.enc.json        متجر KEK مشفَّر AES-256-GCM محلياً
│   ├── root.passphrase           عبارة مرور مزوّد file (وضع 0400 مطلوب)
│   └── root.salt                 ملح Argon2id لمزوّد file
├── keyring/                       حزمة بايثون الرئيسية (الـ backend)
│   ├── api/                      طبقة نقاط النهاية HTTP (10 وحدات موجّهات + مخططات Pydantic)
│   ├── core/                     منطق الأعمال والتشفير (12 وحدة، أهمها service.py وcrypto.py)
│   ├── i18n/                     كتالوجات الترجمة en.json/ar.json + منطق التفاوض اللغوي
│   ├── models/                   تعريفات جداول SQLAlchemy (10 ملفات، 14 كياناً)
│   ├── providers/                4 مزوّدي مفاتيح قابلين للتبديل (file/env/vault/kms) + واجهة base
│   ├── tests/                    16 ملف اختبار pytest (159 دالة اختبار)
│   ├── config.py                 إعدادات pydantic-settings من متغيرات KEYRING_*
│   ├── db.py                     إعداد محرك SQLAlchemy وجلسة DB
│   ├── main.py                   نقطة الدخول: تطبيق FastAPI، الموجّهات، العامل الخلفي، التركيب الثابت
│   └── seed.py                   سكربت تعبئة بيانات تجريبية واقعية
├── ui/                             mockup ساكن من أداة تصميم بصري — مرجع بصري فقط، ليس كوداً منفَّذاً
│   ├── Keyring.dc.html            ملف تصميم (1,359 سطراً)
│   ├── support.js                 منطق دعم للـ mockup (1,911 سطراً)
│   └── _ds/                       حزمة نظام التصميم (design system bundle) المرجعية
├── web/                            الواجهة الأمامية — عملية Vite/React منفصلة
│   ├── public/                    أصول ثابتة تُخدَّم كما هي
│   └── src/
│       ├── api/                  عميل fetch + نقاط النهاية المسمّاة + أنواع TypeScript
│       ├── auth/                 AuthContext — إدارة حالة الجلسة والصلاحيات
│       ├── components/           5 مكوّنات قابلة لإعادة الاستخدام (حوارات، صدفة التخطيط، إشعارات)
│       ├── i18n/                 كتالوج ترجمة الواجهة + سياق اللغة (منفصل عن i18n الخلفية)
│       ├── routes/                9 شاشات (Dashboard، Keys، KeyMap، Rewrap، Privacy، Audit، Settings…)
│       └── styles/                نظام تصميم Nocturne (CSS متغيرات، بلا Tailwind)
├── alembic.ini                    إعداد Alembic (مسار السكربتات، اتصال DB)
├── pyproject.toml                  تعريف الحزمة والتبعيات (setuptools)
├── README.md                       توثيق التثبيت والتشغيل والاختبار
└── THREAT_MODEL.md                 نموذج التهديد الكامل — الأصول، حدود الثقة، نموذج الخصم
```

## 6. إحصاءات المستودع

### عدد الملفات وأسطر الكود (LOC) لكل لغة

| اللغة/النوع | عدد الملفات | عدد الأسطر | المصدر |
|---|---|---|---|
| Python (`keyring/` + `alembic/`، بلا `__pycache__`) | 73 | 6,752 | `find keyring alembic -name '*.py' \| xargs wc -l` |
| TypeScript/TSX (`web/src/`) | 22 | 3,102 | `find web/src -name '*.ts' -o -name '*.tsx' \| xargs wc -l` |
| CSS (`web/src/styles/`) | 3 | 490 | `find web/src -name '*.css' \| xargs wc -l` |
| HTML/JS (`ui/` — mockup مرجعي فقط) | 3 ملفات (`Keyring.dc.html`، `support.js`، `web/index.html`) | 3,281 (لملفات `ui/` فقط) | `wc -l` |
| JSON (تهيئة، بلا `node_modules`/`.venv`/`dist`) | 12 | [غير مُحصى سطرياً — ملفات تهيئة] | `find . -name '*.json'` |
| Markdown (جذر المشروع + `web/`) | 3 (`README.md`، `THREAT_MODEL.md`، `web/README.md`) | — | `find` |

**الإجمالي الفعلي المنفَّذ (Python + TypeScript + CSS)**: 98 ملفاً، 10,344 سطراً.

### حجم المستودع

**12 MB** بدون `.venv/` و`node_modules/` (قياس: `du -sh --exclude=.venv --exclude=node_modules .`).
أكبر مساهم فردي في الحجم: `keyring.db` — **9.1 MB** (قاعدة بيانات SQLite مبذورة ببيانات تجريبية،
انظر `04_DATABASE.md`). ملف `Keyring Design Component.zip` موجود في الجذر ولم يُفحص محتواه (خارج
نطاق الكود المصدري المنفَّذ).

### إحصاءات Git

**[غير موجود في الكود]** — لا يوجد مجلد `.git` في المستودع؛ الأمر `git status` يُرجع
`fatal: not a git repository (or any parent up to mount point /)`. بالتالي لا يمكن استخراج: عدد
الـ commits، تاريخ أول/آخر commit، عدد المساهمين، أو أي تحليل لتاريخ التطوير. هذه الفجوة موثّقة
بالتفصيل في `13_GAPS.md` و`10_METHODOLOGY.md`.

## 7. ملاحظة على `ui/`

مجلد `ui/` ليس جزءاً من التطبيق المنفَّذ (runtime). حسب `README.md:79`:
> "`ui/` holds the original static design-tool mockup used as its visual reference only."

أي أن `ui/Keyring.dc.html` و`ui/support.js` و`ui/_ds/` هي مخرجات أداة تصميم بصري استُخدمت كمرجع
عند بناء `web/src/styles/nocturne.css` الفعلي، ولا تُستورَد أو تُشغَّل من أي كود إنتاجي. يُشار إليها
في `09_UI_INVENTORY.md` كمرجع بصري فقط.
