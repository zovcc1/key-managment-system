# 01 — حزمة التقنيات (Tech Stack)

## 1. إصدارات اللغة والـ runtime

| العنصر | الإصدار المطلوب | الإصدار الفعلي المثبَّت | المصدر |
|---|---|---|---|
| Python | `>=3.11` | `3.14.5` (بيئة `.venv` الفعلية) | `pyproject.toml:9` (`requires-python`)؛ `./.venv/bin/python --version` |
| Node.js | [غير موجود في الكود] — لا يوجد `.nvmrc` ولا حقل `engines` في `web/package.json` | — | بحث في `web/` عن `.nvmrc`/`.node-version` — غير موجود |
| TypeScript | `~6.0.2` (المطلوب) | `6.0.3` (المثبَّت فعلياً في `node_modules`) | `web/package.json:23`؛ `web/package-lock.json` |

## 2. تبعيات Python — Runtime (`pyproject.toml:11-25`)

جميعها مثبَّتة كحد أدنى (`>=`) لا كإصدار مثبَّت (pinned)؛ العمود "الإصدار الفعلي" هو ما نصّبته
`pip` فعلياً في `.venv` (من `pip list --format=freeze`).

| الاسم | القيد في `pyproject.toml` | الإصدار الفعلي المثبَّت | الوظيفة في المشروع | السطر |
|---|---|---|---|---|
| `fastapi` | `>=0.115` | `0.141.1` | إطار عمل ASGI لبناء الـ API؛ التطبيق مُعرَّف في `keyring/main.py` | `pyproject.toml:12` |
| `uvicorn[standard]` | `>=0.30` | `0.52.4` | خادم ASGI لتشغيل التطبيق (`README.md:41`) | `pyproject.toml:13` |
| `pydantic` | `>=2.8` | `2.13.4` | التحقق من صحة مخططات الطلب/الاستجابة في `keyring/api/schemas.py` | `pyproject.toml:14` |
| `pydantic-settings` | `>=2.4` | `2.15.0` | تحميل إعدادات `KEYRING_*` من البيئة/`.env` في `keyring/config.py` | `pyproject.toml:15` |
| `sqlalchemy` | `>=2.0` | `2.0.52` | ORM وتعريف الجداول (`keyring/models/*`، `keyring/db.py`) | `pyproject.toml:16` |
| `alembic` | `>=1.13` | `1.19.1` | إدارة ترحيلات مخطط قاعدة البيانات (`alembic/`) | `pyproject.toml:17` |
| `psycopg[binary]` | `>=3.2` | `3.3.4` | سائق (driver) PostgreSQL — القاعدة المستهدَفة للإنتاج (`THREAT_MODEL.md:101-106`) | `pyproject.toml:18` |
| `cryptography` | `>=43` | `50.0.0` | بدائل AES-256-GCM وHKDF المستخدَمة في `keyring/core/crypto.py` | `pyproject.toml:19` |
| `argon2-cffi` | `>=23.1` | `25.1.0` | اشتقاق مفتاح Argon2id من عبارة المرور الجذرية (`crypto.py:200`) | `pyproject.toml:20` |
| `shamir-mnemonic` | `>=0.3` | `0.3.0` | تقسيم/استرجاع السر الجذري بمخطط SLIP-39 (`keyring/core/shamir.py`) | `pyproject.toml:21` |
| `reportlab` | `>=4.2` | `5.0.1` | توليد شهادات المحو بصيغة PDF (`keyring/core/certificate.py:69`) | `pyproject.toml:22` |
| `python-dotenv` | `>=1.0` | `1.2.3` | تحميل ملف `.env` عند الإقلاع | `pyproject.toml:23` |
| `python-multipart` | `>=0.0.9` | `0.0.32` | دعم FastAPI لبيانات النماذج متعددة الأجزاء | `pyproject.toml:24` |

## 3. تبعيات Python — Dev (`pyproject.toml:28-31`)

| الاسم | القيد | الإصدار الفعلي | الوظيفة | السطر |
|---|---|---|---|---|
| `pytest` | `>=8.3` | `9.1.1` | إطار تشغيل الاختبارات (`keyring/tests/`) | `pyproject.toml:29` |
| `pytest-asyncio` | `>=0.24` | `1.4.0` | دعم اختبارات `async` — **مثبَّتة لكن غير مستخدَمة فعلياً**: لا توجد أي دالة اختبار `async def test_` في `keyring/tests/` (تحقُّق: `grep -rn 'async def test_' keyring/tests/` لا يُرجع نتائج) | `pyproject.toml:30` |
| `httpx` | `>=0.27` | `0.28.1` | عميل HTTP يستخدمه `TestClient` الخاص بـ FastAPI، وأيضاً مُقلَّد (mocked) لاختبار مزوّدَي Vault/KMS في `keyring/tests/test_providers.py` | `pyproject.toml:31` |

**تبعيات انتقالية (transitive) بارزة** ظهرت في `pip list` ولم تُطلب مباشرة في `pyproject.toml`،
مذكورة للتوثيق: `anyio` (4.14.2)، `starlette` (1.6.0 — إطار FastAPI الأساسي)، `h11`/`httpcore`
(بروتوكول HTTP لـ`httpx`/`uvicorn`)، `websockets` (17.0.1 — **مثبَّتة كتبعية لـ`uvicorn[standard]`
لكن لا يوجد أي كود WebSocket في المشروع؛ انظر `05_API.md` قسم القنوات**)، `Pillow` (12.3.0 — تبعية
`reportlab` لمعالجة الصور في PDF)، `Mako`/`MarkupSafe` (قوالب Alembic).

## 4. تبعيات npm — Runtime (`web/package.json:12-16`)

| الاسم | القيد | الإصدار المحلول (lockfile) | الوظيفة | السطر |
|---|---|---|---|---|
| `react` | `^19.2.8` | `19.2.8` | مكتبة الواجهة الأساسية | `web/package.json:13` |
| `react-dom` | `^19.2.8` | `19.2.8` | ربط React بـ DOM المتصفح | `web/package.json:14` |
| `react-router-dom` | `^7.18.2` | `7.18.2` | التوجيه (routing) — يُستخدم كـ `HashRouter` تحديداً في `web/src/App.tsx` | `web/package.json:15` |

## 5. تبعيات npm — Dev (`web/package.json:17-25`)

| الاسم | القيد | الإصدار المحلول | الوظيفة | السطر |
|---|---|---|---|---|
| `@types/node` | `^24.13.3` | `24.13.3` | أنواع Node.js لأدوات البناء | `web/package.json:18` |
| `@types/react` | `^19.2.18` | `19.2.18` | أنواع TypeScript لـ React | `web/package.json:19` |
| `@types/react-dom` | `^19.2.4` | `19.2.5` | أنواع TypeScript لـ react-dom | `web/package.json:20` |
| `@vitejs/plugin-react` | `^6.1.0` | `6.1.0` | تكامل Vite/React (Fast Refresh عبر Oxc) | `web/package.json:21` |
| `oxlint` | `^1.79.0` | `1.79.0` | أداة linting (بديل ESLint مكتوب بـ Rust) | `web/package.json:22` |
| `typescript` | `~6.0.2` | `6.0.3` | مترجم/فاحص أنواع TypeScript | `web/package.json:23` |
| `vite` | `^8.2.2` | `8.2.2` | أداة البناء والخادم التطويري | `web/package.json:24` |

`lockfileVersion: 3` في `web/package-lock.json` (تنسيق npm 7+).

## 6. أداة البناء وأدوات المساعدة

| الأداة | الاستخدام | ملف الإعداد |
|---|---|---|
| **Vite 8** | حزم/تقديم `web/` تطويرياً وإنتاجياً؛ `npm run build` ينفّذ `tsc -b && vite build` (`web/package.json:8`) | `web/vite.config.ts` |
| **oxlint** | فحص جودة كود TypeScript/React؛ قاعدتان فقط مفعّلتان صراحة: `react/rules-of-hooks: error`، `react/only-export-components: warn` | `web/.oxlintrc.json` |
| **setuptools** (`>=68`) | نظام بناء حزمة بايثون؛ `[tool.setuptools.packages.find]` يُدرج `keyring*` فقط | `pyproject.toml:1-3, 34-35` |
| **Alembic** | أداة ترحيل المخطط؛ الاتصال والمسارات معرَّفة في `alembic.ini` (149 سطراً) و`alembic/env.py` | `alembic.ini` |

**خادم Vite التطويري** (`web/vite.config.ts:13-18`) يُمرِّر (proxy) كل طلب يبدأ بـ `/api` إلى
`http://127.0.0.1:8010` — أي أن منفذ التطوير الافتراضي المفترَض للـ API هو **8010**، رغم أن تعليقاً
في نفس الملف (`vite.config.ts:8`) يذكر أن uvicorn يعمل افتراضياً على المنفذ 8000 — وهو تناقض موثَّق
حرفياً بين التعليق والقيمة الفعلية في `target`.

## 7. أدوات الاختبار

| الأداة | النطاق | المصدر |
|---|---|---|
| `pytest` + `pytest.ini_options` (`testpaths = ["keyring/tests"]`) | اختبارات Backend (159 دالة في 16 ملفاً) | `pyproject.toml:37-38` |
| `httpx` عبر `TestClient` من FastAPI | اختبارات HTTP end-to-end في `keyring/tests/test_http_endpoints.py` وغيرها | — |
| **لا يوجد** إطار اختبار في `web/` | لا `vitest`، لا `jest`، لا `@testing-library/*` في `web/package.json` أو `package-lock.json` | `[غير موجود في الكود]` — تفصيل أوسع في `08_TESTING.md` |

## 8. أدوات CI/CD

**[غير موجود في الكود]**. البحث الشامل عن ملفات التكامل/النشر المستمر لم يُظهر أي نتيجة:
لا `.github/workflows/`، لا `.gitlab-ci.yml`، لا `.circleci/`، لا `Jenkinsfile`، لا `Dockerfile`،
لا `docker-compose.yml`/`.yaml` في أي مكان بالمستودع (تحقُّق: `find . -iname 'Dockerfile*' -o -iname '*.yml' -o -iname '*.yaml'` لم يُرجع سوى ملفات `.serena/project*.yml` الخاصة بأداة مساعدة غير متعلقة بالمشروع نفسه). هذا موثَّق كفجوة في `13_GAPS.md`.

## 9. قاعدة البيانات ونسختها

| العنصر | القيمة | المصدر |
|---|---|---|
| النظام الافتراضي (تطوير) | SQLite، ملف `keyring.db` (9.1 MB مبذور) | `README.md:16` (`KEYRING_DATABASE_URL` الافتراضي `sqlite:///./keyring.db`)، `keyring/config.py` |
| النظام المستهدَف للإنتاج | PostgreSQL (عبر `psycopg[binary]>=3.2`) | `pyproject.toml:18`؛ توصية صريحة في `THREAT_MODEL.md:101-106`: "Production deployments should run PostgreSQL; SQLite is a development/test convenience only." |
| نسخة PostgreSQL المستهدَفة تحديداً | `[غير موجود في الكود]` — لا رقم إصدار محدَّد، فقط قيد السائق `psycopg>=3.2` | `pyproject.toml:18` |
| ORM/سائق الوصول | SQLAlchemy 2.0 (ORM) + Alembic (ترحيلات) + psycopg 3 (سائق PostgreSQL) / سائق SQLite المدمَج في بايثون | `keyring/db.py`، `alembic/env.py` |

## 10. ما لم يُستخرج (ملخّص فجوات هذا الملف)

- نسخة Node.js المطلوبة/المستخدَمة — `[غير موجود في الكود]`.
- نسخة PostgreSQL الدقيقة المستهدَفة للإنتاج — `[غير موجود في الكود]`.
- أي أداة CI/CD — `[غير موجود في الكود]`.
- أي حاوية (Docker) أو orchestration — `[غير موجود في الكود]`.
