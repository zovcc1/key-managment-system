# 12. المقاييس الكمّية (Metrics)

هذا الملف يجمّع كل الأرقام الكمّية عن مشروع Keyring التي جرى التحقق منها مباشرة من الكود ومن قاعدة البيانات المبذورة (seeded) في هذا المستودع، لا من تقديرات. كل رقم هنا أُعيد فحصه عبر أوامر عدّ مباشرة (`find`, `wc -l`, `grep -c`, استعلامات SQLite) خلال جلسة الاستخراج، وليس منقولاً حرفياً عن أي وثيقة خارجية. حيث وُجد تعارض بين رقم مُقدَّر مسبقاً ورقم مُتحقَّق منه مباشرة، اعتُمد الرقم المُتحقَّق منه مباشرة وذُكر التصحيح صراحة.

## 12.1 حجم الكود المصدري (Backend — Python)

| المقياس | القيمة | طريقة التحقق |
|---|---|---|
| عدد ملفات Python (باستثناء `.venv`, `__pycache__`) | **73** ملفاً | `find . -name '*.py' -not -path './.venv/*' -not -path '*/__pycache__/*' \| wc -l` |
| إجمالي أسطر الكود (Python) | **6,752** سطراً | `wc -l` على نفس القائمة |
| عدد الـ classes | **62** كلاساً | `grep -rEn '^class ' --include='*.py'` |
| عدد الدوال/التوابع (functions + methods, بما فيها `async def`) | **431** دالة | `grep -rEn '^\s*(async )?def '` (النمط المرن يشمل أي عمق إزاحة) |
| تعليقات `TODO`/`FIXME`/`HACK`/`XXX` | **صفر** | `grep -rniE 'TODO|FIXME|HACK|XXX' --include='*.py'` بلا نتائج |

## 12.2 حجم الكود المصدري (Frontend — `web/src`)

| المقياس | القيمة | طريقة التحقق |
|---|---|---|
| ملفات TypeScript/TSX | **22** ملفاً | `find web/src -name '*.ts' -o -name '*.tsx'` |
| ملفات CSS | **3** ملفات (`nocturne.css` وملفان مرتبطان) | `find web/src -name '*.css'` |
| إجمالي أسطر TS/TSX + CSS مجتمعة | **3,592** سطراً | `wc -l` مجمّعة على القائمتين أعلاه |
| مكوّنات React (function components، بما فيها المساعدة غير المصدَّرة مثل `RequireSession`, `Routed`, `Sparkline`, `ApprovalLookup`) | **21** مكوّناً | `grep -rEn '^function [A-Z]\|^export function [A-Z]\|^export default function [A-Z]' --include='*.tsx' .` |
| مسارات الواجهة (routes) | **9** شاشات | `web/src/routes/*.tsx`: Dashboard, KeyMap, Keys, Locked, Login, Privacy, Rewrap, Settings, Audit |
| مكوّنات UI قابلة لإعادة الاستخدام في `components/` | **5** ملفات | Shell.tsx, Toast.tsx, RotateDialog.tsx, RevokeDialog.tsx, DestroyFlowDialog.tsx |

> **ملاحظة منهجية**: عدّ مبدئي بمعيار "دوال مصدَّرة فقط" (`export default function` / `export function`) أعطى 17 ملفاً فقط. الفرق (21 − 17 = 4) يعود إلى أربعة مكوّنات دالّية معرَّفة داخلياً وغير مصدَّرة مباشرة: `RequireSession` و`Routed` في `web/src/App.tsx`، و`Sparkline` و`ApprovalLookup` في `web/src/routes/Dashboard.tsx`. اعتماد المعيار الأوسع (كل دالة بأحرف PascalCase تُعيد JSX) هو المعيار الصحيح لأن هذه الدوال الأربع مكوّنات React فعلية تُستخدَم داخل JSX رغم عدم تصديرها من ملفاتها.

## 12.3 حجم المستودع الكلي

| المقياس | القيمة | طريقة التحقق |
|---|---|---|
| حجم المستودع (باستثناء `.venv` و`node_modules` و`.git`) | **12 MB** | `du -sh --exclude='.venv' --exclude='node_modules' --exclude='.git' .` |
| حجم `.venv` (بيئة Python الافتراضية، غير جزء من المصدر) | 173 MB | مرجعي فقط، غير محسوب في حجم المستودع |
| حجم `web/node_modules` (تبعيات npm المنصَّبة، غير جزء من المصدر) | 96 MB | مرجعي فقط، غير محسوب في حجم المستودع |

## 12.4 الاختبارات (Testing)

| المقياس | القيمة | المصدر |
|---|---|---|
| ملفات اختبار Python | **16** ملفاً في `keyring/tests/` | تفصيل كامل في `08_TESTING.md` §2 |
| إجمالي دوال الاختبار (`def test_*`) | **159** دالة | `grep -rc '^def test_' keyring/tests/*.py` مجموعة |
| نقاط النهاية (endpoints) المُختبَرة على مستوى HTTP (`TestClient`) | **26 من 45** (58%) | مصفوفة التغطية الكاملة في `08_TESTING.md` §5 |
| نقاط النهاية بلا أي اختبار على مستوى HTTP | **19 من 45** (42%) — أبرزها `subjects.py` (0/6) و`rewrap.py` (0/5) بالكامل | `08_TESTING.md` §5 |
| اختبارات على مستوى الواجهة الأمامية (`web/`) | **صفر** | لا يوجد أي ملف اختبار (`*.test.ts(x)`, `*.spec.ts(x)`) تحت `web/src` |
| أدوات تغطية الكود (coverage) | **[غير موجود في الكود]** | لا `pytest-cov` في `pyproject.toml`، لا تقرير تغطية في المستودع |
| إعداد CI/CD | **[غير موجود في الكود]** | لا `.github/`, لا `.gitlab-ci.yml`, لا أي ملف أتمتة بناء |

## 12.5 قاعدة البيانات (Database)

جميع الأرقام في هذا القسم أُعيد التحقق منها مباشرة عبر استعلام `sqlite3` على ملف `keyring.db` المبذور في جذر المستودع، بالإضافة إلى فحص `keyring/models/__init__.py` و`alembic/versions/e1a463aef094_initial_schema.py`.

| المقياس | القيمة | ملاحظة |
|---|---|---|
| عدد الجداول الموضوعية (لا تشمل `alembic_version`) | **14** جدولاً | `alerts, approvals, audit_log, decrypt_failures, erasure_certificates, idempotency_records, keks, operators, system_settings, rewrap_jobs, sessions, subject_keys, envelopes, rewrap_failures` |
| عدد الجداول الكلي (بما فيها `alembic_version`) | **15** جدولاً | جدول `alembic_version` هو جدول تتبّع ترحيل Alembic الداخلي، لا جدول أعمال |
| عدد الفهارس (indexes) | **21** فهرساً | `grep -c 'op.create_index' alembic/versions/*.py` |
| عدد الترحيلات (migrations) | **1** ترحيل واحد فقط | ملف واحد: `e1a463aef094_initial_schema.py` — لا سلسلة ترحيلات تراكمية |

### 12.5.1 عدّاد صفوف قاعدة البيانات المبذورة (seeded)

هذا الجدول تحقّق مباشر (`SELECT COUNT(*)`) على `keyring.db` في جذر المستودع، وليس رقماً منقولاً عن `seed.py` بدون تنفيذ:

| الجدول | عدد الصفوف |
|---|---|
| `envelopes` | **15,410** |
| `audit_log` | **279** |
| `subject_keys` | **42** |
| `keks` | **4** |
| `approvals` | **5** |
| `operators` | **4** |
| `decrypt_failures` | 41 |
| `sessions` | 25 |
| `rewrap_jobs` | 2 |
| `idempotency_records` | 3 |
| `erasure_certificates` | 1 |
| `system_settings` | 1 |
| `alerts` | 0 |
| `rewrap_failures` | 0 |

الأرقام الستة الأولى (envelopes, audit_log, subject_keys, keks, approvals, operators) مطابقة تماماً لما كان مقدَّراً مسبقاً في خطة الاستخراج، وقد أُعيد التحقق منها بشكل مستقل هنا. الأرقام الثمانية المتبقية (decrypt_failures وحتى rewrap_failures) قياسات إضافية جديدة اكتُشفت أثناء هذا التحقق ولم تكن موثّقة سابقاً في أي ملف من ملفات `thesis-extraction/`.

## 12.6 نقاط نهاية الـ API (HTTP Endpoints)

| المقياس | القيمة | التفصيل |
|---|---|---|
| إجمالي نقاط النهاية HTTP | **45** نقطة | موزّعة عبر 10 وحدات (modules) في `keyring/api/` |
| وحدات API التي تحوي راوترات فعلية | **10** وحدات | `approvals.py`(3), `audit.py`(5), `core_ops.py`(4), `dashboard.py`(3), `graph.py`(2), `keys.py`(7), `rewrap.py`(5), `session.py`(3), `settings.py`(7), `subjects.py`(6) |
| ملفات مساعدة في `keyring/api/` بلا راوترات (schemas/serializers/deps) | 4 ملفات | `schemas.py`, `serializers.py`, `deps.py`, `__init__.py` — غير محسوبة ضمن الـ10 وحدات أعلاه |

جدول تفصيلي كامل لكل نقطة نهاية موجود في `05_API.md`.

## 12.7 التبعيات (Dependencies)

### 12.7.1 Python (`pyproject.toml`)

| الفئة | العدد | القائمة |
|---|---|---|
| Runtime (`[project.dependencies]`) | **13** | fastapi, uvicorn[standard], pydantic, pydantic-settings, sqlalchemy, alembic, psycopg[binary], cryptography, argon2-cffi, shamir-mnemonic, reportlab, python-dotenv, python-multipart |
| Dev (`[project.optional-dependencies].dev`) | **3** | pytest, pytest-asyncio, httpx |
| **الإجمالي** | **16** | |

> **تصحيح على تقدير مبدئي**: كان مقدَّراً مسبقاً عدد 15 تبعية (12 runtime + 3 dev). العدّ المباشر من `pyproject.toml` (السطور 12–24 للـ runtime والسطور 29–32 للـ dev) يُثبت أن العدد الصحيح هو **16 تبعية (13 runtime + 3 dev)**. الفرق تحديداً هو تبعية `python-multipart` التي لم تُحتسب في التقدير المبدئي. الرقم المعتمد في هذا الملف هو 16، المتحقَّق منه مباشرة.

### 12.7.2 npm (`web/package.json`)

| الفئة | العدد | القائمة |
|---|---|---|
| Runtime (`dependencies`) | **3** | react `^19.2.8`, react-dom `^19.2.8`, react-router-dom `^7.18.2` |
| Dev (`devDependencies`) | **7** | @types/node, @types/react, @types/react-dom, @vitejs/plugin-react, oxlint, typescript, vite |
| **الإجمالي** | **10** | |

## 12.8 التعريب (i18n)

| الكتالوج | عدد المفاتيح لكل لغة | الملف |
|---|---|---|
| كتالوج الواجهة الخلفية (رسائل API/أخطاء) | **46** مفتاحاً | `keyring/i18n/en.json`, `keyring/i18n/ar.json` |
| كتالوج الواجهة الأمامية (نصوص الواجهة/chrome) | **193** مفتاحاً | `web/src/i18n/chrome.ts` (445 سطراً إجمالاً، كائنا `en`/`ar`) |

الكتالوجان منفصلان بنيوياً تماماً — لا مصدر مشترك ولا آلية توليد تلقائي تربط بينهما (تفصيل في `09_UI_INVENTORY.md` §6).

## 12.9 متطلبات وظيفية (FR-*)

| المقياس | القيمة |
|---|---|
| معرّفات المتطلبات الوظيفية الفريدة (`FR-X.Y`) الموجودة فعلياً في الكود والاختبارات | **31** معرّفاً فرعياً ضمن 10 مجموعات رئيسية (`FR-1` … `FR-10`) |
| عدد الملفات التي تحوي وسوم `FR-*` | 30+ ملفاً، تشمل `keyring/core/*`, `keyring/api/*`, `keyring/models/*`, وكل ملفات الاختبار الـ16 |

مصفوفة التتبّع الكاملة (`FR-X` ← نص المتطلب ← ملف التنفيذ:السطر ← ملف الاختبار:السطر) موجودة في `02_REQUIREMENTS.md`.

## 12.10 جدول ملخّص نهائي

| الفئة | الرقم |
|---|---|
| ملفات Python / أسطر Python | 73 / 6,752 |
| ملفات TS+TSX+CSS / أسطرها مجتمعة | 25 / 3,592 |
| حجم المستودع (بدون `.venv`/`node_modules`/`.git`) | 12 MB |
| Classes (Python) | 62 |
| Functions/Methods (Python) | 431 |
| دوال اختبار Python | 159 (في 16 ملفاً) |
| تغطية HTTP للـ endpoints | 26/45 (58%) |
| مكوّنات React | 21 |
| مسارات واجهة (routes) | 9 |
| نقاط نهاية HTTP | 45 (في 10 وحدات API) |
| جداول قاعدة البيانات | 14 (+ `alembic_version`) |
| فهارس قاعدة البيانات | 21 |
| ترحيلات Alembic | 1 |
| تبعيات Python | 16 (13 runtime + 3 dev) |
| تبعيات npm | 10 (3 runtime + 7 dev) |
| مفاتيح ترجمة خلفية / أمامية لكل لغة | 46 / 193 |
| معرّفات FR فرعية فريدة | 31 |
| تعليقات TODO/FIXME/HACK/XXX | 0 |
| أدوات CI/CD أو تغطية كود | [غير موجود في الكود] |
