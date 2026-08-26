# 08 — الاختبار (Testing)

## 1. إطار العمل والأدوات

الاختبار الخلفي (backend) مبني بالكامل على **pytest** (تبعية تطوير `pytest>=8.3`، `pyproject.toml:29`)
مع تكوين وحيد في `pyproject.toml:37-38`:

```toml
[tool.pytest.ini_options]
testpaths = ["keyring/tests"]
```

لا يوجد أي ملف `pytest.ini` أو `.coveragerc` أو `setup.cfg` منفصل في كامل المستودع (تأكيد بالبحث
المباشر بامتدادات `*.cfg`/`pytest.ini`/`.coveragerc`، نتيجة البحث فارغة) — `pyproject.toml` هو
مصدر ضبط pytest الوحيد.

قائمة تبعيات التطوير الكاملة (`pyproject.toml:28-32`):

| التبعية | القيد | الاستخدام الفعلي |
|---|---|---|
| `pytest` | `>=8.3` | مشغّل الاختبارات، مستخدَم في كل ملفات `keyring/tests/*.py` |
| `pytest-asyncio` | `>=0.24` | **مثبَّتة لكن غير مستخدَمة فعلياً** — لا يوجد أي `@pytest.mark.asyncio` ولا أي دالة اختبار `async def` في كامل `keyring/tests/` (بحث مباشر بـ`grep` عن `asyncio`/`pytest.mark` في ملفات الاختبار خارج `conftest.py` أعاد 3 نتائج فقط وكلها `@pytest.fixture` وليست `@pytest.mark.asyncio`). المشروع يستخدم `starlette.testclient.TestClient` المتزامن (sync) بدل عميل async، لذا هذه التبعية زائدة فعلياً عن حاجة الاختبارات الحالية. |
| `httpx` | `>=0.27` | تبعية `TestClient`/`starlette` تحتاجها داخلياً، وتُستخدَم مباشرة في `test_providers.py` لمحاكاة استدعاءات HTTP خارجية عبر `httpx.MockTransport` (لاختبار مزوّدَي vault وkms بلا اتصال فعلي بخدمة خارجية) |

الاختبار على مستوى HTTP يستخدم `starlette.testclient.TestClient` (وليس `fastapi.testclient.TestClient`
مباشرة، رغم أنهما متطابقان عملياً)، مستورَد صراحة داخل ثابتة `client` في `keyring/tests/conftest.py:103`.

**لا يوجد أي إطار اختبار في `web/`** — لا `vitest`، لا `jest`، لا `@testing-library/react`، ولا حتى
حقل `"test"` في `scripts` ضمن `web/package.json`. بحث مباشر عن ملفات بامتداد `*.test.*`/`*.spec.*`
داخل `web/` (باستثناء `node_modules`) أعاد صفر نتائج. هذا يعني أن **الواجهة الأمامية بأكملها بلا أي
تغطية اختبارية آلية** — لا اختبارات وحدة (unit)، ولا اختبارات مكوّنات (component)، ولا end-to-end.

## 2. الإحصائيات العامة

| المقياس | القيمة |
|---|---|
| عدد ملفات الاختبار | 16 ملفاً، كلها داخل `keyring/tests/` |
| إجمالي دوال الاختبار | **159** دالة (تأكيد بعدّ `^def test_` في كل ملف وجمعها: 4+5+11+10+4+4+12+32+19+8+14+9+4+13+2+8 = 159) |
| ملف `fixtures` مشترك | `keyring/tests/conftest.py` (133 سطراً) |
| اختبارات معامَلة بمزوّدين (parametrized) | كل اختبار يعتمد على ثابتة `service` أو `provider` يُنفَّذ مرتين تلقائياً (`file` و`env`) عبر `@pytest.fixture(params=["file", "env"])` في `conftest.py:48` |
| اختبارات واجهة الويب `web/` | **صفر** — `[غير موجود في الكود]` |
| أداة قياس تغطية الكود (coverage) | **غير موجودة** — لا `pytest-cov` في التبعيات، لا `.coveragerc`، لا تقرير تغطية محفوظ في المستودع |
| خط أنابيب تكامل مستمر (CI/CD) | **غير موجود** — لا `.github/workflows/`، لا `.gitlab-ci.yml`، ولا أي ملف بامتداد `.yml`/`.yaml` في جذر المشروع يخص CI (تأكيد بالبحث المباشر) |
| حاويات/Docker | **غير موجود** — لا `Dockerfile`، لا `docker-compose.yml` |

## 3. جدول تفصيلي لكل ملف اختبار

| الملف | عدد الدوال | معرّفات FR الموسومة | ما يغطّيه (من docstring الملف) |
|---|---|---|---|
| `test_approvals_idempotency.py` | 4 | FR-9.3 | موافقة الطرفين (two-party approval) ومفتاح اللاتكرار (idempotency key) على مستوى HTTP عبر `TestClient`، بما يشمل رفض الموافقة الذاتية |
| `test_audit.py` | 5 | FR-8.3, FR-8.4 | سجل التدقيق المتسلسل بالهاش (hash-chained): سلسلة جديدة تتحقق بنجاح، وكشف التلاعب |
| `test_certificate.py` | 11 | — (بلا وسم FR صريح) | جولة التوقيع والتحقق لشهادات المحو، كشف التلاعب، ثبات JSON القانوني (canonical)، تصدير JSON/PDF، وحالة فشل غياب مفتاح التوقيع |
| `test_crypto_core.py` | 10 | FR-1, FR-3.4 | اختبارات مستوى بدائي (primitive-level) على `core/crypto.py` مباشرة — بلا قاعدة بيانات، بلا مزوّد |
| `test_crypto_shredding.py` | 4 | — (تعليق "section 3") | محو المواضيع (subject erasure) عبر تدمير التشفير (crypto-shredding) |
| `test_destroy.py` | 4 | FR-4.4 | منع الحذف عند وجود تبعيات (`BlockingDependentsError`) واستثناء subject key المتعمَّد من هذه القاعدة |
| `test_encrypt_decrypt.py` | 12 | FR-2, FR-3, FR-3.2 | صحة التشفير/فك التشفير على مستوى الخدمة (`KeyringService`) واختبارات سلبية؛ كل دالة تُنفَّذ مرة لكل مزوّد عبر ثابتة `service` |
| `test_http_endpoints.py` | 32 | — | تغطية HTTP للموجّهات (routers) التي لم تكن مختبرة سابقاً: `session`، `dashboard`، مقاييس فشل فك التشفير، تأكيد التنبيهات (alert ack)، `graph`، `audit` (قائمة/فلاتر/`export.csv`/`verify`)، `settings`، `providers`، و`threat-model` |
| `test_i18n.py` | 19 | — | تفاوض `Accept-Language`، تكافؤ فهارس الترجمة بين العربية والإنجليزية، والتأكد أن كل مفتاح خطأ/threat-model مُستخدَم في الكود يُحلّ فعلياً في كلتا اللغتين |
| `test_lifecycle.py` | 8 | FR-4 | آلة الحالة (state machine) لكل نوع كيان، رفض الانتقالات غير الشرعية، وقيد "KEK نشط واحد" المفروض على مستوى قاعدة البيانات تحت محاولات تفعيل متسلسلة **ومتزامنة فعلياً** (threading) |
| `test_providers.py` | 14 | FR-6.3 | عقد `KeyProvider` المشترك بين التطبيقات الأربعة: جولة wrap/unwrap، فشل موحَّد عند unwrap بمرجع خاطئ، وسلوك `is_available`/`connect`/`disconnect`؛ vault وkms يعملان عبر نقل HTTP وهمي `httpx.MockTransport` بلا أي backend حقيقي |
| `test_rbac.py` | 9 | FR-9, FR-9.2 | مصفوفة نطاقات RBAC والضمان البنيوي لفصل المهام (لا دور يمكنه الحذف والتلاعب/قراءة سجل التدقيق بما يسمح بتغطية أثره) |
| `test_rewrap.py` | 4 | FR-5, FR-5.1, FR-5.4 | تدوير KEK القابل للاستئناف (resumable) وrewrap — على **مستوى الخدمة**، وليس عبر HTTP |
| `test_shamir_backup.py` | 13 | FR-7 | تمرين الاسترجاع: تقسيم/إعادة تجميع السر الجذري عبر Shamir، ووظيفة التحقق من قابلية الاسترجاع دون إرجاع السر نفسه عبر الحد الفاصل (boundary) |
| `test_streaming_http.py` | 2 | FR-2.5 | تشفير/فك تشفير متدفّق (streaming) على **مستوى HTTP** عبر `TestClient` |
| `test_streaming.py` | 8 | FR-2.5 | تشفير/فك تشفير متدفّق مجزّأ (chunked)، كشف تلاعب لكل جزء (chunk)، والتحقق المبكر (eager) لصحة المغلف (envelope) في مسار فك التشفير |

**ملاحظة على التوزيع**: 159 = 4+5+11+10+4+4+12+32+19+8+14+9+4+13+2+8، وهو الرقم المطابق تماماً لما ورد
في خطة الاستخراج المعتمدة مسبقاً.

## 4. بنية `conftest.py` — الثوابت المشتركة (Fixtures)

`keyring/tests/conftest.py` (133 سطراً) هو المصدر الوحيد لكل ثوابت pytest المشتركة بين الملفات
الـ16. لا يوجد أي ملف `conftest.py` فرعي آخر.

| الثابتة | السطر | الغرض |
|---|---|---|
| `make_engine(db_path)` | `conftest.py:22-25` | دالة مساعدة (وليست ثابتة) تُنشئ محرّك SQLAlchemy على SQLite بملف مؤقت، مع `connect_args={"check_same_thread": False, "timeout": 5}` |
| `db_engine` | `conftest.py:28-33` | محرّك SQLAlchemy معزول لكل اختبار عبر `tmp_path`، يُنشئ كل الجداول بـ`Base.metadata.create_all(engine)` ثم يُتخلَّص منه (`engine.dispose()`) بعد الاختبار |
| `session_factory` | `conftest.py:36-38` | `sessionmaker` مربوط بـ`db_engine`، بلا autoflush وبلا autocommit |
| `db_session` | `conftest.py:41-45` | جلسة SQLAlchemy واحدة تُفتَح وتُغلَق حول كل اختبار |
| `provider` | `conftest.py:48-67` | **مُعامَلة (parametrized)** بقيمتين `["file", "env"]` — أي اختبار يعتمد عليها (مباشرة أو عبر `service`) يُنفَّذ تلقائياً مرة لكل تطبيق `KeyProvider`، تحقيقاً حرفياً لمتطلب FR-6.3 "قابل للتبديل، تُشغَّل حزمة الاختبارات دون تعديل". لتطبيق `file` تُهيَّئ ملفات `root.passphrase`/`root.salt` بصلاحية `0o400` داخل `tmp_path`؛ لتطبيق `env` يُضبَط متغيّر بيئة عشوائي 32 بايت عبر `monkeypatch.setenv` |
| `service` | `conftest.py:70-72` | كائن `KeyringService(db_session, provider)` جاهز — يعتمد على `db_session` و`provider` معاً، فيرث معاملة `provider` تلقائياً |
| `hash_key(raw)` | `conftest.py:75-76` | دالة مساعدة: `sha256` لمفتاح API الخام، تطابق آلية `api_key_hash` الفعلية في `models/session.py` |
| `ClientCtx` | `conftest.py:79-98` | صنف بيانات (`@dataclass`) يغلّف `TestClient` مع دوال مساعدة: `seed_operator` (إدراج `Operator` مباشرة في القاعدة)، `open_session` (طلب `POST /api/session` والتحقق من نجاحه)، و`auth` (بناء ترويسة `Authorization: Bearer …`) |
| `client` | `conftest.py:101-132` | ثابتة HTTP الكاملة: تُنشئ قاعدة بيانات SQLite منفصلة، ثم **تُصحّح (monkeypatch) اسم `SessionLocal` في مكانين منفصلين** — `keyring.db.SessionLocal` (`conftest.py:118`) و`keyring.main.SessionLocal` (`conftest.py:119`) — لأن خيط عامل rewrap الخلفي في `main.py` استورد الاسم مباشرة (`from keyring.db import SessionLocal`) فربطه في مساحة أسماء `main` الخاصة به وقت الاستيراد؛ تصحيح `db.SessionLocal` وحده غير كافٍ وإلا لظلّ الخيط الخلفي يلمس قاعدة بيانات التطوير الحقيقية. تنتهي الثابتة بفصل المزوّد (`runtime.disconnect()`) والتخلص من المحرّك |

هذا التفصيل في `client` (تصحيح مزدوج لـ`SessionLocal`) هو أدق نقطة تقنية في بنية الاختبار الخلفي —
موثَّق صراحةً في تعليق داخل الكود نفسه (`conftest.py:112-117`).

## 5. مصفوفة تغطية HTTP للنقاط الـ45

الفحص هنا مختلف عمّا سبق: هل **مسار HTTP نفسه** (التوجيه، التفويض، ترجمة الأخطاء إلى رموز حالة،
شكل الاستجابة JSON) مُختبَر عبر `TestClient`، بصرف النظر عمّا إذا كان المنطق الداخلي (`KeyringService`)
مُختبَراً على مستوى الوحدة (unit) في ملف آخر. هذا فحص مباشر بحصاد كل استدعاءات
`client.http.(get|post|patch|put|delete)(...)` عبر الاختبارات الـ16 ومطابقتها بمسارات الموجّهات
المُعرَّفة فعلياً في `keyring/api/*.py`.

| الموجّه (router) | نقاط النهاية الكلية | مُختبَرة عبر HTTP فعلياً | غير مُختبَرة عبر HTTP |
|---|---|---|---|
| `session.py` | 3 | 3/3 (`test_http_endpoints.py`) | — |
| `audit.py` | 5 | 5/5 (`test_http_endpoints.py`) | — |
| `dashboard.py` | 3 | 3/3 (`test_http_endpoints.py`) | — |
| `graph.py` | 2 | 2/2 (`test_http_endpoints.py`) | — |
| `settings.py` | 7 | 7/7 (`test_http_endpoints.py`) | — |
| `approvals.py` | 3 | 2/3 (`create`، `approve` عبر `test_approvals_idempotency.py`) | `GET /api/approvals/{approval_id}` (`approvals.py:64-69`) — لا يوجد استدعاء `client.http.get` مباشر لهذا المسار في أي ملف اختبار |
| `core_ops.py` | 4 | 3/4 (`encrypt`، `encrypt-stream`، `decrypt-stream` عبر `test_http_endpoints.py`/`test_streaming_http.py`) | `POST /api/decrypt` (`core_ops.py:37`) — مسار فك التشفير غير المتدفّق لا يُستدعى عبر `TestClient` في أي ملف؛ منطقه الداخلي (`KeyringService.decrypt`) مُختبَر بعمق في `test_encrypt_decrypt.py` لكن على مستوى الخدمة مباشرة، لا عبر HTTP |
| `keys.py` | 7 | 1/7 (`POST /api/keys/{key_id}/destroy` فقط، عبر `test_approvals_idempotency.py`) | `GET /api/keys`، `GET /api/keys/{key_id}`، `GET /api/keys/{key_id}/blast-radius`، `POST /api/keks/{key_id}/rotate/preview`، `POST /api/keks/{key_id}/rotate`، `POST /api/keys/{key_id}/revoke` — ستة من سبعة مسارات في هذا الموجّه بلا أي اختبار HTTP |
| `rewrap.py` | 5 | 0/5 | **الموجّه بأكمله** بلا اختبار HTTP — `GET /jobs/current`، `POST /jobs/{id}/pause`، `POST /jobs/{id}/resume`، `GET /jobs/{id}/failures`، `POST /jobs/{id}/failures/{item_id}/retry`؛ منطق rewrap الداخلي مُختبَر في `test_rewrap.py` لكن عبر استدعاء `KeyringService` مباشرة، لا عبر التوجيه (routing) أو التفويض (`require_scope`) الفعليَّين لهذا الموجّه |
| `subjects.py` | 6 | 0/6 | **الموجّه بأكمله** بلا اختبار HTTP — `GET /subjects/{id}`، `GET /subjects/{id}/fields/{table}/digest`، `POST /subjects/{id}/erasure`، `POST /subjects/{id}/verify-unreadable`، `GET /certificates/{id}`، `GET /certificates/{id}/export`؛ المنطق الداخلي مُختبَر جزئياً عبر `test_crypto_shredding.py` و`test_certificate.py` و`test_destroy.py`، لكن جميعها تستدعي `KeyringService`/`core.certificate` مباشرة دون المرور بطبقة HTTP لهذا الموجّه |

**الخلاصة الرقمية**: من أصل 45 نقطة نهاية، **26 نقطة** (58%) مُختبَرة فعلياً عبر `TestClient` على
مستوى HTTP الكامل (توجيه + تفويض + ترجمة استجابة)، بينما **19 نقطة** (42%) — معظمها في `subjects.py`
و`rewrap.py` و`keys.py` — لا تملك أي اختبار يمرّ عبر طبقة FastAPI/التوجيه نفسها، رغم أن منطقها
الجوهري (`KeyringService`) غالباً مُختبَر جيداً على مستوى الوحدة في ملفات اختبار أخرى. هذا يعني أن
أموراً خاصة بطبقة HTTP تحديداً — مثل تفويض `require_scope` الفعلي لكل مسار من هذه الـ19، وشكل
استجابة JSON، وترجمة استثناءات `KeyringError` إلى رموز حالة HTTP الصحيحة عبر معالج الأخطاء العام —
غير مُتحقَّق منها بشكل آلي لهذه المسارات تحديداً.

## 6. أدوات قياس تغطية الكود (Coverage)

**غير موجودة في الكود.** لا `pytest-cov` ضمن تبعيات `pyproject.toml` (قائمة `dev` الكاملة هي
`pytest`، `pytest-asyncio`، `httpx` فقط — `pyproject.toml:29-32`)، ولا ملف `.coveragerc`، ولا أي
تقرير تغطية (`coverage.xml`، `htmlcov/`) محفوظ في المستودع. لا توجد وسيلة داخل الكود لمعرفة نسبة
تغطية الأسطر أو الفروع (line/branch coverage) الفعلية لحزمة `keyring/`.

## 7. خط أنابيب التكامل المستمر (CI/CD)

**غير موجود في الكود.** لا مجلد `.github/workflows/`، لا `.gitlab-ci.yml`، لا `Jenkinsfile`، ولا أي
ملف تكوين CI آخر في جذر المشروع (تأكيد بالبحث المباشر بامتدادي `.yml`/`.yaml` في جذر المستودع؛
النتائج الوحيدة تخص أداة خارجية `.serena/project.yml` ولا علاقة لها بـCI). كذلك لا يوجد `Dockerfile`
ولا `docker-compose.yml` — الاختبارات تُشغَّل محلياً فقط عبر استدعاء `pytest` مباشرة، ولا توجد أتمتة
تُشغِّلها عند كل تغيير في الكود.

## 8. تغطية الواجهة الأمامية `web/`

**صفر اختبارات آلية.** لا `vitest.config.ts`، لا `jest.config.js`، لا حزمة `@testing-library/react`
أو أي مكافئ لها ضمن `web/package.json`. لا ملف واحد بامتداد `*.test.tsx`/`*.test.ts`/`*.spec.tsx` في
كامل `web/src/` (باستثناء `node_modules`). كل التحقق من صحة الواجهة الأمامية — إن حصل أثناء التطوير —
كان يدوياً عبر تشغيل خادم Vite ومعاينة المتصفح مباشرة؛ لا أثر آلي لذلك في المستودع.

هذا يعني أن كل منطق الواجهة الأمامية — تحويل استجابات API، إدارة الحالة عبر الـcontexts اليدوية، منطق
i18n/RTL، والتوجيه (routing) عبر `react-router-dom` — بلا أي شبكة أمان اختبارية آلية، خلافاً للخلفية
التي تملك 159 دالة اختبار موزَّعة كما هو موضَّح أعلاه.
