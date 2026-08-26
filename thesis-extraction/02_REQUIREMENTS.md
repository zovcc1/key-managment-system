# 02 — المتطلبات الوظيفية وغير الوظيفية

> **ملاحظة منهجية مهمة**: خلافاً لمعظم المشاريع التي تُستنتَج متطلباتها من الكود استنتاجاً، هذا
> المشروع **يُوسِم متطلباته الوظيفية داخل الكود نفسه** بمعرّفات `FR-N` (Functional Requirement)
> في التعليقات التوثيقية (docstrings) للوحدات والدوال، وتُستخدَم نفس المعرّفات حرفياً في أسماء/توثيق
> دوال الاختبار. لذلك تُستخدَم هنا **المعرّفات الأصلية من الكود بصيغتها الفعلية** (`FR-1`، `FR-1.3`،
> `FR-9.2`…) بدل ترقيم `FR-01/FR-02` مولَّد، لأن ذلك أكثر أمانة لمصدر الحقيقة الوحيد: الكود.
> استُخرجت المعرّفات بالأمر:
> ```bash
> grep -rn --include='*.py' -E 'FR-[0-9]+(\.[0-9]+)?' keyring alembic
> ```

## 1. المتطلبات الوظيفية — مصفوفة تتبّع كاملة (Traceability Matrix)

### FR-1 — الأساس التشفيري لاشتقاق السر الجذري (Root Secret Derivation)
**الوصف**: اشتقاق مفتاح تغليف من السر الجذري (عبارة مرور أو سر بيئة) بمعاملات Argon2id محدَّدة،
مع رفض الإقلاع إن كان مولّد الأرقام العشوائية الآمن للنظام (CSPRNG) غير متاح.
- **FR-1.3** (معاملات Argon2id): `keyring/config.py:40-43` (تعليق: "do not lower without a
  security review")، تنفيذ في `keyring/providers/file_provider.py:26`، اشتقاق فعلي في
  `keyring/core/crypto.py:200` (`argon2id_derive`).
- **FR-1.4** (فشل صريح عند غياب CSPRNG): `keyring/core/crypto.py:53` (`assert_csprng_available`)،
  يُستدعى عند إقلاع التطبيق في `keyring/main.py`.
- **اختبار**: `keyring/tests/test_crypto_core.py:1` ("Primitive-level tests (FR-1, FR-3.4)").

### FR-2 — التشفير/فك التشفير أحادي العنصر (Envelope Encryption)
**الوصف**: كل عملية تشفير تُنتج مفتاح بيانات (DEK) عشوائياً جديداً أحادي الاستخدام، مُغلَّفاً
(wrapped) بمفتاح الموضوع (subject key)، ومُخزَّناً كظرف (`Envelope`) واحد لكل سجل.
- **التنفيذ**: `keyring/core/service.py:303` (تعليق "Encrypt / Decrypt (FR-2, FR-3, FR-10)")،
  `service.py:329` دالة `encrypt`.
- **FR-2.5** (تشفير/فك تشفير متدفّق للحمولات الكبيرة): `service.py:33-37`، `service.py:411`
  ("Streaming encrypt / decrypt (FR-2.5)")، مكشوف عبر `POST /api/encrypt-stream` و
  `GET /api/decrypt-stream/{envelope_id}` في `keyring/api/core_ops.py:53-102`، وتعليق توضيحي في
  `keyring/api/core_ops.py:63` ("FR-2.5: request body is the raw plaintext").
- **الاختبار**: `keyring/tests/test_encrypt_decrypt.py:1,45`، `keyring/tests/test_streaming.py`،
  `keyring/tests/test_streaming_http.py:1`.

### FR-3 — سلامة فك التشفير وتوحيد فشل الفك (Decrypt Integrity & Uniform Failure)
**الوصف**: أي محاولة فك تشفير فاشلة (تلاعب بالنص المشفَّر أو التاج، AAD غير مطابق، مفتاح مفقود/
مُلغى/مدمَّر) تُعيد نفس الاستجابة بالضبط (`DECRYPT_FAILED`) دون كشف السبب الحقيقي.
- **FR-3.2** (ربط AAD بالموقع المنطقي للسجل — الجدول/العمود/المعرِّف/الموضوع): تنفيذ في
  `keyring/models/envelope.py:44,52` (دالة `aad()`)، بناء في `keyring/core/crypto.py:215`
  (`build_aad`).
- **FR-3.4** (استجابة موحّدة + تحييد التوقيت الزمني): `keyring/core/crypto.py:39,129,183`،
  تطبيق في `keyring/core/service.py:389` وفحص محاكاة زمنية (`_decoy_aead_attempt`) عند :400.
- **الاختبار**: `keyring/tests/test_encrypt_decrypt.py:90`، `keyring/tests/test_crypto_core.py:29`.

### FR-4 — آلة حالة دورة حياة المفاتيح (Key Lifecycle State Machine)
**الوصف**: كل مفتاح (KEK أو subject key) يمرّ بحالات محدَّدة سلفاً (`pending → active → deprecated
→ revoked → destroyed`) عبر انتقالات أحادية الاتجاه فقط، مع رفض تدمير المفاتيح التي لا تزال لها
تبعيات حيّة (KEK فقط).
- **التنفيذ العام**: `keyring/core/lifecycle.py:1` ("Key lifecycle state machine (FR-4)").
- **FR-4.2** (نشاط KEK واحد فقط، مفروض على مستوى قاعدة البيانات): فهرس فريد جزئي
  `ux_keks_single_active` في `keyring/models/keys.py:24-33` وترحيل `alembic/versions/
  e1a463aef094_initial_schema.py:113`.
- **FR-4.3** (الرسوم البيانية أحادية الاتجاه): `keyring/models/enums.py:47-68`، وتطبيق عملي في
  `keyring/seed.py:199`.
- **FR-4.4** (رفض التدمير مع وجود تبعيات حيّة): `keyring/core/service.py:185-190`.
- **الاختبار**: `keyring/tests/test_lifecycle.py:1`، `keyring/tests/test_destroy.py:1`.

### FR-5 — تدوير KEK القابل للاستئناف وrewrap الخلفي (Resumable Rotation)
**الوصف**: تفعيل KEK جديد فوري وذرّي، مع إعادة تغليف (rewrap) تدريجية لكل مفاتيح الموضوعات
التابعة لـKEK القديم في خيط خلفي، دون أي نافذة يتوقف فيها التشفير/فك التشفير.
- **FR-5.1** (تدوير ذرّي: تنزيل القديم + تفعيل الجديد في معاملة واحدة):
  `keyring/core/service.py:95-97`.
- **FR-5.2/FR-5.3/FR-5.4** (دفعة rewrap، المؤشر/cursor، توفّر مستمر أثناء rewrap):
  `keyring/core/service.py:226` (تعليق "Rewrap batch job (FR-5.2, FR-5.3, FR-5.4)")، مؤشر تقدُّم
  الدفعة في `keyring/models/rewrap.py:22` (`cursor` = آخر `subject_key.id` مُعالَج).
- **FR-5.6** (نقل KEK مشتبَه به إلى `revoked` فوراً — إلغاء طارئ): `keyring/core/service.py:164`
  (`emergency_revoke`).
- **الاختبار**: `keyring/tests/test_rewrap.py:1,20,83`.

### FR-6 — تجريد مزوّد المفاتيح (Pluggable Key Provider)
**الوصف**: طبقة تجريد تسمح بتبديل مصدر السر الجذري (ملف/بيئة/Vault/KMS) دون تغيير منطق التشفير،
مع عدم تخزين أي بايتات KEK خام في قاعدة بيانات التطبيق مطلقاً.
- **FR-6.1** (لا KEK خام في قاعدة البيانات — `provider_ref` فقط): `keyring/config.py:28`،
  `keyring/core/keystore.py:6`، `keyring/models/keys.py:40-42`.
- **FR-6.3** (واجهة `KeyProvider` موحَّدة عبر 4 تطبيقات): `keyring/providers/base.py:1`،
  `keyring/providers/kms_provider.py:19`، تحقُّق في `keyring/tests/conftest.py:52` ("swappable,
  test suite runs unmodified").
- **الاختبار**: `keyring/tests/test_providers.py:1` — مجموعة اختبارات عقدية واحدة تُشغَّل على
  الأربعة مزوّدين.

### FR-7 — احتياط السر الجذري عبر Shamir (Shamir Secret Backup)
**الوصف**: تقسيم مفتاح التغليف المشتق من السر الجذري إلى حصص SLIP-39 (3 من 5)، مع إمكانية
التحقق من قابلية الاسترجاع دون كشف السر ذاته.
- **التنفيذ العام**: `keyring/core/shamir.py:1`، `THRESHOLD = 3`، `SHARES = 5` (`shamir.py:10-11`).
- **FR-7.3** (إثبات قابلية الاسترجاع دون كشف السر): `keyring/core/shamir.py:39-40`
  (`verify_recoverable`)، `keyring/core/backup.py:1`.
- **الاختبار**: `keyring/tests/test_shamir_backup.py:1`.

### FR-8 — سجل التدقيق المسلسل بالهاش (Hash-Chained Audit Log)
**الوصف**: كل عملية حسّاسة تُسجَّل في سجل تدقيق ذي هاش متسلسل (append-only) قابل للتحقق من عدم
العبث به.
- **FR-8.3** (سجل مسلسل بالهاش): `keyring/core/audit.py:1`، `keyring/models/audit.py:19`.
- **FR-8.4** (التحقق من السلسلة واكتشاف أول كسر): `keyring/core/audit.py:1`، دالة
  `verify_chain` في `audit.py:78`.
- **FR-8.5** (سجل فشل فك التشفير لمراجعة المدقِّق فقط): `keyring/models/audit.py:40`
  (`DecryptFailureLog`).
- **الاختبار**: `keyring/tests/test_audit.py:1`.

### FR-9 — RBAC وفصل الصلاحيات (RBAC & Separation of Duty)
**الوصف**: ثلاثة أدوار غير متداخلة الصلاحيات، بحيث لا يملك أي دور القدرة على تدمير مفتاح **و**
تعديل سجل التدقيق معاً؛ العمليات المدمِّرة تتطلَّب موافقة طرف ثانٍ مختلف.
- **التنفيذ العام**: `keyring/core/rbac.py:1-19` (مصفوفة `SCOPES`).
- **FR-9.2** (فصل الصلاحيات — بنيوي: لا يوجد endpoint لتعديل سجل التدقيق أصلاً):
  `keyring/core/rbac.py:3-6`.
- **FR-9.3** (موافقة طرفين، ورفض الموافقة الذاتية): `keyring/models/approvals.py:22`،
  تطبيق الرفض في `keyring/api/approvals.py:81`.
- **الاختبار**: `keyring/tests/test_rbac.py:1,37`، `keyring/tests/test_approvals_idempotency.py:1`.

### FR-10 — العمليات الأساسية الخمس + قواعد الـ Idempotency (Core Operations & Conventions)
**الوصف**: خمس عمليات أساسية يوفّرها `KeyringService` (تشفير، فك تشفير، تدوير، إلغاء/تدمير،
محو) بلا معامل تشفيري قابل لاختيار المستدعي، مع فرض `Idempotency-Key` على كل عملية مدمِّرة.
- **FR-10.1** (العمليات الخمس الأساسية): `keyring/core/service.py:1` ("the five core operations
  (FR-10.1)").
- **FR-10.2** (لا معامل تشفيري قابل للاختيار من المستدعي — الخوارزمية والمعاملات ثابتة داخلياً):
  `keyring/core/crypto.py:127-129`.
- **اتفاقية Idempotency-Key**: `keyring/api/idempotency.py:12-15` (تعليق "FR-10 conventions")،
  مطبَّقة على `POST /api/keys/{key_id}/destroy` و`POST /api/subjects/{subject_id}/erasure`.
- **الاختبار**: `keyring/tests/test_approvals_idempotency.py`.

### ملاحظة: عملية المحو (Crypto-Shredding / Erasure) لا تحمل معرّف FR خاصاً بها
دالة `erase_subject` في `keyring/core/service.py:549-575` (تعليق "Crypto-shredding / erasure
(section 3)") تُرجع إلى **"section 3 of the build spec"** — مستند مواصفات خارجي غير موجود في
هذا المستودع (انظر `13_GAPS.md`). آلياً هي تركيب لـFR-4 (تدمير subject key عبر `destroy_key`)
+ FR-8 (تسجيل تدقيق بعملية `erasure`)، مكشوفة عبر `POST /api/subjects/{subject_id}/erasure`
(`keyring/api/subjects.py:71-72`).

## 2. المتطلبات الوظيفية المشتقة من الـ Endpoints (غير موسومة بـ FR)

هذه القدرات موجودة في الكود وتُستهلَك من `web/`، لكنها بلا معرّف `FR-N` صريح في التعليقات:

| المعرّف | الوصف | الملفات المحقِّقة |
|---|---|---|
| FR-D1 | لوحة معلومات تشغيلية (عدد الأصول، عمر KEK النشط، صحة الدوران) | `keyring/api/dashboard.py`، `web/src/routes/Dashboard.tsx` |
| FR-D2 | خريطة بصرية لعلاقات KEK↔subject key وتحليل "نطاق الانفجار" (blast radius) قبل تدمير مفتاح | `keyring/api/graph.py`، `keyring/core/service.py:599` (`blast_radius`)، `web/src/routes/KeyMap.tsx` |
| FR-D3 | استعراض/تصفية/فرز قائمة المفاتيح مع صفحات (pagination) | `keyring/api/keys.py:30-31`، `web/src/routes/Keys.tsx` |
| FR-D4 | استعراض التقدُّم الحي لمهمة rewrap مع إيقاف/استئناف وإعادة محاولة الفشل | `keyring/api/rewrap.py`، `web/src/routes/Rewrap.tsx` |
| FR-D5 | تصدير شهادة المحو بصيغتَي JSON وPDF | `keyring/core/certificate.py:57,69`، `keyring/api/subjects.py:145-146` |
| FR-D6 | تصدير سجل التدقيق بصيغة CSV مع رؤوس معرَّبة | `keyring/api/audit.py:74-75` |
| FR-D7 | تنشيط/تبديل مزوّد المفتاح النشط من لوحة الإعدادات | `keyring/api/settings.py:55-56`، `web/src/routes/Settings.tsx` |
| FR-D8 | كشف مستند نموذج التهديد آلياً عبر API معرَّب | `keyring/api/settings.py:81-82` (`GET /api/threat-model`، بلا مصادقة) |

## 3. المتطلبات غير الوظيفية (NFR)

### NFR-01 — الأمان: المصادقة (Authentication)
مصادقة من مرحلتين: `X-Api-Key` (SHA-256 hex ثابت مقارنةً بـ`Operator.api_key_hash`) لفتح جلسة،
ثم توكن جلسة عشوائي (`uuid4()`) يُستخدَم كـ`Authorization: Bearer` على كل طلب لاحق.
**المصدر**: `keyring/api/session.py:23-47`، `keyring/api/deps.py:30-49`. تفصيل كامل في
`06_SECURITY.md`.

### NFR-02 — الأمان: التخويل (Authorization)
RBAC بثلاثة أدوار غير متداخلة الصلاحيات مفروضة عبر `require_scope()` في كل مسار API تقريباً
(`keyring/api/deps.py:52-58`). **المصدر**: `keyring/core/rbac.py:12-19`.

### NFR-03 — الأمان: التشفير
AES-256-GCM لكل مستويات التغليف، Argon2id لاشتقاق مفتاح الجذر، HKDF-SHA256 لاشتقاق مفاتيح
مشتقة من السر الجذري، HMAC-SHA256 لتوقيع شهادات المحو. **المصدر**: `keyring/core/crypto.py`.
تفصيل كامل في `06_SECURITY.md`.

### NFR-04 — الأمان: CORS
أصول مسموحة مُثبَّتة صراحةً (hardcoded) على `http://localhost:5173` و`http://127.0.0.1:5173` فقط،
مع `allow_credentials=True`. **المصدر**: `keyring/main.py:67-74`. لا توجد قائمة أصول قابلة للتهيئة
عبر متغيرات بيئة — قيمة ثابتة في الكود، وهو ما يُلاحَظ في `06_SECURITY.md`.

### NFR-05 — الأمان: Rate Limiting
**[غير موجود في الكود]**. بحث شامل (`grep -rniE 'rate.?limit|throttle'`) عبر `keyring/` و`web/src/`
لم يُظهر أي آلية تحديد معدّل طلبات على أي endpoint.

### NFR-06 — الأداء: الفهرسة (Indexing)
21 فهرساً معرَّفاً صراحةً عبر 14 جدولاً، منها فهرس فريد جزئي واحد لفرض قيد عمل (`ux_keks_single_active`).
**المصدر**: تفصيل كامل بجدول الفهارس في `04_DATABASE.md`.

### NFR-07 — الأداء: الترقيم بالصفحات (Pagination)
نمطان مختلفان متعايشان في نفس الكود: ترقيم صفحات تقليدي (`page`/`pageSize`) في
`keyring/api/keys.py:30-31` وterقيم بالمؤشر (cursor-based) في `keyring/api/audit.py:34-35`.
**ملاحظة أداء موثَّقة**: `keyring/api/keys.py:44-63` و`keyring/api/rewrap.py:70` يُحمِّلان **كل**
الصفوف من قاعدة البيانات ثم يُقطِّعان (slice) النتيجة داخل بايثون، دون `LIMIT`/`OFFSET` على مستوى
SQL — عيب أداء محتمل مع نمو البيانات، موثَّق أيضاً في `11_CHALLENGES.md`.

### NFR-08 — الأداء: العمليات غير المتزامنة (Async)
مساران فقط `async def` في كامل الـ API: `encrypt_stream` و`decrypt_stream`
(`keyring/api/core_ops.py:53-102`)، يستخدمان `queue.Queue(maxsize=4)` و`run_in_threadpool` لجسر
التزامن مع الطبقة المتزامنة أسفلهما (`service.py`). باقي كامل الـ API متزامن (sync) رغم أن
FastAPI/uvicorn يدعمان ASGI بالكامل.

### NFR-09 — قابلية التوسّع (Scalability)
- تدوير KEK بلا نافذة توقف: rewrap في خيط خلفي منفصل (`keyring/main.py:23-46`،
  `_rewrap_worker_loop`، يقرأ كل 0.3 ثانية).
- القاعدة مصمَّمة لتُطابَق SQLite في التطوير وPostgreSQL في الإنتاج (`THREAT_MODEL.md:101-106`)
  لدعم القفل متعدد الإصدارات (MVCC) عند التزامن.
- **قيد موثَّق صراحة**: اتصال مزوّد المفاتيح عام على مستوى العملية بأكملها
  (`keyring/core/runtime.py:13,30,40,47`) — قفل جلسة تشغيل واحدة يفصل مزوّد المفاتيح عن **كل**
  الجلسات الأخرى في نفس العملية، وهو قيد توسّع أفقي (horizontal scaling) صريح موثَّق في
  `11_CHALLENGES.md`.

### NFR-10 — الاعتمادية: معالجة الأخطاء (Error Handling)
هرمية استثناءات موحَّدة `KeyringError` (`keyring/core/errors.py:7-93`) بـ13 نوع خطأ محدَّد، كل
واحد بـ`status_code`/`code`/`message_key` معرَّب، مُلتقَطة مركزياً في معالِجات استثناء FastAPI
(`keyring/main.py:86-105`).

### NFR-11 — الاعتمادية: إعادة المحاولة (Retries) وIdempotency
لا آلية إعادة محاولة تلقائية للطلبات الفاشلة على مستوى العميل أو الخادم؛ بدلاً من ذلك يُطبَّق نمط
Idempotency-Key إلزامي على العمليات المدمِّرة (`keyring/api/idempotency.py:12-28`) لجعل إعادة
الإرسال من عميل غير مستقر آمنة (replay بلا إعادة تنفيذ). **قيد موثَّق**: لا وجود لسقف زمني (TTL)
أو تنظيف لسجلات `IdempotencyRecord` — تتراكم إلى الأبد (`keyring/models/idempotency.py`).

### NFR-12 — الاعتمادية: التسجيل (Logging)
لا مكتبة تسجيل تطبيقية عامة (application logger) ظاهرة في الكود بمعزل عن سجل التدقيق البنيوي
(`AuditLog`) وسجل فشل فك التشفير (`DecryptFailureLog`) — التسجيل مُنفَّذ كبيانات (data)، لا كملفات
نصية عبر `logging` القياسية. `[غير موجود في الكود]` لأي إعداد `logging.config` أو تكامل مع أداة
تجميع سجلات خارجية.

### NFR-13 — سهولة الاستخدام: التدويل (i18n)
تعريب كامل مزدوج (en/ar) على مستويين مستقلّين:
- **الخلفية**: `keyring/i18n/translate.py` — 46 مفتاح ترجمة متطابق بين `en.json` و`ar.json`،
  تحقُّق تكامل عند الاستيراد (`translate.py:13-17`) يمنع الإقلاع إن نقص مفتاح.
- **الواجهة**: `web/src/i18n/chrome.ts` (445 سطراً) — قاموس مسطَّح بمفاتيح نقطية، `type Dict =
  typeof en` يفرض تطابقاً بنيوياً وقت الترجمة (compile-time) على `ar`.

### NFR-14 — سهولة الاستخدام: إمكانية الوصول (Accessibility)
دعم محدود وموضعي: `role="status" aria-live="polite"` على مكدّس الإشعارات فقط
(`web/src/components/Toast.tsx:32`). لا سمات ARIA أخرى ظاهرة في بقية المكوّنات/الشاشات — تفصيل
في `09_UI_INVENTORY.md`.

### NFR-15 — سهولة الاستخدام: الاستجابة (Responsive) ودعم RTL
- **RTL**: مدفوع من `document.documentElement.dir` (`web/src/i18n/LocaleContext.tsx:18-21`)،
  خصائص CSS منطقية (`margin-inline-start` إلخ) مع تجاوزات صريحة لأربعة عناصر مُموضَعة مطلقاً
  (`web/src/styles/layout.css:97,121,126,131`).
- **الاستجابة**: نقطة انكسار واحدة فقط عند `≤860px` — تصدُّع الشبكة الجانبية إلى عمود واحد
  (`web/src/styles/layout.css:160-164`). لا نقاط انكسار إضافية لأحجام أخرى (تابلت/موبايل صغير).

## 4. الأدوار والصلاحيات — مصفوفة كاملة (دور × عملية)

المصدر: `keyring/core/rbac.py:12-19` (تعريف)، وربط كل نطاق (scope) بنقاط النهاية الفعلية عبر
`require_scope()` في كل وحدة `api/*.py`.

| العملية / النطاق (scope) | operator | key-admin | auditor | نقطة النهاية المرتبطة |
|---|:---:|:---:|:---:|---|
| `encrypt` | ✅ | ❌ | ❌ | `POST /api/encrypt`, `POST /api/encrypt-stream` |
| `decrypt` | ✅ | ❌ | ❌ | `POST /api/decrypt`, `GET /api/decrypt-stream/{id}`, `GET /api/subjects/{id}/fields/{table}/digest` |
| `rotate` | ❌ | ✅ | ❌ | `POST /api/keks/{id}/rotate/preview`, `POST /api/keks/{id}/rotate` |
| `revoke` | ❌ | ✅ | ❌ | `POST /api/keys/{id}/revoke` |
| `destroy` | ❌ | ✅ | ❌ | `POST /api/keys/{id}/destroy`, `POST /api/subjects/{id}/erasure` |
| `rewrap_manage` | ❌ | ✅ | ❌ | `GET/POST /api/rewrap/jobs/*` (كل نقاط rewrap) |
| `approve` | ❌ | ✅ | ❌ | `POST /api/approvals/{id}/approve` |
| `request_approval` | ❌ | ✅ | ❌ | `POST /api/approvals` |
| `settings_write` | ❌ | ✅ | ❌ | `GET/PATCH /api/settings`, `GET /api/providers`, `POST /api/backup/verify`, `GET /api/backup/verify/{id}` |
| `provider_activate` | ❌ | ✅ | ❌ | `POST /api/providers/{id}/activate` |
| `audit_read` | ❌ | ❌ | ✅ | `GET /api/audit`, `POST /api/audit/verify`, `GET /api/audit/export.csv`, `GET /api/audit/actors`, `GET /api/audit/operations` |

**نقاط بلا فرض صلاحية صريح (session فقط، أي دور)**: `GET /api/dashboard`، `GET /api/keys`،
`GET /api/keys/{id}`، `GET /api/keys/{id}/blast-radius`، `GET /api/graph`، `GET /api/subjects/{id}`،
`POST /api/subjects/{id}/verify-unreadable` (مقصود صراحةً — تعليق في `keyring/api/subjects.py:130`)،
`GET /api/certificates/{id}`، `GET /api/certificates/{id}/export`.

**نقطة بلا مصادقة إطلاقاً**: `GET /api/threat-model` (`keyring/api/settings.py:81-82`) — تعتمد فقط
على `get_locale`، بلا `get_current_session`.

**ملاحظة تصميم واجهة**: مسارات `web/` (9 شاشات) **غير محجوبة على مستوى المسار (route) نفسه** —
كل مستخدم مصادَق عليه يرى كل عناصر التنقل السبعة في `web/src/components/Shell.tsx:6-14`؛ التخويل
الفعلي هو زر-بزر عبر `hasScope()` من `AuthContext`، والخادم هو المُطبِّق الحقيقي والنهائي.
