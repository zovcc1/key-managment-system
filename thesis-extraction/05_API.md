# 05 — واجهة برمجة التطبيقات (API)

## 1. نمط الاتصال العام

كل الواجهة REST/JSON فوق HTTP، مُسجَّلة في `keyring/main.py:108-117` عبر عشر وحدات (routers)،
كل واحدة بادئتها `/api` أو `/api/<مورد>` (`APIRouter(prefix=...)` في رأس كل ملف). المصادقة موحَّدة
عبر Bearer token (تفصيل كامل في `06_SECURITY.md`)، والتفويض عبر `require_scope(<scope>)` من
`keyring/api/deps.py` كاعتمادية (dependency) على مستوى كل مسار على حدة — لا يوجد فحص صلاحيات مركزي
واحد يغطي كل المسارات، بل كل مسار يُصرِّح صراحةً بالنطاق (scope) الذي يحتاجه، أو يكتفي بـ
`get_current_session` (تسجيل دخول فقط، بلا نطاق محدَّد)، أو لا يطلب شيئاً إطلاقاً.

**إجمالي نقاط النهاية**: **45** نقطة موزَّعة على 10 وحدات (تأكيد بالعدّ المباشر من كل ملف):
`approvals` (3) + `audit` (5) + `core_ops` (4) + `dashboard` (3) + `graph` (2) + `keys` (7) +
`rewrap` (5) + `session` (3) + `settings` (7) + `subjects` (6) = **45**.

جميع المسارات مُسجَّلة **قبل** `app.mount("/", StaticFiles(...))` في `keyring/main.py:126-128` التي
تُقدِّم ملفات `web/dist` المبنية — الترتيب مقصود بحيث لا يمكن لأي مسار ثابت (static) أن يحجب مساراً
تحت `/api/*` (الفصل موضَّح في تعليق داخل `main.py`).

## 2. جدول نقاط النهاية الكامل

### 2.1 `keyring/api/approvals.py` — بادئة `/api/approvals`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| POST | `/api/approvals` | إنشاء طلب موافقة على عملية مدمّرة (destroy/erasure) | Body: `ApprovalCreateBody{operation, targetId, recordCount=0}` | `request_approval` | `approvals.py:41-61` (`create_approval`) |
| GET | `/api/approvals/{approval_id}` | جلب تفاصيل طلب موافقة | Path: `approval_id` | تسجيل دخول فقط (`get_current_session`) | `approvals.py:64-69` (`get_approval`) |
| POST | `/api/approvals/{approval_id}/approve` | موافقة الطرف الثاني على الطلب | Path: `approval_id` | `approve` | `approvals.py:72-95` (`approve`) |

**قاعدة منع الموافقة الذاتية**: يُقارَن `approval.requested_by` بهوية العامل الحالي
(`current.operator.id`)؛ عند التطابق تُرفَع `SelfApprovalError` (`approvals.py:81-82`) — تنفيذ مباشر
لقاعدة "لا يمكن لمن طلب أن يوافق" (FR-9.3).

### 2.2 `keyring/api/audit.py` — بادئة `/api/audit`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| GET | `/api/audit` | قائمة مُصفَّاة ومُقسَّمة بمؤشر (cursor) من سجل التدقيق | Query: `actor?, operation?, keyId?, from?, to?, cursor?, limit=50` | `audit_read` | `audit.py:34-63` (`list_audit`) |
| POST | `/api/audit/verify` | التحقق من سلامة سلسلة الهاش الكاملة لسجل التدقيق | — | `audit_read` | `audit.py:66-71` (`verify`)، يستدعي `core/audit.verify_chain` |
| GET | `/api/audit/export.csv` | تصدير كل سجل التدقيق بصيغة CSV مُعرَّبة العناوين | — | `audit_read` | `audit.py:74-82` (`export_csv`) |
| GET | `/api/audit/actors` | قائمة الفاعلين الفريدين الظاهرين في السجل | — | `audit_read` | `audit.py:85-88` (`actors`) |
| GET | `/api/audit/operations` | قائمة أنواع العمليات الفريدة الظاهرة في السجل | — | `audit_read` | `audit.py:91-94` (`operations`) |

**ملاحظة**: `from`/`to` في `list_audit` تُمرَّر مباشرة إلى `datetime.fromisoformat()`
(`audit.py:54,56`) بلا معالجة استثناء صريحة — قيمة غير صالحة الصيغة تنتج خطأ 500 غير مُهيّأ بدل رسالة
تحقق واضحة (400). موثَّق كملاحظة في `11_CHALLENGES.md`.

### 2.3 `keyring/api/core_ops.py` — بادئة `/api` (عمليات التشفير الأساسية)

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| POST | `/api/encrypt` | تشفير حقل بيانات واحد وإنشاء ظرف (Envelope) جديد | Body: `EncryptBody{subjectId, table, column, recordId, plaintext}` | `encrypt` | `core_ops.py:23-34` (`encrypt`) |
| POST | `/api/decrypt` | فك تشفير ظرف موجود عبر معرّفه | Body: `DecryptBody{envelopeId}` | `decrypt` | `core_ops.py:37-50` (`decrypt`) |
| POST | `/api/encrypt-stream` | تشفير جسم ثنائي متدفّق (streamed) بلا تخزين كامل في الذاكرة | Query: `subjectId, table, column, recordId`؛ Body: بايتات خام `application/octet-stream` | `encrypt` | `core_ops.py:53-98` (`encrypt_stream`، دالة `async`) |
| GET | `/api/decrypt-stream/{envelope_id}` | فك تشفير وبثّ محتوى ظرف كبير كتيار بايتات | Path: `envelope_id` | `decrypt` | `core_ops.py:101-132` (`decrypt_stream`، دالة `async`) |

هاتان الدالتان (`encrypt_stream`, `decrypt_stream`) هما **الوحيدتان `async def`** في كامل واجهة الـ
API (تأكيد بالعدّ المباشر — بقية الـ43 نقطة معالجاتها متزامنة `def` عادية تعمل ضمن threadpool
FastAPI الافتراضي). التوثيق الداخلي في `core_ops.py:63-72` يشرح أن الجسر بين حلقة أحداث ASGI
غير المتزامنة و`KeyringService` المتزامن (الذي يملك جلسة قاعدة بيانات متزامنة كبقية طبقة الخدمة) يتم
عبر طابور محدود الحجم (`queue.Queue(maxsize=4)`, `core_ops.py:19,73`): حلقة الأحداث تدفع القطع
(chunks) فور وصولها، وعامل الـ threadpool الذي يُشغِّل `encrypt_stream()` يُحجَب على الطابور بين
القطع. الحد الأقصى `_QUEUE_MAXSIZE = 4` (`core_ops.py:19`) يقيّد عدد القطع "في الطريق" في أي لحظة.

### 2.4 `keyring/api/dashboard.py` — بادئة `/api`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| GET | `/api/dashboard` | لوحة المعلومات الرئيسية: KEK النشط، عدّادات البلاطات، شريط الصحة | — | تسجيل دخول فقط | `dashboard.py:25-57` (`dashboard`) |
| GET | `/api/metrics/decrypt-failures` | إحصاء فشل فك التشفير مُجمَّعاً بالساعة ضمن نافذة زمنية | Query: `window="24h"` | تسجيل دخول فقط | `dashboard.py:60-71` (`decrypt_failures`) |
| POST | `/api/alerts/{alert_id}/ack` | تأكيد استلام تنبيه (acknowledge) | Path: `alert_id` | تسجيل دخول فقط | `dashboard.py:74-83` (`ack_alert`) |

شريط الصحة (`healthStrip`) في `/api/dashboard` يجمع ثلاثة مؤشرات حيّة في طلب واحد
(`dashboard.py:51-55`): حالة اتصال المزوّد (`runtime.is_connected()`)، حالة سلامة سلسلة التدقيق
(`verify_chain(db)`)، ووجود KEK نشط من عدمه — وهذا يُنفِّذ استعلام `verify_chain` (فحص كامل السلسلة)
في **كل** طلب لوحة تحكم، وليس بشكل دوري مُخزَّن مؤقتاً.

### 2.5 `keyring/api/graph.py` — بادئة `/api/graph`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| GET | `/api/graph` | خريطة كاملة لعُقَد (nodes) وأضلاع (edges) KEK/subject_key لعرض شجرة المفاتيح | — | تسجيل دخول فقط | `graph.py:14-29` (`get_graph`) |
| GET | `/api/graph/{node_id}/downstream` | قائمة المعرّفات المنحدرة (downstream) من عقدة معيّنة | Path: `node_id` | تسجيل دخول فقط | `graph.py:32-41` (`downstream`) |

`get_graph` يحسب `dependentCount` لكل KEK بعدّ عناصر Python (`sum(1 for sk in sks if ...)`،
`graph.py:22`) بعد تحميل **كل** صفوف `keks` و`subject_keys` من القاعدة مسبقاً (`graph.py:16-17`) —
لا يوجد `GROUP BY` على مستوى قاعدة البيانات لهذا الحساب.

### 2.6 `keyring/api/keys.py` — بادئة `/api`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| GET | `/api/keys` | قائمة مُصفَّاة/مُرتَّبة/مُقسَّمة لصفحات لكل من KEK وsubject_key معاً | Query: `type?, state?, q?, sort="createdAt", dir="desc", page=1, pageSize=20` | تسجيل دخول فقط | `keys.py:30-64` (`list_keys`) |
| GET | `/api/keys/{key_id}` | تفاصيل مفتاح واحد (KEK أو subject_key، يُحدَّد النوع تلقائياً) | Path: `key_id` | تسجيل دخول فقط | `keys.py:67-70` (`get_key`) |
| GET | `/api/keys/{key_id}/blast-radius` | حساب "نصف قطر الانفجار" — عدد السجلات/الجداول المتأثرة بمفتاح | Path: `key_id` | تسجيل دخول فقط (عبر `get_service`) | `keys.py:73-75` (`blast_radius`) → `service.py:599-620` |
| POST | `/api/keks/{key_id}/rotate/preview` | معاينة أثر تدوير KEK قبل تنفيذه فعلياً | Path: `key_id` | `rotate` | `keys.py:78-80` (`rotate_preview`) |
| POST | `/api/keks/{key_id}/rotate` | تنفيذ تدوير KEK فعلياً وبدء مهمة rewrap خلفية | Path: `key_id` | `rotate` | `keys.py:83-87` (`rotate`) |
| POST | `/api/keys/{key_id}/revoke` | إبطال مفتاح (KEK أو subject_key) | Path: `key_id`؛ Body: `RevokeBody{reason?}` | `revoke` | `keys.py:90-95` (`revoke`) |
| POST | `/api/keys/{key_id}/destroy` | تدمير مفتاح فعلياً (crypto-shredding عند subject_key) | Path: `key_id`؛ Body: `DestroyBody{typedConfirmation, approvalId}`؛ Header: `Idempotency-Key?` | `destroy` | `keys.py:98-125` (`destroy`) |

`destroy` هي أوضح مثال في المشروع على تراكب ثلاث آليات حماية معاً في نقطة نهاية واحدة: (أ) تأكيد
مكتوب (`typedConfirmation` يجب أن يساوي `key_id` حرفياً، وإلا `ConfirmationMismatchError`،
`keys.py:106-107`)، (ب) موافقة طرف ثانٍ مُعتمَدة مسبقاً (`Approval` بحالة `approved`، بعملية `destroy`،
وهدف مطابق لـ`key_id`، وإلا `ApprovalRequiredError`، `keys.py:111-115`)، (ج) مفتاح idempotency
اختياري عبر رأس `Idempotency-Key` يُمرَّر إلى `run_idempotent()` (`keys.py:104,122`) لمنع التنفيذ
المزدوج عند إعادة إرسال نفس الطلب.

### 2.7 `keyring/api/rewrap.py` — بادئة `/api/rewrap`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| GET | `/api/rewrap/jobs/current` | جلب أحدث مهمة rewrap (بالترتيب الزمني) | — | `rewrap_manage` | `rewrap.py:36-41` (`current_job`) |
| POST | `/api/rewrap/jobs/{job_id}/pause` | إيقاف مهمة rewrap مؤقتاً | Path: `job_id` | `rewrap_manage` | `rewrap.py:44-51` (`pause`) |
| POST | `/api/rewrap/jobs/{job_id}/resume` | استئناف مهمة rewrap متوقفة | Path: `job_id` | `rewrap_manage` | `rewrap.py:54-61` (`resume`) |
| GET | `/api/rewrap/jobs/{job_id}/failures` | قائمة مُقسَّمة لصفحات لحالات فشل إعادة تغليف ضمن مهمة | Path: `job_id`؛ Query: `page=1, pageSize=20` | `rewrap_manage` | `rewrap.py:64-81` (`failures`) |
| POST | `/api/rewrap/jobs/{job_id}/failures/{item_id}/retry` | إعادة محاولة إعادة تغليف عنصر فاشل واحد | Path: `job_id, item_id` | `rewrap_manage` | `rewrap.py:84-88` (`retry_failure`) → `service.rewrap_retry_failure` |

حساب المعدّل والوقت المتبقي (`rate`, `eta`) في `_job_public()` (`rewrap.py:19-33`) يُحسَب لحظياً في
كل استدعاء من `done / elapsed_seconds` منذ `created_at` — تقدير بسيط بمعدل تراكمي وليس معدلاً متحركاً
(moving average) لآخر نافذة زمنية.

### 2.8 `keyring/api/session.py` — بادئة `/api/session`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| POST | `/api/session` | فتح جلسة جديدة (تسجيل الدخول) عبر مفتاح API | Header: `x-api-key`؛ Body: `SessionOpenBody{provider?}` | لا مصادقة مسبقة (هذه نقطة الدخول نفسها) | `session.py:23-54` (`open_session`) |
| DELETE | `/api/session` | قفل الجلسة الحالية (تسجيل الخروج المنطقي) | — | تسجيل دخول فقط | `session.py:57-64` (`lock_session`) |
| GET | `/api/session` | حالة الجلسة الحالية (العامل، الدور، القفل، اتصال المزوّد) | — | تسجيل دخول فقط | `session.py:67-76` (`session_status`) |

آلية فتح الجلسة: `x-api-key` يُهاش بـ SHA-256 (`hashlib.sha256(...).hexdigest()`, `session.py:27`)
ويُقارَن بـ `Operator.api_key_hash` المخزَّن — أي أن المفتاح الخام لا يُقارَن نصياً أبداً، والمفتاح
الخام نفسه لا يُخزَّن في أي مكان (منطق مطابق لتعليق `Operator` في `04_DATABASE.md` §2.10).

### 2.9 `keyring/api/settings.py` — بادئة `/api`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| GET | `/api/settings` | قراءة إعدادات النظام (فترة التدوير، عتبة التنبيه، المزوّد النشط) | — | `settings_write` | `settings.py:26-29` (`get_settings`) |
| PATCH | `/api/settings` | تعديل جزئي لإعدادات النظام | Body: `SettingsPatchBody{rotationIntervalDays?, alertThreshold?}` | `settings_write` | `settings.py:32-40` (`patch_settings`) |
| GET | `/api/providers` | قائمة مزوّدي المفاتيح المتاحين وحالة توفّرهم | — | `settings_write` | `settings.py:43-52` (`list_providers`) |
| POST | `/api/providers/{provider_id}/activate` | تفعيل مزوّد مفاتيح مختلف (فصل الحالي واتصال بالجديد) | Path: `provider_id` | `provider_activate` | `settings.py:55-64` (`activate_provider`) |
| POST | `/api/backup/verify` | بدء مهمة تحقّق من نسخة احتياطية | — | `settings_write` | `settings.py:67-70` (`backup_verify`) |
| GET | `/api/backup/verify/{job_id}` | حالة مهمة تحقّق نسخة احتياطية | Path: `job_id` | `settings_write` | `settings.py:73-78` (`backup_verify_status`) |
| GET | `/api/threat-model` | إرجاع نموذج التهديد كاملاً (نص مُعرَّب) للعرض في الواجهة | — | **بلا مصادقة إطلاقاً** | `settings.py:81-83` (`threat_model`) → `core/threat_model.render` |

**ملاحظتان مُلاحَظتان مباشرة من الكود**:
- `GET /api/settings` نفسها (عملية قراءة فقط) محمية بصلاحية **كتابة** (`settings_write`،
  `settings.py:27`) بدل صلاحية قراءة منفصلة — لا يوجد نطاق `settings_read` مستقل في `rbac.py`.
- `GET /api/threat-model` (`settings.py:81-83`) هي نقطة النهاية الوحيدة في كامل الـ45 التي لا تطلب
  أي اعتمادية مصادقة (`Depends`) على الإطلاق سوى تحديد اللغة (`get_locale`) — يبدو تصميماً مقصوداً
  لجعل وثيقة نموذج التهديد قابلة للعرض العلني دون تسجيل دخول (تفصيل إضافي في `06_SECURITY.md`).

### 2.10 `keyring/api/subjects.py` — بادئة `/api`

| Method | Path | الوصف | المدخلات | الصلاحية المطلوبة | المعالج |
|---|---|---|---|---|---|
| GET | `/api/subjects/{subject_id}` | تفاصيل موضوع (subject): حالة مفتاحه، عدد سجلاته، الجداول المرتبطة | Path: `subject_id` | تسجيل دخول فقط (عبر `get_service`) | `subjects.py:28-38` (`get_subject`) |
| GET | `/api/subjects/{subject_id}/fields/{table}/digest` | فك تشفير قيمة حقل واحد وإرجاعها مُقنَّعة (مموَّهة) جزئياً | Path: `subject_id, table` | `decrypt` | `subjects.py:41-68` (`field_digest`) |
| POST | `/api/subjects/{subject_id}/erasure` | تنفيذ محو تشفيري (crypto-shredding) كامل لموضوع + إصدار شهادة موقَّعة | Path: `subject_id`؛ Body: `ErasureBody{typedConfirmation, approvalId}`؛ Header: `Idempotency-Key?` | `destroy` | `subjects.py:71-125` (`erasure`) |
| POST | `/api/subjects/{subject_id}/verify-unreadable` | التحقق من أن كل سجلات موضوع مَمحُوّ صارت فعلاً غير قابلة لفك التشفير | Path: `subject_id` | **بلا نطاق محدَّد** (تعليق صريح في الكود) | `subjects.py:128-134` (`verify_unreadable`) |
| GET | `/api/certificates/{certificate_id}` | جلب شهادة محو موقَّعة (JSON) | Path: `certificate_id` | تسجيل دخول فقط | `subjects.py:137-142` (`get_certificate`) |
| GET | `/api/certificates/{certificate_id}/export` | تصدير شهادة محو بصيغة JSON أو PDF | Path: `certificate_id`؛ Query: `format="json"\|"pdf"` | تسجيل دخول فقط | `subjects.py:145-160` (`export_certificate`) |

**نقاط جديرة بالتوثيق**:
- `erasure` تستخدم نطاق `destroy` نفسه (وليس نطاقاً منفصلاً `erasure`) — أي أن أي عامل بصلاحية
  `destroy` يمكنه أيضاً بدء عملية محو موضوع، طالما توفّرت موافقة طرف ثانٍ صالحة على عملية
  `"erasure"` تحديداً (`subjects.py:76,86-89`؛ نطاقات RBAC مفصَّلة في `02_REQUIREMENTS.md`).
- `verify_unreadable` (`subjects.py:128-134`) لا تطلب أي نطاق — تعليق صريح داخل الكود
  (`subjects.py:130-131`) يبرّر ذلك: "لا يعبر هذا الحد سوى قيَم نجاح/فشل منطقية، لا نص صريح مطلقاً —
  هذا دليل المدقِّق (auditor's proof artifact)" — أي مصمَّم عمداً ليكون متاحاً بلا صلاحية عالية لأنه
  لا يُسرِّب بيانات حسّاسة.
- `field_digest` (`subjects.py:41-68`) عند فشل فك التشفير تُعيد **HTTP 200** مع
  `{"code": "DECRYPT_FAILED", ...}` (`subjects.py:59`) — خلافاً لـ`POST /api/decrypt` و
  `POST /api/subjects/{subject_id}/erasure` اللتين تُعيدان **HTTP 400** لنفس الحالة
  (`core_ops.py:48`)؛ عدم اتساق في رمز الحالة لنفس الشكل المنطقي للخطأ عبر نقطتَي نهاية مختلفتين.
- `erasure` تبني شهادة محو (`ErasureCertificate`) وتوقّعها HMAC-SHA256 (`cert_module.sign_payload`)
  ثم تخزّنها كصفّ جديد **داخل** نفس دالة المعالجة (`subjects.py:106-119`) قبل إرجاع `certificateId` —
  أي أن إصدار الشهادة والمحو نفسه عملية ذرّية واحدة (كلاهما داخل نفس معاملة قاعدة البيانات).

## 3. القنوات غير-REST

**WebSocket**: لا يوجد أي كود WebSocket في المشروع (تأكيد بالبحث عن `websocket`/`WebSocket` في
`keyring/` — لا نتائج). حزمة `websockets` مثبَّتة فعلياً في `.venv` لكنها **تبعية انتقالية**
لـ`uvicorn[standard]` وليست مُستخدَمة مباشرة (موثَّق أيضاً في `01_TECH_STACK.md` §3).

**gRPC / رسائل طابور (Message Queue)**: `[غير موجود في الكود]` — لا مكتبة gRPC ولا وسيط رسائل
(RabbitMQ/Kafka/Redis pub-sub) في أي مكان من `pyproject.toml` أو الكود.

**استقصاء (polling) من جانب الواجهة الأمامية** كبديل عن دفع الأحداث (push): مُلاحَظ في مكوّنَين على
الأقل (تفصيل أوسع في `09_UI_INVENTORY.md`): شاشة `Rewrap` تستقصي كل 3 ثوانٍ، ومربع حوار
`DestroyFlowDialog` يستقصي كل 2.5 ثانية — لا يوجد أي آلية دفع حقيقية (SSE أو WebSocket) لتحديث حالة
العمليات الطويلة الأمد في هذا المشروع.

## 4. المهام المجدوَلة (Scheduled/Background Jobs)

**عامل rewrap الخلفي** (`keyring/main.py:23-46`, `_rewrap_worker_loop`) هو المهمة الخلفية الوحيدة في
النظام: خيط (thread) بايثون واحد (`threading.Thread(target=_rewrap_worker_loop, daemon=True)`،
`main.py:53`) يُطلَق عند إقلاع التطبيق ضمن `lifespan` context manager (`main.py:49-56`)، ويُوقَف عبر
`threading.Event` (`_rewrap_worker_stop`) عند إغلاق التطبيق.

آلية العمل: حلقة `while` تفحص كل **0.3 ثانية** (`main.py:46`, `_rewrap_worker_stop.wait(0.3)`) ما إذا
كان المزوّد متصلاً، وإن كان كذلك تبحث عن أقدم `RewrapJob` بحالة `"running"` (`main.py:33-35`)، وتُنفِّذ
دفعة واحدة من 25 عنصراً (`service.rewrap_step(job.id, batch_size=25)`, `main.py:38`) ثم تُثبِّت
(commit) وتُغلق الجلسة. أي استثناء غير متوقَّع يُبتلَع صراحةً (`except Exception: pass`, `main.py:44`،
معلَّق "worker must never crash the loop") — أي أن فشل دفعة واحدة لا يوقف الحلقة، لكنه أيضاً لا يُسجَّل
في أي سجل تطبيقي (لا يوجد logger مُهيَّأ في المشروع؛ فقط سجل التدقيق كبيانات، انظر `06_SECURITY.md`).

لا يوجد `cron`، لا `APScheduler`، لا `Celery` — هذا الخيط اليدوي هو الآلية الوحيدة لأي معالجة خلفية
في كامل المشروع.

## 5. خدمات خارجية واتصالات طرف ثالث

المزوّدون الأربعة (`keyring/providers/{file,env,vault,kms}.py`، خلف واجهة `KeyProvider` الموحَّدة
الموصوفة في `03_ARCHITECTURE.md`) هم نقطة الاتصال الوحيدة المحتملة بخدمات خارجية فعلية:
- **file / env**: لا اتصال شبكي — قراءة من نظام الملفات أو متغيّرات البيئة محلياً.
- **vault**: مزوّد يمثّل تكاملاً مع HashiCorp Vault (تفاصيل بروتوكول المصادقة والاتصال الفعلية
  مطلوبة من `keyring/providers/vault.py` — غير مُستخرَجة بالتفصيل الكامل في هذا الملف؛ التركيز هنا
  كان على طبقة API لا طبقة المزوّدين، المُغطاة بعمق في `06_SECURITY.md` و`03_ARCHITECTURE.md`).
- **kms**: مزوّد يمثّل تكاملاً مع خدمة KMS سحابية (نفس الملاحظة أعلاه).

لا يوجد استدعاء HTTP خارجي آخر (لا بريد إلكتروني، لا إشعارات push، لا تحليلات/telemetry) في أي مكان
من الكود المفحوص.

## 6. ملخّص فجوات هذا الملف

- تفاصيل بروتوكول اتصال مزوّدَي `vault`/`kms` الدقيقة (نقاط نهاية Vault/KMS الفعلية، طريقة المصادقة)
  تحتاج قراءة مباشرة إضافية لملفَي `keyring/providers/vault.py` و`keyring/providers/kms.py` لم تتم
  ضمن نطاق هذا الملف تحديداً.
- توثيق OpenAPI/Swagger التلقائي لـ FastAPI (`/docs`, `/openapi.json`) متاح ضمنياً بحكم استخدام
  FastAPI نفسه، لكن لا يوجد تخصيص صريح (`openapi_tags`, أوصاف موسَّعة) يتجاوز `tags=[...]` البسيطة
  المذكورة أعلاه — `[غير موجود في الكود]` أي تخصيص أعمق.
