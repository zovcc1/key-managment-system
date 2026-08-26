# 06 — الأمان (Security)

هذا الملف يبني على `THREAT_MODEL.md` (116 سطراً، موجود في جذر المشروع) مع **التحقق من كل ادعاء فيه
مقابل الكود الفعلي**، وليس نقله حرفياً. كل قسم أدناه يذكر أولاً ما تدّعيه `THREAT_MODEL.md` ثم مصدر
التحقق البرمجي.

## 1. آلية المصادقة (Authentication)

**نوع الرمز**: **UUID4 عشوائي مُخزَّن في قاعدة البيانات كنص خام**، وليس JWT ولا أي توكن موقَّع
ذاتياً — لا توجد مكتبة JWT في `pyproject.toml` (تأكيد: لا `pyjwt`/`python-jose` في التبعيات).

**تدفّق فتح الجلسة** (`keyring/api/session.py:23-54`, `POST /api/session`):
1. العميل يرسل رأس `x-api-key` خام (`session.py:24`).
2. الخادم يحسب `hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()` (`session.py:27`) ويقارنه
   بعمود `Operator.api_key_hash` المخزَّن (`session.py:28`) — **المفتاح الخام لا يُخزَّن ولا يُقارَن
   نصياً في أي مكان**؛ فقط هاشه.
3. عند التطابق، يُنشأ صفّ `Session` جديد بمعرّف `uuid.uuid4()` عشوائي (`session.py:36`)، ومدة صلاحية
   `expires_at = now + session_ttl_seconds` (الافتراضي **3600 ثانية = ساعة واحدة**، `config.py:50`،
   `session.py:40`).
4. الاستجابة تُعيد `token` (وهو معرّف صفّ `Session` نفسه، `session.py:47`) — أي أن **معرّف الجلسة في
   قاعدة البيانات هو نفسه رمز الحمل (bearer token)** الذي يستخدمه العميل لاحقاً، دون طبقة تشفير أو
   توقيع إضافية عليه.

**التحقق من الرمز في كل طلب لاحق** (`keyring/api/deps.py:30-49`, `get_current_session`):
- يتطلب رأس `Authorization: Bearer <token>` (`deps.py:34`، وإلا `UnauthorizedError` رمز 401).
- يبحث عن صفّ `Session` بمعرّف يساوي الرمز مباشرة (`db.get(Session, token)`, `deps.py:38`) — بحث
  مساواة مباشرة على المفتاح الأساسي، وليس هاشاً للرمز (خلافاً لـ`api_key_hash` وقت فتح الجلسة).
- يفحص `session.locked` (`deps.py:41-42`, `LockedSessionError` رمز 401 مختلف الكود `SESSION_LOCKED`
  عن `UNAUTHORIZED` رغم تطابق رمز HTTP).
- يفحص انتهاء الصلاحية `aware(session.expires_at) < now()` (`deps.py:43-44`).
- **لا توجد آلية تجديد (refresh) للجلسة** — الرمز صالح لمدة ثابتة `session_ttl_seconds` منذ لحظة
  الإنشاء فقط، ولا يوجد أي مسار `refresh`/`renew` في الـ45 نقطة نهاية.
- **التخزين في الواجهة الأمامية**: مطلوب فحص `web/src/` — إن كان الرمز يُخزَّن في الذاكرة فقط (متغيّر
  JS) وليس `localStorage`/`sessionStorage`/كوكي، فهذا يقلّل من مخاطر XSS-to-token-theft. هذا التفصيل
  **لم يُتحقَّق منه مباشرة ضمن هذا الملف** — التحقق الدقيق من كود الواجهة موصى بإجرائه عند كتابة قسم
  الواجهة الأمامية من الأطروحة، ويُترَك هنا كملاحظة صريحة بدل افتراضه.

## 2. آلية التفويض (Authorization) — RBAC

ثلاثة أدوار غير متداخلة الصلاحيات المدمّرة (`keyring/core/rbac.py:12-19`، `SCOPES` dict):

| الدور | النطاقات (scopes) |
|---|---|
| `operator` | `encrypt`, `decrypt` |
| `key-admin` | `rotate`, `revoke`, `destroy`, `rewrap_manage`, `approve`, `request_approval`, `settings_write`, `provider_activate` |
| `auditor` | `audit_read` |

**تعليق داخل الملف نفسه** (`rbac.py:1-6`) يوثّق تصميم FR-9.2 مباشرة: "لا يمكن لدور واحد أن يدمّر
مفتاحاً ويُعدِّل سجل التدقيق معاً" — وهذا محقَّق **بنيوياً** لا بفحص وقت التشغيل: سجل التدقيق
(`AuditLog`) لا يملك أي مسار API للتعديل إطلاقاً (append-only، يُكتَب فقط من طبقة الخدمة عبر
`core/audit.append`)، لذا لا حاجة لفحص RBAC يمنع "تعديل التدقيق" لأن الإمكانية نفسها غير موجودة في
سطح الـ API.

**نقطة الإنفاذ**: `require_scope(scope)` (`keyring/api/deps.py:52-58`) اعتمادية FastAPI تُغلِّف
`get_current_session` وتفحص `rbac.has_scope(current.operator.role, scope)` (`rbac.py:26-27`)، وإلا
`ForbiddenError` (رمز 403، `errors.py:72-75`). **كل مسار يُصرِّح بنطاقه بشكل منفصل** في توقيع دالته
(انظر الجدول الكامل في `05_API.md`) — لا يوجد middleware مركزي واحد يفرض RBAC على كل الطلبات تلقائياً؛
غياب `Depends(require_scope(...))` في توقيع أي مسار (كما هو الحال في `GET /api/threat-model` و
`POST /api/subjects/{subject_id}/verify-unreadable`) يعني تلقائياً عدم وجود أي قيد تفويض عليه.

## 3. تشفير الأسرار/كلمات المرور (كلمة السر الجذرية)

لا يوجد "كلمة مرور مستخدم" بالمعنى التقليدي في هذا النظام (لا واجهة تسجيل مستخدمين بكلمة مرور) — بدلاً
من ذلك، **السر الجذري (root secret)** هو ما يُشتَق منه كل التسلسل الهرمي للمفاتيح.

**مزوّد الملف (`FileKeyProvider`, `keyring/providers/file_provider.py:24-91`)**، وهو المزوّد الافتراضي
(`config.py:18`, `provider: str = "file"`):
- عبارة المرور تُقرَأ من ملف (`root_passphrase_file`, افتراضياً `./data/root.passphrase`) **يجب أن
  يحمل أذونات نظام ملفات `0400` بالضبط** — فحص صريح `_require_0400()` (`file_provider.py:14-21`)
  يرفض الاتصال ("refusing to start") إن كانت الأذونات مختلفة، مع رسالة تذكر الأذونات الفعلية المرصودة.
- **اشتقاق المفتاح**: `argon2id_derive(passphrase, salt)` (`file_provider.py:55`) يستدعي
  `crypto.argon2id_derive` (`crypto.py:200-212`) بمعطيات Argon2id: **time_cost=3، memory_cost=64
  MiB (65536 KiB)، parallelism=4** (قيَم افتراضية في `config.py:41-43`، معلَّقة صراحة "do not lower
  without a security review"). الملح (salt) لا يقل عن 16 بايت (`crypto.py:202-203`)، ويُنشأ تلقائياً
  عشوائياً (`crypto.random_bytes(16)`) إن لم يكن ملف الملح موجوداً بعد (`file_provider.py:47-50`)،
  ويُحفَظ بدوره بأذونات `0400` (`file_provider.py:50`).
- ناتج الاشتقاق (`_root_wrapping_key`) هو مفتاح تغليف يُستخدَم لفتح/إغلاق مخزن KEK محلي مشفَّر
  (`LocalEncryptedKeyStore`, `settings.kek_store_path`, افتراضياً `./data/kek_store.enc.json`) —
  **يعيش خارج قاعدة بيانات التطبيق تماماً**، تنفيذاً مباشراً لـ FR-6.1 المذكورة في تعليق
  `config.py:27-28`.
- **إزالة المفتاح من الذاكرة**: عند `disconnect()` يُستدعى `crypto.zeroize(self._root_wrapping_key)`
  (`file_provider.py:58-59`) الذي يكتب أصفاراً فوق كل بايت في `bytearray` (`crypto.py:77-84`) — موصوف
  في تعليق الدالة نفسها بأنه "Best-effort overwrite... CPython gives no hard guarantee this is not
  copied elsewhere (interning, GC, swap) — this reduces the exposure window, it does not eliminate
  it." **هذا يتطابق حرفياً مع ادعاء "Best-effort memory zeroization" في `THREAT_MODEL.md:107-112`** —
  تحقَّق ومطابَق بنجاح.
- **مزوّد البيئة (`env_provider.py:42`)** يشتق مفتاح التغليف الجذري بطريقة مختلفة: `HKDF-SHA256` عبر
  `crypto.hkdf_derive(secret, crypto.HKDF_INFO_ROOT_WRAP)` بدل Argon2id — لأن السر في هذه الحالة
  يأتي من متغيّر بيئة (`root_secret_env_var`, افتراضياً `KEYRING_ROOT_SECRET`) وليس عبارة مرور بشرية
  تحتاج تقوية (stretching)؛ الفرق بين المزوّدين موثَّق هنا كملاحظة دقيقة، لا كتناقض.

## 4. تشفير البيانات الحسّاسة

**التسلسل الهرمي الكامل** (موصوف بتفصيل في `03_ARCHITECTURE.md`): سر جذري → KEK (يُغلَّف بالسر
الجذري عبر المزوّد) → subject key (يُغلَّف بـ KEK نشط، مخزَّن كـ `wrapped_key` في جدول
`subject_keys`) → DEK أحادي الاستخدام لكل سجل (يُغلَّف بـ subject key، مخزَّن كـ `wrapped_dek` داخل
صفّ `Envelope` نفسه).

**الخوارزمية الوحيدة المستخدَمة في كل مستوى**: **AES-256-GCM** (AEAD)، عبر `cryptography` (مكتبة
معتمَدة، لا تنفيذ يدوي — تعليق رأس الملف `crypto.py:1-7`: "No primitive... is implemented by hand,
per the build spec"). حجم المفتاح 32 بايت / 256-بت (`KEY_LEN = 32`, `crypto.py:25`)، nonce عشوائي
96-بت (`NONCE_LEN = 12`, `crypto.py:24`)، tag مصادقة 128-بت (`TAG_LEN = 16`, `crypto.py:26`).
الخوارزمية **ثابتة وغير قابلة للاختيار من طرف المستدعي في أي نقطة من السطح العام** — تعليق صريح في
`aead_encrypt()` (`crypto.py:127-129`) يذكر FR-10.2 لهذا التحديد تحديداً.

**AAD (Additional Authenticated Data)** يربط كل ciphertext بموقعه المنطقي الدقيق: `build_aad(table,
column, record_id, subject_id)` (`crypto.py:215-219`) تُنتج نصاً مثل
`table:t|col:c|id:r|subject:s"` مُحوَّلاً لبايتات — تعليقها يشرح السبب مباشرة: "attacker with write
access can relocate an encrypted field between records without breaking confidentiality but
corrupting meaning" — أي أن AAD لا يضيف سرّية بل **يمنع إعادة توطين ciphertext** بين سجلات مختلفة.
هذا **يطابق حرفياً** ادعاء `THREAT_MODEL.md:57`: "AAD binds each envelope to its exact logical
location... so relocating ciphertext between records breaks decryption rather than silently
succeeding (FR-3.2)."

**حارس إعادة استخدام nonce** (`_NonceGuard`, `crypto.py:87-111`): بنية دفاعية إضافية (وليست الضمانة
البنيوية الأساسية) تتعقّب أزواج `(بصمة_المفتاح, nonce)` المُستخدَمة سابقاً في مجموعة محدودة الحجم
(`_MAX = 200_000`)، وترفع `AssertionError` عند اكتشاف تكرار — تعليقها يوضّح أنها "تؤكد" (asserts) بدل
"تثق ضمنياً" في أن كل DEK أحادي الاستخدام ببنيته، لا أنها البديل عن تلك البنية.

**فك التشفير المُوحَّد الفشل** (`aead_decrypt`, `crypto.py:180-190`): يرفع `DecryptFailed` نفسها بلا
تمييز لأي من: وسم غير صالح (`InvalidTag`)، طول مفتاح/nonce/وسم خاطئ، أو أي `ValueError` آخر
(`crypto.py:184-190`). `DecryptFailed` نفسها (`crypto.py:35-45`) موثَّقة بتعليق صريح: "Deliberately
carries no detail about *why* decryption failed... See FR-3.4." **يطابق** ادعاء
`THREAT_MODEL.md:61` حول التوحيد.

**decoy AEAD verification**: مُنفَّذة فعلياً في طبقة الخدمة وليس في `crypto.py` — الدالة
`KeyringService._decoy_aead_attempt()` (`keyring/core/service.py:400-408`) تُنفِّذ تحققاً وهمياً
(throwaway) بمفتاح ونونس عشوائيَّين لا علاقة لهما بالطلب الفعلي، تعليقها: "Perform a throwaway AEAD
verification so early-exit branches (missing envelope, revoked key) still do comparable
cryptographic work to the full unwrap+decrypt path. Reduces — does not claim to eliminate — timing
variance between failure modes." تُستدعى من ثلاث نقاط خروج مبكر داخل `decrypt()`
(`service.py:362,367,372` — ظرف غير موجود، مفتاح فرعي مُبطَل/مُدمَّر، KEK مُبطَل/مُدمَّر) قبل رفع
`DecryptFailed` — **يطابق حرفياً** ادعاء `THREAT_MODEL.md:61`.

## 5. توقيع شهادات المحو (Erasure Certificates)

توقيع **HMAC-SHA256** مستقل تماماً عن التسلسل الهرمي لمفاتيح KEK/subject — تعليق رأس
`certificate.py:1-3`: "Signed with HMAC-SHA256 under a dedicated signing key — independent of any
KEK/subject-key material — so a certificate can be verified without ever touching the crypto
hierarchy."

- مفتاح التوقيع يُقرأ مباشرة من متغيّر بيئة اسمه محدَّد في `settings.signing_key_env_var` (افتراضياً
  **`KEYRING_CERT_SIGNING_KEY`**, `config.py:48`) عبر `os.environ.get(...)` (`certificate.py:20-24`)
  — **وليس عبر `hkdf_derive` أو أي اشتقاق آخر**، رغم وجود ثابت `HKDF_INFO_CERT_SIGNING` مُعرَّف في
  `crypto.py:32` بالضبط لهذا الغرض الظاهري — هذا الثابت **غير مُستخدَم في أي مكان آخر بالكود** (تأكيد
  بحث: لا استدعاء لـ`HKDF_INFO_CERT_SIGNING` خارج تعريفه)؛ ملاحظة بنيوية مفصَّلة في `11_CHALLENGES.md`.
- التوقيع نفسه: `hmac.new(signing_key, canonical_json, hashlib.sha256).hexdigest()`
  (`certificate.py:47-49`) على تمثيل JSON قانوني (`sort_keys=True, separators=(",", ":")`) لضمان أن
  نفس المحتوى المنطقي ينتج نفس البايتات دائماً قبل التوقيع.
- التحقق (`verify_signature`, `certificate.py:52-54`) يستخدم `hmac.compare_digest` (مقارنة بزمن ثابت،
  مطابِقة لـ`constant_time_eq` في `crypto.py:222-223`) — لا مقارنة نصية مباشرة عرضة لهجمات التوقيت.

## 6. طبقات التحقق من صحة المدخلات (Input Validation)

كل جسم طلب (request body) يمر عبر مخطط **Pydantic v2** مُعرَّف في `keyring/api/schemas.py` (9
مخططات: `SessionOpenBody`, `RevokeBody`, `DestroyBody`, `ErasureBody`, `ApprovalCreateBody`,
`EncryptBody`, `DecryptBody`, `SettingsPatchBody` + أي إضافات — القائمة الكاملة موثَّقة في
`05_API.md` §2 لكل نقطة نهاية). التحقق من الأنواع والحقول المطلوبة يتم تلقائياً عبر FastAPI +
Pydantic قبل وصول الطلب لأي كود منطق أعمال — رفض تلقائي بـ HTTP 422 عند عدم التطابق (سلوك FastAPI
الافتراضي، غير مُخصَّص إضافياً في هذا المشروع).

**تحقق مستوى إضافي خاص بالعمليات المدمّرة**: تأكيد كتابي (`typedConfirmation`) يجب أن يساوي حرفياً
معرّف الهدف (`key_id` أو `subject_id`) — `ConfirmationMismatchError` (رمز 400) عند عدم التطابق
(`keys.py:106-107`, `subjects.py:79-80`) — نمط "اكتب الاسم للتأكيد" الشائع في واجهات الحذف الخطيرة.

## 7. الحماية من الثغرات الشائعة

| الثغرة | الحالة في المشروع | المصدر |
|---|---|---|
| **حقن SQL (SQL Injection)** | غير ممكن عملياً عبر المسار المفحوص — لا استعلام SQL خام (`text()`) في أي مكان؛ كل الوصول عبر SQLAlchemy ORM/Core `select()` (تأكيد بحث شامل، انظر `04_DATABASE.md` §7) | `keyring/api/*.py`, `keyring/core/service.py` |
| **XSS** | الواجهة React تُعرِّف (escape) كل نص افتراضياً (سلوك React القياسي)؛ لا استخدام لـ `dangerouslySetInnerHTML` تم رصده ضمن الفحص المُجرى — لم يُفحَص كل ملف `web/src/` سطراً بسطر لتأكيد الغياب المطلق | `[يحتاج تحققاً إضافياً]` |
| **CSRF** | لا آلية CSRF token مخصَّصة؛ الحماية الفعلية الوحيدة هي أن المصادقة عبر رأس `Authorization: Bearer` (وليس كوكي تلقائي الإرسال من المتصفح) — إن كان الرمز مخزَّناً فعلاً في الذاكرة لا في كوكي، فهجمات CSRF التقليدية (المعتمدة على إرسال الكوكي تلقائياً) غير قابلة للتطبيق بنيوياً | `main.py:67-74` (إعداد CORS) |
| **CORS** | أصول مسموحة **مُبَيَّتة (hardcoded)** في الكود مباشرة: `http://localhost:5173` و`http://127.0.0.1:5173` فقط (منفذ Vite التطويري) — لا قراءة من متغيّر بيئة، لا قائمة بيضاء قابلة للتهيئة للإنتاج | `main.py:67-74` |
| **تحديد معدل الطلبات (Rate Limiting)** | **غير موجود إطلاقاً** — لا `slowapi`، لا middleware تحديد معدّل، لا حماية من هجمات القوة الغاشمة (brute-force) على `POST /api/session` (محاولات `x-api-key` متكررة) | `[غير موجود في الكود]` |
| **Prompt Injection** | غير قابل للتطبيق — لا مكوّن AI/ML في المشروع (تأكيد بحث شامل، مذكور في المقدّمة) | لا ينطبق |
| **CSPRNG غير متاح** | فحص إقلاع صريح: `assert_csprng_available()` (`crypto.py:52-59`) يُستدعى في `lifespan()` (`main.py:50`) قبل قبول أي طلب — يرفض الإقلاع إن كان `os.urandom` غير متاح أو ناقص الطول، تنفيذاً لـ FR-1.4 | `crypto.py:52-59`, `main.py:50` |

## 8. إدارة الأسرار (Secrets Management) — أسماء المتغيّرات فقط

**تنويه إلزامي**: القائمة التالية أسماء متغيّرات البيئة **فقط**، دون أي قيمة فعلية مأخوذة من `.env`
أو `data/root.passphrase` — بحسب القاعدة الصارمة المفروضة على هذا الاستخراج.

| المتغيّر | الغرض | المصدر |
|---|---|---|
| `KEYRING_DATABASE_URL` | رابط اتصال قاعدة البيانات | `config.py:15` (`database_url`) |
| `KEYRING_PROVIDER` | مزوّد المفاتيح النشط (`file`\|`env`\|`vault`\|`kms`) | `config.py:18` |
| `KEYRING_ROOT_PASSPHRASE_FILE` | مسار ملف عبارة المرور الجذرية (مزوّد `file`) | `config.py:21` |
| `KEYRING_ROOT_SALT_FILE` | مسار ملف الملح (مزوّد `file`) | `config.py:22` |
| `KEYRING_ROOT_SECRET_ENV_VAR` | اسم المتغيّر الذي يحمل السر الجذري نفسه (مزوّد `env`؛ افتراضياً يشير إلى `KEYRING_ROOT_SECRET`) | `config.py:25` |
| `KEYRING_KEK_STORE_PATH` | مسار ملف مخزن KEK المحلي المشفَّر | `config.py:29` |
| `KEYRING_VAULT_ADDR` | عنوان خادم Vault (مزوّد `vault`) | `config.py:32` |
| `KEYRING_VAULT_TOKEN_ENV_VAR` | اسم المتغيّر الحامل لتوكن Vault | `config.py:33` |
| `KEYRING_VAULT_MOUNT` | مسار تحميل محرك Vault Transit | `config.py:34` |
| `KEYRING_KMS_ENDPOINT` | نقطة نهاية خدمة KMS (مزوّد `kms`) | `config.py:37` |
| `KEYRING_KMS_TOKEN_ENV_VAR` | اسم المتغيّر الحامل لتوكن KMS | `config.py:38` |
| `KEYRING_ARGON2_TIME_COST` / `KEYRING_ARGON2_MEMORY_COST_KIB` / `KEYRING_ARGON2_PARALLELISM` | معطيات Argon2id (افتراضياً 3 / 65536 / 4) | `config.py:41-43` |
| `KEYRING_ROTATION_INTERVAL_DAYS` / `KEYRING_ALERT_THRESHOLD_DAYS` | مهلة تدوير KEK الافتراضية وعتبة التنبيه | `config.py:45-46` |
| `KEYRING_SIGNING_KEY_ENV_VAR` | اسم المتغيّر الذي يحمل مفتاح توقيع شهادات المحو (افتراضياً يشير إلى `KEYRING_CERT_SIGNING_KEY`) | `config.py:48` |
| `KEYRING_SESSION_TTL_SECONDS` | مدة صلاحية الجلسة بالثواني (افتراضياً 3600) | `config.py:50` |

كل هذه المتغيّرات تحمل بادئة موحَّدة `KEYRING_` (`env_prefix="KEYRING_"`, `config.py:13`)، وتُقرأ من
ملف `.env` تلقائياً عند الإقلاع عبر `load_dotenv()` (`config.py:9`) بالإضافة إلى بيئة العملية.

## 9. مطابقة مباشرة إضافية لادعاءات `THREAT_MODEL.md`

| الادعاء في `THREAT_MODEL.md` | نتيجة التحقق | المصدر البرمجي |
|---|---|---|
| "No single role may both destroy a key and mutate the audit log" (سطر 58) | **مطابق** — `AuditLog` بلا أي مسار تعديل API | `rbac.py:1-6`، لا وجود لمسار PATCH/PUT على `/api/audit/*` في `05_API.md` |
| "self-approval is rejected" (سطر 58) | **مطابق** | `approvals.py:81-82`, `SelfApprovalError` |
| "Idempotency-Key required on all destructive endpoints" (سطر 62) | **مطابق جزئياً** — مطلوب على `destroy` و`erasure` فقط (النقطتان اللتان تستدعيان `run_idempotent`)، وهما فعلياً كل العمليات "المدمّرة" الوحيدة (لا يوجد "revoke" أو "rotate" بنفس المستوى من الخطورة يستخدم الآلية) | `keys.py:104,122`, `subjects.py:76,122` |
| "exactly one active KEK, enforced by a partial unique index" (سطر 103) | **مطابق** | `ux_keks_single_active`، تفصيل كامل في `04_DATABASE.md` §2.1 |
| "raw KEK bytes are never stored [in the DB]" (سطر 48) | **مطابق** — عمود `keks.provider_ref` نصي فقط (مرجع رمزي)، لا عمود `LargeBinary` للمفتاح الخام في جدول `keks` | `04_DATABASE.md` §2.1، `keys.py:21-50` |
| "decoy AEAD verification on early-exit paths" (سطر 61) | **مطابق** | `service.py:362,367,372,400-408` (`_decoy_aead_attempt`) |

## 10. ملخّص فجوات هذا الملف

- تأكيد مكان تخزين رمز الجلسة (Bearer token) في الواجهة الأمامية (ذاكرة JS فقط أم `localStorage`) —
  يحتاج قراءة مباشرة لطبقة `web/src/` الخاصة بالمصادقة، مُغطاة بعمق أكبر في `09_UI_INVENTORY.md`.
- تأكيد غياب `dangerouslySetInnerHTML` بشكل قاطع عبر كل ملفات `web/src/` — لم يُفحَص كل ملف سطراً
  بسطر ضمن نطاق هذا الملف تحديداً.
- سلوك بروتوكول اتصال مزوّدَي `vault`/`kms` الدقيق (آلية مصادقة Vault/KMS الفعلية، معالجة الأخطاء عند
  فشل الاتصال بها) — `[يحتاج قراءة مباشرة لـ keyring/providers/vault.py وkms.py]`.
