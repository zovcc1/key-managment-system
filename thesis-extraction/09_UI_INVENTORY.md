# 09 — جرد الواجهة الأمامية (UI Inventory)

## 1. نظرة عامة على البنية

الواجهة الأمامية بأكملها في `web/src/` — **21 ملف TypeScript/TSX + 3 ملفات CSS**، بمجموع
**3,347 سطراً** (تأكيد بـ`wc -l` على كل الملفات المذكورة أدناه). البنية:

```
web/src/
├── api/          client.ts (129) · endpoints.ts (167) · types.ts (227)
├── auth/         AuthContext.tsx (129)
├── components/   DestroyFlowDialog.tsx (238) · RevokeDialog.tsx (54) · RotateDialog.tsx (63) · Shell.tsx (79) · Toast.tsx (47)
├── i18n/         chrome.ts (445) · LocaleContext.tsx (44)
├── routes/       Audit.tsx (154) · Dashboard.tsx (223) · KeyMap.tsx (196) · Keys.tsx (174) · Locked.tsx (21) · Login.tsx (75) · Privacy.tsx (269) · Rewrap.tsx (141) · Settings.tsx (155)
├── styles/       global.css (32) · layout.css (164) · nocturne.css (294)
├── App.tsx (65)
└── main.tsx (9)
```

لا يوجد مجلد `hooks/` أو `store/` أو `context/` مستقل — كل الـcontexts موزَّعة داخل مجلداتها
الوظيفية (`auth/AuthContext.tsx`, `i18n/LocaleContext.tsx`, `components/Toast.tsx`).

نقطة الدخول `main.tsx` (`main.tsx:6-9`) تُركِّب `<App />` داخل `<StrictMode>` عبر
`createRoot(document.getElementById("root")!)`، وتستورد `styles/global.css` كورقة الأنماط
العمومية الوحيدة المُحمَّلة صراحةً عند الإقلاع.

## 2. نمط التوجيه (Routing)

`react-router-dom@^7.18.2` عبر **`HashRouter`** (`App.tsx:57`، وليس `BrowserRouter`) — خيار
متعمَّد لأن الواجهة تُقدَّم كملفات ثابتة (static) من نفس أصل الخادم عبر `app.mount("/",
StaticFiles(...))` في `keyring/main.py:126-128` (موثَّق في `05_API.md`)، فلا حاجة لضبط خادم
لإعادة توجيه كل المسارات إلى `index.html`.

بنية الحراسة (guards) في `App.tsx`:

- **`RequireSession`** (`App.tsx:17-22`): يغلّف كل المسارات الداخلية؛ يحوّل إلى `/locked` إذا
  كانت `status === "locked"`، وإلى `/login` إذا كانت `status === "anonymous"`.
- توجيه `/login` (`App.tsx:28`) نفسه يُعيد التوجيه فوراً إلى `/dashboard` إن كانت الحالة
  `authenticated` أصلاً — يمنع عرض نموذج الدخول لجلسة مفتوحة بالفعل.
- توجيه `/locked` (`App.tsx:29`) يُعيد التوجيه إلى `/login` إن لم تكن الحالة `locked` فعلاً —
  يمنع الوصول المباشر لشاشة القفل بكتابة الرابط يدوياً.
- مسار شامل (catch-all) `*` (`App.tsx:47`) يُعيد أي رابط غير معروف إلى `/dashboard`.
- شجرة المسارات المحمية مُتداخلة تحت عنصر `<Shell />` واحد (`App.tsx:30-46`) عبر `<Outlet />`
  (مُعرَّف داخل `Shell.tsx`)، فكل الشاشات الداخلية تشترك نفس الشريط الجانبي/الترويسة.

## 3. جدول المسارات/الشاشات (9 شاشات)

| المسار (URL) | الملف | الأسطر | الوصف |
|---|---|---|---|
| `/login` | `routes/Login.tsx` | 75 | نموذج دخول: مفتاح API + اختيار مزوّد المفاتيح (`file`/`env`/`vault`/`kms` من ثابتة `PROVIDERS`، `Login.tsx:7`) — الاختيار فعّال فقط عند أول فتح جلسة (المزوّد عملية-عامة singleton، انظر `06_SECURITY.md`) |
| `/locked` | `routes/Locked.tsx` | 21 | شاشة قفل بسيطة بلا أي حالة داخلية؛ زر واحد "إعادة المصادقة" يوجّه إلى `/login` — **لا يوجد فك قفل وهمي** كما في نموذج التصميم `ui/`؛ توثيق هذا القرار المتعمَّد داخل تعليق `AuthContext.tsx:6-14` |
| `/dashboard` | `routes/Dashboard.tsx` | 223 | نظرة عامة على العمليات: نقاط حالة (status dots) لـKEK النشط والمزوّد (`statusDot()` تُصنِّف `ok`/`warn`/`bad`)، رسم بياني صغير (`Sparkline`) لفشل فك التشفير عبر الزمن من `getDecryptFailures`، بطاقة بحث/موافقة على طلبات الموافقة (`getApproval`/`approveApproval`)، وزر تدوير KEK يفتح `RotateDialog` |
| `/map` | `routes/KeyMap.tsx` | 196 | خريطة بصرية للعلاقات بين KEKs ومفاتيح المواضيع (subject keys) عبر `getGraph`/`getDownstream`؛ دالة `layout()` محلية (`KeyMap.tsx`) تحسب إحداثيات `x/y` يدوياً بلا مكتبة رسم بياني خارجية؛ يفتح `RotateDialog` و`DestroyFlowDialog` من نفس الشاشة |
| `/keys` | `routes/Keys.tsx` | 174 | جدول قابل للفرز والتصفية لكل المفاتيح (KEK + subject key) عبر `listKeys` بمعاملات `type/state/q/sort/dir/page/pageSize`؛ يفتح `RotateDialog`/`RevokeDialog`/`DestroyFlowDialog` لكل صف |
| `/rewrap` | `routes/Rewrap.tsx` | 141 | مراقبة مهمة rewrap الحالية (`currentRewrapJob`)، إيقاف/استئناف (`pauseRewrapJob`/`resumeRewrapJob`)، وقائمة فشل (failures) قابلة لإعادة المحاولة عبر `retryRewrapFailure` |
| `/privacy` | `routes/Privacy.tsx` | 269 | "مركز الخصوصية": بحث عن موضوع (subject) بمعرِّفه (افتراضياً `DEMO_SUBJECT_ID = "demo-subject-0001"`)، عرض ملخص حقول (`getFieldDigest`)، عرض/تصدير شهادة محو (`getCertificate`/`exportCertificate` بصيغة `json`/`pdf` عبر تنزيل Blob يدوي)، تشغيل تدفق المحو (erasure) عبر `DestroyFlowDialog` بوضع `mode="erasure"`، والتحقق من عدم قابلية القراءة (`verifyUnreadable`) |
| `/audit` | `routes/Audit.tsx` | 154 | سجل تدقيق مُصفَّى (فاعل/عملية/مفتاح/تاريخ من–إلى) عبر `listAudit` مع تصفح بمؤشر (cursor)، قوائم منسدلة `listActors`/`listOperations`، زر التحقق من سلسلة الهاش (`verifyAuditChain`)، وتصدير CSV (`exportAuditCsv`) |
| `/settings` | `routes/Settings.tsx` | 155 | إعدادات الدوران والتنبيه (`getSettings`/`patchSettings`: `rotationIntervalDays`, `alertThreshold`)، قائمة مزوّدي المفاتيح وتفعيلهم (`listProviders`/`activateProvider`)، تشغيل مهمة التحقق من النسخ الاحتياطي (`startBackupVerify`/`getBackupJob`)، وعرض نموذج التهديد (`getThreatModel`) |

المسار الجذر `/` يُعاد توجيهه فوراً إلى `/dashboard` (`App.tsx:38`) — لا صفحة هبوط (landing page)
مستقلة.

## 4. المكوّنات القابلة لإعادة الاستخدام (5)

| المكوّن | الأسطر | الغرض |
|---|---|---|
| `Shell.tsx` | 79 | الإطار الثابت لكل الشاشات الداخلية: شريط تنقّل جانبي مبني من ثابتة `NAV` (7 عناصر تطابق المسارات السبعة الداخلية، `Shell.tsx:6-13`)، عدّاد تنازلي لانتهاء الجلسة (`formatCountdown`)، وزر قفل يدوي؛ يستضيف `<Outlet />` لعرض الشاشة النشطة |
| `Toast.tsx` | 47 | نظام إشعارات عائم بسيط (`ToastProvider`/`useToast`)؛ كل إشعار له `tone: "default" \| "danger"`؛ حالة داخلية `items: ToastItem[]` وعدّاد `nextId` عبر `useRef` |
| `RotateDialog.tsx` | 63 | حوار تدوير KEK: يعرض معاينة (`rotatePreview`) قبل التنفيذ الفعلي (`rotateKek`) — نمط "معاينة ثم تنفيذ" مطابق لواجهة الخادم `POST /keks/{id}/rotate/preview` ثم `POST /keks/{id}/rotate` |
| `RevokeDialog.tsx` | 54 | حوار إلغاء (revoke) بخطوة تأكيد واحدة فقط — أخف من تدفق الحذف/المحو لأن الإلغاء **قابل للعكس منطقياً** (يوقف القراءات لكن لا يدمّر المفتاح)، بخلاف `destroy`/`erasure`؛ التمييز موثَّق صراحة في تعليق `RevokeDialog.tsx:13-14` |
| `DestroyFlowDialog.tsx` | 238 | الحوار الأهم في الواجهة: تدفق مشترك من 4 خطوات (`type Step = 1 \| 2 \| 3 \| 4`, `DestroyFlowDialog.tsx:19`) يُستخدَم لكل من حذف مفتاح (`mode="key"`) ومحو موضوع (`mode="erasure"`): (1) نصف قطر الانفجار (blast radius) عبر `getBlastRadius` أو `knownBlastRadius` مُمرَّرة مسبقاً لحالة erasure، (2) تأكيد مكتوب حرفياً (typed confirmation)، (3) طلب موافقة طرف ثانٍ حقيقي عبر `POST /api/approvals` ثم استطلاع (polling) `GET /api/approvals/{id}` — **لا يوجد تجاوز محلي (fake approve checkbox) كما في نموذج التصميم**، موثَّق صراحة في تعليق `DestroyFlowDialog.tsx:21-27`، (4) التنفيذ الفعلي (`destroyKey` أو `requestErasure`) بمفتاح idempotency تلقائي |

## 5. إدارة الحالة (State Management)

**لا توجد مكتبة إدارة حالة خارجية** — لا Redux، لا Zustand، لا Jotai، لا React Query/TanStack
Query، لا SWR (تأكيد بغياب أي منها من `dependencies`/`devDependencies` في `web/package.json`).
النمط المستخدَم هو **React Context اليدوي + `useState`/`useEffect` محليين لكل شاشة**، على ثلاثة
مستويات:

1. **`AuthContext.tsx`** (129 سطراً) — الحالة الأكثر أهمية في التطبيق. تُدير: `status` (`"anonymous"
   | "authenticated" | "locked"`)، هوية العامل (`operator`, `role`, `scopes`)، ومؤقّت العدّ التنازلي
   لانتهاء الجلسة (`msUntilLock`, `AuthContext.tsx:89-106`) المبني على `state.expiresAt` القادم من
   الخادم مع `window.setInterval` كل ثانية. **ملاحظة تصميم موثَّقة صراحة في الكود** (`AuthContext.tsx:6-14`):
   نموذج التصميم `ui/` يوفّر زر "إعادة فتح مزوّد المفاتيح" فوري بلا مصادقة عند القفل؛ التطبيق الحقيقي
   لا يملك هذا لأن `DELETE /api/session` أحادي الاتجاه (`keyring/api/session.py`) — الجلسة تموت نهائياً،
   فـ"القفل" هنا يعني دائماً "عد إلى شاشة الدخول وافتح جلسة جديدة بالكامل"، لا فك قفل مزيَّف. هذا خروج
   متعمَّد عن النموذج البصري لمطابقة دلالات الجلسة أحادية الاتجاه الفعلية في الخادم.
2. **`LocaleContext.tsx`** (44 سطراً) — `locale` (`"en" | "ar"`)، `dir` (`"ltr" | "rtl"`) المُشتقّة
   منه، ودالة الترجمة `t(key, params?)` المُغلِّفة حول `tc()` من `i18n/chrome.ts`؛ عند تغيّر `locale`
   يُحدَّث `document.documentElement.lang`/`dir` مباشرة (`LocaleContext.tsx:18-21`) لدفع RTL على مستوى
   المستند كله.
3. **`Toast.tsx`** — قائمة إشعارات عابرة محلية للجلسة، بلا أي اتصال بالخادم.

كل شاشة توجيه (route) تحمل حالتها الخاصة (بيانات مجلوبة، أعلام تحميل/إرسال `busy`، رسائل خطأ) محلياً
عبر `useState`/`useEffect` دون رفعها لأي مخزن عام — نمط "شاشة تجلب بياناتها بنفسها عند التركيب" مكرر
في كل الملفات التسعة (`Dashboard.tsx`, `KeyMap.tsx`, `Keys.tsx`, `Rewrap.tsx`, `Privacy.tsx`,
`Audit.tsx`, `Settings.tsx`)، بلا طبقة تخزين مؤقت (cache) أو إعادة تحقق (revalidation) مشتركة — كل
عملية "تحديث" هي إعادة جلب كاملة يدوية.

## 6. طبقة الاتصال بالـ API

ثلاثة ملفات في `web/src/api/`:

- **`client.ts`** (129 سطراً): غلاف `fetch` رفيع. أهم قراراته موثَّقة في تعليق رأس الملف
  (`client.ts:1-16`): رمز الجلسة (session token) يُحفَظ في **متغيّر وحدة نمطية (module-level) في
  الذاكرة فقط** (`_token`, `client.ts:23`) — **ليس** `localStorage`/`sessionStorage` — لأنه بيانات
  اعتماد حامل (bearer credential) لا ينبغي أن تنجو من إغلاق التبويب؛ اللغة (`Accept-Language`)
  تُرسَل مع كل طلب لتقود كتالوج الترجمة الثنائي على الخادم مباشرة بلا إعادة تطبيق للترجمة على العميل؛
  ترويسة `Idempotency-Key` تُولَّد تلقائياً (`crypto.randomUUID()`, `client.ts:57-59`) لأي طلب POST
  مدمِّر (`{idempotent: true}`)؛ كل استجابة غير 2xx تُطبَّع إلى `ApiError` موحَّد يحمل `{code, status,
  message, details}` مباشرة من مغلَّف الخطأ الذي يبنيه الخادم.
- **`endpoints.ts`** (167 سطراً): دالة واحدة لكل نقطة نهاية HTTP تقريباً، مُجمَّعة بتعليقات أقسام
  (`// ---- session ----` إلخ) بنفس ترتيب موجّهات `keyring/api/*.py`. **نقطتان معرَّفتان وغير
  مُستدعاتين من أي شاشة**: `sessionStatus` (`endpoints.ts:41`، يستدعي `GET /api/session`) و
  `ackAlert` (`endpoints.ts:48`، يستدعي `POST /api/alerts/{alertId}/ack`) — تأكيد مباشر بالبحث عن
  كل استدعاء لهما في `routes/` و`components/`: صفر نتائج لكليهما. الباقي كله مُستدعًى فعلياً من شاشة
  أو مكوّن واحد على الأقل (تأكيد مباشر لكل دالة).
- **`types.ts`** (227 سطراً): كل الأنواع (`interface`/`type`) لأجسام الطلب والاستجابة، معلَّقة صراحة
  في رأس الملف (`types.ts:1-3`) بأنها "منعكسة من `keyring/api/serializers.py`... أسماء الحقول هي
  بالضبط ما يُصدره الخادم (camelCase) — بلا طبقة إعادة تسمية"، أي لا يوجد تحويل `snake_case`↔
  `camelCase` مستقل على العميل؛ الخادم نفسه يُصدر `camelCase` مباشرة.

## 7. طريقة التشغيل في وضع التطوير — ملاحظة تناقض موثَّقة

`web/vite.config.ts` يوكِّل (proxy) كل طلبات `/api` إلى `http://127.0.0.1:8010` (`vite.config.ts:14`)،
مع تعليق يشرح أن هذا يُغني عن ضبط CORS في وضع التطوير لأن العميل يرسل مسارات نسبية فقط. لكن تعليق
الشرح نفسه يقول "uvicorn runs on 8000 by default (see README)" بينما رقم المنفذ الفعلي في `proxy.target`
هو **8010**، وأمر التشغيل الموثَّق في `README.md` (`uvicorn keyring.main:app --reload`) لا يمرّر أي
راية `--port` فيبقى على المنفذ الافتراضي لـuvicorn وهو 8000. أي أن تشغيل الخادم حرفياً كما في
`README.md` مع تشغيل `npm run dev` كما هو **لن يعمل معاً بدون تدخّل يدوي** (تمرير `--port 8010`
صراحة أو تعديل `vite.config.ts`) — هذا تناقض توثيقي فعلي بين ملفين، لا افتراضاً. تفصيل إضافي في
`11_CHALLENGES.md`.

سكربتات `web/package.json`: `dev` → `vite`، `build` → `tsc -b && vite build` (فحص أنواع كامل قبل
البناء)، `lint` → `oxlint` (وليس ESLint)، `preview` → `vite preview`.

## 8. نظام التصميم Nocturne

مصدر الحقيقة الوحيد: `web/src/styles/nocturne.css` (294 سطراً)، مع تعليق رأس صريح
(`nocturne.css:1`): "هذا الملف هو مصدر الحقيقة لمظهر النظام". نمط داكن (dark-only) بلا مبدِّل
فاتح/داكن — لا متغيّر `prefers-color-scheme` ولا وضع مزدوج في الكود.

**ألوان الأساس** (`nocturne.css:5-17`):

| المتغيّر | القيمة | الاستخدام |
|---|---|---|
| `--color-bg` | `#161826` | خلفية الصفحة |
| `--color-surface` | `#232532` | خلفية البطاقات/الألواح |
| `--color-text` | `#e9e9ed` | نص أساسي |
| `--color-accent` | `#9184d9` | لون التمييز الأساسي (بنفسجي "blurple")، مع تعليق مطوَّل يوثِّق قرار تصميم صريح: تحويل اللون من رمادي فولاذي إلى "blurple" المنتج نفسه بمعادلات OKLCH دقيقة (`nocturne.css:8-14`) |
| `--color-accent-2` | `#a7a1db` | لون تمييز ثانوي مُشتقّ آلياً من نفس الصبغة (hue) |
| `--color-divider` | `color-mix(in srgb, #e9e9ed 16%, transparent)` | فواصل خفيفة شبه-شفافة |

**تدرّجات نغمية** (`nocturne.css:21-49`): مقياسان من 9 درجات لكل من `neutral` و`accent`/`accent-2`
(100→900)، مُولَّدة في فضاء OKLCH على درجة إضاءة (lightness) مشتركة كي تتطابق القيمة البصرية لنفس
الخطوة عبر كل الأدوار — موثَّق صراحة في تعليق `nocturne.css:19-20`.

**لا توجد ألوان دلالية منفصلة** (لا `--color-success`/`--color-danger`/`--color-warn` كمتغيّرات CSS
مُسمّاة) — حالات النجاح/التحذير/الخطأ في الشاشات (مثل `statusDot()` في `Dashboard.tsx`) تُبنى بفئات
CSS يدوية (`kr-dot-ok`/`kr-dot-warn`/`kr-dot-bad`) وليس عبر توكِنات تصميم مركزية.

**الخط**: `Inter` حصرياً لكل من العناوين والنص (`--font-heading`/`--font-body`, `nocturne.css:61-63`)،
مستورَد من Google Fonts (`nocturne.css:2`) — لا خط عربي مخصَّص منفصل رغم دعم RTL الكامل.

**المسافات والزوايا**: مقياس مسافات `--space-1..8` من 2.8px إلى 22.4px (`nocturne.css:65-70`)،
وزوايا `--radius-sm/md/lg` من 4px إلى 14px (`nocturne.css:72-74`).

`layout.css` (164 سطراً) و`global.css` (32 سطراً) يكمِّلان `nocturne.css` بترتيب الصفحة (grid/flex)
والتصفير العمومي (reset)، على التوالي.

## 9. التعريب والاتجاه (i18n/RTL) على الواجهة

كتالوجان منفصلان تماماً، بلا اشتراك في المفاتيح ولا مصدر موحَّد:

| الكتالوج | الملف | عدد المفاتيح لكل لغة | الغرض |
|---|---|---|---|
| كتالوج الواجهة (chrome) | `web/src/i18n/chrome.ts` | **193** (تأكيد بعدّ الأسطر المطابقة لنمط مفتاح داخل كائن `en`) | نصوص التنقّل، العناوين، تسميات الحقول، نصوص الحوارات — كل ما يرسمه العميل نفسه ولا يعبر حدود الـAPI أبداً (موثَّق صراحة `chrome.ts:1-7`) |
| كتالوج الخادم | `keyring/i18n/en.json` / `ar.json` | **46** | رسائل الأخطاء، عناوين تصدير CSV، ونص صفحة نموذج التهديد — تُترجَم على الخادم وتُعرَض على العميل حرفياً بلا إعادة ترجمة (تفصيل كامل في `06_SECURITY.md`/`05_API.md`) |

الرقمان (193 مقابل 46) مختلفان تماماً ولا يجب الخلط بينهما في الأطروحة — أحدهما نصوص واجهة ثابتة
والآخر رسائل ديناميكية من الخادم.

آلية التبديل: `getLocale()`/`setLocale()` في `client.ts:34-41` تحفظ الاختيار في `localStorage`
تحت مفتاح `"kr.locale"` (وهو الاستثناء الوحيد لاستخدام `localStorage` في التطبيق — يخزَّن تفضيل
لغة، لا بيانات اعتماد). دالة الترجمة `tc(locale, key, params?)` (`chrome.ts:437-444`) تدعم استبدال
معاملات بصيغة `{param}` داخل النص، مع سقوط احتياطي (fallback) إلى الإنجليزية ثم إلى المفتاح الخام
نفسه إن غاب المفتاح من كلا الكتالوجين (`chrome.ts:438`).

الاتجاه (`dir`) يُشتقّ حصراً من اللغة: `ar` → `rtl`، أي لغة أخرى → `ltr` (`LocaleContext.tsx:16`)؛
يُطبَّق فوراً على `<html lang>`/`<html dir>` عبر `useEffect` عند كل تغيير locale.

## 10. قائمة لقطات شاشة مقترحة للأطروحة

للتوثيق البصري في الأطروحة، الشاشات الأكثر تمثيلاً لعمق النظام (بالأولوية):

1. `/dashboard` — نظرة عامة شاملة (حالة KEK، رسم بياني فشل، بطاقة موافقات)
2. `DestroyFlowDialog` في خطوته الثالثة (طلب موافقة الطرف الثاني) — يُظهر آلية منع الموافقة الذاتية بصرياً
3. `/map` — الرسم البصري لعلاقات KEK↔subject key (`layout()` اليدوي)
4. `/privacy` — عرض شهادة محو مُصدَّرة (JSON/PDF)
5. `/audit` — سجل التدقيق مع نتيجة `verifyAuditChain` (سلسلة الهاش)
6. `/rewrap` — مهمة rewrap قيد التقدّم مع قائمة فشل قابلة لإعادة المحاولة
7. شاشة `/login` وشاشة `/locked` جنباً إلى جنب — لإظهار قرار "لا فك قفل وهمي"
8. نفس الشاشة الرئيسية بلغتين (`en`/`ar`) جنباً إلى جنب — لإظهار دعم RTL الكامل
