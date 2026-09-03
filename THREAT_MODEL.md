# Keyring — Threat Model

This document is the canonical threat model for the Keyring key-management
and crypto-shredding service. The English-language summary at the bottom of
each section under **In Scope** / **Out of Scope** is served verbatim by
`GET /api/threat-model` (localized to `en`/`ar` via `Accept-Language`) — this
file is the full version; the endpoint returns the same title, scope
statement, boundary list, and closing statement as machine-readable JSON for
clients that want to surface it in-product.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Root secret | Outside the app DB entirely — a provider-specific secret (passphrase file, env var, Vault/KMS-held key) | Compromise unwraps every KEK, and transitively every subject key and every record |
| KEKs (Key Encryption Keys) | Raw bytes never touch the app DB; only an opaque `provider_ref` handle does (FR-6.1) | Compromise of one KEK exposes every subject key it wraps, until rotated away from |
| Subject keys (DEK-wrapping keys) | Wrapped (AES-256-GCM) under a KEK, stored in the app DB as `wrapped_key` | Compromise exposes every record for that one subject; destruction of this row is the entire crypto-shredding mechanism |
| DEKs (Data Encryption Keys) | Single-use per record, wrapped under the subject key, stored inline in the `Envelope` row (or, for uploaded files, `b""` — see the blob store row below), never persisted unwrapped | Compromise exposes exactly one record |
| File ciphertext blobs | Framed AEAD ciphertext for uploaded files, on the filesystem at `KEYRING_BLOB_STORE_PATH`, addressed by a UUID (`Envelope.blob_ref`) — the DB keeps the envelope metadata (wrapped DEK, nonces), not the ciphertext bytes | Same exposure as any other ciphertext (worthless without the DEK chain above it), but see the backup-drift note in §5 — this is the one asset that lives *outside* the database |
| Plaintext | Held in process memory only for the duration of one encrypt/decrypt call; zeroized (best-effort) immediately after | The thing everything above exists to protect |
| Audit log | Hash-chained, append-only, in the app DB | Tamper-evidence for who did what; not itself secret, but its integrity is a security property |

## 2. Trust boundaries

```
 operator/service client
        │  (Bearer session token, X-Api-Key at session-open)
        ▼
 ┌─────────────────────────────┐
 │   Keyring API (FastAPI)     │  ← RBAC (3 roles) + two-party approval enforced here
 │   ┌───────────────────────┐ │
 │   │  KeyringService        │ │  ← only layer that ever holds raw key material
 │   └───────────────────────┘ │
 └───────────┬─────────────────┘
             │ provider_ref (opaque handle)
             ▼
 ┌─────────────────────────────┐
 │   KeyProvider (file/env/    │  ← swappable; the only code that unwraps a KEK
 │   vault/kms)                │
 └───────────┬─────────────────┘
             │
             ▼
     Root secret material
 (0400 file / env var / Vault / KMS)
```

The application database is **not** a trust boundary for KEK material — it
is designed to be safely dumped, backed up, or read by a DBA without
exposing any key capable of decrypting a record, because raw KEK bytes are
never stored there (FR-6.1). It *is* a trust boundary for subject keys and
DEKs, both of which are only ever present wrapped.

## 3. Adversary model — what Keyring defends against

| Adversary capability | Defense |
|---|---|
| Full read access to the application database (backup theft, SQL injection, misconfigured replica) | No raw key material is ever stored there — every key at rest is wrapped by the layer above it, up to the KEK, which is stored outside the DB by the provider (FR-6.1). A DB dump alone decrypts nothing. |
| Tampering with historical records in the DB (an attacker with write access, or a rogue insider with DB credentials) | Hash-chained audit log (FR-8.3/8.4) makes any single-entry edit detectable and pinpoints the first broken entry; AAD binds each envelope to its exact logical location (table/column/record/subject), so relocating ciphertext between records breaks decryption rather than silently succeeding (FR-3.2). |
| A single compromised or malicious operator credential | RBAC (FR-9): no single role can both destroy a key and mutate the audit log. Destructive operations (destroy, erasure) additionally require a second, different key-admin's approval (FR-9.3) — one compromised credential cannot unilaterally destroy key material or approve its own request (self-approval is rejected). |
| A subject whose data must be permanently, provably unrecoverable on request (GDPR/CCPA-style erasure) | Crypto-shredding (section 3 of the build spec): destroying a subject key's wrapping metadata renders every envelope under it permanently unreadable — the ciphertext is deliberately left in place as its own unreadability proof, verifiable via `POST /api/subjects/{id}/verify-unreadable` and recorded in a signed erasure certificate. |
| Nonce/key reuse from an implementation bug | Structural: every DEK is single-use by construction, and a defensive in-process nonce-reuse guard raises rather than silently encrypting on any (key, nonce) collision. |
| Timing side-channels distinguishing *why* a decrypt failed | Every decrypt failure mode (bad tag, tampered ciphertext, wrong key, mismatched AAD, missing envelope, revoked/destroyed key) returns the byte-identical `DECRYPT_FAILED` response and performs a decoy AEAD verification on early-exit paths to reduce (not eliminate) timing variance (FR-3.4). |
| A destructive operation retried by a flaky client (double-submit, network retry) | Idempotency-Key required on all destructive endpoints; replays return the original recorded result without re-executing. |
| A KEK suspected of compromise | Resumable rotation (FR-5): a new KEK is activated atomically, and a background job rewraps every dependent subject key in the background, without any window where encrypt/decrypt is unavailable, and without needing to touch the DEKs or plaintext at all (rewrap only re-wraps subject keys, one KEK-decrypt/re-encrypt each — DEKs and ciphertext are untouched). |

## 4. Out of scope — what Keyring does **not** protect against

This is the exact content served by `GET /api/threat-model`:

> Keyring protects data at rest against database and backup compromise, and
> enforces per-subject crypto-shredding. It does not, by itself, protect
> against the following.

- **Live server compromise** with keys resident in process memory at the
  time of compromise. Keyring reduces the in-memory exposure window
  (immediate best-effort zeroization after use) but cannot protect against
  an attacker who can read the live process's memory at the exact moment a
  key is unwrapped.
- **Application authorization bugs** in systems that call this API with
  valid credentials. Keyring enforces its own RBAC and approval rules on
  every request it receives; it has no visibility into whether the caller
  itself should have been allowed to act on a given subject's behalf.
- **A root-level administrator** on the host, database, or provider
  backend. Anyone with root on the machine running the provider (or admin
  on the KMS/Vault instance backing it) can, by definition, reach the root
  secret.
- **A compromised client application** holding valid operator credentials.
  Session tokens and API keys are bearer credentials; a compromised client
  can act with whatever scope that operator's role grants until the
  session expires or is locked.
- **Plaintext already exported** to spreadsheets, analytics pipelines,
  email, or logs before a destroy or erasure operation. Crypto-shredding
  makes the *system of record* unreadable; it cannot reach into downstream
  copies it was never told about.

> Documenting this boundary is part of the design, not an appendix to it. A
> system marketed as comprehensive protection generates false confidence
> more dangerous than no encryption.

## 5. Residual risk notes

- **SQLite vs PostgreSQL**: the schema is written to be portable to both,
  but SQLite's process-wide write lock means the concurrent-activation
  invariant (exactly one active KEK, enforced by a partial unique index) is
  exercised far more conservatively under SQLite than under PostgreSQL's
  MVCC. Production deployments should run PostgreSQL; SQLite is a
  development/test convenience only.
- **Best-effort memory zeroization**: CPython gives no hard guarantee that
  `zeroize()` removes every copy of a buffer's contents (string interning,
  garbage collection timing, and OS-level swap are all outside the
  interpreter's control). This narrows the exposure window; it does not
  eliminate it — consistent with the "live server compromise" boundary
  above.
- **Provider trust**: swapping in a KMS/Vault provider moves — but does not
  remove — the root-secret trust boundary to that backend's own operators
  and access controls.
- **`file` provider on Windows**: the `0400`-only guarantee (readable by
  owner alone) has no NTFS equivalent — `os.stat` there exposes only a
  single read-only attribute, not the POSIX owner/group/other model. On
  Windows the check degrades to "not writable," which does not distinguish
  the file's owner from every other account on the machine. Treat `file` on
  Windows as a development-only configuration; use `env`, `vault`, or `kms`
  for anything production.
- **`super-admin` role is a deliberate, documented break of FR-9**: the
  three production roles are structurally kept from ever holding both
  `destroy` and `audit_read` (§3, "a single compromised or malicious
  operator credential"); `super-admin` (seeded as `Root`, dev/demo only)
  holds every scope at once, specifically to remove that separation for
  local convenience. A credential with this role compromised is equivalent
  to compromising a key-admin and an auditor simultaneously — it can
  destroy key material and cover its tracks in the audit log's *read* path
  (the audit log itself is still append-only and hash-chained regardless of
  who reads it, so tampering is still detectable, but the FR-9 guarantee
  that no single role can even attempt both is gone). Do not provision this
  role outside local dev/demo environments.
- **File blob store breaks the single-source-of-truth erasure proof**: every
  other asset in this system lives in the application database, so "restore
  the DB, the ciphertext and the key metadata are consistent with each
  other" always holds. Uploaded-file ciphertext (`keyring/core/blobstore.py`)
  is the one exception — it lives on the filesystem, written before the DB
  commit (temp-file + fsync + atomic rename, but still not transactional
  with it). A `keyring.db` restored from one backup point paired with a
  `data/blobs/` directory from a different one can drift: a missing blob
  looks byte-for-byte identical, at the decrypt layer, to a correctly
  crypto-shredded one — `decrypt_stream` raises the same `DECRYPT_FAILED`
  either way, by design (FR-3.4's uniform-failure guarantee doesn't carve
  out an exception for "the file is just missing"). The mitigation is
  visibility, not prevention: every file-read endpoint (`GET
  /api/files/{id}/key-tree`, `GET /api/files/{id}/ciphertext-preview`)
  separately reports `blobPresent`, so an operator can tell "shredded" apart
  from "backup drift" without that distinction ever leaking through the
  decrypt path itself. Back up `data/blobs/` and `keyring.db` together, on
  the same schedule, as a single unit.
