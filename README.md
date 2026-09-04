# Keyring API

A production-grade key-management / crypto-shredding backend: envelope
encryption with per-item single-use DEKs, resumable KEK rotation with
background rewrap, right-to-erasure via crypto-shredding with signed
certificates, hash-chained audit log, RBAC with two-party approval for
destructive operations, Shamir-backed root secret recovery, four pluggable
key providers, and full English/Arabic localization.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the trust boundaries and
adversary model this system is designed against.

## Quick start

No manual setup needed — pick your OS and run the one script. It creates a
virtualenv, installs dependencies, applies database migrations, builds the
console if needed, and starts the server.

**Windows** — double-click `run-windows.bat`, or from `cmd.exe`:

```bat
run-windows.bat
```

If Windows Defender blocks it, see
[Troubleshooting](#troubleshooting) below — it's SmartScreen, not a real
detection.

**Linux / macOS**:

```bash
./run.sh
```

Then open **http://127.0.0.1:8010** and sign in with API key
`demo-super-admin-root-0e77` (Root, all scopes — see
[Demo credentials](#demo-credentials--seed-data) for the other four, restricted
production-role keys). Re-running the script is safe — every step is idempotent.

## Requirements

- **Python 3.11+** (verified against 3.14). No database server needed —
  SQLite is the default and `keyring.db` ships pre-migrated and seeded.
- **Node 22 LTS+** — only if you need to rebuild the console. The built
  console is already committed at `web/dist/`, so a fresh checkout runs with
  no Node install at all. (Vite 8 / `@types/node` 24 need Node 20.19+ or
  22.12+ if you do rebuild.)

## Manual setup

If you'd rather not use the launcher script, or want to see what it does:

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"        # the [dev] extra is required, not optional —
                                # httpx and friends are imported at runtime
chmod 0400 data/root.passphrase data/root.salt   # git doesn't preserve modes
alembic upgrade head
uvicorn keyring.main:app --port 8010 --reload
```

**Windows** (PowerShell or `cmd.exe`)

```bat
py -3 -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
attrib +R data\root.passphrase data\root.salt
alembic upgrade head
uvicorn keyring.main:app --port 8010 --reload
```

To populate a fresh, empty database with a realistic demo dataset:

```bash
python -m keyring.seed          # .venv\Scripts\python.exe -m keyring.seed on Windows
```

## Configuration

Copy `.env` (already present with dev-safe defaults) or set the
`KEYRING_*` environment variables yourself. Everything is read by
`keyring/config.py`; the meaningful ones:

| Variable | Purpose | Default |
|---|---|---|
| `KEYRING_DATABASE_URL` | SQLAlchemy URL | `sqlite:///./keyring.db` |
| `KEYRING_PROVIDER` | Active key provider: `file`\|`env`\|`vault`\|`kms` | `file` |
| `KEYRING_ROOT_PASSPHRASE_FILE` | Passphrase file for the `file` provider (must be read-only — mode `0400` on POSIX) | `./data/root.passphrase` |
| `KEYRING_ROOT_SALT_FILE` | Argon2id salt file for the `file` provider | `./data/root.salt` |
| `KEYRING_ROOT_SECRET_ENV_VAR` | Name of the env var holding the hex root secret for the `env` provider | `KEYRING_ROOT_SECRET` |
| `KEYRING_KEK_STORE_PATH` | Local AES-256-GCM-wrapped KEK material store (outside the DB) | `./data/kek_store.enc.json` |
| `KEYRING_BLOB_STORE_PATH` | Framed ciphertext for uploaded files (Files section) — envelope metadata still lives in the DB, only the ciphertext bytes live here | `./data/blobs` |
| `KEYRING_VAULT_ADDR` / `KEYRING_VAULT_TOKEN_ENV_VAR` / `KEYRING_VAULT_MOUNT` | Vault transit-engine provider | — |
| `KEYRING_KMS_ENDPOINT` / `KEYRING_KMS_TOKEN_ENV_VAR` | Generic envelope-encryption KMS provider | — |
| `KEYRING_CERT_SIGNING_KEY` | HMAC key signing erasure certificates | (dev-only default in `.env`) |
| `KEYRING_ROTATION_INTERVAL_DAYS` / `KEYRING_ALERT_THRESHOLD_DAYS` | Dashboard rotation health thresholds | `90` / `100` |

## Demo credentials & seed data

`keyring.seed` (already applied to the committed `keyring.db`) creates four
operator API keys (`X-Api-Key` header on `POST /api/session`):

| Operator | Role | API key |
|---|---|---|
| Alice | key-admin | `demo-key-admin-alice-9f2a` |
| Bob | key-admin | `demo-key-admin-bob-7c31` |
| Carol | auditor | `demo-auditor-carol-1e88` |
| Dan | operator | `demo-operator-dan-4b60` |
| Root | super-admin (dev-only, all scopes) | `demo-super-admin-root-0e77` |

Root's `super-admin` role holds every scope at once, including both
`destroy` and `audit_read` — the one combination the RBAC model otherwise
never allows a single role to hold (see FR-9 in
[`THREAT_MODEL.md`](THREAT_MODEL.md)). It exists so a local operator can
reach every screen without juggling four credentials; it is not part of the
production RBAC model and should not be provisioned outside local dev/demo
use.

It also leaves a deliberately-corrupted audit entry (for `POST
/api/audit/verify`), a KEK mid-rotation with a partially-advanced rewrap job
(the background worker in `keyring.main` finishes it once a session has
opened a provider connection), and a `demo-subject-0001` subject with
records across five tables reserved for an end-to-end erasure walkthrough —
including two demo files in the **Files** section (see below), so the same
erasure makes them visibly unreadable too.

### Files section

Upload a file (`file_write` scope — operators only) and it's streamed
through the same envelope-encryption path as everything else
(`KeyringService.encrypt_stream`), framed and written to
`KEYRING_BLOB_STORE_PATH` rather than the database — the envelope row keeps
only the wrapped DEK and nonces. Selecting a file (`file_read` scope —
operators and auditors) shows its ciphertext as stored (hex, never
plaintext) and its full key tree — provider → KEK → subject key → this
file's DEK → envelope — each node annotated with live state, so a revoked or
crypto-shredded ancestor visibly marks the file unreadable.
Download (`decrypt` scope) streams the plaintext back out; after the owning
subject is erased, the same button returns `DECRYPT_FAILED` while the
ciphertext blob stays on disk as the shredding proof. See
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the trade-offs of storing ciphertext
outside the database.

## Development mode

Run the API with hot reload and the console on Vite's dev server (proxying
`/api/*` to the API — see `web/vite.config.ts`) instead of the built,
single-process setup:

```bash
./run.sh --dev
```

This starts `uvicorn keyring.main:app --reload --port 8010` and `npm run dev`
(console on http://127.0.0.1:5173) side by side. The API's CORS config only
allows `http://localhost:5173` / `http://127.0.0.1:5173`, so the two must run
on exactly these ports. There's no Windows equivalent script yet — on
Windows, run the two commands manually in separate terminals.

## Test

```bash
pytest
```

Verified on Linux/macOS. A few fixtures (`keyring/tests/conftest.py`,
`test_shamir_backup.py`, `test_providers.py`) `chmod` files to `0400` to
exercise the `file` provider; on Windows this makes those temp files
read-only, which can make pytest's own tmpdir cleanup fail after the run.

## Platform notes

The `file` provider's "readable by owner only" guarantee is a POSIX
permission bit (`0400`) with no exact Windows equivalent — NTFS only
exposes a single read-only attribute, not separate owner/group/other
permissions. On Windows the check is relaxed to "not writable," which is
weaker (see [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full note). Treat
`file` on Windows as development-only; use `env`, `vault`, or `kms` for
production there.

## Security note

`data/root.passphrase`, `data/root.salt`, `data/kek_store.enc.json`, and the
`KEYRING_CERT_SIGNING_KEY` in `.env` are committed **dev/demo values**, not
production secrets. Rotate all of them (and regenerate the database) before
using this outside of a local/demo environment.

## Project layout

| Path | What it is |
|---|---|
| `keyring/` | FastAPI backend — API routes, core services, providers, models, i18n, tests |
| `web/` | Operator console (Vite + React + TypeScript, Nocturne design system); `web/dist` is the committed production build |
| `ui/` | Static design-tool mockup — visual reference only, not part of the build |
| `alembic/` | Database migrations (owns the schema; the app never calls `create_all`) |
| `data/` | Runtime secret material for the `file` provider |
| `thesis-extraction/` | Arabic-language project analysis documents |

In production, `keyring/main.py` serves the built `web/dist` directly from
the API process — no separate frontend server is required.

## Troubleshooting

- **Windows Defender / "Windows protected your PC" blocks `run-windows.bat`**
  — this is SmartScreen reacting to the Mark of the Web tag Windows stamps on
  any file that arrived via a browser download or a ZIP extracted from one
  (downloading the repo as a ZIP tags every file this way; `git clone` does
  not). It isn't a real detection of the script's contents. Fastest fixes,
  cheapest first:
  - On the SmartScreen dialog, click **More info** then **Run anyway**.
  - Or clear the tag before running: right-click the file → Properties →
    tick **Unblock** → OK. For the whole checkout at once, from the project
    root in PowerShell:
    ```powershell
    Get-ChildItem -Recurse | Unblock-File
    ```
  - Or avoid it entirely — `git clone` the repo instead of downloading the
    ZIP.
  - If Defender actually quarantines the file rather than showing a dialog,
    check Windows Security → Virus & threat protection → Protection history
    for the verdict name; a generic/heuristic hit (plausible, since the
    script silently runs `winget install`, `pip install`, and `npm install`)
    can be cleared with a folder exclusion scoped to this project directory.
    Don't disable real-time protection for this — it's unnecessary and this
    is exactly the moment three separate dependency installers are about to
    run.
  - Or skip the script and run the [Manual setup](#manual-setup) commands
    directly — same steps, no `.bat` for Defender to look at.
- **`ProviderUnavailable: ... expected 0400`** — the secret files'
  permissions didn't survive a git clone (git doesn't track file modes).
  Run `chmod 0400 data/root.passphrase data/root.salt` (Linux/macOS) or
  `attrib +R data\root.passphrase data\root.salt` (Windows), or just re-run
  the launcher script, which does this automatically.
- **`ModuleNotFoundError: httpx`** — installed with `pip install -e .`
  instead of `pip install -e ".[dev]"`. httpx is a runtime dependency (used
  by the vault/kms providers), not test-only.
- **Blank page / 404 at `/`** — `web/dist` is missing or incomplete. Run
  `cd web && npm install && npm run build`, or re-run the launcher script.
- **Demo API keys (Alice/Bob/Carol/Dan) return `UNAUTHORIZED` on a fresh
  Windows clone** — Git for Windows commonly defaults to
  `core.autocrlf=true`, which rewrites LF to CRLF on checkout for any file
  it guesses is text. `keyring.db` is a raw SQLite file (and `data/root.salt`
  is raw binary), so that rewrite corrupts them, wiping out the seeded demo
  accounts. This repo ships a `.gitattributes` marking both as binary to
  prevent it going forward, but a clone made *before* that fix already has
  the corrupted files on disk — pulling alone won't re-checkout them. Fix
  it with:
  ```
  git pull
  git rm --cached keyring.db data/root.salt
  git checkout keyring.db data/root.salt
  ```
  or simplest, delete the local folder and re-clone.
